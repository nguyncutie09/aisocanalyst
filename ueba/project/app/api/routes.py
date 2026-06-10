"""
FastAPI REST API routes for UEBA system.
Endpoints: event analysis, risk scoring, model management, dashboard, MITRE.
"""
import os
import time
import json
import logging
from typing import List, Optional, Dict, Any
from datetime import datetime

import numpy as np
import pandas as pd
from fastapi import APIRouter, HTTPException, Query, Body
from fastapi.responses import JSONResponse

from app.api.schemas import (
    EventLog, EventBatch, AnalyzeResponse, BatchAnalyzeResponse,
    RiskAssessment, ModelStatus, Alert, DashboardSummary,
    TrainRequest, TrainResponse,
)
from app.models.anomaly import AnomalyDetector
from app.models.sequence_model import SequenceTransformer, SequenceTrainer, prepare_sequences
from app.models.classifier import AttackClassifier
from app.models.risk_scorer import RiskScorer, RiskResult
from app.pipeline.mitre import (
    map_event_to_technique, get_tactic_for_technique,
    get_technique_info, MITRE_DATABASE,
)
from app.pipeline.normalizer import LogNormalizer
from app.database import store
from app.config import settings

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1", tags=["UEBA API"])

# Global model instances
anomaly_detector = None
sequence_model = None
classifier = None
risk_scorer = None
normalizer = None
model_ready = False
total_events_processed = 0


def init_models(config=None):
    """Initialize or load models at server startup."""
    global anomaly_detector, sequence_model, classifier
    global risk_scorer, normalizer, model_ready

    anomaly_detector = AnomalyDetector(config)
    classifier = AttackClassifier(config)
    risk_scorer = RiskScorer(config)
    normalizer = LogNormalizer()

    try:
        anomaly_detector.load(settings.MODEL_DIR)
        logger.info("Loaded pre-trained anomaly models")
    except Exception as e:
        logger.warning("No pre-trained anomaly models: %s", e)

    try:
        classifier.load(settings.MODEL_DIR)
        logger.info("Loaded pre-trained classifier models")
    except Exception as e:
        logger.warning("No pre-trained classifier models: %s", e)

    encoder_path = os.path.join(settings.MODEL_DIR, "label_encoders.pkl")
    if os.path.exists(encoder_path):
        try:
            normalizer.load_encoders(encoder_path)
            logger.info("Loaded label encoders from %s", encoder_path)
        except Exception as e:
            logger.warning("Failed to load label encoders: %s", e)

    model_ready = True
    logger.info("UEBA models initialized")


def _extract_features(event):
    """Full 18-dim feature vector: 9 numeric + 9 encoded categoricals."""
    num = np.array([
        float(event.event_code), float(event.hour_of_day),
        float(event.day_of_week), float(event.session_duration_sec),
        float(event.bytes_transferred), float(event.failed_attempts_last_1h),
        float(event.unique_dest_ips_last_1h),
        float(event.login_frequency_last_1h),
        float(event.is_weekend),
    ]).reshape(1, -1)
    try:
        df = pd.DataFrame([event.model_dump()])
        cat_df = normalizer.extract_features(df, fit=False)
        cat_features = cat_df.iloc[:, 9:].values.astype(np.float32)
        return np.hstack([num, cat_features])
    except Exception:
        return np.hstack([num, np.zeros((1, 9))])


@router.post("/analyze", response_model=AnalyzeResponse)
def analyze_event(event: EventLog):
    """Analyze a single security event and return risk assessment."""
    global total_events_processed, classifier, risk_scorer

    try:
        features = _extract_features(event)
    except Exception as e:
        raise HTTPException(400, "Feature extraction failed: %s" % str(e))

    anomaly_scores = {"ensemble": 0.5}
    if anomaly_detector and anomaly_detector.iso_forest is not None:
        try:
            scores = anomaly_detector.predict(features)
            # Add ensemble score
            try:
                ensemble = anomaly_detector.predict_ensemble(features)
                scores["ensemble"] = float(ensemble[0])
            except Exception:
                scores["ensemble"] = float(np.mean(list(scores.values())))
            anomaly_scores = scores
        except Exception as e:
            logger.error("Anomaly prediction error: %s", e)

    attack_type = "normal"
    tactic = "TA0000_Benign"
    technique_ids = ["T1078"]
    if classifier and classifier.is_fitted:
        try:
            pred = classifier.predict(features)
            if len(pred.get("attack_type", [])) > 0:
                attack_type = pred["attack_type"][0]
                tactic = pred.get("tactic", [tactic])[0]
                technique_ids = map_event_to_technique(event.event_type, attack_type)
                if not technique_ids:
                    technique_ids = ["T1078"]
        except Exception as e:
            logger.error("Classification error: %s", e)

    risk_result = risk_scorer.compute(
        anomaly_prob=anomaly_scores.get("ensemble", 0.5),
        attack_type=attack_type,
        tactic=tactic,
        confidence=anomaly_scores.get("ensemble", 0.5),
        user_role=event.user_role,
        asset_type=event.asset_type,
        hour_of_day=event.hour_of_day,
        is_weekend=event.is_weekend,
        failed_logins_1h=event.failed_attempts_last_1h,
    )

    if risk_result.score >= settings.RISK_LOW_THRESHOLD:
        store.add_alert({
            "id": "alert_%d" % total_events_processed,
            "timestamp": risk_result.timestamp,
            "user_name": event.user_name,
            "source_ip": event.source_ip,
            "risk_score": risk_result.score,
            "risk_level": risk_result.level,
            "attack_type": attack_type,
            "tactic": tactic,
            "mitre_technique_ids": technique_ids,
            "risk_factors": risk_result.risk_factors,
            "recommendations": risk_result.recommendations,
            "anomaly_probability": risk_result.anomaly_probability,
            "event_type": event.event_type,
        })

    total_events_processed += 1

    return AnalyzeResponse(
        event_id="evt_%d" % total_events_processed,
        risk=RiskAssessment(
            score=risk_result.score,
            level=risk_result.level,
            anomaly_probability=risk_result.anomaly_probability,
            attack_type=risk_result.attack_type,
            tactic=risk_result.tactic,
            context_bonus=risk_result.context_bonus,
            impact_weight=risk_result.impact_weight,
            confidence=risk_result.confidence,
            risk_factors=risk_result.risk_factors,
            recommendations=risk_result.recommendations,
            timestamp=risk_result.timestamp,
        ),
        anomaly_scores=anomaly_scores,
        mitre_technique_ids=technique_ids,
    )


@router.post("/analyze/batch", response_model=BatchAnalyzeResponse)
def analyze_batch(batch: EventBatch):
    """Analyze a batch of events with aggregate stats."""
    results = []
    for event in batch.events:
        try:
            results.append(analyze_event(event))
        except Exception as e:
            logger.error("Error analyzing event: %s", e)

    high = sum(1 for r in results if r.risk.score >= settings.RISK_HIGH_THRESHOLD)
    medium = sum(1 for r in results if settings.RISK_MEDIUM_THRESHOLD <= r.risk.score < settings.RISK_HIGH_THRESHOLD)
    low = sum(1 for r in results if settings.RISK_LOW_THRESHOLD <= r.risk.score < settings.RISK_MEDIUM_THRESHOLD)
    info = sum(1 for r in results if r.risk.score < settings.RISK_LOW_THRESHOLD)
    scores = [r.risk.score for r in results] if results else [0]
    aggregate = {
        "avg_score": round(sum(scores) / len(scores), 2),
        "max_score": round(max(scores), 2),
        "total": len(results),
    }
    return BatchAnalyzeResponse(
        total_events=len(results),
        high_risk_count=high,
        medium_risk_count=medium,
        low_risk_count=low,
        info_count=info,
        results=results,
        aggregate=aggregate,
    )


@router.get("/status", response_model=ModelStatus)
def get_status():
    """Get system and model status."""
    stats = store.get_stats()
    return ModelStatus(
        isolation_forest=anomaly_detector.iso_forest is not None if anomaly_detector else False,
        deep_isolation_forest=anomaly_detector.deep_if is not None if anomaly_detector else False,
        autoencoder_vae=anomaly_detector.autoencoder is not None if anomaly_detector else False,
        sequence_transformer=sequence_model is not None,
        xgboost_attack_classifier=classifier.is_fitted if classifier else False,
        xgboost_tactic_classifier=classifier.is_fitted if classifier else False,
        risk_scorer=True,
        total_events_processed=stats["total_processed"],
    )


@router.post("/train", response_model=TrainResponse)
def train_models(req: TrainRequest):
    """Train/retrain all ML models using synthetic data."""
    start_time = time.time()
    from app.pipeline.ingestion import SyntheticLogGenerator

    generator = SyntheticLogGenerator()
    logger.info("Generating training data...")
    df = generator.generate_attack_scenarios(n_normal=5000, n_attack=500, seed=42)
    df.to_parquet(os.path.join(settings.PROCESSED_DIR, "training_data.parquet"))

    normalizer = LogNormalizer()
    feature_df = normalizer.extract_features(df, fit=True)
    encoder_path = os.path.join(settings.MODEL_DIR, "label_encoders.pkl")
    normalizer.save_encoders(encoder_path)
    logger.info("Saved label encoders to %s", encoder_path)

    X = feature_df.values.astype(np.float32)
    y_attack = df["attack_type"].values
    y_tactic = df["tactic"].values
    models_trained = []
    metrics = {}

    logger.info("Training anomaly detectors...")
    normal_mask = df["attack_type"] == "normal"
    X_normal = X[normal_mask]
    anomaly_detector.fit(
        X_normal, fit_iso_forest=True, fit_deep_if=True,
        fit_autoencoder=True, epochs=req.epochs,
        batch_size=req.batch_size, lr=req.learning_rate, verbose=True,
    )
    anomaly_detector.save(settings.MODEL_DIR)
    models_trained.extend(["isolation_forest", "deep_isolation_forest", "autoencoder_vae"])

    logger.info("Training attack classifier...")
    classifier = AttackClassifier({})
    classifier.fit(X, y_attack, y_tactic, feature_names=list(feature_df.columns), verbose=True)
    classifier.save(settings.MODEL_DIR)
    models_trained.extend(["xgboost_attack", "xgboost_tactic"])

    pred_result = classifier.predict(X)
    acc = float(np.mean(np.array(pred_result["attack_type"]) == y_attack))
    metrics["accuracy"] = acc
    metrics["n_samples"] = int(len(X))

    elapsed = round(time.time() - start_time, 2)
    logger.info("Training complete in %.2fs, accuracy=%.4f", elapsed, acc)
    init_models()

    return TrainResponse(
        status="success",
        models_trained=models_trained,
        training_time_seconds=elapsed,
        metrics=metrics,
    )


@router.post("/train/from-data")
def train_from_file(filepath: str = Body(..., embed=True),
                    label_col: str = "attack_type",
                    tactic_col: str = "tactic"):
    """Train models from a labeled data file."""
    from app.pipeline.ingestion import LogIngestor
    if not os.path.exists(filepath):
        raise HTTPException(404, "File not found: %s" % filepath)
    ingestor = LogIngestor()
    df = ingestor.ingest_file(filepath)
    if label_col not in df.columns:
        raise HTTPException(400, "Label column '%s' not found" % label_col)

    normalizer = LogNormalizer()
    feature_df = normalizer.extract_features(df, fit=True)
    encoder_path = os.path.join(settings.MODEL_DIR, "label_encoders.pkl")
    normalizer.save_encoders(encoder_path)

    X = feature_df.values.astype(np.float32)
    y_attack = df[label_col].values
    y_tactic = df.get(tactic_col, ["TA0000_Benign"] * len(df)).values

    anomaly_detector.fit(X[df[label_col] == "normal"], epochs=30, verbose=True)
    anomaly_detector.save(settings.MODEL_DIR)
    classifier.fit(X, y_attack, y_tactic, verbose=True)
    classifier.save(settings.MODEL_DIR)
    init_models()
    return {"status": "success", "n_samples": len(X)}


@router.get("/alerts", response_model=List[Alert])
def get_alerts(limit: int = Query(50, ge=1, le=1000),
               offset: int = Query(0, ge=0),
               min_risk=None, level=None, attack_type=None):
    """Get security alerts with filtering."""
    alerts = store.get_alerts(limit=limit, offset=offset,
                              min_risk=min_risk, level=level,
                              attack_type=attack_type)
    return [Alert(**a) for a in alerts]


@router.get("/alerts/{alert_id}", response_model=Alert)
def get_alert(alert_id: str):
    """Get a specific alert by ID."""
    alert = store.get_alert_by_id(alert_id)
    if not alert:
        raise HTTPException(404, "Alert not found")
    return Alert(**alert)


@router.post("/alerts/{alert_id}/acknowledge")
def acknowledge_alert(alert_id: str):
    """Mark alert as acknowledged."""
    if not store.acknowledge_alert(alert_id):
        raise HTTPException(404, "Alert not found")
    return {"status": "acknowledged", "alert_id": alert_id}


@router.get("/dashboard/summary", response_model=DashboardSummary)
def get_dashboard_summary():
    """Get summary statistics for the dashboard."""
    stats = store.get_stats()
    risk_history = store.get_risk_history(hours=24)
    top_attacks = store.get_top_attack_types()
    entity_risk = store.get_user_risk_summary()
    mitre_coverage = store.get_mitre_coverage()
    model_status = get_status()
    avg_risk = 0.0
    alerts = store.get_alerts(limit=500)
    if alerts:
        avg_risk = sum(a.get("risk_score", 0) for a in alerts) / len(alerts)
    return DashboardSummary(
        total_events_analyzed=stats["total_processed"],
        active_alerts=stats["total_alerts"],
        critical_alerts=stats["critical"],
        high_alerts=stats["high"],
        medium_alerts=stats["medium"],
        avg_risk_score=round(avg_risk, 2),
        top_attack_types=top_attacks,
        risk_over_time=risk_history,
        entity_risk=entity_risk,
        mitre_coverage=mitre_coverage,
        model_status=model_status,
    )


@router.get("/dashboard/risk-timeline")
def get_risk_timeline(hours: int = Query(24, ge=1, le=168)):
    return store.get_risk_history(hours=hours)


@router.get("/dashboard/top-entities")
def get_top_entities(limit: int = Query(20, ge=1, le=100)):
    return store.get_user_risk_summary(top_n=limit)


@router.get("/dashboard/mitre-coverage")
def get_mitre_coverage():
    return store.get_mitre_coverage()


@router.get("/mitre/techniques")
def list_mitre_techniques():
    return {tid: get_technique_info(tid) for tid in MITRE_DATABASE}


@router.get("/mitre/techniques/{technique_id}")
def get_mitre_technique(technique_id: str):
    info = get_technique_info(technique_id.upper())
    if not info:
        raise HTTPException(404, "Technique %s not found" % technique_id)
    return info


@router.get("/mitre/navigator-layer")
def get_mitre_navigator_layer():
    from app.pipeline.mitre import build_mitre_navigator_layer
    coverage = store.get_mitre_coverage()
    techniques = {}
    for tid, tech in MITRE_DATABASE.items():
        techniques[tid] = coverage.get(tech.tactic, 0)
    return build_mitre_navigator_layer(techniques)


@router.get("/health")
def health_check():
    stats = store.get_stats()
    return {
        "status": "healthy",
        "version": settings.APP_VERSION,
        "models_ready": model_ready,
        "total_events_processed": stats["total_processed"],
        "active_alerts": stats["total_alerts"],
        "timestamp": datetime.utcnow().isoformat(),
    }
