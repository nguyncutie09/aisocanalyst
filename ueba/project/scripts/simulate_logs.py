#!/usr/bin/env python3
"""
Synthetic Security Log Generator & Simulator.
Generates realistic security logs for testing the UEBA system.

Usage:
    python scripts/simulate_logs.py                          # Generate and save
    python scripts/simulate_logs.py --n-events 10000         # More events
    python scripts/simulate_logs.py --attack-ratio 0.15      # More attacks
    python scripts/simulate_logs.py --stream http://localhost:8000/api/v1/analyze
    python scripts/simulate_logs.py --output ./data/raw/logs.jsonl
"""

import os
import sys
import json
import time
import argparse
import requests
from tqdm import tqdm

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.pipeline.ingestion import SyntheticLogGenerator


def generate_and_save(n_normal: int, n_attack: int, output_path: str):
    """Generate and save synthetic logs."""
    print(f"Generating {n_normal} normal + {n_attack} attack events...")
    generator = SyntheticLogGenerator()
    df = generator.generate_attack_scenarios(
        n_normal=n_normal, n_attack=n_attack, seed=42
    )

    # Save as JSONL
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "w") as f:
        for _, row in df.iterrows():
            record = row.dropna().to_dict()
            # Convert numpy types
            clean = {}
            for k, v in record.items():
                if hasattr(v, "item"):
                    v = v.item()
                clean[k] = v
            f.write(json.dumps(clean, default=str) + "\n")

    attack_count = df["is_anomaly"].sum()
    normal_count = len(df) - attack_count
    print(f"✓ Saved {len(df)} events to {output_path}")
    print(f"  Normal: {normal_count} | Attack: {attack_count} "
          f"({attack_count/len(df)*100:.1f}%)")
    return df


def stream_to_api(api_url: str, n_normal: int, n_attack: int,
                   delay: float = 0.05):
    """Generate and stream events to the UEBA API."""
    print(f"Streaming {n_normal + n_attack} events to {api_url}...")
    print(f"  (delay={delay}s per event)\n")

    generator = SyntheticLogGenerator()
    df = generator.generate_attack_scenarios(
        n_normal=n_normal, n_attack=n_attack, seed=42
    )

    # Drop non-serializable columns
    cols = [c for c in df.columns if not c.startswith("_")]
    events = df[cols].to_dict(orient="records")

    high_risk = 0
    critical_risk = 0
    start = time.time()

    for i, event in enumerate(tqdm(events, desc="Sending events")):
        # Clean numpy types
        clean = {}
        for k, v in event.items():
            if hasattr(v, "item"):
                v = v.item()
            if isinstance(v, (int, float, str, bool, type(None))):
                clean[k] = v
            else:
                clean[k] = str(v)

        try:
            resp = requests.post(api_url, json=clean, timeout=5)
            if resp.ok:
                result = resp.json()
                score = result.get("risk", {}).get("score", 0)
                if score >= 85:
                    critical_risk += 1
                elif score >= 65:
                    high_risk += 1
            else:
                tqdm.write(f"  ⚠ HTTP {resp.status_code}")
        except Exception as e:
            tqdm.write(f"  ⚠ Error: {e}")

        if delay > 0:
            time.sleep(delay)

    elapsed = time.time() - start
    print(f"\n✓ Streamed {len(events)} events in {elapsed:.1f}s")
    print(f"  Rate: {len(events)/elapsed:.1f} events/s")
    print(f"  Critical alerts: {critical_risk}")
    print(f"  High alerts: {high_risk}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate synthetic security logs")
    parser.add_argument("--n-normal", type=int, default=2000,
                        help="Number of normal events (default: 2000)")
    parser.add_argument("--n-attack", type=int, default=200,
                        help="Number of attack events (default: 200)")
    parser.add_argument("--output", type=str,
                        default="./data/raw/synthetic_logs.jsonl",
                        help="Output file path")
    parser.add_argument("--stream", type=str, default=None,
                        help="Stream to API URL (e.g., http://localhost:8000/api/v1/analyze)")
    parser.add_argument("--delay", type=float, default=0.05,
                        help="Delay between streamed events (seconds)")

    args = parser.parse_args()

    if args.stream:
        stream_to_api(args.stream, args.n_normal, args.n_attack, args.delay)
    else:
        generate_and_save(args.n_normal, args.n_attack, args.output)
