"""
Anomaly Detection Models - Modern approach combining:
  1. Deep Isolation Forest (neural-network based, SOTA)
  2. Standard Isolation Forest (ensemble baseline)
  3. Variational Autoencoder (deep reconstruction-based)
"""

import os
import json
import warnings
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import roc_auc_score, average_precision_score
import joblib
from typing import Optional, Tuple, List, Dict
from tqdm import tqdm

warnings.filterwarnings("ignore")


# ─── 1. Deep Isolation Forest (Neural Network variant) ───

class DeepIsolationForest(nn.Module):
    """
    Deep Isolation Forest using Random Orthogonal Projection + Representation Network.
    Implements the approach from 'Deep Isolation Forest for Anomaly Detection' (2022).
    Uses learnable random projections to compute isolation scores in representation space.
    """
    def __init__(self, input_dim: int, hidden_dims: List[int] = [128, 64, 32],
                 n_projections: int = 256, dropout: float = 0.15):
        super().__init__()
        self.input_dim = input_dim
        self.n_projections = n_projections

        # Representation network
        layers = []
        dims = [input_dim] + hidden_dims
        for i in range(len(dims) - 1):
            layers.append(nn.Linear(dims[i], dims[i + 1]))
            layers.append(nn.LayerNorm(dims[i + 1]))
            layers.append(nn.LeakyReLU(0.2))
            layers.append(nn.Dropout(dropout))
        self.encoder = nn.Sequential(*layers)

        # Random orthogonal projections (learnable but constrained)
        self.projection = nn.Linear(hidden_dims[-1], n_projections, bias=False)
        self._init_projections()

        # Score head
        self.score_head = nn.Sequential(
            nn.Linear(n_projections, 32),
            nn.LeakyReLU(0.2),
            nn.Linear(32, 1),
            nn.Sigmoid()
        )

    def _init_projections(self):
        """Initialize with orthogonal weights."""
        nn.init.orthogonal_(self.projection.weight)

    def forward(self, x: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        encoded = self.encoder(x)
        proj = self.projection(encoded)  # [batch, n_projections]
        # Anomaly score: high = anomalous
        score = self.score_head(proj)
        return score, encoded

    def get_isolation_score(self, x: torch.Tensor) -> np.ndarray:
        """Return anomaly scores (0=normal, 1=anomalous)."""
        self.eval()
        with torch.no_grad():
            score, _ = self.forward(x)
        return score.cpu().numpy().flatten()


class AutoencoderAnomaly(nn.Module):
    """
    Variational Autoencoder for reconstruction-based anomaly detection.
    Anomalous events have high reconstruction error (MSE).
    """
    def __init__(self, input_dim: int, latent_dim: int = 16):
        super().__init__()
        self.input_dim = input_dim
        self.latent_dim = latent_dim

        # Encoder
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 128),
            nn.BatchNorm1d(128),
            nn.LeakyReLU(0.2),
            nn.Dropout(0.1),
            nn.Linear(128, 64),
            nn.BatchNorm1d(64),
            nn.LeakyReLU(0.2),
            nn.Linear(64, latent_dim * 2),  # mu + logvar
        )

        # Decoder
        self.decoder = nn.Sequential(
            nn.Linear(latent_dim, 64),
            nn.BatchNorm1d(64),
            nn.LeakyReLU(0.2),
            nn.Linear(64, 128),
            nn.BatchNorm1d(128),
            nn.LeakyReLU(0.2),
            nn.Linear(128, input_dim),
        )

    def reparameterize(self, mu: torch.Tensor, logvar: torch.Tensor) -> torch.Tensor:
        std = torch.exp(0.5 * logvar)
        eps = torch.randn_like(std)
        return mu + eps * std

    def forward(self, x: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        params = self.encoder(x)
        mu, logvar = params[:, :self.latent_dim], params[:, self.latent_dim:]
        z = self.reparameterize(mu, logvar)
        recon = self.decoder(z)
        return recon, mu, logvar

    def loss_fn(self, x: torch.Tensor, recon: torch.Tensor,
                mu: torch.Tensor, logvar: torch.Tensor,
                beta: float = 0.1) -> torch.Tensor:
        recon_loss = nn.functional.mse_loss(recon, x, reduction='mean')
        kl_loss = -0.5 * torch.mean(1 + logvar - mu.pow(2) - logvar.exp())
        return recon_loss + beta * kl_loss

    def get_reconstruction_error(self, x: torch.Tensor) -> np.ndarray:
        self.eval()
        with torch.no_grad():
            recon, _, _ = self.forward(x)
            errors = torch.mean((x - recon) ** 2, dim=1)
        return errors.cpu().numpy().flatten()


# ─── Anomaly Detector Ensemble ───

class AnomalyDetector:
    """
    Ensemble anomaly detector combining:
    - Standard Isolation Forest (fast baseline)
    - Deep Isolation Forest (neural SOTA)
    - VAE Autoencoder (reconstruction-based)
    """

    def __init__(self, config: dict = None):
        self.config = config or {}
        self.input_dim: Optional[int] = None
        self.scaler = StandardScaler()
        self.iso_forest: Optional[IsolationForest] = None
        self.deep_if: Optional[DeepIsolationForest] = None
        self.autoencoder: Optional[AutoencoderAnomaly] = None
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    def _extract_config(self, key: str, default):
        return self.config.get(key, default)

    def fit(self, X: np.ndarray,
            fit_iso_forest: bool = True,
            fit_deep_if: bool = True,
            fit_autoencoder: bool = True,
            epochs: int = 50,
            batch_size: int = 256,
            lr: float = 1e-3,
            verbose: bool = True) -> "AnomalyDetector":
        """
        Fit all enabled anomaly detectors on baseline data X.
        X should be clean (normal-behavior) data for baseline learning.
        """
        self.input_dim = X.shape[1]

        # Scale
        X_scaled = self.scaler.fit_transform(X)
        X_tensor = torch.FloatTensor(X_scaled).to(self.device)

        # ─── 1. Standard Isolation Forest ───
        if fit_iso_forest:
            if verbose:
                print("[Anomaly] Training Isolation Forest...")
            contamination = self._extract_config("contamination", 0.05)
            self.iso_forest = IsolationForest(
                n_estimators=self._extract_config("n_estimators", 200),
                contamination=contamination,
                random_state=42,
                n_jobs=-1,
                max_samples=self._extract_config("max_samples", 256),
            )
            self.iso_forest.fit(X_scaled)
            if verbose:
                print(f"  ✓ IsolationForest trained (dim={self.input_dim})")

        # ─── 2. Deep Isolation Forest ───
        if fit_deep_if:
            if verbose:
                print("[Anomaly] Training Deep Isolation Forest...")
            hidden = self._extract_config("deep_hidden_dims", [128, 64, 32])
            n_proj = self._extract_config("n_projections", 256)
            self.deep_if = DeepIsolationForest(
                input_dim=self.input_dim,
                hidden_dims=hidden,
                n_projections=n_proj,
            ).to(self.device)

            dataset = TensorDataset(X_tensor)
            loader = DataLoader(dataset, batch_size=batch_size, shuffle=True)
            optimizer = optim.AdamW(self.deep_if.parameters(), lr=lr, weight_decay=1e-5)
            scheduler = optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=epochs)

            self.deep_if.train()
            for epoch in range(epochs):
                epoch_loss = 0.0
                for (batch_x,) in loader:
                    optimizer.zero_grad()
                    score, _ = self.deep_if(batch_x)
                    # Loss: maximize entropy for normal data -> scores near 0
                    loss = torch.mean(score)  # minimize anomaly scores on normal data
                    # Add L2 regularization on projection weights
                    reg = 1e-4 * torch.norm(self.deep_if.projection.weight, p=2)
                    total_loss = loss + reg
                    total_loss.backward()
                    torch.nn.utils.clip_grad_norm_(self.deep_if.parameters(), 1.0)
                    optimizer.step()
                    epoch_loss += loss.item()
                scheduler.step()
                if verbose and (epoch + 1) % 10 == 0:
                    avg_loss = epoch_loss / len(loader)
                    print(f"  Epoch {epoch+1}/{epochs} | Loss: {avg_loss:.6f}")
            if verbose:
                print(f"  ✓ DeepIsolationForest trained")

        # ─── 3. Variational Autoencoder ───
        if fit_autoencoder:
            if verbose:
                print("[Anomaly] Training VAE Autoencoder...")
            latent_dim = self._extract_config("vae_latent_dim", 16)
            self.autoencoder = AutoencoderAnomaly(
                input_dim=self.input_dim,
                latent_dim=latent_dim,
            ).to(self.device)

            dataset = TensorDataset(X_tensor)
            loader = DataLoader(dataset, batch_size=batch_size, shuffle=True)
            optimizer = optim.AdamW(self.autoencoder.parameters(), lr=lr, weight_decay=1e-5)

            self.autoencoder.train()
            for epoch in range(epochs):
                epoch_loss = 0.0
                for (batch_x,) in loader:
                    optimizer.zero_grad()
                    recon, mu, logvar = self.autoencoder(batch_x)
                    loss = self.autoencoder.loss_fn(batch_x, recon, mu, logvar, beta=0.1)
                    loss.backward()
                    torch.nn.utils.clip_grad_norm_(self.autoencoder.parameters(), 1.0)
                    optimizer.step()
                    epoch_loss += loss.item()
                if verbose and (epoch + 1) % 10 == 0:
                    avg_loss = epoch_loss / len(loader)
                    print(f"  Epoch {epoch+1}/{epochs} | VAE Loss: {avg_loss:.6f}")
            if verbose:
                print(f"  ✓ VAE Autoencoder trained")

        return self

    def predict(self, X: np.ndarray) -> Dict[str, np.ndarray]:
        """
        Return anomaly scores from each model (0=normal, 1=anomalous).
        Scores are normalized to [0, 1].
        """
        X_scaled = self.scaler.transform(X)
        X_tensor = torch.FloatTensor(X_scaled).to(self.device)
        results = {}

        if self.iso_forest is not None:
            # IF returns -1 for anomaly, 1 for normal -> convert to [0,1]
            scores = self.iso_forest.decision_function(X_scaled)
            results["isolation_forest"] = 1 - (scores - scores.min()) / (scores.max() - scores.min() + 1e-8)

        if self.deep_if is not None:
            results["deep_isolation_forest"] = self.deep_if.get_isolation_score(X_tensor)

        if self.autoencoder is not None:
            recon_errors = self.autoencoder.get_reconstruction_error(X_tensor)
            err_norm = (recon_errors - recon_errors.min()) / (recon_errors.max() - recon_errors.min() + 1e-8)
            results["autoencoder_vae"] = err_norm

        return results

    def predict_ensemble(self, X: np.ndarray,
                         weights: Optional[List[float]] = None) -> np.ndarray:
        """Weighted ensemble of all available anomaly detectors."""
        scores_dict = self.predict(X)
        if not scores_dict:
            raise RuntimeError("No models trained. Call fit() first.")

        model_names = list(scores_dict.keys())
        if weights is None:
            weights = [1.0 / len(model_names)] * len(model_names)

        ensemble = np.zeros(len(X))
        for name, w in zip(model_names, weights):
            ensemble += w * scores_dict[name]
        return ensemble

    def save(self, model_dir: str):
        """Save all models to disk."""
        os.makedirs(model_dir, exist_ok=True)
        if self.iso_forest is not None:
            joblib.dump(self.iso_forest, os.path.join(model_dir, "isolation_forest.pkl"))
        if self.deep_if is not None:
            torch.save(self.deep_if.state_dict(), os.path.join(model_dir, "deep_isolation_forest.pt"))
        if self.autoencoder is not None:
            torch.save(self.autoencoder.state_dict(), os.path.join(model_dir, "autoencoder.pt"))
        joblib.dump(self.scaler, os.path.join(model_dir, "scaler.pkl"))
        with open(os.path.join(model_dir, "anomaly_metadata.json"), "w") as f:
            json.dump({"input_dim": self.input_dim}, f)
        print(f"✓ Models saved to {model_dir}")

    def load(self, model_dir: str, device: Optional[str] = None):
        """Load all models from disk."""
        if device:
            self.device = torch.device(device)
        meta_path = os.path.join(model_dir, "anomaly_metadata.json")
        if os.path.exists(meta_path):
            with open(meta_path) as f:
                meta = json.load(f)
            self.input_dim = meta["input_dim"]

        self.scaler = joblib.load(os.path.join(model_dir, "scaler.pkl"))

        if_path = os.path.join(model_dir, "isolation_forest.pkl")
        if os.path.exists(if_path):
            self.iso_forest = joblib.load(if_path)

        dif_path = os.path.join(model_dir, "deep_isolation_forest.pt")
        if os.path.exists(dif_path) and self.input_dim:
            hidden = self._extract_config("deep_hidden_dims", [128, 64, 32])
            n_proj = self._extract_config("n_projections", 256)
            self.deep_if = DeepIsolationForest(self.input_dim, hidden, n_proj).to(self.device)
            self.deep_if.load_state_dict(torch.load(dif_path, map_location=self.device))

        ae_path = os.path.join(model_dir, "autoencoder.pt")
        if os.path.exists(ae_path) and self.input_dim:
            latent = self._extract_config("vae_latent_dim", 16)
            self.autoencoder = AutoencoderAnomaly(self.input_dim, latent).to(self.device)
            self.autoencoder.load_state_dict(torch.load(ae_path, map_location=self.device))

        print(f"✓ Models loaded from {model_dir}")
        return self
