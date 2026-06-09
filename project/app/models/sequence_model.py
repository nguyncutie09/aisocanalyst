"""
Sequence Anomaly Detection using Transformer Encoder.
Models user/entity behavior as sequences of events and flags
deviations from learned normal patterns.

Architecture: Time-series Transformer with:
  - Learned positional encoding
  - Multi-head self-attention (causal masking)
  - Feed-forward blocks with residual connections
  - Anomaly scoring head
"""

import os
import math
import json
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset
from typing import Optional, Tuple, List
from tqdm import tqdm


class PositionalEncoding(nn.Module):
    """Sinusoidal positional encoding for sequence position awareness."""

    def __init__(self, d_model: int, max_len: int = 5000, dropout: float = 0.1):
        super().__init__()
        self.dropout = nn.Dropout(p=dropout)
        pe = torch.zeros(max_len, d_model)
        position = torch.arange(0, max_len, dtype=torch.float).unsqueeze(1)
        div_term = torch.exp(torch.arange(0, d_model, 2).float() *
                             (-math.log(10000.0) / d_model))
        pe[:, 0::2] = torch.sin(position * div_term)
        pe[:, 1::2] = torch.cos(position * div_term)
        pe = pe.unsqueeze(0)  # [1, max_len, d_model]
        self.register_buffer("pe", pe)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """x: [batch, seq_len, d_model]"""
        x = x + self.pe[:, :x.size(1), :]
        return self.dropout(x)


class TransformerEncoderBlock(nn.Module):
    """Single Transformer encoder block with pre-norm architecture."""

    def __init__(self, d_model: int, n_heads: int, d_ff: int,
                 dropout: float = 0.15, activation: str = "gelu"):
        super().__init__()
        self.self_attn = nn.MultiheadAttention(d_model, n_heads,
                                                dropout=dropout, batch_first=True)
        self.norm1 = nn.LayerNorm(d_model)
        self.norm2 = nn.LayerNorm(d_model)
        self.ff = nn.Sequential(
            nn.Linear(d_model, d_ff),
            nn.GELU() if activation == "gelu" else nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(d_ff, d_model),
            nn.Dropout(dropout),
        )
        self.dropout = nn.Dropout(dropout)

    def forward(self, x: torch.Tensor,
                mask: Optional[torch.Tensor] = None) -> torch.Tensor:
        # Pre-norm -> attention -> residual
        x_norm = self.norm1(x)
        attn_out, _ = self.self_attn(x_norm, x_norm, x_norm, attn_mask=mask,
                                      need_weights=False)
        x = x + self.dropout(attn_out)
        # Pre-norm -> FF -> residual
        x = x + self.ff(self.norm2(x))
        return x


class SequenceTransformer(nn.Module):
    """
    Transformer for sequence anomaly detection in log data.
    Learns normal event sequences; anomalous sequences have high prediction error.
    """
    def __init__(self, feature_dim: int, d_model: int = 128,
                 n_heads: int = 8, n_layers: int = 4,
                 d_ff: int = 512, max_seq_len: int = 100,
                 dropout: float = 0.15):
        super().__init__()
        self.feature_dim = feature_dim
        self.d_model = d_model
        self.max_seq_len = max_seq_len

        # Input projection
        self.input_proj = nn.Sequential(
            nn.Linear(feature_dim, d_model),
            nn.LayerNorm(d_model),
            nn.Dropout(dropout),
        )

        # Positional encoding
        self.pos_encoding = PositionalEncoding(d_model, max_seq_len, dropout)

        # Transformer blocks
        self.blocks = nn.ModuleList([
            TransformerEncoderBlock(d_model, n_heads, d_ff, dropout)
            for _ in range(n_layers)
        ])

        # Output heads
        self.reconstruction_head = nn.Linear(d_model, feature_dim)
        self.anomaly_score_head = nn.Sequential(
            nn.Linear(d_model, 32),
            nn.GELU(),
            nn.Linear(32, 1),
            nn.Sigmoid(),
        )

        # Causal mask (prevent future token leakage)
        self._causal_mask = None

    def _get_causal_mask(self, seq_len: int, device: torch.device) -> torch.Tensor:
        if self._causal_mask is None or self._causal_mask.size(0) < seq_len:
            mask = torch.triu(torch.full((seq_len, seq_len), float('-inf')),
                              diagonal=1)
            self._causal_mask = mask
        return self._causal_mask[:seq_len, :seq_len].to(device)

    def forward(self, x: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        x: [batch, seq_len, feature_dim]
        Returns: (reconstructed_x, anomaly_scores)
        """
        batch_size, seq_len, _ = x.shape

        # Project to d_model
        h = self.input_proj(x)  # [batch, seq_len, d_model]
        h = self.pos_encoding(h)

        # Transformer blocks
        mask = self._get_causal_mask(seq_len, x.device)
        for block in self.blocks:
            h = block(h, mask=mask)

        # Predict next-token reconstruction (shifted)
        recon = self.reconstruction_head(h)  # [batch, seq_len, feature_dim]

        # Per-step anomaly scores (last step score = sequence-level anomaly)
        scores = self.anomaly_score_head(h)  # [batch, seq_len, 1]

        return recon, scores

    def predict_anomaly(self, x: torch.Tensor) -> np.ndarray:
        """
        Return sequence-level anomaly scores [0, 1] for each sequence.
        1 = highly anomalous.
        """
        self.eval()
        with torch.no_grad():
            recon, scores = self.forward(x)
            # Reconstruction error
            recon_error = torch.mean((x - recon) ** 2, dim=(1, 2))
            # Normalize error
            err = (recon_error - recon_error.min()) / \
                  (recon_error.max() - recon_error.min() + 1e-8)
            # Final score = ensemble of recon error + learned score
            final_score = 0.5 * err + 0.5 * scores[:, -1, 0]
        return final_score.cpu().numpy()


# ─── Trainer ───

class SequenceTrainer:
    """Trainer for SequenceTransformer with early stopping."""

    def __init__(self, model: SequenceTransformer, lr: float = 1e-3,
                 weight_decay: float = 1e-5, device: str = "cpu"):
        self.model = model.to(device)
        self.device = device
        self.optimizer = optim.AdamW(model.parameters(), lr=lr,
                                      weight_decay=weight_decay)
        self.scheduler = optim.lr_scheduler.CosineAnnealingWarmRestarts(
            self.optimizer, T_0=10, T_mult=2
        )

    def train_epoch(self, loader: DataLoader) -> float:
        self.model.train()
        total_loss = 0.0
        recon_criterion = nn.MSELoss()
        for batch_x in loader:
            if isinstance(batch_x, (list, tuple)):
                batch_x = batch_x[0]
            batch_x = batch_x.to(self.device)

            self.optimizer.zero_grad()
            recon, scores = self.model(batch_x)

            # Reconstruction loss
            recon_loss = recon_criterion(recon, batch_x)
            # Anomaly score regularization: push scores down for normal data
            score_loss = torch.mean(scores) * 0.1
            loss = recon_loss + score_loss
            loss.backward()
            torch.nn.utils.clip_grad_norm_(self.model.parameters(), 1.0)
            self.optimizer.step()

            total_loss += loss.item()
        self.scheduler.step()
        return total_loss / len(loader)

    def fit(self, X: np.ndarray, seq_length: int = 10,
            epochs: int = 100, batch_size: int = 64,
            verbose: bool = True) -> List[float]:
        """Train on numpy array X of shape [n_samples, feature_dim]."""
        # Create sequences
        n = len(X)
        sequences = []
        for i in range(n - seq_length):
            sequences.append(X[i:i + seq_length])
        X_seq = np.array(sequences)
        tensor_x = torch.FloatTensor(X_seq)

        dataset = TensorDataset(tensor_x)
        loader = DataLoader(dataset, batch_size=batch_size, shuffle=True)

        history = []
        for epoch in range(epochs):
            loss = self.train_epoch(loader)
            history.append(loss)
            if verbose and (epoch + 1) % 10 == 0:
                print(f"  Epoch {epoch+1}/{epochs} | Loss: {loss:.6f}")

        return history


def prepare_sequences(X: np.ndarray, seq_length: int = 10) -> np.ndarray:
    """Convert 2D array [n, dim] to 3D sequences [n-seq_len, seq_len, dim]."""
    sequences = []
    for i in range(len(X) - seq_length):
        sequences.append(X[i:i + seq_length])
    return np.array(sequences)
