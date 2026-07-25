"""
Stage 1 -- Baseline Behavioral Profiling / Anomaly Detection
===============================================================
Learns "normal" per-entity behavior from a SEQUENCE of each entity's recent
events (a sliding window of the last WINDOW_SIZE events), trained ONLY on
normal traffic (unsupervised / one-class), and outputs, per event:
    - a behavior embedding (learned latent representation)
    - a reconstruction error
    - a bounded anomaly_score in [0, 1]

Two interchangeable backends:
    - TORCH (preferred, matches the spec): an LSTM Sequence Autoencoder.
      Input: sequence of the last WINDOW_SIZE feature vectors for the entity.
      Trained to reconstruct normal sequences; anomalies reconstruct poorly.
    - SKLEARN fallback (auto-selected if torch isn't installed, e.g. in this
      offline sandbox): an MLP Autoencoder over the same flattened windowed
      sequence, plus an IsolationForest as a second, complementary detector.
      The final anomaly_score is an ensemble of both (rank-averaged), which
      is a common, robust way to combine density- and reconstruction-based
      detectors when a single deep sequence model isn't available.

Run:
    python train_baseline.py --in ../artifacts/events_features.csv \
        --out ../artifacts/events_scored.csv --model-out ../artifacts/baseline_model
"""

from __future__ import annotations

import argparse
import json
import os
import pickle
from collections import defaultdict, deque

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.neural_network import MLPRegressor
from sklearn.preprocessing import StandardScaler

from features import FEATURE_COLUMNS

WINDOW_SIZE = 5  # sequence length: last N events per entity

try:
    import torch
    import torch.nn as nn
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False


# --------------------------------------------------------------------------- #
# Sequence construction (shared by both backends)
# --------------------------------------------------------------------------- #

def build_sequences(df: pd.DataFrame, feature_cols: list[str], window: int = WINDOW_SIZE):
    """
    For every event, build a fixed-length window of the entity's last
    `window` events' feature vectors (left-padded with zeros for cold-start
    entities). Returns:
        X: np.ndarray [n_events, window, n_features]
        event_ids: list aligned to X's first axis
    Causal: window for event i only contains events at or before i for that
    entity, so this is safe for streaming / online inference.
    """
    df = df.sort_values("timestamp").reset_index(drop=True)
    n_feat = len(feature_cols)
    buffers: dict[str, deque] = defaultdict(lambda: deque(maxlen=window))
    X = np.zeros((len(df), window, n_feat), dtype=np.float32)
    event_ids = []

    feat_matrix = df[feature_cols].to_numpy(dtype=np.float32)
    for i, (eid, entity_id) in enumerate(zip(df["event_id"], df["entity_id"])):
        buf = buffers[entity_id]
        hist = list(buf)
        pad = window - len(hist) - 1
        seq = ([np.zeros(n_feat, dtype=np.float32)] * max(pad, 0)) + hist + [feat_matrix[i]]
        seq = seq[-window:]
        X[i] = np.stack(seq)
        event_ids.append(eid)
        buf.append(feat_matrix[i])

    return X, event_ids


# --------------------------------------------------------------------------- #
# Torch backend
# --------------------------------------------------------------------------- #

if TORCH_AVAILABLE:
    class LSTMAutoencoder(nn.Module):
        def __init__(self, n_features: int, hidden_size: int = 32, embed_size: int = 16):
            super().__init__()
            self.encoder_lstm = nn.LSTM(n_features, hidden_size, batch_first=True)
            self.to_embed = nn.Linear(hidden_size, embed_size)
            self.from_embed = nn.Linear(embed_size, hidden_size)
            self.decoder_lstm = nn.LSTM(hidden_size, n_features, batch_first=True)

        def forward(self, x):
            _, (h, _) = self.encoder_lstm(x)          # h: [1, B, hidden]
            h = h.squeeze(0)                           # [B, hidden]
            embed = self.to_embed(h)                   # [B, embed]
            dec_in = self.from_embed(embed).unsqueeze(1).repeat(1, x.size(1), 1)  # [B, T, hidden]
            recon, _ = self.decoder_lstm(dec_in)        # [B, T, n_features]
            return recon, embed


def train_torch_autoencoder(X_train: np.ndarray, n_features: int, epochs: int = 15, lr: float = 1e-3):
    model = LSTMAutoencoder(n_features)
    opt = torch.optim.Adam(model.parameters(), lr=lr)
    loss_fn = nn.MSELoss()
    X_t = torch.from_numpy(X_train)
    batch_size = 256
    model.train()
    for epoch in range(epochs):
        perm = torch.randperm(X_t.size(0))
        total_loss = 0.0
        for i in range(0, X_t.size(0), batch_size):
            idx = perm[i:i + batch_size]
            batch = X_t[idx]
            opt.zero_grad()
            recon, _ = model(batch)
            loss = loss_fn(recon, batch)
            loss.backward()
            opt.step()
            total_loss += loss.item() * batch.size(0)
        print(f"  [torch autoencoder] epoch {epoch+1}/{epochs} - mse: {total_loss/X_t.size(0):.5f}")
    return model


def score_torch_autoencoder(model, X: np.ndarray):
    model.eval()
    with torch.no_grad():
        X_t = torch.from_numpy(X.astype(np.float32))
        recon, embed = model(X_t)
        err = ((recon - X_t) ** 2).mean(dim=(1, 2)).numpy()
    return err, embed.numpy()


# --------------------------------------------------------------------------- #
# Sklearn fallback backend
# --------------------------------------------------------------------------- #

def train_sklearn_backend(X_train_flat: np.ndarray):
    ae = MLPRegressor(
        hidden_layer_sizes=(48, 16, 48),
        activation="relu",
        max_iter=300,
        random_state=42,
        early_stopping=True,
        n_iter_no_change=10,
    )
    ae.fit(X_train_flat, X_train_flat)

    iso = IsolationForest(
        n_estimators=200, contamination=0.02, random_state=42, n_jobs=-1
    )
    iso.fit(X_train_flat)
    return ae, iso


def score_sklearn_backend(ae, iso, X_flat: np.ndarray):
    recon = ae.predict(X_flat)
    recon_err = np.mean((recon - X_flat) ** 2, axis=1)
    iso_score = -iso.score_samples(X_flat)  # higher = more anomalous
    return recon_err, iso_score


def to_unit_scale(arr: np.ndarray) -> np.ndarray:
    ranks = pd.Series(arr).rank(pct=True).to_numpy()
    return ranks


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", default="../artifacts/events_features.csv")
    ap.add_argument("--out", dest="out", default="../artifacts/events_scored.csv")
    ap.add_argument("--model-out", dest="model_out", default="../artifacts/baseline_model")
    ap.add_argument("--epochs", type=int, default=15)
    args = ap.parse_args()

    df = pd.read_csv(args.inp, parse_dates=["timestamp"])
    feature_cols = FEATURE_COLUMNS
    os.makedirs(args.model_out, exist_ok=True)

    scaler = StandardScaler()
    df_scaled = df.copy()
    df_scaled[feature_cols] = scaler.fit_transform(df[feature_cols])

    print("Building causal sliding-window sequences...")
    X, event_ids = build_sequences(df_scaled, feature_cols, WINDOW_SIZE)

    # Train ONLY on normal traffic (one-class assumption per brief)
    normal_mask = (df["label"] == "normal").to_numpy()
    X_train = X[normal_mask]

    backend_used = "torch_lstm_autoencoder" if TORCH_AVAILABLE else "sklearn_mlp_autoencoder+isolation_forest"
    print(f"Backend: {backend_used}  |  train sequences (normal only): {len(X_train):,}")

    if TORCH_AVAILABLE:
        model = train_torch_autoencoder(X_train.astype(np.float32), n_features=len(feature_cols), epochs=args.epochs)
        recon_err, embeddings = score_torch_autoencoder(model, X.astype(np.float32))
        anomaly_score = to_unit_scale(recon_err)
        torch.save(model.state_dict(), os.path.join(args.model_out, "lstm_autoencoder.pt"))
        embed_dim = embeddings.shape[1]
    else:
        X_train_flat = X_train.reshape(X_train.shape[0], -1)
        X_flat = X.reshape(X.shape[0], -1)
        ae, iso = train_sklearn_backend(X_train_flat)
        recon_err, iso_score = score_sklearn_backend(ae, iso, X_flat)
        # ensemble: rank-average of reconstruction error and isolation-forest score
        anomaly_score = 0.5 * to_unit_scale(recon_err) + 0.5 * to_unit_scale(iso_score)
        # "embedding" for the sklearn path = activations of the bottleneck layer,
        # approximated here via the hidden layer weights applied to input (fast, no extra deps)
        hidden_w = ae.coefs_[0]
        embeddings = np.tanh(X_flat @ hidden_w)[:, :16]
        embed_dim = embeddings.shape[1]
        with open(os.path.join(args.model_out, "autoencoder.pkl"), "wb") as f:
            pickle.dump(ae, f)
        with open(os.path.join(args.model_out, "isolation_forest.pkl"), "wb") as f:
            pickle.dump(iso, f)

    with open(os.path.join(args.model_out, "scaler.pkl"), "wb") as f:
        pickle.dump(scaler, f)

    out = df.copy()
    out["reconstruction_error"] = recon_err
    out["anomaly_score"] = anomaly_score  # in [0,1], higher = more anomalous
    for d in range(embed_dim):
        out[f"embed_{d}"] = embeddings[:, d]

    meta = {
        "backend": backend_used,
        "window_size": WINDOW_SIZE,
        "feature_columns": feature_cols,
        "embed_dim": embed_dim,
        "trained_on_normal_events": int(normal_mask.sum()),
    }
    with open(os.path.join(args.model_out, "meta.json"), "w") as f:
        json.dump(meta, f, indent=2)

    out.to_csv(args.out, index=False)

    # quick sanity check: anomaly score should separate labels
    print("\nMean anomaly_score by label:")
    print(out.groupby("label")["anomaly_score"].mean())
    print(f"\nSaved scored dataset -> {args.out}")
    print(f"Saved model artifacts -> {args.model_out}/")


if __name__ == "__main__":
    main()
