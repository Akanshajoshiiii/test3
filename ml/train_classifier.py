"""
Stage 2 -- Attack Classification
===================================
Takes the Stage-1 output (behavioral features + embedding + anomaly_score)
and classifies WHICH attack category an event resembles (or "normal").

Backend: LightGBM if installed (spec-preferred, handles class imbalance well
via class_weight), else sklearn's GradientBoostingClassifier /
RandomForestClassifier ensemble as an offline-friendly fallback with
comparable behavior on tabular data.

Handles the brief's "extreme class imbalance" requirement via:
    - class_weight="balanced" (sklearn) / is_unbalance (lightgbm)
    - stratified train/test split
    - reporting precision/recall/F1 per class + macro, not just accuracy
"""

from __future__ import annotations

import argparse
import json
import pickle

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report, confusion_matrix, f1_score,
    precision_recall_fscore_support, roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import label_binarize

from features import FEATURE_COLUMNS

try:
    import lightgbm as lgb
    LGBM_AVAILABLE = True
except ImportError:
    LGBM_AVAILABLE = False

CLASSES = [
    "normal", "brute_force", "credential_stuffing", "impossible_travel",
    "device_spoofing", "lateral_movement", "low_and_slow_exfiltration",
    "insider_drift",
]


def get_model_feature_columns(df: pd.DataFrame) -> list[str]:
    embed_cols = sorted([c for c in df.columns if c.startswith("embed_")],
                         key=lambda c: int(c.split("_")[1]))
    return FEATURE_COLUMNS + ["anomaly_score", "reconstruction_error"] + embed_cols


def train_lgbm(X_train, y_train, n_classes):
    model = lgb.LGBMClassifier(
        objective="multiclass",
        num_class=n_classes,
        n_estimators=300,
        learning_rate=0.05,
        max_depth=6,
        class_weight="balanced",
        random_state=42,
        verbosity=-1,
    )
    model.fit(X_train, y_train)
    return model


def train_sklearn_fallback(X_train, y_train):
    model = RandomForestClassifier(
        n_estimators=140,
        max_depth=11,
        class_weight="balanced_subsample",
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_train, y_train)
    return model


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", default="../artifacts/events_scored.csv")
    ap.add_argument("--model-out", dest="model_out", default="../artifacts/classifier_model.pkl")
    ap.add_argument("--metrics-out", dest="metrics_out", default="../artifacts/classifier_metrics.json")
    args = ap.parse_args()

    df = pd.read_csv(args.inp, parse_dates=["timestamp"])
    feat_cols = get_model_feature_columns(df)

    y = df["attack_type"].replace("none", "normal")
    X = df[feat_cols].to_numpy(dtype=np.float32)

    class_to_idx = {c: i for i, c in enumerate(CLASSES)}
    y_idx = y.map(class_to_idx).to_numpy()

    X_train, X_test, y_train, y_test, idx_train, idx_test = train_test_split(
        X, y_idx, df.index, test_size=0.25, random_state=42, stratify=y_idx
    )

    backend = "lightgbm" if LGBM_AVAILABLE else "sklearn_random_forest"
    print(f"Backend: {backend}")
    if LGBM_AVAILABLE:
        model = train_lgbm(X_train, y_train, n_classes=len(CLASSES))
    else:
        model = train_sklearn_fallback(X_train, y_train)

    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)

    present_classes = sorted(set(y_test) | set(y_pred))
    present_names = [CLASSES[i] for i in present_classes]

    report = classification_report(
        y_test, y_pred, labels=present_classes, target_names=present_names,
        output_dict=True, zero_division=0,
    )
    cm = confusion_matrix(y_test, y_pred, labels=present_classes)

    precision, recall, f1, support = precision_recall_fscore_support(
        y_test, y_pred, labels=present_classes, zero_division=0
    )
    macro_f1 = f1_score(y_test, y_pred, average="macro", zero_division=0)

    # ROC-AUC (one-vs-rest, macro) -- only over classes present in y_test
    try:
        y_test_bin = label_binarize(y_test, classes=present_classes)
        y_proba_present = y_proba[:, present_classes]
        if y_test_bin.shape[1] > 1:
            roc_auc = roc_auc_score(y_test_bin, y_proba_present, average="macro", multi_class="ovr")
        else:
            roc_auc = float("nan")
    except Exception:
        roc_auc = float("nan")

    # Binary (normal vs any-attack) detection metrics -- the headline SOC number
    normal_idx = class_to_idx["normal"]
    y_test_bin_attack = (y_test != normal_idx).astype(int)
    y_pred_bin_attack = (y_pred != normal_idx).astype(int)
    bin_precision, bin_recall, bin_f1, _ = precision_recall_fscore_support(
        y_test_bin_attack, y_pred_bin_attack, average="binary", zero_division=0
    )
    false_positive_rate = (
        ((y_pred_bin_attack == 1) & (y_test_bin_attack == 0)).sum()
        / max((y_test_bin_attack == 0).sum(), 1)
    )
    accuracy = float((y_pred == y_test).mean())

    metrics = {
        "backend": backend,
        "n_train": int(len(X_train)),
        "n_test": int(len(X_test)),
        "overall_accuracy": accuracy,
        "macro_f1": float(macro_f1),
        "roc_auc_macro_ovr": float(roc_auc) if roc_auc == roc_auc else None,  # NaN check
        "binary_attack_detection": {
            "precision": float(bin_precision),
            "recall": float(bin_recall),
            "f1": float(bin_f1),
            "false_positive_rate": float(false_positive_rate),
        },
        "per_class_report": report,
        "confusion_matrix": cm.tolist(),
        "confusion_matrix_labels": present_names,
    }

    with open(args.metrics_out, "w") as f:
        json.dump(metrics, f, indent=2)

    with open(args.model_out, "wb") as f:
        pickle.dump({"model": model, "classes": CLASSES, "feature_columns": feat_cols, "backend": backend}, f)

    print(f"\nOverall accuracy: {accuracy:.4f}  |  macro F1: {macro_f1:.4f}  |  ROC-AUC (macro OvR): {roc_auc:.4f}")
    print(f"Binary attack-detection -> precision: {bin_precision:.4f}  recall: {bin_recall:.4f}  "
          f"F1: {bin_f1:.4f}  FPR: {false_positive_rate:.4f}")
    print("\nPer-class report:")
    print(pd.DataFrame(report).T.round(3))
    print(f"\nSaved model -> {args.model_out}")
    print(f"Saved metrics -> {args.metrics_out}")


if __name__ == "__main__":
    main()
