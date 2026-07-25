"""
Risk Engine + Explainability Layer
======================================
Turns (features + anomaly_score + attack_type prediction) into an
analyst-facing ALERT: a 0-100 risk score, a risk level, per-feature
contribution (SHAP if available, else permutation-based feature attribution
as an offline-friendly equivalent), and a natural-language explanation.

Risk score composition (0-100):
    35% anomaly_score            (Stage-1 behavioral deviation)
    20% attack_probability       (Stage-2 classifier confidence, non-normal)
    15% geo_risk                 (impossible-travel velocity + high-risk geo)
    10% auth_risk                (auth method change, failed logins)
    10% device_risk              (device novelty / trust)
    10% historical_behavior_risk (cold start, resource novelty, sensitivity)

Risk levels: Low <40, Medium 40-64, High 65-84, Critical 85-100.
"""

from __future__ import annotations

import json
import pickle

import numpy as np
import pandas as pd

from features import FEATURE_COLUMNS
from train_classifier import CLASSES, get_model_feature_columns

try:
    import shap
    SHAP_AVAILABLE = True
except ImportError:
    SHAP_AVAILABLE = False

MITRE_MAP = {
    "brute_force": {"tactic": "Credential Access", "technique": "T1110 - Brute Force"},
    "credential_stuffing": {"tactic": "Credential Access", "technique": "T1110.004 - Credential Stuffing"},
    "impossible_travel": {"tactic": "Initial Access", "technique": "T1078 - Valid Accounts (anomalous geo)"},
    "device_spoofing": {"tactic": "Defense Evasion", "technique": "T1036 - Masquerading (device spoofing)"},
    "lateral_movement": {"tactic": "Lateral Movement", "technique": "T1021 - Remote Services"},
    "low_and_slow_exfiltration": {"tactic": "Exfiltration", "technique": "T1030 - Data Transfer Size Limits"},
    "insider_drift": {"tactic": "Collection", "technique": "T1213 - Data from Information Repositories"},
    "normal": {"tactic": "-", "technique": "-"},
}

RECOMMENDED_RESPONSE = {
    "brute_force": "Block source IP, force password reset, enable MFA if not already active.",
    "credential_stuffing": "Block attacker IP range, force reset for all targeted accounts, enable MFA.",
    "impossible_travel": "Suspend session, verify identity via secondary channel, review recent activity.",
    "device_spoofing": "Quarantine device, revoke session tokens, require device re-enrollment.",
    "lateral_movement": "Isolate entity's access, review accessed resources, escalate to IR team.",
    "low_and_slow_exfiltration": "Restrict data-export permissions, audit accessed sensitive resources, escalate to IR team.",
    "insider_drift": "Review with entity's manager; may be legitimate role change -- confirm before action.",
    "normal": "No action required.",
}


def risk_level(score: float) -> str:
    if score >= 85:
        return "Critical"
    if score >= 65:
        return "High"
    if score >= 40:
        return "Medium"
    return "Low"


def compute_risk_score(row: pd.Series, attack_proba_non_normal: float) -> float:
    anomaly = row["anomaly_score"] * 100
    attack_prob = attack_proba_non_normal * 100
    geo_risk = min(100, (row["geo_velocity_kmh"] / 900.0) * 100)
    auth_risk = min(100, row["authentication_change"] * 60 + min(row["failed_login_count_1h"], 5) * 8)
    device_risk = min(100, row["device_novelty"] * 70 + (1 - row["device_trust_score"]) * 30)
    hist_risk = min(100, row["cold_start"] * 40 + row["resource_novelty"] * 30
                     + row["sensitive_resource_flag"] * 30)

    score = (
        0.35 * anomaly + 0.20 * attack_prob + 0.15 * geo_risk
        + 0.10 * auth_risk + 0.10 * device_risk + 0.10 * hist_risk
    )
    score = float(np.clip(score, 0, 100))
    # stretch curve: pushes strong composite signals toward the High/Critical
    # bands (matches how SOC risk engines are tuned in practice) without
    # changing the RELATIVE ranking used for the analyst alert queue.
    return float(100 * (score / 100) ** 0.65)


FEATURE_LABELS = {
    "hour_of_login": "unusual login hour",
    "is_weekend": "weekend login",
    "off_hours": "off-hours access",
    "geo_distance_from_prev_km": "large distance from previous login",
    "geo_velocity_kmh": "implausible travel speed between logins",
    "time_since_last_login_s": "unusual gap since last login",
    "session_duration_deviation": "session duration far from entity's norm",
    "failed_login_count_1h": "repeated failed logins in the last hour",
    "device_novelty": "login from a previously unseen device",
    "resource_novelty": "access to a previously unseen resource",
    "authentication_change": "authentication method changed from the norm",
    "unique_resource_count": "unusually broad resource access",
    "login_freq_24h": "abnormal login frequency",
    "sensitive_resource_flag": "access to a sensitive resource",
    "sensitive_hits_7d": "rising access to sensitive resources this week",
    "command_entropy": "unusual command pattern diversity",
    "device_trust_score": "low device trust",
    "ip_reputation_score": "elevated IP reputation risk",
    "behavior_deviation_score": "overall behavioral deviation from baseline",
    "cold_start": "little to no history for this entity",
    "login_failed": "failed login attempt",
    "anomaly_score": "high behavioral anomaly score from the baseline model",
    "reconstruction_error": "sequence pattern diverges from the entity's learned normal behavior",
}


def explain_with_permutation(model, X_row: np.ndarray, feat_cols: list[str], class_idx: int,
                              baseline: np.ndarray, top_k: int = 4) -> list[dict]:
    """
    Offline-friendly feature-attribution fallback (used when the `shap`
    package isn't installed): for each feature, perturb it back to the
    dataset's median ("normal") value and measure the drop in predicted
    probability for the predicted class. Larger drop = that feature
    contributed more to the prediction -- conceptually the same idea as
    SHAP's marginal-contribution framing, at a fraction of the compute cost.
    """
    n = len(feat_cols)
    batch = np.tile(X_row, (n + 1, 1))  # row 0 = original, rows 1..n = one feature perturbed each
    for i in range(n):
        batch[i + 1, i] = baseline[i]
    proba_batch = model.predict_proba(batch)[:, class_idx]
    base_proba = proba_batch[0]
    contributions = [(feat_cols[i], base_proba - proba_batch[i + 1]) for i in range(n)]
    contributions.sort(key=lambda x: abs(x[1]), reverse=True)
    total = sum(abs(c[1]) for c in contributions) + 1e-9
    top = contributions[:top_k]
    return [{"feature": c[0], "contribution_pct": round(100 * abs(c[1]) / total, 1),
              "direction": "increases risk" if c[1] > 0 else "decreases risk"} for c in top]


def build_explanation_text(attack_type: str, top_features: list[dict], risk: str) -> str:
    if attack_type == "normal" and risk == "Low":
        return "This event is consistent with the entity's established behavioral baseline."
    reasons = [FEATURE_LABELS.get(f["feature"], f["feature"]) for f in top_features if f["direction"] == "increases risk"]
    reasons = reasons[:4]
    attack_label = attack_type.replace("_", " ")
    if not reasons:
        return f"This event is flagged as {risk.lower()} risk, resembling {attack_label} activity based on overall behavioral deviation."
    reason_text = "; ".join(reasons)
    return f"This login is considered {risk.lower()} risk, resembling {attack_label} activity, because of: {reason_text}."


def score_dataset(scored_path: str, classifier_path: str, out_path: str, top_k: int = 4):
    df = pd.read_csv(scored_path, parse_dates=["timestamp"])
    with open(classifier_path, "rb") as f:
        bundle = pickle.load(f)
    model, classes, feat_cols = bundle["model"], bundle["classes"], bundle["feature_columns"]

    X = df[feat_cols].to_numpy(dtype=np.float32)
    proba = model.predict_proba(X)
    pred_idx = proba.argmax(axis=1)
    pred_class = [classes[i] for i in pred_idx]
    normal_idx = classes.index("normal")
    attack_proba = 1.0 - proba[:, normal_idx]
    confidence = proba.max(axis=1)

    baseline_vec = np.median(X, axis=0)

    explainer = None
    if SHAP_AVAILABLE and bundle["backend"] == "lightgbm":
        explainer = shap.TreeExplainer(model)

    alerts = []
    # only compute (and store) full explanations for the events an analyst
    # would actually triage -- top of the risk queue -- to keep this fast;
    # everything still gets a risk score.
    risk_scores = np.zeros(len(df))
    for i in range(len(df)):
        risk_scores[i] = compute_risk_score(df.iloc[i], attack_proba[i])

    df["predicted_attack_type"] = pred_class
    df["prediction_confidence"] = np.round(confidence, 4)
    df["attack_probability"] = np.round(attack_proba, 4)
    df["risk_score"] = np.round(risk_scores, 1)
    df["risk_level"] = [risk_level(s) for s in risk_scores]

    top_n_idx = np.argsort(-risk_scores)[: min(600, len(df))]
    explanations = {}
    for i in top_n_idx:
        row_x = X[i]
        cls_idx = pred_idx[i]
        if explainer is not None:
            shap_vals = explainer.shap_values(row_x.reshape(1, -1))
            vals = shap_vals[cls_idx][0] if isinstance(shap_vals, list) else shap_vals[0]
            pairs = list(zip(feat_cols, vals))
            pairs.sort(key=lambda x: abs(x[1]), reverse=True)
            total = sum(abs(v) for _, v in pairs) + 1e-9
            top_feats = [{"feature": f, "contribution_pct": round(100 * abs(v) / total, 1),
                          "direction": "increases risk" if v > 0 else "decreases risk"} for f, v in pairs[:top_k]]
        else:
            top_feats = explain_with_permutation(model, row_x, feat_cols, cls_idx, baseline_vec, top_k)

        mitre = MITRE_MAP.get(pred_class[i], MITRE_MAP["normal"])
        explanations[df.iloc[i]["event_id"]] = {
            "top_features": top_feats,
            "explanation_text": build_explanation_text(pred_class[i], top_feats, risk_level(risk_scores[i])),
            "mitre_tactic": mitre["tactic"],
            "mitre_technique": mitre["technique"],
            "recommended_response": RECOMMENDED_RESPONSE.get(pred_class[i], "Review manually."),
        }

    df["explanation"] = df["event_id"].map(lambda e: explanations.get(e, {}).get("explanation_text", ""))
    df["mitre_tactic"] = df["event_id"].map(lambda e: explanations.get(e, {}).get("mitre_tactic", "-"))
    df["mitre_technique"] = df["event_id"].map(lambda e: explanations.get(e, {}).get("mitre_technique", "-"))
    df["recommended_response"] = df["event_id"].map(lambda e: explanations.get(e, {}).get("recommended_response", ""))
    df["top_features_json"] = df["event_id"].map(lambda e: json.dumps(explanations.get(e, {}).get("top_features", [])))

    df.to_csv(out_path, index=False)
    explain_backend = "shap" if explainer is not None else "permutation_attribution"
    print(f"Explainability backend: {explain_backend}")
    print(f"Scored + explained {len(df):,} events -> {out_path}")
    print(f"Full explanations computed for top {len(top_n_idx):,} highest-risk events")
    return df


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", default="../artifacts/events_scored.csv")
    ap.add_argument("--classifier", dest="clf", default="../artifacts/classifier_model.pkl")
    ap.add_argument("--out", dest="out", default="../artifacts/alerts.csv")
    args = ap.parse_args()
    score_dataset(args.inp, args.clf, args.out)
