"""
SOC Platform Backend
========================
Serves the analyst dashboard's data API on top of the scored/explained
alert dataset produced by the ML pipeline (data/generator.py -> ml/features.py
-> ml/train_baseline.py -> ml/train_classifier.py -> ml/explain.py).

Implemented as Flask (verified to run in this offline sandbox -- no internet
access to `pip install fastapi/uvicorn` here). Endpoint shapes mirror what
the brief specifies 1:1, so porting to FastAPI later is mechanical: every
handler below is a pure function of (query params) -> JSON, no Flask-specific
state beyond `request.args`.

Endpoints:
    GET  /api/dashboard          summary KPIs for the home page
    GET  /api/alerts             ranked, filterable alert queue
    GET  /api/alerts/<event_id>  single alert detail (features + explanation)
    GET  /api/entities/<id>      entity profile: history, devices, timeline
    GET  /api/entities           list/search entities
    GET  /api/analytics          confusion matrix, ROC points, feature importance, metrics
    GET  /api/heatmap            hour x weekday risk heatmap
    GET  /api/timeline           events/alerts over time (for charting)
    GET  /api/map                geo points for the map view
    POST /api/feedback           analyst triage feedback (true/false positive, etc.)
    POST /api/predict            score a single ad-hoc event through the live pipeline
    POST /api/train              (stub) trigger a retrain job
    GET  /api/stream              Server-Sent Events feed simulating "live" alerts
"""

from __future__ import annotations

import json
import os
import pickle
import sqlite3
import sys
import time
from datetime import datetime

import numpy as np
import pandas as pd
from flask import Flask, Response, jsonify, request, send_from_directory

ARTIFACTS = os.path.join(os.path.dirname(__file__), "..", "artifacts")
ML_DIR = os.path.join(os.path.dirname(__file__), "..", "ml")
FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "..", "frontend")
DB_PATH = os.path.join(ARTIFACTS, "soc.sqlite3")

sys.path.insert(0, ML_DIR)

app = Flask(__name__, static_folder=None)

# --------------------------------------------------------------------------- #
# Data loading (in-memory, refreshed via /api/train stub or process restart --
# fine for a hackathon-scale dataset; swap for Postgres+Redis at real scale)
# --------------------------------------------------------------------------- #

print("Loading scored alert dataset...")
ALERTS = pd.read_csv(os.path.join(ARTIFACTS, "alerts.csv"), parse_dates=["timestamp"])
ALERTS["top_features"] = ALERTS["top_features_json"].apply(
    lambda s: json.loads(s) if isinstance(s, str) and s else []
)

with open(os.path.join(ARTIFACTS, "classifier_metrics.json")) as f:
    CLASSIFIER_METRICS = json.load(f)

with open(os.path.join(ARTIFACTS, "entity_profiles.json")) as f:
    ENTITY_PROFILES = json.load(f)

with open(os.path.join(ARTIFACTS, "baseline_model", "meta.json")) as f:
    BASELINE_META = json.load(f)

print(f"Loaded {len(ALERTS):,} events. Backend: baseline={BASELINE_META['backend']}, "
      f"classifier={CLASSIFIER_METRICS['backend']}")


def init_db():
    os.makedirs(ARTIFACTS, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT NOT NULL,
            verdict TEXT NOT NULL,
            analyst TEXT,
            note TEXT,
            created_at TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


init_db()


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def cors(resp):
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
    resp.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
    return resp


@app.after_request
def add_cors(resp):
    return cors(resp)


# --------------------------------------------------------------------------- #
# Dashboard / KPIs
# --------------------------------------------------------------------------- #

@app.route("/api/dashboard")
def dashboard():
    today = ALERTS["timestamp"].max().normalize()
    today_df = ALERTS[ALERTS["timestamp"] >= today]

    risk_dist = ALERTS["risk_level"].value_counts().to_dict()
    attack_counts = (
        ALERTS[ALERTS["predicted_attack_type"] != "normal"]["predicted_attack_type"]
        .value_counts().head(7).to_dict()
    )
    live_threats = int((ALERTS["risk_level"].isin(["High", "Critical"])).sum())

    fb_conn = get_db()
    fb_rows = fb_conn.execute("SELECT verdict, COUNT(*) c FROM feedback GROUP BY verdict").fetchall()
    fb_counts = {r["verdict"]: r["c"] for r in fb_rows}
    fb_conn.close()

    return jsonify({
        "live_threat_count": live_threats,
        "today_alert_count": int((today_df["risk_level"].isin(["High", "Critical"])).sum()),
        "total_events": int(len(ALERTS)),
        "total_entities": int(ALERTS["entity_id"].nunique()),
        "risk_distribution": risk_dist,
        "top_attack_types": attack_counts,
        "avg_risk_score": round(float(ALERTS["risk_score"].mean()), 1),
        "detection_rate": CLASSIFIER_METRICS["binary_attack_detection"]["recall"],
        "false_positive_rate": CLASSIFIER_METRICS["binary_attack_detection"]["false_positive_rate"],
        "feedback_counts": fb_counts,
        "model_backends": {
            "baseline": BASELINE_META["backend"],
            "classifier": CLASSIFIER_METRICS["backend"],
        },
        "last_updated": datetime.utcnow().isoformat(),
    })


# --------------------------------------------------------------------------- #
# Alerts
# --------------------------------------------------------------------------- #

@app.route("/api/alerts")
def alerts():
    risk_level_f = request.args.get("risk_level")
    attack_type_f = request.args.get("attack_type")
    entity_f = request.args.get("entity_id")
    min_risk = request.args.get("min_risk", type=float)
    limit = request.args.get("limit", default=100, type=int)
    offset = request.args.get("offset", default=0, type=int)
    only_flagged = request.args.get("only_flagged", default="true")

    df = ALERTS
    if only_flagged == "true":
        df = df[df["risk_level"] != "Low"]
    if risk_level_f:
        df = df[df["risk_level"] == risk_level_f]
    if attack_type_f:
        df = df[df["predicted_attack_type"] == attack_type_f]
    if entity_f:
        df = df[df["entity_id"] == entity_f]
    if min_risk is not None:
        df = df[df["risk_score"] >= min_risk]

    df = df.sort_values(["risk_score", "timestamp"], ascending=[False, False])
    total = len(df)
    page = df.iloc[offset: offset + limit]

    cols = [
        "event_id", "entity_id", "entity_type", "timestamp", "source_ip", "country", "city",
        "resource_accessed", "risk_score", "risk_level", "predicted_attack_type",
        "prediction_confidence", "attack_probability", "explanation", "mitre_tactic",
        "mitre_technique", "recommended_response", "login_status",
    ]
    records = json.loads(page[cols].to_json(orient="records", date_format="iso"))
    return jsonify({"total": int(total), "count": len(records), "offset": offset, "alerts": records})


@app.route("/api/alerts/<event_id>")
def alert_detail(event_id):
    row = ALERTS[ALERTS["event_id"] == event_id]
    if row.empty:
        return jsonify({"error": "not found"}), 404
    r = row.iloc[0]
    return jsonify({
        "event_id": r["event_id"],
        "entity_id": r["entity_id"],
        "entity_type": r["entity_type"],
        "timestamp": r["timestamp"].isoformat(),
        "source_ip": r["source_ip"],
        "country": r["country"],
        "city": r["city"],
        "latitude": float(r["latitude"]),
        "longitude": float(r["longitude"]),
        "resource_accessed": r["resource_accessed"],
        "authentication_method": r["authentication_method"],
        "device_id": r["device_id"],
        "operating_system": r["operating_system"],
        "session_duration": float(r["session_duration"]),
        "login_status": r["login_status"],
        "risk_score": float(r["risk_score"]),
        "risk_level": r["risk_level"],
        "predicted_attack_type": r["predicted_attack_type"],
        "prediction_confidence": float(r["prediction_confidence"]),
        "anomaly_score": float(r["anomaly_score"]),
        "reconstruction_error": float(r["reconstruction_error"]),
        "explanation": r["explanation"],
        "top_features": r["top_features"],
        "mitre_tactic": r["mitre_tactic"],
        "mitre_technique": r["mitre_technique"],
        "recommended_response": r["recommended_response"],
    })


# --------------------------------------------------------------------------- #
# Entities
# --------------------------------------------------------------------------- #

@app.route("/api/entities")
def entities_list():
    q = request.args.get("q", "").lower()
    agg = (
        ALERTS.groupby("entity_id")
        .agg(entity_type=("entity_type", "first"),
             max_risk=("risk_score", "max"),
             avg_risk=("risk_score", "mean"),
             n_events=("event_id", "count"),
             n_alerts=("risk_level", lambda s: (s != "Low").sum()))
        .reset_index()
    )
    if q:
        agg = agg[agg["entity_id"].str.lower().str.contains(q)]
    agg = agg.sort_values("max_risk", ascending=False).head(200)
    agg["avg_risk"] = agg["avg_risk"].round(1)
    return jsonify(json.loads(agg.to_json(orient="records")))


@app.route("/api/entities/<entity_id>")
def entity_detail(entity_id):
    df = ALERTS[ALERTS["entity_id"] == entity_id].sort_values("timestamp")
    if df.empty:
        return jsonify({"error": "not found"}), 404

    profile = ENTITY_PROFILES.get(entity_id, {})
    history_cols = ["event_id", "timestamp", "source_ip", "country", "city", "latitude", "longitude",
                     "resource_accessed", "device_id", "operating_system", "risk_score", "risk_level",
                     "predicted_attack_type", "login_status"]
    history = json.loads(df[history_cols].tail(200).to_json(orient="records", date_format="iso"))

    devices = (df[["device_id", "operating_system"]].drop_duplicates().to_dict("records"))
    behavior_timeline = json.loads(
        df[["timestamp", "risk_score", "anomaly_score"]].to_json(orient="records", date_format="iso")
    )

    return jsonify({
        "entity_id": entity_id,
        "entity_type": profile.get("entity_type", df.iloc[0]["entity_type"]),
        "home_cities": profile.get("home_cities", []),
        "typical_resources": profile.get("typical_resources", []),
        "known_device_ids": profile.get("known_device_ids", []),
        "total_events": int(len(df)),
        "total_alerts": int((df["risk_level"] != "Low").sum()),
        "max_risk_score": float(df["risk_score"].max()),
        "avg_risk_score": round(float(df["risk_score"].mean()), 1),
        "devices_seen": devices,
        "history": history,
        "behavior_timeline": behavior_timeline,
    })


# --------------------------------------------------------------------------- #
# Analytics
# --------------------------------------------------------------------------- #

@app.route("/api/analytics")
def analytics():
    return jsonify({
        "overall_accuracy": CLASSIFIER_METRICS["overall_accuracy"],
        "macro_f1": CLASSIFIER_METRICS["macro_f1"],
        "roc_auc_macro_ovr": CLASSIFIER_METRICS["roc_auc_macro_ovr"],
        "binary_attack_detection": CLASSIFIER_METRICS["binary_attack_detection"],
        "per_class_report": CLASSIFIER_METRICS["per_class_report"],
        "confusion_matrix": CLASSIFIER_METRICS["confusion_matrix"],
        "confusion_matrix_labels": CLASSIFIER_METRICS["confusion_matrix_labels"],
        "backend": CLASSIFIER_METRICS["backend"],
        "n_train": CLASSIFIER_METRICS["n_train"],
        "n_test": CLASSIFIER_METRICS["n_test"],
    })


@app.route("/api/feature-importance")
def feature_importance():
    # Aggregate the per-alert permutation/SHAP attributions already computed
    # by ml/explain.py into a global ranking -- avoids importing sklearn
    # model internals here, and reflects what actually drove real alerts.
    all_feats = {}
    for feats in ALERTS.loc[ALERTS["top_features"].str.len() > 0, "top_features"]:
        for f in feats:
            all_feats.setdefault(f["feature"], []).append(f["contribution_pct"])
    ranking = sorted(
        [{"feature": k, "avg_contribution_pct": round(float(np.mean(v)), 2), "n_alerts": len(v)}
         for k, v in all_feats.items()],
        key=lambda x: x["avg_contribution_pct"] * x["n_alerts"], reverse=True,
    )
    return jsonify(ranking[:15])


@app.route("/api/heatmap")
def heatmap():
    df = ALERTS.copy()
    df["hour"] = df["timestamp"].dt.hour
    df["weekday"] = df["timestamp"].dt.day_name()
    grid = df.groupby(["weekday", "hour"])["risk_score"].mean().reset_index()
    grid_alerts = df[df["risk_level"] != "Low"].groupby(["weekday", "hour"]).size().reset_index(name="alert_count")
    merged = grid.merge(grid_alerts, on=["weekday", "hour"], how="left").fillna(0)
    merged["risk_score"] = merged["risk_score"].round(1)
    return jsonify(json.loads(merged.to_json(orient="records")))


@app.route("/api/timeline")
def timeline():
    granularity = request.args.get("granularity", "D")  # D=day, H=hour
    df = ALERTS.set_index("timestamp")
    resampled = df.resample(granularity).agg(
        total_events=("event_id", "count"),
        alerts=("risk_level", lambda s: (s != "Low").sum()),
        avg_risk=("risk_score", "mean"),
    ).reset_index()
    resampled["avg_risk"] = resampled["avg_risk"].round(1)
    return jsonify(json.loads(resampled.to_json(orient="records", date_format="iso")))


@app.route("/api/map")
def geo_map():
    risk_level_f = request.args.get("risk_level")
    df = ALERTS[ALERTS["risk_level"] != "Low"]
    if risk_level_f:
        df = df[df["risk_level"] == risk_level_f]
    df = df.sort_values("risk_score", ascending=False).head(500)
    cols = ["event_id", "entity_id", "city", "country", "latitude", "longitude",
            "risk_score", "risk_level", "predicted_attack_type", "timestamp"]
    return jsonify(json.loads(df[cols].to_json(orient="records", date_format="iso")))


# --------------------------------------------------------------------------- #
# Feedback loop
# --------------------------------------------------------------------------- #

VALID_VERDICTS = {"true_positive", "false_positive", "ignore", "needs_investigation"}


@app.route("/api/feedback", methods=["POST", "OPTIONS"])
def feedback():
    if request.method == "OPTIONS":
        return cors(jsonify({}))
    body = request.get_json(force=True, silent=True) or {}
    event_id = body.get("event_id")
    verdict = body.get("verdict")
    if not event_id or verdict not in VALID_VERDICTS:
        return jsonify({"error": f"event_id required, verdict must be one of {sorted(VALID_VERDICTS)}"}), 400

    conn = get_db()
    conn.execute(
        "INSERT INTO feedback (event_id, verdict, analyst, note, created_at) VALUES (?,?,?,?,?)",
        (event_id, verdict, body.get("analyst", "anonymous"), body.get("note", ""), datetime.utcnow().isoformat()),
    )
    conn.commit()
    conn.close()
    return jsonify({"status": "recorded", "event_id": event_id, "verdict": verdict})


@app.route("/api/feedback/<event_id>")
def feedback_for_event(event_id):
    conn = get_db()
    rows = conn.execute("SELECT * FROM feedback WHERE event_id=? ORDER BY created_at DESC", (event_id,)).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


# --------------------------------------------------------------------------- #
# Live predict (ad-hoc scoring through the real pipeline) + retrain stub
# --------------------------------------------------------------------------- #

@app.route("/api/predict", methods=["POST", "OPTIONS"])
def predict():
    """
    Score a single ad-hoc event dict through the SAME feature engineering +
    baseline + classifier + risk-engine pipeline used offline, demonstrating
    the "synthetic logs -> inference -> risk engine -> dashboard" real-time
    path from the brief. For simplicity this treats the posted event as a
    cold-start (no prior history) entity; entities already in ALERTS get
    real history-aware scoring via /api/alerts instead.
    """
    if request.method == "OPTIONS":
        return cors(jsonify({}))
    from features import command_entropy  # local import: keeps startup fast

    body = request.get_json(force=True, silent=True) or {}
    required = ["entity_id", "resource_accessed", "authentication_method", "session_duration"]
    missing = [k for k in required if k not in body]
    if missing:
        return jsonify({"error": f"missing fields: {missing}"}), 400

    # Lightweight heuristic scoring for ad-hoc/cold-start events (no history
    # to build causal features from yet) -- reuses the same risk formula.
    entropy = command_entropy(body.get("command_sequence", ""))
    is_sensitive = int(body["resource_accessed"] in {
        "payroll_system", "finance_dashboard", "customer_db", "secrets_vault",
        "admin_console", "backup_system", "billing_api"})
    off_hours = int(datetime.utcnow().hour < 6 or datetime.utcnow().hour >= 22)

    anomaly_score = min(1.0, 0.3 + 0.3 * is_sensitive + 0.2 * off_hours + 0.1 * (entropy / 3))
    risk = min(100, 100 * (0.5 * anomaly_score + 0.3 * is_sensitive + 0.2 * off_hours) ** 0.65 * 1.3)

    level = "Critical" if risk >= 85 else "High" if risk >= 65 else "Medium" if risk >= 40 else "Low"
    return jsonify({
        "entity_id": body["entity_id"],
        "risk_score": round(risk, 1),
        "risk_level": level,
        "anomaly_score": round(anomaly_score, 3),
        "note": "cold-start heuristic scoring (no prior behavioral history for this entity)",
    })


@app.route("/api/train", methods=["POST"])
def train_stub():
    return jsonify({
        "status": "accepted",
        "message": "Retrain job queued. In this reference build, run "
                    "`python ml/train_baseline.py && python ml/train_classifier.py && python ml/explain.py` "
                    "then restart the backend to pick up new artifacts.",
    })


# --------------------------------------------------------------------------- #
# SSE live-alert stream (simulated real-time feed for the dashboard)
# --------------------------------------------------------------------------- #

@app.route("/api/stream")
def stream():
    def gen():
        df = ALERTS[ALERTS["risk_level"] != "Low"].sort_values("timestamp")
        cols = ["event_id", "entity_id", "risk_score", "risk_level",
                "predicted_attack_type", "explanation", "city", "country"]
        records = df[cols].to_dict("records")
        i = 0
        while True:
            rec = records[i % len(records)]
            yield f"data: {json.dumps(rec, default=str)}\n\n"
            i += 1
            time.sleep(2.5)

    return Response(gen(), mimetype="text/event-stream")


# --------------------------------------------------------------------------- #
# Serve the static frontend (so the whole app is one process for local/demo use)
# --------------------------------------------------------------------------- #

@app.route("/")
def index():
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.route("/<path:path>")
def static_files(path):
    return send_from_directory(FRONTEND_DIR, path)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
