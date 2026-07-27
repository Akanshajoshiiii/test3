
# Sentinel — AI-Powered Behavioral Anomaly Detection for Cybersecurity

## What's implemented 

| # | Deliverable | File(s) |
|---|---|---|
| 1 | Synthetic data generator, documented assumptions + attack taxonomy | `data/generator.py` |
| 2 | Baseline "normal" behavior profiling | `ml/train_baseline.py` (per-entity profiles + trained model) |
| 3 | Sequence-aware detection model | `ml/train_baseline.py` (windowed sequence autoencoder) |
| 4 | Attack classification (not just anomalous — which category) | `ml/train_classifier.py` |
| 5 | Explainability layer (per-alert feature attribution) | `ml/explain.py` |
| 6 | Analyst-facing dashboard | `frontend/` + `backend/app.py` |

## Architecture

```
generator.py  →  events.csv (labels retained, hidden from the model at inference)
     │
     ▼
features.py   →  causal, per-entity rolling features (hour, geo-velocity, device/
                  resource novelty, failed-login rate, entropy, sensitivity, ...)
                  — computed only from an entity's HISTORY, so it's streaming-safe
     │
     ▼
train_baseline.py   Stage 1: trained ONLY on normal traffic (one-class).
                     Sliding window of last 5 events per entity → sequence
                     autoencoder → reconstruction error → anomaly_score [0,1]
     │
     ▼
train_classifier.py Stage 2: features + anomaly_score + embedding →
                     multi-class classifier → attack_type ∈ {normal, brute_force,
                     credential_stuffing, impossible_travel, device_spoofing,
                     lateral_movement, low_and_slow_exfiltration, insider_drift}
     │
     ▼
explain.py     Risk engine (weighted 0–100 composite) + per-alert feature
               attribution + natural-language explanation + MITRE ATT&CK
               mapping + recommended response
     │
     ▼
backend/app.py  Flask API serving dashboard/alerts/entities/analytics/map/
                feedback/predict endpoints
     │
     ▼
frontend/       Dark SOC dashboard: Home (KPIs, live Threat Radar, risk
                distribution, timeline, heatmap), Alerts (ranked queue +
                explainability drawer + feedback buttons), Entities (profile +
                history + risk trend), Threat Map (Leaflet), Analytics
                (confusion matrix, ROC/AUC, per-class metrics, feature importance)
```


## Results (sklearn fallback path, 70,907 events, 600 entities, 60 days, 3% attack rate)

- **Overall accuracy:** 98.1%
- **Macro F1 (all 8 classes):** 75.2%
- **ROC-AUC (macro, one-vs-rest):** 98.5%
- **Binary attack detection:** precision 74.7%, **recall 93.0%**, F1 82.8%, false-positive rate 1.4%
  (tuned toward high recall — in a SOC, missing a real attack is far costlier than an
  extra analyst triage click; the risk engine's Medium/High/Critical banding is what
  keeps the top-of-queue precision usable)
- Per-class F1: brute_force 97.1%, low_and_slow_exfiltration 90.0%,
  credential_stuffing 87.9%, lateral_movement 87.7%, device_spoofing 82.4%,
  **insider_drift 31.6%, impossible_travel 25.6%** 




## Repo layout

```
data/generator.py         synthetic log generator
ml/features.py             causal feature engineering
ml/train_baseline.py       Stage 1 — behavioral baseline / anomaly detection
ml/train_classifier.py     Stage 2 — attack classification
ml/explain.py              risk engine + explainability
backend/app.py             Flask API + serves the dashboard
frontend/                  dashboard (HTML/CSS/vanilla JS, Chart.js, Leaflet)
artifacts/                 generated dataset, trained models, alerts, metrics
                            (alerts.csv is shipped gzip-compressed as
                            alerts.csv.gz to stay under file-upload size
                            limits — backend/app.py reads either automatically;
                            run.sh/Docker regenerate a plain .csv locally)
requirements.txt, run.sh, Dockerfile, docker-compose.yml
```
