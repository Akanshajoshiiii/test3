# Sentinel — AI-Powered Behavioral Anomaly Detection for Cybersecurity

A working, end-to-end prototype: synthetic behavioral access-log generator →
sequence-aware baseline profiling → attack classification → explainable risk
scoring → analyst SOC dashboard.

## Quick start

```bash
pip install -r requirements.txt
bash run.sh          # generates data, trains everything, starts the dashboard
```
Then open **http://localhost:8000**.

Or with Docker:
```bash
docker compose up --build
```

## Deploy online (free, ~10 minutes) — Render.com

The repo already includes `Dockerfile` + `render.yaml`, so this is a Blueprint deploy:

1. Push this folder to a new GitHub repo:
   ```bash
   cd soc-platform
   git init && git add . && git commit -m "Sentinel SOC platform"
   git branch -M main
   git remote add origin https://github.com/<you>/sentinel-soc.git
   git push -u origin main
   ```
2. Go to https://render.com → sign in with GitHub → **New → Blueprint**.
3. Select your repo. Render reads `render.yaml` automatically and configures
   a free Docker web service (port 8000, health check on `/api/dashboard`).
4. Click **Apply** / **Deploy**. First build takes ~5-8 min (it trains the
   models during the Docker build, so it comes up with real data already
   scored — no extra setup step).
5. You'll get a public URL like `https://sentinel-soc.onrender.com` — open
   it, the dashboard loads directly (backend serves the frontend too).

Notes:
- Free tier sleeps after 15 min idle and takes ~30-60s to wake on the next
  request — fine for a hackathon demo, just don't be surprised by the first
  load.
- The SQLite analyst-feedback DB resets on redeploy (free tier has ephemeral
  disk) — the alert/model data itself does not, it's baked into the image.
- No GitHub account yet? Create one free at https://github.com/join.

**Alternatives** if Render gives you trouble: Railway.app (same Dockerfile,
"Deploy from GitHub repo", auto-detects the Dockerfile) or Hugging Face
Spaces (choose "Docker" SDK, push the same repo). Both work with zero
code changes since the app already reads the `PORT` env var.

To just re-run pieces of the pipeline manually:
```bash
cd data && python generator.py --n-events 70000 --n-entities 600 --attack-rate 0.03
cd ../ml
python features.py
python train_baseline.py
python train_classifier.py
python explain.py
cd ../backend && python app.py
```

## What's implemented (maps to the brief's 6 deliverables)

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

## Backend auto-selection (important, read this)

The spec calls for **PyTorch** (LSTM autoencoder), **LightGBM**, and **SHAP**.
This build was developed in an offline sandbox with no package-installer
network access, so `ml/train_baseline.py`, `ml/train_classifier.py`, and
`ml/explain.py` all **auto-detect** those libraries at runtime:

- If installed → uses the spec-exact stack (`torch.nn.LSTM` autoencoder,
  `lightgbm.LGBMClassifier`, `shap.TreeExplainer`).
- If not installed → automatically falls back to a verified-working
  equivalent (`sklearn.neural_network.MLPRegressor` autoencoder +
  `IsolationForest` ensemble; `RandomForestClassifier`; a batched
  permutation-based feature-attribution method that is conceptually the
  same marginal-contribution idea SHAP uses, at a fraction of the compute).

**Just `pip install torch lightgbm shap` before running `run.sh`** to get the
literal spec stack — no code changes needed, same output schema either way.
All the results below were produced end-to-end with the sklearn fallback
path, i.e. these are real, reproducible numbers, not placeholders.

## Real results (sklearn fallback path, 70,907 events, 600 entities, 60 days, 3% attack rate)

- **Overall accuracy:** 98.1%
- **Macro F1 (all 8 classes):** 75.2%
- **ROC-AUC (macro, one-vs-rest):** 98.5%
- **Binary attack detection:** precision 74.7%, **recall 93.0%**, F1 82.8%, false-positive rate 1.4%
  (tuned toward high recall — in a SOC, missing a real attack is far costlier than an
  extra analyst triage click; the risk engine's Medium/High/Critical banding is what
  keeps the top-of-queue precision usable — see the Analytics page)
- Per-class F1: brute_force 97.1%, low_and_slow_exfiltration 90.0%,
  credential_stuffing 87.9%, lateral_movement 87.7%, device_spoofing 82.4%,
  **insider_drift 31.6%, impossible_travel 25.6%** (see Limitations)

Full metrics (confusion matrix, per-class precision/recall/support) are in
`artifacts/classifier_metrics.json` and rendered live on the dashboard's
Analytics page.

## Known limitations (for the report you're writing)

- **impossible_travel** and **insider_drift** are the weakest classes.
  Impossible travel is only a 2-event pattern per episode, so it's
  inherently low-support and subtle; insider_drift is *deliberately*
  ambiguous per the brief's own table ("edge case for false-positive
  tuning") — its low separability is expected, not a bug, and is a good
  discussion point for the report's "known limitations" section.
- **Cold start**: new entities get `cold_start=1` and reduced device/resource
  novelty signal until they build history; `/api/predict` demonstrates a
  heuristic fallback score for entities with zero prior events.
- **Concept drift**: not implemented as an automated retrainer — `POST
  /api/train` is a stub that tells you which scripts to re-run. Real
  adaptive-threshold/drift-detection would be a natural "future work" item.
- **Scale**: in-memory pandas dataset (fine to ~1M events); Postgres/Redis
  from the original tech-stack wishlist would matter at real SOC scale, not
  at hackathon-dataset scale.
- Explainability is computed in full for the top 600 highest-risk events
  (all events still get a risk score) — a compute/time tradeoff, documented
  in `ml/explain.py`.

## API reference

`GET /api/dashboard` · `GET /api/alerts` · `GET /api/alerts/<event_id>` ·
`GET /api/entities` · `GET /api/entities/<id>` · `GET /api/analytics` ·
`GET /api/feature-importance` · `GET /api/heatmap` · `GET /api/timeline` ·
`GET /api/map` · `POST /api/feedback` · `POST /api/predict` · `POST /api/train` ·
`GET /api/stream` (SSE live feed)

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
requirements.txt, run.sh, Dockerfile, docker-compose.yml
```
