#!/usr/bin/env bash
# Runs the full pipeline end-to-end: generate data -> features -> baseline
# model -> classifier -> risk engine/explainability -> starts the backend
# (which also serves the dashboard at http://localhost:8000).
set -e

echo "== [1/5] Installing dependencies =="
pip install -r requirements.txt

echo "== [2/5] Generating synthetic dataset =="
cd data
python generator.py --n-events 70000 --n-entities 600 --attack-rate 0.03 --days 60 --seed 42 \
    --out ../artifacts/events.csv --profiles-out ../artifacts/entity_profiles.json
cd ..

echo "== [3/5] Feature engineering =="
cd ml
python features.py --in ../artifacts/events.csv --out ../artifacts/events_features.csv

echo "== [4/5] Training baseline (Stage 1) + classifier (Stage 2) =="
python train_baseline.py --in ../artifacts/events_features.csv --out ../artifacts/events_scored.csv --model-out ../artifacts/baseline_model
python train_classifier.py --in ../artifacts/events_scored.csv --model-out ../artifacts/classifier_model.pkl --metrics-out ../artifacts/classifier_metrics.json
python explain.py --in ../artifacts/events_scored.csv --classifier ../artifacts/classifier_model.pkl --out ../artifacts/alerts.csv
cd ..

echo "== [5/5] Starting backend + dashboard on http://localhost:8000 =="
cd backend
python app.py
