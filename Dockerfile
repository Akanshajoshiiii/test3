FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Build the dataset + models at image-build time so the container starts
# instantly with real, pre-scored data. Re-run data/generator.py + the ml/
# scripts (or POST /api/train) to refresh with new synthetic data.
RUN cd data && python generator.py --n-events 70000 --n-entities 600 --attack-rate 0.03 --days 60 --seed 42 \
        --out ../artifacts/events.csv --profiles-out ../artifacts/entity_profiles.json \
    && cd ../ml && python features.py --in ../artifacts/events.csv --out ../artifacts/events_features.csv \
    && python train_baseline.py --in ../artifacts/events_features.csv --out ../artifacts/events_scored.csv --model-out ../artifacts/baseline_model \
    && python train_classifier.py --in ../artifacts/events_scored.csv --model-out ../artifacts/classifier_model.pkl --metrics-out ../artifacts/classifier_metrics.json \
    && python explain.py --in ../artifacts/events_scored.csv --classifier ../artifacts/classifier_model.pkl --out ../artifacts/alerts.csv

EXPOSE 8000
WORKDIR /app/backend
CMD ["python", "app.py"]
