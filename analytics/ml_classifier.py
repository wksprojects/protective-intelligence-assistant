"""
Lightweight ML severity classifier for alert triage.

Compares learned classification against the rule-based ORS scoring pipeline:
- Rules baseline:  keyword_weight * 20 (no context)
- Multi-factor:    compute_risk_score() (keyword × frequency × credibility × recency)
- ML classifier:   TF-IDF on alert text + numeric features → LogisticRegression

Evaluation uses leave-one-out cross-validation on the golden EP scenarios,
which is statistically appropriate for small labeled benchmarks (n < 50).
"""

from __future__ import annotations

import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import LeaveOneOut, cross_val_predict
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from analytics.backtesting import GOLDEN_DATASET

NUMERIC_FEATURES = [
    "keyword_weight",
    "source_credibility",
    "frequency_factor",
    "recency_hours",
]
TEXT_FEATURE = "description"
TARGET = "expected_severity"
SEVERITY_LABELS = ["low", "medium", "high", "critical"]


def build_dataset() -> pd.DataFrame:
    """Convert golden scenarios to a DataFrame for ML training/evaluation."""
    return pd.DataFrame(GOLDEN_DATASET)


def build_pipeline() -> Pipeline:
    """Build a sklearn Pipeline: TF-IDF on description + scaled numeric features → LR."""
    preprocessor = ColumnTransformer(
        transformers=[
            (
                "text",
                TfidfVectorizer(
                    max_features=80,
                    ngram_range=(1, 2),
                    stop_words="english",
                    sublinear_tf=True,
                ),
                TEXT_FEATURE,
            ),
            ("numeric", StandardScaler(), NUMERIC_FEATURES),
        ]
    )
    return Pipeline(
        [
            ("preprocessor", preprocessor),
            (
                "classifier",
                LogisticRegression(
                    max_iter=2000,
                    class_weight="balanced",
                    random_state=42,
                    C=0.5,
                    solver="lbfgs",
                ),
            ),
        ]
    )


def _binary_confusion(y_true: pd.Series, y_pred) -> dict:
    """Compute binary escalation confusion (positive = high|critical)."""
    actual = y_true.isin(["high", "critical"])
    predicted = pd.Series(y_pred).isin(["high", "critical"])
    tp = int((predicted & actual).sum())
    fp = int((predicted & ~actual).sum())
    fn = int((~predicted & actual).sum())
    tn = int((~predicted & ~actual).sum())
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn}


def evaluate_loo() -> dict:
    """
    Leave-one-out cross-validation on golden scenarios.

    Returns dict with accuracy, precision, recall, F1, confusion counts,
    and per-scenario predictions for comparison against rules baseline.
    """
    df = build_dataset()
    X = df[NUMERIC_FEATURES + [TEXT_FEATURE]]
    y = df[TARGET]

    pipeline = build_pipeline()
    loo = LeaveOneOut()
    y_pred = cross_val_predict(pipeline, X, y, cv=loo)

    accuracy = float((y_pred == y).mean())

    conf = _binary_confusion(y, y_pred)
    tp, fp, fn = conf["tp"], conf["fp"], conf["fn"]
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    predictions = []
    for i, row in df.iterrows():
        predictions.append(
            {
                "name": row["name"],
                "expected": row[TARGET],
                "predicted": y_pred[i],
                "correct": y_pred[i] == row[TARGET],
            }
        )

    return {
        "n_scenarios": len(df),
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": conf["tn"],
        "predictions": predictions,
        "method": "LOO-CV, TF-IDF(description) + StandardScaler(numeric) → LogisticRegression",
    }


def train_full_model() -> Pipeline:
    """Train on all golden scenarios (for inference use, not evaluation)."""
    df = build_dataset()
    X = df[NUMERIC_FEATURES + [TEXT_FEATURE]]
    y = df[TARGET]
    pipeline = build_pipeline()
    pipeline.fit(X, y)
    return pipeline
