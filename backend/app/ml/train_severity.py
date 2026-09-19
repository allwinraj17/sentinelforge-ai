import os
import joblib
import pandas as pd

from sklearn.compose import ColumnTransformer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report
)
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_validate
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder


BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DATASET_PATH = os.path.join(
    BASE_DIR,
    "dataset",
    "severity_prediction_dataset.csv"
)

MODEL_DIR = os.path.join(
    BASE_DIR,
    "models"
)

MODEL_PATH = os.path.join(
    MODEL_DIR,
    "severity_prediction_model.pkl"
)


print("=" * 70)
print("SEVERITY PREDICTION MODEL TRAINING")
print("=" * 70)

print("\nLoading severity prediction dataset...")

df = pd.read_csv(DATASET_PATH)

print("Total rows:", len(df))

required_columns = [
    "finding_text",
    "vulnerability_type",
    "cwe",
    "source_type",
    "file_extension",
    "user_input",
    "dangerous_api",
    "production_context",
    "label"
]

missing_columns = [
    column for column in required_columns
    if column not in df.columns
]

if missing_columns:
    raise ValueError(
        f"Dataset is missing required columns: {missing_columns}"
    )


# -------------------------------------------------------------------
# Basic dataset validation
# -------------------------------------------------------------------

print("\nDataset validation:")

print("Missing values:")
print(df[required_columns].isnull().sum())

if df[required_columns].isnull().any().any():
    print("\nFilling missing values...")

    text_columns = [
        "finding_text",
        "vulnerability_type",
        "cwe",
        "source_type",
        "file_extension"
    ]

    for column in text_columns:
        df[column] = df[column].fillna("Unknown").astype(str)

    numeric_columns = [
        "user_input",
        "dangerous_api",
        "production_context"
    ]

    for column in numeric_columns:
        df[column] = pd.to_numeric(
            df[column],
            errors="coerce"
        ).fillna(0)

    df["label"] = df["label"].fillna("INFO").astype(str)


print("\nSeverity distribution:")
print(df["label"].value_counts())


# -------------------------------------------------------------------
# Features
# -------------------------------------------------------------------

feature_columns = [
    "finding_text",
    "vulnerability_type",
    "cwe",
    "source_type",
    "file_extension",
    "user_input",
    "dangerous_api",
    "production_context"
]

X = df[feature_columns]
y = df["label"]


# -------------------------------------------------------------------
# Hold-out test set
# -------------------------------------------------------------------

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

print("\nTraining samples:", len(X_train))
print("Testing samples :", len(X_test))


# -------------------------------------------------------------------
# Preprocessing
# -------------------------------------------------------------------

preprocessor = ColumnTransformer(
    transformers=[
        (
            "text",
            TfidfVectorizer(
                lowercase=True,
                ngram_range=(1, 2),
                sublinear_tf=True,
                min_df=1
            ),
            "finding_text"
        ),
        (
            "categorical",
            OneHotEncoder(
                handle_unknown="ignore"
            ),
            [
                "vulnerability_type",
                "cwe",
                "source_type",
                "file_extension"
            ]
        ),
        (
            "numeric",
            "passthrough",
            [
                "user_input",
                "dangerous_api",
                "production_context"
            ]
        )
    ]
)


# -------------------------------------------------------------------
# Random Forest model
# -------------------------------------------------------------------

model = RandomForestClassifier(
    n_estimators=400,
    random_state=42,
    class_weight="balanced",
    min_samples_leaf=1,
    max_features="sqrt",
    n_jobs=-1
)


pipeline = Pipeline(
    steps=[
        ("preprocessor", preprocessor),
        ("model", model)
    ]
)


# -------------------------------------------------------------------
# Cross-validation
# -------------------------------------------------------------------

print("\n" + "=" * 70)
print("STRATIFIED CROSS-VALIDATION")
print("=" * 70)

cross_validation = StratifiedKFold(
    n_splits=5,
    shuffle=True,
    random_state=42
)

scoring = {
    "accuracy": "accuracy",
    "precision": "precision_weighted",
    "recall": "recall_weighted",
    "f1": "f1_weighted"
}

cv_results = cross_validate(
    pipeline,
    X_train,
    y_train,
    cv=cross_validation,
    scoring=scoring,
    n_jobs=1,
    return_train_score=False
)

cv_accuracy = cv_results["test_accuracy"]
cv_precision = cv_results["test_precision"]
cv_recall = cv_results["test_recall"]
cv_f1 = cv_results["test_f1"]


print("\n5-Fold Cross-Validation Results")
print("--------------------------------------")

print(
    "Accuracy :",
    round(cv_accuracy.mean(), 4),
    "+/-",
    round(cv_accuracy.std(), 4)
)

print(
    "Precision:",
    round(cv_precision.mean(), 4),
    "+/-",
    round(cv_precision.std(), 4)
)

print(
    "Recall   :",
    round(cv_recall.mean(), 4),
    "+/-",
    round(cv_recall.std(), 4)
)

print(
    "F1 Score :",
    round(cv_f1.mean(), 4),
    "+/-",
    round(cv_f1.std(), 4)
)


# -------------------------------------------------------------------
# Final model training
# -------------------------------------------------------------------

print("\n" + "=" * 70)
print("TRAINING FINAL SEVERITY MODEL")
print("=" * 70)

pipeline.fit(
    X_train,
    y_train
)


# -------------------------------------------------------------------
# Hold-out test evaluation
# -------------------------------------------------------------------

print("\n" + "=" * 70)
print("HOLD-OUT TEST EVALUATION")
print("=" * 70)

predictions = pipeline.predict(X_test)


accuracy = accuracy_score(
    y_test,
    predictions
)

precision = precision_score(
    y_test,
    predictions,
    average="weighted",
    zero_division=0
)

recall = recall_score(
    y_test,
    predictions,
    average="weighted",
    zero_division=0
)

f1 = f1_score(
    y_test,
    predictions,
    average="weighted",
    zero_division=0
)


print("\nSeverity Prediction Test Results")
print("--------------------------------------")

print("Accuracy :", round(accuracy, 4))
print("Precision:", round(precision, 4))
print("Recall   :", round(recall, 4))
print("F1 Score :", round(f1, 4))


print("\nDetailed Classification Report:")
print(
    classification_report(
        y_test,
        predictions,
        zero_division=0
    )
)


# -------------------------------------------------------------------
# Save model
# -------------------------------------------------------------------

os.makedirs(
    MODEL_DIR,
    exist_ok=True
)

model_package = {
    "model": pipeline,
    "classes": list(pipeline.classes_),

    # Training information retained for project evaluation
    "evaluation": {
        "test_accuracy": round(float(accuracy), 4),
        "test_precision": round(float(precision), 4),
        "test_recall": round(float(recall), 4),
        "test_f1": round(float(f1), 4),

        "cv_accuracy_mean": round(float(cv_accuracy.mean()), 4),
        "cv_precision_mean": round(float(cv_precision.mean()), 4),
        "cv_recall_mean": round(float(cv_recall.mean()), 4),
        "cv_f1_mean": round(float(cv_f1.mean()), 4)
    }
}

joblib.dump(
    model_package,
    MODEL_PATH
)


print("\n" + "=" * 70)
print("MODEL SAVED SUCCESSFULLY")
print("=" * 70)

print("\nModel path:")
print(MODEL_PATH)

print("\nSeverity classes:")
print(list(pipeline.classes_))

print("\nTraining completed successfully.")