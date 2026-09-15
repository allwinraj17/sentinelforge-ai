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
from sklearn.model_selection import train_test_split
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


print("Loading improved severity prediction dataset...")

df = pd.read_csv(DATASET_PATH)

print("Total rows:", len(df))

print("\nSeverity distribution:")
print(df["label"].value_counts())


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


X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

print("\nTraining samples:", len(X_train))
print("Testing samples:", len(X_test))


preprocessor = ColumnTransformer(
    transformers=[
        (
            "text",
            TfidfVectorizer(
                lowercase=True,
                ngram_range=(1, 2)
            ),
            "finding_text"
        ),
        (
            "categorical",
            OneHotEncoder(handle_unknown="ignore"),
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


model = RandomForestClassifier(
    n_estimators=300,
    random_state=42,
    class_weight="balanced",
    min_samples_leaf=1
)


pipeline = Pipeline(
    steps=[
        ("preprocessor", preprocessor),
        ("model", model)
    ]
)


print("\nTraining improved Random Forest model...")

pipeline.fit(
    X_train,
    y_train
)


print("\nEvaluating severity prediction model...")

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


print("\nImproved Severity Prediction Results")
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


os.makedirs(
    MODEL_DIR,
    exist_ok=True
)

model_package = {
    "model": pipeline,
    "classes": list(pipeline.classes_)
}

joblib.dump(
    model_package,
    MODEL_PATH
)


print("--------------------------------------")
print("Improved model saved successfully:")
print(MODEL_PATH)
