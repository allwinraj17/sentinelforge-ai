import os
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.svm import LinearSVC
from sklearn.metrics import accuracy_score, classification_report
import joblib


BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DATASET_PATH = os.path.join(
    BASE_DIR,
    "dataset",
    "vulnerability_classification_dataset.csv"
)

MODEL_DIR = os.path.join(
    BASE_DIR,
    "models"
)

MODEL_PATH = os.path.join(
    MODEL_DIR,
    "vulnerability_classifier_model.pkl"
)


def build_text(row):
    finding_text = str(row["finding_text"])
    severity = str(row["severity"])
    cwe = str(row["cwe"])
    source_type = str(row["source_type"])
    file_extension = str(row["file_extension"])

    combined_text = (
        finding_text
        + " severity_" + severity
        + " cwe_" + cwe
        + " source_" + source_type
        + " extension_" + file_extension
    )

    return combined_text


def main():

    print("Loading vulnerability classification dataset...")

    df = pd.read_csv(DATASET_PATH)

    required_columns = [
        "finding_text",
        "severity",
        "cwe",
        "source_type",
        "file_extension",
        "label"
    ]

    for column in required_columns:
        if column not in df.columns:
            raise ValueError(
                "Missing required column: " + column
            )

    df = df.fillna("")

    print("Total rows:", len(df))

    print("\nClass distribution:")
    print(df["label"].value_counts())

    df["combined_text"] = df.apply(
        build_text,
        axis=1
    )

    X = df["combined_text"]
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

    vectorizer = TfidfVectorizer(
        lowercase=True,
        ngram_range=(1, 2),
        max_features=5000
    )

    X_train_vectorized = vectorizer.fit_transform(X_train)
    X_test_vectorized = vectorizer.transform(X_test)

    print("\nTraining Linear SVM model...")

    model = LinearSVC(
        random_state=42
    )

    model.fit(
        X_train_vectorized,
        y_train
    )

    predictions = model.predict(
        X_test_vectorized
    )

    accuracy = accuracy_score(
        y_test,
        predictions
    )

    print("\nClassification Model Results")
    print("--------------------------------")
    print("Accuracy:", round(accuracy, 4))

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
        "model": model,
        "vectorizer": vectorizer,
        "classes": list(model.classes_)
    }

    joblib.dump(
        model_package,
        MODEL_PATH
    )

    print("--------------------------------")
    print("Model saved successfully:")
    print(MODEL_PATH)


if __name__ == "__main__":
    main()