import os
import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score


# --------------------------------------------------
# 1. File paths
# --------------------------------------------------

DATASET_PATH = os.path.join(
    os.path.dirname(__file__),
    "dataset",
    "vulnerability_triage_dataset.csv"
)

MODEL_DIR = os.path.join(
    os.path.dirname(__file__),
    "models"
)

MODEL_PATH = os.path.join(
    MODEL_DIR,
    "vulnerability_triage_model.pkl"
)


# --------------------------------------------------
# 2. Load dataset
# --------------------------------------------------

print("Loading dataset...")

df = pd.read_csv(DATASET_PATH)

print("Dataset loaded successfully.")
print("Total rows:", len(df))


# --------------------------------------------------
# 3. Prepare input text
# --------------------------------------------------

df["finding_text"] = df["finding_text"].fillna("")
df["severity"] = df["severity"].fillna("")
df["cwe"] = df["cwe"].fillna("")
df["source_type"] = df["source_type"].fillna("")
df["file_extension"] = df["file_extension"].fillna("")


# Combine useful security information into one text field
df["combined_text"] = (
    df["finding_text"]
    + " severity_" + df["severity"]
    + " " + df["cwe"]
    + " source_" + df["source_type"]
    + " extension_" + df["file_extension"]
)


X = df["combined_text"]
y = df["label"]


# --------------------------------------------------
# 4. Split dataset
# --------------------------------------------------

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

print("Training samples:", len(X_train))
print("Testing samples:", len(X_test))


# --------------------------------------------------
# 5. Create ML pipeline
# --------------------------------------------------

model = Pipeline([
    (
        "tfidf",
        TfidfVectorizer(
            lowercase=True,
            ngram_range=(1, 2)
        )
    ),
    (
        "classifier",
        LogisticRegression(
            max_iter=1000,
            random_state=42
        )
    )
])


# --------------------------------------------------
# 6. Train model
# --------------------------------------------------

print("\nTraining ML model...")

model.fit(X_train, y_train)

print("Training completed.")


# --------------------------------------------------
# 7. Evaluate model
# --------------------------------------------------

predictions = model.predict(X_test)

accuracy = accuracy_score(y_test, predictions)
precision = precision_score(y_test, predictions, zero_division=0)
recall = recall_score(y_test, predictions, zero_division=0)
f1 = f1_score(y_test, predictions, zero_division=0)


print("\n-------------------------------")
print("MODEL PERFORMANCE")
print("-------------------------------")

print("Accuracy :", round(accuracy, 4))
print("Precision:", round(precision, 4))
print("Recall   :", round(recall, 4))
print("F1 Score :", round(f1, 4))


# --------------------------------------------------
# 8. Save trained model
# --------------------------------------------------

os.makedirs(MODEL_DIR, exist_ok=True)

joblib.dump(model, MODEL_PATH)

print("\nModel saved successfully.")
print("Model path:", MODEL_PATH)