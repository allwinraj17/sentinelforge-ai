import os
import joblib
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.svm import SVC
from sklearn.metrics import accuracy_score, classification_report


# ---------------------------------------------------------
# Paths
# ---------------------------------------------------------

DATASET_PATH = os.path.join(
    os.path.dirname(__file__),
    "dataset",
    "code_context_dataset.csv"
)

MODEL_DIR = os.path.join(
    os.path.dirname(__file__),
    "models"
)

MODEL_PATH = os.path.join(
    MODEL_DIR,
    "code_context_model.pkl"
)


# ---------------------------------------------------------
# Load Dataset
# ---------------------------------------------------------

print("Loading code context dataset...")

df = pd.read_csv(DATASET_PATH)

print("Total rows:", len(df))


# ---------------------------------------------------------
# Handle Missing Values
# ---------------------------------------------------------

columns = [
    "finding_text",
    "vulnerability_type",
    "cwe",
    "source_type",
    "file_extension",
    "label"
]

for column in columns:
    df[column] = df[column].fillna("").astype(str)


# ---------------------------------------------------------
# Build Combined Text
# ---------------------------------------------------------

df["combined_text"] = (
    df["finding_text"]
    + " "
    + df["vulnerability_type"]
    + " "
    + df["cwe"]
    + " "
    + df["source_type"]
    + " "
    + df["file_extension"]
)


X = df["combined_text"]
y = df["label"]


# ---------------------------------------------------------
# Display Class Distribution
# ---------------------------------------------------------

print("\nContext distribution:")

print(y.value_counts())


# ---------------------------------------------------------
# Train / Test Split
# ---------------------------------------------------------

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

print("\nTraining samples:", len(X_train))
print("Testing samples:", len(X_test))


# ---------------------------------------------------------
# TF-IDF + Linear SVM
# ---------------------------------------------------------

model = Pipeline([
    (
        "tfidf",
        TfidfVectorizer(
            lowercase=True,
            ngram_range=(1, 2),
            max_features=5000
        )
    ),
    (
        "classifier",
        SVC(
            kernel="linear",
            probability=True,
            random_state=42
        )
    )
])


# ---------------------------------------------------------
# Train Model
# ---------------------------------------------------------

print("\nTraining Code Context Model...")

model.fit(X_train, y_train)


# ---------------------------------------------------------
# Prediction
# ---------------------------------------------------------

y_pred = model.predict(X_test)


# ---------------------------------------------------------
# Evaluation
# ---------------------------------------------------------

accuracy = accuracy_score(y_test, y_pred)

print("\n====================================")
print("CODE CONTEXT MODEL RESULTS")
print("====================================")

print("Accuracy:", round(accuracy, 4))

print("\nClassification Report:")
print(
    classification_report(
        y_test,
        y_pred,
        zero_division=0
    )
)


# ---------------------------------------------------------
# Save Model
# ---------------------------------------------------------

os.makedirs(MODEL_DIR, exist_ok=True)

joblib.dump(model, MODEL_PATH)

print("\nModel saved successfully:")
print(MODEL_PATH)