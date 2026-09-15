import os
import joblib
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report


# ---------------------------------------------------------
# Paths
# ---------------------------------------------------------

BASE_DIR = os.path.dirname(__file__)

DATASET_PATH = os.path.join(
    BASE_DIR,
    "dataset",
    "fix_recommendation_dataset.csv"
)

MODEL_DIR = os.path.join(
    BASE_DIR,
    "models"
)

MODEL_PATH = os.path.join(
    MODEL_DIR,
    "fix_recommendation_model.pkl"
)


# ---------------------------------------------------------
# Load Dataset
# ---------------------------------------------------------

print("Loading Fix Recommendation Dataset...")

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
    "recommended_fix"
]

for column in columns:
    df[column] = df[column].fillna("").astype(str)


# ---------------------------------------------------------
# Build Feature Text
# ---------------------------------------------------------

df["feature_text"] = (
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


# ---------------------------------------------------------
# Features and Labels
# ---------------------------------------------------------

X = df["feature_text"]

y = df["recommended_fix"]


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


print("Training samples:", len(X_train))
print("Testing samples:", len(X_test))


# ---------------------------------------------------------
# TF-IDF
# ---------------------------------------------------------

vectorizer = TfidfVectorizer(
    lowercase=True,
    ngram_range=(1, 2),
    max_features=5000,
    sublinear_tf=True
)


X_train_tfidf = vectorizer.fit_transform(
    X_train
)

X_test_tfidf = vectorizer.transform(
    X_test
)


# ---------------------------------------------------------
# Logistic Regression
# ---------------------------------------------------------

model = LogisticRegression(
    max_iter=2000,
    random_state=42
)


print("\nTraining Fix Recommendation model...")

model.fit(
    X_train_tfidf,
    y_train
)


# ---------------------------------------------------------
# Prediction
# ---------------------------------------------------------

y_pred = model.predict(
    X_test_tfidf
)


# ---------------------------------------------------------
# Evaluation
# ---------------------------------------------------------

accuracy = accuracy_score(
    y_test,
    y_pred
)

print("\n====================================")
print("FIX RECOMMENDATION MODEL RESULTS")
print("====================================")

print(
    "Accuracy:",
    round(accuracy, 4)
)

print("\nClassification Report:")

print(
    classification_report(
        y_test,
        y_pred,
        zero_division=0
    )
)


# ---------------------------------------------------------
# Save Model Components
# ---------------------------------------------------------

os.makedirs(
    MODEL_DIR,
    exist_ok=True
)

model_package = {
    "vectorizer": vectorizer,
    "model": model,
    "classes": list(model.classes_)
}


joblib.dump(
    model_package,
    MODEL_PATH
)


# ---------------------------------------------------------
# Final Information
# ---------------------------------------------------------

print("\nModel classes:")

for class_name in model.classes_:
    print("-", class_name)


print("\nModel saved successfully:")

print(MODEL_PATH)