import os
import pandas as pd
import joblib

from scipy.sparse import hstack
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report
)


# ---------------------------------------------------------
# Paths
# ---------------------------------------------------------

DATASET_PATH = "app/ml/dataset/duplicate_similarity_dataset.csv"

MODEL_DIR = "app/ml/models"

MODEL_PATH = os.path.join(
    MODEL_DIR,
    "duplicate_similarity_model.pkl"
)

VECTORIZER_PATH = os.path.join(
    MODEL_DIR,
    "duplicate_similarity_vectorizer.pkl"
)


# ---------------------------------------------------------
# Load Dataset
# ---------------------------------------------------------

print("Loading dataset...")

df = pd.read_csv(DATASET_PATH)

df = df.fillna("")


finding_1 = df["finding_1"].astype(str)

finding_2 = df["finding_2"].astype(str)

y = df["label"].astype(int)


print("Total pairs:", len(df))

print(
    "Similar pairs:",
    int((y == 1).sum())
)

print(
    "Non-similar pairs:",
    int((y == 0).sum())
)


# ---------------------------------------------------------
# Train/Test Split
# ---------------------------------------------------------

indexes = list(range(len(df)))

train_indexes, test_indexes = train_test_split(
    indexes,
    test_size=0.20,
    random_state=42,
    stratify=y
)


print(
    "Training samples:",
    len(train_indexes)
)

print(
    "Testing samples:",
    len(test_indexes)
)


# ---------------------------------------------------------
# TF-IDF
# ---------------------------------------------------------

vectorizer = TfidfVectorizer(
    lowercase=True,
    ngram_range=(1, 2),
    max_features=5000,
    sublinear_tf=True
)


# Fit TF-IDF using both findings
training_text = pd.concat(
    [
        finding_1.iloc[train_indexes],
        finding_2.iloc[train_indexes]
    ]
)


vectorizer.fit(training_text)


# Transform Finding 1 and Finding 2 separately

f1_train = vectorizer.transform(
    finding_1.iloc[train_indexes]
)

f2_train = vectorizer.transform(
    finding_2.iloc[train_indexes]
)

f1_test = vectorizer.transform(
    finding_1.iloc[test_indexes]
)

f2_test = vectorizer.transform(
    finding_2.iloc[test_indexes]
)


# ---------------------------------------------------------
# Build Pair Features
# ---------------------------------------------------------

def build_pair_features(
    vector_1,
    vector_2
):

    difference = abs(
        vector_1 - vector_2
    )

    product = vector_1.multiply(
        vector_2
    )

    features = hstack(
        [
            vector_1,
            vector_2,
            difference,
            product
        ]
    )

    return features


X_train = build_pair_features(
    f1_train,
    f2_train
)

X_test = build_pair_features(
    f1_test,
    f2_test
)


y_train = y.iloc[
    train_indexes
]

y_test = y.iloc[
    test_indexes
]


# ---------------------------------------------------------
# Train Supervised ML Model
# ---------------------------------------------------------

print()
print("Training Logistic Regression model...")


model = LogisticRegression(
    max_iter=2000,
    random_state=42,
    class_weight="balanced"
)


model.fit(
    X_train,
    y_train
)


# ---------------------------------------------------------
# Evaluation
# ---------------------------------------------------------

predictions = model.predict(
    X_test
)


accuracy = accuracy_score(
    y_test,
    predictions
)

precision = precision_score(
    y_test,
    predictions,
    zero_division=0
)

recall = recall_score(
    y_test,
    predictions,
    zero_division=0
)

f1 = f1_score(
    y_test,
    predictions,
    zero_division=0
)


print()
print(
    "===== SUPERVISED SIMILARITY MODEL RESULTS ====="
)

print(
    "Accuracy :",
    round(accuracy, 4)
)

print(
    "Precision:",
    round(precision, 4)
)

print(
    "Recall   :",
    round(recall, 4)
)

print(
    "F1 Score :",
    round(f1, 4)
)


print()
print("Classification Report:")
print(
    classification_report(
        y_test,
        predictions,
        zero_division=0
    )
)


# ---------------------------------------------------------
# Save Model
# ---------------------------------------------------------

os.makedirs(
    MODEL_DIR,
    exist_ok=True
)


joblib.dump(
    model,
    MODEL_PATH
)


joblib.dump(
    vectorizer,
    VECTORIZER_PATH
)


print()
print("Model saved successfully:")
print(MODEL_PATH)

print()
print("Vectorizer saved successfully:")
print(VECTORIZER_PATH)