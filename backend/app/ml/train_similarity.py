import os
import joblib
import pandas as pd

from sklearn.feature_extraction.text import TfidfVectorizer


# ---------------------------------------------------------
# Paths
# ---------------------------------------------------------

BASE_DIR = os.path.dirname(__file__)

DATASET_PATH = os.path.join(
    BASE_DIR,
    "dataset",
    "duplicate_similarity_dataset.csv"
)

MODEL_DIR = os.path.join(
    BASE_DIR,
    "models"
)

MODEL_PATH = os.path.join(
    MODEL_DIR,
    "duplicate_similarity_model.pkl"
)


# ---------------------------------------------------------
# Build Security Text
# ---------------------------------------------------------

def build_security_text(
    finding_text,
    vulnerability_type,
    cwe,
    source_type,
    file_extension
):
    return (
        str(finding_text)
        + " "
        + str(finding_text)
        + " "
        + str(vulnerability_type)
        + " "
        + str(vulnerability_type)
        + " "
        + str(cwe)
        + " "
        + str(cwe)
        + " "
        + str(source_type)
        + " "
        + str(file_extension)
    )


# ---------------------------------------------------------
# Load Dataset
# ---------------------------------------------------------

print("Loading duplicate similarity dataset...")

df = pd.read_csv(DATASET_PATH)

print("Total rows:", len(df))


# ---------------------------------------------------------
# Handle Missing Values
# ---------------------------------------------------------

columns = [
    "finding_1",
    "finding_2",
    "label"
]

for column in columns:
    df[column] = df[column].fillna("").astype(str)


# ---------------------------------------------------------
# Create Security Metadata
#
# Our dataset contains finding pairs only.
# The finding text itself is used to build the TF-IDF
# vocabulary. The actual agent will additionally use
# vulnerability metadata when available.
# ---------------------------------------------------------

texts = pd.concat(
    [
        df["finding_1"],
        df["finding_2"]
    ],
    ignore_index=True
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


print("\nBuilding TF-IDF vocabulary...")

vectorizer.fit(texts)


# ---------------------------------------------------------
# Vocabulary Information
# ---------------------------------------------------------

vocabulary_size = len(
    vectorizer.vocabulary_
)

print(
    "Vocabulary size:",
    vocabulary_size
)


# ---------------------------------------------------------
# Save Vectorizer
# ---------------------------------------------------------

os.makedirs(
    MODEL_DIR,
    exist_ok=True
)

joblib.dump(
    vectorizer,
    MODEL_PATH
)


# ---------------------------------------------------------
# Dataset Statistics
# ---------------------------------------------------------

print("\nSimilarity pair distribution:")

print(
    df["label"]
    .value_counts()
    .sort_index()
)


print("\n====================================")
print("DUPLICATE SIMILARITY MODEL")
print("====================================")

print(
    "Method: TF-IDF + Cosine Similarity"
)

print(
    "Training pairs:",
    len(df)
)

print(
    "Vectorizer vocabulary:",
    vocabulary_size
)

print(
    "\nThe dataset is used as the TF-IDF "
    "security finding corpus."
)

print(
    "Similarity labels are used for "
    "evaluation/reference, not classifier training."
)


print("\nVectorizer saved successfully:")

print(MODEL_PATH)