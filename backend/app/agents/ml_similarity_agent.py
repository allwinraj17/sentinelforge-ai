import os
import joblib

from sklearn.metrics.pairwise import cosine_similarity


# ---------------------------------------------------------
# Model Path
# ---------------------------------------------------------

MODEL_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "ml",
    "models",
    "duplicate_similarity_model.pkl"
)


# ---------------------------------------------------------
# Load Model
# ---------------------------------------------------------

_model = None


def load_model():
    global _model

    if _model is None:

        if not os.path.exists(MODEL_PATH):
            raise FileNotFoundError(
                f"Duplicate similarity model not found: {MODEL_PATH}"
            )

        _model = joblib.load(MODEL_PATH)

    return _model


# ---------------------------------------------------------
# Build Security Signature
# ---------------------------------------------------------

def build_security_text(finding):
    message = finding.get(
        "message",
        finding.get("finding_text", "")
    )

    vulnerability_type = finding.get(
        "vulnerability_type",
        ""
    )

    cwe = finding.get(
        "cwe",
        ""
    )

    source_type = finding.get(
        "source_type",
        ""
    )

    path = finding.get(
        "path",
        ""
    )

    file_extension = os.path.splitext(
        str(path)
    )[1]

    security_text = (
        str(message)
        + " "
        + str(message)
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

    return security_text


# ---------------------------------------------------------
# Similarity Classification
# ---------------------------------------------------------

def classify_similarity(score):

    if score >= 0.80:
        return "Very Similar"

    if score >= 0.60:
        return "Similar"

    if score >= 0.35:
        return "Moderately Similar"

    return "Low Similarity"


# ---------------------------------------------------------
# Compare Two Findings
# ---------------------------------------------------------

def compare_findings(
    finding_1,
    finding_2
):

    model = load_model()

    text_1 = build_security_text(
        finding_1
    )

    text_2 = build_security_text(
        finding_2
    )

    vector_1 = model.transform(
        [text_1]
    )

    vector_2 = model.transform(
        [text_2]
    )

    score = cosine_similarity(
        vector_1,
        vector_2
    )[0][0]

    score = float(score)

    return {
        "finding_1": finding_1,
        "finding_2": finding_2,
        "similarity_score": round(
            score,
            4
        ),
        "similarity_percentage": round(
            score * 100,
            2
        ),
        "classification": classify_similarity(
            score
        )
    }


# ---------------------------------------------------------
# Run Similarity Agent
# ---------------------------------------------------------

def run_ml_similarity(
    finding_pairs
):

    try:

        results = []

        for pair in finding_pairs:

            finding_1 = pair.get(
                "finding_1",
                {}
            )

            finding_2 = pair.get(
                "finding_2",
                {}
            )

            comparison = compare_findings(
                finding_1,
                finding_2
            )

            results.append(
                comparison
            )

        return {
            "agent":
                "ML Duplicate Vulnerability Similarity Agent",

            "success":
                True,

            "model":
                "TF-IDF + Cosine Similarity",

            "total_pairs":
                len(finding_pairs),

            "results":
                results
        }

    except Exception as error:

        return {
            "agent":
                "ML Duplicate Vulnerability Similarity Agent",

            "success":
                False,

            "model":
                "TF-IDF + Cosine Similarity",

            "total_pairs":
                len(finding_pairs),

            "results":
                [],

            "error":
                str(error)
        }