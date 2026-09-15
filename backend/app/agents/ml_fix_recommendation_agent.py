import os
import joblib
import pandas as pd


# ---------------------------------------------------------
# Model Path
# ---------------------------------------------------------

MODEL_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "ml",
    "models",
    "fix_recommendation_model.pkl"
)


# ---------------------------------------------------------
# Load Model
# ---------------------------------------------------------

_model_package = None


def load_model():
    global _model_package

    if _model_package is None:

        if not os.path.exists(MODEL_PATH):
            raise FileNotFoundError(
                f"Fix recommendation model not found: {MODEL_PATH}"
            )

        _model_package = joblib.load(MODEL_PATH)

    return _model_package


# ---------------------------------------------------------
# Confidence Level
# ---------------------------------------------------------

def get_confidence_level(confidence):

    if confidence >= 0.80:
        return "High Confidence"

    if confidence >= 0.50:
        return "Medium Confidence"

    return "Low Confidence"


# ---------------------------------------------------------
# Build Finding Features
# ---------------------------------------------------------

def build_finding_text(finding):

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

    return (
        str(message)
        + " "
        + str(vulnerability_type)
        + " "
        + str(cwe)
        + " "
        + str(source_type)
        + " "
        + str(file_extension)
    )


# ---------------------------------------------------------
# Recommend Fix
# ---------------------------------------------------------

def recommend_fix(finding):

    model_package = load_model()

    vectorizer = model_package["vectorizer"]
    model = model_package["model"]

    finding_text = build_finding_text(
        finding
    )

    vector = vectorizer.transform(
        [finding_text]
    )

    prediction = model.predict(
        vector
    )[0]

    probabilities = model.predict_proba(
        vector
    )[0]

    confidence = float(
        max(probabilities)
    )

    return {
        "recommended_fix": str(prediction),
        "confidence": round(
            confidence,
            4
        ),
        "confidence_percentage": round(
            confidence * 100,
            2
        ),
        "confidence_level": get_confidence_level(
            confidence
        )
    }


# ---------------------------------------------------------
# Run Fix Recommendation Agent
# ---------------------------------------------------------

def run_ml_fix_recommendation(findings):

    try:

        results = []

        for finding in findings:

            recommendation = recommend_fix(
                finding
            )

            results.append({
                "message": finding.get(
                    "message",
                    finding.get(
                        "finding_text",
                        ""
                    )
                ),
                "vulnerability_type": finding.get(
                    "vulnerability_type",
                    ""
                ),
                "cwe": finding.get(
                    "cwe",
                    ""
                ),
                "path": finding.get(
                    "path",
                    ""
                ),
                "ml_fix_recommendation":
                    recommendation
            })

        return {
            "agent":
                "ML Fix Recommendation Agent",

            "success":
                True,

            "model":
                "TF-IDF + Logistic Regression",

            "total_findings":
                len(findings),

            "results":
                results
        }

    except Exception as error:

        return {
            "agent":
                "ML Fix Recommendation Agent",

            "success":
                False,

            "model":
                "TF-IDF + Logistic Regression",

            "total_findings":
                len(findings),

            "results":
                [],

            "error":
                str(error)
        }