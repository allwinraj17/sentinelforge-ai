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
# Recommendation Consistency Guard
# ---------------------------------------------------------

def apply_recommendation_guard(
    finding,
    model_recommendation
):

    message = str(
        finding.get(
            "message",
            finding.get("finding_text", "")
        )
    ).lower()

    vulnerability_type = str(
        finding.get(
            "vulnerability_type",
            ""
        )
    ).lower()

    cwe = str(
        finding.get(
            "cwe",
            ""
        )
    ).lower()

    combined_text = (
        message
        + " "
        + vulnerability_type
        + " "
        + cwe
    )

    # -----------------------------------------------------
    # SQL Injection
    # -----------------------------------------------------

    if (
        "sql injection" in combined_text
        or "sql-injection" in combined_text
        or "cwe-89" in combined_text
        or "sql" in combined_text
    ):
        return (
            "Use parameterized queries or prepared statements"
        )

    # -----------------------------------------------------
    # Cross-Site Scripting
    # -----------------------------------------------------

    if (
        "xss" in combined_text
        or "cross-site scripting" in combined_text
        or "cwe-79" in combined_text
    ):
        return (
            "Apply context-aware output encoding and input sanitization"
        )

    # -----------------------------------------------------
    # Command Injection
    # -----------------------------------------------------

    if (
        "command injection" in combined_text
        or "command-injection" in combined_text
        or "cwe-78" in combined_text
    ):
        return (
            "Avoid shell execution and use safe process APIs with strict input validation"
        )

    # -----------------------------------------------------
    # Path Traversal
    # -----------------------------------------------------

    if (
        "path traversal" in combined_text
        or "path-traversal" in combined_text
        or "cwe-22" in combined_text
    ):
        return (
            "Validate and restrict file paths to an allowed directory"
        )

    # -----------------------------------------------------
    # Hardcoded Secret
    # -----------------------------------------------------

    if (
        "hardcoded secret" in combined_text
        or "hardcoded-secret" in combined_text
        or "secret" in combined_text
        or "api key" in combined_text
        or "password" in combined_text
        or "token" in combined_text
    ):
        return (
            "Move secrets to environment variables or a secure secret manager"
        )

    # -----------------------------------------------------
    # Insecure Cryptography
    # -----------------------------------------------------

    if (
        "insecure cryptography" in combined_text
        or "weak cryptography" in combined_text
        or "cwe-327" in combined_text
    ):
        return (
            "Use modern cryptographic algorithms and secure password hashing"
        )

    # -----------------------------------------------------
    # Authentication
    # -----------------------------------------------------

    if (
        "authentication" in combined_text
        or "authorization" in combined_text
        or "cwe-287" in combined_text
    ):
        return (
            "Strengthen authentication and authorization checks before protected operations"
        )

    # -----------------------------------------------------
    # Debug Configuration
    # -----------------------------------------------------

    if (
        "debug=true" in combined_text
        or "debug = true" in combined_text
        or "active debug code" in combined_text
        or "cwe-489" in combined_text
    ):
        return (
            "Disable debug mode in production and use secure configuration settings"
        )

    # -----------------------------------------------------
    # Unknown / Other
    # -----------------------------------------------------

    return (
        "Review the affected code and apply the appropriate security control"
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

    # -----------------------------------------------------
    # ML Prediction
    # -----------------------------------------------------

    prediction = model.predict(
        vector
    )[0]

    probabilities = model.predict_proba(
        vector
    )[0]

    confidence = float(
        max(probabilities)
    )

    ml_recommendation = str(
        prediction
    )

    # -----------------------------------------------------
    # Consistency Guard
    # -----------------------------------------------------

    final_recommendation = apply_recommendation_guard(
        finding,
        ml_recommendation
    )

    return {
        "recommended_fix": final_recommendation,

        "ml_predicted_fix": ml_recommendation,

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
    "finding_id": finding.get(
        "finding_id"
    ),

    "finding_index": finding.get(
        "finding_index"
    ),

    "check_id": finding.get(
        "check_id"
    ),

    "rule_id": finding.get(
        "rule_id"
    ),

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
        recommendation,
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