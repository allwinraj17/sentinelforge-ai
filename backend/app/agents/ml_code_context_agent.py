import os
import joblib


# ---------------------------------------------------------
# Model Path
# ---------------------------------------------------------

MODEL_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "ml",
    "models",
    "code_context_model.pkl"
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
                f"Code Context model not found: {MODEL_PATH}"
            )

        _model = joblib.load(MODEL_PATH)

    return _model


# ---------------------------------------------------------
# Build Input Text
# ---------------------------------------------------------

def build_context_text(finding):
    message = finding.get("message", "")
    vulnerability_type = finding.get("vulnerability_type", "")
    cwe = finding.get("cwe", "")
    source_type = finding.get("source_type", "")
    path = finding.get("path", "")

    file_extension = os.path.splitext(path)[1]

    combined_text = (
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

    return combined_text


# ---------------------------------------------------------
# Confidence Level
# ---------------------------------------------------------

def get_confidence_level(probability):
    if probability >= 0.80:
        return "High Confidence"

    if probability >= 0.50:
        return "Medium Confidence"

    return "Low Confidence"


# ---------------------------------------------------------
# Run Code Context Analysis
# ---------------------------------------------------------

def run_ml_code_context(findings):
    try:
        model = load_model()

        results = []

        for finding in findings:
            text = build_context_text(finding)

            predicted_context = model.predict([text])[0]

            confidence = 0.0

            if hasattr(model, "predict_proba"):
                probabilities = model.predict_proba([text])[0]
                confidence = float(max(probabilities))

            confidence_level = get_confidence_level(confidence)

            result = dict(finding)

            result["ml_code_context"] = {
                "predicted_context": str(predicted_context),
                "confidence": round(confidence, 4),
                "confidence_level": confidence_level
            }

            results.append(result)

        return {
            "agent": "ML Code Context Analysis Agent",
            "success": True,
            "model": "TF-IDF + Linear SVM",
            "total_findings": len(findings),
            "results": results
        }

    except Exception as error:
        return {
            "agent": "ML Code Context Analysis Agent",
            "success": False,
            "model": "TF-IDF + Linear SVM",
            "total_findings": len(findings),
            "results": [],
            "error": str(error)
        }