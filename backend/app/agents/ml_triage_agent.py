import os
import joblib


MODEL_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "ml",
    "models",
    "vulnerability_triage_model.pkl"
)


try:
    model = joblib.load(MODEL_PATH)
    MODEL_LOADED = True
except Exception:
    model = None
    MODEL_LOADED = False


def get_confidence_level(probability):
    """
    Converts the ML vulnerability probability
    into an easy-to-understand confidence level.
    """

    if probability >= 0.80:
        return "High Confidence"

    if probability >= 0.50:
        return "Medium Confidence"

    return "Low Confidence"


def run_ml_triage(findings):
    """
    Classifies security findings using the trained
    TF-IDF + Logistic Regression model.

    The model predicts whether each finding is
    likely to be a true security issue and provides
    a confidence level based on the predicted probability.
    """

    results = []

    if not MODEL_LOADED:
        return {
            "agent": "ML Vulnerability Triage Agent",
            "success": False,
            "message": "ML model could not be loaded.",
            "results": []
        }

    for finding in findings:

        finding_text = str(
            finding.get("message", "")
        )

        severity = str(
            finding.get("severity", "")
        )

        metadata = finding.get(
            "metadata",
            {}
        )

        if not isinstance(metadata, dict):
            metadata = {}

        cwe = str(
            metadata.get("cwe", "")
        )

        source_type = str(
            metadata.get(
                "source",
                "semgrep"
            )
        ).lower()

        file_path = str(
            finding.get("path", "")
        )

        file_extension = os.path.splitext(
            file_path
        )[1]

        combined_text = (
            finding_text
            + " severity_" + severity
            + " " + cwe
            + " source_" + source_type
            + " extension_" + file_extension
        )

        prediction = int(
            model.predict(
                [combined_text]
            )[0]
        )

        probability = model.predict_proba(
            [combined_text]
        )[0]

        class_labels = list(
            model.classes_
        )

        if 1 in class_labels:

            vulnerable_index = (
                class_labels.index(1)
            )

            vulnerable_probability = float(
                probability[vulnerable_index]
            )

        else:

            vulnerable_probability = 0.0

        if prediction == 1:

            classification = (
                "Likely Vulnerability"
            )

        else:

            classification = (
                "Likely False Positive"
            )

        confidence_level = (
            get_confidence_level(
                vulnerable_probability
            )
        )

        result = dict(finding)

        result["ml_triage"] = {

            "prediction": prediction,

            "classification": classification,

            "vulnerability_probability":
                round(
                    vulnerable_probability,
                    4
                ),

            "confidence_level":
                confidence_level
        }

        results.append(result)

    return {

        "agent":
            "ML Vulnerability Triage Agent",

        "success": True,

        "model":
            "TF-IDF + Logistic Regression",

        "total_findings":
            len(findings),

        "results":
            results
    }