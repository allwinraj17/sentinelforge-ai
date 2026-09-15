import os
import joblib


BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

MODEL_PATH = os.path.join(
    BASE_DIR,
    "ml",
    "models",
    "vulnerability_classifier_model.pkl"
)


def load_classification_model():
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(
            "Vulnerability classification model not found: "
            + MODEL_PATH
        )

    model_package = joblib.load(MODEL_PATH)

    return (
        model_package["model"],
        model_package["vectorizer"],
        model_package["classes"]
    )


def build_finding_text(finding):
    message = str(
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
        metadata.get("source", "")
    )

    path = str(
        finding.get("path", "")
    )

    file_extension = ""

    if "." in path:
        file_extension = os.path.splitext(
            path
        )[1]

    combined_text = (
        message
        + " severity_" + severity
        + " cwe_" + cwe
        + " source_" + source_type
        + " extension_" + file_extension
    )

    return combined_text


def classify_finding(
    finding,
    model,
    vectorizer
):
    combined_text = build_finding_text(
        finding
    )

    vectorized_text = vectorizer.transform(
        [combined_text]
    )

    prediction = model.predict(
        vectorized_text
    )[0]

    return str(prediction)


def run_ml_classification(findings):
    try:
        model, vectorizer, classes = (
            load_classification_model()
        )

        results = []

        for finding in findings:

            try:
                prediction = classify_finding(
                    finding,
                    model,
                    vectorizer
                )

                result = dict(finding)

                result["ml_classification"] = {
                    "predicted_type": prediction,
                    "available_classes": classes
                }

                results.append(result)

            except Exception as finding_error:

                result = dict(finding)

                result["ml_classification"] = {
                    "predicted_type": "Unknown",
                    "error": str(finding_error)
                }

                results.append(result)

        return {
            "agent": "ML Vulnerability Classification Agent",
            "success": True,
            "model": "TF-IDF + Linear SVM",
            "total_findings": len(findings),
            "results": results
        }

    except Exception as error:

        return {
            "agent": "ML Vulnerability Classification Agent",
            "success": False,
            "model": "TF-IDF + Linear SVM",
            "total_findings": len(findings),
            "results": [],
            "error": str(error)
        }