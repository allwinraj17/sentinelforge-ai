import os
import joblib
import pandas as pd


BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

MODEL_PATH = os.path.join(
    BASE_DIR,
    "ml",
    "models",
    "priority_prediction_model.pkl"
)


def load_priority_model():

    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(
            "Priority prediction model not found: "
            + MODEL_PATH
        )

    model_package = joblib.load(
        MODEL_PATH
    )

    return model_package["model"]


def get_file_extension(path):

    path = str(path)

    if "." in path:
        return os.path.splitext(path)[1]

    return ""


def build_feature_data(finding):

    message = str(
        finding.get(
            "message",
            ""
        )
    )

    vulnerability_type = str(
        finding.get(
            "vulnerability_type",
            "Other"
        )
    )

    cwe = str(
        finding.get(
            "cwe",
            ""
        )
    )

    source_type = str(
        finding.get(
            "source_type",
            "semgrep"
        )
    )

    path = str(
        finding.get(
            "path",
            ""
        )
    )

    file_extension = get_file_extension(
        path
    )

    user_input = int(
        finding.get(
            "user_input",
            0
        )
    )

    dangerous_api = int(
        finding.get(
            "dangerous_api",
            0
        )
    )

    production_context = int(
        finding.get(
            "production_context",
            0
        )
    )

    exposure = int(
        finding.get(
            "exposure",
            0
        )
    )

    exploitability = int(
        finding.get(
            "exploitability",
            0
        )
    )

    data = {
        "finding_text": [message],

        "vulnerability_type": [
            vulnerability_type
        ],

        "cwe": [
            cwe
        ],

        "source_type": [
            source_type
        ],

        "file_extension": [
            file_extension
        ],

        "user_input": [
            user_input
        ],

        "dangerous_api": [
            dangerous_api
        ],

        "production_context": [
            production_context
        ],

        "exposure": [
            exposure
        ],

        "exploitability": [
            exploitability
        ]
    }

    return pd.DataFrame(
        data
    )


def get_priority_confidence(
    confidence
):

    if confidence is None:
        return "Unknown Confidence"

    if confidence >= 0.80:
        return "High Confidence"

    if confidence >= 0.50:
        return "Medium Confidence"

    return "Low Confidence"


def predict_priority(
    finding,
    model
):

    feature_data = build_feature_data(
        finding
    )

    prediction = model.predict(
        feature_data
    )[0]

    confidence = None

    if hasattr(
        model,
        "predict_proba"
    ):

        probabilities = (
            model.predict_proba(
                feature_data
            )[0]
        )

        confidence = float(
            max(probabilities)
        )

    return (
        str(prediction),
        confidence
    )


def run_ml_priority(
    findings
):

    try:

        model = load_priority_model()

        results = []

        for finding in findings:

            result = dict(
                finding
            )

            try:

                predicted_priority, confidence = (
                    predict_priority(
                        finding,
                        model
                    )
                )

                result["ml_priority"] = {

                    "predicted_priority":
                        predicted_priority,

                    "confidence":
                        round(
                            confidence,
                            4
                        )
                        if confidence is not None
                        else None,

                    "confidence_level":
                        get_priority_confidence(
                            confidence
                        )
                }

            except Exception as finding_error:

                result["ml_priority"] = {

                    "predicted_priority":
                        "Unknown",

                    "confidence":
                        None,

                    "confidence_level":
                        "Unknown Confidence",

                    "error":
                        str(
                            finding_error
                        )
                }

            results.append(
                result
            )

        return {

            "agent":
                "ML Priority Prediction Agent",

            "success":
                True,

            "model":
                "TF-IDF + One-Hot Encoding + Random Forest",

            "total_findings":
                len(findings),

            "results":
                results
        }

    except Exception as error:

        return {

            "agent":
                "ML Priority Prediction Agent",

            "success":
                False,

            "model":
                "TF-IDF + One-Hot Encoding + Random Forest",

            "total_findings":
                len(findings),

            "results":
                [],

            "error":
                str(
                    error
                )
        }