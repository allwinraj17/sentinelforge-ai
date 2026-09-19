import os
import joblib

from scipy.sparse import hstack


# ---------------------------------------------------------
# Paths
# ---------------------------------------------------------

BASE_DIR = os.path.dirname(
    os.path.dirname(__file__)
)


MODEL_PATH = os.path.join(
    BASE_DIR,
    "ml",
    "models",
    "duplicate_similarity_model.pkl"
)


VECTORIZER_PATH = os.path.join(
    BASE_DIR,
    "ml",
    "models",
    "duplicate_similarity_vectorizer.pkl"
)


# ---------------------------------------------------------
# Loaded Objects
# ---------------------------------------------------------

_model = None
_vectorizer = None


# ---------------------------------------------------------
# Load Model
# ---------------------------------------------------------

def load_model():

    global _model

    if _model is None:

        if not os.path.exists(
            MODEL_PATH
        ):

            raise FileNotFoundError(
                f"Duplicate similarity model not found: "
                f"{MODEL_PATH}"
            )

        _model = joblib.load(
            MODEL_PATH
        )

    return _model


# ---------------------------------------------------------
# Load Vectorizer
# ---------------------------------------------------------

def load_vectorizer():

    global _vectorizer

    if _vectorizer is None:

        if not os.path.exists(
            VECTORIZER_PATH
        ):

            raise FileNotFoundError(
                f"Duplicate similarity vectorizer not found: "
                f"{VECTORIZER_PATH}"
            )

        _vectorizer = joblib.load(
            VECTORIZER_PATH
        )

    return _vectorizer


# ---------------------------------------------------------
# Build Security Text
# ---------------------------------------------------------

def build_security_text(finding):

    message = finding.get(
        "message",
        finding.get(
            "finding_text",
            ""
        )
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
        + str(vulnerability_type)
        + " "
        + str(cwe)
        + " "
        + str(source_type)
        + " "
        + str(file_extension)
    )


    return security_text


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


# ---------------------------------------------------------
# Classification
# ---------------------------------------------------------

def classify_prediction(
    prediction
):

    if prediction == 1:

        return "Similar"

    return "Not Similar"


# ---------------------------------------------------------
# Confidence Level
# ---------------------------------------------------------

def get_confidence_level(
    confidence
):

    if confidence >= 0.80:

        return "High Confidence"

    if confidence >= 0.50:

        return "Medium Confidence"

    return "Low Confidence"


# ---------------------------------------------------------
# Compare Findings
# ---------------------------------------------------------

def compare_findings(
    finding_1,
    finding_2,
    finding_1_index=None,
    finding_2_index=None
):

    model = load_model()

    vectorizer = load_vectorizer()


    text_1 = build_security_text(
        finding_1
    )

    text_2 = build_security_text(
        finding_2
    )


    vector_1 = vectorizer.transform(
        [text_1]
    )

    vector_2 = vectorizer.transform(
        [text_2]
    )


    pair_features = build_pair_features(
        vector_1,
        vector_2
    )


    prediction = model.predict(
        pair_features
    )[0]


    probabilities = model.predict_proba(
        pair_features
    )[0]


    confidence = float(
        max(probabilities)
    )


    classification = classify_prediction(
        int(prediction)
    )


    return {

        "finding_1_index":
            finding_1_index,

        "finding_2_index":
            finding_2_index,

        "finding_1":
            finding_1,

        "finding_2":
            finding_2,

        "prediction":
            int(prediction),

        "classification":
            classification,

        "similarity_probability":
            round(
                confidence,
                4
            ),

        "confidence":
            round(
                confidence,
                4
            ),

        "confidence_percentage":
            round(
                confidence * 100,
                2
            ),

        "confidence_level":
            get_confidence_level(
                confidence
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


            finding_1_index = pair.get(
                "finding_1_index"
            )

            finding_2_index = pair.get(
                "finding_2_index"
            )


            comparison = compare_findings(
                finding_1,
                finding_2,
                finding_1_index,
                finding_2_index
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
                "TF-IDF + Logistic Regression",

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
                "TF-IDF + Logistic Regression",

            "total_pairs":
                len(finding_pairs),

            "results":
                [],

            "error":
                str(error)
        }