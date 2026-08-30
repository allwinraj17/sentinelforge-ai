import requests

from app.config import settings


def generate_ai_response(prompt: str) -> str:
    """
    Send prompt to Groq using direct HTTP request.
    """

    if not settings.groq_api_key:
        raise ValueError("GROQ_API_KEY is not configured.")

    url = "https://api.groq.com/openai/v1/chat/completions"

    headers = {
        "Authorization": f"Bearer {settings.groq_api_key}",
        "Content-Type": "application/json",
    }

    payload = {
        "model": settings.groq_model,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a cybersecurity AI assistant. "
                    "Analyze software security issues carefully "
                    "and provide accurate, safe recommendations."
                ),
            },
            {
                "role": "user",
                "content": prompt,
            },
        ],
        "temperature": 0.1,
    }

    try:
        response = requests.post(
            url,
            headers=headers,
            json=payload,
            timeout=90,
        )

        if response.status_code != 200:
            try:
                error_data = response.json()
                error_message = error_data.get(
                    "error",
                    {}
                ).get(
                    "message",
                    response.text,
                )
            except Exception:
                error_message = response.text

            raise RuntimeError(
                f"Groq API error ({response.status_code}): "
                f"{error_message}"
            )

        data = response.json()

        choices = data.get("choices", [])

        if not choices:
            raise RuntimeError(
                "Groq returned no response choices."
            )

        content = (
            choices[0]
            .get("message", {})
            .get("content")
        )

        if not content:
            raise RuntimeError(
                "Groq returned an empty response."
            )

        return content

    except requests.exceptions.Timeout:
        raise RuntimeError(
            "Groq request timed out. Please try Auto-Fix again."
        )

    except requests.exceptions.ConnectionError:
        raise RuntimeError(
            "Unable to connect to Groq API from the backend."
        )

    except requests.exceptions.RequestException as e:
        raise RuntimeError(
            f"Groq request failed: {str(e)}"
        )