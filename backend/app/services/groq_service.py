from groq import Groq

from app.config import settings


def generate_ai_response(prompt: str) -> str:
    """
    Send a prompt to Groq and return the AI response.
    """

    if not settings.groq_api_key:
        raise ValueError("GROQ_API_KEY is not configured.")

    print("============================================================")
    print("GROQ REQUEST START")
    print("============================================================")
    print(f"Model: {settings.groq_model}")
    print(f"API key configured: {bool(settings.groq_api_key)}")
    print(f"Prompt length: {len(prompt)}")

    try:
        client = Groq(
            api_key=settings.groq_api_key,
            timeout=60.0,
        )

        print("Groq client created.")
        print("Sending request to Groq...")

        response = client.chat.completions.create(
            model=settings.groq_model,
            messages=[
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
            temperature=0.1,
        )

        print("Groq response received.")

        if not response.choices:
            raise ValueError("Groq returned no choices.")

        result = response.choices[0].message.content

        if not result:
            raise ValueError("Groq returned an empty response.")

        print("GROQ REQUEST SUCCESS")
        print("============================================================")

        return result

    except Exception as e:
        print("============================================================")
        print("GROQ API ERROR")
        print("============================================================")
        print(f"Error type: {type(e).__name__}")
        print(f"Error message: {str(e)}")
        print("============================================================")

        raise