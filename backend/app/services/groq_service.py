import os

from groq import Groq


# ============================================================
# GROQ CONFIGURATION
# ============================================================

GROQ_API_KEY = os.getenv("GROQ_API_KEY")

GROQ_MODEL = os.getenv(
    "GROQ_MODEL",
    "llama-3.3-70b-versatile",
)


# ============================================================
# GENERATE AI RESPONSE
# ============================================================

def generate_ai_response(prompt: str) -> str:
    """
    Send a prompt to Groq and return the AI response as plain text.

    Used by SentinelForge AI agents.

    This function:
    - Does not modify files
    - Does not modify repositories
    - Only sends the supplied prompt to Groq
    - Returns the generated text
    """

    # --------------------------------------------------------
    # VALIDATE API KEY
    # --------------------------------------------------------

    if not GROQ_API_KEY:
        raise RuntimeError(
            "GROQ_API_KEY is not configured."
        )

    # --------------------------------------------------------
    # VALIDATE PROMPT
    # --------------------------------------------------------

    if not prompt or not prompt.strip():
        raise ValueError(
            "AI prompt cannot be empty."
        )

    # --------------------------------------------------------
    # CREATE GROQ CLIENT
    # --------------------------------------------------------

    try:
        client = Groq(
            api_key=GROQ_API_KEY
        )
    except Exception as exc:
        raise RuntimeError(
            f"Unable to initialize Groq client: {exc}"
        ) from exc

    # --------------------------------------------------------
    # SEND REQUEST
    # --------------------------------------------------------

    try:
        response = client.chat.completions.create(
            model=GROQ_MODEL,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a professional software "
                        "security AI assistant. "
                        "Follow the user's instructions exactly. "
                        "When asked to generate source code, "
                        "return complete usable source code."
                    ),
                },
                {
                    "role": "user",
                    "content": prompt,
                },
            ],
            temperature=0.1,
        )
    except Exception as exc:
        raise RuntimeError(
            f"Groq API request failed: {exc}"
        ) from exc

    # --------------------------------------------------------
    # VALIDATE RESPONSE
    # --------------------------------------------------------

    if not response:
        raise RuntimeError(
            "Groq returned no response."
        )

    if not response.choices:
        raise RuntimeError(
            "Groq returned an empty response."
        )

    message = response.choices[0].message

    if not message:
        raise RuntimeError(
            "Groq returned an empty message."
        )

    content = message.content

    if not content:
        raise RuntimeError(
            "Groq returned empty content."
        )

    # --------------------------------------------------------
    # RETURN AI RESPONSE
    # --------------------------------------------------------

    return content.strip()