import os

from groq import Groq


# ============================================================
# GROQ CONFIGURATION
# ============================================================

GROQ_API_KEY = os.getenv("GROQ_API_KEY")

# You can change this model if needed.
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

    This function is used by:
    - Auto-Fix Agent
    - Other SentinelForge AI agents

    The function does not modify files or repositories.
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

    client = Groq(
        api_key=GROQ_API_KEY
    )

    # --------------------------------------------------------
    # SEND REQUEST TO GROQ
    # --------------------------------------------------------

    response = client.chat.completions.create(
        model=GROQ_MODEL,
        messages=[
            {
                "role": "system",
                "content": (
                    "You are a professional software "
                    "security AI assistant. "
                    "Follow the user's instructions exactly."
                ),
            },
            {
                "role": "user",
                "content": prompt,
            },
        ],
        temperature=0.1,
    )

    # --------------------------------------------------------
    # EXTRACT RESPONSE
    # --------------------------------------------------------

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

    return content.strip()