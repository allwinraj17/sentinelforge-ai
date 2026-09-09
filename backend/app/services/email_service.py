from typing import Optional

import resend

from app.config import settings


# ============================================================
# PHASE 4 - EMAIL SERVICE
# ============================================================

def send_security_report(
    recipient_email: str,
    subject: str,
    html_content: str,
) -> Optional[str]:
    """
    Send a SentinelForge AI security report using Resend.

    This service is intentionally isolated from the email agent.

    The Email Agent:
        -> creates the HTML report

    This service:
        -> sends the generated HTML report

    Required environment variables:
        RESEND_API_KEY
        EMAIL_FROM

    Returns:
        Resend email ID when successful.

    Raises:
        RuntimeError when email configuration is missing
        or sending fails.
    """

    # ========================================================
    # VALIDATE INPUT
    # ========================================================

    if not recipient_email:
        raise ValueError(
            "Recipient email is required."
        )

    if not subject:
        raise ValueError(
            "Email subject is required."
        )

    if not html_content:
        raise ValueError(
            "HTML email content is required."
        )

    # ========================================================
    # CHECK RESEND CONFIGURATION
    # ========================================================

    api_key = getattr(
        settings,
        "resend_api_key",
        None,
    )

    email_from = getattr(
        settings,
        "email_from",
        None,
    )

    if not api_key:
        raise RuntimeError(
            "RESEND_API_KEY is not configured."
        )

    if not email_from:
        raise RuntimeError(
            "EMAIL_FROM is not configured."
        )

    # ========================================================
    # CONFIGURE RESEND
    # ========================================================

    resend.api_key = api_key

    # ========================================================
    # SEND EMAIL
    # ========================================================

    try:
        response = resend.Emails.send(
            {
                "from": email_from,
                "to": [recipient_email],
                "subject": subject,
                "html": html_content,
            }
        )

    except Exception as exc:
        raise RuntimeError(
            f"Failed to send security report email: {exc}"
        ) from exc

    # ========================================================
    # EXTRACT EMAIL ID
    # ========================================================

    if isinstance(response, dict):
        email_id = response.get("id")

        if email_id:
            return str(email_id)

    # Some Resend client versions return an object
    # instead of a normal dictionary.
    email_id = getattr(
        response,
        "id",
        None,
    )

    if email_id:
        return str(email_id)

    # Email was submitted but no ID was returned.
    return None