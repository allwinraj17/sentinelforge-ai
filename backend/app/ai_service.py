import httpx


async def analyze_with_gemini(api_key: str, findings: list[dict]) -> str:
    findings_summary = "\n".join(
        f"- {f.get('check_id', 'unknown')}: {f.get('extra', {}).get('message', '')} "
        f"(file: {f.get('path', '')}, line: {f.get('start', {}).get('line', '')})"
        for f in findings[:20]
    )

    prompt = f"""You are a security analyst. Analyze these static analysis findings and for each one provide:
1. Root cause explanation
2. Real-world impact
3. Confidence (low/medium/high)
4. OWASP/CWE mapping if applicable
5. A concrete remediation suggestion

Findings:
{findings_summary}
"""

    async with httpx.AsyncClient(timeout=60.0) as client:
        response = await client.post(
            f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={api_key}",
            headers={"Content-Type": "application/json"},
            json={
                "contents": [{"parts": [{"text": prompt}]}]
            },
        )
        response.raise_for_status()
        data = response.json()
        return data["candidates"][0]["content"]["parts"][0]["text"]