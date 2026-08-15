import httpx


async def analyze_with_openai(api_key: str, findings: list[dict]) -> str:
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
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 2000,
            },
        )
        response.raise_for_status()
        data = response.json()
        return data["choices"][0]["message"]["content"]