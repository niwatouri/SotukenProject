import os
from openai import OpenAI


def _get_required_env(name):
    value = os.getenv(name, "").strip()
    if not value:
        raise ValueError(f"{name} is required but not set.")
    return value


def _build_prompt(vuln_info):
    param = vuln_info.get("parameter") or vuln_info.get("param") or "unknown"
    solution = vuln_info.get("solution") or ""

    lines = [
        "You are a friendly senior engineer. Respond in Japanese.",
        "Explain the vulnerability without jargon where possible.",
        "Do not use HTML or Markdown. Plain text only.",
        "",
        "Detected vulnerability:",
        f"- ID: {vuln_info.get('id') or 'unknown'}",
        f"- Title: {vuln_info.get('title') or 'unknown'}",
        f"- Risk: {vuln_info.get('risk') or 'unknown'}",
        f"- Description: {vuln_info.get('description') or 'unknown'}",
        f"- URL: {vuln_info.get('url') or 'unknown'}",
        f"- Parameter: {param}",
        "",
        "Please cover:",
        "1) What is happening",
        "2) Why it is risky for users",
        "3) How to fix it, step by step",
        "4) A simple analogy",
    ]

    if solution:
        lines.extend(["", f"ZAP suggested fix: {solution}"])

    return "\n".join(lines)


def generate_suggestion(vuln_info):
    api_key = _get_required_env("OPENAI_API_KEY")
    model = os.getenv("OPENAI_MODEL", "").strip() or "gpt-4o-mini"
    client = OpenAI(api_key=api_key)

    prompt = _build_prompt(vuln_info)
    try:
        response = client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
        )
    except Exception as exc:
        return f"AI request failed: {exc}"

    content = response.choices[0].message.content if response.choices else ""
    return content.strip() if content else "AI response was empty."
