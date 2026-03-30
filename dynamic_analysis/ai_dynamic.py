import requests
import json

OLLAMA_URL = "http://localhost:11434"
MODEL = "deepseek-coder:6.7b"


def analyze_dynamic_behavior(file_path, findings):
    if not findings:
        return {
            "verdict": "benign",
            "confidence": 0.5,
            "explanation": "No suspicious runtime behavior detected."
        }

    prompt = f"""
You are a cybersecurity expert analyzing runtime behavior of a Python script.

File: {file_path}

Observed behaviors:
{json.dumps(findings, indent=2)}

Tasks:
1. Is this behavior malicious, suspicious, or benign?
2. Explain why
3. Can this be exploited in real-world conditions?
4. Give confidence (0–1)

Respond in JSON:
{{
  "verdict": "...",
  "confidence": 0.0,
  "explanation": "...",
  "exploitability": "low/medium/high"
}}
"""

    try:
        res = requests.post(
            f"{OLLAMA_URL}/api/generate",
            json={
                "model": MODEL,
                "prompt": prompt,
                "stream": False
            },
            timeout=60
        )

        data = res.json()
        return json.loads(data.get("response", "{}"))

    except Exception as e:
        return {
            "verdict": "unknown",
            "confidence": 0.0,
            "explanation": f"AI error: {str(e)}"
        }
