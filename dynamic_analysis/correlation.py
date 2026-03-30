import requests
import json

OLLAMA_URL = "http://localhost:11434"
MODEL = "deepseek-coder:6.7b"


def correlate_dynamic_results(results):
    behaviors = []
    files = []

    for r in results:
        files.append(r.get("file"))
        behaviors.extend(r.get("findings", []))

    behaviors = list(set(behaviors))

    flags = []
    coordinated = False
    explanation = ""

    if "Command execution detected" in behaviors and "Network activity detected" in behaviors:
        coordinated = True
        flags.append("Remote Command Execution Chain")

    if "Sensitive file access" in behaviors and "File write detected" in behaviors:
        coordinated = True
        flags.append("Data Exfiltration Pattern")

    if "Process spawning detected" in behaviors and "Command execution detected" in behaviors:
        coordinated = True
        flags.append("Privilege Escalation Behavior")

    if "Network activity detected" in behaviors and "File write detected" in behaviors:
        coordinated = True
        flags.append("Download & Execute Pattern")

    if coordinated:
        explanation = "Coordinated multi-file attack behavior detected: " + ", ".join(flags)
    else:
        explanation = "No strong cross-file correlation detected."

    return {
        "coordinated": coordinated,
        "flags": flags,
        "explanation": explanation,
        "files_involved": files
    }


def ai_correlate_dynamic(results):
    if not results:
        return {
            "coordinated": False,
            "attack_type": "none",
            "severity": "low",
            "explanation": "No dynamic results available."
        }

    prompt = f"""
Analyze cross-file behavior:

{json.dumps(results, indent=2)}

Are these files forming an attack chain?
Return JSON:
{{"coordinated":bool,"attack_type":"...","severity":"...","explanation":"..."}}
"""

    try:
        res = requests.post(
            f"{OLLAMA_URL}/api/generate",
            json={"model": MODEL, "prompt": prompt, "stream": False},
            timeout=60
        )

        return json.loads(res.json().get("response", "{}"))

    except Exception as e:
        return {
            "coordinated": False,
            "attack_type": "unknown",
            "severity": "low",
            "explanation": str(e)
        }
