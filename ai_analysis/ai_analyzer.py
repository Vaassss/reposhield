"""
ai_analysis/ai_analyzer.py
Advanced AI-assisted code analysis using Ollama (deepseek-coder).

Pipeline per file:
  1. Semantic deobfuscation  — decode hidden strings before analysis
  2. Block-level chain analysis — detect logic chains across a function block
  3. Full file verdict        — richer prompt with regex context + filename
  4. Confidence calibration   — adjust AI confidence using static evidence

After all files:
  5. Multi-file correlation   — detect coordinated attack patterns across files
"""

import json
import hashlib
import urllib.request
import urllib.error
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from config import OLLAMA_URL, OLLAMA_MODEL, MAX_AI_FILES, MAX_FILE_CHARS

# ── Ollama call ───────────────────────────────────────────────

def _ollama(prompt: str, max_tokens: int = 400) -> str:
    """Raw call to Ollama. Returns response text or empty string on failure."""
    payload = json.dumps({
        "model":  OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": 0.1, "num_predict": max_tokens}
    }).encode("utf-8")
    try:
        req = urllib.request.Request(
            f"{OLLAMA_URL}/api/generate",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=120) as resp:
            return json.loads(resp.read()).get("response", "").strip()
    except Exception as e:
        return f"__ERROR__: {e}"


def _extract_json(text: str) -> dict | None:
    """Extract the first valid JSON object from a model response."""
    start = text.find("{")
    end   = text.rfind("}") + 1
    if start == -1 or end == 0:
        return None
    try:
        return json.loads(text[start:end])
    except json.JSONDecodeError:
        return None


def _read_file(filepath: str) -> str:
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception as e:
        return f"# Could not read file: {e}"


def _error_result(msg: str) -> dict:
    return {
        "verdict": "unknown", "confidence": 0.0,
        "reasons": [], "mitre_hints": [],
        "chains": [], "deobfuscated": [],
        "correlation_flags": [], "error": msg
    }


# ── Step 1: Semantic deobfuscation ────────────────────────────

OBFUSCATION_PATTERNS = [
    r"base64\.b64decode\s*\(",
    r"__import__\s*\(",
    r"marshal\.loads\s*\(",
    r"pickle\.loads\s*\(",
    r"compile\s*\(",
    r"bytes\.fromhex\s*\(",
    r"codecs\.decode\s*\(",
    r"zlib\.decompress\s*\(",
]

def _has_obfuscation(code: str) -> bool:
    return any(re.search(p, code) for p in OBFUSCATION_PATTERNS)


def _deobfuscate(code: str, filename: str) -> list:
    """
    Ask the model to identify and explain any obfuscated constructs.
    Returns list of plain-English explanations.
    """
    if not _has_obfuscation(code):
        return []

    prompt = f"""You are a malware analyst. In the Python file '{filename}',
identify any obfuscated, encoded, or dynamically constructed strings/code.
For each one found, explain in plain English what it likely does when executed.

Respond ONLY as a JSON array of strings, no other text. Example:
["Decodes a base64 string that resolves to 'import os; os.system(...)'",
 "Dynamically imports subprocess module to hide it from static scanners"]

If nothing obfuscated is found, respond with: []

Code:
```python
{code[:MAX_FILE_CHARS]}
```"""

    response = _ollama(prompt, max_tokens=300)
    if response.startswith("__ERROR__"):
        return []
    try:
        start = response.find("[")
        end   = response.rfind("]") + 1
        if start == -1 or end == 0:
            return []
        parsed = json.loads(response[start:end])
        return [str(x) for x in parsed if x][:5]
    except Exception:
        return []


# ── Step 2: Block-level logic chain analysis ──────────────────

def _extract_blocks(code: str) -> list:
    """
    Extract function and class blocks from Python code.
    Returns list of (block_name, block_code) tuples.
    """
    blocks  = []
    lines   = code.splitlines()
    current = []
    name    = "module-level"

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("def ") or stripped.startswith("class "):
            if current:
                blocks.append((name, "\n".join(current)))
            name    = stripped.split("(")[0].split(":")[0]
            current = [line]
        else:
            current.append(line)

    if current:
        blocks.append((name, "\n".join(current)))

    # Only return blocks with actual content
    return [(n, c) for n, c in blocks if len(c.strip()) > 50]


def _analyze_chains(code: str, filename: str) -> list:
    """
    Ask model to identify multi-step logic chains within the code
    that together form a vulnerability, even if no single line does.
    """
    blocks = _extract_blocks(code)
    if not blocks:
        return []

    # Build a compact summary of blocks for the prompt
    block_summary = ""
    for bname, bcode in blocks[:6]:  # limit to 6 blocks
        block_summary += f"\n--- {bname} ---\n{bcode[:800]}\n"

    prompt = f"""You are a senior malware analyst reviewing Python code from file '{filename}'.

Your task: identify LOGIC CHAINS where multiple statements together create a
vulnerability, even if each statement alone seems harmless.

Examples of dangerous chains:
- decode(data) -> eval(decoded)           [obfuscated execution]
- requests.get(url) -> open(f,'w') -> exec(content)  [download and execute]
- base64.b64decode -> subprocess.run      [encoded command execution]
- socket.connect -> send(system_info)     [data exfiltration]
- os.listdir -> open -> requests.post     [file theft]

Code blocks to analyze:
{block_summary}

Respond ONLY as a JSON array of chain descriptions. Each entry must be a string
describing the chain and why it is dangerous. Example:
["decode_payload() decodes base64 -> passes to eval() on line 12: hidden code execution chain",
 "fetch_data() downloads from remote URL -> writes to disk -> executes: download-and-run chain"]

If no dangerous chains found, respond with: []"""

    response = _ollama(prompt, max_tokens=400)
    if response.startswith("__ERROR__"):
        return []
    try:
        start = response.find("[")
        end   = response.rfind("]") + 1
        if start == -1 or end == 0:
            return []
        parsed = json.loads(response[start:end])
        return [str(x) for x in parsed if x][:6]
    except Exception:
        return []


# ── Step 3: Full file verdict with rich context ───────────────

def _verdict(
    code: str,
    filename: str,
    patterns: list,
    deobfuscated: list,
    chains: list,
) -> dict:
    """
    Final verdict call with all context included in the prompt.
    """
    # Build context section
    ctx_parts = []

    if patterns:
        ctx_parts.append(
            "Regex scanner already found these suspicious patterns in this file:\n"
            + "\n".join(f"  - {p}" for p in patterns)
        )
    if deobfuscated:
        ctx_parts.append(
            "Deobfuscation analysis found:\n"
            + "\n".join(f"  - {d}" for d in deobfuscated)
        )
    if chains:
        ctx_parts.append(
            "Logic chain analysis found:\n"
            + "\n".join(f"  - {c}" for c in chains)
        )

    context_block = (
        "\n\nAdditional context from prior analysis:\n" + "\n".join(ctx_parts)
        if ctx_parts else ""
    )

    prompt = f"""You are a malware analyst performing final verdict assessment.

File: '{filename}'
{context_block}

Now analyze the full file code below. Consider:
1. Individual suspicious statements
2. The logic chains described above (if any)
3. Whether the combined behavior suggests malicious intent
4. Whether obfuscation is being used to hide true purpose

Respond ONLY with a valid JSON object, no other text:
{{
  "verdict": "malicious" or "suspicious" or "benign",
  "confidence": <float 0.0 to 1.0>,
  "reasons": ["reason 1", "reason 2"],
  "mitre_hints": ["T1059"]
}}

Code:
```python
{code[:MAX_FILE_CHARS]}
```"""

    response = _ollama(prompt, max_tokens=350)
    if response.startswith("__ERROR__"):
        return _error_result(response)

    parsed = _extract_json(response)
    if not parsed:
        return _error_result(f"Could not parse verdict JSON from: {response[:120]}")

    verdict = parsed.get("verdict", "benign").lower()
    if verdict not in ("malicious", "suspicious", "benign"):
        verdict = "suspicious"

    return {
        "verdict":     verdict,
        "confidence":  min(float(parsed.get("confidence", 0.5)), 1.0),
        "reasons":     parsed.get("reasons", [])[:5],
        "mitre_hints": parsed.get("mitre_hints", [])[:5],
        "chains":      chains,
        "deobfuscated": deobfuscated,
        "correlation_flags": [],
        "error":       None,
    }


# ── Step 4: Confidence calibration ───────────────────────────

def _calibrate_confidence(
    ai_confidence: float,
    verdict: str,
    patterns: list,
    chains: list,
    deobfuscated: list,
) -> float:
    """
    Adjust AI confidence using static evidence weight.
    Formula: final = (ai_confidence * 0.6) + (static_weight * 0.4)

    More regex hits, chains, and deobfuscated strings = higher static weight.
    If AI says benign but static evidence is heavy, confidence is pulled down.
    """
    # Build static evidence score (0.0 to 1.0)
    evidence_score = 0.0
    evidence_score += min(len(patterns) * 0.12, 0.5)     # up to 0.5 from patterns
    evidence_score += min(len(chains) * 0.20, 0.4)       # up to 0.4 from chains
    evidence_score += min(len(deobfuscated) * 0.15, 0.3) # up to 0.3 from deobfuscation
    evidence_score = min(evidence_score, 1.0)

    # If model says benign but evidence is strong, flip toward suspicious
    if verdict == "benign" and evidence_score > 0.4:
        # Pull confidence DOWN — model may have missed something
        calibrated = (ai_confidence * 0.6) - (evidence_score * 0.3)
        return max(round(calibrated, 3), 0.05)

    # Otherwise, reinforce confidence with evidence
    calibrated = (ai_confidence * 0.6) + (evidence_score * 0.4)
    return min(round(calibrated, 3), 1.0)


# ── Step 5: Multi-file correlation ────────────────────────────

def _correlate_files(file_results: list) -> dict:
    """
    Send a summary of all file verdicts to the model and ask
    whether the files work together as a coordinated attack.
    """
    if len(file_results) < 2:
        return {"coordinated": False, "flags": [], "explanation": ""}

    # Build a compact summary
    summary_lines = []
    for r in file_results:
        verdict_str = r["verdict"].upper()
        reasons_str = "; ".join(r["reasons"][:2]) if r["reasons"] else "none"
        chains_str  = "; ".join(r["chains"][:1])  if r["chains"]  else "none"
        summary_lines.append(
            f"File: {r['filename']}\n"
            f"  Verdict: {verdict_str} (confidence {r['confidence']:.2f})\n"
            f"  Reasons: {reasons_str}\n"
            f"  Chains:  {chains_str}"
        )
    summary = "\n\n".join(summary_lines)

    prompt = f"""You are a malware analyst. Below are analysis results for multiple
files from the same repository. Determine if these files work TOGETHER
as a coordinated attack — for example:
- One file encodes/prepares a payload, another executes it
- One file exfiltrates data collected by another
- Files together implement a full attack chain that none implements alone

File analysis results:
{summary}

Respond ONLY with a valid JSON object, no other text:
{{
  "coordinated": true or false,
  "flags": ["flag 1", "flag 2"],
  "explanation": "one sentence summary"
}}

If files are independent or benign, set coordinated to false and flags to []."""

    response = _ollama(prompt, max_tokens=300)
    if response.startswith("__ERROR__"):
        return {"coordinated": False, "flags": [], "explanation": ""}

    parsed = _extract_json(response)
    if not parsed:
        return {"coordinated": False, "flags": [], "explanation": ""}

    return {
        "coordinated":   bool(parsed.get("coordinated", False)),
        "flags":         parsed.get("flags", [])[:5],
        "explanation":   str(parsed.get("explanation", ""))[:300],
    }


# ── Main entry point ──────────────────────────────────────────

def analyze_top_files(ranked_files: list) -> dict:
    """
    Full multi-stage analysis of top N ranked files.

    Returns:
        {
            "file_results":   [...],   # per-file analysis
            "correlation":    {...},   # cross-file correlation
            "ai_score":       float,   # aggregate risk score 0-100
        }
    """
    top     = ranked_files[:MAX_AI_FILES]
    results = []

    print(f"[ai] Analysing {len(top)} file(s) with {OLLAMA_MODEL} — multi-stage pipeline")

    for item in top:
        filepath = item["file"]
        fname    = os.path.basename(filepath)
        patterns = item.get("patterns", [])
        print(f"[ai] ── {fname} (static risk: {item.get('risk_score',0)})")

        code = _read_file(filepath)

        # Stage 1: deobfuscation
        print(f"[ai]    stage 1: deobfuscation")
        deobfuscated = _deobfuscate(code, fname)
        if deobfuscated:
            print(f"[ai]    found {len(deobfuscated)} obfuscated construct(s)")

        # Stage 2: block-level chain analysis
        print(f"[ai]    stage 2: chain analysis")
        chains = _analyze_chains(code, fname)
        if chains:
            print(f"[ai]    found {len(chains)} logic chain(s)")

        # Stage 3: full verdict with context
        print(f"[ai]    stage 3: verdict")
        result = _verdict(code, fname, patterns, deobfuscated, chains)

        # Stage 4: calibrate confidence
        result["confidence"] = _calibrate_confidence(
            result["confidence"],
            result["verdict"],
            patterns,
            chains,
            deobfuscated,
        )

        result["file"]       = filepath
        result["filename"]   = fname
        result["risk_score"] = item.get("risk_score", 0)
        result["patterns"]   = patterns

        print(
            f"[ai]    verdict={result['verdict']} "
            f"confidence={result['confidence']:.2f}"
            + (f" | ERROR: {result['error']}" if result.get("error") else "")
        )
        results.append(result)

    # Stage 5: multi-file correlation
    correlation = {"coordinated": False, "flags": [], "explanation": ""}
    if len(results) >= 2:
        print(f"[ai] ── stage 5: multi-file correlation")
        correlation = _correlate_files(results)
        if correlation["coordinated"]:
            print(f"[ai]    coordinated attack detected: {correlation['explanation']}")

    return {
        "file_results": results,
        "correlation":  correlation,
        "ai_score":     _aggregate_score(results, correlation),
    }


def _aggregate_score(results: list, correlation: dict) -> float:
    """
    Compute aggregate AI risk score (0–100).
    Coordinated attack detection adds a bonus.
    """
    if not results:
        return 0.0

    weights  = {"malicious": 100, "suspicious": 60, "benign": 0, "unknown": 10}
    base     = sum(
        weights.get(r["verdict"], 10) * r["confidence"]
        for r in results
    ) / len(results)

    # Chain bonus — each chain found in any file adds weight
    chain_count = sum(len(r.get("chains", [])) for r in results)
    chain_bonus = min(chain_count * 5, 20)

    # Coordination bonus
    coord_bonus = 15 if correlation.get("coordinated") else 0

    return min(round(base + chain_bonus + coord_bonus, 1), 100.0)


def ai_risk_score(analysis: dict) -> float:
    """Convenience wrapper — extract score from analyze_top_files result."""
    return analysis.get("ai_score", 0.0)
