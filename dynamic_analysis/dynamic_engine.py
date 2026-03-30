import os

from .tracer import trace_execution
from .analyzer import analyze_trace
from .scorer import calculate_dynamic_score
from .ai_dynamic import analyze_dynamic_behavior
from .correlation import correlate_dynamic_results, ai_correlate_dynamic


def is_executable(file_path):
    try:
        with open(file_path, "r", errors="ignore") as f:
            content = f.read()

        keywords = [
            "__main__",
            "os.system",
            "subprocess",
            "eval(",
            "exec(",
            "socket",
            "input(",
        ]

        return any(k in content for k in keywords)

    except:
        return False


def run_dynamic_analysis(repo_path):
    results = []

    for root, _, files in os.walk(repo_path):
        for file in files:
            if not file.endswith(".py"):
                continue

            full_path = os.path.join(root, file)

            if not is_executable(full_path):
                continue

            print(f"[dynamic] Analyzing: {full_path}")

            trace_path = trace_execution(full_path)
            findings = analyze_trace(trace_path)
            score = calculate_dynamic_score(findings)

            ai_result = analyze_dynamic_behavior(full_path, findings)

            verdict = ai_result.get("verdict", "").lower()

            if verdict == "malicious":
                score = min(score + 20, 100)
            elif verdict == "suspicious":
                score = min(score + 10, 100)

            results.append({
                "file": full_path,
                "findings": findings,
                "dynamic_score": score,
                "ai_analysis": ai_result
            })

    # 🔥 NEW: Correlation layer
    correlation = correlate_dynamic_results(results)
    ai_correlation = ai_correlate_dynamic(results)

    return {
        "files": results,
        "correlation": correlation,
        "ai_correlation": ai_correlation
    }
