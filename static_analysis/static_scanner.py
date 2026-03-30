"""
static_analysis/static_scanner.py
Scans Python files for suspicious patterns AND ranks files by risk
AND builds a graph for behavior analysis.
"""

import os
import re
from typing import List, Dict

from graph_engine.graph_builder import CodeGraph

SUSPICIOUS_PATTERNS = {
    "os.system":               {"regex": r"os\.system\s*\(",           "weight": 30},
    "subprocess":              {"regex": r"subprocess\.(call|run|Popen|check_output)\s*\(", "weight": 30},
    "eval":                    {"regex": r"\beval\s*\(",               "weight": 35},
    "exec":                    {"regex": r"\bexec\s*\(",               "weight": 35},
    "base64":                  {"regex": r"base64\.b64decode\s*\(",    "weight": 25},
    "socket":                  {"regex": r"\.connect\s*\(",            "weight": 30},
    "import_dynamic":          {"regex": r"__import__\s*\(",           "weight": 25},
    "compile":                 {"regex": r"\bcompile\s*\(",            "weight": 20},
    "ctypes":                  {"regex": r"\bctypes\b",                "weight": 55},
    "marshal":                 {"regex": r"marshal\.loads\s*\(",       "weight": 30},
    "pickle":                  {"regex": r"pickle\.loads\s*\(",        "weight": 25},
    "urllib":                  {"regex": r"urllib\.request",           "weight": 25},
    "requests":                {"regex": r"requests\.(get|post|put|delete|patch)\s*\(", "weight": 20},
    "env":                     {"regex": r"os\.environ\s*[\[\.]",      "weight": 25},
    "delete":                  {"regex": r"shutil\.rmtree\s*\(",       "weight": 40},
    "file_write":              {"regex": r"open\s*\(.*['\"]w['\"]",   "weight": 15},
}

SKIP_DIRS = {
    "__pycache__", ".git", "node_modules", ".tox",
    "venv", ".venv", "env", ".env", "dist", "build",
}


def scan_file(filepath: str, graph: CodeGraph) -> List[Dict]:
    findings = []
    file_behaviors = []  # 🔥 NEW

    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except Exception as e:
        return [{"file": filepath, "line": 0,
                 "pattern": "read_error", "snippet": str(e), "weight": 0}]

    for lineno, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue

        for pattern_name, rule in SUSPICIOUS_PATTERNS.items():
            if re.search(rule["regex"], line):

                findings.append({
                    "file":    filepath,
                    "line":    lineno,
                    "pattern": pattern_name,
                    "snippet": stripped[:200],
                    "weight":  rule["weight"],
                })

                # 🔥 Track behavior sequence
                file_behaviors.append(pattern_name)

                # 🔥 Map to graph nodes
                if pattern_name in ["eval", "exec"]:
                    graph.add_edge(filepath, pattern_name, relation="exec", weight=10)

                elif pattern_name in ["subprocess", "os.system"]:
                    graph.add_edge(filepath, "system_call", relation="execute", weight=9)

                elif pattern_name in ["requests", "urllib"]:
                    graph.add_edge(filepath, "network_call", relation="download", weight=8)

                elif pattern_name == "file_write":
                    graph.add_edge(filepath, "file_write", relation="file_write", weight=6)

                elif pattern_name in ["pickle", "marshal"]:
                    graph.add_edge(filepath, "deserialize", relation="deserialize", weight=7)

                elif pattern_name == "base64":
                    graph.add_edge(filepath, "obfuscation", relation="decode", weight=6)

    # 🔥 IMPORTANT: Create behavior chain
    for i in range(len(file_behaviors) - 1):
        graph.add_edge(file_behaviors[i], file_behaviors[i + 1],
                       relation="sequence", weight=5)

    return findings


def _file_risk_score(findings: List[Dict]) -> int:
    return sum(f.get("weight", 10) for f in findings)


def scan_repository(repo_path: str) -> Dict:
    all_findings   = []
    scanned_files  = 0
    pattern_counts = {}
    file_findings_map = {}

    graph = CodeGraph()

    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]

        for fname in files:
            if not fname.endswith(".py"):
                continue

            scanned_files += 1
            fpath = os.path.join(root, fname)

            graph.add_file(fpath)

            file_findings = scan_file(fpath, graph)

            if file_findings:
                file_findings_map[fpath] = file_findings

                for f in file_findings:
                    p = f.get("pattern")
                    if p:
                        pattern_counts[p] = pattern_counts.get(p, 0) + 1

            all_findings.extend(file_findings)

    ranked_files = sorted(
        [
            {
                "file":       fp,
                "risk_score": _file_risk_score(findings),
                "patterns":   list({f["pattern"] for f in findings}),
            }
            for fp, findings in file_findings_map.items()
        ],
        key=lambda x: x["risk_score"],
        reverse=True,
    )

    print(
        f"[static] Scanned {scanned_files} files. "
        f"Findings: {len(all_findings)}. "
        f"Risky files: {len(ranked_files)}."
    )

    return {
        "scanned_files":  scanned_files,
        "total_findings": len(all_findings),
        "pattern_counts": pattern_counts,
        "findings":       all_findings,
        "ranked_files":   ranked_files,
        "graph":          graph.get_graph(),
    }
