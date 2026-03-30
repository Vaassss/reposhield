"""
run.py — Start RepoShield Phase 1 + Analysis Engine

Usage:
    python3 run.py                        # runs web app
    python3 run.py --analyze /path/repo   # run analysis pipeline
    python3 run.py --port 8080
    python3 run.py --debug
"""

import os
import sys
import argparse

# Ensure imports work
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from web.app import create_app
from web.models import db

# 🔥 NEW IMPORTS (your pipeline)
from static_analysis.static_scanner import scan_repository
from scoring_engine.graph_scoring import score_graph
from analysis.traversal import weighted_dfs
from analysis.patterns import match_pattern


def run_analysis(repo_path: str):
    print(f"\n[+] Running analysis on: {repo_path}\n")

    # Step 1: Scan repo
    scan_result = scan_repository(repo_path)

    graph = scan_result.get("graph")

    if not graph:
        print("[!] No graph generated.")
        return

    # Step 2: Score graph
    graph = score_graph(graph)

    # Step 3: Priority split
    HIGH = []
    LOW = []

    for node in graph.nodes():
        risk = graph.nodes[node].get("risk", 0)
        if risk >= 8:
            HIGH.append(node)
        else:
            LOW.append(node)

    print(f"[+] High priority nodes: {len(HIGH)}")
    print(f"[+] Low priority nodes: {len(LOW)}\n")

    # Step 4: Analyze high priority first
    critical_results = []
    for node in HIGH:
        paths = weighted_dfs(graph, node)

        for path in paths:
            match = match_pattern(path)
            if match:
                critical_results.append({
                    "type": match,
                    "path": path
                })

    # Step 5: Analyze low priority (deferred)
    secondary_results = []
    for node in LOW:
        paths = weighted_dfs(graph, node, max_depth=3)

        for path in paths:
            match = match_pattern(path)
            if match:
                secondary_results.append({
                    "type": match,
                    "path": path
                })

    # Step 6: Output results
    print("\n🚨 ===== CRITICAL FINDINGS =====")
    if not critical_results:
        print("No high-confidence threats found.")
    else:
        for r in critical_results:
            print(f"\n[!] {r['type']}")
            print("Path:", " → ".join(r["path"]))

    print("\n🧠 ===== SECONDARY FINDINGS =====")
    if not secondary_results:
        print("No secondary patterns found.")
    else:
        for r in secondary_results:
            print(f"\n[*] {r['type']}")
            print("Path:", " → ".join(r["path"]))

    print("\n📊 ===== SUMMARY =====")
    print(f"Critical: {len(critical_results)}")
    print(f"Secondary: {len(secondary_results)}")
    print(f"Total findings: {scan_result.get('total_findings', 0)}")

    print("\n[✓] Analysis complete.\n")


def main():
    parser = argparse.ArgumentParser(description="RepoShield Phase 1 + Analysis")

    parser.add_argument("--host", default="0.0.0.0",
                        help="Host to bind (default: 0.0.0.0)")
    parser.add_argument("--port", default=5000, type=int,
                        help="Port (default: 5000)")
    parser.add_argument("--debug", action="store_true",
                        help="Enable debug mode")

    # 🔥 NEW ARGUMENT
    parser.add_argument("--analyze", type=str,
                        help="Path to repository to analyze")

    args = parser.parse_args()

    # 🔥 CLI ANALYSIS MODE
    if args.analyze:
        if not os.path.exists(args.analyze):
            print("[!] Invalid path.")
            return

        run_analysis(args.analyze)
        return

    # 🌐 NORMAL WEB MODE
    app = create_app()

    with app.app_context():
        db.create_all()
        print("[+] Database tables ready.")

    print(f"""
╔══════════════════════════════════════════════╗
║           RepoShield — Phase 1               ║
║       Static Threat Intelligence             ║
╠══════════════════════════════════════════════╣
║  URL  →  http://localhost:{args.port:<19}║
║  Host →  {args.host:<35}║
╚══════════════════════════════════════════════╝
""")

    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()
