"""
graph_engine/cross_file_graph.py
Detects attack chains that span multiple files.
Example: file_a downloads → file_b writes → file_c executes
"""

import os
import re
import networkx as nx

# These are the "action types" we track across files
ACTION_MAP = {
    "network_call":  ["requests", "urllib", "socket"],
    "file_write":    ["file_write", "open"],
    "system_call":   ["subprocess", "os.system"],
    "exec_code":     ["eval", "exec"],
    "deserialize":   ["pickle", "marshal"],
    "obfuscation":   ["base64"],
    "env_access":    ["env"],
    "delete":        ["delete"],
}

# Known dangerous cross-file chains:
# Each chain is a list of action types that must appear IN ORDER across any files
CROSS_FILE_CHAINS = [
    {
        "name": "DownloadAndExecute",
        "description": "One file downloads a payload, another executes it",
        "sequence": ["network_call", "file_write", "system_call"],
        "severity": "critical",
    },
    {
        "name": "ObfuscatedExecution",
        "description": "One file decodes data, another executes it",
        "sequence": ["obfuscation", "exec_code"],
        "severity": "high",
    },
    {
        "name": "DataExfiltration",
        "description": "One file reads sensitive data, another sends it out",
        "sequence": ["file_write", "network_call"],
        "severity": "high",
    },
    {
        "name": "DeserializeAndRun",
        "description": "Deserializes untrusted data then executes commands",
        "sequence": ["deserialize", "system_call"],
        "severity": "critical",
    },
]


def _patterns_to_actions(patterns: list) -> list:
    """Convert raw pattern names (e.g. 'requests') to action types."""
    actions = []
    for pat in patterns:
        for action, triggers in ACTION_MAP.items():
            if any(t in pat for t in triggers):
                if action not in actions:
                    actions.append(action)
    return actions


def _is_subsequence(sequence, pattern):
    """Check if pattern appears in order inside sequence."""
    it = iter(sequence)
    return all(any(p == x for x in it) for p in pattern)


def build_cross_file_graph(ranked_files: list) -> dict:
    """
    Takes ranked_files from the static scanner.
    Returns a dict with:
      - graph: networkx DiGraph connecting files via shared actions
      - chains_found: list of detected cross-file attack chains
      - graph_data: ready-to-use dict for the frontend 3D graph
    """
    G = nx.DiGraph()

    # Step 1: Build a map of file → actions
    file_actions = {}
    for item in ranked_files:
        fp      = item["file"]
        fname   = os.path.basename(fp)
        patterns = item.get("patterns", [])
        actions  = _patterns_to_actions(patterns)

        if actions:
            file_actions[fp] = {
                "filename": fname,
                "actions":  actions,
                "risk":     item.get("risk_score", 0),
            }
            G.add_node(fp, label=fname, actions=actions,
                       risk=item.get("risk_score", 0))

    # Step 2: Link files that share or chain actions
    files = list(file_actions.keys())
    for i, fa in enumerate(files):
        for j, fb in enumerate(files):
            if i == j:
                continue
            a_actions = file_actions[fa]["actions"]
            b_actions = file_actions[fb]["actions"]

            # If file A does network_call and file B does file_write,
            # they might be part of a download chain
            shared_or_chained = False
            for action in a_actions:
                if action in b_actions:
                    shared_or_chained = True
                    G.add_edge(fa, fb, relation="shares_action",
                               action=action, weight=5)
                    break

    # Step 3: Detect known cross-file chains
    chains_found = []

    # Collect all actions in order across all files (sorted by risk desc)
    sorted_files = sorted(file_actions.items(),
                          key=lambda x: x[1]["risk"], reverse=True)
    all_actions_sequence = []
    all_actions_files    = []

    for fp, data in sorted_files:
        for action in data["actions"]:
            all_actions_sequence.append(action)
            all_actions_files.append(fp)

    for chain_def in CROSS_FILE_CHAINS:
        if _is_subsequence(all_actions_sequence, chain_def["sequence"]):
            # Find which files are involved
            involved = []
            remaining = list(chain_def["sequence"])
            for action, fp in zip(all_actions_sequence, all_actions_files):
                if remaining and action == remaining[0]:
                    involved.append({"file": fp,
                                     "filename": os.path.basename(fp),
                                     "action": action})
                    remaining.pop(0)

            chains_found.append({
                "name":        chain_def["name"],
                "description": chain_def["description"],
                "severity":    chain_def["severity"],
                "files":       involved,
            })

            # Add chain edges to graph
            for k in range(len(involved) - 1):
                src = involved[k]["file"]
                dst = involved[k+1]["file"]
                G.add_edge(src, dst,
                           relation=chain_def["name"],
                           weight=10)

    # Step 4: Export graph_data for frontend
    graph_data = {
        "nodes": [
            {
                "id":      n,
                "label":   G.nodes[n].get("label", os.path.basename(n)),
                "risk":    G.nodes[n].get("risk", 0),
                "actions": G.nodes[n].get("actions", []),
            }
            for n in G.nodes()
        ],
        "edges": [
            {
                "source":   u,
                "target":   v,
                "relation": d.get("relation", ""),
                "weight":   d.get("weight", 1),
            }
            for u, v, d in G.edges(data=True)
        ],
    }

    print(f"[cross-file] Files in graph: {len(G.nodes())}. "
          f"Edges: {len(G.edges())}. "
          f"Chains found: {len(chains_found)}")

    return {
        "graph":       G,
        "chains_found": chains_found,
        "graph_data":  graph_data,
    }
