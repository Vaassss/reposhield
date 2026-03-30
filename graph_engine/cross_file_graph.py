"""
graph_engine/cross_file_graph.py
Detects attack chains that span multiple files.
"""

import os
import networkx as nx

ACTION_MAP = {
    "network_call": ["requests", "urllib", "socket"],
    "file_write":   ["file_write", "open"],
    "system_call":  ["subprocess", "os.system"],
    "exec_code":    ["eval", "exec"],
    "deserialize":  ["pickle", "marshal"],
    "obfuscation":  ["base64"],
    "env_access":   ["env"],
    "delete":       ["delete"],
}

CROSS_FILE_CHAINS = [
    {
        "name":        "DownloadAndExecute",
        "description": "One file downloads a payload, another executes it",
        "sequence":    ["network_call", "file_write", "system_call"],
        "severity":    "critical",
    },
    {
        "name":        "ObfuscatedExecution",
        "description": "One file decodes data, another executes it",
        "sequence":    ["obfuscation", "exec_code"],
        "severity":    "high",
    },
    {
        "name":        "DataExfiltration",
        "description": "Reads/writes data then sends it over the network",
        "sequence":    ["file_write", "network_call"],
        "severity":    "high",
    },
    {
        "name":        "DeserializeAndRun",
        "description": "Deserializes untrusted data then executes commands",
        "sequence":    ["deserialize", "system_call"],
        "severity":    "critical",
    },
]


def _patterns_to_actions(patterns: list) -> list:
    actions = []
    for pat in patterns:
        for action, triggers in ACTION_MAP.items():
            if any(t in pat for t in triggers):
                if action not in actions:
                    actions.append(action)
    return actions


def _is_subsequence(sequence, pattern):
    it = iter(sequence)
    return all(any(p == x for x in it) for p in pattern)


def build_cross_file_graph(ranked_files: list) -> dict:
    G = nx.DiGraph()
    file_actions = {}

    for item in ranked_files:
        fp       = item["file"]
        fname    = os.path.basename(fp)
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

    files = list(file_actions.keys())
    for i, fa in enumerate(files):
        for j, fb in enumerate(files):
            if i == j:
                continue
            a_actions = file_actions[fa]["actions"]
            b_actions = file_actions[fb]["actions"]
            for action in a_actions:
                if action in b_actions:
                    G.add_edge(fa, fb, relation="shares_action",
                               action=action, weight=5)
                    break

    chains_found = []
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
            involved  = []
            remaining = list(chain_def["sequence"])
            for action, fp in zip(all_actions_sequence, all_actions_files):
                if remaining and action == remaining[0]:
                    involved.append({
                        "file":     fp,
                        "filename": os.path.basename(fp),
                        "action":   action,
                    })
                    remaining.pop(0)

            chains_found.append({
                "name":        chain_def["name"],
                "description": chain_def["description"],
                "severity":    chain_def["severity"],
                "files":       involved,
            })

            for k in range(len(involved) - 1):
                G.add_edge(involved[k]["file"], involved[k+1]["file"],
                           relation=chain_def["name"], weight=10)

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

    print(f"[cross-file] Files: {len(G.nodes())} | "
          f"Edges: {len(G.edges())} | "
          f"Chains: {len(chains_found)}")

    return {
        "graph":        G,
        "chains_found": chains_found,
        "graph_data":   graph_data,
    }