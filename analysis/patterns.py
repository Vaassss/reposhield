"""
analysis/patterns.py

Upgraded pattern matcher:
- Supports ordered matching (chain-aware)
- Returns structured node data (for UI graph)
"""

PATTERNS = {
    "RCE": ["eval", "system_call"],
    "DownloadExec": ["network_call", "file_write", "system_call"],
    "Exfiltration": ["file_write", "network_call"],
    "Deserialization": ["deserialize", "exec"],
}


# -----------------------------
# ORDERED MATCH (IMPORTANT)
# -----------------------------
def _is_subsequence(path, pattern):
    """
    Checks if pattern appears in order inside path
    Example:
    path = [a, b, c, d]
    pattern = [b, d] → True
    """
    it = iter(path)
    return all(any(p == x for x in it) for p in pattern)


# -----------------------------
# MAIN MATCH FUNCTION
# -----------------------------
def match_pattern(path, graph=None):
    """
    path: list of node labels
    graph: networkx graph (optional, for metadata)
    """

    for name, pattern in PATTERNS.items():

        # 🔥 ORDER-AWARE MATCH
        if _is_subsequence(path, pattern):

            # 🔥 RETURN STRUCTURED DATA (UI READY)
            structured_path = []

            for node in path:
                node_data = {
                    "label": node,
                    "file": None,
                    "line": None,
                    "snippet": None
                }

                # If graph available → enrich
                if graph and node in graph.nodes:
                    data = graph.nodes[node]

                    node_data["file"] = data.get("file")
                    node_data["line"] = data.get("line")
                    node_data["snippet"] = data.get("snippet")

                structured_path.append(node_data)

            return {
                "type": name,
                "path": structured_path
            }

    return None
