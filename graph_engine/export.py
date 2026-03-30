def export_graph(graph):
    return {
        "nodes": [
            {"id": n, "risk": graph.nodes[n].get("risk", 0)}
            for n in graph.nodes()
        ],
        "edges": [
            {
                "source": u,
                "target": v,
                "relation": d.get("relation", "")
            }
            for u, v, d in graph.edges(data=True)
        ]
    }
