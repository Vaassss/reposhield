def score_graph(graph):
    for node in graph.nodes():
        score = 0

        for _, _, data in graph.out_edges(node, data=True):
            if data["relation"] == "exec":
                score += 10
            elif data["relation"] == "download":
                score += 8
            elif data["relation"] == "file_write":
                score += 6
            elif data["relation"] == "execute":
                score += 9

        graph.nodes[node]["risk"] = score

    return graph
