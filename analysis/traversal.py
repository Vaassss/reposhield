def weighted_dfs(graph, start, max_depth=5):
    paths = []

    def dfs(node, path, depth):
        if depth > max_depth:
            return

        path.append(node)

        neighbors = sorted(
            list(graph.successors(node)),
            key=lambda n: graph.nodes[n].get("risk", 0),
            reverse=True
        )

        if not neighbors:
            paths.append(path)

        for n in neighbors:
            dfs(n, path.copy(), depth + 1)

    dfs(start, [], 0)
    return paths
