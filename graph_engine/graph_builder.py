import networkx as nx

class CodeGraph:
    def __init__(self):
        self.graph = nx.DiGraph()

    def add_file(self, file_name):
        self.graph.add_node(file_name, type="file")

    def add_function(self, func_name, file_name):
        self.graph.add_node(func_name, type="function", file=file_name)
        self.graph.add_edge(file_name, func_name, relation="contains", weight=1)

    def add_edge(self, src, dst, relation, weight=1):
        self.graph.add_node(src)
        self.graph.add_node(dst)
        self.graph.add_edge(src, dst, relation=relation, weight=weight)

    def get_graph(self):
        return self.graph
