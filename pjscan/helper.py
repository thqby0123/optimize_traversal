import logging
import os
from typing import List, Callable
import re
import matplotlib.pyplot as plt
import networkx as nx

import Levenshtein

BASE_GRAPH_OPTIONS = {"with_labels": True, "font_size": 16, "node_color": "white", "edgecolors": "blue", "width": 1.5,
                      "node_size": 2000, "alpha": 0.65}


class StringMatcher(object):
    @staticmethod
    def match_best_similar_str_index(org_str: str, given: List[str], method: Callable = Levenshtein.jaro) -> int:
        score_vector = [method(org_str, i) for i in given]
        return score_vector.index(max(score_vector))


import sys


class GeometryVisualizer(object):
    @staticmethod
    def show_graph(nxgraph: nx.DiGraph, save_path: str =None):
        """
        Parameters
        ----------
        save_path : str
        nxgraph : nx.DiGraph

        """
        global BASE_GRAPH_OPTIONS
        EXTEND_SIZE = int(0.44 * nxgraph.__len__())
        plt.figure(dpi=60, figsize=(10 + EXTEND_SIZE, 10 + EXTEND_SIZE))
        pos = nx.shell_layout(nxgraph)
        labels = {key: f"{value['lineno']}:{value['type'].replace('AST_', '')}" for key, value in nxgraph.nodes.items()}
        control_node_options = {"node_size": 2000, "node_color": "red", "alpha": 0.5}
        taint_rel_options = {"edge_color": "purple", "width": 2, "alpha": 0.85, "node_size": 2000}

        nx.draw(nxgraph, pos=pos, labels=labels, **BASE_GRAPH_OPTIONS)
        # if COLOR_CONTROL_NODE:
        #     node_list = [k for k, v in nxgraph.nodes.items() if
        #                  'is_control_node' in v.keys() and v['is_control_node'] is True]
        #     nx.draw_networkx_nodes(nxgraph, pos, nodelist=node_list, **control_node_options)
        # if COLOR_TANT_REL:
        #     edge_list = [(u, v) for (u, v, d) in nxgraph.edges(data=True) if
        #                  "is_taint" in d.keys() and d["is_taint"] is True]
        #     nx.draw_networkx_edges(nxgraph, pos, edgelist=edge_list, **taint_rel_options)
        if save_path is None:
            plt.show()
        else:
            plt.savefig(save_path)
