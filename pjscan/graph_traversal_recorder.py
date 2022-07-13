import abc

import py2neo
from typing import Dict, Set, Union, List, Callable
import networkx as nx
from pjscan.analysis_framework import AnalysisFramework as Neo4jEngine
from pjscan.const import *
from abc import abstractmethod, ABCMeta


class BaseRecorder(object, metaclass=ABCMeta):
    """
    This is a class used to record the traversed node
    """

    @abstractmethod
    def __init__(self, neo4j_engine: Neo4jEngine):
        """

        Parameters
        ----------
        neo4j_engine

        """
        self.neo4j_engine = neo4j_engine
        self.storage_graph = None

    @abstractmethod
    def record(self, node: py2neo.Node, next_node: py2neo.Node, taint_var:str = '') -> bool:
        """

        Parameters
        ----------
        node
        next_node

        Returns
        -------

        """
        return True

    @abstractmethod
    def record_origin(self, o: py2neo.Node) -> bool:
        """

        Parameters
        ----------
        o

        Returns
        -------

        """
        return True


class GraphTraversalRecorder(BaseRecorder):
    """
    This is a class used to record the traversed node
    """

    def __init__(self, neo4j_engine: Neo4jEngine):
        super(GraphTraversalRecorder, self).__init__(neo4j_engine)
        self.storage_graph = nx.DiGraph()

    def record(self, node: py2neo.Node, next_node: py2neo.Node) -> bool:
        self.storage_graph.add_node(next_node[NODE_INDEX],
                                    **{NODE_LINENO: next_node[NODE_LINENO], NODE_TYPE: next_node[NODE_TYPE]})
        self.storage_graph.add_edge(node[NODE_INDEX], next_node[NODE_INDEX])
        return True

    def record_origin(self, o: py2neo.Node) -> bool:
        self.storage_graph.add_node(o[NODE_INDEX], **{NODE_LINENO: o[NODE_LINENO], NODE_TYPE: o[NODE_TYPE]})
        return True

class GraphTraversalStraightRecorder(BaseRecorder):
    """
    This is a class used to record the traversed node
    """

    def __init__(self, neo4j_engine: Neo4jEngine):
        super(GraphTraversalStraightRecorder, self).__init__(neo4j_engine)
        self.storage_graph = nx.DiGraph()
        self.loop_structure_instance = {}  # start is entry node, and end is exit node.
        # ENTRY : AST_EXPR[3rd child of AST_FOREACH]
        # EXIT  : AST_ [out of AST_FOREACH]

    def __switch(self, next_node):
        if next_node in self.loop_structure_instance.keys():
            return self.__switch(self.loop_structure_instance[next_node])
        else:
            return next_node

    def record(self, node: py2neo.Node, next_node: py2neo.Node) -> bool:
        """

        Parameters
        ----------
        node
        next_node

        Returns
        -------

        Notes
        -----
        Here we use a new record function, this function will make each loop structure visit only once,
         and the return subGraph is a simple graph (without cycles)

        To achieve this ,we need to change the next_node destination.

        """
        parent_node = self.neo4j_engine.get_ast_parent_node(node)
        if parent_node[NODE_TYPE] == TYPE_FOR and \
                self.neo4j_engine.get_ast_ith_child_node(parent_node, 2) \
                not in self.loop_structure_instance.keys():
            self.loop_structure_instance[
                self.neo4j_engine.get_ast_ith_child_node(parent_node, 2)
            ] = self.neo4j_engine.find_cfg_successors(
                    self.neo4j_engine.get_ast_ith_child_node(parent_node, 1)
            )[1]
        elif parent_node[NODE_TYPE] == TYPE_WHILE:
            self.loop_structure_instance[node] = self.neo4j_engine.find_cfg_successors(node)[1]
        elif node[NODE_TYPE] == TYPE_FOREACH:
            self.loop_structure_instance[node] = self.neo4j_engine.find_cfg_successors(node)[1]
        if next_node[NODE_INDEX] < node[NODE_INDEX]:
            # This must be loop structure instance
            if next_node in self.loop_structure_instance.keys():
                next_node = self.__switch(next_node)
            else:
                print("Problem not solved")
                return False

        # because the nx only support the simple path, here we must reconnect the LOOP INSTANCE structure.
        flow_label = self.neo4j_engine.get_cfg_flow_label(node, next_node)
        self.storage_graph.add_node(next_node[NODE_INDEX],
                                    **{NODE_LINENO: next_node[NODE_LINENO], NODE_TYPE: next_node[NODE_TYPE]})
        self.storage_graph.add_edge(node[NODE_INDEX], next_node[NODE_INDEX], **{CFG_EDGE_FLOW_LABEL: flow_label})
        return True

    def record_origin(self, o: py2neo.Node) -> bool:
        """

        Parameters
        ----------
        o

        Returns
        -------

        """
        self.storage_graph.add_node(o[NODE_INDEX], **{NODE_LINENO: o[NODE_LINENO], NODE_TYPE: o[NODE_TYPE]})
        return True
