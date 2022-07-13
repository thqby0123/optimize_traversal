import copy
import sys

import networkx as nx
import py2neo
from typing import List
from abc import ABC, abstractmethod
from pjscan.const import *


class AbstractCacheGraph(ABC):
    """
    Basic Cache Graph

    You can extends this class to definite your own cache.

    Use Digraph to record the relationship information and use hashtable to record property information.

    Attributes
    ----------

    node_cache_pool: dict
        A hashtable that the key is node_id and the value is py2neo.Node

        when we get a node_id from cache we can use this hashtable to find the node and return

    Notes
    -----
    You can extend the class and use more attribute to cache more information about the node.

    You can use networkx.Digraph() to record relationships of a node and use hashtable to record properties of a node.

    We provide a base cache model and You can use it.

    BasicCacheGraph



    """

    def __init__(self, **kwargs):
        """Initial the abstract class

        Parameters
        ----------
        node_cache_pool:dict
            A hashtable that the key is node_id and the value is py2neo.Node

            when we get a node_id from cache we can use this hashtable to find the node and return

        """
        self.node_cache_pool = {}
        self.node_source = {}
    @abstractmethod
    def get_node(self, _node_index):
        """For given node index, return a node entity in py2neo

        Parameters
        ----------
        _node_index : Integer

        Returns
        -------
        node : py2neo.Node

        """
        return self.node_cache_pool.get(_node_index, False)

    @abstractmethod
    def add_node(self, node: py2neo.Node):
        """For a given node, add it into cache

        Parameters
        ----------
        node : py2neo.Node

        """
        node = copy.deepcopy(node)
        if not node[NODE_INDEX] in self.node_cache_pool.keys():
            self.node_cache_pool[node[NODE_INDEX]] = node


class BasicCacheGraph(AbstractCacheGraph):
    """
    Attributes
    ----------

    ast_cache_graph: networkx.Digraph()
        a graph that store the ast information

    cfg_cache_graph: networkx.Digraph()
        a graph that store the cfg information

    pdg_cache_graph: networkx.Digraph()
        a graph that store the pdg information

    cg_cache_graph: networkx.Digraph()
        a graph that store the cg information

    node_code_cache_pool:dict
        a hashtable that store the code information

    Notes
    -----
    Other attribution and method is as same as ast_cache_graph, add_ast_outflow() and get_ast_outflow()

    You can also write your cache extends this class

    """

    def __init__(self, **kwargs):
        """ Initial this class

        Parameters
        ----------

        ast_cache_graph
            the cache graph that store ast relationship

        cfg_cache_graph
            the cache graph that store cfg relationship

        pdg_cache_graph
            the cache graph that store pdg relationship

        cg_cache_graph
            the cache graph that store cg relationship

        node_code_cache_pool
            the hashtable that store node code

        customize_storage
            A dict that store cunstomized cache

            You can definite your own cache like, self.customize_storage[Customize_cache] = Dict or Digraph
        """
        self.ast_cache_graph = nx.DiGraph()
        self.cfg_cache_graph = nx.DiGraph()
        self.pdg_cache_graph = nx.DiGraph()
        self.cg_cache_graph = nx.DiGraph()
        self.node_code_cache_pool = {}
        self.customize_storage = {}
        super().__init__(**kwargs)

    def get_node(self, _node_index):
        """For given node index, return a node entity in py2neo

        Parameters
        ----------
        _node_index : Integer

        Returns
        -------
        node : py2neo.Node

        """
        return self.node_cache_pool.get(_node_index, False)

    def add_node(self, node: py2neo.Node,source:str='traversal'):
        """For a given node, add it into cache

        Parameters
        ----------
        node : py2neo.Node

        """
        if not self.ast_cache_graph.has_node(node[NODE_INDEX]):
            self.ast_cache_graph.add_node(node[NODE_INDEX], visiable=0b00)

        if not self.cfg_cache_graph.has_node(node[NODE_INDEX]):
            self.cfg_cache_graph.add_node(node[NODE_INDEX], visiable=0b00)

        if not self.pdg_cache_graph.has_node(node[NODE_INDEX]):
            self.pdg_cache_graph.add_node(node[NODE_INDEX], visiable=0b00)

        if not self.cg_cache_graph.has_node(node[NODE_INDEX]):
            self.cg_cache_graph.add_node(node[NODE_INDEX], visiable=0b00)

        if not self.node_cache_pool.__contains__(node[NODE_INDEX]):
            self.node_cache_pool[node[NODE_INDEX]] = node
            self.node_source[node[NODE_INDEX]] = source

    def add_ast_outflow(self, node: py2neo.Node, relationships: List[py2neo.Relationship]):
        """For a given node and ast outflow relationships, add this node and relationships into ast graph

        Parameters
        ----------
        node : py2neo.Node
        relationships :  List[py2neo.Relationship]
        """
        self.add_node(node)
        if not self.ast_cache_graph.nodes[node[NODE_INDEX]]['visiable'] & 0b10:
            self.ast_cache_graph.nodes[node[NODE_INDEX]]['visiable'] |= 0b10
            for relationship in relationships:
                end_node = relationship.end_node
                self.add_node(end_node)
                end_node_id = end_node[NODE_INDEX]
                if not self.ast_cache_graph.has_edge(node[NODE_INDEX], end_node_id):
                    self.ast_cache_graph.add_edge(node[NODE_INDEX], end_node_id)

    def add_ast_inflow(self, node: py2neo.Node, relationships: List[py2neo.Relationship]):
        """For a given node and ast inflow relationships, add this node and relationships into ast graph

        Parameters
        ----------
        node : py2neo.Node
        relationships :  List[py2neo.Relationship]
        """
        self.add_node(node)
        if not self.ast_cache_graph.nodes[node[NODE_INDEX]]['visiable'] & 0b01:
            self.ast_cache_graph.nodes[node[NODE_INDEX]]['visiable'] |= 0b01
            for relationship in relationships:
                start_node = relationship.start_node
                self.add_node(start_node)
                start_node_id = start_node[NODE_INDEX]
                if not self.ast_cache_graph.has_edge(start_node_id, node[NODE_INDEX]):
                    self.ast_cache_graph.add_edge(start_node_id, node[NODE_INDEX])

    def get_ast_inflow(self, node: py2neo.Node):
        """For a given node, return the ast inflow relationships store in ast graph.

        Parameters
        ----------
        node : py2neo.Node

        Returns
        -------
        rels : List[py2neo.Node]
        """
        self.add_node(node)
        if self.ast_cache_graph.nodes[node[NODE_INDEX]]['visiable'] & 0b01:
            rels = [self.node_cache_pool.get(node_id) for node_id in
                    list(self.ast_cache_graph.predecessors(node[NODE_INDEX]))]
            return rels
        return None

    def get_ast_outflow(self, node: py2neo.Node):
        """For a given node, return the ast outflow relationships store in ast graph.

        Parameters
        ----------
        node : py2neo.Node

        Returns
        -------
        rels : List[py2neo.Node]
        """
        self.add_node(node)
        if self.ast_cache_graph.nodes[node[NODE_INDEX]]['visiable'] & 0b10:
            rels = [self.node_cache_pool.get(node_id) for node_id in
                    list(self.ast_cache_graph.successors(node[NODE_INDEX]))]
            return rels
        return None

    def add_cfg_outflow(self, node: py2neo.Node, relationships: List[py2neo.Relationship]):
        """For a given node and cfg outflow relationships, add this node and relationships into cfg graph

        Parameters
        ----------
        node : py2neo.Node
        relationships :  List[py2neo.Relationship]
        """
        self.add_node(node)
        if not self.cfg_cache_graph.nodes[node[NODE_INDEX]]['visiable'] & 0b10:
            self.cfg_cache_graph.nodes[node[NODE_INDEX]]['visiable'] |= 0b10
            for relationship in relationships:
                end_node = relationship.end_node
                self.add_node(end_node)
                end_node_id = end_node[NODE_INDEX]
                if not self.cfg_cache_graph.has_edge(node[NODE_INDEX], end_node_id):
                    self.cfg_cache_graph.add_edge(node[NODE_INDEX], end_node_id)

    def add_cfg_inflow(self, node: py2neo.Node, relationships: List[py2neo.Relationship]):
        """For a given node and cfg inflow relationships, add this node and relationships into cfg graph

        Parameters
        ----------
        node : py2neo.Node
        relationships :  List[py2neo.Relationship]
        """
        self.add_node(node)
        if not self.cfg_cache_graph.nodes[node[NODE_INDEX]]['visiable'] & 0b01:
            self.cfg_cache_graph.nodes[node[NODE_INDEX]]['visiable'] |= 0b01
            for relationship in relationships:
                start_node = relationship.start_node
                self.add_node(start_node)
                start_node_id = start_node[NODE_INDEX]
                if not self.cfg_cache_graph.has_edge(start_node_id, node[NODE_INDEX]):
                    self.cfg_cache_graph.add_edge(start_node_id, node[NODE_INDEX])

    def get_cfg_inflow(self, node: py2neo.Node):
        """For a given node, return the cfg inflow relationships store in cfg graph.

        Parameters
        ----------
        node : py2neo.Node

        Returns
        -------
        rels : List[py2neo.Node]
        """
        self.add_node(node)
        if self.cfg_cache_graph.nodes[node[NODE_INDEX]]['visiable'] & 0b01:
            rels = [self.node_cache_pool.get(node_id) for node_id in
                    list(self.cfg_cache_graph.predecessors(node[NODE_INDEX]))]
            return rels
        return None

    def get_cfg_outflow(self, node: py2neo.Node):
        """For a given node, return the cfg outflow relationships store in cfg graph.

        Parameters
        ----------
        node : py2neo.Node

        Returns
        -------
        rels : List[py2neo.Node]
        """
        self.add_node(node)
        if self.cfg_cache_graph.nodes[node[NODE_INDEX]]['visiable'] & 0b10:
            rels = [self.node_cache_pool.get(node_id) for node_id in
                    list(self.cfg_cache_graph.successors(node[NODE_INDEX]))]
            return rels
        return None

    def add_pdg_outflow(self, node: py2neo.Node, relationships: List[py2neo.Relationship]):
        """For a given node and pdg outflow relationships, add this node and relationships into pdg graph

        Parameters
        ----------
        node : py2neo.Node
        relationships :  List[py2neo.Relationship]
        """
        self.add_node(node)
        if not self.pdg_cache_graph.nodes[node[NODE_INDEX]]['visiable'] & 0b10:
            self.pdg_cache_graph.nodes[node[NODE_INDEX]]['visiable'] |= 0b10
            for relationship in relationships:
                end_node = relationship.end_node
                self.add_node(end_node)
                end_node_id = end_node[NODE_INDEX]
                if not self.pdg_cache_graph.has_edge(node[NODE_INDEX], end_node_id):
                    self.pdg_cache_graph.add_edge(node[NODE_INDEX], end_node_id,taint_var = relationship['var'])

    def add_pdg_inflow(self, node: py2neo.Node, relationships: List[py2neo.Relationship], source: str = "traversal"):
        """For a given node and pdg inflow relationships, add this node and relationships into pdg graph

        Parameters
        ----------
        node : py2neo.Node
        relationships :  List[py2neo.Relationship]
        """
        self.add_node(node,source=source)
        if not self.pdg_cache_graph.nodes[node[NODE_INDEX]]['visiable'] & 0b01:
            self.pdg_cache_graph.nodes[node[NODE_INDEX]]['visiable'] |= 0b01
            for relationship in relationships:
                start_node = relationship.start_node
                self.add_node(start_node,source=source)
                start_node_id = start_node[NODE_INDEX]
                if not self.pdg_cache_graph.has_edge(start_node_id, node[NODE_INDEX]):
                    self.pdg_cache_graph.add_edge(start_node_id, node[NODE_INDEX], source=source,taint_var = relationship['var'])

    def get_pdg_inflow(self, node: py2neo.Node):
        """For a given node, return the pdg inflow relationships store in pdg graph.

        Parameters
        ----------
        node : py2neo.Node

        Returns
        -------
        rels : List[py2neo.Node]
        """
        self.add_node(node)
        if self.pdg_cache_graph.nodes[node[NODE_INDEX]]['visiable'] & 0b01:
            rels = [self.node_cache_pool.get(node_id) for node_id in
                    list(self.pdg_cache_graph.predecessors(node[NODE_INDEX]))]
            if rels == []:
                return rels, True # 空的时候，一定是prefetch hit么？
            elif \
            self.pdg_cache_graph.edges[list(self.pdg_cache_graph.predecessors(node[NODE_INDEX]))[0], node[NODE_INDEX]][
                'source'] == 'prefetch':
                return rels, True
            else:
                return rels, False
        return None

    def get_pdg_outflow(self, node: py2neo.Node):
        """For a given node, return the pdg outflow relationships store in pdg graph.

        Parameters
        ----------
        node : py2neo.Node

        Returns
        -------
        rels : List[py2neo.Node]
        """
        self.add_node(node)
        if self.pdg_cache_graph.nodes[node[NODE_INDEX]]['visiable'] & 0b10:
            rels = [self.node_cache_pool.get(node_id) for node_id in
                    list(self.pdg_cache_graph.successors(node[NODE_INDEX]))]
            return rels
        return None

    def add_cg_outflow(self, node: py2neo.Node, relationships: List[py2neo.Relationship]):
        """For a given node and cg outflow relationships, add this node and relationships into cg graph

        Parameters
        ----------
        node : py2neo.Node
        relationships :  List[py2neo.Relationship]
        """
        self.add_node(node)
        if not self.cg_cache_graph.nodes[node[NODE_INDEX]]['visiable'] & 0b10:
            self.cg_cache_graph.nodes[node[NODE_INDEX]]['visiable'] |= 0b10
            for relationship in relationships:
                end_node = relationship.end_node
                self.add_node(end_node)
                end_node_id = end_node[NODE_INDEX]
                if not self.cg_cache_graph.has_edge(node[NODE_INDEX], end_node_id):
                    self.cg_cache_graph.add_edge(node[NODE_INDEX], end_node_id)

    def add_cg_inflow(self, node: py2neo.Node, relationships: List[py2neo.Relationship]):
        """For a given node and cg inflow relationships, add this node and relationships into cg graph

        Parameters
        ----------
        node : py2neo.Node
        relationships :  List[py2neo.Relationship]
        """
        self.add_node(node)
        if not self.cg_cache_graph.nodes[node[NODE_INDEX]]['visiable'] & 0b01:
            self.cg_cache_graph.nodes[node[NODE_INDEX]]['visiable'] |= 0b01
            for relationship in relationships:
                start_node = relationship.start_node
                self.add_node(start_node)
                start_node_id = start_node[NODE_INDEX]
                if not self.cg_cache_graph.has_edge(start_node_id, node[NODE_INDEX]):
                    self.cg_cache_graph.add_edge(start_node_id, node[NODE_INDEX])

    def get_cg_inflow(self, node: py2neo.Node):
        """For a given node, return the cg inflow relationships store in cg graph.

        Parameters
        ----------
        node : py2neo.Node

        Returns
        -------
        rels : List[py2neo.Node]
        """
        self.add_node(node)
        if self.cg_cache_graph.nodes[node[NODE_INDEX]]['visiable'] & 0b01:
            rels = [self.node_cache_pool.get(node_id) for node_id in
                    list(self.cg_cache_graph.predecessors(node[NODE_INDEX]))]
            return rels
        return None

    def get_cg_outflow(self, node: py2neo.Node):
        """For a given node, return the cg outflow relationships store in cg graph.

        Parameters
        ----------
        node : py2neo.Node

        Returns
        -------
        rels : List[py2neo.Node]
        """
        self.add_node(node)
        if self.cg_cache_graph.nodes[node[NODE_INDEX]]['visiable'] & 0b10:
            rels = [self.node_cache_pool.get(node_id) for node_id in
                    list(self.cg_cache_graph.successors(node[NODE_INDEX]))]
            return rels
        return None

    def add_node_code_cache(self, node: py2neo.Node, code: str):
        """For a given node and node code, add this node and code into node_code_cache_pool

        Parameters
        ----------
        node : py2neo.Node
        code :  str
        """
        if not self.node_code_cache_pool.__contains__(node[NODE_INDEX]):
            self.node_code_cache_pool[node[NODE_INDEX]] = code

    def get_node_code(self, node: py2neo.Node):
        """For a given node, return the node code store in node_code_cache_pool

        Parameters
        ----------
        node : py2neo.Node

        Returns
        -------
        result : str
        """
        return self.node_code_cache_pool.get(node[NODE_INDEX], None)

    def get_memory_size(self):
        memory_size = sys.getsizeof(self.customize_storage)+sys.getsizeof(self.node_cache_pool)
        print(f"customize_storage {sys.getsizeof(self.customize_storage)}")
        print(f"node_cache_pool {sys.getsizeof(self.node_cache_pool)}")
        pdg_size = 0;
        for customized_ in list(self.customize_storage.keys()):
            dict = self.customize_storage.get(customized_,None)

        for e in self.pdg_cache_graph.edges():
            pdg_size += sys.getsizeof(e);
        print(f"pdg_size {pdg_size}")
        return memory_size+pdg_size