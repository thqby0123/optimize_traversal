from typing import List, Union, Dict, Set
import py2neo
from pjscan.const import *
from pjscan.exceptions import Neo4jNodeListIndexError
import networkx
from .abstract_step import AbstractStep


class PDGStep(AbstractStep):
    def __init__(self, parent):
        super().__init__(parent, "pdg_step")

    def find_use_nodes(self, _node: py2neo.Node) -> List[py2neo.Node]:
        """For given DEFINE node , return all of its direct USE nodes

        Parameters
        ----------
        _node : py2neo.Node
        the given node must in type of [TYPE_ASSIGN , TYPE_ASSIGN_OP , TYPE_ASSIGN_REF]

        Returns
        -------
        object : List[py2neo.Node]


        Notes
        -----

        Basic Query for Neo4j

        ```
        MATCH (A:AST)-[:REACHES]->(B:AST) WHERE id(A)=? RETURN A;
        ```
        """
        if self.parent._use_cache:
            if self.parent.cache.get_pdg_outflow(_node) is None:
                rels = self.parent.neo4j_graph.relationships.match(nodes=[_node, None], r_type=DATA_FLOW_EDGE, ).all()
                self.parent.cache.add_pdg_outflow(_node, rels)
                res = [i.end_node for i in rels]
            else:
                res = self.parent.cache.get_pdg_outflow(_node)
        else:
            res = [i.end_node for i in
                   self.parent.neo4j_graph.relationships.match(nodes=[_node, None], r_type=DATA_FLOW_EDGE, )]

        return list(sorted([i for i in res if i is not None], key=lambda x: x[NODE_INDEX]))

    def find_def_nodes(self, _node: py2neo.Node) -> List[py2neo.Node]:
        """For given USE node , return all of its direct DEFINE nodes

        Parameters
        ----------
        _node : py2neo.Node

        Returns
        -------
        object : List[py2neo.Node]
        the return node must in type of [TYPE_ASSIGN , TYPE_ASSIGN_OP , TYPE_ASSIGN_REF]


        Notes
        -----

        Basic Query for Neo4j

        ```
        MATCH (A:AST)-[:REACHES]->(B:AST) WHERE id(B)=? RETURN B;
        ```
        """
        if self.parent._use_cache:
            if self.parent.cache.get_pdg_inflow(_node) is None:
                if _node not in self.parent.node_without_cache_hit and \
                        _node not in self.parent.node_with_cache_prefetch_hit and \
                        _node not in self.parent.node_with_cache_main_thread_hit:
                    self.parent.node_without_cache_hit.append(_node)
                rels = self.parent.neo4j_graph.relationships.match(nodes=[None, _node], r_type=DATA_FLOW_EDGE, ).all()
                self.parent.cache.add_pdg_inflow(_node, rels)
                res = [i.start_node for i in rels]
            else:
                self.parent.cache_hit += 1
                res, b = self.parent.cache.get_pdg_inflow(_node)
                if b:
                    self.parent.prefetch_hit += 1
                    if _node not in self.parent.node_without_cache_hit and \
                            _node not in self.parent.node_with_cache_prefetch_hit and \
                            _node not in self.parent.node_with_cache_main_thread_hit:
                        self.parent.node_with_cache_prefetch_hit.append(_node)
                else:
                    if _node not in self.parent.node_without_cache_hit and \
                            _node not in self.parent.node_with_cache_prefetch_hit and \
                            _node not in self.parent.node_with_cache_main_thread_hit:
                        self.parent.node_with_cache_main_thread_hit.append(_node)
        # self.parent._threadPool.put_entity(res)
        else:
            res = [i.start_node for i in
                   self.parent.neo4j_graph.relationships.match(nodes=[None, _node], r_type=DATA_FLOW_EDGE, )]

        return list(sorted(res, key=lambda x: x[NODE_INDEX]))

    def get_related_vars(self, _node_start: py2neo.Node, _node_end: py2neo.Node) -> List[str]:
        """For given start and end node , return the labels.

        Parameters
        ----------
        _node_end : py2neo.Node
        _node_start : py2neo.Node

        Returns
        -------
        object : List[str]

        Notes
        -----
        Basic Query for Neo4j

        ```
        MATCH (A:AST)-[r:REACHS]->(B:AST) WHERE id(A)=? and id(B)=? RETURN r.vars;
        ```
        """
        return [i.get(DATA_FLOW_SYMBOL) for i in
                self.parent.neo4j_graph.relationships.match(nodes=[_node_start, _node_end], r_type=CALLS_EDGE, )]
