from typing import List, Union, Dict, Set
import py2neo
from pjscan.const import *
import logging
from .abstract_step import AbstractStep

logger = logging.getLogger(__name__)


class CGStep(AbstractStep):
    def __init__(self, parent):
        super().__init__(parent, "cg_step")

    def find_decl_nodes(self, _node: py2neo.Node) -> List[py2neo.Node]:
        """For given callable node , return its calls.

        Parameters
        ----------
        _node : py2neo.Node
        the given node must in type of [TYPE_METHOD,TYPE_FUNC_DECL]

        Returns
        -------
        object : List[py2neo.Node]


        Notes
        -----

        Basic Query for Neo4j

        ```
        MATCH (CALL:AST)-[:CALLS]->(DECL:AST) WHERE id(CALL)=? RETURN DECL;
        ```
        """
        if self.parent._use_cache:
            if self.parent.cache.get_cg_outflow(_node) is None:
                rels = self.parent.neo4j_graph.relationships.match(nodes=[_node, None], r_type=CALLS_EDGE, ).all()
                self.parent.cache.add_cg_outflow(_node, rels)
                res = [i.end_node for i in rels]
            else:
                res = self.parent.cache.get_cg_outflow(_node)
          #  self.parent._threadPool.put_entity(res)
        else:
            res = [i.end_node for i in
                   self.parent.neo4j_graph.relationships.match(nodes=[_node, None], r_type=CALLS_EDGE, )]
        return list(sorted(res, key=lambda x: x[NODE_INDEX]))

    def find_call_nodes(self, _node: py2neo.Node) -> List[py2neo.Node]:
        """For given callable node , return its calls.

        Parameters
        ----------
        _node : py2neo.Node
        the given node must in type of [TYPE_METHOD,TYPE_FUNC_DECL]

        Returns
        -------
        object : List[py2neo.Node]


        Notes
        -----

        Basic Query for Neo4j

        ```
        MATCH (CALL:AST)-[:CALLS]->(DECL:AST) WHERE id(DECL)=? RETURN CALL;
        ```
        """
        if self.parent._use_cache:
            if self.parent.cache.get_cg_inflow(_node) is None:
                rels = self.parent.neo4j_graph.relationships.match(nodes=[None, _node], r_type=CALLS_EDGE, ).all()
                self.parent.cache.add_cg_inflow(_node, rels)
                res = [i.start_node for i in rels]
            else:
                res = self.parent.cache.get_cg_inflow(_node)
        else:
            res = [i.start_node for i in
                   self.parent.neo4j_graph.relationships.match(nodes=[None, _node], r_type=CALLS_EDGE, )]
        return list(sorted(res, key=lambda x: x[NODE_INDEX]))
