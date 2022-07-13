from typing import List, Union, Dict, Set
import py2neo
from pjscan.const import *
from .abstract_step import AbstractStep


class BasicStep(AbstractStep):
    """DOC HERE

    """
    def __init__(self, parent):
        """

        Parameters
        ----------
        parent
        """
        super().__init__(parent, "basic_step")
        self.neo4j_graph = parent.neo4j_graph

    def run(self, query) -> py2neo.NodeMatch:
        """The API for py2neo.graph.run

        Parameters
        ----------
        query

        Returns
        -------

        """
        return self.neo4j_graph.run(query)

    def run_and_fetch_one(self, query) -> py2neo.NodeMatch:
        """The API for py2neo.graph.run

        Parameters
        ----------
        query

        Returns
        -------

        """
        for i in self.neo4j_graph.run(query):
            return i
        return None

    def match(self, *args, **kwargs) -> py2neo.NodeMatch:
        """The API for py2neo.nodes.match

        Parameters
        ----------
        args
        kwargs

        Returns
        -------
        node_match : py2neo.NodeMatch

        Examples
        --------
        >>> neo4j_engine = AnalysisFramework()
        >>> res = neo4j_engine.match(LABEL_AST,**{NODE_LINENO : 5 , NODE_INDEX: 1498})
        >>> res.first()
        (_1044:AST {childnum: 1, classid: 0, fileid: 1489, funcid: 1490, id: 1498, lineno: 5, type: 'AST_ASSIGN'})
        """
        return self.neo4j_graph.nodes.match(*args, **kwargs)

    def match_first(self, *args, **kwargs) -> py2neo.Node:
        """The API for py2neo.nodes.match().first()

        Parameters
        ----------
        args
        kwargs

        Returns
        -------
        node_match : py2neo.Node

        Examples
        --------
        >>> res = neo4j_engine.match_first(LABEL_AST,**{NODE_LINENO : 5 , NODE_INDEX: 1498})
        (_1044:AST {childnum: 1, classid: 0, fileid: 1489, funcid: 1490, id: 1498, lineno: 5, type: 'AST_ASSIGN'})
        """
        return self.neo4j_graph.nodes.match(*args, **kwargs).first()

    def match_relationship(self, *args, **kwargs) -> py2neo.RelationshipMatch:
        """The API for py2neo.relationship.match()

        Parameters
        ----------
        args
        kwargs

        Other Parameters
        ----------------
        r_type : str

        Returns
        -------
        object : py2neo.RelationshipMatch

        Examples
        --------
        >>> r = neo4j_engine.match_relationship([start_node, None], r_type=EXTENDS_EDGE)
        >>> r.first()
        (_2400)-[:EXTENDS {}]->(_2290)
        >>> r.first().start_node
        (_2400:AST {childnum: 6, classid: 4216, endlineno: 53,
        fileid: 4038, funcid: 4039, id: 4216, lineno: 43, namespace: 'Test', type: 'AST_CLASS'})
        >>> r.first().end_node
        (_2290:AST {childnum: 3, classid: 4106, endlineno: 37,
        fileid: 4038, funcid: 4039, id: 4106, lineno: 18, namespace: 'Amy', type: 'AST_CLASS'})
        """
        return self.neo4j_graph.relationships.match(*args, **kwargs)

    def match_first_relationship(self, *args, **kwargs) -> py2neo.Relationship:
        """The API for py2neo.relationship.match().first()

        Parameters
        ----------
        args
        kwargs

        Other Parameters
        ----------------
        r_type : str

        Returns
        -------
        object : py2neo.Relationship

        Examples
        --------
        >>> r = neo4j_engine.match_first_relationship([start_node, None], r_type=EXTENDS_EDGE)
        (_2400)-[:EXTENDS {}]->(_2290)
        >>> r.start_node
        (_2400:AST {childnum: 6, classid: 4216, endlineno: 53,
        fileid: 4038, funcid: 4039, id: 4216, lineno: 43, namespace: 'Test', type: 'AST_CLASS'})
        >>> r.end_node
        (_2290:AST {childnum: 3, classid: 4106, endlineno: 37,
        fileid: 4038, funcid: 4039, id: 4106, lineno: 18, namespace: 'Amy', type: 'AST_CLASS'})
        """
        return self.neo4j_graph.relationships.match(*args, **kwargs).first()

    def get_node_itself(self, _id: int) -> py2neo.Node:
        """Get node by `id` field

        Parameters
        ----------
        _id : int

        Returns
        -------
        node : py2neo.Node

        Notes
        -----
        This api is query the `id` field for Node , rather than get the `id(Node)` result for node.
        To get query the `identity` field , use get_node_itself_by_identity to query

        Basic Query for Neo4j

        ```sql
        MATCH (A:AST) WHERE A.id = ? RETURN A;
        ```

        Examples
        --------
        >>> r = neo4j_engine.get_node_itself(4216)
        (_2400:AST {childnum: 6, classid: 4216, endlineno: 53,
        fileid: 4038, funcid: 4039, id: 4216, lineno: 43, namespace: 'Test', type: 'AST_CLASS'})
        """
        if self.parent._use_cache and self.parent.cache.get_node(_id):
            return self.parent.cache.get_node(_id)
        else:
            node = self.neo4j_graph.nodes.match(id=_id).limit(1).first()
            if self.parent._use_cache:
                self.parent.cache.add_node(node)
            return node

    def get_node_itself_by_identity(self, _id: int):
        """Get node by `identity` field

        Parameters
        ----------
        _id : int

        Returns
        -------
        node : py2neo.Node

        Notes
        -----

        Basic Query for Neo4j

        ```sql
        MATCH (A:AST) WHERE id(A)=? RETURN A;
        ```

        Examples
        --------
        >>> r = neo4j_engine.get_node_itself_by_identity(2400)
        (_2400:AST {childnum: 6, classid: 4216, endlineno: 53,
        fileid: 4038, funcid: 4039, id: 4216, lineno: 43, namespace: 'Test', type: 'AST_CLASS'})
        """
        return self.neo4j_graph.nodes.get(identity=_id)
