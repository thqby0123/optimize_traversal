from typing import List, Union, Dict, Set
import py2neo
from pjscan.const import *
from pjscan.exceptions import Neo4jNodeListIndexError
import networkx as nx
from collections import deque
from pjscan.helper import StringMatcher
from .abstract_step import AbstractStep


class FIGStep(AbstractStep):
    def __init__(self, parent):
        super().__init__(parent, "fig_step")

    def get_filesystem_node(self, _node: py2neo.Node) -> py2neo.Node:
        """Return the Filesytem node

        Parameters
        ----------
        _node

        Returns
        -------
        object : py2neo.Node
        the return node has label 'File'

        Notes
        -----

        Basic Query for Neo4j

        ```
        MATCH (A:FleSystem) WHERE A.id=?.fileid RETURN A;
        ```


        """
        return self.parent.basic_step.match_first(LABEL_FILESYSTEM,
                                                  **{NODE_TYPE: "File", NODE_INDEX: _node[NODE_FILEID]})

    def find_include_src(self, _node: py2neo.Node) -> List[py2neo.Node]:
        """For given FILE node

        ```
        // a.php
        include ("b.php")
        // b.php
        echo b;
        ```
        Here we get the edge (a.php)-[:INCLUDE]->(b.php)
        we call a.php as include_src and b.php as include_dst

        Parameters
        ----------
        _node : py2neo.Node
        the given node must in type of [TYPE_FILE]

        Returns
        -------
        object : List[py2neo.Node]


        Notes
        -----

        Basic Query for Neo4j

        ```
        MATCH (A:AST)-[:INCLUDE]->(B:AST) WHERE id(B)=? RETURN B;
        ```
        """
        res = [i.start_node for i in
               self.parent.neo4j_graph.relationships.match(nodes=[None, _node], r_type=INCLUDE_EDGE, )]
        return list(sorted(res, key=lambda x: x[NODE_INDEX]))

    def find_include_dst(self, _node: py2neo.Node) -> List[py2neo.Node]:
        """For given file node , return its callable node.

        ```
        // a.php
        include ("b.php")
        // b.php
        echo b;
        ```
        Here we get the edge (a.php)-[:INCLUDE]->(b.php)
        we call a.php as include_src and b.php as include_dst

        Parameters
        ----------
        _node : py2neo.Node
        the given node must in type of [TYPE_FILE]

        Returns
        -------
        object : List[py2neo.Node]


        Notes
        -----

        Basic Query for Neo4j

        ```
        MATCH (A:AST)-[:INCLUDE]->(B:AST) WHERE id(A)=? RETURN A;
        ```
        """
        return [i.end_node for i in
                self.parent.neo4j_graph.relationships.match(nodes=[_node, None], r_type=INCLUDE_EDGE, )]

    def get_include_map(self, _node: py2neo.Node) -> nx.DiGraph:
        """For given file node , return its callable node.

        ```
        // a.php
        include ("b.php")
        // b.php
        echo b;
        ```
        Here we get the edge (a.php)-[:INCLUDE]->(b.php)
        we call a.php as include_src and b.php as include_dst

        Parameters
        ----------
        _node : py2neo.Node
        the given node must in type of [TYPE_FILE]

        Returns
        -------
        object : nx.DiGraph


        Notes
        -----

        Basic Query for Neo4j

        ```
        MATCH (A:AST)-[:INCLUDE]->(B:AST) WHERE id(A)=? RETURN A;
        ```
        """
        return_map = nx.DiGraph()
        return_map.add_node(_node.identity, **_node)
        queue: deque[py2neo.Node] = deque()
        queue.append(_node)
        while queue.__len__() != 0:
            current_node = queue.popleft()
            for node in self.parent.find_fig_include_dst(current_node):
                return_map.add_node(node.identity, **_node)
                return_map.add_edge(current_node.identity, node.identity)
                queue.append(node)
        return return_map

    def get_belong_file(self, _node: py2neo.Node) -> str:
        """Return file name which belong to the given node

        Parameters
        ----------
        _node : py2neo.Node

        Returns
        -------
        object : str

        """
        file_system_node = self.parent.match(LABEL_FILESYSTEM, id=_node[NODE_FILEID]).first()
        return self.get_node_from_file_system(file_system_node)[NODE_NAME]

    def get_file_name_node(self, _file_name: str, match_strategy=1) -> Union[py2neo.Node, None]:
        """

        Parameters
        ----------
        _file_name : str
            The name of given file, if use relax mode, the file name can be relative path or not imcomplete path
        match_strategy : int
            The option of match_strategy
            - 0             strict mode , the full filename with absolute path should be given
            - 1 (default)   relax  mode , return the best similarity of name node

        Returns
        -------
        node :  Union[py2neo.Node, None]
            The return node must be  TYPE_TOPLEVEL with FLAG  FLAG_TOPLEVEL_FILE

        Examples
        --------
        >>> neo4j_engine.get_file_name_belong_node("classExtendsTest7.php")
        (_2223:AST {endlineno: 57, fileid: 4038, flags: ['TOPLEVEL_FILE'], id: 4039, lineno: 1, type: 'AST_TOPLEVEL'
        name: '../enhanced-phpjoern-framework/tests/resource//NormalCase/CHG/classExtendsTest7/classExtendsTest7.php'})

        Notes
        -----
        The name of TOPLEVEL_FILE node refer to the given format of php2ast.

        For given absolute path like

        ```shell
        $ php2ast /path/to/code/code_dir
        ```

        The prefix of each file will be /path/to/code/code_dir

        For given absolute path like

        ```shell
        $ php2ast ../../code_dir
        ```

        The prefix of each file will be ../../code_dir

        Note that this situation is php-ast's default action ,rather than bug in EnhancedPHPJoern frontend

        That is why we need to use relax mode (Distance Similarity) to solve this problem.
        """
        if match_strategy == 1:
            nodes = [i for i in
                     self.parent.match("AST", ).where(
                         f"_.type='{TYPE_TOPLEVEL}' and   _.name CONTAINS '{_file_name}' ")]
            if nodes.__len__() >= 1:
                best_index = StringMatcher.match_best_similar_str_index(_file_name, [i[NODE_NAME] for i in nodes])
                return nodes[best_index]
            else:
                return None  # file not found error;
        elif match_strategy == 0:
            return self.parent.match(LABEL_AST, ).where(f"_.type='{TYPE_TOPLEVEL}' and '{_file_name}' =  _.name").limit(
                1).first()

    def get_node_from_file_system(self, _node: py2neo.Node) -> py2neo.Node:
        """
        given

        :param _node:
        :return:
        """
        r = self.parent.neo4j_graph.relationships.match(nodes=[_node], r_type=FILE_EDGE).first()
        return r.end_node

    def get_toplevel_file_first_statement(self, toplevel_file_node):
        assert toplevel_file_node[NODE_TYPE] in {TYPE_TOPLEVEL} and \
               NODE_FLAGS in toplevel_file_node.keys() and \
               set(toplevel_file_node[NODE_FLAGS]) & {FLAG_TOPLEVEL_FILE}
        stmt = self.parent.get_ast_child_node(toplevel_file_node)
        return self.parent.get_ast_child_node(stmt)

    def get_top_filesystem_node(self, _node: py2neo.Node) -> py2neo.Node:
        """Return the Filesytem node

        Parameters
        ----------
        _node

        Returns
        -------
        object : py2neo.Node
        the return node has label 'File'

        Notes
        -----

        Basic Query for Neo4j

        ```
        MATCH (A:FleSystem) WHERE A.id=?.fileid RETURN A;
        ```


        """
        return self.parent.match_first(LABEL_FILESYSTEM, **{NODE_TYPE: "File", NODE_INDEX: _node[NODE_FILEID]})
