import py2neo

from abc import ABCMeta, ABC, abstractclassmethod, abstractmethod, abstractproperty
from typing import Dict, Set, Union, List, Callable
from py2neo import Node, Relationship
import networkx as nx
from collections import deque
from pjscan.analysis_framework import AnalysisFramework
from pjscan.graph_traversal_recorder import BaseRecorder, GraphTraversalRecorder
from pjscan.const import *

DEFAULT_SANTITZER = lambda *args, **kwargs: False  # return True, treat as sanitizer , stack the traversal

__all__ = ["BaseGraphTraversal",
           "ControlGraphForwardTraversal", "GlobalControlGraphForwardTraversal",
           "GlobalProgramDependencyGraphBackwardTraversal", "ProgramDependencyGraphBackwardTraversal"]

ORIGIN_RULE = 0xcf01
TERMINAL_RULE = 0xcf02
SANITIZER_RULE = 0xcf03


class BaseGraphTraversal(object):
    """Base graph traversal


    Parameters
    ----------
    sanitizer : List[Callable]  (optional)

        The default value for sanitizer is list contain a lambda function which always return False,
        which means the sanitizer will **never** block the traversal process

        >>> DEFAULT_SANTITZER = lambda *args, **kwargs: False
        >>> sanitizer = [DEFAULT_SANTITZER]

    recorder : Callable  (optional)

        The default value for recorder is :class:`~pjscan.graph_traversal_recorder.GraphTraversalRecorder`
        This recorder class will record all the path visited.

    origin : List[Node]
        The origin of graph traversal.

    terminal : List[Callable] (optional,default [])
        The terminal of graph traversal.

    analysis_framework : AnalysisFramework
        The class instance of :class:`~pjscan.AnalysisFramework`

    Attributes
    ----------
    origin: List[Node]
        The origin of graph traversal.

    terminal: List[Callable]
        The terminal of graph traversal.

    sanitizer: List[Callable]
        The sanitizer of graph traversal.

    recorder: BaseRecorder
        The result recorder of graph traversal.


    Examples
    --------

    This is an example to create the ``terminal`` rule.
    If the terminal node is clear, you can create an anonymous function
    and set it as the ``terminal`` attribute of ``GraphTraversal`` class.

    >>> graph_traversal = BaseGraphTraversal(analysis_framework=AnalysisFramework())
    >>> terminal_node = analysis_framework.match_first(**{
    ...     NODE_FILEID: file_name_node[NODE_FILEID], NODE_TYPE: TYPE_BINARY_OP, NODE_LINENO: 212,
    ... })
    >>> graph_traversal.terminal = [lambda x: x[NODE_INDEX] <= terminal_node[NODE_INDEX]]

    This is an example to create the ``sanitizer`` rule
    If user don't want to track the node after the given terminal node,
    the ``sanitizer`` rule can be seted as follows

    >>> graph_traversal.sanitizer = [lambda x: x[NODE_INDEX] > terminal_node[NODE_INDEX]]

    Note that the return value of sanitizer function means whether this node has been sanitized (which means not track it )
    and the default sanitizer rule is always return False

    >>> DEFAULT_SANTITZER = lambda *args, **kwargs: False

    This is an example to create the ``traverse`` rule.
    This implementation means we will only track the TRUE branc of IF statement.

    >>> class ControlGraphForwardTrueBranchTraversal(BaseGraphTraversal):
    ...     def traversal(self, node, *args, **kwargs):
    ...         parent_node = self.analysis_framework.get_ast_parent_node(node)
    ...         if parent_node[NODE_TYPE] == TYPE_IF_ELEM and node[NODE_CHILDNUM] == 0:
    ...             x = self.analysis_framework.find_cfg_successors(node)
    ...             return [x[0]]
    ...         else:
    ...             return self.analysis_framework.find_cfg_successors(node)

    This is an example to set ``record`` rule, the record rule must a class of BaseRecord
    This us implementation to record the node and edge in ``nx.Digraph``.

    >>> class GraphTraversalRecorder(BaseRecorder):
    ...     def __init__(self, analysis_framework: AnalysisFramework):
    ...         super(GraphTraversalRecorder, self).__init__(analysis_framework)
    ...         self.storage_graph = nx.DiGraph()
    ...
    ...     def record(self, node: py2neo.Node, next_node: py2neo.Node) -> bool:
    ...         self.storage_graph.add_node(next_node.identity,
    ...                                     **{NODE_LINENO: next_node[NODE_LINENO], NODE_TYPE: next_node[NODE_TYPE]})
    ...         self.storage_graph.add_edge(node.identity, next_node.identity)
    ...         return True
    ...
    ...     def record_origin(self, o: py2neo.Node) -> bool:
    ...         self.storage_graph.add_node(o.identity, **{NODE_LINENO: o[NODE_LINENO], NODE_TYPE: o[NODE_TYPE]})
    ...         return True

    Notes
    -----
    You can extend this class your self.

    Otherwise, we provide 4 class which extends it , which used for analysis different flows

    - :class:`~pjscan.graph_traversal.ProgramDependencyGraphBackwardTraversal`
    - :class:`~pjscan.graph_traversal.ControlGraphForwardTraversal`
    - :class:`~pjscan.graph_traversal.GlobalProgramDependencyGraphBackwardTraversal`
    - :class:`~pjscan.graph_traversal.GlobalControlGraphForwardTraversal`


    """

    def __init__(self, analysis_framework: AnalysisFramework,
                 origin: List[Callable] = None,
                 terminal: List[Callable] = None,
                 sanitizer: List[Callable] = None,
                 recorder: Callable = None):
        """

        Parameters
        ----------
        sanitizer : List[Callable]
        recorder : Callable
        origin : List[Node]
            The origin of graph traversal
        terminal : List[Callable]
            The terminal of graph traversal. Note that
        analysis_framework : AnalysisFramework
        """
        if sanitizer is None:
            sanitizer = [DEFAULT_SANTITZER]
        if origin is None:
            origin = []
        if terminal is None:
            terminal = []
        if recorder is None:
            recorder = GraphTraversalRecorder
        self.analysis_framework: AnalysisFramework = analysis_framework
        self.cache_graph = self.analysis_framework.cache

        self.__visit_node_pool: Dict = {}
        self._origin: List[Callable] = origin
        self.origin = []
        self.terminal: List[Callable] = terminal
        self.sanitizer: List[Callable] = sanitizer
        self.recorder: BaseRecorder = recorder(analysis_framework)
        self._result: List[Node] = []

        self.traversal_param_list = {}
        self.sanitizer_param_list = {}
        self.terminal_param_list = {}

    def get_record(self):
        """Return the record storage_graph.

        Returns
        -------

        """
        return self.recorder.storage_graph

    def get_result(self):
        """Return the exact terminal node which can be reachable through traversal

        Returns
        -------

        """
        return self._result

    @abstractmethod
    def traversal(self, current_node, *args, **kwargs):
        """Atom traversal graph step.

        Parameters
        ----------
        current_node
        args
        kwargs

        Returns
        -------

        """
        return self.analysis_framework.find_cfg_successors(current_node)

    def init_traversal(self):
        """Init the traversal graph

        - Apply sink rules
        - Apply terminal rules
        - Apply sanitizer rules

        Returns
        -------

        """
        if self.origin.__len__() != 0:
            return True

        if self._origin.__len__() == 0:
            raise IndexError("self.origin should not be empty")
        if isinstance(self._origin[0], py2neo.Node):
            self.origin = self._origin  # type:List[py2neo.Node]
        else:
            for origin_func in self._origin:
                self.origin.extend(origin_func(self.analysis_framework))

    def run(self):
        """Main entrance

        Returns
        -------

        """
        self.__visit_node_pool = {}
        self.init_traversal()
        # Note that to implement a queue , append is add item to tail and popleft is pop item from head.
        query: deque[py2neo.Node] = deque()
        for o in self.origin:  # may be run should only serve the first elem
            query.append(o)
            self.__visit_node_pool[o[NODE_INDEX]] = {}
            o['origin'] = o[NODE_INDEX]
            self.recorder.record_origin(o)
        # 为理想情况下，这里应该涉及成消费者生产者模式
        while query.__len__() != 0:
            current_node = query.popleft()
            next_nodes = []
            candidate_nodes = []

            if current_node['origin'] in self.__visit_node_pool.keys() \
                    and current_node.identity in self.__visit_node_pool[current_node['origin']].keys():
                self.__visit_node_pool[current_node['origin']][current_node.identity] += 1
                continue
            else:
                self.__visit_node_pool[current_node['origin']][current_node.identity] = 1

            node__ = self.traversal(current_node, **self.traversal_param_list)
            for node_ in node__:
                node_['origin'] = current_node['origin']
            candidate_nodes.extend(node__)  # How to pass args...

            for candidate_node in candidate_nodes:
                # _sanitize_flag_pass = (1 << self.sanitizer.__len__()) - 1
                _sanitize_flag = 0b0  # (1 << (self.sanitizer.__len__()-1))
                _terminal_flag = 0b0
                for index, rule in enumerate(self.sanitizer, start=0):
                    _sanitize_flag |= 0 if rule(candidate_node, **self.sanitizer_param_list) else (
                            1 << index)  # How to add dynamic args...
                if _sanitize_flag == (1 << self.sanitizer.__len__()) - 1:
                    for index, rule in enumerate(self.terminal, start=0):
                        _terminal_flag |= (1 << index) if rule(candidate_node,
                                                               **self.terminal_param_list) else 0
                        # is terminal. return 1.
                    if _terminal_flag > 0:
                        self._result.append(candidate_node)
                    next_nodes.append(candidate_node)
            # record part
            for next_node in next_nodes:
                # Add data to digraph
                if self.recorder.record(current_node, next_node,taint_var = next_node['taint_var']):
                    query.append(next_node)


class ProgramDependencyGraphBackwardTraversal(BaseGraphTraversal):
    """The PDG Backward Traversal Interface with Intraprocedural Analysis

    """

    def __init__(self, *args, **kwargs):
        """

        Parameters
        ----------
        args
        kwargs
        """
        super(ProgramDependencyGraphBackwardTraversal, self).__init__(*args, **kwargs)

    def traversal(self, node, *args, **kwargs):
        # to avoid repeat traversal we can do like this.
        return self.analysis_framework.find_pdg_def_nodes(node)


class ControlGraphForwardTraversal(BaseGraphTraversal):
    """The CFG Forward Traversal Interface with Intraprocedural Analysis

    """

    def __init__(self, *args, **kwargs):
        """

        Parameters
        ----------
        args
        kwargs
        """
        super(ControlGraphForwardTraversal, self).__init__(*args, **kwargs)
        self.loop_structure_instance = {}

    def __switch(self, next_node):
        if next_node in self.loop_structure_instance.keys():
            return self.__switch(self.loop_structure_instance[next_node])
        else:
            return next_node

    def traversal(self, node, *args, **kwargs):
        # We can cut the loop structure's return node.
        next_nodes = self.analysis_framework.find_cfg_successors(node)
        result = []
        for next_node in next_nodes:
            parent_node = self.analysis_framework.get_ast_parent_node(node)
            if parent_node[NODE_TYPE] == TYPE_FOR and \
                    self.analysis_framework.get_ast_ith_child_node(parent_node, 2) \
                    not in self.loop_structure_instance.keys():
                self.loop_structure_instance[
                    self.analysis_framework.get_ast_ith_child_node(parent_node, 2)
                ] = self.analysis_framework.find_cfg_successors(
                        self.analysis_framework.get_ast_ith_child_node(parent_node, 1)
                )[1]
            elif parent_node[NODE_TYPE] == TYPE_WHILE:
                self.loop_structure_instance[node] = self.analysis_framework.find_cfg_successors(node)[1]
            elif node[NODE_TYPE] == TYPE_FOREACH:
                self.loop_structure_instance[node] = self.analysis_framework.find_cfg_successors(node)[1]
            if next_node[NODE_INDEX] < node[NODE_INDEX]:
                # This must be loop structure instance
                if next_node in self.loop_structure_instance.keys():
                    next_node = self.__switch(next_node)
                else:
                    print("Problem not solved")
                    # return False
            result.append(next_node)
        return result


class GlobalProgramDependencyGraphBackwardTraversal(BaseGraphTraversal):
    """The PDG Backward Traversal Interface with Interprocedural Analysis

    """

    def __init__(self, *args, **kwargs):
        """

        Parameters
        ----------
        args
        kwargs
        """
        super(GlobalProgramDependencyGraphBackwardTraversal, self).__init__(*args, **kwargs)
        self.func_depth = {}
        self.max_func_depth = kwargs.get('max_func_depth', 3)
        self.sanitizer_param_list = {"analysis_framework": self.analysis_framework}
        # here list some storage

    def traversal(self, node, *args, **kwargs):
        if node[NODE_FUNCID] not in self.func_depth:
            self.func_depth[node[NODE_FUNCID]] = 0
        if self.func_depth[node[NODE_FUNCID]] >= self.max_func_depth:
            return []
        # introprocedure pdg analysis
        result = []
        define_nodes = self.analysis_framework.find_pdg_def_nodes(node)
        for define_node in define_nodes:
            define_node['taint_var'] = self.analysis_framework.cache.pdg_cache_graph.edges[define_node[NODE_INDEX],node[NODE_INDEX]]['taint_var']
        result.extend(define_nodes)
        # interprocedural pdg analysis
        if node[NODE_TYPE] != TYPE_ASSIGN:
            return result
        call_nodes = self.analysis_framework.filter_ast_child_nodes(
                self.analysis_framework.get_ast_ith_child_node(node, 1),
                node_type_filter=[TYPE_CALL, TYPE_METHOD_CALL, TYPE_STATIC_CALL]
        )
        for call_node in call_nodes:
            callable_node = self.analysis_framework.find_cg_decl_nodes(call_node)
            if callable_node:
                callable_node = callable_node[0]
                # traverse from return .
                return_nodes = self.analysis_framework.ast_step.find_function_return_expr(callable_node)
                for return_node in return_nodes:
                    if return_node[NODE_FUNCID] not in self.func_depth:
                        self.func_depth[return_node[NODE_FUNCID]] = self.func_depth[node[NODE_FUNCID]] + 1
                    return_node['taint_var'] = ""
                result.extend(return_nodes)
        return result


class GlobalControlGraphForwardTraversal(ControlGraphForwardTraversal):
    """The CFG Forward Traversal Interface with Intraprocedural Analysis

    """

    def __init__(self, *args, **kwargs):
        """

        Parameters
        ----------
        args
        kwargs
        """
        super(ControlGraphForwardTraversal, self).__init__(*args, **kwargs)
        self.func_depth = {}
        self.max_func_depth = kwargs.get('max_func_depth', 3)
        self.loop_structure_instance = {}

    def traversal(self, node, *args, **kwargs):
        # cancel param
        if node[NODE_FUNCID] not in self.func_depth:
            self.func_depth[node[NODE_FUNCID]] = 0
        if self.func_depth[node[NODE_FUNCID]] >= self.max_func_depth:
            return []

        # local cfg
        result = []
        # We can cut the loop structure's return node.
        next_nodes = self.analysis_framework.find_cfg_successors(node)
        for next_node in next_nodes:
            parent_node = self.analysis_framework.get_ast_parent_node(node, ignore_error_flag=True)
            if parent_node is None: parent_node = {NODE_TYPE: TYPE_NULL}
            if parent_node[NODE_TYPE] == TYPE_FOR and \
                    self.analysis_framework.get_ast_ith_child_node(parent_node, 2) \
                    not in self.loop_structure_instance.keys():
                self.loop_structure_instance[
                    self.analysis_framework.get_ast_ith_child_node(parent_node, 2)
                ] = self.analysis_framework.find_cfg_successors(
                        self.analysis_framework.get_ast_ith_child_node(parent_node, 1)
                )[1]
            elif parent_node[NODE_TYPE] == TYPE_WHILE:
                self.loop_structure_instance[node] = self.analysis_framework.find_cfg_successors(node)[1]
            elif node[NODE_TYPE] == TYPE_FOREACH:
                self.loop_structure_instance[node] = self.analysis_framework.find_cfg_successors(node)[1]
            if next_node[NODE_INDEX] < node[NODE_INDEX]:
                # This must be loop structure instance
                if next_node in self.loop_structure_instance.keys():
                    next_node = self.__switch(next_node)
                else:
                    print("Problem not solved")
                    # return False
            result.append(next_node)
        # global cfg
        call_nodes = self.analysis_framework.filter_ast_child_nodes(node,
                                                                    node_type_filter=[TYPE_CALL, TYPE_METHOD_CALL,
                                                                                      TYPE_STATIC_CALL])
        for call_node in call_nodes:
            callable_node = self.analysis_framework.find_cg_decl_nodes(call_node)
            if callable_node:
                callable_node = callable_node[0]
                # traverse from return .
                first_elems = self.analysis_framework.ast_step.find_function_entrance_expr(callable_node)
                assert first_elems.__len__() == 1
                for first_elem in first_elems:
                    if first_elem[NODE_FUNCID] not in self.func_depth:
                        self.func_depth[first_elem[NODE_FUNCID]] = self.func_depth[node[NODE_FUNCID]] + 1
                result.extend(first_elems)
        return result
