from pjscan.cache.cache_graph import BasicCacheGraph
from pjscan.cache.prefetch_task import *


class FunctionModelTask(AbstractPrefetchTask):
    def __init__(self, func_id, prefetch_queue=None, **kwargs):
        super(FunctionModelTask, self).__init__(**kwargs)
        self.func_id = func_id

    def _get_result(self, _node):
        if self.cache_graph.get_pdg_inflow(_node) is None:
            rels = self.analysis_framework.neo4j_graph.relationships.match(nodes=[None, _node],
                                                                           r_type=DATA_FLOW_EDGE, ).all()
            self.cache_graph.add_pdg_inflow(_node, rels, source="prefetch")
        else:
            rels, flag = self.cache_graph.get_pdg_inflow(_node)
        res = [i.start_node for i in rels]
        return res

    def _sub_traversal(self, _node):
        for predecessor in self._get_result(_node):
            if predecessor[NODE_INDEX] < _node[NODE_INDEX]:
                self._sub_traversal(predecessor)

    def do_task(self):
        return_nodes = self.analysis_framework.ast_step.find_function_return_expr(
                self.analysis_framework.basic_step.get_node_itself(self.func_id))
        for return_node in return_nodes:
            self._sub_traversal(return_node)
        print(id(self.cache_graph), self.cache_graph.pdg_cache_graph.nodes.keys().__len__(), "FunctionModelTask")


class PrePDGBackwardTask(AbstractPrefetchTask):
    def __init__(self, input_node_list, **kwargs):
        self.node = None
        self.input_node_list = input_node_list
        super(PrePDGBackwardTask, self).__init__(**kwargs)

    def do_task(self):
        for node_id in self.input_node_list:
            node = self.analysis_framework.get_node_itself(node_id)
            if self.cache_graph.get_pdg_inflow(node) is None:
                rels = self.analysis_framework.neo4j_graph.relationships.match(nodes=[None, node],
                                                                               r_type=DATA_FLOW_EDGE, ).all()
                self.cache_graph.add_pdg_inflow(node, rels, source="prefetch")
        return True


class RuntimePDGBackwardTask(AbstractPrefetchTask):
    def __init__(self, node=None, queue=None, **kwargs):
        self.node = node
        super(RuntimePDGBackwardTask, self).__init__(**kwargs)

    def _get_result(self, _node):
        if self.cache_graph.get_pdg_inflow(_node) is None:
            rels = self.analysis_framework.neo4j_graph.relationships.match(nodes=[None, _node],
                                                                           r_type=DATA_FLOW_EDGE, ).all()
            self.cache_graph.add_pdg_inflow(_node, rels, source="prefetch")
            res = [i.start_node for i in rels]
            return res
        else:
            return []

    def _sub_traversal(self, _node):
        # print("RuntimePDGBackwardTask", _node)
        for predecessor in self._get_result(_node):
            if predecessor[NODE_INDEX] < _node[NODE_INDEX]:
                self._sub_traversal(predecessor)

    def do_task(self):
        self._sub_traversal(self.node)
        # print(id(self.cache_graph), self.cache_graph.pdg_cache_graph.nodes.keys().__len__(), "RuntimePDGBackwardTask")


class FindCallDeclTask(AbstractPrefetchTask):
    def __init__(self, node=None, **kwargs):
        self.node = node
        self.get_call_return = lambda x: self.cache_graph.customize_storage['call_return'].get(x, None)
        self.get_call_return_source = lambda x: self.cache_graph.customize_storage['call_return_source'].get(
                self.node[NODE_INDEX], None)
        self.set_call_return = lambda k, v: self.cache_graph.customize_storage['call_return'].__setitem__(k, v)
        self.set_call_return_source = lambda k, v: self.cache_graph.customize_storage['call_return_source'].__setitem__(
                k, v)
        super(FindCallDeclTask, self).__init__(**kwargs)

    def do_task(self):
        if self.node[NODE_TYPE] not in {TYPE_ASSIGN, TYPE_ASSIGN_OP, TYPE_ASSIGN_REF}:
            return False
        if self.get_call_return(self.node[NODE_INDEX]) is not None:
            return False
        self.cache_graph.add_node(self.node,source='prefetch')

        call_nodes = self.analysis_framework.filter_ast_child_nodes(
                self.analysis_framework.get_ast_ith_child_node(self.node, 1),
                node_type_filter=[TYPE_CALL, TYPE_METHOD_CALL, TYPE_STATIC_CALL]
        )
        result = []
        return_nodes = []
        for call_node in call_nodes:
            callable_node = self.analysis_framework.find_cg_decl_nodes(call_node)
            if callable_node:
                callable_node = callable_node[0]
                # traverse from return .
                return_nodes = self.analysis_framework.ast_step.find_function_return_expr(callable_node)
            result.extend(return_nodes)
        self.set_call_return(self.node[NODE_INDEX], result)
        self.set_call_return_source(self.node[NODE_INDEX], 'prefetch')
        # print(id(self.cache_graph), self.cache_graph.customize_storage['call_return_source'].keys().__len__(),
        #       "FindCallDeclTask")
        return True


class FindASTRootTask(AbstractPrefetchTask):
    def __init__(self, **kwargs):
        self.node = kwargs.pop('node', None)
        self.get_ast_root = lambda x: self.cache_graph.customize_storage['ast_root'].get(x, None)
        self.set_ast_root = lambda k, v: self.cache_graph.customize_storage['ast_root'].__setitem__(k, v)
        super(FindASTRootTask, self).__init__(**kwargs)

    def do_task(self):
        if self.get_ast_root(self.node[NODE_INDEX]) is not None:
            return False
        self.cache_graph.add_node(self.node)
        ast_root = self.analysis_framework.get_ast_root_node(self.node)
        self.set_ast_root(self.node[NODE_INDEX], ast_root)
        return True
