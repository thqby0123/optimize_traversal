import unittest, time
import json
import os.path
from pjscan.cache.thread_pool import *
from pjscan.analysis_framework import *
from SQLI.sqli_recorder import SQLIRecorder
from SQLI.customized_prefetch_task import PrePDGBackwardTask, RuntimePDGBackwardTask, FindCallDeclTask, FindASTRootTask
from pjscan.graph_traversal import GlobalProgramDependencyGraphBackwardTraversal


class ExtendedSQLInjectionTraversal_3Task(GlobalProgramDependencyGraphBackwardTraversal):
    def __init__(self, *args, **kwargs):
        prefetch_thread_count = kwargs.pop("prefetch_thread_count", 6)
        super(ExtendedSQLInjectionTraversal_3Task, self).__init__(*args, **kwargs)
        self.traversal_count = 0
        self.cache_hit = 0
        self.prefetch_hit = 0
        self.thread_pool = PrefetchPool.from_analyzer(self.analysis_framework, thread_count=prefetch_thread_count)
        self.cache_graph = self.analysis_framework.cache
        self.cache_graph.customize_storage['ast_root'] = {}
        self.cache_graph.customize_storage['call_return_source'] = {}
        self.origin, self.origin_id = self.find_origin()
        self.terminal, self.terminal_id = self.find_terminal()
        self.sanitizer = self.find_sanitizer()
        self.recorder: SQLIRecorder = SQLIRecorder(self.analysis_framework)

        self.get_call_return = lambda x: self.cache_graph.customize_storage['call_return'].get(x, None)
        self.set_call_return = lambda k, v: self.cache_graph.customize_storage['call_return'].__setitem__(k, v)

        self.thread_pool.put_task(PrePDGBackwardTask(
                cache_graph=self.analysis_framework.cache, input_node_list=self.origin_id,
        ))

    def find_terminal(self):
        if os.path.exists("_terminal.json"):
            terminal_node_id = json.load(open('_terminal.json', 'r'))
        else:
            user_input_nodes = []
            for user_input_code in {'_GET', '_POST'}:
                user_input_nodes.extend(
                        self.analysis_framework.basic_step.match(**{NODE_CODE: user_input_code, }).all())
            for target_node in user_input_nodes:
                self.thread_pool.put_task(FindASTRootTask(node=target_node, cache_graph=self.cache_graph))
            terminal_node = []
            for target_node in user_input_nodes:
                if self.cache_graph.customize_storage["ast_root"].get(target_node[NODE_INDEX], None) is not None:
                    node = self.cache_graph.customize_storage["ast_root"].get(target_node[NODE_INDEX], None)
                else:
                    self.traversal_count += 1
                    node = self.analysis_framework.get_ast_root_node(target_node)
                    self.cache_graph.customize_storage["ast_root"][target_node[NODE_INDEX]] = node
                if node is not None:
                    terminal_node.append(node)
            terminal_node_id = []
            for node in terminal_node:
                terminal_node_id.append(node[NODE_INDEX])
            json.dump(terminal_node_id, open('_terminal.json', 'w'))
        print(f"the number of terminal is:" + str(len(terminal_node_id)))
        self.thread_pool.queue.queue.clear()
        return [lambda x: x[NODE_INDEX] in terminal_node_id], terminal_node_id

    def find_sanitizer(self):
        target_nodes = []
        for sanitizer_function in {'mysql_real_escape_string', 'pg_escape_string', 'sqlite_escape_string'}:
            target_nodes.extend(
                    self.analysis_framework.neo4j_graph.nodes.match(**{NODE_CODE: sanitizer_function, }).all())
        result_node = []
        for target_node in target_nodes:
            self.traversal_count += 1
            node = self.analysis_framework.ast_step.get_root_node(target_node)
            if node is not None:
                result_node.append(node)
        sanitizer_nodes_id = []
        for sanitizer_node in result_node:
            sanitizer_nodes_id.append(sanitizer_node[NODE_INDEX])
        return [lambda x, **kwargs: x[NODE_INDEX] in sanitizer_nodes_id]

    def find_origin(self):
        if os.path.exists("_origin.json"):
            origin_node_id = json.load(open('_origin.json', 'r'))
            origin_node = list(map(lambda x: self.analysis_framework.get_node_itself(x), origin_node_id))
        else:
            origin_node = []
            origin_node_id = []
            for source in ['pwg_query']:
                target_nodes = self.analysis_framework.neo4j_graph.nodes.match(
                        **{NODE_CODE: source, }).all()
                for target_node in target_nodes:
                    self.thread_pool.put_task(FindASTRootTask(node=target_node, cache_graph=self.cache_graph))
                for target_node in target_nodes:
                    if self.cache_graph.customize_storage["ast_root"].get(target_node[NODE_INDEX], None) is not None:
                        node = self.cache_graph.customize_storage["ast_root"].get(target_node[NODE_INDEX], None)
                    else:
                        self.traversal_count += 1
                        node = self.analysis_framework.get_ast_root_node(target_node)
                        self.cache_graph.customize_storage["ast_root"][target_node[NODE_INDEX]] = node
                    if node is not None:
                        origin_node.append(node)
                        origin_node_id.append(node[NODE_INDEX])
            json.dump(origin_node_id, open('_origin.json', 'w'))
        print(f"the number of origin is:" + str(len(origin_node)))
        self.thread_pool.queue.queue.clear()
        return origin_node, origin_node_id

    def traversal(self, node, *args, **kwargs):
        if node[NODE_FUNCID] not in self.func_depth:
            self.func_depth[node[NODE_FUNCID]] = 0
        if self.func_depth[node[NODE_FUNCID]] >= self.max_func_depth:
            return []
        # introprocedure
        result = []
        define_nodes = self.analysis_framework.find_pdg_def_nodes(node)
        self.traversal_count += 1
        result.extend(define_nodes)
        # interprocedural pdg analysis
        if node[NODE_TYPE] != TYPE_ASSIGN:
            for res in result:
                self.thread_pool.put_task(
                        RuntimePDGBackwardTask(cache_graph=self.analysis_framework.cache, node=res,
                                               queue=self.thread_pool.queue)
                )
            return result
        self.traversal_count += 1
        if self.get_call_return(node) is None:
            # origin code
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
                    result.extend(return_nodes)
        else:
            self.cache_hit += 1
            # Here is a method to accelerate the speed of these code.
            for return_node in self.get_call_return(node):
                if return_node[NODE_FUNCID] not in self.func_depth:
                    self.func_depth[return_node[NODE_FUNCID]] = self.func_depth[node[NODE_FUNCID]] + 1
            result.extend(self.get_call_return(node))

        for res in result:
            self.thread_pool.put_task(FindCallDeclTask(cache_graph=self.analysis_framework.cache, node=res))
            self.thread_pool.put_task(RuntimePDGBackwardTask(cache_graph=self.analysis_framework.cache, node=res,
                                                             queue=self.thread_pool.queue))
        return result
