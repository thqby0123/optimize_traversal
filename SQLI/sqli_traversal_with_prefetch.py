import sys
import unittest, time

from pjscan.cache.thread_pool import *
from pjscan.analysis_framework import *
from SQLI.sqli_recorder import SQLIRecorder
from SQLI.customized_prefetch_task import PrePDGBackwardTask, RuntimePDGBackwardTask, FindCallDeclTask
from SQLI.sqli_traversal import BaseSQLInjectionTraversal


class ExtendedSQLInjectionTraversal(BaseSQLInjectionTraversal):
    def __init__(self, *args, **kwargs):
        prefetch_thread_count = kwargs.pop("prefetch_thread_count", 6)
        super(ExtendedSQLInjectionTraversal, self).__init__(*args, **kwargs)
        self.traversal_count = 0
        self.cache_graph.customize_storage['call_return_source'] = {}
        self.cache_hit = 0
        self.prefetch_hit = 0
        self.thread_pool = PrefetchPool.from_analyzer(self.analysis_framework, thread_count=prefetch_thread_count)

        self.get_call_return = lambda x: self.cache_graph.customize_storage['call_return'].get(x, None)
        self.set_call_return = lambda k, v: self.cache_graph.customize_storage['call_return'].__setitem__(k, v)
        self.node_without_cache_hit = []
        for node_id in self.origin_id:
            self.thread_pool.put_task(RuntimePDGBackwardTask(
                    cache_graph=self.analysis_framework.cache,
                    node=self.analysis_framework.get_node_itself(node_id),
            ))

    def traversal(self, node, *args, **kwargs):
     #   print(node)

        if node[NODE_FUNCID] not in self.func_depth:
            self.func_depth[node[NODE_FUNCID]] = 0
        if self.func_depth[node[NODE_FUNCID]] >= self.max_func_depth:
            return []
        # introprocedure
        result = []
        self.traversal_count += 1
        define_nodes = self.analysis_framework.find_pdg_def_nodes(node)
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
        if self.get_call_return(node[NODE_INDEX]) is None:
            self.node_without_cache_hit.append(node)

            # origin code
            call_nodes = self.analysis_framework.filter_ast_child_nodes(
                    self.analysis_framework.get_ast_ith_child_node(node, 1),
                    node_type_filter=[TYPE_CALL, TYPE_METHOD_CALL, TYPE_STATIC_CALL]
            )
            results = []
            for call_node in call_nodes:
                callable_node = self.analysis_framework.find_cg_decl_nodes(call_node)
                if callable_node:
                    callable_node = callable_node[0]
                    # traverse from return .
                    return_nodes = self.analysis_framework.ast_step.find_function_return_expr(callable_node)
                    for return_node in return_nodes:
                        if return_node[NODE_FUNCID] not in self.func_depth:
                            self.func_depth[return_node[NODE_FUNCID]] = self.func_depth[node[NODE_FUNCID]] + 1
                    results.extend(return_nodes)
                    result.extend(return_nodes)
            self.set_call_return(node[NODE_INDEX], results)
            self.cache_graph.customize_storage['call_return_source'][node[NODE_INDEX]] = 'traversal'
        else:
            self.cache_hit += 1
            # Here is a method to accelerate the speed of these code.
            for return_node in self.get_call_return(node[NODE_INDEX]):
                if return_node[NODE_FUNCID] not in self.func_depth:
                    self.func_depth[return_node[NODE_FUNCID]] = self.func_depth[node[NODE_FUNCID]] + 1
            if self.cache_graph.customize_storage['call_return_source'][node[NODE_INDEX]] == 'prefetch':
                self.prefetch_hit += 1
            result.extend(self.get_call_return(node[NODE_INDEX]))

        for res in result:
            self.thread_pool.put_task(FindCallDeclTask(cache_graph=self.analysis_framework.cache, node=res))
            self.thread_pool.put_task(RuntimePDGBackwardTask(cache_graph=self.analysis_framework.cache, node=res,
                                                             queue=self.thread_pool.queue))
  #      print(id(self.cache_graph), self.cache_graph.pdg_cache_graph.nodes.keys().__len__(), "traverse")
        return result

    def get_hit(self):
        self.cache_hit += self.analysis_framework.cache_hit
        self.prefetch_hit += self.analysis_framework.prefetch_hit
        self.node_without_cache_hit.extend(self.analysis_framework.node_without_cache_hit)
        return self.traversal_count, self.cache_hit, self.prefetch_hit, self.thread_pool.get_count()

    def write_no_cache_list(self):
        file_name_hash = {}
        result_set = set()
        for i in self.node_without_cache_hit:
            if i[NODE_FILEID] not in file_name_hash:
                file_name_hash[i[NODE_FILEID]] = self.analysis_framework.fig_step.get_belong_file(i)
            file_name = file_name_hash.get(i[NODE_FILEID])
            result_set.add((file_name, i[NODE_LINENO]))
        with open("not_hit_list.csv", "w") as f:
            for line in sorted(result_set):
                f.write(f"{line[0]},{line[1]}\n")

    def get_size_of_cache(self):
        prefetch_size = 0
        cache_size = 0
        for edge in self.cache_graph.pdg_cache_graph.edges():
            if self.cache_graph.pdg_cache_graph.edges[edge[0], edge[1]]['source'] == 'prefetch':
                prefetch_size += sys.getsizeof(edge)
            cache_size += sys.getsizeof(edge)
        print(f"cache size of pdg {cache_size}")
        print(f"prefetch size of pdg {prefetch_size}")
        for edge in self.cache_graph.ast_cache_graph.edges():
            cache_size += sys.getsizeof(edge)
        print(f"cache size of ast {cache_size}")
        for node in list(self.cache_graph.node_cache_pool.keys()):
            if self.cache_graph.node_source[node] == 'prefetch':
                prefetch_size += sys.getsizeof(node)
                prefetch_size += sys.getsizeof(self.cache_graph.node_cache_pool[node])
            cache_size += sys.getsizeof(node)
            cache_size += sys.getsizeof(self.cache_graph.node_cache_pool[node])
        print(f"cache size of node pool {cache_size}")
        print(f"prefetch size of node pool {prefetch_size}")
        for call_return in list(self.cache_graph.customize_storage['call_return'].keys()):
            if self.cache_graph.customize_storage['call_return_source'][call_return] == 'prefetch':
                prefetch_size += sys.getsizeof(call_return)
                prefetch_size += sys.getsizeof(self.cache_graph.customize_storage['call_return'][call_return])
            cache_size += sys.getsizeof(call_return)
            cache_size += sys.getsizeof(self.cache_graph.customize_storage['call_return'][call_return])
        print(f"cache size of call_return {cache_size}")
        print(f"prefetch size of call_return {prefetch_size}")
        return cache_size, prefetch_size