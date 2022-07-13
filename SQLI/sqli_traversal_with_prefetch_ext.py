import unittest, time

from pjscan.cache.thread_pool import *
from pjscan.analysis_framework import *
from SQLI.sqli_recorder import SQLIRecorder
from SQLI.customized_prefetch_task import PrePDGBackwardTask, RuntimePDGBackwardTask, FindCallDeclTask, \
    FunctionModelTask
from SQLI.sqli_traversal import BaseSQLInjectionTraversal


class ExtendedSQLInjectionTraversalExt(BaseSQLInjectionTraversal):
    def __init__(self, *args, **kwargs):
        """
        traversal count:7249  , cache_hit:6901  ,prefetch_hit:6864  ,task_count:3646
        time for SQL Injection with 24 prefetch threads(3 task): 206.50474667549133

        :param args:
        :param kwargs:
        """
        prefetch_thread_count = kwargs.pop("prefetch_thread_count", 4)
        super(ExtendedSQLInjectionTraversalExt, self).__init__(*args, **kwargs)
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

        for file_name in {'/home/lth/PHPJoyMaster/source_code/Piwigo-2.9.0/admin/include/functions.php': 39,
                          '/home/lth/PHPJoyMaster/source_code/Piwigo-2.9.0/include/functions_user.inc.php': 35,
                          '/home/lth/PHPJoyMaster/source_code/Piwigo-2.9.0/include/dblayer/functions_mysqli.inc.php': 34,
                          '/home/lth/PHPJoyMaster/source_code/Piwigo-2.9.0/include/dblayer/functions_mysql.inc.php': 32,
                          '/home/lth/PHPJoyMaster/source_code/Piwigo-2.9.0/include/ws_functions/pwg.images.php': 32,
                          '/home/lth/PHPJoyMaster/source_code/Piwigo-2.9.0/include/ws_functions/pwg.categories.php': 1}.keys():
            for func_decl_node in self.analysis_framework.basic_step.match(
                    LABEL_AST, **{
                            NODE_TYPE: TYPE_FUNC_DECL,
                            NODE_FILEID: self.analysis_framework.fig_step.get_file_name_node(file_name)[NODE_FILEID]
                    }
            ):
                self.thread_pool.put_task(FunctionModelTask(
                        cache_graph=self.analysis_framework.cache, func_id=func_decl_node[NODE_INDEX],
                        prefetch_queue=self.thread_pool.queue
                ))

    def traversal(self, node, *args, **kwargs):
        if node[NODE_FUNCID] not in self.func_depth:
            self.func_depth[node[NODE_FUNCID]] = 0
        if self.func_depth[node[NODE_FUNCID]] >= self.max_func_depth:
            return []
        # introprocedure
        result = []
        self.traversal_count += 1
        define_nodes = self.analysis_framework.find_pdg_def_nodes(node)
        result.extend(define_nodes)
        self.thread_pool.put_task(FindCallDeclTask(cache_graph=self.analysis_framework.cache, node=node))

        for res in result:
            self.thread_pool.put_task(
                    RuntimePDGBackwardTask(cache_graph=self.analysis_framework.cache, node=res,
                                           queue=self.thread_pool.queue)
            )
            self.thread_pool.put_task(FindCallDeclTask(cache_graph=self.analysis_framework.cache, node=res))

        # interprocedural pdg analysis
        if node[NODE_TYPE] not in {TYPE_ASSIGN, TYPE_ASSIGN_OP, TYPE_ASSIGN_REF}:
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
