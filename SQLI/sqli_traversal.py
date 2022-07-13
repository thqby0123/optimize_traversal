import json
import os.path
from IG_traversal import *
from pjscan.graph_traversal import GlobalProgramDependencyGraphBackwardTraversal
from pjscan.cache.thread_pool import *
from typing import Set, List, Dict, Union, Callable

from .sqli_recorder import SQLIRecorder
from IG_tainted_variable import *

class BaseSQLInjectionTraversal(GlobalProgramDependencyGraphBackwardTraversal):
    def __init__(self, *args, **kwargs):
        super(BaseSQLInjectionTraversal, self).__init__(*args, **kwargs)
        self.cache_graph = self.analysis_framework.cache
        self.origin, self.origin_id = self.find_origin()
        self.terminal, self.terminal_id,self.terminal_node = self.find_terminal()
        self.sanitizer = self.find_sanitizer()
        self.recorder: SQLIRecorder = SQLIRecorder(self.analysis_framework)
        self.ig_traversal = IG_PDG_forward(self.sanitizer,self.analysis_framework)
    def find_terminal(self):
        user_input_nodes = []
        for user_input_code in {'_GET', '_POST', '_COOKIE','_REQUEST','_SESSION'}:
            user_input_nodes.extend(
                    self.analysis_framework.basic_step.match(**{NODE_CODE: user_input_code, }).all())
        terminal_node = []
        for target_node in user_input_nodes:
            node = self.analysis_framework.get_ast_root_node(target_node)
            if node is not None:
                taint = self.analysis_framework.ast_step.get_ith_child_node(self.analysis_framework.ast_step.get_parent_node(self.analysis_framework.ast_step.get_parent_node(target_node)),1)['code']
                s = "$"+target_node['code']+"['"+taint+"']"
                node['source_var'] = s
                terminal_node.append(node)
        terminal_node_id = []
        for node in terminal_node:
            terminal_node_id.append(node[NODE_INDEX])
        print(f"the number of terminal is:" + str(len(terminal_node_id)))
        return [lambda x: x[NODE_INDEX] in terminal_node_id], terminal_node_id,terminal_node
        # return [],[]

    def find_sanitizer(self):
        return [lambda x,**kwargs:False]
        target_nodes = []
        for sanitizer_function in {'mysql_real_escape_string', 'pg_escape_string', 'sqlite_escape_string'}:
            target_nodes.extend(
                    self.analysis_framework.neo4j_graph.nodes.match(**{NODE_CODE: sanitizer_function, }).all())
        result_node = []
        for target_node in target_nodes:
            node = self.analysis_framework.ast_step.get_root_node(target_node)
            if node is not None:
                result_node.append(node)
        sanitizer_nodes_id = []
        for sanitizer_node in result_node:
            sanitizer_nodes_id.append(sanitizer_node[NODE_INDEX])
        return [lambda x, **kwargs: x[NODE_INDEX] in sanitizer_nodes_id]

    def find_origin(self):
        origin_node = []
        origin_node_id = []
     #   for source in ['Execute','ExecuteNoLog','GenID','sqlStatement','sqlStatementNoLog','sqlStatementCdrEngine','sqlFetchArray','sqlGetAssoc','sqlInsert','sqlQuery','sqlQueryNoLog','sqlQueryNoLogIgnoreError','sqlQueryCdrEngine','sqlInsertClean_audit','sqlListFields','sqlNumRows','sqlQ','idSqlStatement','sqlInsertClean']:
     #   for source in ['db_query','db_query_bound','db_num_rows']:
     #   for source in ['pwg_query']:
        for source in ["pg_query", "pg_send_query", "pg_prepare", "mysql_query", "mysqli_prepare", "mysqli_query","mysqli_real_query","query", "mysqli_prepare","mysqli_multi_query"]:
            target_nodes = self.analysis_framework.neo4j_graph.nodes.match(
                    **{NODE_CODE: source, }).all()
            #print(len(target_nodes))

            for target_node in target_nodes:
            #    print(target_node)
                type = self.analysis_framework.ast_step.get_parent_node(target_node)['type']
                if type == TYPE_VAR:
                    continue
                node = self.analysis_framework.ast_step.get_root_node(target_node)
                if node is not None and self.analysis_framework.ast_step.filter_child_nodes(_node=node,
                                                                   node_type_filter=VAR_TYPES_EXCLUDE_CONST_VAR).__len__() >= 1:
                    origin_node.append(node)
                    origin_node_id.append(node[NODE_INDEX])
        print(f"the number of origin is:" + str(len(origin_node)))
        return origin_node, origin_node_id

    def traversal(self, node, *args, **kwargs):
        if node[NODE_FUNCID] not in self.func_depth:
            self.func_depth[node[NODE_FUNCID]] = 0
        if self.func_depth[node[NODE_FUNCID]] >= self.max_func_depth:
            return []
            # introprocedure pdg analysis
        result = []
        all_vars = self.analysis_framework.find_variables(node)
        if node not in self.origin:
            all_vars.remove(node['taint_var'])
        define_nodes = self.analysis_framework.find_pdg_def_nodes(node)
        for define_node in define_nodes:
            define_node['taint_var'] = "$"+\
            self.analysis_framework.cache.pdg_cache_graph.edges[define_node[NODE_INDEX], node[NODE_INDEX]]['taint_var']
            all_vars.remove(define_node['taint_var'])
        l = self.ig_traversal.get_sample(node)
        for each in l:
            for var in all_vars:
                if each.__contains__(var[1:]):
                    node__ = each[var[1:]]
                    node__['taint_var'] = var
                    result.append(node__)

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

  #      result.extend(IG_step(node=node,analysis_framework=self.analysis_framework,unreason_var=all_vars))

        return result