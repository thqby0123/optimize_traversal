from collections import deque

import py2neo

from pjscan import *
from pjscan.const import *
#返回是否有include出现


class IG_PDG_forward(object):
    def __init__(self,sanitizer,analysis_framework:AnalysisFramework):
        self.IG_cache = {}
        self.IG_source = {}
        self.analysis_framework = analysis_framework
        self.sanitizer = sanitizer
        self.sanitizer_param_list = {}
    def find_IG_fileno(self, node):
        file_node = self.analysis_framework.neo4j_graph.nodes.match(**{NODE_INDEX: node[NODE_FILEID]}).all()[0]
        include_files = self.analysis_framework.fig_step.find_include_dst(file_node)
        result = []
        for include_file in include_files:
            result.append(include_file[NODE_INDEX])
        return result


    def find_origin(self, file_id):
        user_input_nodes = []
        for user_input_code in {'_GET', '_POST', '_COOKIE', '_REQUEST', '_SESSION'}:
            user_input_nodes.extend(
                self.analysis_framework.basic_step.match(**{NODE_CODE: user_input_code, NODE_FILEID:file_id}).all())
        origin_node = []
        for target_node in user_input_nodes:
            node = self.analysis_framework.get_ast_root_node(target_node)
            if node is not None:
                # taint = self.analysis_framework.ast_step.get_ith_child_node(
                #     self.analysis_framework.ast_step.get_parent_node(
                #         self.analysis_framework.ast_step.get_parent_node(target_node)), 1)['code']
                # s = "$" + target_node['code'] + "['" + taint + "']"
                # node['taint_var'] = s
                origin_node.append(node)
        return  origin_node

    def traversal(self,node):
        return self.analysis_framework.pdg_step.find_use_nodes(node)

    def get_sample(self,node):
        l = []
        if self.IG_cache.get(node[NODE_FILEID],None) != None:
            ig_dst = self.IG_cache[node[NODE_FILEID]]
            for ig_dst_ in ig_dst:
                l.append(self.IG_source[ig_dst_])

        else:
            ig_dst = self.find_IG_fileno(node)
            self.IG_cache[node[NODE_FILEID]] = ig_dst
            for ig_dst_ in ig_dst:
                if self.IG_source.get(ig_dst_,None) == None:
                    origin = self.find_origin(ig_dst_)
                    d = self.run(origin)
                    self.IG_source[ig_dst_] = d
                    l.append(d)
                else:
                    l.append(self.IG_source[ig_dst_])
        return l
    def run(self,origin):
        d = {}
        self.__visit_node_pool = {}
        query: deque[py2neo.Node] = deque()
        for o in origin:  # may be run should only serve the first elem
            query.append(o)
            self.__visit_node_pool[o[NODE_INDEX]] = {}
            o['origin'] = o[NODE_INDEX]
        #    self.recorder.record_origin(o)
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
            if current_node[NODE_TYPE] == TYPE_ASSIGN:
                taint_var = self.get_left_var_in_assign(current_node)
            d[taint_var] = current_node
            node__ = self.traversal(current_node)
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
                    next_nodes.append(candidate_node)

            for next_node in next_nodes:
                # Add data to digraph

                query.append(next_node)
        return d
    def get_left_var_in_assign(self,node):
        return \
        self.analysis_framework.ast_step.get_ith_child_node(self.analysis_framework.ast_step.get_ith_child_node(node, 0), 0)[
            NODE_CODE]