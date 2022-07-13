import py2neo

from pjscan import *
from queue import Queue
from pjscan.const import *

#返回是否有include出现
def find_IG_fileno(node,analysis_framework:AnalysisFramework):
    file_node = analysis_framework.neo4j_graph.nodes.match(**{NODE_INDEX:node[NODE_FILEID]}).all()[0]
    include_files = analysis_framework.fig_step.find_include_dst(file_node)
    result = []
    for include_file in include_files:
        result.append(include_file[NODE_INDEX])
    return result

#同名变量匹配
def find_ast_code_node_by_name(name:str, file_nos:list,analysis_framework:AnalysisFramework):
    result = []
    for file_no in file_nos:
        nodes = list(analysis_framework.neo4j_graph.nodes.match(**{NODE_CODE:name,NODE_FILEID:file_no}).all())
        result.extend(nodes)
    return result

def find_all_ast_root(nodes,analysis_framework:AnalysisFramework):
    result = []
    for node in nodes:
        ast_root = analysis_framework.get_ast_root_node(node)
        result.append(ast_root)
    return result


#找到所有CFG后继
def find_all_predecessors(node:py2neo.Node, analysis_framework:AnalysisFramework):
    queue = Queue()
    queue.put(node)
    result = []
    while not queue.empty():
        n = queue.get()
        predecessors = analysis_framework.cfg_step.find_predecessors(n)
        result.extend(predecessors)
        for predecessor in predecessors:
            queue.put(predecessor)
    return result

#在list中找到处于CFG最后的节点
def compare_latest(nodes, all_predecessors):
    candidate = list(nodes)
    for i in candidate:
        if i[NODE_INDEX] in all_predecessors:
            candidate.remove(i)
    return candidate


def find_latest_cfg_node(nodes:list, analysis_framework:AnalysisFramework):
    all_predecessors = []
    for node in nodes:
        predecessors = find_all_predecessors(node, analysis_framework)
        all_predecessors.extend(predecessors)
    all_predecessors = list(set(all_predecessors))
    result = compare_latest(nodes,all_predecessors)
    return result

def get_left_var_in_assign(node,analysis_framework:AnalysisFramework):
    return analysis_framework.ast_step.get_ith_child_node(analysis_framework.ast_step.get_ith_child_node(node,0),0)[NODE_CODE]

def get_assign_ensure(nodes:list,analysis_framework:AnalysisFramework,var):
    result = nodes
    for node in nodes:
        if node[NODE_TYPE]!=TYPE_ASSIGN:
            result.remove(node)
        elif get_left_var_in_assign(node,analysis_framework) != var:
            result.remove(node)
    return result

def IG_step(node,analysis_framework:AnalysisFramework,unreason_var):
    file_nos = find_IG_fileno(node=node,analysis_framework=analysis_framework)
    result = []
    if file_nos == []:
        return []
    for var_ in unreason_var:
        var = var_[1:]
        ast_code_nodes = find_ast_code_node_by_name(name=var,analysis_framework=analysis_framework,file_nos=file_nos)
        ast_root_nodes = find_all_ast_root(nodes=ast_code_nodes,analysis_framework=analysis_framework)
        assign_nodes = get_assign_ensure(nodes = ast_root_nodes,analysis_framework=analysis_framework,var=var)
        latest_cfg = find_latest_cfg_node(nodes = assign_nodes,analysis_framework=analysis_framework)
        for i in latest_cfg:
            i['taint_var'] = var
        result.extend(latest_cfg)
    return result