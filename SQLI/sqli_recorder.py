from pjscan.graph_traversal_recorder import BaseRecorder
from pjscan.const import *
from typing import List
import py2neo
import networkx as nx
from pjscan import AnalysisFramework


class SQLIRecorder(BaseRecorder):
    def __init__(self, *args, **kwargs):
        super(SQLIRecorder, self).__init__(*args, **kwargs)
        self.storage_graph = nx.DiGraph()

    def record(self, node: py2neo.Node, next_node: py2neo.Node,taint_var:str = "ho") -> bool:
        self.storage_graph.add_node(next_node[NODE_INDEX],
                                    **{NODE_LINENO: next_node[NODE_LINENO], NODE_TYPE: next_node[NODE_TYPE]})
        self.storage_graph.add_edge(node[NODE_INDEX], next_node[NODE_INDEX],taint_var = taint_var)
        return True

    def record_origin(self, o: py2neo.Node) -> bool:
        self.storage_graph.add_node(o[NODE_INDEX], **{NODE_LINENO: o[NODE_LINENO], NODE_TYPE: o[NODE_TYPE]})
        return True


    def get_all_path(self, origins: List, terminals: List):
        paths = []
        for origin in origins:
            for terminal in terminals:
                if self.storage_graph.has_node(origin[NODE_INDEX]) and self.storage_graph.has_node(terminal[NODE_INDEX]):
                    #  print(str(origin[NODE_INDEX])+" "+str(terminal))
                    path = nx.all_simple_paths(self.storage_graph, origin[NODE_INDEX], terminal[NODE_INDEX])
                    for path_ in map(nx.utils.pairwise, path):
                        list__ = []
                        for relation in path_:
                            taint = self.storage_graph.edges[relation[0],relation[1]]['taint_var']
                            #taint = "$" + taint
                            list__.append([relation[0],taint])
                        print(list__)
                        list__.append([terminal[NODE_INDEX],terminal['source_var']])
                        paths.append(list__)
        return paths

    def get_report(self, origin_ids, terminal_ids, analysis_framework: AnalysisFramework):
        paths = self.get_all_path(origin_ids, terminal_ids)
        file_storage = {}
        report_list = []
        for path in paths:
            path_list = []
            #print(path)
            for point in path:
                node = analysis_framework.basic_step.get_node_itself(point[0])
                taint = point[1]
                if file_storage.__contains__(node[NODE_FILEID]):
                    file_name = file_storage.get(node[NODE_FILEID])
                else:
                    file_node = analysis_framework.neo4j_graph.nodes.match(**{NODE_INDEX: node[NODE_FILEID]}).all()[0]
                    file_name = \
                        analysis_framework.neo4j_graph.relationships.match(nodes=[file_node, None],
                                                                           r_type=FILE_EDGE).all()[
                            0].end_node[NODE_NAME]
                    file_storage[node[NODE_FILEID]] = file_name
                position = {'file_name': file_name, 'lineno': node[NODE_LINENO] , 'taint_variable':taint}
                path_list.append(position)
            report_list.append(path_list)
        return report_list
