import networkx as nx
import py2neo
from typing import List
from abc import ABC, abstractmethod
from pjscan.const import *
from pjscan.analysis_framework import AnalysisFramework


class AbstractPrefetchTask(ABC):
    '''

        Attributes
        ----------

        cache_graph : cache_graph.BasicCacheGraph
            use the cache pool to record the result of prefetch

        Method
        ------
        do_task()

            In this method, you should finish your own prefetch stratege, including prefetch condition(in which condition you will do prefetch),
            prefetch operation and store it in cache_graph. Especially, if the parameter your prefetch is costomizedm, please use contomimzed_storage to store it.


        Examples
        --------

        This is an example of how to override the do_task() method.
        You want to prefetch about the PDG relationship,
        and you use the drop out strategy to judge whether the thread should prefetch,
        then difinite the query of database

        >>> def do_task(self):
        ...     if random.randint(0, 100) * 0.01 >= self.drop_out:
        ...         return
        ...     if self.node[NODE_TYPE] not in AST_ROOT:
        ...         return
        ...     if self.cache_graph.get_pdg_inflow(self.node) is None:
        ...         rels = self.analysis_framework.neo4j_graph.relationships.match(nodes=[None, self.node], r_type=DATA_FLOW_EDGE, ).all()
        ...         self.cache_graph.add_pdg_inflow(self.node, rels)
        ...     if self.cache_graph.get_pdg_outflow(self.node) is None:
        ...         rels = self.analysis_framework.neo4j_graph.relationships.match(nodes=[self.node, None], r_type=DATA_FLOW_EDGE, ).all()
        ...         self.cache_graph.add_pdg_outflow(self.node, rels)

        Notes
        -----
        You can extend this method your self.

        Otherwise, we provide 4 class which extends it , which used for prefetch different relationships

        You can use it as
            AstPrefetchTask

            CfgPrefetchTask

            PdgPrefetchTask

            CgPrefetchTask

        Besides, the attributes 'analysis_framework' is pjscan.AnalysisFramework, it will initialize in prefetch thread
        to make a new connection with database.
        '''

    def __init__(self, cache_graph, analysis_framework: AnalysisFramework = None):
        """Initial the prefetch task

            Parameters
            ----------
            cache_graph : cache_graph.BasicCacheGraph
                use the cache pool to record the result of prefetch

            """
        if cache_graph is None:
            raise "Task Wrong!Graph is not definited!!"
        self.cache_graph = cache_graph
        self.analysis_framework = analysis_framework  # type:AnalysisFramework

    @abstractmethod
    def do_task(self):
        """do your own task.

        """
        return None
