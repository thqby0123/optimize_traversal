import queue
import threading
from queue import Queue
from pjscan.cache.cache_graph import *
from pjscan.analysis_framework import AnalysisFramework
import py2neo


class PrefetchThread(threading.Thread):
    '''

    Attributes
    ----------

    queue: queue.Queue
        the queue that the thread fetch the task from

    analysis_framework: pjscan.Analysis_Framework
        the connect to neo4j database and the framework of prefetch

    cache_graph : cache_graph.BasicCacheGraph
        use the cache pool to record the result of prefetch

    Method
    ------
    run()
        the prefetch thread fetch the node from the queue and do your prefetch

    stop()
        stop the thread
    '''

    def __init__(self, queue: Queue, cache_graph, connector_profile: py2neo.ServiceProfile):
        """Initial the prefetch thread

        Parameters
        ----------

        analysis_framework: pjscan.Analysis_Framework
            the connect to neo4j database and the framework of prefetch

        queue : queue.Queue
            queue to be queried

        cache_graph : BasicCacheGraph
            the cache to store prefetch result

        """
        super(PrefetchThread, self).__init__()
        self.analysis_framework = AnalysisFramework.from_dict({
                "NEO4J_HOST": connector_profile.host,
                "NEO4J_USERNAME": connector_profile.user,
                "NEO4J_PASSWORD": connector_profile.password,
                "NEO4J_PORT": connector_profile.port,
                "NEO4J_PROTOCOL": connector_profile.protocol,
                "NEO4J_DATABASE": "neo4j",
        }, cache_graph=cache_graph)
        self.queue = queue
        self.task_count = 0
        self.running = False

    def run(self):
        """Fetch a task from queue, and do the task by running do_task() method

        """
        self.running = True
        while self.running:
            task = self.queue.get()
            task.analysis_framework = self.analysis_framework
            b = task.do_task()
            if b:
                self.task_count += 1

    def stop(self):
        """Stop the thread.

        """
        self.running = False
