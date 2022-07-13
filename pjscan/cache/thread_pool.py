import py2neo
from .prefetch_thread import *
from .prefetch_task import AbstractPrefetchTask

class PrefetchPool(object):
    '''PrefetchPool is the manager of all the PrefetchThreads

    PrefetchPool will be created in traversal , with the input the cache_graph and thread_count

    Attributes
    ----------

    threads: List[PrefetchThread]
        the list that manage all prefetch thread.

    queue: queue.Queue
        the queue to be prefetched, in this queue there is many tasks to be done.

    cache_graph : cache_graph.BasicCacheGraph
        use the cache pool to record the result of prefetch

    Method
    ------
    start_all()
        start all the thread.

    stop_all()
        stop all the thread

    put_task(task)
        put the prefetch task to queue.
    '''

    @classmethod
    def from_analyzer(cls, analyzer, thread_count: int = 1):
        """A class method of thread_pool, use `pjscan.AnalysisFramework` and `thread_count`  as input

        Parameters
        ----------
        analyzer : pjscan.AnalysisFramework
            the current analyzer, note that prefetch thread pool will use the same cache space from analyzer and generate new connector from analyzer's connection profiles

        thread_count : int
            the thread count

        """
        return cls(cache_graph=analyzer.cache, connector_profile=analyzer.service_profile, thread_count=thread_count)

    def __init__(self, cache_graph, connector_profile: py2neo.ServiceProfile, thread_count: int = 1):
        """PrefetchPool is the manager of all the PrefetchThreads

        PrefetchPool will be created in traversal , with the input the cache_graph , connector_profile and thread_count

        Parameters
        ----------
        cache_graph : BasicCacheGraph
            the cache_graph ref

        thread_count : List[PrefetchThread]
            the list that manage all prefetch thread, the length of threads is thread_count

        queue : queue.Queue
            stores all the task to be done, all the thread fetch task from this queue and do them.


        """
        self.threads = []
        self.queue = Queue()
        self.cache_graph = cache_graph
        self.thread_count = thread_count
        for i in range(thread_count):
            prefetch_thread = PrefetchThread(queue=self.queue, cache_graph=self.cache_graph,
                                             connector_profile=connector_profile)
            prefetch_thread.daemon = True
            self.threads.append(prefetch_thread)
        self.start_all()
        self.task_count = 0

    def start_all(self):
        """Start all the threads

        """
        for i in self.threads:
            i.start()

    def stop_all(self):
        """Stop all the threads

        """
        for i in self.threads:
            i.stop()

    def put_task(self, task):
        """Put task in thread

        Parameters
        ----------
        task : the class extends to AbstractPrefetchTask
            put this task in queue

        """
        assert isinstance(task, AbstractPrefetchTask)
        self.queue.put(task)

    def calculate_count(self):
        for i in self.threads:
            self.task_count += i.task_count

    def get_count(self):
        self.calculate_count()
        return self.task_count