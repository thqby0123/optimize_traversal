import os
import sys
import unittest, time
from pjscan.graph_traversal import BaseGraphTraversal
import json
from pjscan.cache.thread_pool import *
from pjscan.analysis_framework import *
from SQLI.sqli_recorder import SQLIRecorder
from SQLI.sqli_traversal import BaseSQLInjectionTraversal as SQLInjectionTraversal
from SQLI.sqli_traversal_with_prefetch_3task import ExtendedSQLInjectionTraversal_3Task
from SQLI.sqli_traversal_with_prefetch import ExtendedSQLInjectionTraversal
from SQLI.sqli_traversal_with_prefetch_ext import ExtendedSQLInjectionTraversalExt


def sample_result(result):
    print(f"The number of paths is " + str(len(result)))
    d = {}
    d['isSQL'] = True
    traces = []
    for path_list in result:
        trace = []
        for entry in path_list[:-1]:
            dt = {}
            dt['file'] = entry['file_name']
            dt['line'] = entry['lineno']
            dt['taint_variable'] = entry['taint_variable']
            trace.append(dt)
        dt = {}
        dt['file'] = path_list[-1]['file_name']
        dt['line'] =  path_list[-1]['lineno']
        dt['taint_variable'] =  path_list[-1]['taint_variable']
        trace.append(dt)
        traces.append(trace)
    d['traces'] = traces
    return d


def test_without_cache():
    start_time = time.time()
    if os.path.exists("_origin.json"):
        os.remove("_origin.json")
    if os.path.exists("_terminal.json"):
        os.remove("_terminal.json")
    with open("neo4j_default_config.yaml", 'w') as f:
        f.write("""NEO4J_HOST: 10.176.36.21
NEO4J_USERNAME: neo4j
NEO4J_PASSWORD: 123
NEO4J_PORT: 17484
NEO4J_PROTOCOL: bolt
NEO4J_DATABASE: neo4j""")
    analysis_framework = AnalysisFramework.from_yaml("neo4j_default_config.yaml", use_cache=False)
    sql_traversal = SQLInjectionTraversal(analysis_framework)
    sql_traversal.run()
    end_time = time.time()
    print("time for SQL Injection without cache:", str(end_time - start_time))
    result = sql_traversal.recorder.get_report(origin_ids=sql_traversal.origin_id,
                                               terminal_ids=sql_traversal.terminal_id,
                                               analysis_framework=analysis_framework)
    print(f"the reachable terminal count is : " + str(len(sql_traversal.get_result())))
    sample_result(result)
    os.remove("neo4j_default_config.yaml")


def test_with_cache():
    start_time = time.time()
    if os.path.exists("_origin.json"):
        os.remove("_origin.json")
    if os.path.exists("_terminal.json"):
        os.remove("_terminal.json")
    with open("neo4j_default_config.yaml", 'w') as f:
        f.write("""NEO4J_HOST: 10.176.36.21
NEO4J_USERNAME: neo4j
NEO4J_PASSWORD: 123
NEO4J_PORT: 19092
NEO4J_PROTOCOL: bolt
NEO4J_DATABASE: neo4j""")
    analysis_framework = AnalysisFramework.from_yaml("neo4j_default_config.yaml", use_cache=True)
    sql_traversal = SQLInjectionTraversal(analysis_framework)
    sql_traversal.run()
    end_time = time.time()
    s = "time for SQL Injection with cache:" + str(end_time - start_time)
    print(s)
    # with open("cache_result.csv", "w") as f:
    #     f.write(s)
    result = sql_traversal.recorder.get_report(origin_ids=sql_traversal.origin,
                                               terminal_ids=sql_traversal.terminal_node,
                                               analysis_framework=analysis_framework)
    print(f"the reachable terminal count is : " + str(len(sql_traversal.get_result())))
    json.dump(sample_result(result), open('trace.json', 'w'))
   # print(f"cache size for cache without prefetch is {sys.getsizeof(sql_traversal.cache_graph)}")
    # sample_result(result)
    os.remove("neo4j_default_config.yaml")


def test_with_prefetch_3task():
    start_time = time.time()
    if os.path.exists("_origin.json"):
        os.remove("_origin.json")
    if os.path.exists("_terminal.json"):
        os.remove("_terminal.json")
    with open("neo4j_default_config.yaml", 'w') as f:
        f.write("""NEO4J_HOST: 10.176.36.21
NEO4J_USERNAME: neo4j
NEO4J_PASSWORD: 123
NEO4J_PORT: 17484
NEO4J_PROTOCOL: bolt
NEO4J_DATABASE: neo4j""")

    cache_graph = BasicCacheGraph()
    cache_graph.customize_storage['call_return'] = {}
    analysis_framework = AnalysisFramework.from_yaml("neo4j_default_config.yaml", cache_graph=cache_graph)
    sql_traversal = ExtendedSQLInjectionTraversal_3Task(analysis_framework, recorder=SQLIRecorder)
    sql_traversal.run()
    end_time = time.time()
    print("time for SQL Injection with 6 prefetch threads(3 task):", str(end_time - start_time))
    result = sql_traversal.recorder.get_report(origin_ids=sql_traversal.origin_id,
                                               terminal_ids=sql_traversal.terminal_id,
                                               analysis_framework=analysis_framework)

    os.remove("neo4j_default_config.yaml")


def test_with_prefetch_2task():
    start_time = time.time()
    if os.path.exists("_origin.json"):
        os.remove("_origin.json")
    if os.path.exists("_terminal.json"):
        os.remove("_terminal.json")
    with open("neo4j_default_config.yaml", 'w') as f:
        f.write("""NEO4J_HOST: 10.176.36.21
NEO4J_USERNAME: neo4j
NEO4J_PASSWORD: 123
NEO4J_PORT: 17482
NEO4J_PROTOCOL: bolt
NEO4J_DATABASE: neo4j""")
    cache_graph = BasicCacheGraph()
    cache_graph.customize_storage['call_return'] = {}
    analysis_framework = AnalysisFramework.from_yaml("neo4j_default_config.yaml", cache_graph=cache_graph)
    sql_traversal = ExtendedSQLInjectionTraversal(analysis_framework, recorder=SQLIRecorder, prefetch_thread_count=6)
    sql_traversal.run()
    end_time = time.time()

    traversal_count, cache_hit, prefetch_hit, task_count = sql_traversal.get_hit()
    s = f"traversal count:{traversal_count}  , cache_hit:{cache_hit}  ,prefetch_hit:{prefetch_hit}  ,task_count:{task_count}"
    print(s)
    s += "\n"
    s += "time for SQL Injection with 6 prefetch threads(2 task):" + str(end_time - start_time)
    print(f"time for SQL Injection with {sql_traversal.thread_pool.thread_count} prefetch threads(2 task):", str(end_time - start_time))
    with open("prefetch_result.csv", "w") as f:
        f.write(s)
    cache_size, prefetch_size = sql_traversal.get_size_of_cache()
    print(f"cache size is {cache_size}")
    print(f"cache size for with prefetch is {prefetch_size}")
    #print(f"cache size for 2 task with prefetch is {sys.getsizeof(cache_graph)}")
    # result = sql_traversal.recorder.get_report(origin_ids=sql_traversal.origin_id,
    #                                            terminal_ids=sql_traversal.terminal_id,
    #                                            analysis_framework=analysis_framework)
    # with open("dvwa-latest-SQLI.csv","w") as f:
    #     f.write(sample_result(result))
    # sql_traversal.write_no_cache_list()
    os.remove("neo4j_default_config.yaml")


    # traversal count:14852  , cache_hit:13493  ,prefetch_hit:12122  ,task_count:3425
    # time for SQL Injection with 6 prefetch threads(2 task): 24856.32749223709


def test_with_prefetch_ext(cnt=6):
    if os.path.exists("_origin.json"):
        os.remove("_origin.json")
    if os.path.exists("_terminal.json"):
        os.remove("_terminal.json")
    start_time = time.time()
    with open("neo4j_default_config.yaml", 'w') as f:
        f.write("""NEO4J_HOST: 10.176.36.21
NEO4J_USERNAME: neo4j
NEO4J_PASSWORD: 123
NEO4J_PORT: 17474
NEO4J_PROTOCOL: bolt
NEO4J_DATABASE: neo4j""")
    cache_graph = BasicCacheGraph()
    cache_graph.customize_storage['call_return'] = {}
    analysis_framework = AnalysisFramework.from_yaml("neo4j_default_config.yaml", cache_graph=cache_graph)
    sql_traversal = ExtendedSQLInjectionTraversalExt(analysis_framework, recorder=SQLIRecorder,
                                                     prefetch_thread_count=cnt)
    sql_traversal.run()
    end_time = time.time()
    traversal_count, cache_hit, prefetch_hit, task_count = sql_traversal.get_hit()
    print(
            f"traversal count:{traversal_count}  , cache_hit:{cache_hit}  ,prefetch_hit:{prefetch_hit}  ,task_count:{task_count}")
    print(f"time for SQL Injection with {sql_traversal.thread_pool.thread_count} prefetch threads(3 task):",
          str(end_time - start_time))
    print(
            f"[*]  {sql_traversal.thread_pool.thread_count},{end_time - start_time},{cache_hit / traversal_count * 100}%,{prefetch_hit / cache_hit * 100}%")
    result = sql_traversal.recorder.get_report(origin_ids=sql_traversal.origin_id,
                                               terminal_ids=sql_traversal.terminal_id,
                                               analysis_framework=analysis_framework)
    sql_traversal.write_no_cache_list()
    os.remove("neo4j_default_config.yaml")


if __name__ == '__main__':
    #    test_without_cache()
    test_with_cache()
#    test_with_prefetch_2task()
#    test_with_prefetch_3task()
