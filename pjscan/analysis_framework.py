import copy
from urllib.parse import urlparse
import py2neo
import networkx as nx
import re
from typing import Dict, List, Union, Set
from argparse import Namespace
from pjscan.neo4j_defauilt_config import NEO4J_DEFAULT_CONFIG
from pjscan.const import *
from ruamel.yaml import YAML
from pjscan.steps import *
from pjscan.cache.cache_graph import BasicCacheGraph
import logging

__all__ = ["AnalysisFramework"]

logger = logging.getLogger(__name__)
MAX_CACHE_SIZE = 128


class AnalysisFramework(object):
    """The core class of Enhanced PHPJoern Framework

    Parameters
    ----------
    graph : py2neo.Graph | Dict | Namespace
        given init format
    use_cache : bool (optional, default: True)
        enable cache or not
    prefetch_setting : dict (optional, default: {'astThreadCount': 0, 'cfgThreadCount': 0, 'pdgThreadCount': 0} )
        prefetch_setting feeder. For default , the prefetch thead will be closed.

    cache_setting : dict (optional, default: {"cacheImpl": BasicCacheGraph} )
        cache_setting feeder. Please see example to customize it.

    Attributes
    ----------
    ast_step : ASTStep | AbstractStep
        The ast_step for query. Refer to :class:`~pjscan.steps.ASTStep`。
    pdg_step : PDGStep | AbstractStep
        The pdg_step for query. Refer to :class:`~pjscan.steps.PDGStep`。
    cfg_step : CFGStep | AbstractStep
        The cfg_step for query. Refer to :class:`~pjscan.steps.CFGStep`。
    cg_step : CGStep | AbstractStep
        The cg_step for query. Refer to :class:`~pjscan.steps.CGStep`。
    chg_step : CHGStep | AbstractStep
        The chg_step for query. Refer to :class:`~pjscan.steps.CHGStep`。
    fig_step : FIGStep | AbstractStep
        The fig_step for query. Refer to :class:`~pjscan.steps.FIGStep`。
    code_step : CodeStep | AbstractStep
        The code_step for query. Refer to :class:`~pjscan.steps.CodeStep`。
    basic_step : BasicStep | AbstractStep
        The basic_step for query.Refer to :class:`~pjscan.steps.BasicStep`.


    Examples
    --------

    **Basic Usage**

    To init the AnalysisFramework, you can pass a dict and the cache or prefetch setting will be set as default.

    >>> framework = AnalysisFramework() # use the default config
    >>> framework = AnalysisFramework({"NEO4J_HOST": "localhost", # use the dict instance
    ...         "NEO4J_USERNAME": "neo4j",
    ...         "NEO4J_PASSWORD": "123",
    ...         "NEO4J_PORT": "7474",
    ...         "NEO4J_PROTOCOL": "http",
    ...         "NEO4J_DATABASE": "neo4j",})

    Or you can refer :mod:`~AnalysisFramework.from_yaml` or `from_namespace` or `from_dict` to find other interface to init the fromework

    To accomplish a simple task , e.g. find a node with id , you can use `basic_step.get_node_itself`

    >>> node =  framework.basic_step.get_node_itself(1498)
    (_1044:AST {childnum: 1, classid: 0, fileid: 1489, funcid: 1490, id: 1498, lineno: 5, type: 'AST_ASSIGN'})

    To accomplish a complex task , e.g. global taint analysis, we recommand use :class:`~pjscan.graph_traversal.GlobalProgramDependencyGraphBackwardTraversal`

    To accomplish a customized task , e.g. find SQLInjection expliatble path, we recommand extend :class:`~pjscan.graph_traversal.BaseGraphTraversal`.

    We provied a demo in :doc:tutorial/index page.

    **Advanced Usage (modify prefetch thread)**

    PrefetchThread is how the framework's prefetch functionality is implemented.

    Speed up graph traversal by starting prefetch threads in the background.

    In defulat, this functionality will be closed. Because turning on multi-threaded prefetching may increase network traffic
    ,resulting in negative optimization.

    To open them , you need to identify the prefetch thread count for each relationship via passing dict value.

    - `astThreadCount` : Specifies how many threads will be created in the background for prefetching AST relations
    - `cfgThreadCount` : Specifies how many threads will be created in the background for prefetching CFG relations
    - `pdgThreadCount` : Specifies how many threads will be created in the background for prefetching PDG relations
    - `cgThreadCount`  : Specifies how many threads will be created in the background for prefetching CG relations

    >>> prefetch_setting={
        ... "pdgThreadCount": 1, # open pdg prefetch thread , which will speed up data-flow-related query
        ... }
    >>> framework = AnalysisFramework(prefetch_setting=prefetch_setting)

    Otherwise , if you want to pass customized prefetch thread. The `<graph_name>_prefetch_thread_configure` should be given.

    For instance , if you want to pass customized `PrefetchThread`, `prefetch_setting` dict can be modifed as follows:

    >>> from pjscan.cache import BasePrefetchThread
    >>> class PdgBackwardPrefetchThread(BasePrefetchThread){...}
    >>> prefetch_setting={
        ... "pdgThreadCount": 1,
        ... "pdg_prefetch_thread_configure": {
        ...     "class_name": PdgBackwardPrefetchThread,
        ...     "drop_out": 0.25 # the PdgBackwardPrefetchThread example
        ...    }
        ... }
    >>> framework = AnalysisFramework(prefetch_setting=prefetch_setting)


    For more information , you can refer to :class:`~pjscan.cache.BasePrefetchTread` part to learn how to cutomize a `PrefetchThread` to speed up
    graph traversal according to your task requirements.

    **Advanced Usage(modify cache graph)**

    CacheGraph is how the framework's cache functionality is implemented.

    In defulat, the cache will be opened, and the default cache class is implemented by :class:`~pjscan.cache.BasicCacheGraph`

    Otherwise , if you want to pass customized `CacheGraph`, The `cache_setting` dict can be modifed as follows:

    >>> from pjscan.cache.cache_graph import BasicCacheGraph
    >>> class CustomizedCacheGraph(BasicCacheGraph){...}
    >>> cache_setting={
        ... "cacheImpl": CustomizedCacheGraph,
        ... "init_param" : "123"
        ... }

    For more information , you can refer to :class:`~pjscan.cache.PrefetchThread` part to learn how to cutomize a `CaheGraph`  to speed up
    graph traversal according to your task requirements

    **Advanced Usage(extend APIs)**

    To santisfy graph traversal interface vividly, you can pass customize step which extends :class:`~pjscan.steps.AbstractStep`

    >>> from pjscan.steps import AbstractStep
    >>> class CustomizedStep(AbstractStep):
    ...    def __init__(self, parent):
    ...        super().__init__(parent, "customize_step")
    ...    def get_x(self,node):
    ...        return node
    >>> framework = AnalysisFramework() # use the default config
    >>> framework.customize_step = CustomizedStep() # this step will be checked by framework.__register_step(o)
    >>> framework.customize_step.get_x(node)

    For more information , you can refer to :class:`~pjscan.steps.AbstractStep` part to learn how to cutomize a `CustomizedStep` to support
    various graph traversal according to your task requirements

    """

    @classmethod
    def from_dict(cls, input_dict, use_cache=True, cache_graph=None):
        """Init the Neo4j Graph Engine with dict

        Notes
        -----
        input dict must like following format

        >>> input_dict
        {
            "NEO4J_HOST": "localhost",
            "NEO4J_USERNAME": "neo4j",
            "NEO4J_PASSWORD": "123",
            "NEO4J_PORT": "16109",
            "NEO4J_PROTOCOL": "http",
            "NEO4J_DATABASE": "neo4j",
        }

        Parameters
        ----------
        input_dict : dict
            given init format
        use_cache : bool
            enable cache or not
        prefetch_setting : dict
            prefetch_setting feeder.
        cache_setting: dict
            cache_setting feeder.

        Raises
        ------
        Neo4jInitFormatError
            The input format of graph not fit the given type

        Examples
        --------
        >>> framework = AnalysisFramework.from_dict({
            "NEO4J_HOST": "localhost",
            "NEO4J_USERNAME": "neo4j",
            "NEO4J_PASSWORD": "123",
            "NEO4J_PORT": "16109",
            "NEO4J_PROTOCOL": "http",
            "NEO4J_DATABASE": "neo4j",
        })
        """
        assert "NEO4J_HOST" in input_dict.keys()
        assert "NEO4J_USERNAME" in input_dict.keys()
        assert "NEO4J_PASSWORD" in input_dict.keys()
        assert "NEO4J_PORT" in input_dict.keys()
        assert "NEO4J_PROTOCOL" in input_dict.keys()
        assert "NEO4J_DATABASE" in input_dict.keys()
        return cls(input_dict, use_cache=use_cache, cache_graph=cache_graph)

    @classmethod
    def from_yaml(cls, yaml_file, use_cache=True, cache_graph=None, ):
        """Init the Neo4j Graph Engine with YML file

        Notes
        -----
        Yaml file must like following format


        >>> open("neo4j_default_config.yml").read()
        NEO4J_HOST: 10.177.88.53
        NEO4J_USERNAME: neo4j
        NEO4J_PASSWORD: 123
        NEO4J_PORT: 7474
        NEO4J_PROTOCOL: http
        NEO4J_DATABASE: neo4j

        Parameters
        ----------
        yaml_file : str
            given init format
        use_cache : bool
            enable cache or not
        prefetch_setting : dict
            prefetch_setting feeder.
        cache_setting: dict
            cache_setting feeder.

        Raises
        ------
        Neo4jInitFormatError
            The input format of graph not fit the given type

        Examples
        --------
        >>> framework = AnalysisFramework.from_yaml("neo4j_default_config.yml") # use the default config
        """
        yaml = YAML()
        with open(yaml_file, encoding="utf8") as f:
            obj = yaml.load(f.read())
        return cls(obj, use_cache=use_cache, cache_graph=cache_graph)

    @classmethod
    def from_namespace(cls, namespace_obj, use_cache=True, cache_graph=None):
        """Init the Neo4j Graph Engine with YML file

        Notes
        -----
        namespace_obj must like following format

        >>> class ObjectInput(object):
        >>>    host = 1
        >>>    username = 1
        >>>    password = 1
        >>>    port = 1
        >>>    protocol = 1
        >>>    database = 1

        Parameters
        ----------
        namespace_obj : Namespace | object
            given init format
        use_cache : bool
            enable cache or not
        prefetch_setting : dict
            prefetch_setting feeder.
        cache_setting: dict
            cache_setting feeder.

        Raises
        ------
        Neo4jInitFormatError
            The input format of graph not fit the given type

        Examples
        --------
        >>> framework = AnalysisFramework.from_namespace(ObjectInput())
        """
        return cls(
                {
                        "NEO4J_HOST": namespace_obj.host,
                        "NEO4J_USERNAME": namespace_obj.username,
                        "NEO4J_PASSWORD": namespace_obj.password,
                        "NEO4J_PORT": namespace_obj.port,
                        "NEO4J_PROTOCOL": namespace_obj.protocol,
                        "NEO4J_DATABASE": namespace_obj.database,
                },
                use_cache=use_cache, cache_graph=cache_graph)

    def __init__(self, graph: Dict or Namespace = None, use_cache: bool = True, cache_graph=None):
        """Init the Neo4j Graph Engine

        Parameters
        ----------
        graph : Dict | Namespace
            given init format
        use_cache : bool
            enable cache or not
        prefetch_setting : dict
            prefetch_setting feeder.
        cache_setting: dict
            cache_setting feeder.

        Raises
        ------
        Neo4jInitFormatError
            The input format of graph not fit the given type

        Examples
        --------
        >>> framework = AnalysisFramework() # use the default config
        >>> framework = AnalysisFramework({"NEO4J_HOST": "localhost", # use the dict instance
        ...         "NEO4J_USERNAME": "neo4j",
        ...         "NEO4J_PASSWORD": "123",
        ...         "NEO4J_PORT": "7474",
        ...         "NEO4J_PROTOCOL": "http",
        ...         "NEO4J_DATABASE": "neo4j",})

        """
        if graph is None:
            graph = NEO4J_DEFAULT_CONFIG

        self.__py2neo_version = py2neo.__version__
        self.neo4j_graph = None
        self.graph_map = graph
        try:
            self.neo4j_graph = py2neo.Graph(f"{self.graph_map['NEO4J_PROTOCOL']}://"
                                            f"{self.graph_map['NEO4J_HOST']}:{self.graph_map['NEO4J_PORT']}",
                                            user=self.graph_map['NEO4J_USERNAME'].__str__(),
                                            password=self.graph_map['NEO4J_PASSWORD'].__str__())
        except Exception as e:
            logger.fatal(e)
        self.service_profile = copy.deepcopy(self.neo4j_graph.service.profile)
        assert self.neo4j_graph is not None, \
            "[*] failed to connect to Neo4jGraph, please check whether neo4j is opened"
        self._use_cache = use_cache
        self.cache = cache_graph if cache_graph is not None else BasicCacheGraph()
        #       print(self.cache)
        self.ast_step = ASTStep(self)
        self.pdg_step = PDGStep(self)
        self.cfg_step = CFGStep(self)
        self.cg_step = CGStep(self)
        self.chg_step = CHGStep(self)
        self.fig_step = FIGStep(self)
        self.code_step = CodeStep(self)
        self.basic_step = BasicStep(self)
        self.cache_hit = 0
        self.prefetch_hit = 0
        self.node_without_cache_hit = []
        self.node_with_cache_prefetch_hit = []
        self.node_with_cache_main_thread_hit = []

    def __register_step(self, step_clazz: AbstractStep):
        assert isinstance(step_clazz, AbstractStep), "step_clazz must be abstract_step Impl"
        setattr(self, step_clazz.step_name, step_clazz)

    def clear_cache(self):
        """clear the cache for framework

        Returns
        -------
        flag : bool

        """
        return True

    # These APIs will be removed in the future.

    # Basic Step
    def run(self, query) -> py2neo.NodeMatch:
        return self.basic_step.run(query)

    def run_and_fetch_one(self, query) -> py2neo.NodeMatch:
        return self.basic_step.run_and_fetch_one(query)

    def match(self, *args, **kwargs) -> py2neo.NodeMatch:
        return self.basic_step.match(*args, **kwargs)

    def match_first(self, *args, **kwargs) -> py2neo.Node:
        return self.basic_step.match_first(*args, **kwargs)

    def match_relationship(self, *args, **kwargs) -> py2neo.RelationshipMatch:
        return self.basic_step.match_relationship(*args, **kwargs)

    def match_first_relationship(self, *args, **kwargs) -> py2neo.Relationship:
        return self.basic_step.match_first_relationship(*args, **kwargs)

    def get_node_itself(self, _id: int) -> py2neo.Node:
        return self.basic_step.get_node_itself(_id)

    def get_node_itself_by_identity(self, _id: int):
        return self.basic_step.get_node_itself_by_identity(_id)

    # Code APIs
    def get_ast_node_code(self, _node: py2neo.Node) -> str:
        return self.code_step.get_node_code(_node)

    def find_variables(self, _node: py2neo.Node, target_type: Union[List, Set] = None) -> List[str]:
        return self.code_step.find_variables(_node, target_type)

    # AST APIs
    def find_ast_parent_nodes(self, _node: py2neo.Node) -> List[py2neo.Node]:
        return self.ast_step.find_parent_nodes(_node)

    def find_ast_child_nodes(self, _node: py2neo.Node, include_type: List[str] = None) -> List[py2neo.Node]:
        return self.ast_step.find_child_nodes(_node, include_type)

    def get_ast_ith_parent_node(self, _node: py2neo.Node, i: int = 0, ignore_error_flag=False) -> py2neo.Node or None:
        return self.ast_step.get_ith_parent_node(_node, i, ignore_error_flag)

    def get_ast_parent_node(self, _node: py2neo.Node, ignore_error_flag=False) -> Union[py2neo.Node, None]:
        return self.ast_step.get_ith_parent_node(_node, ignore_error_flag=ignore_error_flag)

    def get_ast_child_node(self, _node: py2neo.Node, ignore_error_flag=False) -> py2neo.Node:
        return self.ast_step.get_child_node(_node, ignore_error_flag)

    def get_ast_ith_child_node(self, _node: py2neo.Node, i: int = 0, ignore_error_flag=False) -> py2neo.Node or None:
        return self.ast_step.get_ith_child_node(_node, i, ignore_error_flag)

    def filter_ast_child_nodes(self, _node: py2neo.Node, max_depth=20, not_include_self: bool = False,
                               node_type_filter: Union[List[str], str, Set[str]] = None) -> List[py2neo.Node]:
        return self.ast_step.filter_child_nodes(_node, max_depth, not_include_self, node_type_filter)

    def get_ast_root_node(self, _node: py2neo.Node) -> py2neo.Node:
        return self.ast_step.get_root_node(_node)

    def get_control_node_condition(self, _node: py2neo.Node, ignore_error=False) -> py2neo.Node:
        return self.ast_step.get_control_node_condition(_node, ignore_error)

    # CFG APIs
    def find_cfg_predecessors(self, _node: py2neo.Node) -> List[py2neo.Node]:
        return self.cfg_step.find_successors(_node)

    def find_cfg_successors(self, _node: py2neo.Node) -> List[py2neo.Node]:
        return self.cfg_step.find_successors(_node)

    def get_cfg_flow_label(self, _node_start: py2neo.Node, _node_end: py2neo.Node) -> List[str]:
        return self.cfg_step.get_flow_label(_node_start, _node_end)

    def has_cfg(self, node):
        return self.match_relationship({node}, r_type=CFG_EDGE).exists()

    # PDG APIs
    def find_pdg_use_nodes(self, _node: py2neo.Node) -> List[py2neo.Node]:
        return self.pdg_step.find_use_nodes(_node)

    def find_pdg_def_nodes(self, _node: py2neo.Node) -> List[py2neo.Node]:
        return self.pdg_step.find_def_nodes(_node)

    def get_pdg_vars(self, _node_start: py2neo.Node, _node_end: py2neo.Node) -> List[str]:
        return self.pdg_step.get_related_vars(_node_start, _node_end)

    # CG APIs
    def find_cg_call_nodes(self, _node: py2neo.Node) -> List[py2neo.Node]:
        return self.cg_step.find_call_nodes(_node)

    def find_cg_decl_nodes(self, _node: py2neo.Node) -> List[py2neo.Node]:
        return self.cg_step.find_decl_nodes(_node)

    # FIG APIs
    def find_fig_include_src(self, _node: py2neo.Node) -> List[py2neo.Node]:
        return self.fig_step.find_include_src(_node)

    def find_fig_include_dst(self, _node: py2neo.Node) -> List[py2neo.Node]:
        return self.fig_step.find_include_dst(_node)

    def get_fig_include_map(self, _node: py2neo.Node) -> nx.DiGraph:
        return self.fig_step.get_include_map(_node)

    def get_fig_belong_file(self, _node: py2neo.Node) -> str:
        return self.fig_step.get_belong_file(_node)

    def get_fig_file_name_node(self, _file_name: str, match_strategy=1) -> Union[py2neo.Node, None]:
        return self.fig_step.get_file_name_node(_file_name, match_strategy)

    def get_fig_filesystem_node(self, _node: py2neo.Node) -> py2neo.Node:
        return self.fig_step.get_filesystem_node(_node)

    # 未来上述这些代码都会删掉
