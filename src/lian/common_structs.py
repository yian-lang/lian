##!/usr/bin/env python3
import dataclasses
import json
import os
import networkx as nx
import pandas as pd
import matplotlib.pyplot as plt
import pprint
import numpy
import copy
import heapq
from collections import Counter
from itertools import count
from collections import defaultdict
from lian.util import readable_gir
from lian.util.gir_block import GIRBlockViewer

from lian.util import util
from lian.config.constants import (
    BUILTIN_OR_CUSTOM_DATA_TYPE,
    CONDITION_FLAG,
    LIAN_SYMBOL_KIND,
    STATE_TYPE_KIND,
    SYMBOL_OR_STATE,
    CALLEE_TYPE,
    LIAN_INTERNAL,
    EXTERNAL_KEY_STATE_TYPE,
    EXPORT_NODE_TYPE,
    ACCESS_POINT_KIND,
    SFG_NODE_KIND,
    SFG_EDGE_KIND
)
from lian.config import config

class BasicElement:
    def get_id(self):
        pass

    def change_id(self):
        pass

class ToDict:
    def to_dict(self):
        """
        Converts the dataclass to a dict
        """
        result = {}
        for field in dataclasses.fields(self):
            result[field.name] = getattr(self, field.name)
        return result

class BasicSpace:
    def __init__(self):
        self.id_to_indexes = {}
        self.index_to_id = {}
        self.space = []
        # else:
        #     self.space = copy.deepcopy(space)

    def change_id(self, index, new_id):
        element = self.space[index]
        element.change_id(new_id)

        self.notify_id_change(index, new_id)

    def notify_id_change(self, index, new_id):
        old_id = self.index_to_id[index]
        self.index_to_id[index] = new_id

        self.id_to_indexes[old_id].remove(index)
        if new_id not in self.id_to_indexes:
            self.id_to_indexes[new_id] = set()
        self.id_to_indexes[new_id].append(index)

    def find_first_by_id(self, _id):
        if _id in self.id_to_indexes:
            indexes = self.id_to_indexes[_id]
            if len(indexes) != 0:
                return self.space[min(indexes)]
        return None

    def find_all_by_id(self, _id):
        result = []
        if _id in self.id_to_indexes:
            indexes = self.id_to_indexes[_id]
            for each_index in indexes:
                result.append(self.space[each_index])
        return result

    def find_all_stmt_ids_by_id(self, _id):
        result = []
        all_elements = self.find_all_by_id(_id)
        if all_elements:
            for elem in all_elements:
                result.append(elem.stmt_id)
        return result

    def __getitem__(self, index):
        if not isinstance(index, (int, numpy.int64)):
            if int_index := util.str_to_int(index):
                index = int_index
            else:
                return None
        if index >= 0 and index < len(self.space):
            return self.space[index]
        return None

    def add(self, item):
        index = -1
        if util.is_empty(item):
            return index

        self.space.append(item)
        index = len(self.space) - 1

        if isinstance(item, BasicElement):
            _id = item.get_id()
            if _id not in self.id_to_indexes:
                self.id_to_indexes[_id] = set()
            self.id_to_indexes[_id].add(index)

        return index

    def __iter__(self):
        for row in self.space:
            yield row

    def get_length(self):
        return len(self.space)

class BasicGraph:
    def __init__(self):
        self.graph = nx.MultiDiGraph()

    def retrieve_graph(self):
        return self.graph

    def show(self):
        # dot_graph = nx.drawing.nx_pydot.to_pydot(G)
        # dot_file_path = "graph.dot"
        # dot_graph.write_dot(dot_file_path)
        self.draw_graph()
        plt.show()

    def draw_graph(self):
        plt.clf()
        pos = nx.circular_layout(self.graph)
        nx.draw(
            self.graph, pos, with_labels=True, node_color='skyblue', node_size=700,
            edge_color='k', linewidths=1, font_size=15, arrows=True
        )
        edge_labels = dict([((u, v,), d['weight']) for u, v, d in self.graph.edges(data=True)])
        nx.draw_networkx_edge_labels(self.graph, pos, edge_labels=edge_labels)

    def save_png(self, path):
        self.draw_graph()
        plt.savefig(path)

    def _add_one_edge(self, src_stmt_id, dst_stmt_id, weight):
        if src_stmt_id == dst_stmt_id:
            return
        if isinstance(src_stmt_id, (int, numpy.int64)) and src_stmt_id < 0:
            return
        # if config.DEBUG_FLAG:
        #     util.debug(f"_add_one_edge:{src_stmt_id}->{dst_stmt_id}, weight={weight}")
        if not self.graph.has_edge(src_stmt_id, dst_stmt_id):
            self.graph.add_edge(src_stmt_id, dst_stmt_id, weight = weight)

    # def add_node(self, node):
    #     if node:
    #         self.graph.add_node(node)

    def has_edge(self, src, dst):
        return self.graph.has_edge(src, dst)

    @profile
    def add_edge(self, src_stmt, dst_stmt, weight = None):
        src_stmt_id = -1
        dst_stmt_id = -1
        if util.is_empty(src_stmt) or util.is_empty(dst_stmt) :
            return

        if isinstance(src_stmt, (int, numpy.int64, str)):
            src_stmt_id = src_stmt
        elif isinstance(src_stmt, list):
            for src in src_stmt:
                self.add_edge(src, dst_stmt, weight)
            return
        else:
            src_stmt_id = src_stmt.stmt_id

        if type(dst_stmt) in (int, numpy.int64, str):
            dst_stmt_id = dst_stmt
        else:
            dst_stmt_id = dst_stmt.stmt_id

        self._add_one_edge(src_stmt_id, dst_stmt_id, weight)

    def backward_search(self, node, node_constraint):
        """
        query_constraint_over_node: given an node, check if the node meet the requirements or not.

        [return]
        true/false: the current node will be kept
        the list or set of the nodes, which meet the requirements: the list or set will be saved
        """
        satisfying_nodes = set()
        visited = set()

        if node not in self.graph:
            return satisfying_nodes

        stack = [node]

        while stack:
            current_node = stack.pop()
            if current_node in visited:
                continue
            visited.add(current_node)

            tmp_result = node_constraint(current_node)
            if tmp_result:
                if isinstance(tmp_result, bool):
                    satisfying_nodes.add(current_node)
                else:
                    satisfying_nodes.update(tmp_result)

                # stop this path
                continue

            for parent in util.graph_predecessors(self.graph, current_node):
                if parent not in visited:
                    stack.append(parent)

        return satisfying_nodes

class BasicGraphWithSelfCircle(BasicGraph):
    def _add_one_edge(self, src_stmt_id, dst_stmt_id, weight):
        # if src_stmt_id == dst_stmt_id:
        #     return
        if isinstance(src_stmt_id, (int, numpy.int64)) and src_stmt_id < 0:
            return
        # if config.DEBUG_FLAG:
        #     util.debug(f"_add_one_edge:{src_stmt_id}->{dst_stmt_id}, weight={weight}")
        self.graph.add_edge(src_stmt_id, dst_stmt_id, weight = weight)

class MultipleDirectedGraph(BasicGraph):
    pass

@dataclasses.dataclass
class ImportStmtInfo:
    stmt_id: int            = -1
    imported_unit_id: int   = -1
    imported_stmt_id: int   = -1
    is_parsed: bool         = False
    is_unit: bool           = False


class SimpleWorkList:
    def __init__(self, init_data = [], graph = None, entry_node = None):
        self.work_list = []
        self.all_data = set()
        self.graph = graph
        self.priority_dict = {}
        if init_data:
            self.add(init_data)

        if self.graph:
            if not entry_node:
                first_nodes = list(sorted(util.find_graph_nodes_with_zero_in_degree(self.graph)))
                if first_nodes:
                    entry_node = first_nodes[0]

            if entry_node:
                # Prevent duplicate insertion of late-execution nodes
                # For example: if () {1; } else {2; 3;} 4
                cfg_order = list(reversed(list(
                    nx.dfs_postorder_nodes(self.graph, source = entry_node)
                )))

                self.priority_dict = {
                    node: idx for idx, node in enumerate(cfg_order)
                }

    def _add_with_priority(self, item):
        if item not in self.all_data:
            if self.priority_dict:
                heapq.heappush(self.work_list, (self.priority_dict.get(item, 0), item))
            else:
                self.work_list.append(item)
            self.all_data.add(item)

    def fast_add(self, item):
        if item not in self.all_data:
            self._add_with_priority(item)
        return self

    def add(self, data):
        if hasattr(data, '__iter__'):
            for node in data:
                if node not in self.all_data:
                    self._add_with_priority(node)

            return self

        if data not in self.all_data:
            self._add_with_priority(data)

        return self

    def pop(self):
        if len(self.work_list) <= 0:
            return None

        result = self.work_list.pop(0)
        if isinstance(result, tuple):
            result = result[1]
        if result in self.all_data:
            self.all_data.remove(result)
        return result

    def insert_to_first(self, stmt_id):
        if self.priority_dict:
            heapq.heappush(self.work_list, (0, stmt_id))
        else:
            self.work_list.insert(0, stmt_id)
        self.all_data.add(stmt_id)

    def peek(self):
        if len(self.work_list) <= 0:
            return None

        result = self.work_list[0]
        if isinstance(result, tuple):
            result = result[1]

        return result

    def __len__(self):
        return len(self.work_list)

    def is_available(self):
        return len(self.work_list) != 0

    def __iter__(self):
        for row in self.work_list:
            yield row

    def __repr__(self):
        return f"{self.work_list}"

    def __getitem__(self, index):
        if index >= 0 and index < len(self.work_list):
            result = self.work_list[index]
            if isinstance(result, tuple):
                result = result[1]
            return result
        return None

    def __contains__(self, index):
        return index in self.all_data

class SimpleSet:
    def __init__(self, init_data = []):
        self.all_data = set()
        if init_data:
            self.add(init_data)

    def fast_add(self, item):
        if item not in self.all_data:
            self.all_data.add(item)
        return self

    def add(self, data):
        if hasattr(data, '__iter__'):
            for node in data:
                self.all_data.add(node)
            return self

        if data not in self.all_data:
            self.all_data.add(data)

        return self

    def remove(self, item):
        if len(self.all_data) <= 0:
            return None

        if item in self.all_data:
            self.all_data.remove(item)

    def __len__(self):
        return len(self.all_data)

    def __contains__(self, index):
        return index in self.all_data

@dataclasses.dataclass
class Scope(BasicElement):
    unit_id: int = -1
    stmt_id: int = -1
    scope_id: int = -1
    parent_stmt_id: int = -1
    scope_kind: LIAN_SYMBOL_KIND = LIAN_SYMBOL_KIND.METHOD_KIND
    source: str = ""            # for from_import_stmt source import name as alis
    name: str = ""
    # attrs: list = dataclasses.field(default_factory=list)
    attrs: str = ""
    supers: str = ""
    alias: str = ""

    def get_id(self):
        return self.stmt_id

    def to_dict(self):
        row_dict = {
            "unit_id": self.unit_id,
            "stmt_id": self.stmt_id,
            "scope_id": self.scope_id,
            "parent_stmt_id": self.parent_stmt_id,
            "scope_kind": self.scope_kind,
            "name": self.name,
            "attrs": self.attrs,
            "supers": self.supers,
            "alias": self.alias,
            "source": self.source
        }
        return row_dict

    def from_dict(self, _dict: dict):
        for key, value in _dict.items():
            if hasattr(self, key):
                setattr(self, key, value)
        return self

    def __repr__(self):
        result = self.to_dict()
        return (f"Scope [{str(result)}]")

class ScopeSpace(BasicSpace):
    def to_dict(self):
        results = []
        for row in self.space:
            results.append(row.to_dict())
        return results

class CFGNode:
    def __init__(self, stmt, edge = None):
        self.stmt = stmt
        self.edge = edge

class ControlFlowGraph(BasicGraph):
    def __init__(self, method_id):
        self.method_id = method_id
        self.graph = nx.MultiDiGraph()

    def add_edge(self, src_stmt, dst_stmt, control_flow_type = None):
        if isinstance(src_stmt, CFGNode):
            self.add_edge(src_stmt.stmt, dst_stmt, src_stmt.edge)
        else:
            super().add_edge(src_stmt, dst_stmt, control_flow_type)

@dataclasses.dataclass
class AccessPoint:
    kind: int = ACCESS_POINT_KIND.TOP_LEVEL
    key: str = ""
    state_id: int = -1

    def to_dict(self):
        row_dict = {
            "kind": self.kind,
            "key": self.key,
            "state_id": self.state_id
        }
        return row_dict

    def to_dict_str(self):
        return f"{{\"kind\": \"{util.process_string(self.kind)}\", \"key\": \"{util.process_string(self.key)}\", \"state_id\": \"{self.state_id}\"}}"

    def __eq__(self, other):
        if isinstance(other, AccessPoint):
            return self.kind == other.kind and self.key == other.key and self.state_id == other.state_id
        return False


# @dataclasses.dataclass
# class ExternalKeyState:
#     stmt_id: int = -1
#     source_unit_id: int = -1
#     symbol_id: int = -1
#     data_type: DataType = ""
#     key_type: ExternalKeyStateType = ExternalKeyStateType.EMPTY
#     access_path: str = ""

#     def to_dict(self, method_id, counter):
#         return {
#             "method_id": method_id,
#             "index": counter,
#             "symbol_or_state": SymbolOrState.EXTERNAL_KEY_STATE,
#             "stmt_id": self.stmt_id,
#             "source_unit_id": str(self.source_unit_id),
#             "symbol_id": str(self.symbol_id),
#             "data_type": self.data_type,
#             "key_type": self.key_type,
#             "access_path": self.access_path,
#         }

#     def copy(self):
#         return ExternalKeyState(
#             self.stmt_id,
#             self.symbol_id,
#             self.source_unit_id,
#             self.data_type,
#             self.key_type,
#             self.access_path,
#         )

#global_unique_id = config.START_INDEX
global_state_id = config.START_INDEX

@dataclasses.dataclass
class State(BasicElement):
    """
    state_id: _id
    data_type: the state's data type
    value: state content
    stmt_id: stmt_id, indicating where the state is defined
    """
    stmt_id: int = -1
    state_id: int = -1
    symbol_or_state: int = SYMBOL_OR_STATE.STATE
    state_type: int = STATE_TYPE_KIND.REGULAR

    data_type: str = ""
    data_type_ids: set[int] = dataclasses.field(default_factory=set)

    value: object = ""
    fields: dict = dataclasses.field(default_factory=lambda: {})
    array: list[set] = dataclasses.field(default_factory=list)

    tangping_elements: set = dataclasses.field(default_factory=set)
    tangping_flag: bool = False

    source_symbol_id: int = -1
    source_state_id: int = -1
    access_path: list[AccessPoint] = dataclasses.field(default_factory=list)

    # unique_id: int = -1
    # analysis_round_number: int = -1
    # analysis_phase_id: int = -1

    def __post_init__(self):
        if self.state_id == -1:
            global global_state_id
            self.state_id = global_state_id
            global_state_id += 1

        if self.source_state_id == -1:
            self.source_state_id = self.state_id

        # global global_unique_id
        # global_unique_id += 1
        # self.unique_id = global_unique_id

    def get_id(self):
        return self.state_id

    def get_data_type(self):
        return self.data_type
    
    @staticmethod
    def _safe_str(obj) -> str:
        """
        Best-effort stringification that won't crash on huge int decimal conversion.
        Keeps plain strings unchanged (no added quotes), to preserve prior behavior.
        """
        if isinstance(obj, str):
            return obj
        if isinstance(obj, int):
            try:
                return str(obj)
            except ValueError:
                return hex(obj)
        try:
            return str(obj)
        except ValueError:
            # fall back to a literal-safe representation
            return State._safe_literal(obj)

    @staticmethod
    def _safe_literal(obj):
        """
        Convert object into a Python-literal string that is safe against Python's
        max int->decimal string conversion limit.

        Notes:
        - For large ints, we fall back to hex integer literals (0x... / -0x...),
          which remain parseable by ast.literal_eval.
        - For containers, we recursively build literals so loader-side
          ast.literal_eval continues to work.
        """
        # primitives
        if obj is None or isinstance(obj, (bool, float)):
            return repr(obj)

        if isinstance(obj, int):
            try:
                return str(obj)
            except ValueError:
                return hex(obj)

        if isinstance(obj, str):
            return repr(obj)

        # containers
        if isinstance(obj, list):
            return "[" + ", ".join(State._safe_literal(v) for v in obj) + "]"

        if isinstance(obj, tuple):
            inner = ", ".join(State._safe_literal(v) for v in obj)
            if len(obj) == 1:
                inner += ","
            return "(" + inner + ")"

        if isinstance(obj, set):
            if len(obj) == 0:
                return "set()"
            return "{" + ", ".join(State._safe_literal(v) for v in obj) + "}"

        if isinstance(obj, dict):
            parts = []
            for k, v in obj.items():
                parts.append(State._safe_literal(k) + ": " + State._safe_literal(v))
            return "{" + ", ".join(parts) + "}"

        # fallback
        try:
            return repr(obj)
        except ValueError:
            # last resort: stringify, but still avoid crashing the serializer
            return repr(f"<unreprable {type(obj).__name__}>")
        
    def _adjust_fields(self):
        keys_to_move = []
        for k in self.fields:
            if not isinstance(k, str): 
                keys_to_move.append((k, int(k)))

        # 2. Execute in-place movement
        for old_k, new_k in keys_to_move:
            value = self.fields[old_k]
            # Remove the old key
            del self.fields[old_k]
            # Assign the new key
            self.fields[new_k] = value

    def to_dict(self, counter, _id):
        self._adjust_fields()

        result = {
            "index"                 : counter,
            "symbol_or_state"       : self.symbol_or_state,
            "stmt_id"               : self.stmt_id,
            "state_id"              : self.state_id,
            # the following three fields are for symbol
            "name"                  : None,
            "default_data_type"     : None,
            "states"                : None,

            "state_type"            : self.state_type,
            "data_type"             : self.data_type,
            "value"                 : str(self.value), 
            "tangping_flag"         : self.tangping_flag,
            "tangping_elements"     : json.dumps(list(self.tangping_elements)),
            "fields"                : json.dumps(self.fields, default=lambda x: list(x)),
            "array"                 : json.dumps(self.array, default=lambda x: list(x)),
            "source_symbol_id"      : self.source_symbol_id,
            "source_state_id"       : self.source_state_id,
            "access_path"           : json.dumps(self.access_path, default=lambda x: x.to_dict()),
            # "unique_id"              : self.unique_id,
            # "analysis_round_number"  : self.analysis_round_number,
            # "analysis_phase_id"      : self.analysis_phase_id,
        }

        # if isinstance(_id, tuple):
        #     result["caller_id"] = _id[0]
        #     result["call_stmt_id"] = _id[1]
        #     result["method_id"] = _id[2]
        #     result["hash_id"] = hash(_id)
        # else:
        result["method_id"] = _id

        return result

    def __eq__(self, other):
        if not isinstance(other, State):
            return False
        return (
            self.data_type == other.data_type and
            self.value == other.value and
            self.fields == other.fields and
            self.array == other.array and
            self.tangping_elements == other.tangping_elements
        )

    def copy(self, stmt_id = None):
        if stmt_id is None:
            stmt_id = self.stmt_id

        return State(
            stmt_id = stmt_id,
            state_id = self.state_id,
            symbol_or_state = self.symbol_or_state,
            state_type = self.state_type,
            data_type = self.data_type,
            value = self.value,
            fields = copy.deepcopy(self.fields),
            array = copy.deepcopy(self.array),
            tangping_elements= self.tangping_elements.copy(),
            tangping_flag = self.tangping_flag,
            source_symbol_id = self.source_symbol_id,
            source_state_id= self.source_state_id,
            access_path = self.access_path.copy(),
        )

    def __hash__(self):
        return hash((self.stmt_id, self.state_id))

    def recover_access_path_str(self) -> str:
        """Convert the state access_path back to a.b.c format"""
        access_path_str = ""
        for access_point in self.access_path:
            access_path_str += access_point.key + "."

        return access_path_str[:-1] if access_path_str else ""

@dataclasses.dataclass
class Symbol(BasicElement):
    """
    symbol_id: _id
    name: symbol name
    state: list of state
        # a = 3; a.value -> 3
        # a = b; a.value -> b.value
        # a = &b; a.value -> addr_of(b) = b.state.state_id
        # if () {} [merge] value -> [state1, state2, 3, b.value, b.state.state_id]
    stmt_id: it is a stmt_id, indicating which scope the symbol is located at
    alias: another alias name (or symbol_id?) of this symbol
    """
    stmt_id: int = -1
    name: str = ""
    default_data_type: str = ""
    states: set[int] = dataclasses.field(default_factory=set)
    symbol_or_state: int = SYMBOL_OR_STATE.SYMBOL
    symbol_id: int = -1
    source_unit_id: int = -1

    # unique_id: int = -1

    # def __post_init__(self):
    #     global global_unique_id
    #     global_unique_id += 1
    #     self.unique_id = global_unique_id

    def copy(self, stmt_id = None):
        if stmt_id is None:
            stmt_id = self.stmt_id

        return Symbol(
            stmt_id = self.stmt_id,
            name = self.name,
            default_data_type = self.default_data_type,
            states = self.states.copy(),
            symbol_or_state = self.symbol_or_state,
            symbol_id = self.symbol_id,
            source_unit_id = self.source_unit_id,
        )

    def to_dict(self, counter, _id):
        result = {
            "index": counter,
            "symbol_or_state": self.symbol_or_state,
            "stmt_id": self.stmt_id,
            "source_unit_id": self.source_unit_id,
            "symbol_id": self.symbol_id,
            "name": self.name,
            "default_data_type": self.default_data_type,
            "states": list(self.states),
            "state_id": -1,
            "data_type": None,
            "value": None,
            "fields": None,
            "array": None,
        }

        # if isinstance(_id, tuple):
        #     result["caller_id"] = _id[0]
        #     result["call_stmt_id"] = _id[1]
        #     result["method_id"] = _id[2]
        #     result["hash_id"] = hash(_id)
        # else:
        result["method_id"] = _id

        return result

@dataclasses.dataclass
class ParameterMapping:
    arg_index_in_space: int = -1
    arg_state_id: int = -1
    arg_source_symbol_id: int = -1
    arg_access_path: list[AccessPoint] = dataclasses.field(default_factory=list)
    parameter_symbol_id: int = -1
    parameter_type: int = LIAN_INTERNAL.PARAMETER_DECL
    parameter_access_path: AccessPoint = None
    is_default_value: bool = False

    def copy(self):
        return ParameterMapping(
            arg_index_in_space = self.arg_index_in_space,
            arg_state_id = self.arg_state_id,
            arg_source_symbol_id = self.arg_source_symbol_id,
            arg_access_path = self.arg_access_path.copy(),
            parameter_symbol_id = self.parameter_symbol_id,
            parameter_type = self.parameter_type,
            parameter_access_path = self.parameter_access_path,
            is_default_value = self.is_default_value
        )

    def to_dict(self, _id):
        return {
            "hash_id": hash(_id),
            "caller_id": _id.caller_id,
            "call_stmt_id": _id.call_stmt_id,
            "callee_id": _id.callee_id,
            "arg_index_in_space": self.arg_index_in_space,
            "arg_state_id": self.arg_state_id,
            "arg_source_symbol_id": self.arg_source_symbol_id,
            "arg_access_path": [p.to_dict_str() for p in self.arg_access_path],
            "parameter_symbol_id": self.parameter_symbol_id,
            "parameter_type": self.parameter_type,
            "parameter_access_path": self.parameter_access_path.to_dict_str() if self.parameter_access_path else None,
            "is_default_value": self.is_default_value,
        }

@dataclasses.dataclass
class ShiftIndexResult:
    new_indexes: object = None
    old_index_to_new_index: dict = dataclasses.field(default_factory=lambda: {})
    new_index_to_old_index: dict = dataclasses.field(default_factory=lambda: {})

class SymbolStateSpace(BasicSpace, ShiftIndexResult):
    def __init__(self):
        self.state_index_to_id = {}
        BasicSpace.__init__(self)
        ShiftIndexResult.__init__(self)

    def rescan(self):
        self.state_index_to_id = {}
        if self.space:
            for index, item in enumerate(self.space):
                if isinstance(item, State):
                    self.state_index_to_id[index] = item.state_id

    def to_dict(self, _id):
        results = []
        for counter in range(len(self.space)):
            element = self.space[counter]
            results.append(element.to_dict(counter, _id))
        return results

    def add(self, item):
        index = -1
        if util.is_empty(item):
            return index

        self.space.append(item)
        index = len(self.space) - 1

        if isinstance(item, State):
            self.state_index_to_id[index] = item.state_id

        return index

    def convert_state_index_to_state_id(self, state_index):
        return self.state_index_to_id.get(state_index, -1)

    def convert_state_indexes_to_state_ids(self, state_indexes):
        state_ids = set()
        for each_index in state_indexes:
            each_id = self.convert_state_index_to_state_id(each_index)
            if each_id > 0:
                state_ids.add(each_id)
        return state_ids

    def exist_state_index(self, index):
        return index in self.state_index_to_id

    def copy(self):
        copied = SymbolStateSpace()
        for item in self.space:
            copied.add(item.copy())
        copied.old_index_to_new_index = self.old_index_to_new_index.copy()
        copied.new_index_to_old_index = self.new_index_to_old_index.copy()
        return copied

    def __repr__(self):
        return str(self.to_dict(0))

    def __len__(self):
        return len(self.space)

    def shift_indexes(self, target_indexes, baseline_index, shift_result = None):
        # shift target_indexes by baseline_index
        old_index_to_new_index = {}
        new_index_to_old_index = {}
        new_indexes = []
        is_list = True
        if isinstance(target_indexes, set):
            new_indexes = set()
            is_list = False

        if util.is_available(shift_result):
            shift_result.new_indexes = new_indexes
            old_index_to_new_index = shift_result.old_index_to_new_index
            new_index_to_old_index = shift_result.new_index_to_old_index

        for index in target_indexes:
            if index in old_index_to_new_index:
                if is_list:
                    new_indexes.append(old_index_to_new_index[index])
                else:
                    new_indexes.add(old_index_to_new_index[index])
                continue
            new_index = index + baseline_index
            old_index_to_new_index[index] = new_index
            new_index_to_old_index[new_index] = index
            if is_list:
                new_indexes.append(new_index)
            else:
                new_indexes.add(new_index)

        shift_result.old_index_to_new_index.update(old_index_to_new_index)
        shift_result.new_index_to_old_index.update(new_index_to_old_index)

    def extract_related_elements_to_new_space(self, target_list):
        results = []
        old_index_to_new_index = {}
        new_index_to_old_index = {}
        all_indexes = set()
        target_list_copy = target_list.copy()
        target_list_copy = set(target_list_copy)

        # scanning all needed elements
        while len(target_list_copy) != 0:
            index = target_list_copy.pop()
            if index in all_indexes:
                continue
            all_indexes.add(index)

            content = self.space[index]
            if util.is_available(content):
                if isinstance(content, State):
                    for each_value in content.fields.values():
                        target_list_copy.update(each_value)

                    target_list_copy.update(content.tangping_elements)

                    for each_value in content.array:
                        target_list_copy.update(each_value)
                elif isinstance(content, Symbol):
                    # Symbol: states
                    target_list_copy.update(content.states)

        # copy target elements
        for index in all_indexes:
            content = self.space[index]
            if util.is_available(content):
                results.append(content.copy())
                new_index = len(results) - 1
                old_index_to_new_index[index] = new_index
                new_index_to_old_index[new_index] = index

        # adjust ids
        for element in results:
            if isinstance(element, State):
                element.tangping_elements = util.map_index_to_new_index(
                    element.tangping_elements, old_index_to_new_index
                )
                for each_field in element.fields:
                    element.fields[each_field] = util.map_index_to_new_index(
                        element.fields[each_field], old_index_to_new_index
                    )
                new_array = []
                for index_group in element.array:
                    new_array.append(util.map_index_to_new_index(index_group, old_index_to_new_index))
                element.array = new_array

            # Symbol
            elif isinstance(element, Symbol):
                element.states = util.map_index_to_new_index(element.states, old_index_to_new_index)

        space = SymbolStateSpace()
        space.space = results
        space.rescan()
        space.old_index_to_new_index = old_index_to_new_index
        space.new_index_to_old_index = new_index_to_old_index
        return space

    def append_space_copy(self, another):
        baseline_index = len(self.space)
        copy_of_another = another.copy()
        copy_of_another.old_index_to_new_index = {}
        copy_of_another.new_index_to_old_index = {}
        another_space = copy_of_another.space
        for old_index in range(len(another_space)):
            self.shift_indexes([old_index], baseline_index, copy_of_another)
            element = another_space[old_index]
            if isinstance(element, State):
                self.shift_indexes(element.tangping_elements, baseline_index, copy_of_another)
                element.tangping_elements = copy_of_another.new_indexes

                for each_field in element.fields:
                    self.shift_indexes(element.fields[each_field], baseline_index, copy_of_another)
                    element.fields[each_field] = copy_of_another.new_indexes

                new_array = []
                for index_group in element.array:
                    self.shift_indexes(index_group, baseline_index, copy_of_another)
                    new_array.append(copy_of_another.new_indexes)
                element.array = new_array

            elif isinstance(element, Symbol):
                # Symbol
                self.shift_indexes(element.states, baseline_index, copy_of_another)
                element.states = copy_of_another.new_indexes

        for new_index in sorted(copy_of_another.new_index_to_old_index.keys()):
            old_index = copy_of_another.new_index_to_old_index[new_index]
            element = another_space[old_index]
            self.add(element)

        another.old_index_to_new_index = copy_of_another.old_index_to_new_index
        another.new_index_to_old_index = copy_of_another.new_index_to_old_index

@dataclasses.dataclass
class StateDefNode:
    index: int = -1
    state_id: int = -1
    stmt_id: int = -1

    def __hash__(self) -> int:
        return hash((self.index, self.state_id, self.stmt_id))

    def __eq__(self, other: object) -> bool:
        return isinstance(other, StateDefNode) and self.state_id == other.state_id and self.index == other.index and self.stmt_id == other.stmt_id

    def to_dict(self, method_id, bit_pos):
        return {
            "method_id": method_id,
            "bit_pos": bit_pos,
            "index": self.index,
            "state_id": self.state_id,
            "stmt_id": self.stmt_id
        }
    
    def to_simple_dict(self):
        return {
            "index": int(self.index),
            "state_id": int(self.state_id),
            "stmt_id": int(self.stmt_id)
        }

@dataclasses.dataclass
class SymbolDefNode:
    index: int = -1
    symbol_id: int = -1
    stmt_id: int = -1

    def __hash__(self) -> int:
        return hash((self.index, self.symbol_id, self.stmt_id))

    def __eq__(self, other: object) -> bool:
        return isinstance(other, SymbolDefNode) and self.index == other.index and self.symbol_id == other.symbol_id and self.stmt_id == other.stmt_id

    def to_tuple(self):
        return (self.index, self.symbol_id, self.stmt_id,)

    def to_dict(self, method_id = -1, bit_pos = -1):
        return {
            "method_id": method_id,
            "bit_pos": bit_pos,
            "index": self.index,
            "symbol_id": self.symbol_id,
            "stmt_id": self.stmt_id
        }
    
    def to_simple_dict(self):
        return {
            "index": int(self.index),
            "symbol_id": int(self.symbol_id),
            "stmt_id": int(self.stmt_id)
        }

@dataclasses.dataclass
class StmtStatus:
    stmt_id: int = -1

    defined_symbol: int = -1
    used_symbols: list[int] = dataclasses.field(default_factory=list)
    implicitly_defined_symbols: list[int] = dataclasses.field(default_factory=list)
    implicitly_used_symbols: list[int] = dataclasses.field(default_factory=list)
    in_symbol_bits: set[SymbolDefNode]   = dataclasses.field(default_factory=set)
    out_symbol_bits: set[SymbolDefNode] = dataclasses.field(default_factory=set)

    defined_states: set[int]= dataclasses.field(default_factory=set)
    in_state_bits: set[StateDefNode]  = dataclasses.field(default_factory=set)
    out_state_bits: set[StateDefNode] = dataclasses.field(default_factory=set)

    field_name: str = ""

    def copy(self):
        return StmtStatus(
            stmt_id = self.stmt_id,
            defined_symbol = self.defined_symbol,
            used_symbols = self.used_symbols.copy(),
            implicitly_defined_symbols = self.implicitly_defined_symbols.copy(),
            implicitly_used_symbols = self.implicitly_used_symbols.copy(),
            in_symbol_bits = self.in_symbol_bits,
            out_symbol_bits = self.out_symbol_bits,
            defined_states = self.defined_states.copy(),
            in_state_bits = self.in_state_bits,
            out_state_bits = self.out_state_bits,
            field_name = self.field_name,
        )

    def to_dict(self, method_id):
        new_in_symbol_bits = []
        for each_bit in self.in_symbol_bits:
            new_in_symbol_bits.append(each_bit.to_simple_dict())

        new_out_symbol_bits = []
        for each_bit in self.out_symbol_bits:
            new_out_symbol_bits.append(each_bit.to_simple_dict())

        new_in_state_bits = []
        for each_bit in self.in_state_bits:
            new_in_state_bits.append(each_bit.to_simple_dict())

        new_out_state_bits = []
        for each_bit in self.out_state_bits:
            new_out_state_bits.append(each_bit.to_simple_dict())

        return {
            "method_id"                 : method_id,
            "stmt_id"                   : self.stmt_id,
            "defined_symbol"            : self.defined_symbol,
            "used_symbols"              : json.dumps(self.used_symbols),
            "implicitly_defined_symbols": json.dumps(self.implicitly_defined_symbols),
            "implicitly_used_symbols"   : json.dumps(self.implicitly_used_symbols),
            "in_symbol_bits"            : json.dumps(new_in_symbol_bits),
            "out_symbol_bits"           : json.dumps(new_out_symbol_bits),
            "defined_states"            : json.dumps(list(self.defined_states)),
            "in_state_bits"             : json.dumps(new_in_state_bits),
            "out_state_bits"            : json.dumps(new_out_state_bits),
            "field"                     : self.field_name,
        }

class SymbolGraph(BasicGraphWithSelfCircle):
    def __init__(self, method_id):
        super().__init__()
        self.method_id = method_id
        self.graph = nx.DiGraph()

    def add_edge(self, src_node, dst_node, weight = None):
        if util.is_empty(src_node) or util.is_empty(dst_node):
            return
        
        self._add_one_edge(src_node, dst_node, weight)

class StateGraph(SymbolGraph):
    pass

class StateFlowGraph(SymbolGraph):
    def add_edge(self, src_node, dst_node, weight = None):
        if util.is_empty(dst_node):
            return
        
        if isinstance(src_node, list):
            for node in src_node:
                if util.is_empty(node):
                    continue
                self._add_one_edge(node, dst_node, weight)

        else:
            if util.is_empty(src_node):
                return
        
            self._add_one_edge(src_node, dst_node, weight)

@dataclasses.dataclass
class SFGNode:
    """
    node_type: the type of sfg node (symbol or state)
    def_stmt_id: which stmt defines current node
    index: the indexing position of current node in symbol state space
    node_id: symbol or state ID
    context_id: the context ID of current node, i.e., 1-call ID, the ID of call_stmt that calls current method (being tested)
    name: the name of symbol node
    value: the value of state node
    """

    # @profile
    def __init__(self, node_type=-1, def_stmt_id=-1, method_id=-1, index=-1, node_id=-1, context=None, stmt=None, name="ep", access_path=[]):
        # Node type
        self.node_type = node_type
        # The stmt_id where this node is defined
        self.def_stmt_id = def_stmt_id
        # Index of this node in the symbol state space
        self.index = index
        # Specific ID of this node, typically symbol_id or state_id (determined by node_type)
        self.node_id = node_id
        self.name = name
        # context info: here we use 1-call, indicating which call_stmt calls current method (being tested)
        # Hence it is call_site
        self.context_id = -1
        if isinstance(context, int):
            self.context_id = context
        elif isinstance(context, CallSite):
            self.context_id = context.call_stmt_id
        #self.method_name=None
        #self.module_name=None
        self.line_no = -1
        self.access_path = access_path
        # if access_path:
        #     self.access_path = util.access_path_formatter(access_path)
        self.operation = ""
        self.stmt = None

        if stmt is not None:
            self.stmt = stmt
            self.line_no = stmt.start_row
            if len(name) == 0:
                self.name = stmt.operation

            # if config.COMPLETE_SFG_DUMP_FLAG:
            self.operation = readable_gir.get_gir_str(stmt)

    def __hash__(self) -> int:
        return hash((self.node_type, self.def_stmt_id, self.index, self.node_id, self.context_id))

    def __eq__(self, other) -> bool:
        return (
            isinstance(other, SFGNode)
            and self.node_type == other.node_type
            and self.def_stmt_id == other.def_stmt_id
            and self.index == other.index
            and self.node_id == other.node_id
            and self.context_id == other.context_id
        )

    def to_dict(self):
        if self.node_type == SFG_NODE_KIND.STMT:
            return {
                "node_type"             : self.node_type,
                "stmt_id"               : self.def_stmt_id,
                "context"            : self.context_id,
            }

        return {
            "node_type"             : self.node_type,
            "stmt_id"               : self.def_stmt_id,
            "index"                 : self.index,
            "internal_id"           : self.node_id,
            "context"            : self.context_id,
        }

    def copy(self):
        return SFGNode(
            node_type = self.node_type,
            def_stmt_id = self.def_stmt_id,
            index = self.index,
            node_id = self.node_id,
            context = self.context_id,
        )

    def to_tuple(self):
        return (
            self.node_type,
            self.def_stmt_id,
            self.index,
            self.node_id,
            self.context_id,
            self.name,
            self.stmt,
            self.line_no,
            self.operation,
            self.access_path
        )

    def from_tuple(self, tup):
        self.node_type, self.def_stmt_id, self.index, self.node_id, self.context_id, self.name, self.stmt, self.line_no, self.operation, self.access_path= tup
        return self

@dataclasses.dataclass
class SFGEdge:
    """
    edge_type: the type of sfg edge (SYMBOL_FLOW, STATE COPY, STATE INCLUSION etc.)
    stmt_id: where this edge is defined
    round: the round number the edge is defined
    name: the edge name; it is usually used in field operations for indicating the field name
    """
    # Edge type
    edge_type: int = -1
    # Location where this edge is defined
    stmt_id: int = -1
    # The round in which this edge is defined
    round: int = -1
    # The phase that generated this edge
    #phase: int = -1
    # Position of this node among its siblings, e.g., index in the parameter list
    pos: int = -1
    # Name of the edge during connection
    name: str = ""

    def __hash__(self) -> int:
        return hash((self.edge_type, self.stmt_id, self.round, self.pos, self.name))

    def __eq__(self, other) -> bool:
        return isinstance(other, SFGEdge) and self.edge_type == other.edge_type and self.stmt_id == other.stmt_id and self.round == other.round and self.pos == other.pos and self.name == other.name

    def copy(self):
        return SFGEdge(
            edge_type = self.edge_type,
            stmt_id = self.stmt_id,
            round = self.round,
            #phase = self.phase,
            name = self.name,
        )

    def to_dict_with_prefix(self, prefix):
        return {
            f"{prefix}_edge_type"                       : self.edge_type,
            f"{prefix}_stmt_id"                         : self.stmt_id,
            f"{prefix}_round"                           : self.round,
            #f"{prefix}_phase"                          : self.phase,
            f"{prefix}_name"                            : self.name,
        }

    def to_dict(self):
        return {
            "edge_type"                                 : self.edge_type,
            "stmt_id"                                   : self.stmt_id,
            "round"                                     : self.round,
            #"phase"                                    : self.phase,
            "name"                                      : self.name,
        }

    def to_tuple(self):
        return (
            self.edge_type,
            self.stmt_id,
            self.round,
            self.pos,
            self.name,
        )

    def from_tuple(self, tup):
        self.edge_type, self.stmt_id, self.round, self.pos, self.name = tup
        return self

@dataclasses.dataclass
class SourceSymbolScopeInfo:
    source_unit_id:int = -1
    source_symbol_id:int = -1 # Also functions as source_decl_stmt_id
    decl_scope_id: int = -1
    current_symbol_id: int = -1

    def __post_init__(self):
        # After instantiation, defaults to source_symbol_id if current_symbol_id is not explicitly assigned
        if self.current_symbol_id == -1:
            self.current_symbol_id = self.source_symbol_id

class MethodCall:
    def __init__(self, unit_id, stmt_id, name, method_state = None):
        self.unit_id = unit_id
        self.stmt_id = stmt_id
        self.name = name
        self.method_state = method_state

# global_bit_vector_id = 0



@dataclasses.dataclass
class LastSymbolDefNode:
    index: int = -1
    symbol_id: int = -1
    last_stmt_id: int= -1

    def __hash__(self) -> int:
        return hash((self.index, self.symbol_id, self.last_stmt_id))

    def __eq__(self, other: object) -> bool:
        return isinstance(other, SymbolDefNode) and self.index == other.index and self.symbol_id == other.symbol_id and self.last_stmt_id == other.last_stmt_id


# class BitVector:
#

class BitVectorManager:
    def __init__(self):
        self.bit_vector_id = 0
        self.counter = 1
        self.id_to_bit_pos = {}
        self.bit_pos_to_id = {}

    def init(self, id_list: set):
        for bit_id in id_list:
            self.add_bit_id(bit_id)

    def to_dict(self, method_id):
        results = []
        for bit_pos, bit_id in self.bit_pos_to_id.items():
            if isinstance(bit_id, (int, numpy.int64)):
                results.append({
                    "method_id": method_id,
                    "bit_pos": bit_pos,
                    "stmt_id": bit_id,
                })
            elif isinstance(bit_id, (SymbolDefNode, StateDefNode)):
                results.append(bit_id.to_dict(method_id, bit_pos))
        return results

    def add_bit_id(self, bit_id):
        if not isinstance(bit_id, (SymbolDefNode, StateDefNode)):
            raise ValueError(f"bit_id {bit_id} is not a SymbolDefNode or StateDefNode")
        if bit_id in self.id_to_bit_pos:
            return
        self.id_to_bit_pos[bit_id] = self.counter
        self.bit_pos_to_id[self.counter] = bit_id
        self.counter += 1

    def find_bit_pos_by_id(self, bit_id):
        return self.id_to_bit_pos.get(bit_id, -1)

    # find all 1s -> bit_id
    def explain(self, bit_vector):
        return bit_vector

    def kill_bit_ids(self, bit_vector, id_list):

        for bit_id in id_list:
            if not isinstance(bit_id, (SymbolDefNode, StateDefNode)):
                raise ValueError(f"bit_id {bit_id} is not a SymbolDefNode or StateDefNode")
            
            if bit_id in bit_vector:
                bit_vector.discard(bit_id)
        return bit_vector

    def gen_bit_ids(self, bit_vector, id_list):
        for bit_id in id_list:

            if not isinstance(bit_id, (SymbolDefNode, StateDefNode)):
                raise ValueError(f"bit_id {bit_id} is not a SymbolDefNode or StateDefNode")
            
            bit_vector.add(bit_id)
        return bit_vector

    def is_bit_id_available(self, bit_vector, bit_id):
        bit_pos = self.id_to_bit_pos.get(bit_id)
        if bit_pos is not None:
            if (bit_vector & (1 << bit_pos)) != 0:
                return True
        return False



    def copy(self):
        bit_vector_manager = BitVectorManager()
        bit_vector_manager.bit_vector_id = self.bit_vector_id
        bit_vector_manager.counter = self.counter
        bit_vector_manager.id_to_bit_pos = self.id_to_bit_pos.copy()
        bit_vector_manager.bit_pos_to_id = self.bit_pos_to_id.copy()
        return bit_vector_manager


@dataclasses.dataclass
class SimplyGroupedMethodTypes:
    no_callees: set
    only_direct_callees: set
    mixed_direct_callees: set
    only_dynamic_callees: set
    containing_dynamic_callees: set
    containing_error_callees: set

    def to_dict(self):
        return {
            "no_callees": list(self.no_callees),
            "only_direct_callees": list(self.only_direct_callees),
            "mixed_direct_callees": list(self.mixed_direct_callees),
            "only_dynamic_callees": list(self.only_dynamic_callees),
            "containing_dynamic_callees": list(self.containing_dynamic_callees),
            "containing_error_callees": list(self.containing_error_callees)
        }

    def __repr__(self) -> str:
        return f"no_callees: {self.no_callees}\n" \
            f"only_direct_callees: {self.only_direct_callees}\n" \
            f"mixed_direct_callees: {self.mixed_direct_callees}\n" \
            f"only_dynamic_callees: {self.only_dynamic_callees}\n" \
            f"containing_dynamic_callees: {self.containing_dynamic_callees}\n" \
            f"containing_error_callees: {self.containing_error_callees}"

    def get_methods_with_direct_call(self):
        return [
            *self.no_callees,
            *self.only_direct_callees,
            # *self.mixed_direct_callees,
            # *self.only_dynamic_callees,
            # *self.containing_error_callees
        ]

    def get_methods_with_dynamic_call(self):
        return [
            *self.mixed_direct_callees,
            *self.only_dynamic_callees,
            *self.containing_error_callees
        ]

@dataclasses.dataclass
class MethodDefUseSummary:
    method_id: int = -1
    parameter_symbol_ids: set[tuple] = dataclasses.field(default_factory=set)
    local_symbol_ids: set[int] = dataclasses.field(default_factory=set)
    defined_external_symbol_ids: set[int] = dataclasses.field(default_factory=set)
    used_external_symbol_ids: set[int] = dataclasses.field(default_factory=set)
    return_symbol_ids: set[int] = dataclasses.field(default_factory=set)
    this_symbol_id : int = -1

    def to_dict(self):
        return {
            "method_id": self.method_id,
            "parameter_symbol_ids": self.parameter_symbol_ids,
            "local_symbol_ids": self.local_symbol_ids,
            "defined_external_symbol_ids": self.defined_external_symbol_ids,
            "used_external_symbol_ids": self.used_external_symbol_ids,
            "return_symbol_ids": self.return_symbol_ids,
            "this_symbol_id":self.this_symbol_id,
        }

    def __str__(self):
        return  f"method_id={self.method_id}, " \
                f"parameter_symbol_ids={self.parameter_symbol_ids}, " \
                f"local_symbol_ids={self.local_symbol_ids}, " \
                f"defined_external_symbol_ids={self.defined_external_symbol_ids}, " \
                f"used_external_symbol_ids={self.used_external_symbol_ids}, " \
                f"return_symbol_ids={self.return_symbol_ids}, "\
                f"this_symbol_id={self.this_symbol_id}"


    def copy(self):
        return MethodDefUseSummary(
            method_id = self.method_id,
            parameter_symbol_ids = self.parameter_symbol_ids.copy(),
            local_symbol_ids = self.local_symbol_ids.copy(),
            defined_external_symbol_ids = self.defined_external_symbol_ids.copy(),
            used_external_symbol_ids = self.used_external_symbol_ids.copy(),
            return_symbol_ids = self.return_symbol_ids.copy(),
            this_symbol_id = self.this_symbol_id
        )

@dataclasses.dataclass
class MethodSummaryTemplate:
    key: int = -1
    parameter_symbols: dict[int, set[int]] = dataclasses.field(default_factory=dict)
    defined_external_symbols: dict[int, set[int]] = dataclasses.field(default_factory=dict)
    used_external_symbols: dict[int, set[int]] = dataclasses.field(default_factory=dict)
    return_symbols: dict[int, set[int]] = dataclasses.field(default_factory=dict)
    key_dynamic_content: dict[int, set[int]] = dataclasses.field(default_factory=dict)
    dynamic_call_stmts: set[int] = dataclasses.field(default_factory=set)
    this_symbols : dict[int, set[int]] = dataclasses.field(default_factory=dict)
    external_symbol_to_state : dict[int, int] = dataclasses.field(default_factory=dict)
    raw_to_new_index: dict[int, int] = dataclasses.field(default_factory=dict) # Mapping from the original index in the full space to the new index in the compact space
    index_to_default_value: dict[int, int] = dataclasses.field(default_factory=dict) # index -> default_value_symbol_id  mapping

    def copy(self):
        summary = MethodSummaryTemplate(
            key = self.key,
            parameter_symbols = copy.deepcopy(self.parameter_symbols),
            defined_external_symbols = copy.deepcopy(self.defined_external_symbols),
            used_external_symbols = copy.deepcopy(self.used_external_symbols),
            return_symbols = copy.deepcopy(self.return_symbols),
            key_dynamic_content = copy.deepcopy(self.key_dynamic_content),
            dynamic_call_stmts = self.dynamic_call_stmts.copy(),
            this_symbols = copy.deepcopy(self.this_symbols),
            external_symbol_to_state = self.external_symbol_to_state.copy(),
            raw_to_new_index = self.raw_to_new_index.copy(),
            index_to_default_value = self.index_to_default_value.copy()
        )
        return summary

    def convert_parameter_dict_to_list(self, d: dict):
        if len(d) == 0:
            return []

        results = []
        for key in sorted(d.keys()):
            index_set = d[key]
            for index in index_set:
                new_index = self.raw_to_new_index.get(index, index)
                default_value_symbol_id = self.index_to_default_value.get(index, -1)

                if default_value_symbol_id != -1:
                    results.append((key, index, new_index, default_value_symbol_id))
                else:
                    results.append((key, index, new_index))
        return results

    def convert_dict_to_list(self, d: dict):
        if len(d) == 0:
            return []

        results = []
        for key in sorted(d.keys()):
            if isinstance(d[key], (int, numpy.int64)):
                results.append((key, d[key]))
                continue
            index_set = d[key]
            for index in index_set:
                new_index = self.raw_to_new_index.get(index, index)
                results.append((key, index, new_index))
        return results

    def to_dict(self):
        return {
            "method_id": self.key,
            "parameter_symbols": self.convert_parameter_dict_to_list(self.parameter_symbols),
            "defined_external_symbols": self.convert_dict_to_list(self.defined_external_symbols),
            "used_external_symbols": self.convert_dict_to_list(self.used_external_symbols),
            "return_symbols": self.convert_dict_to_list(self.return_symbols),
            "key_dynamic_content": self.convert_dict_to_list(self.key_dynamic_content),
            "dynamic_call_stmts": self.dynamic_call_stmts,
            "this_symbols": self.convert_dict_to_list(self.this_symbols),
            "external_symbol_to_state":self.convert_dict_to_list(self.external_symbol_to_state)
        }

    def __str__(self):
        return  f"method_id={self.key}, " \
                f"parameter_symbols={self.parameter_symbols}, " \
                f"defined_external_symbols={self.defined_external_symbols}, " \
                f"key_dynamic_content={self.key_dynamic_content}, " \
                f"used_external_symbols={self.used_external_symbols}, " \
                f"return_symbols={self.return_symbols}, "\
                f"dynamic_call_stmts={self.dynamic_call_stmts}, " \
                f"this_symbols={self.this_symbols}, "\
                f"external_symbol_to_state={self.external_symbol_to_state}"

    def get_important_symbol_records(self):
        return [self.parameter_symbols, self.defined_external_symbols, self.used_external_symbols, self.return_symbols, self.key_dynamic_content, self.this_symbols]

    def adjust_ids(self, old_index_to_new_index):
        for content_record in self.get_important_symbol_records():
            for symbol_id in content_record:
                new_index_set = set()
                old_index_set = content_record[symbol_id].copy()
                for raw_index in old_index_set:
                    new_index = util.map_index_to_new_index(
                        raw_index, old_index_to_new_index
                    )
                    self.raw_to_new_index[raw_index] = new_index
                    new_index_set.add(new_index)
                    if raw_index in self.index_to_default_value:
                        default_value_symbol_id = self.index_to_default_value[raw_index]
                        self.index_to_default_value[new_index] = default_value_symbol_id

                content_record[symbol_id] = new_index_set

@dataclasses.dataclass
class DeferedIndexUpdate:
    state_index : int
    state_symbol_id : int
    stmt_id : int
    arg_state_indexes: set[int] = dataclasses.field(default_factory=set)
    access_path:list[AccessPoint] = dataclasses.field(default_factory=list)
    set_to_update: set[int] = dataclasses.field(default_factory=set)


    def __eq__(self, other):
        if not isinstance(other, DeferedIndexUpdate):
            return False
        return (
            self.state_index == other.state_index and
            self.access_path == other.access_path and
            self.state_symbol_id == other.state_symbol_id and
            self.stmt_id == other.stmt_id and
            self.arg_state_indexes == other.arg_state_indexes
        )

    def __hash__(self):
        return hash((self.state_index, self.state_symbol_id, self.stmt_id))

import dataclasses
@dataclasses.dataclass
class MethodSummaryInstance(MethodSummaryTemplate):
    def __post_init__(self):
        self.call_site = self.key
        self.caller_id = self.call_site.caller_id
        self.call_stmt_id = self.call_site.call_stmt_id
        self.method_id = self.call_site.callee_id

    def copy_template_to_instance(self, summary_template: MethodSummaryTemplate):
        self.key = summary_template.key
        # self.parameter_symbols = summary_template.parameter_symbols
        # self.defined_external_symbols = summary_template.defined_external_symbols
        self.used_external_symbols = summary_template.used_external_symbols
        # self.return_symbols = summary_template.return_symbols
        self.key_dynamic_content = summary_template.key_dynamic_content
        self.dynamic_call_stmts = summary_template.dynamic_call_stmts
        self.resolver_result = {}
        # self.this_symbols = summary_template.this_symbols

    def copy(self):
        summary = MethodSummaryInstance(
            self.call_site,
            copy.deepcopy(self.parameter_symbols),
            copy.deepcopy(self.defined_external_symbols),
            copy.deepcopy(self.used_external_symbols),
            copy.deepcopy(self.return_symbols),
            copy.deepcopy(self.key_dynamic_content),
            self.dynamic_call_stmts.copy(),
            copy.deepcopy(self.this_symbols)
        )
        return summary

    def to_dict(self):
        return {
            "caller_id": self.caller_id,
            "call_stmt_id": self.call_stmt_id,
            "method_id": self.method_id,
            "parameter_symbols": self.convert_parameter_dict_to_list(self.parameter_symbols),
            "defined_external_symbols": self.convert_dict_to_list(self.defined_external_symbols),
            "used_external_symbols": self.convert_dict_to_list(self.used_external_symbols),
            "return_symbols": self.convert_dict_to_list(self.return_symbols),
            "key_dynamic_content": self.convert_dict_to_list(self.key_dynamic_content),
            "dynamic_call_stmts": self.dynamic_call_stmts,
            "this_symbols": self.convert_dict_to_list(self.this_symbols),
            "external_symbol_to_state":self.convert_dict_to_list(self.external_symbol_to_state)
        }

@dataclasses.dataclass
class MethodInternalCallee:
    method_id: int = -1
    callee_type: int = CALLEE_TYPE.DIRECT_CALLEE
    stmt_id: int = -1
    callee_symbol_id: int = -1
    callee_symbol_index: int = -1

    def to_dict(self):
        return {
            "method_id": self.method_id,
            "callee_type": self.callee_type,
            "stmt_id": self.stmt_id,
            "callee_symbol_id": self.callee_symbol_id,
            "callee_symbol_index": self.callee_symbol_index
        }

    def __hash__(self):
        return hash((self.callee_type, self.stmt_id, self.callee_symbol_id, self.callee_symbol_index))

    def __eq__(self, other):
        if not isinstance(other, MethodInternalCallee):
            return False

        return (self.callee_type == other.callee_type) \
            and (self.stmt_id == other.stmt_id) \
            and (self.callee_symbol_id == other.callee_symbol_id) \
            and (self.callee_symbol_index == other.callee_symbol_index)

class BasicCallGraph(BasicGraph):
    pass

class CallGraph(BasicGraph):
    def add_edge(self, caller_id, callee_id, call_stmt_id = None):
        if not self.graph.has_edge(caller_id, callee_id):
            super().add_edge(caller_id, callee_id, weight=call_stmt_id)
        else:
            has_weight = False
            for w in self.graph[caller_id][callee_id].values():
                if w.get('weight') == call_stmt_id:
                    has_weight = True
            if not has_weight:
                super().add_edge(caller_id, callee_id, weight=call_stmt_id)

    def has_specific_weight(self, caller_id, callee_id, call_stmt_id):
        if self.graph.has_edge(caller_id, callee_id):
            edge_data = self.graph[caller_id][callee_id]
            return call_stmt_id in edge_data
        return False

    def find_paths(self, start_node):
        all_paths = []

        def dfs(current_node, current_path: list, visited: set):
            current_path.append(current_node)
            visited.add(current_node)

            for succ in self.graph.successors(current_node):
                if succ not in visited:
                    edge_weight = self.graph.get_edge_data(current_node, succ)['weight']
                    for w in edge_weight:
                        dfs(succ, current_path + [w], visited)

            if not list(self.graph.successors(current_node)):
                all_paths.append(tuple(current_path.copy()))

            elif len(current_path) > 1:
                all_paths.append(tuple(current_path.copy()))

            current_path.pop()
            visited.remove(current_node)

        dfs(start_node, [], set())

        return all_paths

    def _add_one_edge(self, src_stmt_id, dst_stmt_id, weight):
        if isinstance(src_stmt_id, (int, numpy.int64)) and src_stmt_id < 0:
            return

        self.graph.add_edge(src_stmt_id, dst_stmt_id, weight = weight)

    def export(self):
        pass

@dataclasses.dataclass
class CGNode:
    def __init__(self, method_id):
        self.method_id = method_id

@dataclasses.dataclass
class UnitSymbolDeclSummary:
    unit_id: int = -1
     # <variable_name: set<scope_id>>
    symbol_name_to_scope_ids: dict[str, set] = dataclasses.field(default_factory=dict)
    # <scope_id: <variable_name, stmt_id>>
    scope_id_to_symbol_info: dict[int, dict[str, int]] = dataclasses.field(default_factory=dict)
    # <scope_id: set<scope_id>>
    scope_id_to_available_scope_ids: dict[int, set[int]] = dataclasses.field(default_factory=dict)

    def __repr__(self):
        return  f"UnitSymbolDeclSummary(\n" \
                f"symbol_name_to_scope_ids:{str(self.symbol_name_to_scope_ids)}\n" \
                f"scope_id_to_symbol_info:{str(self.scope_id_to_symbol_info)}\n" \
                f"scope_id_to_available_scope_ids:{str(self.scope_id_to_available_scope_ids)})"

@dataclasses.dataclass
class SummaryData:
    summary: object = None
    s2space: object = None

@dataclasses.dataclass
class MetaComputeFrame:
    unit_id: int = 0
    method_id: int = 0
    # K/V: <key> / <SummaryData: summary + corresponding_s2space>
    # <key> formats:
    #       - call_stmt:    stmt_id, callee_id
    #       - other stmts:  stmt_id

    # K/V: <key> / {true, false}
    content_already_analyzed: dict = dataclasses.field(default_factory=dict)

    is_meta_frame:bool = True

class ComputeFrame(MetaComputeFrame):
    def __init__(self, method_id, caller_id = -1, call_stmt_id = -1, loader = None, space = None, params_list = None, classes_of_method = [], this_class_ids = [], state_flow_graph = None, call_site_analyze_counter=None):
        super().__init__(method_id)
        if this_class_ids is None:
            this_class_ids = []
        self.is_meta_frame = False
        self.has_been_inited = False
        self.method_id = method_id
        self.caller_id = caller_id
        self.call_stmt_id = call_stmt_id
        self.call_site = CallSite(self.caller_id, self.call_stmt_id, self.method_id)

        self.loader = loader
        self.lang = "unknown"
        if self.loader:
            self.unit_id = self.loader.convert_method_id_to_unit_id(method_id)
            self.lang = self.loader.convert_unit_id_to_lang_name(self.unit_id)
            self.method_name = self.loader.convert_method_id_to_method_name(self.method_id)

        self.method_decl_stmt = None
        self.frame_stack = None

        self.stmt_def_use_analysis = None
        self.stmt_state_analysis = None

        self.interruption_flag = False
        self.interruption_data: InterruptionData = None

        self.stmt_worklist = None
        self.stmts_with_symbol_update = SimpleSet()
        self.unit_gir: GIRBlockViewer = GIRBlockViewer()
        self.stmt_id_to_status: dict[int, StmtStatus] = {}
        if space is None:
            self.symbol_state_space = SymbolStateSpace()
        else:
            self.symbol_state_space: SymbolStateSpace = space
        self.space_summary: SymbolStateSpace = SymbolStateSpace()
        self.all_symbol_defs = set()
        self.all_state_defs = set()
        self.defined_symbols = {}
        self.defined_states = {}
        self.used_symbols = {}
        self.method_def_use_summary: MethodDefUseSummary = MethodDefUseSummary(self.method_id)
        self.stmt_id_to_callee_info = {}

        self.stmt_counters = {}
        self.is_first_round = {}
        self.loop_total_rounds = {}
        self.symbol_bit_vector_manager: BitVectorManager = BitVectorManager()
        self.state_bit_vector_manager: BitVectorManager = BitVectorManager()
        self.symbol_graph = SymbolGraph(self.method_id)
        self.state_flow_graph: StateFlowGraph = state_flow_graph
        if self.state_flow_graph is None:
            self.state_flow_graph = StateFlowGraph(self.method_id)
        self.method_summary_template: MethodSummaryTemplate = MethodSummaryTemplate(self.method_id)
        self.method_summary_instance: MethodSummaryInstance = MethodSummaryInstance(self.call_site)

        self.positional_args = None
        self.named_args = None
        self.callee_list = []
        self.basic_callees = set()
        self.content_already_analyzed = {}
        self.key_dynamic_content = {}
        self.all_local_symbol_ids = set()
        self.used_external_symbol_id_to_state_id_set = {}
        self.initial_state_to_external_symbol = {}
        self.external_symbol_id_to_initial_state_index = {}
        self.call_path: CallPath = CallPath()

        self.args_list = None
        self.params_list = params_list
        self.callee_param = None
        self.classes_of_method = classes_of_method
        self.callee_classes_of_method = []
        self.this_class_ids = this_class_ids
        self.callee_this_class_ids = []
        self.call_site_analyze_counter = call_site_analyze_counter

    def get_context(self):
        return self.call_site

    def hash_context(self):
        return hash(self.call_site)

class ComputeFrameStack:
    def __init__(self):
        self._stack = []
        self.method_ids = set()

    def push(self, element: ComputeFrame):
        return self.add(element)

    def add(self, element: ComputeFrame):
        self._stack.append(element)
        self.method_ids.add(element.method_id)
        return self

    def _update_method_ids(self):
        self.method_ids = set()
        for frame in self._stack:
            self.method_ids.add(frame.method_id)

    def pop(self) -> ComputeFrame:
        if len(self._stack) <= 0:
            return None
        element = self._stack.pop()
        self._update_method_ids()
        return element

    def peek(self) -> ComputeFrame:
        if len(self._stack) <= 0:
            return None
        return self._stack[-1]

    def __len__(self):
        return len(self._stack)

    def has_method_id(self, method_id):
        return method_id in self.method_ids

    def __getitem__(self, index):
        if  index < len(self._stack):
            return self._stack[index]
        return None

    def __iter__(self):
        for row in self._stack:
            yield row

@dataclasses.dataclass
class InterruptionData:
    caller_id: int = -1
    call_stmt_id: int = -1
    callee_ids: list = dataclasses.field(default_factory=list)
    args_list: list = dataclasses.field(default_factory=list)
    classes_of_method: list = dataclasses.field(default_factory=list)
    this_class_ids: list = dataclasses.field(default_factory=list)

@dataclasses.dataclass
class P2ResultFlag:
    state_changed: bool = False
    symbol_def_changed: bool = False
    symbol_use_changed: bool = False
    interruption_flag: bool = False
    interruption_data: InterruptionData = None
    condition_path_flag: int = CONDITION_FLAG.NO_PATH

@dataclasses.dataclass
class MethodCallArguments:
    positional_args: list = dataclasses.field(default_factory=list)
    named_args: dict = dataclasses.field(default_factory=dict)

@dataclasses.dataclass
class MethodDeclParameters:
    positional_parameters: list = dataclasses.field(default_factory=list)
    keyword_parameters: list = dataclasses.field(default_factory=list)
    packed_positional_parameter: object = None
    packed_named_parameter: object = None
    all_parameters: set = dataclasses.field(default_factory=set)

@dataclasses.dataclass
class Argument:
    state_id: int = -1
    call_stmt_id: int = -1
    position: int = -1
    name: str = ""
    source_symbol_id: int = -1,
    access_path: list[AccessPoint] = dataclasses.field(default_factory=list)
    states: set[int] = dataclasses.field(default_factory=set)
    index_in_space: int = -1

    def __hash__(self):
        return hash((self.position, self.name, self.index_in_space))

@dataclasses.dataclass
class Parameter:
    method_id: int = -1
    position: int = -1
    name: str = ""
    # default_value:
    symbol_id: int = -1
    packed_content: list = dataclasses.field(default_factory=list)

    def __hash__(self) -> int:
        return hash((self.method_id, self.position, self.name, self.symbol_id))

class CallSite:
    def __init__(self, caller_id, call_stmt_id, callee_id):
        self.caller_id = caller_id
        self.call_stmt_id = call_stmt_id
        self.callee_id = callee_id

    def __eq__(self, other):
        if not isinstance(other, CallSite):
            return False
        return (self.caller_id == other.caller_id and
                self.call_stmt_id == other.call_stmt_id and
                self.callee_id == other.callee_id)

    def __lt__(self, other):
        if not isinstance(other, CallSite):
            return NotImplemented
        return (self.caller_id, self.call_stmt_id) < (other.caller_id, other.call_stmt_id)

    def __hash__(self):
        return hash((self.caller_id, self.call_stmt_id, self.callee_id))

    def __repr__(self):
        return f"CallSite({self.caller_id}, {self.call_stmt_id}, {self.callee_id})"

    def to_tuple(self):
        """Convert the core attributes of the CallSite object to a tuple"""
        return (self.caller_id, self.call_stmt_id, self.callee_id)

    def has_negative(self):
        return self.caller_id < 0 or self.call_stmt_id < 0 or self.callee_id < 0

    def is_entry_point(self):
        return self.caller_id > 0 and self.call_stmt_id == 0 and self.callee_id == 0

    def hash(self):
        return self.__hash__()

@dataclasses.dataclass(frozen=True)  # frozen=True Make it immutable
class CallPath:
    path: tuple = dataclasses.field(default_factory=tuple)

    def __len__(self):
        return len(self.path)

    def get_length(self):
        return len(self.path)

    def __iter__(self):
        for item in self.path:
            yield item

    def __contains__(self, item):
        return item in self.path

    def __getitem__(self, index):
        return self.path[index]

    # Remove __hash__ and __eq__ as they are auto-generated by dataclass

    def to_tuple(self):
        return self.path  # Already a tuple

    def has_any_negative(self):
        for item in self.path:
            if item and item.has_negative():
                return True
        return False

    def add_call(self, caller_id, call_stmt_id, callee_id):
        return self.add_callsite(CallSite(caller_id, call_stmt_id, callee_id))

    def add_callsite(self, callsite: CallSite):
        # Return a new object instead of modifying the existing one
        return CallPath(self.path + (callsite,))

    def count_cycles(self):
        visited = set()
        cycle_count = 0

        for callsite in self.path:
            caller_id = callsite.caller_id
            callee_id = callsite.callee_id

            if callee_id in visited:
                cycle_count += 1

            visited.add(caller_id)
            visited.add(callee_id)

        return cycle_count

class TrieNode:
    def __init__(self):
        self.children = {}
        self.is_terminal = False
        self.path = None

class PathTrie:
    def __init__(self):
        self.root = TrieNode()
        self.paths = set()

    def add_path(self, path):
        """
        添加路径的规则（长路径优先，但不同分支可共存）：
        1. 如果新路径与已存在路径完全一致 -> 拒绝
        2. 如果新路径是已存在某条路径的严格前缀 -> 拒绝
        3. 如果某条已存在路径是新路径的严格前缀 -> 删除旧路径，添加新路径
        4. 如果新路径与已存在路径只是部分重叠（不同分支）-> 都保留
        """

        # Step 1: Traverse the new path to check for conflicts with existing paths
        node = self.root
        for i, elem in enumerate(path.path):
            if elem not in node.children:
                # The new path diverges here; no conflicts, so it can be added
                break
            node = node.children[elem]

            # Check if the current node is a terminating node
            if node.is_terminal:
                # A prefix path exists
                if i + 1 == len(path.path):
                    # The new path is identical to an existing path
                    return False
                else:
                    # The new path is longer, and the existing path is its prefix
                    # Remove the prefix path and continue adding the new path
                    pass  # Processed later
        else:
            # Completed traversal of all elements in the new path
            # Check if the current node is a terminating node
            if node.is_terminal:
                # Path already exists
                return False

            # Check if the current node has child nodes (i.e., a longer path exists)
            if node.children:
                # A longer path with the new path as a prefix exists; reject the new path
                return False

        # Step 2: Find and remove existing paths that are strict prefixes of the new path
        paths_to_remove = []
        node = self.root
        for i, elem in enumerate(path.path):
            if elem not in node.children:
                break
            node = node.children[elem]

            if node.is_terminal and i + 1 < len(path.path):
                # Found a strict prefix path
                paths_to_remove.append(node.path)

        # Remove the prefix path
        for p in paths_to_remove:
            self.paths.discard(p)
            self._mark_non_terminal(p)

        # Step 3: Insert the new path
        node = self.root
        for elem in path.path:
            if elem not in node.children:
                node.children[elem] = TrieNode()
            node = node.children[elem]

        node.is_terminal = True
        node.path = path
        self.paths.add(path)
        return True

    def _mark_non_terminal(self, path):
        """
        将路径标记为非终端
        """
        node = self.root
        for elem in path.path:
            if elem not in node.children:
                return
            node = node.children[elem]

        node.is_terminal = False
        node.path = None

    def path_exists(self, path):
        return path in self.paths

    def remove_path(self, path):
        if path not in self.paths:
            return False
        self.paths.discard(path)
        self._mark_non_terminal(path)
        return True

class PathManager:
    def __init__(self):
        self.trie = PathTrie()  # Added
        self.paths = set()      # Public view

    def add_path(self, new_path: CallPath):
        # Retain type checking and business logic
        if not isinstance(new_path, CallPath):
            util.error("@PathManager: Invalid path type", str(new_path))
            return False

        if new_path.has_any_negative():
            return False

        if new_path in self.paths:
            return False

        # Use Trie for prefix matching
        ok = self.trie.add_path(new_path)
        if ok:
            # Internal Trie paths updated
            self.paths = set(self.trie.paths)   # Retrieve the set of terminal paths
        return ok

    def remove_path(self, removed_path):
        ok = self.trie.remove_path(removed_path)
        if ok:
            self.paths = set(self.trie.paths)
        return ok

    def path_exists(self, path):
        return self.trie.path_exists(path)

class SymbolNodeInImportGraph:
    def __init__(self, scope_id, symbol_type, symbol_id, symbol_name, unit_id=-1):
        self.scope_id:int = scope_id
        self.symbol_type:int = symbol_type
        self.symbol_id:int = symbol_id
        self.symbol_name:str = symbol_name
        self.unit_id:int = unit_id

    def clone(self):
        node = SymbolNodeInImportGraph(
            self.scope_id,
            self.symbol_type,
            self.symbol_id,
            self.symbol_name,
            self.unit_id
        )
        return node

    def __eq__(self, value):
        if isinstance(value, SymbolNodeInImportGraph):
            return (
                self.scope_id == value.scope_id and
                self.symbol_type == value.symbol_type and
                self.symbol_id == value.symbol_id and
                self.symbol_name == value.symbol_name and
                self.unit_id == value.unit_id
            )
        return False

    def __hash__(self):
        return hash((
            self.scope_id, self.symbol_type, self.symbol_id,
            self.symbol_name, self.unit_id
        ))
        #return hash((self.scope_id, self.symbol_type, self.symbol_id, self.symbol_name))

    def to_dict(self):
        result = {
            "scope_id": self.scope_id,
            "symbol_type": self.symbol_type,
            "symbol_id": self.symbol_id,
            "symbol_name": self.symbol_name,
        }
        if self.unit_id > 0:
            result["unit_id"] = self.unit_id

        return result

    def to_tuple(self):
        return (
            self.scope_id, self.symbol_type, self.symbol_id,
            self.symbol_name, self.unit_id
        )

    def __repr__(self):
        return f"SymbolNode(scope_id={self.scope_id}, symbol_type={self.symbol_type}, symbol_id={self.symbol_id}, symbol_name={self.symbol_name}, unit_id={self.unit_id})"

@dataclasses.dataclass
class MethodInClass:
    unit_id: int = -1
    class_id: int = -1
    name: str = ""
    stmt_id: int = -1

    def to_dict(self):
        return {
            "unit_id": self.unit_id,
            "class_id": self.class_id,
            "name": self.name,
            "stmt_id": self.stmt_id
        }

    def __repr__(self) -> str:
        return f"MethodInClass(unit_id={self.unit_id}, class_id={self.class_id}, name={self.name}, stmt_id={self.stmt_id})"

    def __hash__(self) -> int:
        return hash((self.class_id, self.name, self.unit_id))

@dataclasses.dataclass
class TypeNode:
    name: str = ""
    class_stmt_id: int = -1
    unit_id: int = -1
    parent_name: str = ""
    parent_id: int = -1
    parent_index: int = -1

    def to_dict(self):
        return {
            "class_stmt_id": self.class_stmt_id,
            "unit_id": self.unit_id,
            "parent_name": self.parent_name,
            "parent_id": self.parent_id,
            "parent_index": self.parent_index,
            "name": self.name
        }

    def __repr__(self) -> str:
        return f"TypeNode(class_stmt_id={self.class_stmt_id}, unit_id={self.unit_id}, parent_name={self.parent_name}, parent_id={self.parent_id}, parent_index={self.parent_index}, name={self.name})"

@dataclasses.dataclass
class TypeGraphEdge:
    parent_name: str = ""
    name: str = ""
    parent_pos: int = -1

    def __hash__(self) -> int:
        return hash((self.parent_name, self.name, self.parent_pos))

    def __eq__(self, other) -> bool:
        if not isinstance(other, TypeGraphEdge):
            return False
        return self.parent_name and self.name == other.name and self.parent_pos == other.parent_pos

    def to_dict(self):
        return {
            "parent_name": self.parent_name,
            "name": self.name,
            "parent_pos": self.parent_pos
        }

class UnionFind:
    def __init__(self):
        self.parent = {}

    def find(self, x):
        if x not in self.parent:
            self.parent[x] = x

        # Path compression
        elif self.parent[x] != x:
            self.parent[x] = self.find(self.parent[x])

        return self.parent[x]

    def union(self, x, y):
        x_root = self.find(x)
        y_root = self.find(y)

        if x_root != y_root:
            self.parent[y_root] = x_root

    def get_sets(self):
        sets = {}
        for element in self.parent:
            root = self.find(element)
            if root in sets:
                sets[root].add(element)

            else:
                sets[root] = {element}

        return sets.values()

@dataclasses.dataclass
class CountStmtDefStateNode:
    """Inspect the number of new states created by different statement types (for debugging purposes)"""
    stmt_id : int
    stmt_operation : str = ""
    in_states : set[int] = dataclasses.field(default_factory=set)
    new_out_states_len : int = 0


    def add_new_states_count(self, len):
        self.new_out_states_len += len


    def print_as_beautiful_dict(self):
        ordered_fields = [
            'new_out_states_len',
            'stmt_id',
            'stmt_operation',
            'in_states'
        ]
        node_dict = dataclasses.asdict(self)
        print(f"{'='*20} Node {node_dict['stmt_id']} {'='*20}")
        for field in ordered_fields:
            value = node_dict[field]

            if field == 'in_states':
                print(f"{field:18} :")
                if isinstance(value, dict):
                    for key, val in value.items():
                        print(f"{'':20}{key:6} : {val}")
                else:
                    print(f"{'':20}{value}")
            else:
                print(f"{field:18} : {value}")

        print(f"{'='*50}")

    def print_as_dict(self):
        ordered_fields = [
            'new_out_states_len',
            'stmt_id',
            'stmt_operation',
            'in_states'
        ]
        node_dict = dataclasses.asdict(self)
        ordered_dict = {field: node_dict[field] for field in ordered_fields}
