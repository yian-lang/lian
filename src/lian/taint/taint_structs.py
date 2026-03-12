#!/usr/bin/env python3

import dataclasses
import lian.config.config as config
from lian.util import util
class MethodTaintFrame:
    def __init__(self, method_id, frame_stack, env):
        self.method_id = method_id
        self.frame_stack = frame_stack
        self.taint_env:TaintEnv = env
        self.propagation = None
        self.lian = None
        self.stmt_id_to_stmt = {}
        self.stmt_counters = {}
        self.path_manager = []
        self.taint_state_manager = None
        self.cfg = None
        self.stmt_worklist = None
        self.stmt_id_to_status = None
        self.stmt_id_to_taint_status = {}
        self.state_id_to_access_path = None
        self.symbol_state_space = None
        self.symbol_graph = None
        self.stmt_id_to_callees = None
        self.content_already_analyzed = {}
        self.return_tag = None
        self.callee_return = None
        self.current_call_site = None

@dataclasses.dataclass
class Flow:
    parent_to_source:list = dataclasses.field(default_factory=list)
    parent_to_sink:list = dataclasses.field(default_factory=list)
    source_stmt_id=-1
    sink_stmt_id=-1
    vuln_type: str = ""

@dataclasses.dataclass
class StmtTaintStatus:
    def __init__(self, stmt_id):
        self.stmt_id: int = stmt_id
        # {symbol_id: tag_bv}
        self.in_taint: dict = {}
        self.out_taint: dict = {}

    def set_out_taint_tag(self, symbol_id, tag):
        if tag != config.NO_TAINT:
            self.out_taint[symbol_id] = tag

    def get_in_taint_tag(self, symbol_id):
        return self.in_taint.get(symbol_id, config.NO_TAINT)

class TaintEnv:
    def __init__(self):
        self.states_to_bv = {} # state_id -> tagbitvector
        self.symbols_to_bv = {} # symbol_id -> tagbitvector
        self.bit_vector_manager = TagBitVectorManager()
        self.tag_info_hash_to_data = {}
        # 记录“本次污点传播过程中实际出队处理过”的节点，用于图可视化染色（与是否 tainted 无关）。
        # 存储为 node.to_tuple() 的结果，避免直接持有图节点对象导致跨图/跨进程不一致。
        self.processed_nodes = set()

    def mark_processed_node(self, node):
        """
        标记一个 SFGNode 在传播过程中被处理过（出队并执行传播逻辑）。
        该标记仅用于可视化染色，不参与 taint tag 计算。
        """
        if node is None:
            return
        try:
            if hasattr(node, "to_tuple"):
                self.processed_nodes.add(node.to_tuple())
                return
        except Exception:
            pass
        # fallback：尽量构造稳定 key
        self.processed_nodes.add(
            (
                getattr(node, "node_type", None),
                getattr(node, "def_stmt_id", None),
                getattr(node, "index", None),
                getattr(node, "node_id", None),
                getattr(node, "context_id", None),
            )
        )

    def is_processed_node(self, node) -> bool:
        if node is None:
            return False
        try:
            if hasattr(node, "to_tuple"):
                return node.to_tuple() in self.processed_nodes
        except Exception:
            return False
        return (
            (
                getattr(node, "node_type", None),
                getattr(node, "def_stmt_id", None),
                getattr(node, "index", None),
                getattr(node, "node_id", None),
                getattr(node, "context_id", None),
            )
            in self.processed_nodes
        )

    def add_and_update_tag_bv(self, tag_info, current_taint):
        """添加一位新tag到tag_bv, 并更新当前bv"""
        # 添加新tag_info
        self.tag_info_hash_to_data[hash(str(tag_info.to_dict()))] = tag_info
        new_bit_pos = self.bit_vector_manager.add_tag(hash(str(tag_info.to_dict())))
        # 更新tag_bv
        if new_bit_pos > 0:
           return self.bit_vector_manager.gen(current_taint, [new_bit_pos])

    def remove_tag_info(self, tag_info):
        del self.tag_info_hash_to_data[hash(tag_info)]

    def set_symbols_tag(self, symbol_ids, tag):
        if tag != config.NO_TAINT:
            for id in symbol_ids:
                self.symbols_to_bv[id] = tag

    def set_symbol_tag(self, symbol_id, tag):
        if tag != config.NO_TAINT:
            self.symbols_to_bv[symbol_id] = tag

    def get_symbol_tag(self, symbol_id):
        return self.symbols_to_bv.get(symbol_id, 0)

    def remove_symbol_tag(self, symbol_id):
        del self.symbols_to_bv[symbol_id]

    def set_states_tag(self, state_ids, tag):
        for id in state_ids:
            self.states_to_bv[id] = tag

    def get_state_tag(self, state_id):
        return self.states_to_bv.get(state_id, 0)

    def remove_state_tag(self, state_id):
        del self.states_to_bv[state_id]

    def merge_tag(self, _id, tag_list):
        pass

    def sync_arg_to_param(self, parameter_list):
        if parameter_list is None:
            return
        for arg_to_param in parameter_list:
            arg_id = arg_to_param.arg_state_id
            param_id = arg_to_param.parameter_symbol_id
            print(f"arg_id: {arg_id}, param_id: {param_id}")
            arg_tag = self.states_to_bv.get(arg_id, 0)
            print(f"arg_id: {arg_id},arg_tag: {arg_tag} param_id: {param_id}")
            if arg_tag != config.NO_TAINT:
                self.symbols_to_bv[param_id] = arg_tag


# 应该像taint_env一样，一个函数整体一个taint_state
# field_read/write时，更新TaintState 本身的path与小弟的path

# symbol_to_access_path用于函数内access_path传递
# access_path_to_tag用于函数间tag传递


# 每个symbol一个taint_state
class TaintState:
    def __init__(self):
        self.origin_access_path = []
        self.children_access_path = []
# 用taintstatemanager来管理taintstate
class TaintStateManager:
    def __init__(self) :
        self.taint_tag = {}
        self.access_path_to_tag = {}
        self.symbol_id_to_access_path = {} # {id:taintstate, id1:taintstate1}

    def add_path_to_tag(self, access_path, tag):
        self.access_path_to_tag[access_path] = tag

    def get_path_tag(self, access_path):
        return self.access_path_to_tag.get(access_path, config.NO_TAINT)

    def delete_path(self, access_path):
        self.access_path_to_tag.pop(access_path)

    def get_access_path_tag_in_sink(self, access_path):
        tag = config.NO_TAINT
        for key, value in self.access_path_to_tag.items():
            if key.startswith(access_path):
                tag |= value
        return tag

    def symbol_to_access_path(self, symbol_id):
        return self.symbol_id_to_access_path.get(symbol_id, None)

    def add_tag_and_path_for_field_read(self, symbol_id, origin_access_path):
        origin_access_path = util.access_path_formatter(origin_access_path)

        if symbol_id not in self.symbol_id_to_access_path:
            self.symbol_id_to_access_path[symbol_id] = TaintState()
        # b = a.g 给b加origin_access_path
        self.symbol_id_to_access_path[symbol_id].origin_access_path = [origin_access_path]

        #给b加tag
        if symbol_id in self.taint_tag and origin_access_path in self.access_path_to_tag:
            self.taint_tag[symbol_id] = self.access_path_to_tag[origin_access_path]

    def add_tag_and_path_for_field_write(self, symbol_id, field_name, tag):
        # x.f = w 给x加children_access_path
        if symbol_id not in self.symbol_id_to_access_path:
            self.symbol_id_to_access_path[symbol_id] = TaintState()

        self.symbol_id_to_access_path[symbol_id].children_access_path.append(field_name)

        if tag != config.NO_TAINT:
            for path in self.symbol_id_to_access_path[symbol_id].origin_access_path:
                if path and field_name:
                    self.access_path_to_tag[path + "." + field_name] = tag

    def sync_arg_to_param(self, param_list, caller_manager):
        for arg_to_param in param_list:
            taint_state = TaintState()
            arg_id = arg_to_param.arg_source_symbol_id
            param_id = arg_to_param.parameter_symbol_id

            # 把arg的children_path给param
            if arg_id in caller_manager.symbol_id_to_access_path:
                taint_state.children_access_path = caller_manager.symbol_id_to_access_path[arg_id].children_access_path
            self.symbol_id_to_access_path[param_id] = taint_state

            # 把arg的tag给param
            # if arg_id in caller_manager.taint_tag:
            #     self.taint_tag[param_id] = caller_manager.taint_tag[arg_id]


        # 从symbol的state中读取access_path
class TagBitVectorManager:
    def __init__(self):
        self.bit_vector_id = 0
        self.bit_pos_to_tag_info = {}
        self.tag_info_to_bit_pos = {}
        self.counter = 1

    def init(self, tag_list: set):
        for tag_info in tag_list:
            self.add_tag(tag_info)

    def add_tag(self, tag_info):
        """添加新tag, 并分配其在tag_bv中的bit_pos。返回bit_pos"""
        if tag_info in self.tag_info_to_bit_pos:
            return self.tag_info_to_bit_pos.get(tag_info, -1)
        bit_pos = self.counter
        self.tag_info_to_bit_pos[tag_info] = bit_pos
        self.bit_pos_to_tag_info[bit_pos] = tag_info
        self.counter += 1
        return bit_pos

    def find_bit_pos_by_tag(self, tag_info):
        return self.tag_info_to_bit_pos.get(tag_info, -1)

    def explain(self, bit_vector):
        results = set()
        # still remain 1
        while bit_vector:
            # Brian Kernighan algorithm to find all 1
            next_bit_vector = bit_vector & (bit_vector - 1)
            rightmost_1_vector = bit_vector ^ next_bit_vector
            bit_pos = rightmost_1_vector.bit_length() - 1
            tag_info = self.bit_pos_to_tag_info[bit_pos]
            results.add(tag_info)
            bit_vector = next_bit_vector
        return results

    def gen(self, bit_vector, bit_pos_list):
        for bit_pos in bit_pos_list:
            if bit_pos and bit_pos > 0:
                bit_vector |= (1 << bit_pos)
        return bit_vector

    def is_tag_info_available(self, bit_vector, tag_info):
        bit_pos = self.tag_info_to_bit_pos.get(tag_info)
        if bit_pos is not None:
            if (bit_vector & (1 << bit_pos)) != 0:
                return True
        return False

    def kill(self, bit_vector, bit_pos_list):
         #killed_ids = []
        for bit_id in bit_pos_list:
            bit_pos = self.tag_info_to_bit_pos.get(bit_id)
            if bit_pos is not None:
                target_mask = (1 << bit_pos)
                if bit_vector & target_mask != 0:
                    #killed_ids.append(bit_id)
                    bit_vector &= ~target_mask
        return bit_vector

    def copy(self):
        bit_vector_manager = TagBitVectorManager()
        bit_vector_manager.bit_vector_id = self.bit_vector_id
        bit_vector_manager.counter = self.counter
        bit_vector_manager.tag_info_to_bit_pos = self.tag_info_to_bit_pos.copy()
        bit_vector_manager.bit_pos_to_tag_info = self.bit_pos_to_tag_info.copy()
        return bit_vector_manager

class PropagationResult:
    def __init__(self, stmt_id = -1) :
        self.stmt_id = stmt_id
        self.interruption_flag = False
