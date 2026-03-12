#!/usr/bin/env python3
import ast
import pprint
import re
import copy

from lian.events.handler_template import EventData
from lian.util import util
from lian.config import config, type_table
from lian.util.loader import Loader
# from lian.events.handler_template import AppTemplate
from lian.config.constants import (
    CONDITION_FLAG,
    LIAN_SYMBOL_KIND,
    LIAN_INTERNAL,
    STATE_TYPE_KIND,
    LIAN_INTERNAL,
    CALLEE_TYPE,
    EVENT_KIND,
    SYMBOL_OR_STATE,
    ACCESS_POINT_KIND,
    ANALYSIS_PHASE_ID,
    SFG_NODE_KIND,
    SFG_EDGE_KIND,
)
import lian.events.event_return as er
from lian.taint.rule_manager import RuleManager
from lian.common_structs import (
    MethodDeclParameters,
    Parameter,
    Argument,
    MethodCallArguments,
    StateDefNode,
    StateFlowGraph,
    StmtStatus,
    Symbol,
    State,
    CallGraph,
    CallSite,
    AccessPoint,
    MethodCall,
    ComputeFrameStack,
    ComputeFrame,
    MethodSummaryTemplate,
    MethodDefUseSummary,
    SymbolDefNode,
    SymbolStateSpace,
    SimpleWorkList,
    P2ResultFlag,
    MethodCallArguments,
    InterruptionData,
    ParameterMapping,
    PathManager,
    UnionFind,
    SFGNode,
    SFGEdge,
)
from lian.core.resolver import Resolver


_taint_rule_manager = None


def _get_taint_rule_manager():
    """
    懒加载并缓存全局的 RuleManager，用于读取污点配置规则。
    如果显式配置了 default_settings，则优先使用该路径；否则使用默认路径。
    """
    global _taint_rule_manager
    if _taint_rule_manager is not None:
        return _taint_rule_manager

    default_settings = getattr(config, "DEFAULT_SETTINGS", None)
    try:
        _taint_rule_manager = RuleManager(default_settings)
    except Exception:
        # 当外部 default_settings 异常时，退回到 RuleManager 自己的默认行为
        _taint_rule_manager = RuleManager()
    return _taint_rule_manager

class StmtStates:
    def __init__(
        self, analysis_phase_id, event_manager, loader: Loader, resolver: Resolver,
        compute_frame: ComputeFrame, call_graph: CallGraph, analyzed_method_list=[], complete_graph=False
    ):
        self.event_manager = event_manager
        self.loader:Loader = loader
        self.resolver: Resolver = resolver
        self.frame: ComputeFrame = compute_frame
        self.frame_stack: ComputeFrameStack = compute_frame.frame_stack
        self.call_graph = call_graph
        self.analyzed_method_list = analyzed_method_list
        self.unit_id = self.frame.unit_id
        self.lang = self.frame.lang
        self.analysis_phase_id = analysis_phase_id
        self.sfg: StateFlowGraph = self.frame.state_flow_graph
        self.used_symbol_id_to_indexes = {}
        self.complete_graph = complete_graph

        # if self.analysis_phase_id == ANALYSIS_PHASE_ID.PRELIM_SEMANTICS:
        #     self.complete_graph = False

        self.context = None
        if self.analysis_phase_id == ANALYSIS_PHASE_ID.GLOBAL_SEMANTICS:
            self.context = self.frame.get_context()

        self.state_analysis_handlers = {
            "comment_stmt": self.regular_stmt_state,
            "package_stmt": self.regular_stmt_state,
            "echo_stmt": self.regular_stmt_state,
            "exit_stmt": self.regular_stmt_state,
            "return_stmt": self.regular_stmt_state,
            "yield_stmt": self.regular_stmt_state,
            "sync_stmt": self.regular_stmt_state,
            "label_stmt": self.regular_stmt_state,
            "throw_stmt": self.regular_stmt_state,
            "try_stmt": self.regular_stmt_state,
            "catch_stmt": self.regular_stmt_state,
            "asm_stmt": self.regular_stmt_state,
            "assert_stmt": self.regular_stmt_state,
            "pass_stmt": self.regular_stmt_state,
            "with_stmt": self.regular_stmt_state,
            "await_stmt": self.regular_stmt_state,
            "catch_clause": self.regular_stmt_state,
            "unsafe_block": self.regular_stmt_state,

            "if_stmt": self.control_flow_stmt_state,
            "dowhile_stmt": self.control_flow_stmt_state,
            "while_stmt": self.control_flow_stmt_state,
            "for_stmt": self.control_flow_stmt_state,
            "switch_stmt": self.control_flow_stmt_state,
            "case_stmt": self.control_flow_stmt_state,
            "default_stmt": self.control_flow_stmt_state,
            "switch_type_stmt": self.control_flow_stmt_state,
            "break_stmt": self.regular_stmt_state,
            "continue_stmt": self.regular_stmt_state,
            "goto_stmt": self.control_flow_stmt_state,
            "block": self.control_flow_stmt_state,
            "block_start": self.regular_stmt_state,

            "forin_stmt": self.forin_stmt_state,
            "for_value_stmt": self.forin_stmt_state,

            "import_stmt": self.import_stmt_state,
            "from_import_stmt": self.from_import_stmt_state,
            "export_stmt": self.export_stmt_state,
            "export_from_stmt": self.export_from_stmt_state,
            "require_stmt": self.require_stmt_state,

            "assign_stmt": self.assign_stmt_state,
            "call_stmt": self.call_stmt_state,
            "object_call_stmt":self.object_call_state,
            "global_stmt": self.global_stmt_state,
            "nonlocal_stmt": self.nonlocal_stmt_state,
            "type_cast_stmt": self.type_cast_stmt_state,
            "type_alias_decl": self.type_alias_decl_state,
            "phi_stmt": self.phi_stmt_state,

            "namespace_decl": self.namespace_decl_stmt_state,
            "class_decl": self.class_decl_stmt_state,
            "record_decl": self.class_decl_stmt_state,
            "interface_decl": self.class_decl_stmt_state,
            "enum_decl": self.class_decl_stmt_state,
            "struct_decl": self.class_decl_stmt_state,
            "enum_constants": self.regular_stmt_state,
            "annotation_type_decl": self.regular_stmt_state,
            "annotation_type_elements_decl": self.regular_stmt_state,

            "parameter_decl": self.parameter_decl_stmt_state,
            "variable_decl": self.variable_decl_stmt_state,
            "method_decl": self.method_decl_stmt_state,

            "new_array": self.new_array_stmt_state,
            "new_object": self.new_object_stmt_state,
            "new_record": self.new_record_stmt_state,
            "new_set": self.new_set_stmt_state,
            "new_struct": self.new_object_stmt_state,

            "addr_of": self.addr_of_stmt_state,
            "mem_read": self.mem_read_stmt_state,
            "mem_write": self.mem_write_stmt_state,
            "array_write": self.common_element_write_stmt_state,
            "array_read": self.common_element_read_stmt_state,
            "array_insert": self.array_insert_stmt_state,
            "array_append": self.array_append_stmt_state,
            "array_extend": self.array_extend_stmt_state,
            "record_extend": self.record_extend_stmt_state,
            "record_write": self.field_write_stmt_state,
            "field_write": self.field_write_stmt_state,
            "field_read": self.field_read_stmt_state,
            "field_addr": self.field_addr_stmt_state,
            "slice_write": self.slice_write_stmt_state,
            "slice_read": self.slice_read_stmt_state,
            "del_stmt": self.del_stmt_state,
            "unset_stmt": self.unset_stmt_state,
        }

    def _taint_guided_p3_enabled(self) -> bool:
        """
        判断当前是否处于“第三阶段 + 启用污点引导剪枝”的模式。
        只在 GLOBAL_SEMANTICS 阶段生效，避免影响 P2 的行为。

        开关来自 loader.options.enable_p3_taint_guided，而不是全局配置。
        """
        if self.analysis_phase_id != ANALYSIS_PHASE_ID.GLOBAL_SEMANTICS:
            return False

        loader = getattr(self, "loader", None)
        if loader is None:
            return False
        options = getattr(loader, "options", None)
        if options is None:
            return False
        return bool(getattr(options, "enable_p3_taint_guided", False))

    def _recover_extern_callee_names(self, stmt, name_symbol, unsolved_callee_states):
        """
        针对未解析/外部调用，尽量恢复出可能的被调函数名称集合。

        返回值是一个字符串集合，用于和污点规则里的 name 字段进行匹配。
        """
        names = set()

        # call_stmt：优先使用直接的函数名 symbol
        if isinstance(name_symbol, Symbol):
            if util.is_available(getattr(name_symbol, "name", None)):
                names.add(name_symbol.name)
            for state_index in getattr(name_symbol, "states", set()):
                if state_index < 0 or state_index >= len(self.frame.symbol_state_space):
                    continue
                state = self.frame.symbol_state_space[state_index]
                if isinstance(state, State):
                    access_name = util.access_path_formatter(state.access_path)
                    if access_name:
                        names.add(access_name)

        # object_call_stmt 或其它动态场景：使用未解析 callee 的 access_path
        for state_index in unsolved_callee_states:
            if state_index < 0 or state_index >= len(self.frame.symbol_state_space):
                continue
            state = self.frame.symbol_state_space[state_index]
            if not isinstance(state, State):
                continue
            access_name = util.access_path_formatter(state.access_path)
            if access_name:
                names.add(access_name)

        # 如果前面都没拿到名字，最后退回到 stmt 的 name/operation 信息
        if not names:
            if util.is_available(getattr(stmt, "name", None)):
                names.add(stmt.name)
            if util.is_available(getattr(stmt, "operation", None)):
                names.add(stmt.operation)

        return names

    def _extern_call_may_affect_taint(self, callee_names) -> bool:
        """
        针对未解析/外部调用，基于 taint 规则做一个启发式判断：
        如果 callee 名称在任意 source/sink/propagation 规则中出现过，就认为“可能影响污点分析”。
        """
        if not callee_names:
            return False

        rule_manager = _get_taint_rule_manager()
        lang = getattr(self, "lang", None)

        def _match_rule_name(rule_name: str, candidate: str) -> bool:
            if not rule_name or not candidate:
                return False
            if rule_name == candidate:
                return True
            # 简单地支持 Class.method 与 method 之间的后缀/前缀匹配
            return (
                rule_name.endswith("." + candidate)
                or candidate.endswith("." + rule_name)
            )

        all_rules = []
        all_rules.extend(getattr(rule_manager, "all_sources", []))
        all_rules.extend(getattr(rule_manager, "all_sinks", []))
        all_rules.extend(getattr(rule_manager, "all_propagations", []))

        for candidate in callee_names:
            for rule in all_rules:
                # Language must match or be ANY_LANG
                if getattr(rule, "lang", None) not in (lang, config.ANY_LANG):
                    continue
                if _match_rule_name(getattr(rule, "name", None), candidate):
                    return True
        return False

    def copy_and_extend_access_path(self, original_access_path, access_point):
        new_path: list = original_access_path.copy()
        new_path.append(access_point)
        return new_path

    def make_state_tangping(self, new_state):
        new_state.tangping_flag = True
        for each_array in new_state.array:
            new_state.tangping_elements.update(each_array)
        for each_field in new_state.fields.values():
            new_state.tangping_elements.update(each_field)
        new_state.array = []
        new_state.fields = {}

    def make_state_index_tangping_and_ensure_not_empty(self, new_state_index, status, stmt_id, stmt):
        new_state = self.frame.symbol_state_space[new_state_index]
        if not isinstance(new_state, State):
            return

        self.make_state_tangping(new_state)
        if new_state.tangping_elements:
            return
        tmp_state_index = self.create_state_and_add_space(
            status=status,
            stmt_id=stmt_id,
            source_symbol_id=new_state.source_symbol_id,
            data_type=new_state.data_type,
            source_state_id=new_state.source_state_id,
        )
        new_state.tangping_elements.add(tmp_state_index)
        self.sfg.add_edge(
            self.make_state_sfg_node(new_state_index),
            self.make_state_sfg_node(tmp_state_index),
            self.make_stmt_sfg_edge(stmt_id, SFG_EDGE_KIND.STATE_INCLUSION, name=stmt.operation)
        )

    def make_symbol_or_state_sfg_node(self, node_index):
        node = self.frame.symbol_state_space[node_index]
        if isinstance(node, Symbol):
            return SFGNode(
                node_type=SFG_NODE_KIND.SYMBOL,
                def_stmt_id=node.stmt_id,
                index=node_index,
                node_id=node.symbol_id,
                context=self.context,
                name=node.name,
            )
        elif isinstance(node, State):
            return SFGNode(
                node_type=SFG_NODE_KIND.STATE,
                def_stmt_id=node.stmt_id,
                index=node_index,
                node_id=node.state_id,
                context=self.context,
                access_path=node.access_path,
            )
        return None

    def make_symbol_sfg_node(self, node_index):
        node = self.frame.symbol_state_space[node_index]
        if isinstance(node, Symbol):
            return SFGNode(
                node_type=SFG_NODE_KIND.SYMBOL,
                def_stmt_id=node.stmt_id,
                index=node_index,
                node_id=node.symbol_id,
                context=self.context,
                name=node.name,
            )
        return None

    def make_used_symbol_sfg_node(self, node_index):
        node = self.frame.symbol_state_space[node_index]
        if isinstance(node, Symbol):
            symbol_id = node.symbol_id
            if node.symbol_id not in self.used_symbol_id_to_indexes:
                return SFGNode(
                    node_type=SFG_NODE_KIND.SYMBOL,
                    def_stmt_id=node.stmt_id,
                    index=node_index,
                    node_id=node.symbol_id,
                    context=self.context,
                    name=node.name,
                )
            result = []
            for real_index in self.used_symbol_id_to_indexes[symbol_id]:
                result.append(self.make_symbol_sfg_node(real_index))
            return result
        return None

    def make_state_sfg_node(self, node_index):
        node = self.frame.symbol_state_space[node_index]
        if isinstance(node, State):
            return SFGNode(
                node_type=SFG_NODE_KIND.STATE,
                def_stmt_id=node.stmt_id,
                index=node_index,
                node_id=node.state_id,
                context=self.context,
                access_path=node.access_path,
            )
        return None

    def make_state_sfg_node_with_no_context(self, node_index):
        node = self.frame.symbol_state_space[node_index]
        if isinstance(node, State):
            return SFGNode(
                node_type=SFG_NODE_KIND.STATE,
                def_stmt_id=node.stmt_id,
                index=node_index,
                node_id=node.state_id,
                access_path=node.access_path,
            )
        return None

    def make_stmt_sfg_edge(self, stmt_id, edge_type=SFG_EDGE_KIND.SYMBOL_FLOW, round=-1, name=""):
        return SFGEdge(edge_type=edge_type, stmt_id=stmt_id, round=round, name=name)

    def is_state_a_class_decl(self, state):
        if state.data_type == LIAN_INTERNAL.CLASS_DECL:
            return True
        if self.loader.is_class_decl(state.value):
            return True
        return False

    def is_state_a_unit(self, state):
        if state.data_type == LIAN_INTERNAL.UNIT:
            return True

    def is_state_a_method_decl(self, state):
        if state.data_type == LIAN_INTERNAL.METHOD_DECL:
            return True
        if self.loader.is_method_decl(state.value):
            return True
        return False

    def node_is_state(self, node):
        if isinstance(node, SFGNode) and node.node_type == SFG_NODE_KIND.STATE:
            return True
        return False

    def is_first_round(self, stmt_id):
        return self.frame.stmt_counters[stmt_id] == 0

    def create_state_and_add_space(
        self, status: StmtStatus, stmt_id, source_symbol_id=-1, source_state_id=-1, value="", data_type="",
        state_type=STATE_TYPE_KIND.REGULAR, access_path=[], overwritten_flag=False, parent_state=None, parent_state_index = -1,args = None, edge_name = None
    ):
        item = State(
            stmt_id=stmt_id,
            value=value,
            source_symbol_id=source_symbol_id,
            source_state_id=source_state_id,
            data_type=str(data_type),
            state_type=state_type,
            access_path=access_path,
            fields={},
            array=[]
        )

        index = self.frame.symbol_state_space.add(item)
        state_def_node = StateDefNode(index=index, state_id=item.state_id, stmt_id=stmt_id)
        util.add_to_dict_with_default_set(
            self.frame.defined_states,
            item.state_id,
            state_def_node
        )
        if parent_state:
            self.frame.state_flow_graph.add_edge(
                SFGNode(
                    node_type=SFG_NODE_KIND.STATE,
                    def_stmt_id=parent_state.stmt_id,
                    index=parent_state_index,
                    node_id=parent_state.state_id,
                    # context=self.context,
                    access_path=parent_state.access_path,
                ),
                SFGNode(
                    node_type=SFG_NODE_KIND.STATE,
                    def_stmt_id=item.stmt_id,
                    index=index,
                    node_id=item.state_id,
                    # context=self.context,
                    access_path=item.access_path,
                ),
                SFGEdge(
                    edge_type=SFG_EDGE_KIND.STATE_INCLUSION,
                    stmt_id=stmt_id
                )
            )
        if args:
            positional_args = args.positional_args
            for pos_arg in positional_args:
                for arg in pos_arg:
                    arg_state = self.frame.symbol_state_space[arg.index_in_space]
                    self.frame.state_flow_graph.add_edge(
                        SFGNode(
                            node_type=SFG_NODE_KIND.STATE,
                            def_stmt_id=arg_state.stmt_id,
                            index=arg.index_in_space,
                            node_id=arg.state_id,
                            # context=self.context,
                            access_path=arg_state.access_path,
                        ),
                        SFGNode(
                            node_type=SFG_NODE_KIND.STATE,
                            def_stmt_id=item.stmt_id,
                            index=index,
                            node_id=item.state_id,
                            # context=self.context,
                            access_path=item.access_path,
                        ),
                        SFGEdge(
                            edge_type=SFG_EDGE_KIND.STATE_INCLUSION,
                            stmt_id=stmt_id,
                            name=edge_name,
                        )
                    )
        # if state_def_node not in self.frame.all_state_defs:
        #     self.frame.state_bit_vector_manager.add_bit_id(state_def_node)
        #     self.frame.all_state_defs.add(state_def_node)
        # status.defined_states.add(index)

        # 如果新建的state是基于我们在generate_external_state里手动给的state，说明该symbol也被我们define了，需添加到define集合中
        # if overwritten_flag and source_state_id in self.frame.initial_state_to_external_symbol:
        #     symbol_id = self.frame.initial_state_to_external_symbol[source_state_id]
        #     if symbol_id != self.frame.method_def_use_summary.this_symbol_id:
        #         self.frame.method_def_use_summary.defined_external_symbol_ids.add(symbol_id)
        return index

    def create_copy_of_state_and_add_space(self, status: StmtStatus, stmt_id, state_index, stmt):
        state = self.frame.symbol_state_space[state_index]
        if not isinstance(state, State):
            return -1
        new_state = state.copy(stmt_id)
        index = self.frame.symbol_state_space.add(new_state)
        state_id = state.state_id
        if state_id != -1:
            state_def_node = StateDefNode(index=index, state_id=state_id, stmt_id=stmt_id)
            util.add_to_dict_with_default_set(
                self.frame.defined_states,
                state_id,
                state_def_node
            )
            if state_def_node not in self.frame.all_state_defs:
                self.frame.state_bit_vector_manager.add_bit_id(state_def_node)
                self.frame.all_state_defs.add(state_def_node)

        self.sfg.add_edge(
            self.make_state_sfg_node(state_index),
            self.make_state_sfg_node(index),
            self.make_stmt_sfg_edge(stmt_id, SFG_EDGE_KIND.STATE_COPY, name=stmt.operation)
        )

        status.defined_states.discard(state_index)
        status.defined_states.add(index)
        return index

    def create_copy_of_symbol_and_add_space(self, status: StmtStatus, stmt_id, symbol: Symbol):
        new_symbol = symbol.copy(stmt_id)
        new_symbol_index = self.frame.symbol_state_space.add(new_symbol)

        util.add_to_dict_with_default_set(
            self.frame.defined_symbols,
            new_symbol.symbol_id,
            SymbolDefNode(
                index=new_symbol_index, symbol_id=new_symbol.symbol_id, stmt_id=stmt_id
            )
        )
        status.implicitly_defined_symbols.append(new_symbol_index)

        return new_symbol_index

    def create_unsolved_state_and_update_symbol(
        self, status, stmt_id, receiver_symbol, data_type="", state_type=STATE_TYPE_KIND.UNSOLVED
    ):
        if isinstance(receiver_symbol, Symbol):
            index = self.create_state_and_add_space(
                status, stmt_id, receiver_symbol.symbol_id, data_type=data_type, state_type=state_type
            )
            receiver_symbol.states.add(index)
        else:
            index = self.create_state_and_add_space(
                status, stmt_id, stmt_id, data_type=data_type, state_type=state_type
            )

        return index

    def read_used_states(self, index, in_states):
        target = self.frame.symbol_state_space[index]
        if isinstance(target, Symbol):
            return in_states.get(target.symbol_id, set())

        return {index}

    def obtain_states(self, index):
        s = self.frame.symbol_state_space[index]
        if isinstance(s, State):
            return {index}
        elif isinstance(s, Symbol):
            return s.states
        return set()

    def run(self, stmt_id, stmt, status: StmtStatus, in_states, used_symbol_id_to_indexes):
        # print("status.operation:", status.operation)
        self.used_symbol_id_to_indexes = used_symbol_id_to_indexes
        handler = self.state_analysis_handlers.get(stmt.operation, None)
        result = None
        if handler is None:
            result = self.regular_stmt_state(stmt_id, stmt, status, in_states)
        else:
            result = handler(stmt_id, stmt, status, in_states)
        self.used_symbol_id_to_indexes = {}
        return result

    def copy_on_write_arg_state(self, stmt_id, stmt, status: StmtStatus, old_arg_state_index, old_to_new_arg_state, old_to_latest_old_arg_state):
        if old_arg_state_index in old_to_new_arg_state:
            return old_to_new_arg_state[old_arg_state_index]

        latest_old_arg_indexes = self.resolver.retrieve_latest_states(
            self.frame,
            stmt_id,
            self.frame.symbol_state_space,
            {old_arg_state_index},
            self.frame.state_bit_vector_manager.explain(status.in_state_bits),
            old_to_latest_old_arg_state
        )
        if not latest_old_arg_indexes:
            return -1
        latest_old_arg_index = next(iter(latest_old_arg_indexes))
        new_arg_state_index = self.create_copy_of_state_and_add_space(status, stmt_id, latest_old_arg_index, stmt)
        old_to_new_arg_state[old_arg_state_index] = new_arg_state_index
        status.defined_states.add(new_arg_state_index)
        return new_arg_state_index

    def adjust_indexes(self, callee_space: SymbolStateSpace, callee_summary: MethodSummaryTemplate, index_set: set[int]):
        if self.analysis_phase_id != ANALYSIS_PHASE_ID.PRELIM_SEMANTICS:
            return index_set.copy()

        result_indexes = set()
        for index in index_set:
            new_index = callee_summary.raw_to_new_index.get(index, index)
            if new_index == -1:
                continue
            if new_index not in callee_space.old_index_to_new_index:
                continue
            index_in_appended_space = callee_space.old_index_to_new_index[new_index]
            result_indexes.add(index_in_appended_space)
        return result_indexes

    def extract_callee_param_last_states(self, mapping, callee_summary: MethodSummaryTemplate, callee_space: SymbolStateSpace):
        last_state_indexes = set()
        parameter_symbol_id = mapping.parameter_symbol_id
        parameter_symbols = callee_summary.parameter_symbols
        parameter_last_states = parameter_symbols.get(parameter_symbol_id, set())

        adjusted_indexes = self.adjust_indexes(callee_space, callee_summary, parameter_last_states)
        for index_in_appended_space in adjusted_indexes:
            each_parameter_last_state = self.frame.symbol_state_space[index_in_appended_space]
            if not (each_parameter_last_state and isinstance(each_parameter_last_state, State)):
                continue

            if mapping.parameter_type == LIAN_INTERNAL.PARAMETER_DECL:
                last_state_indexes.add(index_in_appended_space)

            elif mapping.parameter_type == LIAN_INTERNAL.PACKED_POSITIONAL_PARAMETER:
                parameter_access_path = mapping.parameter_access_path
                parameter_index_in_array = parameter_access_path.key
                if hasattr(each_parameter_last_state, "array") and \
                   len(each_parameter_last_state.array) > int(parameter_index_in_array):
                    states_at_pos = each_parameter_last_state.array[int(parameter_index_in_array)]
                    for idx in states_at_pos:
                        last_state_indexes.add(idx)

            elif mapping.parameter_type == LIAN_INTERNAL.PACKED_NAMED_PARAMETER:
                parameter_access_path = mapping.parameter_access_path
                parameter_field_name = parameter_access_path.key
                if hasattr(each_parameter_last_state, "fields"):
                    states_in_field = each_parameter_last_state.fields.get(parameter_field_name, set())
                    for idx in states_in_field:
                        last_state_indexes.add(idx)

        return last_state_indexes

    def read_defined_symbol_states(self, status: StmtStatus):
        defined_symbol = self.frame.symbol_state_space[status.defined_symbol]
        if not isinstance(defined_symbol, Symbol):
            return set()

        return defined_symbol.states

    def unset_key_state_flag(self, symbol_id, state_index, stmt_id=-1):
        key_state = self.frame.symbol_state_space[state_index]
        if not (key_state and isinstance(key_state, State)):
            return

        if key_state.symbol_or_state == SYMBOL_OR_STATE.EXTERNAL_KEY_STATE:
            key_state.symbol_or_state = SYMBOL_OR_STATE.STATE
            key_dynamic_content = self.frame.method_summary_template.key_dynamic_content
            if symbol_id in key_dynamic_content:
                values = key_dynamic_content[symbol_id]
                values.discard(state_index)

        if stmt_id > 0:
            self.frame.method_summary_template.dynamic_call_stmts.discard(stmt_id)

    def tag_key_state_flag(self, stmt_id, symbol_id, state_index):
        key_state = self.frame.symbol_state_space[state_index]
        if not (key_state and isinstance(key_state, State)):
            return

        key_state.symbol_or_state = SYMBOL_OR_STATE.EXTERNAL_KEY_STATE
        key_dynamic_content = self.frame.method_summary_template.key_dynamic_content
        # print("tag_key_state_flag@add_state_index",state_index)
        util.add_to_dict_with_default_set(
            key_dynamic_content, symbol_id, state_index
        )
        self.frame.method_summary_template.dynamic_call_stmts.add(stmt_id)

    def regular_stmt_state(self, stmt_id, stmt, status: StmtStatus, in_states):
        return P2ResultFlag()

    def control_flow_stmt_state(self, stmt_id, stmt, status: StmtStatus, in_states):
        condition_index = status.used_symbols[0]
        condition_states = self.read_used_states(condition_index, in_states)

        condition_flag = CONDITION_FLAG.NO_PATH
        for each_state_index in condition_states:
            each_state = self.frame.symbol_state_space[each_state_index]
            if not isinstance(each_state, State):
                continue
            # print("each_state:", each_state)
            if len(each_state.fields) != 0 or len(each_state.array) != 0 or len(each_state.tangping_elements) != 0:
                condition_flag |= CONDITION_FLAG.TRUE_PATH
            else:
                if each_state.value == LIAN_INTERNAL.FALSE:
                    condition_flag |= CONDITION_FLAG.FALSE_PATH
                elif isinstance(each_state.value, int) and each_state.value == 0:
                    condition_flag |= CONDITION_FLAG.FALSE_PATH
                else:
                    condition_flag |= CONDITION_FLAG.TRUE_PATH

            if condition_flag == CONDITION_FLAG.ANY_PATH:
                break

        return P2ResultFlag(condition_path_flag=condition_flag)
        # return P2ResultFlag()

    def update_access_path_state_id(self, state_index):
        state = self.frame.symbol_state_space[state_index]
        if not isinstance(state, State):
            return
        if len(state.access_path) == 0:
            return
        state.access_path[-1].state_id = state.state_id

    def forin_stmt_state(self, stmt_id, stmt, status: StmtStatus, in_states):
        receiver_index = status.used_symbols[0]
        receiver_symbol = self.frame.symbol_state_space[receiver_index]
        receiver_states = self.read_used_states(receiver_index, in_states)

        defined_symbol_index = status.defined_symbol
        defined_symbol = self.frame.symbol_state_space[defined_symbol_index]
        defined_symbol_states = set()

        # print(f"loop_total_rounds: {self.frame.loop_total_rounds[stmt_id]}")
        if not isinstance(defined_symbol, Symbol):
            return P2ResultFlag()

        if self.frame.stmt_counters[stmt_id] == config.FIRST_ROUND:
            edge_type = SFG_EDGE_KIND.INDIRECT_SYMBOL_FLOW
            if stmt.operation == "for_value_stmt":
                edge_type = SFG_EDGE_KIND.SYMBOL_FLOW
            # flows from receiver to defined symbol
            self.sfg.add_edge(
                self.make_used_symbol_sfg_node(receiver_index),
                self.make_symbol_sfg_node(defined_symbol_index),
                self.make_stmt_sfg_edge(stmt_id, edge_type, name=stmt.operation)
            )

        for receiver_state_index in receiver_states:
            receiver_state = self.frame.symbol_state_space[receiver_state_index]
            if not isinstance(receiver_state, State):
                continue

            if receiver_state.tangping_elements:
                defined_symbol_states.update(receiver_state.tangping_elements)

            # 根据receiver类型进行分发. array / dict
            # 处理array
            elif receiver_state.array:
                receiver_array = receiver_state.array
                if isinstance(receiver_array, list):
                    for element in receiver_array:
                        defined_symbol_states.update(element)
                else:
                    defined_symbol_states.update(receiver_array)
            else:
                if stmt.operation == "for_value_stmt":
                    if receiver_state.fields:
                        # 遍历fields.values()，逐个处理元素
                        for val in receiver_state.fields.values():
                            if isinstance(val, set):
                                # 若元素是集合，拆解后加入（用update添加多个元素）
                                defined_symbol_states.update(val)
                            else:
                                # 若元素是普通可哈希类型，直接添加（用add添加单个元素）
                                defined_symbol_states.add(val)
                        continue

                source_index = self.create_state_and_add_space(
                    status=status,
                    stmt_id=stmt_id,
                    data_type=receiver_state.data_type,
                    source_symbol_id=defined_symbol.symbol_id,
                    state_type=STATE_TYPE_KIND.ANYTHING,
                )
                defined_symbol_states = {source_index}
                break

        defined_symbol.states = defined_symbol_states
        return P2ResultFlag()

    def import_stmt_state(self, stmt_id, stmt, status: StmtStatus, in_states):
        return P2ResultFlag()

    def from_import_stmt_state(self, stmt_id, stmt, status: StmtStatus, in_states):
        return self.import_stmt_state(stmt_id, stmt, status, in_states)

    def export_stmt_state(self, stmt_id, stmt, status: StmtStatus, in_states):
        return P2ResultFlag()

    def export_from_stmt_state(self, stmt_id, stmt, status: StmtStatus, in_states):
        return P2ResultFlag()

    def require_stmt_state(self, stmt_id, stmt, status: StmtStatus, in_states):
        name_symbol_index = status.used_symbols[0]
        name_symbol = self.frame.symbol_state_space[name_symbol_index]
        name_state_indexes = self.read_used_states(name_symbol_index, in_states)

        defined_symbol_index = status.defined_symbol
        defined_symbol = self.frame.symbol_state_space[defined_symbol_index]
        if not isinstance(defined_symbol, Symbol):
            return P2ResultFlag()

        result = set()
        require_values = set()
        for each_index in name_state_indexes:
            each_name_state = self.frame.symbol_state_space[each_index]
            if each_name_state.value:
                require_values.add(each_name_state.value)

        for each_value in require_values:
            state_index = self.create_state_and_add_space(
                status,
                stmt_id,
                source_symbol_id=defined_symbol.symbol_id,
                data_type=LIAN_INTERNAL.REQUIRED_MODULE,
                value=each_value,
                access_path=[AccessPoint(
                    kind=ACCESS_POINT_KIND.REQUIRED_MODULE
                )]
            )
            self.update_access_path_state_id(state_index)

            result.add(state_index)

        defined_symbol.states = result
        return P2ResultFlag()

    def compute_two_states(self, stmt, state1, state2, defined_symbol: Symbol):
        symbol_id = defined_symbol.symbol_id
        if util.is_empty(state1) or util.is_empty(state2):
            return set()

        status = self.frame.stmt_id_to_status[stmt.stmt_id]
        value1 = state1.value
        state_type1 = state1.state_type
        data_type1 = state1.data_type
        value2 = state2.value
        state_type2 = state2.state_type
        data_type2 = state2.data_type
        operator = stmt.operator

        if not (state_type1 == state_type2 == STATE_TYPE_KIND.REGULAR):
            return set()

        if not (
            value1 and type_table.is_builtin_type(data_type1) and value2 and type_table.is_builtin_type(data_type2)):
            return set()

        value = None
        data_type = state1.data_type

        tmp_value1 = value1
        tmp_value2 = value2

        is_bool = True if operator in ["and", "or"] else False
        is_string = False
        if data_type1 == LIAN_INTERNAL.STRING:
            value1 = str(value1)
            if not value1.isdigit():
                is_string = True
        if not is_string:
            if data_type2 == LIAN_INTERNAL.STRING:
                value2 = str(value2)
                if not value2.isdigit():
                    is_string = True

        if not is_bool and is_string:
            tmp_value1 = f'"{tmp_value1}"'
            tmp_value2 = f'"{tmp_value2}"'
            data_type = LIAN_INTERNAL.STRING
        else:
            is_float = False
            if data_type1 == LIAN_INTERNAL.FLOAT or data_type2 == LIAN_INTERNAL.FLOAT:
                is_float = True
                data_type = LIAN_INTERNAL.FLOAT
            else:
                data_type = LIAN_INTERNAL.INT

            tmp_value1 = f'{tmp_value1}'
            tmp_value2 = f'{tmp_value2}'

        try:
            # print(tmp_value1, tmp_value2, operator)
            value = util.strict_eval(f"{tmp_value1} {operator} {tmp_value2}")
        except:
            # value = ""
            value = str(value1) + str(operator) + str(value2)
            data_type = LIAN_INTERNAL.STRING

        # else:
        #     value = str(value1) + str(operator) + str(value2)
        #     data_type = LianInternal.STRING

        if value:
            result_state_index = self.create_state_and_add_space(
                status, stmt_id=stmt.stmt_id, source_symbol_id=symbol_id, value=value, data_type=data_type,
                access_path=[AccessPoint(
                    kind=ACCESS_POINT_KIND.BINARY_ASSIGN,
                    key=defined_symbol.name
                )]
            )
            self.update_access_path_state_id(result_state_index)

            return {result_state_index}

        return set()

    def assign_stmt_state(self, stmt_id, stmt, status: StmtStatus, in_states):
        operand_index = status.used_symbols[0]
        operand_symbol = self.frame.symbol_state_space[operand_index]
        operand_states = self.read_used_states(operand_index, in_states)
        defined_symbol = self.frame.symbol_state_space[status.defined_symbol]
        if not isinstance(defined_symbol, Symbol):
            return P2ResultFlag()

        source_symbol_id = -1
        if isinstance(operand_symbol, Symbol):
            source_symbol_id = operand_symbol.symbol_id

        if self.frame.stmt_counters[stmt_id] == config.FIRST_ROUND:
            if isinstance(operand_symbol, Symbol):
                self.sfg.add_edge(
                    self.make_used_symbol_sfg_node(operand_index),
                    self.make_symbol_sfg_node(status.defined_symbol),
                    self.make_stmt_sfg_edge(stmt_id, SFG_EDGE_KIND.SYMBOL_FLOW, name=stmt.operation)
                )

        # only one operand
        if util.isna(stmt.operand2):
            # compute unary operation
            # 形如 a = b

            if util.isna(stmt.operator):
                # print(">>>>>", stmt_id, stmt)
                # print(operand_states)
                defined_symbol.states = operand_states
                return P2ResultFlag()

            tmp_index = self.create_state_and_add_space(
                status,
                stmt.stmt_id,
                value=None,
                data_type="",
                source_symbol_id=source_symbol_id,
                state_type=STATE_TYPE_KIND.ANYTHING
            )
            defined_symbol.states = {tmp_index}

            return P2ResultFlag()

        # two operands
        operand2_index = status.used_symbols[1]
        operand2_states = self.read_used_states(operand2_index, in_states)
        new_states = set()
        for operand_state_index in operand_states:
            operand_state = self.frame.symbol_state_space[operand_state_index]
            if not isinstance(operand_state, State):
                continue
            if operand_state.state_type != STATE_TYPE_KIND.REGULAR:
                continue
            for operand2_state_index in operand2_states:
                operand2_state = self.frame.symbol_state_space[operand2_state_index]
                if not isinstance(operand2_state, State):
                    continue
                if operand2_state.state_type != STATE_TYPE_KIND.REGULAR:
                    continue

                new_states.update(
                    self.compute_two_states(
                        stmt, operand_state, operand2_state, defined_symbol
                    )
                )

        # if new_states is empty
        if not new_states:
            state_index = self.create_state_and_add_space(
                status, stmt.stmt_id,
                value=None,
                data_type="",
                source_symbol_id=source_symbol_id,
                state_type=STATE_TYPE_KIND.ANYTHING
            )
            new_states = {state_index}

        defined_symbol.states = new_states
        return P2ResultFlag()

    def prepare_args(self, stmt_id, stmt, status: StmtStatus, in_states, args_state_set=dict()):
        # used_symbols: [name, packed_positional_args, packed_named_args]
        # used_symbols: [name, packed_positional_args, named_args]
        # used_symbols: [name, positional_args, packed_named_args]
        # used_symbols: [name, positional_args, named_args]
        # index#1 of packed_positional_args: 1
        # index#2 of packed_named_args: -1
        # index#3 of named_args: [sorted values, -1]
        # index#4 of positional_args: [1, index#2/index#3]

        positional_args = []
        named_args = {}
        named_args_index = len(status.used_symbols)

        # deal with packed_positional_args
        if not util.isna(stmt.packed_named_args):
            packed_named_arg_index = status.used_symbols[-1]
            item_index_set = self.read_used_states(packed_named_arg_index, in_states)
            if util.is_available(item_index_set):
                for each_item_index in item_index_set:
                    each_item = self.frame.symbol_state_space[each_item_index]
                    packed_named_arg_symbol = self.frame.symbol_state_space[packed_named_arg_index]
                    if not (each_item and isinstance(each_item, State)):
                        continue

                    # named_args.update(each_item.fields)
                    named_args[packed_named_arg_symbol.name]=item_index_set
                    for field_name, state_index_set in each_item.fields.items():
                        util.add_to_dict_with_default_set(named_args, field_name, state_index_set)

            named_args_index -= 1

        # deal with named_args
        if not util.isna(stmt.named_args):
            args_dict = ast.literal_eval(stmt.named_args)
            keys = sorted(args_dict.keys())
            keys_len = len(keys)
            len_of_used_symbols = len(status.used_symbols)

            if len_of_used_symbols > keys_len:
                indexes = status.used_symbols[-keys_len:]
                tmp_counter = 0
                while tmp_counter < keys_len:
                    each_key = keys[tmp_counter]
                    each_arg = self.frame.symbol_state_space[indexes[tmp_counter]]
                    if isinstance(each_arg, Symbol):
                        for each_state_index in each_arg.states:
                            each_state = self.frame.symbol_state_space[each_state_index]
                            if not (each_state and isinstance(each_state, State)):
                                continue
                            if each_state.state_type == STATE_TYPE_KIND.ANYTHING:
                                self.tag_key_state_flag(stmt_id, each_arg.symbol_id, each_state_index)
                        named_args[each_key] = each_arg.states
                    elif isinstance(each_arg, State):
                        named_args[each_key] = {indexes[tmp_counter]}
                    tmp_counter += 1

                named_args_index -= len(named_args)

        # deal with positional_args
        positional_args: list[set] = []
        if not util.isna(stmt.packed_positional_args):
            index_in_used_symbols_list = 1
            if stmt.operation == "object_call_stmt":
                index_in_used_symbols_list = 2
            item_index_set = self.read_used_states(status.used_symbols[index_in_used_symbols_list], in_states)
            if util.is_available(item_index_set):
                for each_item_index in item_index_set:
                    each_item = self.frame.symbol_state_space[each_item_index]
                    if not (each_item and isinstance(each_item, State) and each_item.tangping_elements):
                        continue

                    for array_index in range(len(each_item.tangping_elements)):
                        array_length = len(positional_args)
                        if array_length <= array_index:
                            positional_args.extend(
                                [set() for _ in range(array_index + 1 - array_length)]
                            )

                        # positional_args[array_index].update(each_item.tangping_elements)
                        positional_args[array_index] = item_index_set
        elif not util.isna(stmt.positional_args):
            start_index = 1
            if stmt.operation == "object_call_stmt":
                start_index = 2
            for index in range(start_index, named_args_index):
                each_arg = self.frame.symbol_state_space[status.used_symbols[index]]
                if isinstance(each_arg, Symbol):
                    for each_state_index in each_arg.states:
                        each_state = self.frame.symbol_state_space[each_state_index]
                        if not (each_state and isinstance(each_state, State)):
                            continue
                        if each_state.state_type == STATE_TYPE_KIND.ANYTHING:
                            self.tag_key_state_flag(stmt_id, each_arg.symbol_id, each_state_index)
                    positional_args.append(each_arg.states)
                elif isinstance(each_arg, State):
                    positional_args.append({status.used_symbols[index]})
            # for index in range(1, named_args_index):
            #     positional_args.append({status.used_symbols[index]})

        # adjust named_args
        for each_key, index_set in named_args.items():
            arg_set = set()
            for each_index in index_set:
                content = self.frame.symbol_state_space[each_index]
                if isinstance(content, State):
                    arg_set.add(
                        Argument(
                            state_id=content.state_id,
                            call_stmt_id=stmt_id,
                            name=each_key,
                            source_symbol_id=content.source_symbol_id,
                            access_path=content.access_path,
                            index_in_space=each_index
                        )
                    )

            named_args[each_key] = arg_set

        # adjust positional_args
        counter = 0
        while counter < len(positional_args):
            index_set = positional_args[counter]
            arg_set = set()
            for each_index in index_set:
                content = self.frame.symbol_state_space[each_index]
                if isinstance(content, State):
                    arg_set.add(
                        Argument(
                            state_id=content.state_id,
                            call_stmt_id=stmt_id,
                            position=counter,
                            source_symbol_id=content.source_symbol_id,
                            access_path=content.access_path,
                            index_in_space=each_index
                        )
                    )

            positional_args[counter] = arg_set

            counter += 1

        return MethodCallArguments(positional_args, named_args)

    def prepare_parameters(self, callee_id):
        result = MethodDeclParameters()
        _, parameters_block = self.loader.get_method_header(callee_id)
        if not parameters_block:
            return result

        counter = 0
        for row in parameters_block:
            if row.operation != "parameter_decl":
                continue

            param = Parameter(
                method_id=callee_id, position=counter, name=row.name, symbol_id=row.stmt_id
            )
            is_attr = not util.isna(row.attrs)
            result.all_parameters.add(param)
            if is_attr and LIAN_INTERNAL.PACKED_NAMED_PARAMETER in row.attrs:
                result.packed_named_parameter = param
            elif is_attr and LIAN_INTERNAL.PACKED_POSITIONAL_PARAMETER in row.attrs:
                result.packed_positional_parameter = param
            else:
                result.positional_parameters.append(param)

            counter += 1

        return result

    def map_arguments(
        self, args: MethodCallArguments, parameters: MethodDeclParameters,
        parameter_mapping_list: list[ParameterMapping], call_site
    ):
        #### < key:symbol_id of parameter, value: parameter's states >

        # link args and parameters in terms of symbol_ids
        positional_arg_len = len(args.positional_args)
        positional_parameter_len = len(parameters.positional_parameters)
        common_len = min(positional_arg_len, positional_parameter_len)
        named_args_matched = set()
        rest_parameters = parameters.all_parameters.copy()

        pos = 0
        while pos < common_len:
            arg_set: set[Argument] = args.positional_args[pos]
            parameter: Parameter = parameters.positional_parameters[pos]
            if arg_set:
                rest_parameters.discard(parameter)
            for arg in arg_set:
                parameter_mapping_list.append(
                    ParameterMapping(
                        arg_index_in_space=arg.index_in_space,
                        arg_state_id=arg.state_id,
                        arg_access_path=arg.access_path,
                        arg_source_symbol_id=arg.source_symbol_id,
                        parameter_symbol_id=parameter.symbol_id
                    )
                )
            pos += 1

        name_to_parameter = {}
        if common_len < positional_parameter_len:
            # has default_parameter || has named_args
            # 下面处理named_args
            tmp_pos = common_len
            while tmp_pos < positional_parameter_len:
                each_parameter: Parameter = parameters.positional_parameters[tmp_pos]
                name_to_parameter[each_parameter.name] = each_parameter
                tmp_pos += 1

            if len(args.named_args) > 0 and len(name_to_parameter) > 0:
                for each_arg_name in args.named_args:
                    each_arg_set: set[Argument] = args.named_args[each_arg_name]
                    for each_arg in each_arg_set:
                        if each_arg_name in name_to_parameter:
                            each_parameter = name_to_parameter[each_arg_name]
                            rest_parameters.discard(each_parameter)
                            named_args_matched.add(each_arg_name)
                            parameter_mapping_list.append(
                                ParameterMapping(
                                    arg_index_in_space=each_arg.index_in_space,
                                    arg_state_id=each_arg.state_id,
                                    arg_source_symbol_id=each_arg.source_symbol_id,
                                    arg_access_path=each_arg.access_path,
                                    parameter_symbol_id=each_parameter.symbol_id
                                )
                            )

        elif common_len < positional_arg_len:
            if util.is_available(parameters.packed_positional_parameter):
                id = parameters.packed_positional_parameter.symbol_id
                parameter_index = 0
                for arg_set in args.positional_args[pos:]:
                    if arg_set:
                        rest_parameters.discard(parameters.packed_positional_parameter)
                    for arg in arg_set:
                        parameter_mapping_list.append(
                            ParameterMapping(
                                arg_index_in_space=arg.index_in_space,
                                arg_state_id=arg.state_id,
                                arg_source_symbol_id=arg.source_symbol_id,
                                arg_access_path=arg.access_path,
                                parameter_symbol_id=id,
                                parameter_type=LIAN_INTERNAL.PACKED_POSITIONAL_PARAMETER,
                                parameter_access_path=AccessPoint(
                                    kind=ACCESS_POINT_KIND.ARRAY_ELEMENT,
                                    key=parameter_index,
                                    state_id=arg.state_id
                                )
                            )
                        )
                    parameter_index += 1

        if util.is_available(parameters.packed_named_parameter):
            id = parameters.packed_named_parameter.symbol_id
            if len(args.named_args) > 0:
                for each_arg_name in args.named_args:
                    if each_arg_name in named_args_matched:
                        continue

                    each_arg_set: set[Argument] = args.named_args[each_arg_name]
                    if each_arg_set:
                        rest_parameters.discard(parameters.packed_named_parameter)
                    for each_arg in each_arg_set:
                        parameter_mapping_list.append(
                            ParameterMapping(
                                arg_index_in_space=each_arg.index_in_space,
                                arg_state_id=each_arg.state_id,
                                arg_source_symbol_id=each_arg.source_symbol_id,
                                arg_access_path=each_arg.access_path,
                                parameter_symbol_id=id,
                                parameter_type=LIAN_INTERNAL.PACKED_NAMED_PARAMETER,
                                parameter_access_path=AccessPoint(
                                    kind=ACCESS_POINT_KIND.FIELD_ELEMENT,
                                    key=str(each_arg_name),
                                    state_id=each_arg.state_id
                                )
                            )
                        )

                    named_args_matched.add(each_arg_name)

        if rest_parameters:
            for each_parameter in rest_parameters:
                parameter_symbol_id = each_parameter.symbol_id
                default_value_symbol_id = None
                callee_method_def_use_summary = self.loader.get_method_def_use_summary(call_site.callee_id).copy()
                for symbol_default_pair in callee_method_def_use_summary.parameter_symbol_ids:
                    if parameter_symbol_id == symbol_default_pair[0]:
                        default_value_symbol_id = symbol_default_pair[1]
                        break

                # if default_value_symbol_id and default_value_symbol_id in callee_def_use_summary.used_external_symbol_ids:
                if default_value_symbol_id:
                    parameter_mapping_list.append(
                        ParameterMapping(
                            arg_state_id=default_value_symbol_id,
                            parameter_symbol_id=parameter_symbol_id,
                            is_default_value=True
                        )
                    )
        if self.analysis_phase_id == ANALYSIS_PHASE_ID.PRELIM_SEMANTICS:
            self.loader.save_parameter_mapping_p2(call_site, parameter_mapping_list)
        elif self.analysis_phase_id == ANALYSIS_PHASE_ID.GLOBAL_SEMANTICS:
            self.loader.save_parameter_mapping_p3(call_site, parameter_mapping_list)

    def fuse_states_to_one_state(self, state_indexes: set, stmt_id, stmt, status: StmtStatus):
        if util.is_empty(state_indexes) or len(state_indexes) == 1:
            return state_indexes
        # 以集合中的任一个元素作为模板，创建一个fusion_state。create_copy过程中会自动将fusion_state加入status.defined_states中。
        new_state_index = self.create_copy_of_state_and_add_space(status, stmt_id, list(state_indexes)[0], stmt)
        new_state: State = self.frame.symbol_state_space[new_state_index]
        state_array: list[set] = []
        tangping_flag = False
        tangping_elements = set()
        state_fields = {}
        for each_state_index in state_indexes:
            each_state = self.frame.symbol_state_space[each_state_index]
            if not (each_state and isinstance(each_state, State)):
                continue
            for index in range(len(each_state.array)):
                util.add_to_list_with_default_set(state_array, index, each_state.array[index])
            for field_name in each_state.fields:
                util.add_to_dict_with_default_set(state_fields, field_name, each_state.fields[field_name])
            tangping_flag |= each_state.tangping_flag
            tangping_elements.update(each_state.tangping_elements)
        new_state.array = state_array
        new_state.fields = state_fields
        new_state.tangping_elements = tangping_elements
        new_state.tangping_flag = tangping_flag
        if tangping_flag:
            self.make_state_tangping(new_state)
        return {new_state_index}

    def recursively_collect_children_fields(
        self, stmt_id, stmt, status: StmtStatus, state_set_in_summary_field: set,
        state_set_in_arg_field: set, source_symbol_id, access_path
    ):
        cache = {}

        def _set_attributes_on_states(states, fields_to_set, state_type, source_symbol_id, access_path):
            for state_index in states:
                state: State = self.frame.symbol_state_space[state_index]
                state.fields = fields_to_set
                state.state_type = state_type
                state.source_symbol_id = source_symbol_id
                state.access_path = access_path
            return states

        def _merge_fields_for_states(summary_states_fields, arg_state_fields, access_path):
            current_arg_state_fields = arg_state_fields.copy()

            # 处理字段合并
            for field_name in summary_states_fields:
                if field_name not in current_arg_state_fields:
                    current_arg_state_fields[field_name] = summary_states_fields[field_name]
                # 如果已经存在，则 深入递归合并
                else:
                    # 生成更深一层的access_path
                    new_access_path = self.copy_and_extend_access_path(
                        original_access_path=access_path,
                        access_point=AccessPoint(
                            kind=ACCESS_POINT_KIND.FIELD_ELEMENT,
                            key=field_name
                        )
                    )
                    current_arg_state_fields[field_name] = _recursively_collect_children_fields(
                        stmt_id,
                        stmt,
                        status,
                        summary_states_fields[field_name],
                        current_arg_state_fields[field_name],
                        source_symbol_id,
                        new_access_path
                    )

            return current_arg_state_fields

        def _recursively_collect_children_fields(
            stmt_id, stmt, status: StmtStatus, state_set_in_summary_field: set,
            state_set_in_arg_field: set, source_symbol_id, access_path
        ):
            cache_key = (
                stmt_id,
                frozenset(state_set_in_summary_field),
                frozenset(state_set_in_arg_field),
                source_symbol_id,
            )
            # 检查缓存
            if cache_key in cache:
                cached_result = cache[cache_key]
                if cached_result is None:
                    # 循环依赖情况，避免无限递归
                    if state_set_in_arg_field:
                        return state_set_in_arg_field.copy()
                    else:
                        return state_set_in_summary_field.copy()
                return cached_result

            cache[cache_key] = None

            # state_type默认为REGULAR，如果任意一个输入状态的 state_type 是 ANYTHING，则结果也标记为 ANYTHING。
            state_type = STATE_TYPE_KIND.REGULAR
            # summary_states_fields / arg_state_fields：分别用来收集summary和arg两组状态的字段映射（字段名 → 值集合）。
            summary_states_fields = {}
            arg_state_fields = {}
            tangping_flag = False
            tangping_elements = set()
            return_set = set()

            # 填充summary_states_fields
            for each_state_index in state_set_in_summary_field:
                each_state = self.frame.symbol_state_space[each_state_index]
                if not (each_state and isinstance(each_state, State)):
                    continue
                if each_state.state_type == STATE_TYPE_KIND.ANYTHING:
                    state_type = STATE_TYPE_KIND.ANYTHING
                if each_state.tangping_flag:
                    tangping_flag = True
                    tangping_elements.update(each_state.tangping_elements)
                    continue
                # 将该State的fields中每个字段名和对应值集，合并到summary_states_fields，同名字段时将值集并集。
                each_state_fields = each_state.fields.copy()
                for field_name in each_state_fields:
                    util.add_to_dict_with_default_set(summary_states_fields, field_name, each_state_fields[field_name])

            state_id_to_states = {}
            # 填充arg_state_fields
            for each_state_index in state_set_in_arg_field:
                each_state = self.frame.symbol_state_space[each_state_index]
                util.add_to_dict_with_default_set(state_id_to_states, each_state.state_id, each_state_index)

                if not (each_state and isinstance(each_state, State)):
                    continue
                if each_state.tangping_flag:
                    tangping_flag = True
                    tangping_elements.update(each_state.tangping_elements)
                    continue
                each_state_fields = each_state.fields.copy()
                for field_name in each_state_fields:
                    util.add_to_dict_with_default_set(arg_state_fields, field_name, each_state_fields[field_name])

            # 合并caller中同id的states
            states_with_diff_ids = set()
            # 如果是第三阶段，把states加到states_with_diff_ids，不允许下面的for
            if self.analysis_phase_id == ANALYSIS_PHASE_ID.PRELIM_SEMANTICS:
                for state_id, states in state_id_to_states.items():
                    if len(states) == 1:
                        new_state_index = self.create_copy_of_state_and_add_space(status, stmt_id, next(iter(states)), stmt)
                        states_with_diff_ids.add(new_state_index)
                    else:
                        states_with_diff_ids.update(self.fuse_states_to_one_state(states, stmt_id, stmt, status))
            else:
                for state_id, states in state_id_to_states.items():
                    if len(states) == 1:
                        states_with_diff_ids.update(states)
            if tangping_flag:
                for state_index in states_with_diff_ids:
                    state: State = self.frame.symbol_state_space[state_index]
                    state.tangping_flag = True
                    state.tangping_elements = tangping_elements
                return_set.update(states_with_diff_ids)

            # 只有单侧有字段时的处理
            if not arg_state_fields or not summary_states_fields:
                if summary_states_fields:
                    _set_attributes_on_states(
                        states_with_diff_ids, summary_states_fields, state_type, source_symbol_id, access_path
                    )
                    return_set.update(states_with_diff_ids)
                elif arg_state_fields:
                    _set_attributes_on_states(
                        states_with_diff_ids, arg_state_fields, state_type, source_symbol_id, access_path
                    )
                    return_set.update(states_with_diff_ids)
                else:
                    if not return_set:
                        return_set.update(state_set_in_summary_field)
                cache[cache_key] = return_set
                return return_set

            # 两侧都有字段
            merged_fields = _merge_fields_for_states(summary_states_fields, arg_state_fields, access_path)
            _set_attributes_on_states(states_with_diff_ids, merged_fields, state_type, source_symbol_id, access_path)
            return_set.update(states_with_diff_ids)

            cache[cache_key] = return_set
            return return_set

        return _recursively_collect_children_fields(
            stmt_id, stmt, status, state_set_in_summary_field, state_set_in_arg_field,
            source_symbol_id, access_path
        )

    def apply_parameter_summary_to_args_states(
        self,
        stmt_id,
        stmt,
        status: StmtStatus,
        last_state_indexes: set[int],
        old_arg_state_index,
        old_to_new_arg_state,
        parameter_symbol_id=-1,
        callee_id=-1,
        deferred_index_updates=None,
        old_to_latest_old_arg_state=None,
    ):
        if util.is_empty(old_to_latest_old_arg_state):
            old_to_latest_old_arg_state = {}

        new_arg_state_index = self.copy_on_write_arg_state(
            stmt_id, stmt, status, old_arg_state_index, old_to_new_arg_state, old_to_latest_old_arg_state
        )
        if new_arg_state_index == -1:
            return
        new_arg_state: State = self.frame.symbol_state_space[new_arg_state_index]

        (
            callee_state_arrays,
            callee_state_fields,
            tangping_flag,
            tangping_elements,
        ) = self.collect_callee_state_effects(last_state_indexes, stmt_id, callee_id)

        # 更新caller实参的array/fields/tangping
        self.merge_callee_arrays_into_arg_state(new_arg_state, callee_state_arrays)
        self.merge_callee_tangping_into_arg_state(new_arg_state, tangping_flag, tangping_elements, stmt_id, callee_id)
        self.merge_callee_fields_into_arg_state(
            stmt_id, stmt, status, new_arg_state, callee_state_fields, parameter_symbol_id
        )
        self.resolve_anything_in_arg_fields(
            new_arg_state.fields,
            stmt_id,
            parameter_symbol_id,
            callee_id,
            deferred_index_updates,
        )

    def collect_callee_state_effects(self, last_state_indexes, stmt_id, callee_id):
        callee_state_arrays: list[set] = []
        callee_state_fields = {}
        tangping_flag = False
        tangping_elements = set()

        for each_state_index in last_state_indexes:
            each_last_state = self.frame.symbol_state_space[each_state_index]
            if not (each_last_state and isinstance(each_last_state, State)):
                continue

            if each_last_state.tangping_flag:
                tangping_flag = True
                tangping_elements.update(each_last_state.tangping_elements)

            for index in range(len(each_last_state.array)):
                util.add_to_list_with_default_set(callee_state_arrays, index, each_last_state.array[index])

            each_state_fields = each_last_state.fields.copy()
            for field_name in each_state_fields:
                util.add_to_dict_with_default_set(callee_state_fields, field_name, each_state_fields[field_name])

        self.resolve_anything_in_arrays(callee_state_arrays, stmt_id, callee_id)

        return callee_state_arrays, callee_state_fields, tangping_flag, tangping_elements

    def resolve_anything_in_arrays(self, callee_state_arrays, stmt_id, callee_id):
        for index, states in enumerate(callee_state_arrays):
            for each_array_state_index in list(states):
                each_array_state = self.frame.symbol_state_space[each_array_state_index]
                if each_array_state.state_type == STATE_TYPE_KIND.ANYTHING:
                    self.resolver.resolve_anything_in_summary_generation(
                        each_array_state_index,
                        self.frame,
                        stmt_id,
                        callee_id,
                        set_to_update=callee_state_arrays[index],
                    )

    def merge_callee_arrays_into_arg_state(self, arg_state: State, callee_state_arrays: list[set]):
        new_array = arg_state.array.copy()
        for index in range(len(callee_state_arrays)):
            util.add_to_list_with_default_set(new_array, index, callee_state_arrays[index])
        arg_state.array = new_array

    def merge_callee_tangping_into_arg_state(
        self, arg_state: State, tangping_flag: bool, tangping_elements: set, stmt_id, callee_id
    ):
        if not (tangping_flag or tangping_elements):
            return

        arg_state.tangping_flag |= tangping_flag
        for each_tangping_element_index in tangping_elements.copy():
            each_tangping_element = self.frame.symbol_state_space[each_tangping_element_index]
            if each_tangping_element.state_type == STATE_TYPE_KIND.ANYTHING:
                self.resolver.resolve_anything_in_summary_generation(
                    each_tangping_element_index,
                    self.frame,
                    stmt_id,
                    callee_id,
                    set_to_update=tangping_elements,
                )
        arg_state.tangping_elements.update(tangping_elements)

    def merge_callee_fields_into_arg_state(
        self, stmt_id, stmt, status, arg_state: State, callee_state_fields: dict, parameter_symbol_id
    ):
        arg_fields = arg_state.fields
        arg_base_access_path = arg_state.access_path

        for field_name, callee_fields in callee_state_fields.items():
            if field_name not in arg_fields:
                arg_fields[field_name] = callee_fields
                continue

            access_path = self.copy_and_extend_access_path(
                original_access_path=arg_base_access_path,
                access_point=AccessPoint(
                    kind=ACCESS_POINT_KIND.FIELD_ELEMENT,
                    key=field_name,
                ),
            )
            arg_fields[field_name] = self.recursively_collect_children_fields(
                stmt_id,
                stmt,
                status,
                callee_fields,
                arg_fields[field_name],
                parameter_symbol_id,
                access_path,
            )

    def resolve_anything_in_arg_fields(
        self, arg_fields, stmt_id, parameter_symbol_id, callee_id, deferred_index_updates
    ):
        for field_name, field_states in copy.deepcopy(arg_fields).items():
            for each_field_state_index in field_states:
                if each_field_state_index < 0:
                    continue
                each_field_state = self.frame.symbol_state_space[each_field_state_index]
                if each_field_state.state_type != STATE_TYPE_KIND.ANYTHING:
                    continue

                self.resolver.resolve_anything_in_summary_generation(
                    each_field_state_index,
                    self.frame,
                    stmt_id,
                    callee_id,
                    deferred_index_updates,
                    set_to_update=arg_fields[field_name],
                    parameter_symbol_id=parameter_symbol_id,
                )

    def apply_this_symbol_semantic_summary(
        self, stmt_id, stmt, callee_id, callee_summary: MethodSummaryTemplate,
        callee_space: SymbolStateSpace, instance_state_indexes: set[int],
        new_object_flag: bool
    ):
        deferred_index_updates = set()
        if util.is_empty(instance_state_indexes):
            return
        status = self.frame.stmt_id_to_status[stmt_id]
        old_to_new_arg_state = {}
        this_symbols = callee_summary.this_symbols
        # 收集callee_summary中this_symbols的last_states，并应用到实际传入的instance_state中。
        for this_symbol_id in this_symbols:
            this_symbol_last_states = this_symbols.get(this_symbol_id, [])
            last_state_indexes = self.adjust_indexes(callee_space, callee_summary, this_symbol_last_states)
            for instance_state_index_in_space in instance_state_indexes.copy():
                # 将summary中的this_symbol_last_state应用到实际的instance_state上
                self.apply_parameter_summary_to_args_states(
                    stmt_id, stmt, status, last_state_indexes, instance_state_index_in_space,
                    old_to_new_arg_state, callee_id = callee_id, deferred_index_updates = deferred_index_updates
                )

        self.resolver.update_deferred_index(
            old_to_new_arg_state, deferred_index_updates, self.frame.symbol_state_space
        )

        # 如果caller是通过new_object_stmt调用到callee的，就不应该将以上对this的修改添加到caller的summary中
        if new_object_flag:
            return

        new_this_states = set()
        for old_state in old_to_new_arg_state:
            new_this_states.add(old_to_new_arg_state[old_state])
        if not new_this_states:
            return

        this_symbol_id = self.frame.method_def_use_summary.this_symbol_id
        index_to_add = self.frame.symbol_state_space.add(
            Symbol(
                stmt_id=stmt_id,
                name=LIAN_INTERNAL.THIS,
                symbol_id=this_symbol_id,
                states=new_this_states
            )
        )
        util.add_to_dict_with_default_set(self.frame.method_summary_template.this_symbols, this_symbol_id,
                                          new_this_states)
        util.add_to_dict_with_default_set(self.frame.method_summary_instance.this_symbols, this_symbol_id,
                                          new_this_states)
        status.implicitly_defined_symbols.append(index_to_add)

    def apply_parameter_semantic_summary(
        self,
        stmt_id,
        stmt,
        callee_id,
        callee_summary: MethodSummaryTemplate,
        callee_space: SymbolStateSpace,
        parameter_mapping_list: list[ParameterMapping],
    ):
        status = self.frame.stmt_id_to_status[stmt_id]
        old_to_new_arg_state = {}
        old_to_latest_old_arg_state = {}
        deferred_index_updates = set()

        for each_mapping in parameter_mapping_list:
            if each_mapping.is_default_value:
                self.apply_default_parameter_mapping(
                    stmt_id,
                    stmt,
                    status,
                    each_mapping,
                    callee_summary,
                    callee_space,
                    old_to_new_arg_state,
                    old_to_latest_old_arg_state,
                )
                continue

            if each_mapping.arg_source_symbol_id == -1:
                continue

            last_state_indexes = self.extract_callee_param_last_states(
                each_mapping, callee_summary, callee_space
            )
            self.apply_parameter_summary_to_args_states(
                stmt_id,
                stmt,
                status,
                last_state_indexes,
                each_mapping.arg_index_in_space,
                old_to_new_arg_state,
                each_mapping.parameter_symbol_id,
                callee_id,
                deferred_index_updates,
                old_to_latest_old_arg_state,
            )

        self.resolver.update_deferred_index(
            old_to_new_arg_state, deferred_index_updates, self.frame.symbol_state_space
        )

    def apply_default_parameter_mapping(
        self,
        stmt_id,
        stmt,
        status: StmtStatus,
        mapping: ParameterMapping,
        callee_summary: MethodSummaryTemplate,
        callee_space: SymbolStateSpace,
        old_to_new_arg_state,
        old_to_latest_old_arg_state,
    ):
        parameter_symbol_id = mapping.parameter_symbol_id
        default_value_symbol_id = mapping.arg_state_id
        last_state_indexes = set()
        default_value_state_type = STATE_TYPE_KIND.REGULAR

        parameter_last_states = callee_summary.parameter_symbols.get(parameter_symbol_id, set())
        adjusted_indexes = self.adjust_indexes(callee_space, callee_summary, parameter_last_states)
        for index_in_appended_space in adjusted_indexes:
            each_default_value_last_state = self.frame.symbol_state_space[index_in_appended_space]
            if not (each_default_value_last_state and isinstance(each_default_value_last_state, State)):
                continue

            if default_value_state_type != STATE_TYPE_KIND.ANYTHING:
                if each_default_value_last_state.state_type == STATE_TYPE_KIND.ANYTHING:
                    default_value_state_type = STATE_TYPE_KIND.ANYTHING

            last_state_indexes.add(index_in_appended_space)

        if util.is_empty(last_state_indexes):
            return

        tmp_default_value_state_index = self.create_state_and_add_space(
            status, stmt_id, state_type=default_value_state_type
        )
        self.apply_parameter_summary_to_args_states(
            stmt_id,
            stmt,
            status,
            last_state_indexes,
            tmp_default_value_state_index,
            old_to_new_arg_state,
            mapping.parameter_symbol_id,
            callee_id=-1,
            deferred_index_updates=None,
            old_to_latest_old_arg_state=old_to_latest_old_arg_state,
        )
        new_default_value_state_index = old_to_new_arg_state[tmp_default_value_state_index]

        if default_value_symbol_id not in self.frame.all_local_symbol_ids:
            util.add_to_dict_with_default_set(
                self.frame.method_summary_template.defined_external_symbols,
                default_value_symbol_id,
                {new_default_value_state_index},
            )
            self.frame.method_summary_template.index_to_default_value[new_default_value_state_index] = default_value_symbol_id

        index_to_add = self.frame.symbol_state_space.add(
            Symbol(
                stmt_id=stmt_id,
                symbol_id=default_value_symbol_id,
                states={new_default_value_state_index},
            )
        )
        status.defined_states.discard(tmp_default_value_state_index)
        status.implicitly_defined_symbols.append(index_to_add)

    def apply_other_semantic_summary(
        self, stmt_id, callee_id, status: StmtStatus, callee_summary: MethodSummaryTemplate,
        callee_compact_space: SymbolStateSpace
    ):
        target_index = status.defined_symbol
        target_symbol = self.frame.symbol_state_space[target_index]
        if not isinstance(target_symbol, Symbol):
            return P2ResultFlag()

        return_state_index_set = set()
        for _, return_states in callee_summary.return_symbols.items():
            adjusted_indexes = self.adjust_indexes(callee_compact_space, callee_summary, return_states)
            return_state_index_set.update(adjusted_indexes)

        target_symbol.states.update(return_state_index_set)
        status.defined_states.update(return_state_index_set)

        for callee_defined_external_symbol_id, defined_external_states in callee_summary.defined_external_symbols.items():
            new_defined_external_states = self.adjust_indexes(callee_compact_space, callee_summary, defined_external_states)
            if callee_defined_external_symbol_id not in self.frame.all_local_symbol_ids:
                util.add_to_dict_with_default_set(
                    self.frame.method_summary_template.defined_external_symbols,
                    callee_defined_external_symbol_id,
                    new_defined_external_states
                )

            index_to_add = self.frame.symbol_state_space.add(
                Symbol(
                    stmt_id=stmt_id,
                    symbol_id=callee_defined_external_symbol_id,
                    states=new_defined_external_states
                )
            )

            status.implicitly_defined_symbols.append(index_to_add)

    def apply_callee_semantic_summary(
        self, stmt_id, stmt, callee_id, args: MethodCallArguments,
        callee_summary, callee_compact_space: SymbolStateSpace,
        this_state_set: set = set(), new_object_flag=False
    ):
        status = self.frame.stmt_id_to_status[stmt_id]
        # append callee space to caller space
        if self.analysis_phase_id == ANALYSIS_PHASE_ID.PRELIM_SEMANTICS:
            self.frame.symbol_state_space.append_space_copy(callee_compact_space)

        # add necessary state in defined_states
        top_state_index_set = set()
        for each_summary in [
            callee_summary.parameter_symbols,
            callee_summary.defined_external_symbols,
            callee_summary.return_symbols
        ]:
            if util.is_empty(each_summary):
                continue
            for symbol_id in each_summary:
                index_set = each_summary[symbol_id]
                adjusted_indexes = self.adjust_indexes(callee_compact_space, callee_summary, index_set)
                top_state_index_set.update(adjusted_indexes)

        work_list = SimpleWorkList(top_state_index_set)
        state_visited = set()
        defined_states = set()
        defined_state_id_set = set()
        # 将summary中涉及到的所有states(包括children states)加入到defined_states中
        while len(work_list) != 0:
            current_state_index = work_list.pop()
            if current_state_index in state_visited or current_state_index < 0:
                continue
            state_visited.add(current_state_index)

            current_state: State = self.frame.symbol_state_space[current_state_index]
            if not current_state or isinstance(current_state, Symbol):
                continue
            defined_states.add(current_state_index)
            defined_state_id_set.add(current_state.state_id)
            for each_array_item in current_state.array:
                work_list.add(each_array_item)
            for each_field_item in current_state.fields.values():
                work_list.add(each_field_item)
            if current_state.tangping_flag:
                work_list.add(current_state.tangping_elements)
        old_defined_states = status.defined_states.copy()
        # 移除旧status.defined_states中和新defined_states同state_id的states
        for each_state_index in old_defined_states:
            if self.frame.symbol_state_space.convert_state_index_to_state_id(each_state_index) in defined_state_id_set:
                status.defined_states.discard(each_state_index)
        status.defined_states.update(defined_states)

        # mapping parameter and argument
        caller_id = self.frame.method_id
        call_stmt_id = stmt_id
        call_site = CallSite(caller_id, call_stmt_id, callee_id)
        if self.analysis_phase_id == ANALYSIS_PHASE_ID.PRELIM_SEMANTICS:
            parameter_mapping_list = self.loader.get_parameter_mapping_p2(call_site)
        else:
            parameter_mapping_list = self.loader.get_parameter_mapping_p3(call_site)
        # apply parameter's state in callee_summary to args
        self.apply_parameter_semantic_summary(
            stmt_id, stmt, callee_id, callee_summary, callee_compact_space, parameter_mapping_list
        )

        # apply this_symbol's state in callee_summary to this_state_set
        self.apply_this_symbol_semantic_summary(
            stmt_id, stmt, callee_id, callee_summary, callee_compact_space, this_state_set, new_object_flag
        )

        # apply other callee_summary to args
        self.apply_other_semantic_summary(
            stmt_id, callee_id, status, callee_summary, callee_compact_space
        )

        if callee_summary.dynamic_call_stmts:
            self.frame.method_summary_template.dynamic_call_stmts.add(stmt_id)

    def trigger_extern_callee(
        self, stmt_id, stmt, status: StmtStatus, in_states, unsolved_callee_states, name_symbol, defined_symbol, args
    ):
        # 在第三阶段中，对未解析/外部调用做一次“污点相关性”过滤：
        # 如果按照 taint 规则判断与污点无关，则直接跳过 extern/LLM 处理，
        # 仅为返回值创建一个保守的 UNSOLVED 状态占位。
        if self._taint_guided_p3_enabled():
            callee_names = self._recover_extern_callee_names(
                stmt, name_symbol, unsolved_callee_states
            )
            if not self._extern_call_may_affect_taint(callee_names):
                if isinstance(defined_symbol, Symbol):
                    unsolved_state_index = self.create_state_and_add_space(
                        status,
                        stmt_id,
                        source_symbol_id=defined_symbol.symbol_id,
                        state_type=STATE_TYPE_KIND.UNSOLVED,
                        data_type=util.read_stmt_field(stmt.data_type),
                        access_path=[
                            AccessPoint(
                                kind=ACCESS_POINT_KIND.CALL_RETURN,
                                key=util.read_stmt_field(defined_symbol.name),
                            )
                        ],
                    )
                    self.update_access_path_state_id(unsolved_state_index)
                    defined_symbol.states = {unsolved_state_index}
                return None

        p2result_flag = P2ResultFlag()
        event = EventData(
            self.lang,
            EVENT_KIND.P2STATE_EXTERN_CALLEE,
            {
                "resolver": self.resolver,
                "stmt_id": stmt_id,
                "stmt": stmt,
                "status": status,
                "frame": self.frame,
                "in_states": in_states,
                "state_analysis": self,
                "callee_symbol": name_symbol,
                "unsolved_callee_states": unsolved_callee_states,
                "defined_symbol": defined_symbol,
                "args": args,
                "p2result_flag": p2result_flag,
                "loader": self.loader,
                "space": self.frame.symbol_state_space,
            }
        )
        app_return = self.event_manager.notify(event)
        if hasattr(event.out_data, "interruption_flag") and event.out_data.interruption_flag:
            return event.out_data

        if er.is_event_unprocessed(app_return):
            unsolved_state_index = self.create_state_and_add_space(
                status, stmt_id,
                source_symbol_id=defined_symbol.symbol_id,
                state_type=STATE_TYPE_KIND.UNSOLVED,
                data_type=util.read_stmt_field(stmt.data_type),  # LianInternal.RETURN_VALUE,
                access_path=[AccessPoint(
                    kind=ACCESS_POINT_KIND.CALL_RETURN,
                    key=util.read_stmt_field(defined_symbol.name)
                )],
                # args=args
            )
            self.update_access_path_state_id(unsolved_state_index)
            defined_symbol.states = {unsolved_state_index}

        return None

    def call_stmt_state(self, stmt_id, stmt, status: StmtStatus, in_states):
        defined_symbol_index = status.defined_symbol
        defined_symbol = self.frame.symbol_state_space[defined_symbol_index]

        name_index = status.used_symbols[0]
        name_symbol = self.frame.symbol_state_space[name_index]
        if not isinstance(name_symbol, Symbol):
            return P2ResultFlag()

        name_states = self.read_used_states(name_index, in_states)
        unsolved_callee_states = set()
        args = self.prepare_args(stmt_id, stmt, status, in_states)
        callee_info = self.frame.stmt_id_to_callee_info.get(stmt_id)

        event = EventData(
            self.lang,
            EVENT_KIND.P2STATE_CALL_STMT_BEFORE,
            {
                "resolver": self.resolver,
                "stmt_id": stmt_id,
                "stmt": stmt,
                "status": status,
                "frame": self.frame,
                "in_states": in_states,
                "defined_symbol": defined_symbol,
                "state_analysis": self,
                "args": args,
                "name_states": name_states,
                "space": self.frame.symbol_state_space,
            }
        )
        app_return = self.event_manager.notify(event)
        if er.should_block_event_requester(app_return):
            if util.is_available(event.out_data):
                return event.out_data
            return P2ResultFlag()
        if util.is_empty(callee_info):
            result = self.trigger_extern_callee(
                stmt_id, stmt, status, in_states, unsolved_callee_states, name_symbol, defined_symbol, args
            )
            if util.is_available(result):
                return result
            return P2ResultFlag()

        callee_type = callee_info.callee_type
        callee_method_ids = set()
        callee_class_ids = set()
        this_state_set = set()
        for each_state_index in name_states:
            each_state = self.frame.symbol_state_space[each_state_index]
            if not isinstance(each_state, State):
                continue

            if each_state.state_type == STATE_TYPE_KIND.ANYTHING:
                self.tag_key_state_flag(stmt_id, name_symbol.symbol_id, each_state_index)

            if self.is_state_a_method_decl(each_state):
                if each_state.value:
                    source_state_id = each_state.source_state_id
                    # 如果是state1.func()的形式，要去找state1
                    if source_state_id != each_state.state_id:
                        this_state_set.update(
                            self.resolver.obtain_parent_states(stmt_id, self.frame, status, each_state_index)
                        )
                    if callee_id := util.str_to_int(each_state.value):
                        callee_method_ids.add(callee_id)

            #  what if it calls class_constructor.  e.g., o = A()
            elif self.is_state_a_class_decl(each_state) or each_state.data_type == LIAN_INTERNAL.THIS or name_symbol.name == LIAN_INTERNAL.THIS:
                return self.new_object_stmt_state(stmt_id, stmt, status, in_states)

            else:
                unsolved_callee_states.add(each_state_index)

        # call plugin to deal with undefined_callee_error
        # if len(unsolved_callee_states) != 0:
        caller_id = self.frame.method_id
        if len(callee_method_ids) == 0 or self.is_abstract_method(callee_method_ids) or caller_id in callee_method_ids:
            out_data = self.trigger_extern_callee(
                stmt_id, stmt, status, in_states, unsolved_callee_states, name_symbol, defined_symbol, args
            )
            if util.is_available(out_data):
                if hasattr(out_data, "callee_method_ids"):
                    callee_method_ids.update(out_data.callee_method_ids)
                else:
                    return out_data
        # 在进入 P3 的跨函数分析前，再做一轮污点相关性判断：
        # 如果当前调用在 taint 视角下完全无关，则不再深入 callee，仅保留保守占位。
        if self._taint_guided_p3_enabled():
            relevance = self.frame.stmt_state_analysis.judge_call_relevance(
                stmt_id,
                stmt,
                status,
                in_states,
                args,
                defined_symbol,
                this_state_set,
                callee_method_ids,
                name_symbol,
            )
            if not relevance.is_relevant:
                if isinstance(defined_symbol, Symbol):
                    unsolved_state_index = self.create_state_and_add_space(
                        status,
                        stmt_id,
                        source_symbol_id=defined_symbol.symbol_id,
                        state_type=STATE_TYPE_KIND.UNSOLVED,
                        data_type=util.read_stmt_field(stmt.data_type),
                        access_path=[
                            AccessPoint(
                                kind=ACCESS_POINT_KIND.CALL_RETURN,
                                key=util.read_stmt_field(defined_symbol.name),
                            )
                        ],
                    )
                    self.update_access_path_state_id(unsolved_state_index)
                    defined_symbol.states = {unsolved_state_index}
                return P2ResultFlag()

        return self.compute_target_method_states(
            stmt_id, stmt, status, in_states, callee_method_ids, defined_symbol, args, this_state_set
        )

    def is_abstract_method(self, callee_method_ids):
        for stmt_id in callee_method_ids:
            stmt = self.loader.get_stmt_gir(stmt_id)
            # why stmt.attrs is nan
            if isinstance(stmt.attrs, str) and 'abstract' in stmt.attrs:
                return True
        return False

    def compute_target_method_states(
        self, stmt_id, stmt, status, in_states,
        callee_method_ids, defined_symbol, args,
        this_state_set=set(), new_object_flag=False
    ):
        # Compute callees' summaries
        callee_ids_to_be_analyzed = []
        caller_id = self.frame.method_id
        if config.DEBUG_FLAG:
            util.debug(f"positional_args of stmt <{stmt_id}>: {args.positional_args}")
            util.debug(f"named_args of stmt <{stmt_id}>: {args.named_args}")
            util.debug(f"callee_method_ids: {callee_method_ids}")

        for each_callee_id in callee_method_ids:
            if self.call_graph:
                if not self.call_graph.has_specific_weight(self.frame.method_id, each_callee_id, stmt_id):
                    self.call_graph.add_edge(int(self.frame.method_id), int(each_callee_id), int(stmt_id))

            if not (each_callee_id in self.analyzed_method_list or self.frame_stack.has_method_id(each_callee_id)):
                callee_ids_to_be_analyzed.append(each_callee_id)
            # prepare callee parameters
            parameters = self.prepare_parameters(each_callee_id)
            if config.DEBUG_FLAG:
                util.debug(f"parameters of callee <{each_callee_id}>: {parameters}")
            new_call_site = CallSite(caller_id, stmt_id, each_callee_id)
            parameter_mapping_list = self.loader.get_parameter_mapping_p2(new_call_site)
            if util.is_empty(parameter_mapping_list):
                parameter_mapping_list = []
                self.map_arguments(args, parameters, parameter_mapping_list, new_call_site)

        # print(f"callee_ids_to_be_analyzed: {callee_ids_to_be_analyzed}")
        # print(f"analyzed_method_list: {self.analyzed_method_list}")
        # print(f"frame_stack.method_ids: {self.frame_stack.method_ids}")

        if len(callee_ids_to_be_analyzed) != 0:
            self.frame.stmts_with_symbol_update.add(stmt_id)
            if config.DEBUG_FLAG:
                util.debug(f"callee need to be analyzed: {callee_ids_to_be_analyzed}")

            return P2ResultFlag(
                interruption_flag=True,
                interruption_data=InterruptionData(
                    caller_id=self.frame.method_id,
                    call_stmt_id=stmt_id,
                    callee_ids=callee_ids_to_be_analyzed,
                )
            )

        # Here we link args and parameters
        # argument : <position, name, symbol_id#1, states#1>
        #               ^        ^            ^             ^
        #               |        |            |             |
        #               v        v            v             v
        # parameter: <position, name, symbol_id#2, states#2>
        #            \__________________________________________/
        #                             |
        #                             v
        # Summary  :      state-level semantic summary

        if len(callee_method_ids) == 0:
            name_index = status.used_symbols[0]
            name_symbol = self.frame.symbol_state_space[name_index]
            return_access_path = []
            for index in name_symbol.states:
                name_state = self.frame.symbol_state_space[index]
                if not isinstance(name_state, State) or len(name_state.access_path) == 0:
                    continue
                return_access_path = copy.deepcopy(name_state.access_path)

            if stmt.operation == "call_stmt":
                return_access_path.append(AccessPoint(
                    kind=ACCESS_POINT_KIND.CALL_RETURN,
                    key=name_symbol.name
                ))
            elif stmt.operation == "object_call_stmt":
                field_index = status.used_symbols[1]
                field_state = self.frame.symbol_state_space[field_index]

                return_access_path.append(AccessPoint(
                    kind=ACCESS_POINT_KIND.FIELD_ELEMENT,
                    key=field_state.value
                ))
            unsolved_state_index = self.create_state_and_add_space(
                status, stmt_id,
                source_symbol_id=defined_symbol.symbol_id,
                state_type=STATE_TYPE_KIND.UNSOLVED,
                data_type=util.read_stmt_field(stmt.data_type),  # LianInternal.RETURN_VALUE,
                access_path=return_access_path
            )
            self.update_access_path_state_id(unsolved_state_index)
            defined_symbol.states = {unsolved_state_index}

            return P2ResultFlag()

        # args = self.prepare_args(stmt_id, stmt, status, in_states, args_state_set)
        # if config.DEBUG_FLAG:
        #     util.debug(f"positional_args of stmt <{stmt_id}>: {args.positional_args}")
        #     util.debug(f"named_args of stmt <{stmt_id}>: {args.named_args}")

        for each_callee_id in callee_method_ids:
            # prepare callee summary template and compact space
            callee_summary = self.loader.get_method_summary_template(each_callee_id)
            if util.is_empty(callee_summary):
                # print(f"\neach_callee_id: {each_callee_id}")
                continue
            callee_summary = callee_summary.copy()

            callee_compact_space: SymbolStateSpace = self.loader.get_symbol_state_space_summary_p2(each_callee_id)
            if util.is_empty(callee_compact_space):
                continue
            callee_compact_space = callee_compact_space.copy()

            self.apply_callee_semantic_summary(
                stmt_id, stmt, each_callee_id, args, callee_summary,
                callee_compact_space, this_state_set, new_object_flag
            )

        return P2ResultFlag()

    def global_stmt_state(self, stmt_id, stmt, status: StmtStatus, in_states):
        global_symbol_index = status.defined_symbol
        # self.frame_stack.global_bit_vector_manager.add_bit_id()
        global_symbol = self.frame.symbol_state_space[global_symbol_index]
        if not isinstance(global_symbol, Symbol):
            return P2ResultFlag()

        state_index = self.create_state_and_add_space(
            status, stmt_id, source_symbol_id=global_symbol.symbol_id,
            data_type=util.read_stmt_field(stmt.data_type),
            state_type=STATE_TYPE_KIND.ANYTHING,
            access_path=[AccessPoint(
                kind=ACCESS_POINT_KIND.EXTERNAL,
                key=util.read_stmt_field(stmt.name),
            )]
        )
        self.update_access_path_state_id(state_index)
        global_symbol.states = {state_index}

        return P2ResultFlag()

    def nonlocal_stmt_state(self, stmt_id, stmt, status: StmtStatus, in_states):
        defined_symbol = self.frame.symbol_state_space[status.defined_symbol]
        if not isinstance(defined_symbol, Symbol):
            return P2ResultFlag()

        state_index = self.create_state_and_add_space(
            status, stmt_id,
            source_symbol_id=defined_symbol.symbol_id,
            data_type=util.read_stmt_field(stmt.data_type),
            state_type=STATE_TYPE_KIND.ANYTHING,
            access_path=[AccessPoint(
                kind=ACCESS_POINT_KIND.EXTERNAL,
                key=util.read_stmt_field(stmt.name),
            )]
        )
        self.update_access_path_state_id(state_index)
        defined_symbol.states = {state_index}

        return P2ResultFlag()

    # TODO:
    def type_cast_stmt_state(self, stmt_id, stmt, status: StmtStatus, in_states):
        source_symbol_index = status.used_symbols[0]
        source_symbol = self.frame.symbol_state_space[source_symbol_index]
        source_states = self.read_used_states(source_symbol_index, in_states)

        defined_symbol_index = status.defined_symbol
        defined_symbol = self.frame.symbol_state_space[defined_symbol_index]
        if not isinstance(defined_symbol, Symbol):
            return P2ResultFlag()

        data_type = util.read_stmt_field(stmt.data_type)

        defined_states = set()
        for source_state_index in source_states:
            source_state = self.frame.symbol_state_space[source_state_index]
            if not isinstance(source_state, State):
                continue

            if source_state.data_type == str(data_type):
                defined_states.add(source_state_index)

        if len(defined_states) == 0:
            self.sfg.add_edge(
                self.make_used_symbol_sfg_node(source_symbol_index),
                self.make_symbol_sfg_node(defined_symbol_index),
                self.make_stmt_sfg_edge(stmt_id, edge_type=SFG_EDGE_KIND.SYMBOL_FLOW, name=stmt.operation)
            )
            source_symbol_id = -1
            if isinstance(source_symbol, Symbol):
                source_symbol_id = source_symbol.symbol_id
            new_state = self.create_state_and_add_space(
                status, stmt_id, source_symbol_id=source_symbol_id,
                data_type=str(data_type),
                state_type=STATE_TYPE_KIND.ANYTHING,
            )
            defined_states = {new_state}

        defined_symbol.states = defined_states
        return P2ResultFlag()

    # TODO:
    def type_alias_decl_state(self, stmt_id, stmt, status: StmtStatus, in_states):
        source_symbol_index = status.used_symbols[0]
        source_symbol = self.frame.symbol_state_space[source_symbol_index]
        if not isinstance(source_symbol, Symbol):
            return P2ResultFlag()

        defined_symbol_index = status.defined_symbol
        defined_symbol = self.frame.symbol_state_space[defined_symbol_index]
        if not isinstance(defined_symbol, Symbol):
            return P2ResultFlag()

        data_type = util.read_stmt_field(stmt.data_type)
        state_index = self.create_state_and_add_space(
            status, stmt_id, source_symbol_id=source_symbol.symbol_id,
            data_type=str(data_type)
        )
        defined_symbol.states = {state_index}
        return P2ResultFlag()

    def phi_stmt_state(self, stmt_id, stmt, status: StmtStatus, in_states):
        used_symbol_indexes = status.used_symbols
        defined_symbol_index = status.defined_symbol
        defined_symbol = self.frame.symbol_state_space[defined_symbol_index]
        if not isinstance(defined_symbol, Symbol):
            return P2ResultFlag()

        for each_index in used_symbol_indexes:
            states = self.read_used_states(each_index, in_states)
            defined_symbol.states.update(states)

        return P2ResultFlag()

    def namespace_decl_stmt_state(self, stmt_id, stmt, status: StmtStatus, in_states):
        defined_symbol_index = status.defined_symbol
        defined_symbol = self.frame.symbol_state_space[defined_symbol_index]
        if not isinstance(defined_symbol, Symbol):
            return P2ResultFlag()

        state_index = self.create_state_and_add_space(
            status, stmt_id,
            source_symbol_id=defined_symbol.symbol_id,
            data_type=LIAN_INTERNAL.NAMESPACE_DECL,
            value=stmt_id,
            access_path=[AccessPoint(
                key=util.read_stmt_field(stmt.name),
            )]
        )
        self.update_access_path_state_id(state_index)
        defined_symbol.states = {state_index}

        return P2ResultFlag()

    def class_decl_stmt_state(self, stmt_id, stmt, status: StmtStatus, in_states):
        defined_symbol = self.frame.symbol_state_space[status.defined_symbol]
        if not isinstance(defined_symbol, Symbol):
            return P2ResultFlag()

        state_index = self.create_state_and_add_space(
            status, stmt_id,
            source_symbol_id=defined_symbol.symbol_id,
            data_type=LIAN_INTERNAL.CLASS_DECL,
            value=stmt_id,
            access_path=[AccessPoint(
                key=util.read_stmt_field(stmt.name),
            )]
        )
        self.update_access_path_state_id(state_index)
        defined_symbol.states = {state_index}

        return P2ResultFlag()

    def parameter_decl_stmt_state(self, stmt_id, stmt, status: StmtStatus, in_states):
        defined_symbol_index = status.defined_symbol
        parameter_name_symbol = self.frame.symbol_state_space[defined_symbol_index]
        if isinstance(parameter_name_symbol, Symbol):
            parameter_state_index = self.create_state_and_add_space(
                status, stmt_id,
                source_symbol_id=parameter_name_symbol.symbol_id,
                data_type=util.read_stmt_field(stmt.data_type),
                state_type=STATE_TYPE_KIND.ANYTHING,
                access_path=[AccessPoint(
                    key=util.read_stmt_field(stmt.name),
                )]
            )
            self.update_access_path_state_id(parameter_state_index)
            parameter_name_symbol.states = {parameter_state_index}

            if len(status.used_symbols) > 0:
                default_value_index = status.used_symbols[0]
                default_value = self.frame.symbol_state_space[default_value_index]
                if isinstance(default_value, Symbol):
                    value_state_indexes = self.read_used_states(default_value_index, in_states)
                    for default_value_state_index in value_state_indexes:
                        # self.tag_key_state_flag(stmt_id, default_value.symbol_id, default_value_state_index)
                            util.add_to_dict_with_default_set(
                                self.frame.method_summary_template.used_external_symbols,
                                default_value.symbol_id,
                                {default_value_state_index}
                            )
                else:
                    parameter_name_symbol.states.add(default_value_index)

        return P2ResultFlag()

    def variable_decl_stmt_state(self, stmt_id, stmt, status: StmtStatus, in_states):
        # variable_name_symbol: Symbol = self.frame.symbol_state_space[status.defined_symbol]
        # variable_state_index = self.create_state_and_add_space(
        #     status, stmt_id,
        #     source_symbol_id=variable_name_symbol.symbol_id,
        #     data_type = util.read_stmt_field(stmt.data_type),
        #     state_type = StateTypeKind.UNINIT,
        #     access_path=[AccessPoint(
        #         key = util.read_stmt_field(stmt.name),
        #     )]
        # )
        # self.update_access_path(variable_state_index)
        # variable_name_symbol.states = {variable_state_index}

        return P2ResultFlag()

    def method_decl_stmt_state(self, stmt_id, stmt, status: StmtStatus, in_states):
        method_name_symbol = self.frame.symbol_state_space[status.defined_symbol]
        if isinstance(method_name_symbol, Symbol):
            method_state_index = self.create_state_and_add_space(
                status,
                stmt_id,
                source_symbol_id=method_name_symbol.symbol_id,
                value=stmt_id,
                data_type=LIAN_INTERNAL.METHOD_DECL,
                access_path=[AccessPoint(
                    key=util.read_stmt_field(stmt.name),
                )]
            )
            self.update_access_path_state_id(method_state_index)
            method_name_symbol.states = {method_state_index}

        return P2ResultFlag()

    def new_object_stmt_state(self, stmt_id, stmt, status: StmtStatus, in_states):
        defined_symbol_index = status.defined_symbol
        defined_symbol = self.frame.symbol_state_space[defined_symbol_index]
        if not isinstance(defined_symbol, Symbol):
            return P2ResultFlag()
        type_index = status.used_symbols[0]
        type_states = self.read_used_states(type_index, in_states)
        args = self.prepare_args(stmt_id, stmt, status, in_states)
        p2result_flag = P2ResultFlag()
        type_state_to_new_index = {}
        type_state_to_callee_methods = {}

        event = EventData(
            self.lang,
            EVENT_KIND.P2STATE_NEW_OBJECT_BEFORE,
            {
                "resolver": self.resolver,
                "stmt_id": stmt_id,
                "stmt": stmt,
                "status": status,
                "frame": self.frame,
                "in_states": in_states,
                "state_analysis": self,
                "defined_symbol": defined_symbol,
                "defined_states": defined_symbol.states,
                "type_states": type_states,
                "type_state_to_new_index": type_state_to_new_index,
                "type_state_to_callee_methods": type_state_to_callee_methods,
                "p2result_flag": p2result_flag,
                "args": args
            }
        )
        app_return = self.event_manager.notify(event)

        # 如果需要先去分析callee，先中断
        if p2result_flag.interruption_flag:
            return p2result_flag

        if er.is_event_unprocessed(app_return):
            for each_state_index in type_states:
                each_state = self.frame.symbol_state_space[each_state_index]
                init_state_index = self.create_state_and_add_space(
                    status,
                    stmt_id,
                    source_symbol_id=defined_symbol.symbol_id,
                    data_type=LIAN_INTERNAL.CLASS_DECL,
                    value=each_state.value,
                    parent_state=each_state,
                    parent_state_index=each_state_index,
                    access_path=[AccessPoint(
                        key=each_state.value,
                    )]
                )
                self.update_access_path_state_id(init_state_index)
                defined_symbol.states.add(init_state_index)

            # print("new_object_stmt_state@ create a default_state for new object", defined_symbol.states)

        p2result_flag = P2ResultFlag()
        event = EventData(
            self.lang,
            EVENT_KIND.P2STATE_NEW_OBJECT_AFTER,
            {
                "resolver": self.resolver,
                "stmt_id": stmt_id,
                "stmt": stmt,
                "status": status,
                "frame": self.frame,
                "in_states": in_states,
                "state_analysis": self,
                "defined_symbol": defined_symbol,
                "defined_states": defined_symbol.states,
                "type_states": type_states,
                "type_state_to_new_index": type_state_to_new_index,
                "type_state_to_callee_methods": type_state_to_callee_methods,
                "p2result_flag": p2result_flag,
                "args": args
            }
        )
        self.event_manager.notify(event)

        return p2result_flag

    def new_array_stmt_state(self, stmt_id, stmt, status: StmtStatus, in_states):
        defined_symbol_index = status.defined_symbol
        defined_symbol = self.frame.symbol_state_space[defined_symbol_index]
        if not isinstance(defined_symbol, Symbol):
            return P2ResultFlag()
        init_state_index = self.create_state_and_add_space(
            status, stmt_id, source_symbol_id=defined_symbol.symbol_id, data_type=LIAN_INTERNAL.ARRAY,
            access_path=[AccessPoint(
                key=util.read_stmt_field(stmt.data_type),
            )]
        )
        self.update_access_path_state_id(init_state_index)
        defined_symbol.states = {init_state_index}

        return P2ResultFlag()

    def new_record_stmt_state(self, stmt_id, stmt, status: StmtStatus, in_states):
        defined_symbol_index = status.defined_symbol
        defined_symbol = self.frame.symbol_state_space[defined_symbol_index]
        if not isinstance(defined_symbol, Symbol):
            return P2ResultFlag()

        init_state_index = self.create_state_and_add_space(
            status, stmt_id, source_symbol_id=defined_symbol.symbol_id, data_type=LIAN_INTERNAL.RECORD,
            access_path=[AccessPoint(
                key=util.read_stmt_field(stmt.data_type),
            )]
        )
        self.update_access_path_state_id(init_state_index)
        defined_symbol.states = {init_state_index}

        return P2ResultFlag()

    def new_set_stmt_state(self, stmt_id, stmt, status: StmtStatus, in_states):
        defined_symbol_index = status.defined_symbol
        defined_symbol = self.frame.symbol_state_space[defined_symbol_index]
        if not isinstance(defined_symbol, Symbol):
            return P2ResultFlag()

        init_state_index = self.create_state_and_add_space(
            status, stmt_id, source_symbol_id=defined_symbol.symbol_id, data_type=LIAN_INTERNAL.SET,
            access_path=[AccessPoint(
                key=util.read_stmt_field(stmt.data_type),
            )]
        )
        self.update_access_path_state_id(init_state_index)
        defined_symbol.states = {init_state_index}

        return P2ResultFlag()

    def addr_of_stmt_state(self, stmt_id, stmt, status: StmtStatus, in_states):
        source_symbol_index = status.used_symbols[0]
        source_symbol: Symbol = self.frame.symbol_state_space[source_symbol_index]
        defined_symbol_index = status.defined_symbol
        defined_symbol: Symbol = self.frame.symbol_state_space[defined_symbol_index]
        state_index = self.create_state_and_add_space(
            status, stmt_id, source_symbol_id=stmt_id, value=source_symbol.symbol_id,
            access_path=self.copy_and_extend_access_path(
                source_symbol.access_path,
                AccessPoint(kind=ACCESS_POINT_KIND.ADDR_OF)
            )
        )
        self.update_access_path_state_id(state_index)
        defined_symbol.states = {state_index}

        return P2ResultFlag()

    def mem_read_stmt_state(self, stmt_id, stmt, status: StmtStatus, in_states):
        address_index = status.used_symbols[0]
        address_symbol: Symbol = self.frame.symbol_state_space[address_index]
        old_id_list = self.obtain_states(address_index)
        address_id_list = self.read_used_states(address_index, in_states)

        #print("address_id_list:", address_id_list)

        target_states = set()
        reachable_symbol_defs = self.frame.symbol_bit_vector_manager.explain(status.in_symbol_bits)
        for symbol_id_index in address_id_list:
            symbol_id_state = self.frame.symbol_state_space[symbol_id_index]
            if not isinstance(symbol_id_state, State):
                continue

            if symbol_id_state.value in self.frame.defined_symbols:
                index = self.create_state_and_add_space(
                    status,
                    stmt_id,
                    source_symbol_id=stmt_id,
                    state_type=STATE_TYPE_KIND.UNSOLVED,
                    parent_state=symbol_id_state,
                    parent_state_index=symbol_id_index
                )
                target_states.add(index)
                continue

            if symbol_id_state.state_type == STATE_TYPE_KIND.ANYTHING:
                index = self.create_state_and_add_space(
                    status,
                    stmt_id,
                    source_symbol_id=symbol_id_state.source_symbol_id,
                    parent_state=symbol_id_state,
                    parent_state_index=symbol_id_index,
                    access_path=self.copy_and_extend_access_path(
                        symbol_id_state.access_path,
                        AccessPoint(
                            kind=ACCESS_POINT_KIND.MEM_READ
                        )
                    )
                )
                self.update_access_path_state_id(index)
                target_states.add(index)
                continue

            symbol_id = symbol_id_state.value
            all_defs = self.frame.defined_symbols[symbol_id]
            all_defs &= reachable_symbol_defs
            for def_stmt_id, def_source in all_defs:
                reachable_status = self.frame.stmt_id_to_status[def_stmt_id]
                defined_symbol = self.frame.symbol_state_space[reachable_status.defined_symbol]
                flag = True
                if util.is_available(defined_symbol) and defined_symbol.symbol_id == def_source:
                    target_states.update(defined_symbol.states)
                    flag = False
                if flag:
                    if def_source in reachable_status.implicitly_defined_symbols:
                        index = reachable_status.implicitly_defined_symbols[def_source]
                        defined_symbol = self.frame.symbol_state_space[index]
                        if util.is_available(defined_symbol):
                            target_states.update(defined_symbol.states)

        defined_symbol = self.frame.symbol_state_space[status.defined_symbol]
        defined_symbol.states = target_states

        return P2ResultFlag()

    def mem_write_stmt_state(self, stmt_id, stmt, status: StmtStatus, in_states):
        address_symbol_index = status.used_symbols[0]
        source_symbol_index = status.used_symbols[1]
        # address_symbol = self.frame.symbol_state_space[address_symbol_index]
        # old_source_states = self.obtain_states(source_symbol_index)
        source_states = self.read_used_states(source_symbol_index, in_states)
        address_states = self.read_used_states(address_symbol_index, in_states)

        implicitly_defined_symbols = []

        reachable_defs = self.frame.symbol_bit_vector_manager.explain(status.in_symbol_bits)
        for state_index in address_states:
            state = self.frame.symbol_state_space[state_index]
            if util.is_empty(state):
                continue
            symbol_id = state.value
            if symbol_id not in self.frame.defined_symbols:
                # TODO: need to deal with such a case
                continue
            all_defs = self.frame.defined_symbols[symbol_id]
            all_defs &= reachable_defs

            for def_stmt_id, def_source in all_defs:
                target_status = self.frame.stmt_id_to_status[def_stmt_id]
                defined_symbol = self.frame.symbol_state_space[target_status.defined_symbol]
                if util.is_available(defined_symbol):
                    if defined_symbol.symbol_id == def_source:
                        new_symbol = defined_symbol.copy(stmt_id)
                        new_symbol.states = source_states
                        implicitly_defined_symbols[def_source] = self.frame.symbol_state_space.add(new_symbol)
                        continue

                if def_source in target_status.implicitly_defined_symbols:
                    index = target_status.implicitly_defined_symbols[def_source]
                    defined_symbol = self.frame.symbol_state_space[index]
                    if util.is_available(defined_symbol):
                        new_symbol = defined_symbol.copy(stmt_id)
                        new_symbol.states = source_states
                        implicitly_defined_symbols[def_source] = self.frame.symbol_state_space.add(new_symbol)

        status.implicitly_defined_symbols = implicitly_defined_symbols

        return P2ResultFlag()

    def common_element_read_stmt_state(self, stmt_id, stmt, status: StmtStatus, in_states):
        # 统一建模为 receiver field
        # [例] target = receiver[field], target = receiver.field
        field_index = status.used_symbols[1]
        field_states = self.read_used_states(field_index, in_states)
        is_array_operation = False

        for field_state_id in field_states:
            field_state = self.frame.symbol_state_space[field_state_id]
            if not isinstance(field_state, State):
                continue

            if field_state.data_type == LIAN_INTERNAL.INT or isinstance(field_state.value, int):
                is_array_operation = True
                break

        if is_array_operation:
            return self.array_read_stmt_state(stmt_id, stmt, status, in_states)
        return self.field_read_stmt_state(stmt_id, stmt, status, in_states)

    def common_element_write_stmt_state(self, stmt_id, stmt, status: StmtStatus, in_states):
        # 统一建模为 receiver field source
        # [例] receiver[field] = source, receiver.field = source
        field_index = status.used_symbols[1]
        field_states = self.read_used_states(field_index, in_states)
        is_array_operation = False
        for field_state_index in field_states:
            field_state = self.frame.symbol_state_space[field_state_index]
            if not isinstance(field_state, State):
                continue
            if re.match(r'^-?\d+$', (str(field_state.value))):  # 判断field是不是一个数字
                is_array_operation = True
                break

        if is_array_operation:
            return self.array_write_stmt_state(stmt_id, stmt, status, in_states)
        return self.field_write_stmt_state(stmt_id, stmt, status, in_states)

    def is_state_array_empty(self, state: State):
        if not state.array:
            return True
        for element in state.array:
            if element:
                return False
        return True

    def array_read_stmt_state(self, stmt_id, stmt, status: StmtStatus, in_states):
        defined_symbol_index = status.defined_symbol
        defined_symbol: Symbol = self.frame.symbol_state_space[defined_symbol_index]
        if not isinstance(defined_symbol, Symbol):
            return P2ResultFlag()

        defined_states = set()
        # new_array_symbol = None
        # new_array_symbol_index = None

        array_symbol_index = status.used_symbols[0]
        index_symbol_index = status.used_symbols[1]
        array_symbol: Symbol = self.frame.symbol_state_space[array_symbol_index]
        if not isinstance(array_symbol, Symbol):
            return P2ResultFlag()

        array_state_indexes = self.read_used_states(array_symbol_index, in_states)
        index_state_indexes = self.read_used_states(index_symbol_index, in_states)
        index_values = set()

        for index_state_id in index_state_indexes:
            index_state = self.frame.symbol_state_space[index_state_id]
            if not isinstance(index_state, State):
                continue

            this_value = index_state.value
            if this_value and len(str(this_value)) > 0 and re.match(r'^-?\d+$', (str(this_value))):
                index_values.add(int(this_value))
            else:
                index_values = set()
                break

        if len(index_values) == 0:
            # collect all states in array
            defined_states = set()
            for each_array_state_index in array_state_indexes:
                array_state = self.frame.symbol_state_space[each_array_state_index]
                if not isinstance(array_state, State):
                    continue
                if array_state.tangping_elements:
                    defined_states.update(array_state.tangping_elements)
                elif array_state.array:
                    for tmp_value_set in array_state.array:
                        defined_states.update(tmp_value_set)
                else:
                    self.make_state_index_tangping_and_ensure_not_empty(each_array_state_index, status, stmt_id, stmt)
                    defined_states.update(array_state.tangping_elements)

        else:
            # find the array index values
            for each_array_state_index in array_state_indexes:
                array_state = self.frame.symbol_state_space[each_array_state_index]
                if not isinstance(array_state, State):
                    continue

                # 躺平，返回整个数组
                if array_state.tangping_flag:
                    defined_states.update(array_state.tangping_elements)
                    continue
                if self.is_state_array_empty(array_state):
                    self.make_state_index_tangping_and_ensure_not_empty(each_array_state_index, status, stmt_id, stmt)
                    defined_states.update(array_state.tangping_elements)
                    continue

                # for index_value in index_set:
                current_round_state_collection = set()
                for each_index_value in index_values:
                    array_length = len(array_state.array)
                    # 处理下标是负数时的情况
                    if each_index_value >= 0:
                        real_index_value = each_index_value
                    else:
                        real_index_value = array_length + each_index_value

                    if (
                        real_index_value >= 0 and
                        real_index_value < array_length and
                        array_state.array[real_index_value]
                    ):
                        array_index_set: set = array_state.array[real_index_value]
                        for element_symbol_index in array_index_set:
                            current_round_state_collection.add(element_symbol_index)

                if len(current_round_state_collection) == 0:
                    self.make_state_index_tangping_and_ensure_not_empty(each_array_state_index, status, stmt_id, stmt)
                    current_round_state_collection.update(array_state.tangping_elements)
                defined_states.update(current_round_state_collection)

        if defined_states:
            defined_symbol.states = defined_states
        else:
            self.sfg.add_edge(
                self.make_used_symbol_sfg_node(array_symbol_index),
                self.make_symbol_sfg_node(defined_symbol_index),
                self.make_stmt_sfg_edge(stmt_id, SFG_EDGE_KIND.SYMBOL_FLOW, name=stmt.operation)
            )
            self.sfg.add_edge(
                self.make_used_symbol_sfg_node(index_symbol_index),
                self.make_symbol_sfg_node(defined_symbol_index),
                self.make_stmt_sfg_edge(stmt_id, SFG_EDGE_KIND.SYMBOL_FLOW, name=stmt.operation)
            )
        return P2ResultFlag()

    def array_write_stmt_state(self, stmt_id, stmt, status: StmtStatus, in_states):
        array_index = status.used_symbols[0]
        index_index = status.used_symbols[1]
        source_index = status.used_symbols[2]

        array_states = self.read_used_states(array_index, in_states)
        index_states = self.read_used_states(index_index, in_states)
        source_states = self.read_used_states(source_index, in_states)

        defined_symbol_index = status.defined_symbol
        defined_array_symbol = self.frame.symbol_state_space[defined_symbol_index]
        if not isinstance(defined_array_symbol, Symbol):
            return P2ResultFlag()

        defined_states = set()
        index_values = set()
        for index_state_id in index_states:
            index_state = self.frame.symbol_state_space[index_state_id]
            if not isinstance(index_state, State):
                continue

            this_value = index_state.value
            if this_value and  re.match(r'^-?\d+$', (str(this_value))) and this_value != '':
                index_values.add(int(this_value))
            else:
                index_values = set()
                break

        if len(index_values) == 0:
            # collect all states in array
            defined_states = set()
            for each_array_state_index in array_states:
                array_state = self.frame.symbol_state_space[each_array_state_index]
                if not isinstance(array_state, State):
                    continue
                new_array_state_index = self.create_copy_of_state_and_add_space(status, stmt_id, each_array_state_index, stmt)
                new_array_state: State = self.frame.symbol_state_space[new_array_state_index]

                self.make_state_tangping(new_array_state)
                new_array_state.tangping_elements.update(source_states)
                defined_states.add(new_array_state_index)
        else:
            for array_state_id in array_states:
                array_state = self.frame.symbol_state_space[array_state_id]
                if not isinstance(array_state, State):
                    continue

                tangping_flag = array_state.tangping_flag
                tmp_array = []
                if not tangping_flag:
                    tmp_array = array_state.array.copy()
                    for each_index_value in index_values:
                        array_length = len(tmp_array)
                        if each_index_value < 0:
                            each_index_value = array_length + each_index_value

                        # 数组下标越界，将数组扩展
                        if not util.add_to_list_with_default_set(tmp_array, each_index_value, source_states):
                            tangping_flag = True

                if tangping_flag or self.is_state_array_empty(array_state):
                    new_array_state_index = self.create_copy_of_state_and_add_space(status, stmt_id, array_state_id, stmt)
                    new_array_state: State = self.frame.symbol_state_space[new_array_state_index]

                    self.make_state_tangping(new_array_state)
                    new_array_state.tangping_elements.update(source_states)
                    for source_state in source_states:
                        self.sfg.add_edge(
                            self.make_state_sfg_node(new_array_state_index),
                            self.make_state_sfg_node(source_state),
                            self.make_stmt_sfg_edge(stmt_id, SFG_EDGE_KIND.STATE_INCLUSION, name=stmt.operation)
                        )
                    defined_states.add(new_array_state_index)

                elif tmp_array != array_state.array:
                    new_array_state_index = self.create_copy_of_state_and_add_space(status, stmt_id, array_state_id, stmt)
                    new_array_state: State = self.frame.symbol_state_space[new_array_state_index]
                    new_array_state.array = tmp_array
                    defined_states.add(new_array_state_index)

        defined_array_symbol.states = defined_states

        if self.frame.stmt_counters[stmt_id] == config.FIRST_ROUND and len(defined_states) == 0:
            self.sfg.add_edge(
                self.make_used_symbol_sfg_node(source_index),
                self.make_symbol_sfg_node(array_index),
                self.make_stmt_sfg_edge(stmt_id, SFG_EDGE_KIND.SYMBOL_FLOW, name=stmt.operation)
            )

        return P2ResultFlag()

    def array_insert_stmt_state(self, stmt_id, stmt, status: StmtStatus, in_states):
        array_index = status.used_symbols[0]
        source_index = status.used_symbols[1]
        index_index = status.used_symbols[2]

        array_states = self.read_used_states(array_index, in_states)
        source_states = self.read_used_states(source_index, in_states)
        index_states = self.read_used_states(index_index, in_states)

        defined_array_symbol = self.frame.symbol_state_space[status.defined_symbol]
        if not isinstance(defined_array_symbol, Symbol):
            return P2ResultFlag()

        defined_symbol_states = set()

        for array_state_id in array_states:
            array_state = self.frame.symbol_state_space[array_state_id]
            if not (array_state and isinstance(array_state, State)):
                continue

            tmp_array = None

            tangping_flag = array_state.tangping_flag
            if not tangping_flag:
                tmp_array = array_state.array.copy()
                for index_state_id in index_states:
                    index_state = self.frame.symbol_state_space[index_state_id]
                    if not (index_state and isinstance(index_state, State)):
                        continue
                    index_value = index_state.value

                    if index_value.isdigit():
                        index_value = int(index_value)
                        array_length = len(tmp_array)

                        # 处理下标是负数时的情况
                        if index_value >= 0:
                            real_index_value = index_value
                        else:
                            real_index_value = array_length + index_value

                        # 数组下标越界，将数组扩展
                        if real_index_value >= array_length:
                            tmp_array.extend([set() for _ in range(real_index_value + 1 - array_length)])

                        tmp_array.insert(real_index_value, source_states)

                    # 下标值非法，将数组变成崩溃状态
                    else:
                        tangping_flag = True
                        break

            if tangping_flag:
                new_array_state_index = self.create_copy_of_state_and_add_space(status, stmt_id, array_state_id, stmt)
                new_array_state: State = self.frame.symbol_state_space[new_array_state_index]
                self.make_state_tangping(new_array_state)
                new_array_state.tangping_elements.update(source_states)
                defined_symbol_states.add(new_array_state_index)

            elif tmp_array != array_state.array:
                new_array_state_index = self.create_copy_of_state_and_add_space(status, stmt_id, array_state_id, stmt)
                new_array_state: State = self.frame.symbol_state_space[new_array_state_index]
                new_array_state.array = tmp_array
                defined_symbol_states.add(new_array_state_index)

        defined_array_symbol.states = defined_symbol_states
        if self.frame.stmt_counters[stmt_id] == config.FIRST_ROUND:
            self.sfg.add_edge(
                self.make_used_symbol_sfg_node(source_index),
                self.make_symbol_sfg_node(array_index),
                self.make_stmt_sfg_edge(stmt_id, SFG_EDGE_KIND.SYMBOL_FLOW, name=stmt.operation)
            )
        return P2ResultFlag()

    def array_append_stmt_state(self, stmt_id, stmt, status: StmtStatus, in_states):
        used_array_index = status.used_symbols[0]
        used_array_states: set = self.read_used_states(used_array_index, in_states)

        source_index = status.used_symbols[1]
        source_states: set = self.read_used_states(source_index, in_states)

        defined_array_symbol = self.frame.symbol_state_space[status.defined_symbol]
        if not isinstance(defined_array_symbol, Symbol):
            return P2ResultFlag()

        defined_symbol_states = set()

        for array_state_index in used_array_states:
            array_state = self.frame.symbol_state_space[array_state_index]
            if not (array_state and isinstance(array_state, State)):
                continue

            new_target_state_index = self.create_copy_of_state_and_add_space(status, stmt_id, array_state_index, stmt)
            new_target_state: State = self.frame.symbol_state_space[new_target_state_index]
            if array_state.tangping_flag:
                new_target_state.tangping_elements.update(source_states)
            else:
                new_target_state.array.append(source_states)
            defined_symbol_states.add(new_target_state_index)

        defined_array_symbol.states = defined_symbol_states
        if self.frame.stmt_counters[stmt_id] == config.FIRST_ROUND:
            self.sfg.add_edge(
                self.make_used_symbol_sfg_node(source_index),
                self.make_symbol_sfg_node(used_array_index),
                self.make_stmt_sfg_edge(stmt_id, SFG_EDGE_KIND.SYMBOL_FLOW, name=stmt.operation)
            )

        return P2ResultFlag()

    def array_extend_stmt_state(self, stmt_id, stmt, status: StmtStatus, in_states):
        used_array_index = status.used_symbols[0]
        used_array = self.frame.symbol_state_space[used_array_index]
        used_array_states: set = self.read_used_states(used_array_index, in_states)

        source_index = status.used_symbols[1]
        source_array = self.frame.symbol_state_space[used_array_index]
        source_states: set = self.read_used_states(source_index, in_states)

        defined_array_symbol = self.frame.symbol_state_space[status.defined_symbol]
        if not isinstance(defined_array_symbol, Symbol):
            return P2ResultFlag()

        defined_symbol_states = set()

        array_state_to_extend: list[set] = []
        for target_state_index in used_array_states:
            target_state = self.frame.symbol_state_space[target_state_index]
            if not (target_state and isinstance(target_state, State)):
                continue

            for source_state_index in source_states:
                source_state = self.frame.symbol_state_space[source_state_index]
                if not (source_state and isinstance(source_state, State)):
                    continue

                tmp_array = source_state.array
                for index in range(len(tmp_array)):
                    array_length = len(array_state_to_extend)
                    util.add_to_list_with_default_set(array_state_to_extend, index, tmp_array[index])

            if array_state_to_extend:
                new_target_state_index = self.create_copy_of_state_and_add_space(status, stmt_id, target_state_index, stmt)
                new_target_state: State = self.frame.symbol_state_space[new_target_state_index]
                if new_target_state.tangping_flag:
                    for element in array_state_to_extend:
                        new_target_state.tangping_elements.update(element)
                else:
                    new_target_state.array.extend(array_state_to_extend)
                defined_symbol_states.add(new_target_state_index)
            else:
                new_target_state_index = self.create_copy_of_state_and_add_space(status, stmt_id, target_state_index, stmt)
                new_target_state: State = self.frame.symbol_state_space[new_target_state_index]
                defined_symbol_states.add(new_target_state_index)

        defined_array_symbol.states = defined_symbol_states
        if self.frame.stmt_counters[stmt_id] == config.FIRST_ROUND:
            self.sfg.add_edge(
                self.make_used_symbol_sfg_node(source_index),
                self.make_symbol_sfg_node(used_array_index),
                self.make_stmt_sfg_edge(stmt_id, SFG_EDGE_KIND.SYMBOL_FLOW, name=stmt.operation)
            )
        return P2ResultFlag()

    def record_extend_stmt_state(self, stmt_id, stmt, status: StmtStatus, in_states):
        receiver_state_index = status.used_symbols[0]
        receiver_symbol = self.frame.symbol_state_space[receiver_state_index]
        receiver_states = self.read_used_states(receiver_state_index, in_states)

        source_index = status.used_symbols[1]
        source = self.frame.symbol_state_space[source_index]
        source_states = self.read_used_states(source_index, in_states)

        defined_symbol = self.frame.symbol_state_space[status.defined_symbol]  # copy on write

        for each_receiver_state_index in receiver_states:
            each_receiver_state = self.frame.symbol_state_space[each_receiver_state_index]
            if not isinstance(each_receiver_state, State):
                continue

            for source_state_index in source_states:
                each_source_state = self.frame.symbol_state_space[source_state_index]
                if not isinstance(each_source_state, State):
                    continue
                if each_source_state.tangping_flag:
                    new_receiver_state_index = self.create_copy_of_state_and_add_space(status, stmt_id, each_receiver_state_index, stmt)
                    new_receiver_state: State = self.frame.symbol_state_space[new_receiver_state_index]
                    if each_receiver_state.tangping_flag:
                        self.make_state_tangping(new_receiver_state)
                    new_receiver_state.tangping_elements.update(each_source_state.tangping_elements)
                    defined_symbol.states.add(new_receiver_state_index)
                    continue

                if each_receiver_state.tangping_flag:
                    new_receiver_state_index = self.create_copy_of_state_and_add_space(status, stmt_id, each_receiver_state_index, stmt)
                    new_receiver_state: State = self.frame.symbol_state_space[new_receiver_state_index]
                    for each_field_set in each_source_state.fields.values():
                        new_receiver_state.tangping_elements.update(each_field_set)
                    defined_symbol.states.add(new_receiver_state_index)
                    continue

                new_receiver_state_index = self.create_copy_of_state_and_add_space(status, stmt_id, each_receiver_state_index, stmt)
                new_receiver_state: State = self.frame.symbol_state_space[new_receiver_state_index]
                for each_field in each_source_state.fields:
                    util.add_to_dict_with_default_set(new_receiver_state.fields, each_field,
                                                      each_source_state.fields[each_field])
                defined_symbol.states.add(new_receiver_state_index)

        if self.frame.stmt_counters[stmt_id] == config.FIRST_ROUND:
            self.sfg.add_edge(
                self.make_used_symbol_sfg_node(source_index),
                self.make_symbol_sfg_node(receiver_state_index),
                self.make_stmt_sfg_edge(stmt_id, SFG_EDGE_KIND.SYMBOL_FLOW, name=stmt.operation)
            )
        return P2ResultFlag()

    def is_state_fields_empty(self, state: State):
        if not state.fields:
            return True
        for each_field_set in state.fields.values():
            if each_field_set:
                return False
        return True

    def change_field_read_receiver_state(
        self, stmt_id, stmt, status, receiver_symbol_index, receiver_state_index, receiver_state,
        field_name, defined_states, is_tangping=False
    ):
        if receiver_state.tangping_elements:
            defined_states.update(receiver_state.tangping_elements)
            return

        receiver_symbol = self.frame.symbol_state_space[receiver_symbol_index]
        # new_receiver_state_index = self.create_copy_of_state_and_add_space(status, stmt_id, receiver_state_index, stmt)

        if (not field_name) or is_tangping:
            # self.make_state_tangping(new_receiver_state)
            self.make_state_index_tangping_and_ensure_not_empty(receiver_state_index, status, stmt_id, stmt)

        if receiver_state.tangping_elements:
            defined_states.update(receiver_state.tangping_elements)

        elif defined_states:
            if receiver_state.tangping_flag:
                receiver_state.tangping_elements.update(defined_states)
            else:
                receiver_state.fields[field_name] = defined_states

        else:
            # [ah]
            # if receiver_symbol.name.startswith(LIAN_INTERNAL.VARIABLE_DECL_PREF):
            source_index = self.create_state_and_add_space(
                status, stmt_id=stmt_id,
                source_symbol_id=receiver_state.source_symbol_id,
                source_state_id=receiver_state.source_state_id,
                state_type=STATE_TYPE_KIND.ANYTHING,
                access_path=self.copy_and_extend_access_path(
                    original_access_path=receiver_state.access_path,
                    access_point=AccessPoint(
                        kind=ACCESS_POINT_KIND.FIELD_ELEMENT,
                        key=field_name
                    )
                ),
                parent_state=receiver_state,
                parent_state_index=receiver_state_index,
                edge_name=field_name,
            )
            # else:
            # source_index = self.create_state_and_add_space(
            #     status, stmt_id=stmt_id,
            #     source_symbol_id=receiver_state.source_symbol_id,
            #     source_state_id=receiver_state.source_state_id,
            #     state_type=STATE_TYPE_KIND.ANYTHING,
            #     access_path=[AccessPoint(
            #         kind=ACCESS_POINT_KIND.TOP_LEVEL,
            #         key=receiver_symbol.name
            #     ),
            #         AccessPoint(
            #             kind=ACCESS_POINT_KIND.FIELD_ELEMENT,
            #             key=field_name
            #         )],
            #     parent_state=receiver_state,
            #     parent_state_index=receiver_state_index,
            #     edge_name=field_name,
            # )
            self.update_access_path_state_id(source_index)

            if receiver_state.tangping_flag:
                receiver_state.tangping_elements.add(source_index)
            else:
                receiver_state.fields[field_name] = {source_index}

            defined_states.add(source_index)

        receiver_symbol.states.discard(receiver_state_index)
        receiver_symbol.states.add(receiver_state_index)

    def field_read_stmt_state(self, stmt_id, stmt, status: StmtStatus, in_states):
        receiver_symbol_index = status.used_symbols[0]
        field_index = status.used_symbols[1]
        receiver_symbol: Symbol = self.frame.symbol_state_space[receiver_symbol_index]
        field_symbol: Symbol = self.frame.symbol_state_space[field_index]
        if not isinstance(receiver_symbol, Symbol):  # TODO: 暂时未处理<string>.format的形式
            return
        receiver_states = self.read_used_states(receiver_symbol_index, in_states)
        field_states = self.read_used_states(field_index, in_states)
        defined_symbol_index = status.defined_symbol
        defined_symbol = self.frame.symbol_state_space[defined_symbol_index]
        if not isinstance(defined_symbol, Symbol):
            return P2ResultFlag()

        defined_states = set()

        event = EventData(
            self.lang,
            EVENT_KIND.P2STATE_FIELD_READ_BEFORE,
            {
                "resolver": self.resolver,
                "stmt_id": stmt_id,
                "stmt": stmt,
                "status": status,
                "receiver_states": receiver_states,
                "receiver_symbol": receiver_symbol,
                "frame": self.frame,
                "field_states": field_states,
                "in_states": in_states,
                "defined_symbol": defined_symbol,
                "state_analysis": self,
                "defined_states": defined_states
            }
        )
        app_return = self.event_manager.notify(event)
        if er.should_block_event_requester(app_return):
            defined_symbol.states = event.out_data.defined_states
            return P2ResultFlag()
        # else:
        # receiver_states = event.out_data.receiver_states

        for receiver_state_index in receiver_states:
            each_defined_states = set()
            each_receiver_state = self.frame.symbol_state_space[receiver_state_index]
            if not isinstance(each_receiver_state, State):
                continue
            if isinstance(receiver_symbol, Symbol):
                self.tag_key_state_flag(stmt_id, receiver_symbol.symbol_id, receiver_state_index)
            for each_field_state_index in field_states:
                each_field_state = self.frame.symbol_state_space[each_field_state_index]
                if not isinstance(each_field_state, State):
                    continue

                field_name = str(each_field_state.value)
                if each_receiver_state.tangping_elements:
                    each_defined_states.update(each_receiver_state.tangping_elements)
                    continue

                elif len(field_name) == 0 or each_field_state.state_type == STATE_TYPE_KIND.ANYTHING:
                    self.change_field_read_receiver_state(
                        stmt_id, stmt, status, receiver_symbol_index, receiver_state_index, each_receiver_state,
                        field_name, each_defined_states, is_tangping=True
                    )
                    continue

                elif field_name in each_receiver_state.fields:
                    index_set = each_receiver_state.fields.get(field_name, set())
                    each_defined_states.update(index_set)
                    continue

                # if field_name not in receiver_state.fields:
                elif self.is_state_a_unit(each_receiver_state):
                    import_graph = self.loader.get_import_graph()
                    import_symbols = self.loader.get_unit_export_symbols(each_receiver_state.value)
                    # [ah]
                    found_in_import_graph = False
                    # 解决file.symbol的情况，从import graph里找symbol
                    for u, v, wt in import_graph.edges(data=True):
                        real_name = wt.get("real_name", None)
                        if real_name == field_name:
                            symbol_type = wt.get("symbol_type", None)
                            if symbol_type == LIAN_SYMBOL_KIND.METHOD_KIND:
                                data_type = LIAN_INTERNAL.METHOD_DECL
                            elif symbol_type == LIAN_SYMBOL_KIND.CLASS_KIND:
                                data_type = LIAN_INTERNAL.CLASS_DECL
                            else:
                                data_type = LIAN_INTERNAL.UNIT
                
                            state_index = self.create_state_and_add_space(
                                status, stmt_id=stmt_id,
                                source_symbol_id=v,
                                source_state_id=each_receiver_state.source_state_id,
                                data_type=data_type,
                                value=v,
                                # access_path=self.copy_and_extend_access_path(
                                #     each_receiver_state.access_path,
                                #     AccessPoint(
                                #         key=real_name,
                                #     )
                                # )
                                access_path=[AccessPoint(key=real_name)]
                            )
                            found_in_import_graph = True
                            self.update_access_path_state_id(state_index)
                            each_defined_states.add(state_index)
                
                    if import_symbols and not found_in_import_graph:
                        for import_symbol in import_symbols:
                            if import_symbol.symbol_name == field_name:
                                if import_symbol.symbol_type == LIAN_SYMBOL_KIND.METHOD_KIND:
                                    data_type = LIAN_INTERNAL.METHOD_DECL
                                elif import_symbol.symbol_type == LIAN_SYMBOL_KIND.CLASS_KIND:
                                    data_type = LIAN_INTERNAL.CLASS_DECL
                                else:
                                    data_type = LIAN_INTERNAL.UNIT
                
                                state_index = self.create_state_and_add_space(
                                    status, stmt_id=stmt_id,
                                    source_symbol_id=import_symbol.symbol_id,
                                    source_state_id=each_receiver_state.source_state_id,
                                    data_type=data_type,
                                    value=import_symbol.import_stmt,
                                    # access_path = self.copy_and_extend_access_path(
                                    #     each_receiver_state.access_path,
                                    #     AccessPoint(
                                    #         key=import_symbol.symbol_name,
                                    #     )
                                    # )
                                    access_path=[AccessPoint(key=import_symbol.symbol_name)]
                                )
                                self.update_access_path_state_id(state_index)
                                each_defined_states.add(state_index)

                elif self.is_state_a_class_decl(each_receiver_state):
                    first_found_class_id = -1  # 记录从下往上找到该方法的第一个class_id。最后只返回该class中所有的同名方法，不继续向上找。
                    class_methods = self.loader.get_methods_in_class(each_receiver_state.value)
                    if class_methods:
                        for method in class_methods:
                            if method.name == field_name:
                                method_class_id = self.loader.convert_method_id_to_class_id(method.stmt_id)
                                if first_found_class_id == -1:
                                    first_found_class_id = method_class_id

                                if method_class_id != first_found_class_id:
                                    continue
                                data_type = LIAN_INTERNAL.METHOD_DECL
                                if self.loader.is_class_decl(method.stmt_id):
                                    data_type = LIAN_INTERNAL.CLASS_DECL
                                state_index = self.create_state_and_add_space(
                                    status, stmt_id=stmt_id,
                                    source_symbol_id=method.stmt_id,
                                    source_state_id=each_receiver_state.source_state_id,
                                    data_type=data_type,
                                    value=method.stmt_id,
                                    # access_path=[AccessPoint(key=method.name)]
                                    access_path = self.copy_and_extend_access_path(
                                        each_receiver_state.access_path,
                                        AccessPoint(
                                            key=method.name,
                                        )
                                    )
                                )
                                self.update_access_path_state_id(state_index)
                                each_defined_states.add(state_index)

                # 创建一个新的receiver_symbol，只创建一次。并将更新后的receiver_states赋给它
                self.change_field_read_receiver_state(
                    stmt_id, stmt, status, receiver_symbol_index, receiver_state_index, each_receiver_state,
                    field_name, each_defined_states, is_tangping=False
                )
            defined_states |= each_defined_states

        defined_symbol.states = defined_states

        event = EventData(
            self.lang,
            EVENT_KIND.P2STATE_FIELD_READ_AFTER,
            {
                "resolver": self.resolver,
                "stmt_id": stmt_id,
                "stmt": stmt,
                "status": status,
                "receiver_states": receiver_states,
                "receiver_symbol": receiver_symbol,
                "frame": self.frame,
                "field_states": field_states,
                "in_states": in_states,
                "defined_symbol": defined_symbol,
                "state_analysis": self,
                "defined_states": defined_states
            }
        )
        app_return = self.event_manager.notify(event)

        return P2ResultFlag()

    def object_call_state(self, stmt_id, stmt, status: StmtStatus, in_states):
        """
        <field_read: target, receiver_object, field>
        target = receiver_symbol.field

        通过state_bit_vector_manager拿到receiver_states的state id对应的最新的state
        """
        if len(status.used_symbols) < 2:
            return
        receiver_symbol_index = status.used_symbols[0]
        field_index = status.used_symbols[1]
        receiver_symbol: Symbol = self.frame.symbol_state_space[receiver_symbol_index]
        field_symbol: Symbol = self.frame.symbol_state_space[field_index]
        if not isinstance(receiver_symbol, Symbol):
            return
        receiver_states = self.read_used_states(receiver_symbol_index, in_states)
        field_states = self.read_used_states(field_index, in_states)
        defined_symbol_index = status.defined_symbol
        defined_symbol = self.frame.symbol_state_space[defined_symbol_index]
        if not isinstance(defined_symbol, Symbol):
            return P2ResultFlag()

        named_states = set()
        receiver_callee_dict = {}

        event = EventData(
            self.lang,
            EVENT_KIND.P2STATE_FIELD_READ_BEFORE,
            {
                "resolver": self.resolver,
                "stmt_id": stmt_id,
                "stmt": stmt,
                "status": status,
                "receiver_states": receiver_states,
                "receiver_symbol": receiver_symbol,
                "frame": self.frame,
                "field_states": field_states,
                "in_states": in_states,
                "defined_symbol": defined_symbol,
                "state_analysis": self,
                "defined_states": named_states
            }
        )
        app_return = self.event_manager.notify(event)
        if er.should_block_event_requester(app_return):
            defined_symbol.states = event.out_data.defined_states
            return P2ResultFlag()
        # else:
        # receiver_states = event.out_data.receiver_states

        for receiver_state_index in receiver_states:
            each_defined_states = set()
            each_receiver_state = self.frame.symbol_state_space[receiver_state_index]
            if not isinstance(each_receiver_state, State):
                continue

            for each_field_state_index in field_states:
                each_field_state = self.frame.symbol_state_space[each_field_state_index]
                if not isinstance(each_field_state, State):
                    continue

                field_name = str(each_field_state.value)
                if each_receiver_state.tangping_elements:
                    each_defined_states.update(each_receiver_state.tangping_elements)
                    continue

                elif len(field_name) == 0 or each_field_state.state_type == STATE_TYPE_KIND.ANYTHING:
                    self.change_field_read_receiver_state(
                        stmt_id, stmt, status, receiver_symbol_index, receiver_state_index, each_receiver_state,
                        field_name, each_defined_states, is_tangping=True
                    )
                    continue

                elif field_name in each_receiver_state.fields:
                    index_set = each_receiver_state.fields.get(field_name, set())
                    each_defined_states.update(index_set)
                    continue

                # # if field_name not in receiver_state.fields:
                # elif self.is_state_a_unit(each_receiver_state):
                #     import_graph = self.loader.get_import_graph()
                #     import_symbols = self.loader.get_unit_export_symbols(each_receiver_state.value)
                #     # [ah]
                #     found_in_import_graph = False
                #     # 解决file.symbol的情况，从import graph里找symbol
                #     for u, v, wt in import_graph.edges(data=True):
                #         real_name = wt.get("real_name", None)
                #         if real_name == field_name:
                #             symbol_type = wt.get("symbol_type", None)
                #             if symbol_type == LIAN_SYMBOL_KIND.METHOD_KIND:
                #                 data_type = LIAN_INTERNAL.METHOD_DECL
                #             elif symbol_type == LIAN_SYMBOL_KIND.CLASS_KIND:
                #                 data_type = LIAN_INTERNAL.CLASS_DECL
                #             else:
                #                 data_type = LIAN_INTERNAL.UNIT
                #
                #             state_index = self.create_state_and_add_space(
                #                 status, stmt_id=stmt_id,
                #                 source_symbol_id=v,
                #                 source_state_id=each_receiver_state.source_state_id,
                #                 data_type=data_type,
                #                 value=v,
                #                 # access_path=self.copy_and_extend_access_path(
                #                 #     each_receiver_state.access_path,
                #                 #     AccessPoint(
                #                 #         key=real_name,
                #                 #     )
                #                 # )
                #                 access_path=[AccessPoint(key=real_name)]
                #             )
                #             found_in_import_graph = True
                #             self.update_access_path_state_id(state_index)
                #             each_defined_states.add(state_index)
                #
                #     if import_symbols and not found_in_import_graph:
                #         for import_symbol in import_symbols:
                #             if import_symbol.symbol_name == field_name:
                #                 if import_symbol.symbol_type == LIAN_SYMBOL_KIND.METHOD_KIND:
                #                     data_type = LIAN_INTERNAL.METHOD_DECL
                #                 elif import_symbol.symbol_type == LIAN_SYMBOL_KIND.CLASS_KIND:
                #                     data_type = LIAN_INTERNAL.CLASS_DECL
                #                 else:
                #                     data_type = LIAN_INTERNAL.UNIT
                #
                #                 state_index = self.create_state_and_add_space(
                #                     status, stmt_id=stmt_id,
                #                     source_symbol_id=import_symbol.symbol_id,
                #                     source_state_id=each_receiver_state.source_state_id,
                #                     data_type=data_type,
                #                     value=import_symbol.import_stmt,
                #                     # access_path = self.copy_and_extend_access_path(
                #                     #     each_receiver_state.access_path,
                #                     #     AccessPoint(
                #                     #         key=import_symbol.symbol_name,
                #                     #     )
                #                     # )
                #                     access_path=[AccessPoint(key=import_symbol.symbol_name)]
                #                 )
                #                 self.update_access_path_state_id(state_index)
                #                 each_defined_states.add(state_index)

                elif self.is_state_a_class_decl(each_receiver_state):
                    first_found_class_id = -1  # 记录从下往上找到该方法的第一个class_id。最后只返回该class中所有的同名方法，不继续向上找。
                    class_methods = self.loader.get_methods_in_class(each_receiver_state.value)
                    if class_methods:
                        for method in class_methods:
                            if method.name == field_name:
                                method_class_id = self.loader.convert_method_id_to_class_id(method.stmt_id)
                                if first_found_class_id == -1:
                                    first_found_class_id = method_class_id

                                if method_class_id != first_found_class_id:
                                    continue
                                data_type = LIAN_INTERNAL.METHOD_DECL
                                if self.loader.is_class_decl(method.stmt_id):
                                    data_type = LIAN_INTERNAL.CLASS_DECL
                                state_index = self.create_state_and_add_space(
                                    status, stmt_id=stmt_id,
                                    source_symbol_id=method.stmt_id,
                                    source_state_id=each_receiver_state.source_state_id,
                                    data_type=data_type,
                                    value=method.stmt_id,
                                    # access_path=[AccessPoint(key=method.name)]
                                    access_path = self.copy_and_extend_access_path(
                                        each_receiver_state.access_path,
                                        AccessPoint(
                                            key=method.name,
                                        )
                                    )
                                )
                                self.update_access_path_state_id(state_index)
                                each_defined_states.add(state_index)

                # 创建一个新的receiver_symbol，只创建一次。并将更新后的receiver_states赋给它
                self.change_field_read_receiver_state(
                    stmt_id, stmt, status, receiver_symbol_index, receiver_state_index, each_receiver_state,
                    field_name, each_defined_states, is_tangping=False
                )

            named_states |= each_defined_states
            util.add_to_dict_with_default_set(receiver_callee_dict, receiver_state_index, each_defined_states)

        defined_symbol.states = named_states

        event = EventData(
            self.lang,
            EVENT_KIND.P2STATE_FIELD_READ_AFTER,
            {
                "resolver": self.resolver,
                "stmt_id": stmt_id,
                "stmt": stmt,
                "status": status,
                "receiver_states": receiver_states,
                "receiver_symbol": receiver_symbol,
                "frame": self.frame,
                "field_states": field_states,
                "in_states": in_states,
                "defined_symbol": defined_symbol,
                "state_analysis": self,
                "defined_states": named_states
            }
        )
        app_return = self.event_manager.notify(event)
        args = self.prepare_args(stmt_id, stmt, status, in_states)
        event = EventData(
            self.lang,
            EVENT_KIND.P2STATE_CALL_STMT_BEFORE,
            {
                "resolver": self.resolver,
                "stmt_id": stmt_id,
                "stmt": stmt,
                "status": status,
                "receiver_states": receiver_states,
                "receiver_symbol": receiver_symbol,
                "frame": self.frame,
                "field_states": field_states,
                "in_states": in_states,
                "defined_symbol": defined_symbol,
                "state_analysis": self,
                "args": args,
                "defined_states": named_states
            }
        )
        app_return = self.event_manager.notify(event)
        if er.should_block_event_requester(app_return):
            if util.is_available(event.out_data):
                return event.out_data
            return P2ResultFlag()
        unsolved_callee_states = set()
        callee_info = self.frame.stmt_id_to_callee_info.get(stmt_id)

        name_symbol = None
        if util.is_empty(callee_info):
            result = self.trigger_extern_callee(
                stmt_id, stmt, status, in_states, unsolved_callee_states, name_symbol, defined_symbol, args
            )
            if util.is_available(result):
                return result
            return P2ResultFlag()

        callee_type = callee_info.callee_type
        callee_method_ids = set()
        callee_class_ids = set()
        this_state_set = set()
        for each_receiver_state_index, callee_state_index_set in receiver_callee_dict.items():
            each_receiver_state = self.frame.symbol_state_space[each_receiver_state_index]
            for each_state_index in callee_state_index_set:
                each_state = self.frame.symbol_state_space[each_state_index]
                if not isinstance(each_state, State):
                    continue

                if self.is_state_a_method_decl(each_state):
                    if each_state.value:
                        this_state_set.update(
                            self.resolver.collect_newest_states_by_state_ids(self.frame, status, each_receiver_state.state_id)
                        )
                        if callee_id := util.str_to_int(each_state.value):
                            callee_method_ids.add(callee_id)

                else:
                    unsolved_callee_states.add(each_state_index)

        # call plugin to deal with undefined_callee_error
        if len(callee_method_ids) == 0 or self.is_abstract_method(callee_method_ids):
            out_data = self.trigger_extern_callee(
                stmt_id, stmt, status, in_states, unsolved_callee_states, name_symbol, defined_symbol, args
            )
            if util.is_available(out_data):
                if hasattr(out_data, "callee_method_ids"):
                    callee_method_ids.update(out_data.callee_method_ids)
                else:
                    return out_data

        # 针对 object 调用，同样在进入 P3 的跨函数分析前做一轮污点相关性判断：
        # 如果当前调用与污点无关，则不再深入 callee，仅保留保守占位。
        if self._taint_guided_p3_enabled():
            relevance = self.frame.stmt_state_analysis.judge_call_relevance(
                stmt_id,
                stmt,
                status,
                in_states,
                args,
                defined_symbol,
                this_state_set,
                callee_method_ids,
                None,  # name_symbol 在 object 调用场景下通常不使用
            )
            if not relevance.is_relevant:
                if isinstance(defined_symbol, Symbol):
                    unsolved_state_index = self.create_state_and_add_space(
                        status,
                        stmt_id,
                        source_symbol_id=defined_symbol.symbol_id,
                        state_type=STATE_TYPE_KIND.UNSOLVED,
                        data_type=util.read_stmt_field(stmt.data_type),
                        access_path=[
                            AccessPoint(
                                kind=ACCESS_POINT_KIND.CALL_RETURN,
                                key=util.read_stmt_field(defined_symbol.name),
                            )
                        ],
                    )
                    self.update_access_path_state_id(unsolved_state_index)
                    defined_symbol.states = {unsolved_state_index}
                return P2ResultFlag()

        return self.compute_target_method_states(
            stmt_id, stmt, status, in_states, callee_method_ids, defined_symbol, args, this_state_set
        )

    def field_write_stmt_state(self, stmt_id, stmt, status: StmtStatus, in_states):

        def tangping():
            new_receiver_state_index = self.create_copy_of_state_and_add_space(status, stmt_id, receiver_state_index, stmt)
            new_receiver_state: State = self.frame.symbol_state_space[new_receiver_state_index]
            self.make_state_tangping(new_receiver_state)
            new_receiver_state.tangping_elements.update(source_states)
            status.defined_states.discard(receiver_state_index)
            defined_symbol_states.discard(receiver_state_index)
            defined_symbol_states.add(new_receiver_state_index)
            return new_receiver_state

        receiver_index = status.used_symbols[0]
        field_index = status.used_symbols[1]
        source_index = status.used_symbols[2]
        source_symbol = self.frame.symbol_state_space[source_index]
        if source_symbol and isinstance(source_symbol, Symbol):
            if source_symbol.name.startswith(LIAN_INTERNAL.METHOD_DECL_PREF):
                is_anonymous = True

        receiver_states = self.read_used_states(receiver_index, in_states)
        field_states = self.read_used_states(field_index, in_states)
        source_states = self.read_used_states(source_index, in_states)
        receiver_symbol: Symbol = self.frame.symbol_state_space[receiver_index]

        if len(receiver_states) == 0 or len(source_states) == 0:
            self.sfg.add_edge(
                self.make_used_symbol_sfg_node(source_index),
                self.make_symbol_sfg_node(receiver_index),
                self.make_stmt_sfg_edge(stmt_id, SFG_EDGE_KIND.SYMBOL_FLOW, name=stmt.operation)
            )
            return P2ResultFlag()

        defined_symbol_index = status.defined_symbol
        defined_symbol = self.frame.symbol_state_space[defined_symbol_index]
        if not isinstance(defined_symbol, Symbol):
            return P2ResultFlag()

        defined_symbol_states = set()

        for receiver_state_index in receiver_states:
            receiver_state = self.frame.symbol_state_space[receiver_state_index]
            if not (receiver_state and isinstance(receiver_state, State)):
                continue

            if receiver_state.tangping_flag:
                tangping()
                continue

            # TODO: Here we need to leverage type system to filter out false positives
            for each_field_index in field_states:
                each_field_state = self.frame.symbol_state_space[each_field_index]
                if not (each_field_state and isinstance(each_field_state, State)):
                    continue

                if len(str(each_field_state.value)) == 0 or each_field_state.state_type == STATE_TYPE_KIND.ANYTHING:
                    tangping()
                    continue

                new_receiver_state_index = self.create_copy_of_state_and_add_space(status, stmt_id, receiver_state_index, stmt)
                new_receiver_state: State = self.frame.symbol_state_space[new_receiver_state_index]
                # print("@field_state write", new_receiver_state)

                # if is_anonymous:
                # [ah]a.b = c.d access_path 变成a.b
                for each_source_state_index in source_states:
                    each_source_state = self.frame.symbol_state_space[each_source_state_index]
                    if not (each_source_state and isinstance(each_source_state, State)):
                        continue
                    #
                    # if each_source_state.state_type == STATE_TYPE_KIND.ANYTHING:
                    #     continue

                    self.update_access_path_state_id(each_source_state_index)
                    self.sfg.add_edge(
                        self.make_state_sfg_node_with_no_context(new_receiver_state_index),
                        self.make_state_sfg_node_with_no_context(each_source_state_index),
                        self.make_stmt_sfg_edge(stmt_id, SFG_EDGE_KIND.STATE_INCLUSION, name=each_field_state.value)
                    )

                new_receiver_state.fields[each_field_state.value] = source_states
                defined_symbol_states.add(new_receiver_state_index)

        defined_symbol.states = defined_symbol_states
        # print(f"defined_symbol_states: {defined_symbol_states}")
        event = EventData(
            self.lang,
            EVENT_KIND.P2STATE_FIELD_WRITE_AFTER,
            {
                "resolver": self.resolver,
                "stmt_id": stmt_id,
                "stmt": stmt,
                "status": status,
                "receiver_states": receiver_states,
                "receiver_symbol": receiver_symbol,
                "frame": self.frame,
                "field_states": field_states,
                "source_states": source_states,
                "in_states": in_states,
                "defined_symbol": defined_symbol,
                "state_analysis": self,
                "defined_states": defined_symbol_states
            }
        )
        self.event_manager.notify(event)

        return P2ResultFlag()

    # TODO:
    def field_addr_stmt_state(self, stmt_id, stmt, status: StmtStatus, in_states):
        # data_type_index = status.used_symbols[0]
        # name_index = status.used_symbols[1]
        # data_type = self.frame.symbol_state_space[data_type_index]
        # name = self.frame.symbol_state_space[name_index]
        # data_type_states = self.read_used_states(data_type_index, in_states)
        # name_states = self.read_used_states(name_index, in_states)

        # defined_symbol_index = status.defined_symbol
        # defined_symbol: Symbol = self.frame.symbol_state_space[defined_symbol_index]
        # defined_symbol.states = {
        #     self.create_state_and_add_space(
        #         status, stmt_id,
        #         source_symbol_id=defined_symbol.symbol_id,
        #         data_type=LianInternal.U32
        #     )
        # }
        return P2ResultFlag()

    # TODO:
    def slice_write_stmt_state(self, stmt_id, stmt, status: StmtStatus, in_states):
        start_set = set()
        end_set = set()
        step_set = set()
        source_states_set = set()

        array_symbol_index = status.used_symbols[0]
        source_symbol_index = status.used_symbols[1]
        start_symbol_index = status.used_symbols[2]
        end_symbol_index = status.used_symbols[3]
        step_symbol_index = status.used_symbols[4]

        if self.frame.stmt_counters[stmt_id] == config.FIRST_ROUND:
            self.sfg.add_edge(
                self.make_used_symbol_sfg_node(source_symbol_index),
                self.make_symbol_sfg_node(array_symbol_index),
                self.make_stmt_sfg_edge(stmt_id, SFG_EDGE_KIND.SYMBOL_FLOW, name=stmt.operation)
            )

        used_array_symbol = self.frame.symbol_state_space[array_symbol_index]
        used_source_symbol = self.frame.symbol_state_space[source_symbol_index]
        used_start_symbol = self.frame.symbol_state_space[start_symbol_index]
        used_end_symbol = self.frame.symbol_state_space[end_symbol_index]
        used_step_symbol = self.frame.symbol_state_space[step_symbol_index]

        array_state_indexes = self.read_used_states(array_symbol_index, in_states)
        source_state_indexes = self.read_used_states(source_symbol_index, in_states)
        start_state_indexes = self.read_used_states(start_symbol_index, in_states)
        end_state_indexes = self.read_used_states(end_symbol_index, in_states)
        step_state_indexes = self.read_used_states(step_symbol_index, in_states)

        defined_array_symbol = self.frame.symbol_state_space[status.defined_symbol]
        if not isinstance(defined_array_symbol, Symbol):
            return P2ResultFlag()

        defined_symbol_states = set()

        for source_state_index in source_state_indexes:
            source_state = self.frame.symbol_state_space[source_state_index]
            if not isinstance(source_state, State):
                continue
            if source_state.value:
                source_states_set.add(source_state_index)
            elif source_state.array:
                for array_content in source_state.array:
                    source_states_set.update(array_content)

        if not source_states_set:
            return

        for each_array_state_index in array_state_indexes:
            array_state = self.frame.symbol_state_space[each_array_state_index]
            if not isinstance(array_state, State):
                continue

            tmp_array = set()
            tangping_flag = array_state.tangping_flag
            if not tangping_flag:
                tmp_array = array_state.array.copy()
                for start_state_id in start_state_indexes:
                    start_state = self.frame.symbol_state_space[start_state_id]
                    if not isinstance(start_state, State) or start_state.state_type == STATE_TYPE_KIND.ANYTHING:
                        tangping_flag = True
                        break

                    for end_state_id in end_state_indexes:
                        end_state = self.frame.symbol_state_space[end_state_id]
                        if not isinstance(end_state, State) or end_state.state_type == STATE_TYPE_KIND.ANYTHING:
                            tangping_flag = True
                            break

                        for step_state_id in step_state_indexes:
                            step_state = self.frame.symbol_state_space[step_state_id]
                            if not isinstance(step_state, State) or step_state.state_type == STATE_TYPE_KIND.ANYTHING:
                                tangping_flag = True
                                break

                            array_length = len(array_state.array)
                            if not used_start_symbol:
                                start_value = str(0)
                            else:
                                start_value = start_state.value

                            if not used_end_symbol:
                                end_value = str(array_length)
                            else:
                                end_value = end_state.value

                            if not used_step_symbol:
                                step_value = str(1)
                            else:
                                step_value = step_state.value

                            if start_value.isdigit() and end_value.isdigit() and step_value.isdigit():
                                start_value = int(start_value)
                                end_value = int(end_value)
                                step_value = int(step_value)

                                tmp_array[start_value:end_value:step_value] = source_states_set
                            else:
                                tangping_flag = True
                                break
                            if tangping_flag:
                                break
                        if tangping_flag:
                            break
                    if tangping_flag:
                        break

            if tangping_flag:
                new_array_state_index = self.create_copy_of_state_and_add_space(status, stmt_id, each_array_state_index, stmt)
                new_array_state: State = self.frame.symbol_state_space[new_array_state_index]
                self.make_state_tangping(new_array_state)
                new_array_state.tangping_elements.update(source_state_indexes)
                defined_symbol_states.add(new_array_state_index)

            elif len(tmp_array) > 0 and tmp_array != array_state.array:
                new_array_state_index = self.create_copy_of_state_and_add_space(status, stmt_id, each_array_state_index, stmt)
                new_array_state: State = self.frame.symbol_state_space[new_array_state_index]
                new_array_state.array = tmp_array
                defined_symbol_states.add(new_array_state_index)

        defined_array_symbol.states = defined_symbol_states
        return P2ResultFlag()

    def slice_read_stmt_state(self, stmt_id, stmt, status: StmtStatus, in_states):
        defined_states = set()
        start_set = set()
        end_set = set()
        step_set = set()
        new_array_symbol = None
        new_array_symbol_index = None

        array_symbol_index = status.used_symbols[0]
        start_symbol_index = status.used_symbols[1]
        end_symbol_index = status.used_symbols[2]
        step_symbol_index = status.used_symbols[3]

        if self.frame.stmt_counters[stmt_id] == config.FIRST_ROUND:
            self.sfg.add_edge(
                self.make_used_symbol_sfg_node(array_symbol_index),
                self.make_symbol_sfg_node(status.defined_symbol),
                self.make_stmt_sfg_edge(stmt_id, SFG_EDGE_KIND.SYMBOL_FLOW, name=stmt.operation)
            )

        used_array_symbol = self.frame.symbol_state_space[array_symbol_index]
        if not isinstance(used_array_symbol, Symbol):  # TODO 暂时不处理<string>[1:3]
            return P2ResultFlag()
        used_start_symbol = self.frame.symbol_state_space[start_symbol_index]
        used_end_symbol = self.frame.symbol_state_space[end_symbol_index]
        used_step_symbol = self.frame.symbol_state_space[step_symbol_index]

        array_state_indexes = self.read_used_states(array_symbol_index, in_states)
        start_state_indexes = self.read_used_states(start_symbol_index, in_states)
        end_state_indexes = self.read_used_states(end_symbol_index, in_states)
        step_state_indexes = self.read_used_states(step_symbol_index, in_states)

        target_symbol = self.frame.symbol_state_space[status.defined_symbol]
        if not isinstance(target_symbol, Symbol):
            return P2ResultFlag()

        for each_array_state_index in array_state_indexes:
            array_state = self.frame.symbol_state_space[each_array_state_index]
            if not isinstance(array_state, State):
                continue

            if array_state.tangping_flag:
                defined_states.update(array_state.tangping_elements)
                continue

            tmp_array: list = []

            tangping_flag = True
            for start_state_id in start_state_indexes:
                start_state = self.frame.symbol_state_space[start_state_id]
                if not isinstance(start_state, State) or start_state.state_type == STATE_TYPE_KIND.ANYTHING:
                    break

                for end_state_id in end_state_indexes:
                    end_state = self.frame.symbol_state_space[end_state_id]
                    if not isinstance(end_state, State) or end_state.state_type == STATE_TYPE_KIND.ANYTHING:
                        break

                    for step_state_id in step_state_indexes:
                        step_state = self.frame.symbol_state_space[step_state_id]
                        if not isinstance(step_state, State) or step_state.state_type == STATE_TYPE_KIND.ANYTHING:
                            break

                        array_length = len(array_state.array)
                        if not used_start_symbol:
                            start_value = str(0)
                        else:
                            start_value = start_state.value

                        if not used_end_symbol:
                            end_value = str(array_length)
                        else:
                            end_value = end_state.value

                        if not used_step_symbol:
                            step_value = str(1)
                        else:
                            step_value = step_state.value

                        if isinstance(start_value, int) or start_value.isdigit() and (isinstance(end_value, int) or end_value.isdigit()) and (isinstance(step_value, int) or step_value.isdigit()):
                            start_value = int(start_value)
                            end_value = int(end_value)
                            step_value = int(step_value)

                            if (
                                start_value < end_value < array_length and
                                array_state.array[start_value:end_value:step_value]
                            ):
                                tmp_array = array_state.array[start_value:end_value:step_value]
                                defined_state_index = self.create_state_and_add_space(
                                    status=status,
                                    stmt_id=stmt_id,
                                    source_symbol_id=target_symbol.symbol_id,
                                    data_type=LIAN_INTERNAL.ARRAY,
                                    access_path=[AccessPoint()]
                                )
                                self.update_access_path_state_id(defined_state_index)
                                defined_state: State = self.frame.symbol_state_space[defined_state_index]
                                defined_state.array = tmp_array

                                defined_states.add(defined_state_index)
                                tangping_flag = False
                            else:
                                break

                        if tangping_flag:
                            break
                    if tangping_flag:
                        break
                if tangping_flag:
                    break

            if not tangping_flag:
                continue

            # tangping
            if util.is_empty(new_array_symbol_index):
                new_array_symbol: Symbol = used_array_symbol

            # new_array_state_index = self.create_copy_of_state_and_add_space(status, stmt_id, each_array_state_index, stmt)
            new_array_state_index = each_array_state_index
            new_array_state: State = self.frame.symbol_state_space[new_array_state_index]
            new_path: list = array_state.access_path.copy()
            new_path.append(AccessPoint(
                kind=ACCESS_POINT_KIND.FIELD_ELEMENT,
                key=util.read_stmt_field(target_symbol.name)
            ))
            source_index = self.create_state_and_add_space(
                status,
                stmt_id,
                source_symbol_id=array_state.source_symbol_id,
                source_state_id=array_state.source_state_id,
                state_type=STATE_TYPE_KIND.ANYTHING,
                access_path=new_path
            )
            self.update_access_path_state_id(source_index)

            self.make_state_tangping(new_array_state)
            new_array_state.tangping_elements.add(source_index)
            defined_states.update(new_array_state.tangping_elements)
            new_array_symbol.states.discard(each_array_state_index)
            new_array_symbol.states.add(new_array_state_index)

        target_symbol.states = defined_states

        return P2ResultFlag()

    def del_stmt_state(self, stmt_id, stmt, status: StmtStatus, in_states):
        return P2ResultFlag()

    def unset_stmt_state(self, stmt_id, stmt, status: StmtStatus, in_states):
        target_symbol = self.frame.symbol_state_space[status.defined_symbol]
        if not isinstance(target_symbol, Symbol):
            return P2ResultFlag()

        target_symbol.states = []
        return P2ResultFlag()

