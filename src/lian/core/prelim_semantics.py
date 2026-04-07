#!/usr/bin/env python3
import copy
import pprint, os
import sys
import traceback
import numpy
import networkx as nx

from lian.config import type_table
from lian.core.sfg_dumper import SFGDumper
from lian.util import util
from lian.config import config
from lian.config.constants import (
    SYMBOL_DEPENDENCY_GRAPH_EDGE_KIND,
    LIAN_INTERNAL,
    STATE_TYPE_KIND,
    SYMBOL_OR_STATE,
    CONTROL_FLOW_KIND,
    EVENT_KIND,
    LIAN_SYMBOL_KIND,
    ANALYSIS_PHASE_ID,
    RETURN_STMT_OPERATION,
    SUMMARY_GENERAL_SYMBOL_ID,
    LOOP_OPERATIONS,
    SFG_NODE_KIND,
    SFG_EDGE_KIND
)
import lian.events.event_return as er
from lian.events.handler_template import EventData
from lian.common_structs import (
    AccessPoint,
    SimpleWorkList,
    StateDefNode,
    Symbol,
    State,
    ComputeFrame,
    ComputeFrameStack,
    CallGraph,
    SimplyGroupedMethodTypes,
    InterruptionData,
    P2ResultFlag,
    StmtStatus,
    SymbolDefNode,
    MethodSummaryTemplate,
    SymbolStateSpace,
    LastSymbolDefNode,
    CountStmtDefStateNode,
    SFGNode,
    SFGEdge
)
from lian.util.gir_block import GIRBlockViewer
from lian.util.loader import Loader
from lian.core.resolver import Resolver
from lian.core.stmt_states import StmtStates
from networkx.generators.classic import complete_graph

# from lian.config.type_table import get_lang_init_script_name

stmt_counts = 0

class P2PrelimSemanticAnalysis:
    def __init__(self, lian):
        self.options = lian.options
        self.complete_graph = self.options.complete_graph
        self.event_manager = lian.event_manager
        self.loader:Loader = lian.loader
        self.resolver: Resolver = lian.resolver
        self.call_graph = CallGraph()
        self.analyzed_method_list = set()
        self.inited_unit_list = set()
        self.analysis_phase_id = ANALYSIS_PHASE_ID.PRELIM_SEMANTICS
        self.max_analysis_round = config.MAX_ANALYSIS_ROUND_FOR_PRELIM_ANALYSIS

        self.count_stmt_defined_states_for_debug = {}
        self.count_stmt_defined_states_number_for_debug = {}

        # progress info for phase II
        self._p2_total_methods_set: set[int] = set()

    def get_stmt_id_to_callee_info(self, callees):
        results = {}
        for each_callee in callees:
            results[each_callee.stmt_id] = each_callee
        return results

    def adjust_defined_symbols_and_init_bit_vector(self, frame: ComputeFrame, method_id):
        raw_data = self.loader.get_method_defined_symbols_raw_p1(method_id)
        if util.is_empty(raw_data):
            return
        
        symbol_id_to_stmt_ids = {}
        for row in raw_data:
            symbol_id_to_stmt_ids[row.symbol_id] = set(row.defined)

        all_symbol_defs = set()
        defined_symbols = {}

        for each_index, item in enumerate(frame.symbol_state_space.space):
            if isinstance(item, Symbol):
                symbol_id = item.symbol_id
                stmt_id = item.stmt_id
                if symbol_id in symbol_id_to_stmt_ids and stmt_id in symbol_id_to_stmt_ids[symbol_id]:
                    if symbol_id not in defined_symbols:
                        defined_symbols[symbol_id] = set()
                    symbol_node = SymbolDefNode(
                        index = each_index, symbol_id=symbol_id, stmt_id=stmt_id
                    )
                    defined_symbols[symbol_id].add(symbol_node)
                    all_symbol_defs.add(symbol_node)

        frame.defined_symbols = defined_symbols
        frame.all_symbol_defs = all_symbol_defs
        frame.symbol_bit_vector_manager.init(all_symbol_defs)

    def adjust_defined_states_and_init_bit_vector(self, frame: ComputeFrame, method_id):
        frame.defined_states = self.loader.get_method_defined_states_p1(method_id)
        all_state_defs = set()
        for state_id, defined_set in frame.defined_states.items():
            for state_def_node in defined_set:
                all_state_defs.add(state_def_node)

        frame.all_state_defs = all_state_defs
        frame.state_bit_vector_manager.init(all_state_defs)

    def init_compute_frame(self, frame: ComputeFrame, frame_stack):
        frame.has_been_inited = True
        frame.frame_stack = frame_stack
        method_id = frame.method_id

        frame.cfg = self.loader.get_method_cfg(method_id)
        if util.is_empty(frame.cfg):
            return None

        _, parameter_decls, method_body = self.loader.get_splitted_method_gir(method_id)
        parameter_decl_block = GIRBlockViewer(parameter_decls)
        method_body_block = GIRBlockViewer(method_body)
        frame.unit_gir.append_other(parameter_decl_block).append_other(method_body_block)

        for stmt_id in frame.unit_gir.get_all_stmt_ids():
            frame.stmt_counters[stmt_id] = config.FIRST_ROUND
            frame.is_first_round[stmt_id] = True

        frame.stmt_state_analysis = StmtStates(
            analysis_phase_id = self.analysis_phase_id,
            event_manager = self.event_manager,
            loader = self.loader,
            resolver = self.resolver,
            compute_frame = frame,
            call_graph = self.call_graph,
            analyzed_method_list = self.analyzed_method_list,
            complete_graph=self.options.complete_graph,
        )

        frame.stmt_worklist = SimpleWorkList(graph = frame.cfg)
        frame.stmt_worklist.add(util.find_cfg_first_nodes(frame.cfg))
        frame.stmts_with_symbol_update.add(util.find_cfg_first_nodes(frame.cfg))

        # avoid changing the content of the loader
        frame.stmt_id_to_status = self.loader.get_stmt_status_p1(method_id)
        frame.symbol_state_space = self.loader.get_symbol_state_space_p1(method_id)
        if util.is_empty(frame.symbol_state_space):
            return None

        frame.stmt_id_to_callee_info = self.get_stmt_id_to_callee_info(
            self.loader.get_method_internal_callees(method_id)
        )
        frame.method_def_use_summary = self.loader.get_method_def_use_summary(method_id)
        frame.all_local_symbol_ids = frame.method_def_use_summary.local_symbol_ids

        self.adjust_defined_symbols_and_init_bit_vector(frame, method_id)
        self.adjust_defined_states_and_init_bit_vector(frame, method_id)

        return frame

    def update_current_symbol_bit(self, bit_id: SymbolDefNode, frame: ComputeFrame, current_bits):
        symbol_id = bit_id.symbol_id
        if bit_id not in frame.all_symbol_defs:
            frame.all_symbol_defs.add(bit_id)
            if symbol_id not in frame.defined_symbols:
                frame.defined_symbols[symbol_id] = set()
            frame.defined_symbols[symbol_id].add(bit_id)
            frame.symbol_bit_vector_manager.add_bit_id(bit_id)
        all_def_stmts = frame.defined_symbols[symbol_id]

        current_bits = frame.symbol_bit_vector_manager.kill_bit_ids(current_bits, all_def_stmts)
        current_bits = frame.symbol_bit_vector_manager.gen_bit_ids(current_bits, [bit_id])

        return current_bits

    def update_current_state_bit(self, bit_id: StateDefNode, frame: ComputeFrame, current_bits, new_defined_state_set: set):
        state_id = bit_id.state_id
        if bit_id not in frame.all_state_defs:
            frame.all_state_defs.add(bit_id)
            util.add_to_dict_with_default_set(frame.defined_states, state_id, bit_id)
            frame.state_bit_vector_manager.add_bit_id(bit_id)
        # 由于一条指令可能同时新定义多个state id相同的state，因此不能将同stmt id的state kill掉
        # 每一轮需要将同一语句前面几轮中相同state id的state都kill掉
        all_def_states = frame.defined_states[state_id]
        all_def_stmt_except_current_stmt = set()
        for each_def_state in all_def_states:
            # 不是本轮产生的state
            if each_def_state.index not in new_defined_state_set:
                all_def_stmt_except_current_stmt.add(each_def_state)

        current_bits = frame.state_bit_vector_manager.kill_bit_ids(current_bits, all_def_stmt_except_current_stmt)
        current_bits = frame.state_bit_vector_manager.gen_bit_ids(current_bits, [bit_id])

        return current_bits

    def update_out_states(self, stmt_id, frame: ComputeFrame, status: StmtStatus, old_index_ceiling, old_status_defined_states = set()):
        # 这条语句新产生的状态
        new_defined_state_set = set()
        for index in status.defined_states:
            if index >= old_index_ceiling: # or self.analysis_phase_id == ANALYSIS_PHASE_ID.PRELIM_SEMANTICS: # newly generated states
                new_defined_state_set.add(index)

        if old_status_defined_states:
            defined_states = old_status_defined_states
            if not new_defined_state_set:
                new_defined_state_set = old_status_defined_states
        else:
            defined_states = status.defined_states

        state_current_bits = status.in_state_bits

        # 为每个defined_state创建一个StateDefNode，并更新out_state_bits
        for defined_state_index in defined_states:
            defined_state: State = frame.symbol_state_space[defined_state_index]
            if not isinstance(defined_state, State):
                continue

            state_id = defined_state.state_id
            state_node = StateDefNode(index=defined_state_index, state_id=state_id, stmt_id=stmt_id)
            state_current_bits = self.update_current_state_bit(state_node, frame, state_current_bits, new_defined_state_set)
        status.out_state_bits = state_current_bits

        # 若本句语句的defined_symbol没有被解析出任何状态，生成一个UNSOLVED状态给它。并不加入到out_state_bits
        if defined_symbol := frame.symbol_state_space[status.defined_symbol]:
            if isinstance(defined_symbol, Symbol) and len(defined_symbol.states) == 0:
                new_state = State(
                    stmt_id = stmt_id,
                    source_symbol_id = defined_symbol.symbol_id,
                    state_type = STATE_TYPE_KIND.UNSOLVED
                )
                defined_symbol.states.add(frame.symbol_state_space.add(new_state))

        return new_defined_state_set

    def update_symbols_if_changed(
        self, stmt_id, stmt, frame: ComputeFrame, status: StmtStatus, old_in_symbol_bits, old_out_symbol_bits, def_changed = False, use_changed = False
    ):
        if use_changed:
            self.update_used_symbols_to_symbol_graph(stmt_id, stmt, frame, only_implicitly_used_symbols = True)
        elif status.in_symbol_bits != old_in_symbol_bits:
            self.update_used_symbols_to_symbol_graph(stmt_id, stmt, frame)

        if status.out_symbol_bits != old_out_symbol_bits or def_changed:
            frame.stmts_with_symbol_update.add(util.graph_successors(frame.cfg, stmt_id))

    @profile
    def analyze_reachable_symbols(self, stmt_id, stmt, frame: ComputeFrame):
        status = frame.stmt_id_to_status[stmt_id]
        old_out_symbol_bits = status.out_symbol_bits
        old_in_symbol_bits = status.in_symbol_bits
        status.in_symbol_bits = set()

        # collect parent stmts
        parent_stmt_ids = util.graph_predecessors(frame.cfg, stmt_id)
        if stmt.operation in LOOP_OPERATIONS:
            new_parent_stmt_ids = []
            for each_parent_stmt_id in parent_stmt_ids:
                edge_weight = util.get_graph_edge_weight(frame.cfg, each_parent_stmt_id, stmt_id)
                if frame.stmt_counters[stmt_id] == config.FIRST_ROUND:
                    if edge_weight != CONTROL_FLOW_KIND.LOOP_BACK:
                        new_parent_stmt_ids.append(each_parent_stmt_id)
                else:
                    if edge_weight == CONTROL_FLOW_KIND.LOOP_BACK:
                        new_parent_stmt_ids.append(each_parent_stmt_id)
            parent_stmt_ids = new_parent_stmt_ids

        # collect in symbol bits
        for each_parent_stmt_id in parent_stmt_ids:
            if each_parent_stmt_id in frame.stmt_id_to_status:
                status.in_symbol_bits |= frame.stmt_id_to_status[each_parent_stmt_id].out_symbol_bits

        if self.analysis_phase_id in [ANALYSIS_PHASE_ID.PRELIM_SEMANTICS]:
            if not frame.is_first_round[stmt_id] and status.in_symbol_bits == old_in_symbol_bits:
                return

        current_bits = status.in_symbol_bits.copy()
        all_defined_symbols = [status.defined_symbol] + status.implicitly_defined_symbols
        for tmp_counter, defined_symbol_index in enumerate(all_defined_symbols):
            defined_symbol = frame.symbol_state_space[defined_symbol_index]
            if not isinstance(defined_symbol, Symbol):
                continue
            symbol_id = defined_symbol.symbol_id
            key = SymbolDefNode(index = defined_symbol_index, symbol_id = symbol_id, stmt_id = stmt_id)
            if key in current_bits:
                continue
            current_bits = self.update_current_symbol_bit(key, frame, current_bits)

            edge_type = SYMBOL_DEPENDENCY_GRAPH_EDGE_KIND.EXPLICITLY_DEFINED
            if tmp_counter != 0:
                edge_type = SYMBOL_DEPENDENCY_GRAPH_EDGE_KIND.IMPLICITLY_DEFINED

            frame.symbol_graph.add_edge(stmt_id, key, edge_type)
            tmp_context = None
            if self.analysis_phase_id == ANALYSIS_PHASE_ID.GLOBAL_SEMANTICS:
                tmp_context = frame.get_context()

            if stmt.operation != "variable_decl":
                frame.state_flow_graph.add_edge(
                    SFGNode(
                        node_type=SFG_NODE_KIND.STMT,
                        def_stmt_id=stmt_id,
                        name=stmt.operation,
                        context=tmp_context,
                        stmt=stmt
                    ),
                    SFGNode(
                        node_type=SFG_NODE_KIND.SYMBOL,
                        index=key.index,
                        def_stmt_id=key.stmt_id,
                        node_id=key.symbol_id,
                        name=defined_symbol.name,
                        context=tmp_context,
                        ),
                    SFGEdge(
                        edge_type=SFG_EDGE_KIND.SYMBOL_IS_DEFINED,
                        stmt_id=stmt_id
                    )
                )

        status.out_symbol_bits = current_bits

        # check if the out bits are changed
        if self.analysis_phase_id == ANALYSIS_PHASE_ID.PRELIM_SEMANTICS:
            if frame.is_first_round[stmt_id]:
                self.update_used_symbols_to_symbol_graph(stmt_id, stmt, frame)
                frame.stmts_with_symbol_update.add(util.graph_successors(frame.cfg, stmt_id))
            else:
                self.update_symbols_if_changed(stmt_id, stmt, frame, status, old_in_symbol_bits, old_out_symbol_bits)

        elif self.analysis_phase_id == ANALYSIS_PHASE_ID.GLOBAL_SEMANTICS:
            self.update_symbols_if_changed(stmt_id, stmt, frame, status, old_in_symbol_bits, old_out_symbol_bits)

    def rerun_analyze_reachable_symbols(self, stmt_id, stmt, frame: ComputeFrame, result_flag: P2ResultFlag):
        status = frame.stmt_id_to_status[stmt_id]
        old_out_symbol_bits = status.out_symbol_bits
        current_bits = status.out_symbol_bits
        all_defined_symbols = status.implicitly_defined_symbols
        for defined_symbol_index in all_defined_symbols:
            defined_symbol = frame.symbol_state_space[defined_symbol_index]
            if not isinstance(defined_symbol, Symbol):
                continue
            symbol_id = defined_symbol.symbol_id
            key = SymbolDefNode(index=defined_symbol_index, symbol_id=symbol_id, stmt_id=stmt_id)
            if key in current_bits:
                continue
            current_bits = self.update_current_symbol_bit(key, frame, current_bits)
            frame.symbol_graph.add_edge(stmt_id, key, SYMBOL_DEPENDENCY_GRAPH_EDGE_KIND.IMPLICITLY_DEFINED)
            tmp_context = None
            if self.analysis_phase_id == ANALYSIS_PHASE_ID.GLOBAL_SEMANTICS:
                tmp_context = frame.get_context()
            frame.state_flow_graph.add_edge(
                SFGNode(
                    node_type=SFG_NODE_KIND.STMT,
                    def_stmt_id=stmt_id,
                    name=stmt.operation,
                    context=tmp_context,
                    stmt=stmt
                ),
                SFGNode(
                    node_type=SFG_NODE_KIND.SYMBOL,
                    index=key.index,
                    def_stmt_id=key.stmt_id,
                    node_id=key.symbol_id,
                    name=defined_symbol.name,
                    context=tmp_context,
                ),
                SFGEdge(
                    edge_type=SFG_EDGE_KIND.SYMBOL_IS_DEFINED,
                    stmt_id=stmt_id
                )
            )

        status.out_symbol_bits = current_bits

        # check if the out bits are changed
        self.update_symbols_if_changed(
            stmt_id, stmt, frame, status, status.in_symbol_bits, old_out_symbol_bits, result_flag.symbol_def_changed, result_flag.symbol_use_changed
        )

    def check_reachable_symbol_defs(self, stmt_id, frame: ComputeFrame, status, used_symbol_index, used_symbol: Symbol, available_symbol_defs):
        used_symbol_id = used_symbol.symbol_id
        reachable_symbol_defs = set()
        if used_symbol_id in frame.defined_symbols:
            reachable_symbol_defs = available_symbol_defs & frame.defined_symbols[used_symbol_id]
        else:
            if used_symbol_id not in frame.all_local_symbol_ids:
                if used_symbol_id not in frame.method_def_use_summary.used_external_symbol_ids:
                    frame.method_def_use_summary.used_external_symbol_ids.add(used_symbol_id)
                reachable_symbol_defs.add(
                    SymbolDefNode(symbol_id=used_symbol_id, stmt_id=stmt_id, index=used_symbol_index)
                )

        return reachable_symbol_defs

    @profile
    def update_used_symbols_to_symbol_graph(self, stmt_id, stmt, frame: ComputeFrame, only_implicitly_used_symbols=False):
        status = frame.stmt_id_to_status[stmt_id]
        available_defs = frame.symbol_bit_vector_manager.explain(status.in_symbol_bits)
        all_used_symbols = []
        if only_implicitly_used_symbols:
            all_used_symbols = status.implicitly_used_symbols
        else:
            all_used_symbols = status.used_symbols + status.implicitly_used_symbols

        for pos, used_symbol_index in enumerate(all_used_symbols):
            used_content = frame.symbol_state_space[used_symbol_index]
            if isinstance(used_content, State):
                tmp_context = None
                if self.analysis_phase_id == ANALYSIS_PHASE_ID.GLOBAL_SEMANTICS:
                    tmp_context = frame.get_context()
                    
                frame.state_flow_graph.add_edge(
                    SFGNode(
                        node_type=SFG_NODE_KIND.STATE,
                        index=used_symbol_index,
                        def_stmt_id=used_content.stmt_id,
                        node_id=used_content.state_id,
                        access_path=used_content.access_path
                    ),
                    SFGNode(
                        node_type=SFG_NODE_KIND.STMT,
                        def_stmt_id=stmt_id,
                        name=stmt.operation,
                        context=frame.get_context(),
                        stmt=stmt
                    ),
                    SFGEdge(
                        edge_type=SFG_EDGE_KIND.STATE_IS_USED,
                        stmt_id=stmt_id,
                        pos=pos
                    )
                )

            elif isinstance(used_content, Symbol):
                reachable_defs = self.check_reachable_symbol_defs(stmt_id, frame, status, used_symbol_index, used_content, available_defs)
                edge_type = SYMBOL_DEPENDENCY_GRAPH_EDGE_KIND.IMPLICITLY_USED
                if not only_implicitly_used_symbols:
                    if used_symbol_index < len(status.used_symbols):
                        edge_type = SYMBOL_DEPENDENCY_GRAPH_EDGE_KIND.EXPLICITLY_USED

                for tmp_key in reachable_defs:
                    if frame.symbol_graph.has_edge(tmp_key, stmt_id):
                        continue
                    frame.symbol_graph.add_edge(tmp_key, stmt_id, edge_type)
                    if tmp_key.index <= 0:
                        continue

                    tmp_context = None
                    if self.analysis_phase_id == ANALYSIS_PHASE_ID.GLOBAL_SEMANTICS:
                        tmp_context = frame.get_context()
                    frame.state_flow_graph.add_edge(
                        SFGNode(
                            node_type=SFG_NODE_KIND.SYMBOL,
                            index=tmp_key.index,
                            def_stmt_id=tmp_key.stmt_id,
                            node_id=tmp_key.symbol_id,
                            name=used_content.name,
                            context=tmp_context,
                        ),
                        SFGNode(
                            node_type=SFG_NODE_KIND.STMT,
                            def_stmt_id=stmt_id,
                            name=stmt.operation,
                            context=tmp_context,
                            stmt=stmt
                        ),
                        SFGEdge(
                            edge_type=SFG_EDGE_KIND.SYMBOL_IS_USED,
                            stmt_id=stmt_id,
                            pos=pos
                        )
                    )

    def get_used_symbol_indexes(self, stmt_id, frame: ComputeFrame, status: StmtStatus):
        available_defs = frame.symbol_bit_vector_manager.explain(status.in_symbol_bits)
        all_used_symbols = status.used_symbols + status.implicitly_used_symbols
        all_reachable_defs = set()
        for used_symbol_index in all_used_symbols:
            used_symbol = frame.symbol_state_space[used_symbol_index]
            if not isinstance(used_symbol, Symbol):
                continue
            all_reachable_defs.update(
                self.check_reachable_symbol_defs(stmt_id, frame, status, used_symbol_index, used_symbol, available_defs)
            )

        available_indexes = set()
        for node in all_reachable_defs:
            if not isinstance(node, SymbolDefNode):
                continue
            if node.stmt_id <= 0:
                continue
            available_indexes.add(node.index)

        return available_indexes

    def group_used_symbol_id_to_indexes(self, available_indexes, frame: ComputeFrame):
        result = {}
        for index in available_indexes:
            used_symbol = frame.symbol_state_space[index]
            if not isinstance(used_symbol, Symbol):
                continue
            symbol_id = used_symbol.symbol_id
            if symbol_id not in result:
                result[symbol_id] = set()
            result[symbol_id].add(index)
        return result

    def collect_in_state_bits(self, stmt_id, stmt, frame: ComputeFrame):
        in_state_bits = set()
        parent_stmt_ids = util.graph_predecessors(frame.cfg, stmt_id)
        if stmt.operation in LOOP_OPERATIONS:
            new_parent_stmt_ids = []
            for each_parent_stmt_id in parent_stmt_ids:
                edge_weight = util.get_graph_edge_weight(frame.cfg, each_parent_stmt_id, stmt_id)
                if frame.stmt_counters[stmt_id] == config.FIRST_ROUND and edge_weight != CONTROL_FLOW_KIND.LOOP_BACK:
                    new_parent_stmt_ids.append(each_parent_stmt_id)
                elif frame.stmt_counters[stmt_id] != config.FIRST_ROUND and edge_weight == CONTROL_FLOW_KIND.LOOP_BACK:
                    new_parent_stmt_ids.append(each_parent_stmt_id)
            parent_stmt_ids = new_parent_stmt_ids

        for each_parent_stmt_id in parent_stmt_ids:
            if each_parent_stmt_id in frame.stmt_id_to_status:
                in_state_bits |= frame.stmt_id_to_status[each_parent_stmt_id].out_state_bits

        return in_state_bits

    def group_in_states(self, stmt_id, stmt, in_symbol_indexes, frame: ComputeFrame, status):
        stmt_sfg_node = None

        # all_in_states are all states of used symbols
        # all_in_states -> align -> status.used_symbols
        symbol_id_to_state_index = {}
        for each_in_symbol_index in in_symbol_indexes:
            each_in_symbol = frame.symbol_state_space[each_in_symbol_index]
            if not isinstance(each_in_symbol, Symbol):
                continue

            symbol_id = each_in_symbol.symbol_id
            available_state_defs = frame.state_bit_vector_manager.explain(status.in_state_bits)
            latest_state_index_set = self.resolver.collect_newest_states_by_state_indexes(
                frame, stmt_id, each_in_symbol.states, available_state_defs
            )
            if latest_state_index_set:
                util.add_to_dict_with_default_set(symbol_id_to_state_index, symbol_id, latest_state_index_set)

                if self.is_global_phase_first_round(stmt_id, frame):
                    tmp_context = frame.get_context()
                    used_symbol_node = SFGNode(
                        node_type=SFG_NODE_KIND.SYMBOL,
                        def_stmt_id=each_in_symbol.stmt_id,
                        index=each_in_symbol_index,
                        node_id=each_in_symbol.symbol_id,
                        name=each_in_symbol.name,
                        context=tmp_context,
                    )
                    symbol_state_sfg_edge = SFGEdge(
                        edge_type=SFG_EDGE_KIND.SYMBOL_STATE,
                        stmt_id=stmt_id,
                    )
                    used_symbol_out_nodes = util.graph_successors(frame.state_flow_graph.graph, used_symbol_node)
                    contain_state_flag = False
                    for each_node in used_symbol_out_nodes:
                        if each_node.node_type == SFG_NODE_KIND.STATE:
                            if each_node.index in latest_state_index_set:
                                contain_state_flag = True
                                break
                    if not contain_state_flag:
                        for state_index in latest_state_index_set:
                            tmp_state = frame.symbol_state_space[state_index]
                            if not isinstance(tmp_state, State):
                                continue

                            frame.state_flow_graph.add_edge(
                                used_symbol_node,
                                SFGNode(
                                    node_type=SFG_NODE_KIND.STATE,
                                    def_stmt_id=tmp_state.stmt_id,
                                    index=state_index,
                                    node_id=tmp_state.state_id,
                                    access_path=tmp_state.access_path,
                                ),
                                symbol_state_sfg_edge
                            )

                    if stmt_sfg_node is None:
                        stmt_sfg_node = SFGNode(
                            node_type=SFG_NODE_KIND.STMT,
                            def_stmt_id=stmt_id,
                            name=stmt.operation,
                            context=frame.get_context(),
                            stmt=stmt
                        )
                    stmt_in_nodes = util.graph_predecessors(frame.state_flow_graph.graph, stmt_sfg_node)
                    contain_used_symbol_flag = False
                    for each_node in stmt_in_nodes:
                        if each_node.node_type == SFG_NODE_KIND.SYMBOL:
                            if each_node.index == each_in_symbol_index:
                                contain_used_symbol_flag = True
                                break
                    if not contain_used_symbol_flag:
                        for tmp_pos, tmp_used_symbol_index in enumerate(status.used_symbols + status.implicitly_used_symbols):
                            tmp_used_symbol = frame.symbol_state_space[tmp_used_symbol_index]
                            if not isinstance(tmp_used_symbol, Symbol):
                                continue
                            if tmp_used_symbol.symbol_id == used_symbol_node.node_id:
                                frame.state_flow_graph.add_edge(
                                    used_symbol_node,
                                    stmt_sfg_node,
                                    SFGEdge(
                                        edge_type=SFG_EDGE_KIND.SYMBOL_IS_USED,
                                        stmt_id=stmt_id,
                                        pos=tmp_pos,
                                    )
                                )

        for symbol_id, each_symbol_in_states in symbol_id_to_state_index.items():
            # 对每个symbol的in_states按state_id合并一次，并将fusion_state添加到status.defined_states中
            state_id_to_indexes = self.group_states_with_state_ids(frame, each_symbol_in_states)
            for state_id, states_with_same_id in state_id_to_indexes.items():
                fusion_state = frame.stmt_state_analysis.fuse_states_to_one_state(states_with_same_id, stmt_id, stmt, status)
                each_symbol_in_states -= states_with_same_id
                each_symbol_in_states |= fusion_state
        return symbol_id_to_state_index

    def generate_external_symbol_states(self, frame: ComputeFrame, stmt_id, symbol_id, used_symbol, method_summary):
        if self.loader.is_method_decl(symbol_id):
            new_state = State(
                stmt_id = stmt_id,
                source_symbol_id = symbol_id,
                data_type = LIAN_INTERNAL.METHOD_DECL,
                state_type = STATE_TYPE_KIND.REGULAR,
                value = symbol_id,
            )
            new_state.access_path = [AccessPoint(key=used_symbol.name, state_id=new_state.state_id)]
        elif self.loader.is_class_decl(symbol_id):
            new_state = State(
                stmt_id = stmt_id,
                source_symbol_id = symbol_id,
                data_type = LIAN_INTERNAL.CLASS_DECL,
                state_type = STATE_TYPE_KIND.REGULAR,
                value = symbol_id
            )
            new_state.access_path = [AccessPoint(key=used_symbol.name, state_id=new_state.state_id)]
        elif self.loader.is_unit_id(symbol_id):
            new_state = State(
                stmt_id = stmt_id,
                source_symbol_id = symbol_id,
                data_type = LIAN_INTERNAL.UNIT,
                state_type = STATE_TYPE_KIND.REGULAR,
                value = symbol_id
            )
            new_state.access_path = [AccessPoint(key=used_symbol.name, state_id=new_state.state_id)]
        else:
            new_state = State(
                stmt_id = stmt_id,
                source_symbol_id = symbol_id,
                state_type = STATE_TYPE_KIND.ANYTHING
            )
            new_state.access_path = [AccessPoint(key=used_symbol.name, state_id=new_state.state_id)]

        if used_symbol.name == LIAN_INTERNAL.THIS:
            new_state.data_type = LIAN_INTERNAL.THIS

        # util.add_to_dict_with_default_set(frame.used_external_symbol_id_to_state_id_set, symbol_id, new_state.state_id)
        index = frame.symbol_state_space.add(new_state)
        frame.initial_state_to_external_symbol[new_state.state_id] = symbol_id
        frame.external_symbol_id_to_initial_state_index[symbol_id] = index
        event = EventData(
            frame.lang,
            EVENT_KIND.P2STATE_GENERATE_EXTERNAL_STATES,
            {
                "stmt_id": stmt_id,
                "frame": frame,
                "state_analysis": self,
                "symbol_id": symbol_id,
                "new_state": new_state,
                "external_state_index": index
            }
        )
        app_return = self.event_manager.notify(event)

        status = frame.stmt_id_to_status[stmt_id]
        util.add_to_dict_with_default_set(
            frame.defined_states,
            new_state.state_id,
            StateDefNode(index=index, state_id=new_state.state_id, stmt_id=stmt_id)
        )
        status.defined_states.add(index)

        return {index}

    def collect_external_symbol_states(self, frame, stmt_id, stmt, symbol_id, summary_template: MethodSummaryTemplate, old_key_state_indexes: set):
        if symbol_id in summary_template.key_dynamic_content:
            return old_key_state_indexes

        return_indexes = summary_template.used_external_symbols[symbol_id].copy()
        return return_indexes

    def complete_in_states_and_check_continue_flag(self, stmt_id, frame: ComputeFrame, stmt, status, in_states, method_summary: MethodSummaryTemplate):
        if stmt.operation == "parameter_decl":
            return True

        # TODO：暂时注释。global阶段如果一条call语句在这return了，会导致其找不到callee。
        # if stmt_id not in frame.stmts_with_symbol_update:
        #     return False

        # 如果已经达到最大轮数，则不继续分析
        if frame.stmt_counters[stmt_id] >= self.max_analysis_round:
            return False

        change_flag = False
        if frame.is_first_round[stmt_id]:
            change_flag = True

        for used_symbol_pos, used_symbol_index in enumerate(status.used_symbols + status.implicitly_used_symbols):
            used_symbol = frame.symbol_state_space[used_symbol_index]
            if not isinstance(used_symbol, Symbol):
                continue

            symbol_id = used_symbol.symbol_id
            # This symbol is from locals
            need_update = False
            if symbol_id in in_states:
                if len(in_states[symbol_id]) == 0:
                    need_update = True
                else:
                    if not change_flag:
                        if used_symbol.states != in_states[symbol_id]:
                            change_flag = True
                    used_symbol.states = in_states[symbol_id]

            if need_update or symbol_id not in in_states:
                if symbol_id not in method_summary.used_external_symbols:
                    change_flag = True
                    state_indexes = self.generate_external_symbol_states(frame, stmt_id, symbol_id, used_symbol, method_summary)
                    method_summary.used_external_symbols[symbol_id] = state_indexes

                    # add one edge from symbol to states

                    tmp_context = None
                    if self.analysis_phase_id == ANALYSIS_PHASE_ID.GLOBAL_SEMANTICS:
                        tmp_context = frame.get_context()
                    used_symbol_node = SFGNode(
                        node_type=SFG_NODE_KIND.SYMBOL,
                        def_stmt_id=used_symbol.stmt_id,
                        index=used_symbol_index,
                        node_id=used_symbol.symbol_id,
                        name=used_symbol.name,
                        context=tmp_context,
                    )
                    stmt_node = SFGEdge(
                        edge_type=SFG_EDGE_KIND.SYMBOL_STATE,
                        stmt_id=stmt_id,
                    )
                    for state_index in state_indexes:
                        tmp_state = frame.symbol_state_space[state_index]
                        if not isinstance(tmp_state, State):
                            continue

                        frame.state_flow_graph.add_edge(
                            used_symbol_node,
                            SFGNode(
                                node_type=SFG_NODE_KIND.STATE,
                                def_stmt_id=tmp_state.stmt_id,
                                index=state_index,
                                node_id=tmp_state.state_id,
                                access_path=tmp_state.access_path,
                            ),
                            stmt_node
                        )

                        frame.state_flow_graph.add_edge(
                            used_symbol_node,
                            SFGNode(
                                node_type=SFG_NODE_KIND.STMT,
                                def_stmt_id=stmt_id,
                                name=stmt.operation,
                                context=tmp_context,
                                stmt=stmt,
                            ),
                            SFGEdge(
                                edge_type=SFG_EDGE_KIND.SYMBOL_IS_USED,
                                stmt_id=stmt_id,
                                pos=used_symbol_pos
                            )
                        )

                new_state_indexes = set()
                for index in method_summary.used_external_symbols[symbol_id]:
                    new_state_indexes.add(index)
                in_states[symbol_id] = new_state_indexes
                used_symbol.states = new_state_indexes

        if self.analysis_phase_id == ANALYSIS_PHASE_ID.GLOBAL_SEMANTICS and stmt.operation in ["call_stmt", "object_call_stmt"]:
            return True
        return change_flag

    def get_next_stmts_for_state_analysis(self, stmt_id, symbol_graph):
        if not symbol_graph.has_node(stmt_id):
            return set()

        results = set()
        for tmp_id in util.graph_successors(symbol_graph, stmt_id):
            for tmp_stmt in util.graph_successors(symbol_graph, tmp_id):
                results.add(tmp_stmt)

        return results

    def unset_states_of_defined_symbol(self, stmt_id, frame: ComputeFrame, status: StmtStatus):
        defined_symbol = frame.symbol_state_space[status.defined_symbol]
        if defined_symbol:
            defined_symbol.states = set()
        status.implicitly_defined_symbols = []

    def restore_states_of_defined_symbol_and_status(
        self, stmt_id, frame: ComputeFrame, status: StmtStatus, old_defined_symbol_states, old_implicitly_defined_symbols, old_status_defined_states
    ):
        defined_symbol = frame.symbol_state_space[status.defined_symbol]
        if defined_symbol:
            defined_symbol.states = old_defined_symbol_states
        status.implicitly_defined_symbols = old_implicitly_defined_symbols
        status.defined_states = old_status_defined_states

    def check_outdated_state_indexes(self, status, frame: ComputeFrame):
        outdated_state_indexes = set()
        for defined_symbol_index in [status.defined_symbol, *status.implicitly_defined_symbols]:
            defined_symbol = frame.symbol_state_space[defined_symbol_index]
            if defined_symbol:
                for each_state_index in defined_symbol.states:
                    if frame.state_bit_vector_manager.exist_state_index(each_state_index):
                        outdated_state_indexes.add(each_state_index)
        return outdated_state_indexes

    def adjust_computation_results(self, stmt_id, frame, status: StmtStatus, old_index_ceiling):
        available_state_defs = frame.state_bit_vector_manager.explain(status.in_state_bits)
        for defined_symbol_index in [status.defined_symbol, *status.implicitly_defined_symbols]:
            defined_symbol = frame.symbol_state_space[defined_symbol_index]
            if not isinstance(defined_symbol, Symbol):
                continue
            adjusted_states = self.resolver.collect_newest_states_by_state_indexes(
                frame, stmt_id, defined_symbol.states, available_state_defs, old_index_ceiling
            )

            defined_symbol.states = adjusted_states

        adjusted_states = self.resolver.collect_newest_states_by_state_indexes(
            frame, stmt_id, status.defined_states, available_state_defs, old_index_ceiling
        )

        status.defined_states = adjusted_states

    @profile
    def add_sfg_edge_of_defined_symbol_to_state(self, stmt_id, stmt, status, frame:ComputeFrame, old_defined_symbol_states):
        if stmt.operation == "variable_decl":
            return
        for each_symbol_index in [status.defined_symbol, *status.implicitly_defined_symbols]:
            defined_symbol = frame.symbol_state_space[each_symbol_index]
            if not isinstance(defined_symbol, Symbol):
                continue
            for each_state_index in defined_symbol.states:
                if each_state_index == -1:
                    continue
                
                if each_state_index in old_defined_symbol_states:
                    continue

                state = frame.symbol_state_space[each_state_index]
                if not isinstance(state, State):
                    continue
                tmp_context = None
                if self.analysis_phase_id == ANALYSIS_PHASE_ID.GLOBAL_SEMANTICS:
                    tmp_context = frame.get_context()

                frame.state_flow_graph.add_edge(
                    SFGNode(
                        node_type=SFG_NODE_KIND.SYMBOL,
                        def_stmt_id=defined_symbol.stmt_id,
                        index=each_symbol_index,
                        node_id=defined_symbol.symbol_id,
                        name=defined_symbol.name,
                    ),
                    SFGNode(
                        node_type=SFG_NODE_KIND.STATE,
                        def_stmt_id=state.stmt_id,
                        index=each_state_index,
                        node_id=state.state_id,
                        access_path=state.access_path,
                    ),
                    SFGEdge(
                        edge_type=SFG_EDGE_KIND.SYMBOL_STATE,
                        stmt_id=stmt_id,
                    )
                )

    def is_global_phase_first_round(self, stmt_id, frame):
        if self.analysis_phase_id == ANALYSIS_PHASE_ID.GLOBAL_SEMANTICS:
            if frame.is_first_round[stmt_id]:
                return True
        return False

    @profile
    def compute_stmt_states(self, stmt_id, stmt, frame: ComputeFrame):
        status = frame.stmt_id_to_status[stmt_id]
        in_states = {}
        symbol_graph = frame.symbol_graph.graph

        if not symbol_graph.has_node(stmt_id) :
            return P2ResultFlag()

        # collect in state bits
        old_defined_symbol_states = set()
        defined_symbol = frame.symbol_state_space[status.defined_symbol]
        if isinstance(defined_symbol, Symbol):
            old_defined_symbol_states = defined_symbol.states
        old_status_defined_states = status.defined_states
        old_in_state_bits = status.in_state_bits
        old_index_ceiling = frame.symbol_state_space.get_length()
        old_implicitly_defined_symbols = status.implicitly_defined_symbols.copy()
        old_implicitly_used_symbols = status.implicitly_used_symbols.copy()
        status.in_state_bits = self.collect_in_state_bits(stmt_id, stmt, frame)
        # reset defined_states
        status.defined_states = set()
        # collect in state

        in_symbol_indexes = self.get_used_symbol_indexes(stmt_id, frame, status)
        used_symbol_id_to_indexes = self.group_used_symbol_id_to_indexes(in_symbol_indexes, frame)
        in_states = self.group_in_states(stmt_id, stmt, in_symbol_indexes, frame, status)
        method_summary = frame.method_summary_template
        continue_flag = self.complete_in_states_and_check_continue_flag(stmt_id, frame, stmt, status, in_states, method_summary)
        if not continue_flag:
            if status.in_state_bits != old_in_state_bits:
                status.out_state_bits = status.in_state_bits
            self.restore_states_of_defined_symbol_and_status(stmt_id, frame, status, old_defined_symbol_states, old_implicitly_defined_symbols, old_status_defined_states)
            return P2ResultFlag()

        self.unset_states_of_defined_symbol(stmt_id, frame, status)
        util.debug("before stmt_state_analysis")
        change_flag: P2ResultFlag = frame.stmt_state_analysis.run(stmt_id, stmt, status, in_states, used_symbol_id_to_indexes)
        if change_flag is None:
            change_flag = P2ResultFlag()

        self.adjust_computation_results(stmt_id, frame, status, old_index_ceiling)
        util.debug("after adjust_computation_results")
        new_out_states = self.update_out_states(stmt_id, frame, status, old_index_ceiling)

        if self.options.debug:
            self.collect_defined_states_amount_for_debug(stmt_id, stmt, len(new_out_states), in_states)

        new_defined_symbol_states = set()
        if defined_symbol := frame.symbol_state_space[status.defined_symbol]:
            new_defined_symbol_states = defined_symbol.states

        if new_out_states:
            change_flag.state_changed = True

        if new_defined_symbol_states != old_defined_symbol_states:
            change_flag.state_changed = True

        if status.implicitly_defined_symbols != old_implicitly_defined_symbols:
            change_flag.symbol_def_changed = True

        if status.implicitly_used_symbols != old_implicitly_used_symbols:
            change_flag.symbol_use_changed = True

        if change_flag.state_changed:
            frame.stmts_with_symbol_update.add(
                self.get_next_stmts_for_state_analysis(stmt_id, symbol_graph)
            )

        if change_flag.state_changed or change_flag.symbol_def_changed:
            self.add_sfg_edge_of_defined_symbol_to_state(stmt_id, stmt, status, frame, old_defined_symbol_states)

        return change_flag

    def group_states_with_state_ids(self, frame: ComputeFrame, state_indexes: set):
        state_id_to_indexes = {}
        space = frame.symbol_state_space
        for index in state_indexes:
            if not isinstance(state := space[index], State):
                continue
            state_id = state.state_id
            util.add_to_dict_with_default_set(state_id_to_indexes, state_id, index)
        return state_id_to_indexes

    def update_method_def_use_summary(self, stmt_id, frame: ComputeFrame):
        summary = frame.method_def_use_summary
        status = frame.stmt_id_to_status[stmt_id]
        for implicitly_defined_symbols_index in status.implicitly_defined_symbols:
            implicitly_defined_symbol = frame.symbol_state_space[implicitly_defined_symbols_index]
            if not isinstance(implicitly_defined_symbol, Symbol):
                continue
            symbol_id = implicitly_defined_symbol.symbol_id
            if symbol_id in frame.all_local_symbol_ids:
                continue
            # only keyword global and nonlocal symbol can be added in defined_external_symbol_ids in python

        for symbol_id in status.implicitly_used_symbols:
            if symbol_id in frame.all_local_symbol_ids:
                continue
            summary.used_external_symbol_ids.add(symbol_id)

    def save_analysis_summary_and_space(self, frame: ComputeFrame, method_summary: MethodSummaryTemplate, compact_space: SymbolStateSpace):
        self.loader.save_symbol_state_space_summary_p2(frame.method_id, compact_space)
        self.loader.save_method_summary_template(frame.method_id, method_summary)

    def generate_and_save_analysis_summary(self, frame: ComputeFrame, method_summary: MethodSummaryTemplate):
        def_use_summary = frame.method_def_use_summary
        if util.is_empty(def_use_summary):
            return

        symbol_state_space = frame.symbol_state_space

        basic_target_symbol_ids = set()
        for each_id_set in (
            {pair[0] for pair in def_use_summary.parameter_symbol_ids}, # 只取每个二元组的前一个元素
            [def_use_summary.this_symbol_id],
            # def_use_summary.used_external_symbol_ids,
            def_use_summary.defined_external_symbol_ids,
        ):
            basic_target_symbol_ids.update(each_id_set)

        all_indexes = set()

        for stmt_id in util.find_cfg_last_nodes(frame.cfg):
            stmt = frame.unit_gir.get_stmt_by_id(stmt_id)
            status = frame.stmt_id_to_status[stmt_id]
            current_symbol_bits = status.out_symbol_bits
            current_state_bits = status.out_state_bits

            # obtain target symbol_ids
            returned_states = set()
            current_symbol_ids = basic_target_symbol_ids.copy()
            if stmt.operation in RETURN_STMT_OPERATION and len(status.used_symbols) != 0: # 说明该语句有return_symbol
                returned_symbol_index = status.used_symbols[0]
                returned_symbol = symbol_state_space[returned_symbol_index]
                if isinstance(returned_symbol, Symbol):
                    returned_states.update(returned_symbol.states)
                else:
                    returned_states.add(returned_symbol_index)

            # get current out_bits from return_stmt_id
            available_defined_symbols = frame.symbol_bit_vector_manager.explain(current_symbol_bits) # 收集到当前last_stmt中所有可用last_symbol_def
            available_defined_states = frame.state_bit_vector_manager.explain(current_state_bits)
            # find symbol_ids' states
            old_states = set()
            symbol_id_to_old_state_indexes= {}
            for symbol_def_node in available_defined_symbols:
                if not isinstance(symbol_def_node, SymbolDefNode):
                    continue
                symbol_id = symbol_def_node.symbol_id
                if symbol_id in current_symbol_ids: # 说明是我们需要放到summary中去的symbol
                     symbol = symbol_state_space[symbol_def_node.index]
                     # get old_states
                     if symbol and isinstance(symbol, Symbol):
                        util.add_to_dict_with_default_set(symbol_id_to_old_state_indexes, symbol_id, symbol.states)

            # 统一更新所有小弟
            state_index_old_to_new = {}
            symbol_id_to_latest_state_indexes = {}
            for symbol_id in symbol_id_to_old_state_indexes:
                old_states = symbol_id_to_old_state_indexes[symbol_id]
                latest_states = self.resolver.retrieve_latest_states(frame, stmt_id, symbol_state_space, old_states, available_defined_states, state_index_old_to_new)
                # 将latest_states中所有state_id相同的states进行合并成一个state,避免summary中保存的state过多。
                state_id_to_indexes = self.group_states_with_state_ids(frame, latest_states)
                fusion_states = set()
                for state_id, states_with_same_id in state_id_to_indexes.items():
                    if (len(states_with_same_id) > 1):
                        fusion_state = frame.stmt_state_analysis.fuse_states_to_one_state(states_with_same_id, stmt_id, stmt, status)
                        fusion_states.update(fusion_state)
                    else:
                        fusion_states.update(states_with_same_id)
                symbol_id_to_latest_state_indexes[symbol_id] = fusion_states

            # 补充defined_external_symbol_ids的情况，因为defined_external_symbol_ids在frame里没有symbol_def_node
            for symbol_id in def_use_summary.defined_external_symbol_ids:
                state_index = frame.external_symbol_id_to_initial_state_index.get(symbol_id, None)
                if state_index:
                    latest_states = self.resolver.retrieve_latest_states(frame, stmt_id, symbol_state_space, {state_index}, available_defined_states, state_index_old_to_new)
                    state_id_to_indexes = self.group_states_with_state_ids(frame, latest_states)
                    fusion_states = set()
                    for state_id, states_with_same_id in state_id_to_indexes.items():
                        if (len(states_with_same_id) > 1):
                            fusion_state = frame.stmt_state_analysis.fuse_states_to_one_state(states_with_same_id, stmt_id, stmt, status)
                            fusion_states.update(fusion_state)
                        else:
                           fusion_states.update(states_with_same_id)
                    symbol_id_to_latest_state_indexes[symbol_id] = fusion_states

            # save results
            lines_to_be_updated = (
                (def_use_summary.parameter_symbol_ids,          method_summary.parameter_symbols),
                # (def_use_summary.used_external_symbol_ids,      method_summary.used_external_symbols),
                (def_use_summary.defined_external_symbol_ids,   method_summary.defined_external_symbols),
                # (def_use_summary.return_symbol_ids,             method_summary.return_symbols),
                # (returned_symbol_id,                            method_summary.return_symbols),
                (set(),                                         method_summary.key_dynamic_content),
                ([def_use_summary.this_symbol_id],        method_summary.this_symbols),
            )
            # 逐条语句添加
            for summary_ids, content_record in lines_to_be_updated:
                for symbol_id in content_record:
                    state_index_set = content_record[symbol_id]
                    all_indexes.update(state_index_set)

                for symbol_id in summary_ids:
                    default_value_symbol_id = -1
                    if isinstance(symbol_id, (int, numpy.int64)):
                        default_value_symbol_id = -1
                    # only parameter_symbol_id may have a default_value_symbol_id
                    elif isinstance(symbol_id, tuple):
                        symbol_id = symbol_id[0]
                        #default_value_symbol_id = symbol_id[1]

                    if symbol_id in symbol_id_to_latest_state_indexes:
                        state_indexes = symbol_id_to_latest_state_indexes[symbol_id]
                        for each_state_index in state_indexes:
                            util.add_to_dict_with_default_set(
                                content_record,
                                symbol_id,
                                {each_state_index}
                            )
                            all_indexes.add(each_state_index)
                            if default_value_symbol_id != -1:
                                method_summary.index_to_default_value[each_state_index] = default_value_symbol_id

            # 处理return
            new_return_states = self.resolver.retrieve_latest_states(frame, stmt_id, symbol_state_space, returned_states, available_defined_states, state_index_old_to_new)

            if new_return_states:
                util.add_to_dict_with_default_set(
                    method_summary.return_symbols,
                    SUMMARY_GENERAL_SYMBOL_ID.RETURN_SYMBOL_ID,
                    new_return_states
                )
                all_indexes.update(new_return_states)

        method_summary.external_symbol_to_state = frame.external_symbol_id_to_initial_state_index

        if self.analysis_phase_id == ANALYSIS_PHASE_ID.PRELIM_SEMANTICS:
            # save space
            compact_space = frame.symbol_state_space.extract_related_elements_to_new_space(all_indexes)
            # adjust ids and save summary template
            method_summary.adjust_ids(compact_space.old_index_to_new_index)
            self.save_analysis_summary_and_space(frame, method_summary, compact_space)
        return method_summary

    @profile
    def analyze_stmts(self, frame: ComputeFrame):
        # perf counters (debug only)
        while len(frame.stmt_worklist) != 0:
            stmt_id = frame.stmt_worklist.peek()
            if stmt_id <= 0 or stmt_id not in frame.stmt_counters:
                frame.stmt_worklist.pop()
                continue

            stmt = frame.unit_gir.get_stmt_by_id(stmt_id)
            if stmt_id in frame.loop_total_rounds:
                if frame.stmt_counters[stmt_id] <= frame.loop_total_rounds[stmt_id]:
                    frame.stmt_worklist.add(util.graph_successors(frame.cfg, stmt_id))
                    frame.stmts_with_symbol_update.add(stmt_id)
                else:
                    frame.stmt_worklist.pop()
                    continue
            else:
                if frame.stmt_counters[stmt_id] < self.max_analysis_round:
                    frame.stmt_worklist.add(util.graph_successors(frame.cfg, stmt_id))
                else:
                    frame.stmt_worklist.pop()
                    continue

            if self.options.debug:
                util.debug(f"-----analyzing stmt <{stmt_id}> of method <{frame.method_id}> operation is {stmt.operation}-----")

            if frame.interruption_flag:
                frame.interruption_flag = False
            else:
                # compute in/out bits
                self.analyze_reachable_symbols(stmt_id, stmt, frame)

            # according to symbol_graph, compute the state flow of current statement
            result_flag = self.compute_stmt_states(stmt_id, stmt, frame)
            frame.stmts_with_symbol_update.remove(stmt_id)
            # check if interruption is enabled
            if result_flag.interruption_flag:
                return result_flag

            # re-analyze def/use
            if result_flag.symbol_def_changed or result_flag.symbol_use_changed:
                # change out_bit to reflect implicitly_defined_symbols
                self.rerun_analyze_reachable_symbols(stmt_id, stmt, frame, result_flag)
                # update method def/use
                self.update_method_def_use_summary(stmt_id, frame)

            frame.stmt_worklist.pop()
            frame.stmt_counters[stmt_id] += 1
            frame.is_first_round[stmt_id] = False

    def save_graph_to_dot(self, graph, entry_point, phase_id, symbol_state_space):
        if not (self.options.graph or self.options.complete_graph):
            return

        if graph is None or len(graph) == 0:
            return

        dumper = SFGDumper(
            loader=self.loader,
            options=self.options,
            phase_id=phase_id,
            entry_point=entry_point,
            symbol_state_space=symbol_state_space,
            graph=graph,
            taint_manager=None
        )

        try:
            file_name = dumper.dump_to_file()
            if self.options.debug:
                util.debug(">>> Write state flow graph to dot file: ", file_name)
        except Exception:
            if not self.options.quiet:
                util.error("An error occurred while writing state flow graph to dot file.")
                traceback.print_exc()

    @profile
    def analyze_method(self, method_id):
        current_frame = ComputeFrame(method_id=method_id, loader=self.loader)
        frame_stack = ComputeFrameStack().add(current_frame)
        while len(frame_stack) != 0:
            frame = frame_stack.peek()


            if not frame.has_been_inited:
                if not self.options.quiet:
                    print(f"Analyzing <method {frame.method_id}>")
                if self.init_compute_frame(frame, frame_stack) is None:
                    self.analyzed_method_list.add(frame.method_id)
                    frame_stack.pop()
                    continue

            result: P2ResultFlag = self.analyze_stmts(frame)
            if result is not None and result.interruption_flag and result.interruption_data:
                # here an interruption is faced
                # create a new frame and add it to the stack
                frame.interruption_flag = True
                data:InterruptionData = result.interruption_data
                if not self.options.quiet:
                    print(f"Interrupt! Now handle unsolved_callee_ids: {data.callee_ids}")
                if len(data.callee_ids) != 0:
                    frame.stmts_with_symbol_update.add(data.call_stmt_id)
                    for callee_id in data.callee_ids:
                        if callee_id not in self.analyzed_method_list:
                            new_frame = ComputeFrame(
                                method_id = callee_id,
                                caller_id = data.caller_id,
                                call_stmt_id = data.call_stmt_id,
                                loader = self.loader
                            )
                            frame_stack.add(new_frame)
                # new_frame = ComputeFrame(method_id = data.method_id, caller_id = data.caller_id, call_stmt_id = data.call_stmt_id, loader = self.loader)
                # frame_stack.add(new_frame)
                continue

            # Current frame is done, pop it
            # save the result
            self.analyzed_method_list.add(frame.method_id)

            self.generate_and_save_analysis_summary(frame, frame.method_summary_template)
            self.loader.save_stmt_status_p2(frame.method_id, frame.stmt_id_to_status)
            self.loader.save_symbol_bit_vector_p2(frame.method_id, frame.symbol_bit_vector_manager)
            self.loader.save_state_bit_vector_p2(frame.method_id, frame.state_bit_vector_manager)
            self.loader.save_symbol_state_space_p2(frame.method_id, frame.symbol_state_space)
            self.loader.save_method_symbol_graph_p2(frame.method_id, frame.symbol_graph.graph)
            self.loader.save_method_defined_symbols_p2(frame.method_id, frame.defined_symbols)
            self.loader.save_method_defined_states_p2(frame.method_id, frame.defined_states)
            self.loader.save_method_def_use_summary(frame.method_id, frame.method_def_use_summary)
            self.loader.save_method_sfg(frame.method_id, frame.state_flow_graph.graph)
            self.save_graph_to_dot(frame.state_flow_graph.graph, frame.method_id, self.analysis_phase_id, frame.symbol_state_space)

            if frame.method_id not in self._p2_total_methods_set:
                self._p2_total_methods_set.add(frame.method_id)

            frame_stack.pop()

    def sort_methods_by_unit_id(self, methods):
        return sorted(list(methods), key=lambda method: self.loader.convert_method_id_to_unit_id(method))

    def reversed_methods_by_unit_id(self, methods):
        return reversed(self.sort_methods_by_unit_id(methods))

    def collect_defined_states_amount_for_debug(self, stmt_id, stmt, new_out_states_len, in_states):
        op = stmt.operation

        if stmt_id not in self.count_stmt_defined_states_for_debug:
            self.count_stmt_defined_states_for_debug[stmt_id] = CountStmtDefStateNode(stmt_id, op, in_states)
        self.count_stmt_defined_states_for_debug[stmt_id].add_new_states_count(new_out_states_len)

        if op not in self.count_stmt_defined_states_number_for_debug:
            self.count_stmt_defined_states_number_for_debug[op] = 0
        self.count_stmt_defined_states_number_for_debug[op] += new_out_states_len

    def print_count_stmt_def_states(self):
        filtered_stmts_nodes = [node for node in self.count_stmt_defined_states_for_debug.values() if node.new_out_states_len >= 5]
        sorted_stmts_nodes = sorted(filtered_stmts_nodes, key=lambda x: x.new_out_states_len, reverse=True)
        counter = 0
        for node in sorted_stmts_nodes:
            if counter >= 20:
                break
            counter+=1
            node.print_as_dict()

        sorted_ops = sorted(self.count_stmt_defined_states_number_for_debug.items(), key=lambda x: x[1], reverse=True)
        counter = 0
        for each_op in sorted_ops:
            if counter >= 20:
                break
            counter+=1

    def run(self):
        if not self.options.quiet:
            print("\n############ # Phase II: Preliminary (Bottom-up) Analysis # ##########")

        # analyze all methods
        grouped_methods:SimplyGroupedMethodTypes = self.loader.get_grouped_methods()
        # initialize total method set for progress printing
        self._p2_total_methods_set = set(grouped_methods.get_methods_with_direct_call()) | set(grouped_methods.get_methods_with_dynamic_call())
        for method_id in grouped_methods.get_methods_with_direct_call():
            if method_id not in self.analyzed_method_list:
                self.analyze_method(method_id)

        # in every round only analyze the stmts once
        for method_id in grouped_methods.get_methods_with_dynamic_call():
            if method_id not in self.analyzed_method_list:
                self.analyze_method(method_id)

        # save all results here
        self.loader.save_call_graph_p2(self.call_graph)
        # self.print_count_stmt_def_states()

        return self
