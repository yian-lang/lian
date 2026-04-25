#!/usr/bin/env python3

import os,sys
import pprint
import copy
from os.path import commonprefix

import networkx as nx
from lian.core.prelim_semantics import P2PrelimSemanticAnalysis
from lian.util import util
from lian.config import config
import lian.util.data_model as dm
from lian.config.constants import (
    LIAN_INTERNAL,
    STATE_TYPE_KIND,
    SYMBOL_DEPENDENCY_GRAPH_EDGE_KIND,
    SYMBOL_OR_STATE,
    ANALYSIS_PHASE_ID,
    CALL_OPERATION,
    SENSITIVE_OPERATIONS
)
from lian.common_structs import (
    MetaComputeFrame,
    P2ResultFlag,
    Symbol,
    State,
    ComputeFrame,
    ComputeFrameStack,
    SimpleWorkList,
    SummaryData,
    InterruptionData,
    MethodSummaryTemplate,
    SymbolDefNode,
    SymbolStateSpace,
    BasicCallGraph,
    CallGraph,
    PathManager,
    StateDefNode,
    MethodSummaryInstance,
    CallPath,
    StmtStatus,
    StateFlowGraph,
    CallSite,
)
from lian.basics.entry_points import EntryPointGenerator
from lian.basics.control_flow import ControlFlowAnalysis
from lian.basics.stmt_def_use_analysis import StmtDefUseAnalysis
from lian.core.stmt_states import StmtStates
from lian.core.prelim_semantics import P2PrelimSemanticAnalysis
from lian.util.gir_block import GIRBlockViewer
from lian.util.loader import Loader
from lian.core.resolver import Resolver
from lian.core.global_stmt_states import GlobalStmtStates
from networkx.generators.classic import complete_graph


class P3GlobalSemanticAnalysis(P2PrelimSemanticAnalysis):
    def __init__(self, lian, analyzed_method_list):
        super().__init__(lian)
        self.max_analysis_round = config.MAX_ANALYSIS_ROUND_FOR_GLOBAL_ANALYSIS
        self.path_manager = PathManager()
        self.analyzed_method_list = analyzed_method_list
        self.analysis_phase_id = ANALYSIS_PHASE_ID.GLOBAL_SEMANTICS
        self.caller_unknown_callee_edge = {}
        self.call_site_analyze_counter = {}

    def _describe_method_context(self, method_id):
        method_name = "<unknown>"
        unit_path = "<unknown>"

        try:
            method_format = self.loader.convert_method_id_to_method_decl_format(method_id)
            if method_format and getattr(method_format, "name", None):
                method_name = method_format.name
        except Exception:
            pass

        try:
            unit_id = self.loader.convert_method_id_to_unit_id(method_id)
            unit_info = self.loader.convert_module_id_to_module_info(unit_id)
            if unit_info and getattr(unit_info, "original_path", None):
                unit_path = unit_info.original_path
        except Exception:
            pass

        return method_name, unit_path

    def get_stmt_id_to_callee_info(self, callees):
        results = {}
        for each_callee in callees:
            results[each_callee.stmt_id] = each_callee
        return results

    def adjust_index_of_status_space(self, baseline_index, frame, status,space, defined_symbols, symbol_bit_vector, state_bit_vector, method_summary_template):
        if method_summary_template:
            for symbol_id in method_summary_template.used_external_symbols:
                new_index_set = set()
                for index in method_summary_template.used_external_symbols[symbol_id]:
                    new_index_set.add(index + baseline_index)
                method_summary_template.used_external_symbols[symbol_id] = new_index_set
        if symbol_bit_vector:
            for symbol_def_nodes in symbol_bit_vector.bit_pos_to_id.values():
                symbol_def_nodes.index += baseline_index
        else:
            return

        for state_def_nodes in state_bit_vector.bit_pos_to_id.values():
            state_def_nodes.index += baseline_index
        # for symbol_def_nodes in defined_symbols.values():
        #     for node in symbol_def_nodes:
        #         node.index += baseline_index
        for stmt_status in status.values():
            for each_id, value in enumerate(stmt_status.used_symbols):
                if value != -1:
                    stmt_status.used_symbols[each_id] = value + baseline_index
            for each_id, value in enumerate(stmt_status.implicitly_used_symbols):
                if value != -1:
                    stmt_status.implicitly_used_states[each_id] = value + baseline_index
            for each_id, value in enumerate(stmt_status.implicitly_defined_symbols):
                stmt_status.implicitly_defined_symbols[each_id] = value + baseline_index

            new_in_symbol_bits = set()
            new_out_symbol_bits = set()
            new_in_state_bits = set()
            new_out_state_bits = set()

            for symbol_def_node in stmt_status.in_symbol_bits:
                new_node = SymbolDefNode(
                    index=symbol_def_node.index + baseline_index,
                    symbol_id=symbol_def_node.symbol_id,
                    stmt_id=symbol_def_node.stmt_id
                )
                new_in_symbol_bits.add(new_node)

            for symbol_def_node in stmt_status.out_symbol_bits:
                new_node = SymbolDefNode(
                    index=symbol_def_node.index + baseline_index,
                    symbol_id=symbol_def_node.symbol_id,
                    stmt_id=symbol_def_node.stmt_id
                )
                new_out_symbol_bits.add(new_node)

            for state_def_node in stmt_status.in_state_bits:
                new_node = StateDefNode(
                    index=state_def_node.index + baseline_index,
                    state_id=state_def_node.state_id,
                    stmt_id=state_def_node.stmt_id
                )
                new_in_state_bits.add(new_node)

            for state_def_node in stmt_status.out_state_bits:
                new_node = StateDefNode(
                    index=state_def_node.index + baseline_index,
                    state_id=state_def_node.state_id,
                    stmt_id=state_def_node.stmt_id
                )
                new_out_state_bits.add(new_node)


            stmt_status.in_symbol_bits = new_in_symbol_bits
            stmt_status.out_symbol_bits = new_out_symbol_bits
            stmt_status.in_state_bits = new_in_state_bits
            stmt_status.out_state_bits = new_out_state_bits

            stmt_status.defined_symbol += baseline_index

        for each_item in space:
            # each_item.index += baseline_index

            if isinstance(each_item, Symbol):
                new_set = set()
                for each_id in each_item.states:
                    new_set.add(each_id + baseline_index)
                each_item.states = new_set
            else:
                for each_id, each_status in enumerate(each_item.array):
                    new_set = set()
                    for index in each_status:
                        new_set.add(index + baseline_index)
                    each_item.array[each_id] = new_set
                for each_field, value_set in each_item.fields.items():
                    new_set = set()
                    for index in value_set:
                        new_set.add(index + baseline_index)
                    each_item.fields[each_field] = new_set
            # ????
            #each_item.call_site = frame.call_path[-1]

    def init_compute_frame(self, frame: ComputeFrame, frame_stack: ComputeFrameStack, global_space):   
        if frame.is_meta_frame:
            return None

        frame.has_been_inited = True
        frame.frame_stack = frame_stack
        method_id = frame.method_id

        if not self.loader.contain_symbol_state_space_p1(method_id):
            return None
        frame.cfg = self.loader.get_method_cfg(method_id)
        if util.is_empty(frame.cfg):
            return None
        if len(frame_stack) > 2:
            last_frame = frame_stack[-2]
            frame.call_path = last_frame.call_path.add_call(
                last_frame.method_id, frame.call_stmt_id, frame.method_id
            )
            self.path_manager.add_path(frame.call_path)

        if not self.options.enable_p2:
            super().init_compute_frame(frame, frame_stack)
            
            for stmt in frame.stmt_worklist:
                frame.stmts_with_symbol_update.add(stmt)

            frame.stmt_state_analysis = GlobalStmtStates(
                analysis_phase_id = self.analysis_phase_id,
                event_manager = self.event_manager,
                loader = self.loader,
                resolver = self.resolver,
                compute_frame = frame,
                path_manager = self.path_manager,
                caller_unknown_callee_edge = self.caller_unknown_callee_edge,
                complete_graph=self.options.complete_graph,
            )

            self.adjust_index_of_status_space(len(global_space), frame, frame.stmt_id_to_status, frame.symbol_state_space, frame.defined_symbols, frame.symbol_bit_vector_manager, frame.state_bit_vector_manager, frame.method_summary_template)
            for item in frame.symbol_state_space:
                global_space.add(item)
            frame.symbol_state_space = global_space
            
            return frame


        
        round_number = config.FIRST_ROUND
        if method_id in self.analyzed_method_list:
            round_number = config.SECOND_ROUND
        _, parameter_decls, method_body = self.loader.get_splitted_method_gir(method_id)
        parameter_decl_block = GIRBlockViewer(parameter_decls)
        method_body_block = GIRBlockViewer(method_body)
        frame.unit_gir.append_other(parameter_decl_block).append_other(method_body_block)

        for stmt_id in frame.unit_gir.get_all_stmt_ids():
            frame.stmt_counters[stmt_id] = round_number
            frame.is_first_round[stmt_id] = True

        frame.stmt_state_analysis = GlobalStmtStates(
            analysis_phase_id = self.analysis_phase_id,
            event_manager = self.event_manager,
            loader = self.loader,
            resolver = self.resolver,
            compute_frame = frame,
            path_manager = self.path_manager,
            caller_unknown_callee_edge = self.caller_unknown_callee_edge,
            complete_graph=self.options.complete_graph,
        )

        frame.stmt_worklist = SimpleWorkList(graph = frame.cfg)
        first_stmts = util.find_cfg_first_nodes(frame.cfg)
        frame.stmt_worklist.add(first_stmts)
        frame.stmts_with_symbol_update.add(first_stmts)
        defined_symbols = self.loader.get_method_defined_symbols_p2(method_id)
        if defined_symbols:
            frame.defined_symbols = defined_symbols
            all_symbol_defs = set()
            for stmt_id in frame.defined_symbols:
                symbol_def_set = frame.defined_symbols[stmt_id]
                for symbol_def in symbol_def_set:
                    all_symbol_defs.add(symbol_def)
            frame.all_symbol_defs = all_symbol_defs

        defined_states = self.loader.get_method_defined_states_p2(method_id)
        if defined_states:
            frame.defined_states = defined_states

        # avoid changing the content of the loader
        stmt_id_to_status = self.loader.get_stmt_status_p2(method_id)
        symbol_state_space = self.loader.get_symbol_state_space_p2(method_id)
        defined_symbols = self.loader.get_method_defined_symbols_p2(method_id)
        symbol_bit_vector_manager = self.loader.get_symbol_bit_vector_p2(method_id)
        state_bit_vector_manager = self.loader.get_state_bit_vector_p2(method_id)
        frame.symbol_bit_vector_manager = symbol_bit_vector_manager
        frame.state_bit_vector_manager = state_bit_vector_manager
        method_summary_template = self.loader.get_method_summary_template(method_id)
        frame.method_summary_template = method_summary_template
        self.adjust_index_of_status_space(len(global_space), frame, stmt_id_to_status, symbol_state_space, defined_symbols, symbol_bit_vector_manager, state_bit_vector_manager, method_summary_template)
        frame.stmt_id_to_status = stmt_id_to_status
        frame.defined_symbols = defined_symbols
        # This is the results generated by the previous phase
        if not symbol_state_space:
            return None
        for item in symbol_state_space:
            global_space.add(item)

        frame.symbol_state_space = global_space
        frame.stmt_id_to_callee_info = self.get_stmt_id_to_callee_info(self.loader.get_method_internal_callees(method_id))

        frame.method_def_use_summary = self.loader.get_method_def_use_summary(method_id)
        frame.external_symbol_id_to_initial_state_index = frame.method_summary_template.external_symbol_to_state
        frame.space_summary = self.loader.get_symbol_state_space_summary_p2(method_id)
        frame.symbol_graph.graph = self.loader.get_method_symbol_graph_p2(method_id)
        frame.method_summary_instance.copy_template_to_instance(frame.method_summary_template)
        return frame

    def collect_external_symbol_states(self, frame: ComputeFrame, stmt_id, stmt, symbol_id, summary: MethodSummaryTemplate, old_key_state_indexes: set):
        # key_dynamic_content = summary.key_dynamic_content
        if not frame.is_first_round[stmt_id]:
            return old_key_state_indexes

        new_state_indexes = set()

        status = frame.stmt_id_to_status[stmt_id]
        old_length = len(frame.symbol_state_space)
        for old_key_state_index in old_key_state_indexes:
            old_key_state = frame.symbol_state_space[old_key_state_index]
            if not(old_key_state and isinstance(old_key_state, State)):
                continue

            if old_key_state.data_type in (LIAN_INTERNAL.METHOD_DECL, LIAN_INTERNAL.CLASS_DECL):
                new_state_indexes.add(old_key_state_index)
                continue

            if old_key_state.symbol_or_state != SYMBOL_OR_STATE.EXTERNAL_KEY_STATE:
                continue

            # TODO JAVA CASE 处理java中 call this()的情况，应该去找它的构造函数
            if stmt.operation in CALL_OPERATION and old_key_state.data_type == LIAN_INTERNAL.THIS:
                continue

            if old_key_state.state_type != STATE_TYPE_KIND.ANYTHING:
                continue

            resolved_state_indexes = self.resolver.resolve_symbol_states(old_key_state, frame.frame_stack, frame, stmt_id, stmt, status)
            util.add_to_dict_with_default_set(frame.method_summary_instance.resolver_result, old_key_state_index, resolved_state_indexes)
            for each_resolved_state_index in resolved_state_indexes:
                each_resolved_state: State = frame.symbol_state_space[each_resolved_state_index]
                each_resolved_state.state_id = old_key_state.state_id
            new_state_indexes.update(resolved_state_indexes)

        # append callee space to caller space
        new_length = len(frame.symbol_state_space)
        while old_length < new_length:
            item = frame.symbol_state_space[old_length]
            if isinstance(item, State):
                status.defined_states.add(old_length)
            old_length += 1

        # update external symbols
        # used_external_symbols[symbol_id] = {IndexMapInSummary(raw_index = index, new_index = -1) for index in new_state_indexes}
        # if self.options.debug:
        #     for index in new_state_indexes:
        return new_state_indexes

    # def generate_analysis_summary_and_s2space(self, frame: ComputeFrame):
    #     summary_data = SummaryData()
    #     return summary_data

    # def save_result_to_last_frame_v1(self, frame_stack: ComputeFrameStack, current_frame: ComputeFrame, summary: MethodSummaryTemplate):
    #     self.save_result_to_last_frame_v2(frame_stack, current_frame, summary, current_frame.space_summary)

    # def save_result_to_last_frame_v2(self, frame_stack: ComputeFrameStack, current_frame: ComputeFrame, summary: MethodSummaryTemplate, s2space: SymbolStateSpace):
    #     summary_data = SummaryData(summary, s2space)
    #     self.save_result_to_last_frame_v3(frame_stack, current_frame, summary_data)

    # def save_result_to_last_frame_v3(self, frame_stack: ComputeFrameStack, current_frame: ComputeFrame, summary_data):
    #     last_frame: MetaComputeFrame = frame_stack[-2]
    #     key = CallSite(current_frame.caller_id, current_frame.call_stmt_id, current_frame.method_id)
    #     last_frame.summary_collection[key] = summary_data

    def analyze_frame_stack(self, frame_stack: ComputeFrameStack, global_space, sfg: StateFlowGraph):
        while len(frame_stack) >= 2:
            # get current compute frame
            frame: ComputeFrame = frame_stack.peek()
            if frame.is_meta_frame:
                frame_stack.pop()
                continue

            if not frame.has_been_inited:
                # Attempt to initialize the frame
                if self.init_compute_frame(frame, frame_stack, global_space) is None:
                    # Remove the frame from the stack in both cases
                    frame_stack.pop()
                    continue

            if frame.content_already_analyzed:
                # check if all children have been analyzed
                children_done_flag = True
                for key, value in frame.content_already_analyzed.items():
                    if not value: # false means not done
                        frame.content_already_analyzed[key] = True
                        new_frame = ComputeFrame(
                            method_id = key.callee_id,
                            caller_id = key.caller_id,
                            call_stmt_id = key.call_stmt_id,
                            loader = self.loader,
                            space = global_space,
                            params_list = frame.args_list,
                            classes_of_method = frame.callee_classes_of_method,
                            this_class_ids = frame.callee_this_class_ids,
                            state_flow_graph = sfg,
                            call_site_analyze_counter=self.call_site_analyze_counter,
                        )
                        frame_stack.add(new_frame)
                        children_done_flag = False
                        break
                if not children_done_flag:
                    if self.options.debug:
                        util.debug(f"\t<method {frame.method_id}> has content to be analyzed: {frame.content_already_analyzed}")
                    continue

            if not self.options.quiet:
                print(f"Analyzing <method {frame.method_id} name: {frame.method_name}>")

            result: P2ResultFlag = self.analyze_stmts(frame)
            if util.is_available(result) and result.interruption_flag:
                frame.interruption_flag = True
                data: InterruptionData = result.interruption_data
                new_callee = False
                frame.args_list = data.args_list
                frame.callee_classes_of_method = data.classes_of_method
                frame.callee_this_class_ids = data.this_class_ids
                frame.content_already_analyzed = {}
                for callee_id in data.callee_ids:
                    key = CallSite(data.caller_id, data.call_stmt_id, callee_id)
                    if key not in frame.content_already_analyzed:
                        frame.content_already_analyzed[key] = False
                        new_callee = True

                if new_callee:
                    continue

            context_id = frame.hash_context()
            # summary_data = self.generate_analysis_summary_and_s2space(frame)
            # self.save_result_to_last_frame_v3(frame_stack, frame, summary_data)
            summary = self.generate_and_save_analysis_summary(frame, frame.method_summary_instance)
            # TODO: if there is already a summary for this context, we need to merge the two summaries
            self.loader.save_method_summary_instance(context_id, summary)
            self.loader.save_stmt_status_p3(context_id, frame.stmt_id_to_status)
            self.loader.save_method_defined_symbols_p3(context_id, frame.defined_symbols)
            # self.loader.save_symbol_bit_vector_p3(context_id, frame.symbol_bit_vector_manager)
            # self.loader.save_state_bit_vector_p3(context_id, frame.state_bit_vector_manager)
            # self.loader.save_method_symbol_graph_p3(context_id, frame.symbol_graph.graph)

            frame_stack.pop()
            if not self.options.quiet:
                print(f"<method {frame.method_id}> is Done")

        # meta_frame: MetaComputeFrame = frame_stack[0]
        # return meta_frame.summary_collection

    def init_frame_stack(self, entry_method_id, global_space, sfg):
        frame_stack = ComputeFrameStack()
        frame_stack.add(MetaComputeFrame()) #  used for collecting the final results
        entry_frame = ComputeFrame(
            method_id = entry_method_id,
            loader = self.loader,
            space = global_space,
            state_flow_graph = sfg,
            call_site_analyze_counter=self.call_site_analyze_counter
        )
        frame_stack.add(entry_frame)
        return frame_stack

    def run(self):
        if not self.options.quiet:
            print("\n########### # Phase III: Global (Top-down) Semantic Analysis ##########")

        if not self.options.enable_p2:
            config.MAX_ANALYSIS_ROUND_FOR_GLOBAL_ANALYSIS = config.MAX_ANALYSIS_ROUND_FOR_PRELIM_ANALYSIS
        
        for entry_point in self.loader.get_entry_points():
            global_space = SymbolStateSpace()
            self.call_site_analyze_counter = {}
            sfg = StateFlowGraph(entry_point)
            frame_stack = self.init_frame_stack(entry_point, global_space, sfg)
            self.analyze_frame_stack(frame_stack, global_space, sfg)
            self.loader.save_global_sfg_by_entry_point(entry_point, sfg)
            self.save_graph_to_dot(sfg.graph, entry_point, self.analysis_phase_id, global_space)
            self.loader.save_symbol_state_space_p3(entry_point, global_space)

        self.loader.save_call_paths_p3(self.path_manager.paths)
