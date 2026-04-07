#!/usr/bin/env python3

import ast
from inspect import Parameter
import pprint

from networkx.generators.classic import complete_graph
from pandas.core import frame

from lian.core.resolver import Resolver
from lian.core.stmt_states import StmtStates
from lian.util import util
from lian.config import config
from lian.util.loader import Loader
# from lian.events.handler_template import AppTemplate
from lian.config.constants import (
    LIAN_SYMBOL_KIND,
    LIAN_INTERNAL,
    STATE_TYPE_KIND,
    LIAN_INTERNAL,
    CALLEE_TYPE,
    EVENT_KIND
)
from lian.common_structs import (
    CallGraph,
    CallSite,
    MethodDeclParameters,
    Parameter,
    Argument,
    MethodCallArguments,
    PathManager,
    StateDefNode,
    StmtStatus,
    Symbol,
    State,
    MethodCall,
    ComputeFrameStack,
    ComputeFrame,
    MethodSummaryTemplate,
    MethodSummaryInstance,
    SymbolStateSpace,
    SimpleWorkList,
    P2ResultFlag,
    MethodCallArguments,
    InterruptionData,
    CallPath,
    MethodDefUseSummary,
    SFGNode,
    SFGEdge,
    SFG_NODE_KIND,
    SFG_EDGE_KIND,
)

class GlobalStmtStates(StmtStates):
    def __init__(
        self, analysis_phase_id, event_manager, loader: Loader, resolver: Resolver, compute_frame: ComputeFrame,
        path_manager: PathManager, caller_unknown_callee_edge: dict, complete_graph=None
    ):
        super().__init__(
            analysis_phase_id=analysis_phase_id,
            event_manager=event_manager,
            loader=loader,
            resolver=resolver,
            compute_frame=compute_frame,
            call_graph=None,
            complete_graph=complete_graph,
        )
        self.path_manager = path_manager
        self.caller_unknown_callee_edge = caller_unknown_callee_edge

    # def get_method_summary(self, method_id):
    #     pass

    # def has_been_analyzed(self, method_id):
    #     pass

    def print_path(self, path: tuple):
        if not path:
            return

        path_len = len(path)
        if path_len < 1:
            return

        path_str = f"{path[0]}"
        for i in range(3, len(path)+1, 2):
            path_str += f"-@-{path[i-2]}->-{path[i-1]}"

        print(f"current path: {path_str}")

    def compute_target_method_states(
        self, stmt_id, stmt, status, in_states,
        callee_method_ids, target_symbol, args,
        this_state_set = set(), new_object_flag = False
    ):
        callee_ids_to_be_analyzed = []
        caller_id = self.frame.method_id
        if config.DEBUG_FLAG:
            util.debug(f"positional_args of stmt <{stmt_id}>: {args.positional_args}")
            util.debug(f"named_args of stmt <{stmt_id}>: {args.named_args}")
            util.debug(f"callee_method_ids: {callee_method_ids}")

        parameter_mapping_list = []

        if len(callee_method_ids) == 0:
            callee_name = self.resolver.recover_callee_name(stmt, status, self.frame.symbol_state_space)
            unknown_callee_set = self.caller_unknown_callee_edge.get(str(caller_id), set())
            unknown_callee_set.add((str(stmt_id), callee_name))
            self.caller_unknown_callee_edge[str(caller_id)] = unknown_callee_set

        for each_callee_id in callee_method_ids:
            new_call_site = CallSite(caller_id, stmt_id, each_callee_id)
            callee_path = self.frame.call_path.add_callsite(new_call_site)

            if(
                self.path_manager.path_exists(callee_path) or
                callee_path.count_cycles() > 1 or
                each_callee_id in self.frame.call_path or
                self.frame.content_already_analyzed.get(new_call_site, False) or
                self.frame.call_site_analyze_counter.get(new_call_site, 0) > config.MAX_ANALYSIS_ROUND_FOR_CALL_SITE
            ):
                continue
            self.frame.call_site_analyze_counter[new_call_site] = self.frame.call_site_analyze_counter.get(new_call_site, 0) + 1

            callee_ids_to_be_analyzed.append(each_callee_id)
            # prepare callee parameters
            # 可能第二阶段没有这个caller->callee，因此该call的parameter_list可能是空的，在这个阶段还是需要生成一遍parameter_list
            parameters = self.prepare_parameters(each_callee_id)
            if config.DEBUG_FLAG:
                util.debug(f"parameters of callee <{each_callee_id}>: {parameters}")
            # current_parameter_mapping_list = self.loader.load_parameter_mapping(new_call_site)
            # if util.is_empty(current_parameter_mapping_list):
            current_parameter_mapping_list = []
            self.map_arguments(args, parameters, current_parameter_mapping_list, new_call_site)
            parameter_mapping_list.extend(current_parameter_mapping_list)

        classes_of_method = []
        for index in this_state_set:
            instance_state = self.frame.symbol_state_space[index]
            if isinstance(instance_state, State) and self.is_state_a_class_decl(instance_state):
                classes_of_method.append(instance_state.value)

        if len(callee_ids_to_be_analyzed) != 0:
            this_class_ids = []
            name_symbol_index = status.used_symbols[0]
            name_symbol = self.frame.symbol_state_space[name_symbol_index]
            for name_state_index in name_symbol.states:
                name_state = self.frame.symbol_state_space[name_state_index]
                if isinstance(name_state, State) and self.is_state_a_class_decl(name_state):
                   this_class_ids.append(name_state.value)

            return P2ResultFlag(
                # states_changed = True,
                # defuse_changed = defuse_changed,
                interruption_flag = True,
                interruption_data = InterruptionData(
                    caller_id = self.frame.method_id,
                    call_stmt_id = stmt_id,
                    callee_ids = callee_ids_to_be_analyzed,
                    args_list = parameter_mapping_list,
                    classes_of_method = classes_of_method,
                    this_class_ids = this_class_ids,
                ),
            )

        for each_callee_id in callee_method_ids:
            new_call_site = CallSite(caller_id, stmt_id, each_callee_id)
            self.frame.call_site_analyze_counter[new_call_site] = self.frame.call_site_analyze_counter.get(new_call_site, 0) + 1
            if caller_id != each_callee_id:
                new_path = self.frame.call_path.add_callsite(new_call_site)
                self.path_manager.add_path(new_path)
            # prepare callee summary instance and compact space
            callee_summary = self.loader.get_method_summary_instance(new_call_site.hash())
            if callee_summary:
                callee_summary = callee_summary.copy()
                self.apply_callee_semantic_summary(
                    stmt_id, stmt, each_callee_id, args, callee_summary,
                    self.frame.symbol_state_space, this_state_set, new_object_flag
                )

        return P2ResultFlag()

    def parameter_decl_stmt_state(self, stmt_id, stmt, status: StmtStatus, in_states):
        parameter_name_symbol = self.frame.symbol_state_space[status.defined_symbol]
        symbol_id = parameter_name_symbol.symbol_id
        if isinstance(parameter_name_symbol, Symbol) and self.frame.params_list:
            parameter_name_symbol.states = set()
            for each_pair in self.frame.params_list:
                if each_pair.parameter_symbol_id == symbol_id:
                    parameter_state_index = each_pair.arg_index_in_space
                    # self.update_access_path_state_id(parameter_state_index)
                    parameter_name_symbol.states.add(parameter_state_index)
                    status.defined_states.add(parameter_state_index)
                    self.add_arg_to_param_edge(each_pair, status, parameter_name_symbol)

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
                            [default_value_state_index]
                        )

                else:
                    parameter_name_symbol.states.add(default_value_index)
        return P2ResultFlag()

    def is_used_in_call_stmt(self, sfg_node):
        children = list(self.sfg.graph.successors(sfg_node))
        for child in children:
            if (
                child.node_type == SFG_NODE_KIND.STMT
                and self.loader.get_stmt_gir(child.def_stmt_id).operation in ["call_stmt", "object_call_stmt"]
            ):
                return True
        return False

    def add_arg_to_param_edge(self, each_pair, status, parameter_name_symbol):
        for node in self.sfg.graph.nodes:
            if self.node_is_state(node) and node.index == each_pair.arg_index_in_space:
                # `node` 是参数对应的 STATE 节点；它的直接前驱通常是 SYMBOL。
                # 但在某些建图路径下，可能出现 STATE -> STATE 的链路（如 inclusion/copy），
                # 导致直接前驱里包含 STATE 节点。此时需要把这些 STATE 的父 SYMBOL 也纳入候选，
                # 以便找到真正“在 call_stmt/object_call_stmt 中被使用”的变量节点。
                all_parent_nodes = set(self.sfg.graph.predecessors(node))
                for parent in list(all_parent_nodes):
                    if getattr(parent, "node_type", None) != SFG_NODE_KIND.STATE:
                        continue
                    for pp in self.sfg.graph.predecessors(parent):
                        if getattr(pp, "node_type", None) == SFG_NODE_KIND.SYMBOL:
                            all_parent_nodes.add(pp)

                all_parent_nodes = list(all_parent_nodes)
                for parent_node in all_parent_nodes:
                    if not self.is_used_in_call_stmt(parent_node):
                        continue
                    self.sfg.add_edge(
                        parent_node,
                        SFGNode(
                            node_type=SFG_NODE_KIND.SYMBOL,
                            def_stmt_id=parameter_name_symbol.stmt_id,
                            index=status.defined_symbol,
                            node_id=parameter_name_symbol.symbol_id,
                            name=parameter_name_symbol.name,
                            context=self.frame.get_context(),
                        ),
                        SFGEdge(
                            edge_type=SFG_EDGE_KIND.SYMBOL_FLOW,
                            stmt_id=parameter_name_symbol.stmt_id
                        )
                    )
                    break
