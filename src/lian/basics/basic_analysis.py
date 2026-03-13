#!/usr/bin/env python3
import pprint
import sys
import traceback

from lian.util import util
from lian.config import config
import lian.util.data_model as dm
from lian.config.constants import (
    EXPORT_NODE_TYPE,
    SYMBOL_DEPENDENCY_GRAPH_EDGE_KIND,
    LIAN_SYMBOL_KIND,
    LIAN_SYMBOL_KIND,
    EVENT_KIND,
    CALLEE_TYPE,
    BASIC_CALL_GRAPH_NODE_KIND
)
from lian.common_structs import (
    Symbol,
    State,
    ComputeFrame,
    ComputeFrameStack,
    SimpleWorkList,
    CallGraph,
    BasicCallGraph,
    BasicGraph,
    MethodDefUseSummary,
    MethodSummaryTemplate,
    MethodSummaryInstance,
    SimplyGroupedMethodTypes,
)
from lian.util.loader import Loader
from lian.util.gir_block import GIRBlockViewer
from lian.incremental.unit_level_incremental_checker import UnitLevelIncrementalChecker
from lian.core.resolver import Resolver
from lian.basics.scope_hierarchy import UnitScopeHierarchyAnalysis
from lian.basics.import_hierarchy import ImportHierarchy
from lian.basics.type_hierarchy import TypeHierarchy

from lian.basics.entry_points import EntryPointGenerator
from lian.basics.control_flow import ControlFlowAnalysis
from lian.basics.stmt_def_use_analysis import StmtDefUseAnalysis


class P1BasicSemanticAnalysis:
    def __init__(self, lian):
        self.lian = lian
        self.analysis_phases = []
        self.options = lian.options
        self.event_manager = lian.event_manager
        self.extern_system = lian.extern_system
        self.loader:Loader = lian.loader
        self.resolver: Resolver = lian.resolver
        self.entry_points = EntryPointGenerator(lian.options, lian.event_manager, lian.loader)
        self.basic_call_graph = BasicCallGraph()
        self.analyzed_method_ids = set()
        self.incremental_checker = None
        if self.options.incremental:
            self.incremental_checker = UnitLevelIncrementalChecker.unit_level_incremental_checker()

    def config(self):
        pass

    @profile
    def analyze_and_save_method_decl_format(self, method_id, method_decl_stmt, parameter_decl_block):
        unit_id = self.loader.convert_method_id_to_unit_id(method_id)
        parameters_info = []
        for each_parameter_stmt in parameter_decl_block.query_operation("parameter_decl"):
            parameters_info.append({
                "stmt_id": each_parameter_stmt.stmt_id,
                "name": each_parameter_stmt.name,
                "data_type": each_parameter_stmt.data_type
            })
        method_format = {
            "unit_id" : unit_id,
            "method_id" : method_id,
            "name": method_decl_stmt.name,
            "data_type": method_decl_stmt.data_type,
            "parameters": str(parameters_info)
        }
        self.loader.save_method_id_to_method_decl_format(method_id, method_format)

    @profile
    def analyze_method(self, method_id, import_analysis, external_symbol_id_collection, unit_is_analyzed = False):
        frame = ComputeFrame(method_id = method_id, loader = self.loader)
        method_decl_stmt, parameter_decls, method_body = self.loader.get_splitted_method_gir(method_id)
        frame.method_decl_stmt = method_decl_stmt

        parameter_decl_block = GIRBlockViewer(parameter_decls)
        method_body_block = GIRBlockViewer(method_body)

        frame.unit_gir.append_other(parameter_decl_block)
        frame.unit_gir.append_other(method_body_block)

        self.analyze_and_save_method_decl_format(method_id, method_decl_stmt, parameter_decl_block)

        if unit_is_analyzed:
            cfg = self.incremental_checker.fetch_cfg(method_id)
            self.loader.save_method_cfg(method_id, cfg)
        else:
            cfg = ControlFlowAnalysis(self.loader, method_id, parameter_decl_block, method_body_block).analyze()
        all_cfg_nodes = set(cfg.nodes())

        # Perform def-use analysis; This is flow-insensitive
        frame.stmt_def_use_analysis = StmtDefUseAnalysis(
            self.loader,
            self.resolver,
            self.basic_call_graph,
            compute_frame = frame,
            import_analysis=import_analysis,
            external_symbol_id_collection=external_symbol_id_collection,
        )

        for stmt_id in frame.unit_gir.get_all_stmt_ids(): 
            if stmt_id in all_cfg_nodes:
                frame.stmt_def_use_analysis.analyze_stmt(stmt_id, frame.unit_gir.get_stmt_by_id(stmt_id))

        # print("frame.method_def_use_summary", frame.method_def_use_summary)
        self.loader.save_stmt_status_p1(method_id, frame.stmt_id_to_status)
        self.loader.save_symbol_state_space_p1(method_id, frame.symbol_state_space)
        self.loader.save_method_defined_symbols_p1(method_id, frame.defined_symbols)
        self.loader.save_method_used_symbols(method_id, frame.used_symbols)
        self.loader.save_method_defined_states_p1(frame.method_id, frame.defined_states)
        self.loader.save_method_internal_callees(method_id, frame.basic_callees)
        self.loader.save_method_def_use_summary(method_id, frame.method_def_use_summary)

    def search_impacted_parent_nodes(self, graph, node):
        if node not in graph:
            return set()

        results = set()
        worklist = SimpleWorkList(node)
        while len(worklist) != 0:
            node = worklist.pop()
            if node in results:
                continue
            results.add(node)
            for tmp_node in util.graph_predecessors(graph, node):
                if tmp_node not in results:
                    worklist.add(tmp_node)
        return results

    def group_methods_by_callee_types(self):
        graph = self.basic_call_graph.graph

        containing_dynamic_callees = self.search_impacted_parent_nodes(graph, BASIC_CALL_GRAPH_NODE_KIND.DYNAMIC_METHOD)
        containing_error_callees = self.search_impacted_parent_nodes(graph, BASIC_CALL_GRAPH_NODE_KIND.ERROR_METHOD)

        # print(containing_dynamic_callees)
        # print(containing_error_callees)
        leaf_nodes = util.find_graph_nodes_with_zero_out_degree(graph)

        only_direct_callees = set()
        mixed_direct_callees = set()
        dynamic_error_set = containing_error_callees | containing_dynamic_callees
        for method_id in dynamic_error_set:
            flag = False
            for child_id in util.graph_successors(graph, method_id):
                if child_id not in dynamic_error_set:
                    only_direct_callees.add(child_id)
                    flag = True
            if flag:
                mixed_direct_callees.add(method_id)

        only_dynamic_callees = containing_dynamic_callees - mixed_direct_callees
        only_direct_callees -= leaf_nodes
        has_calls = only_direct_callees | mixed_direct_callees | only_dynamic_callees | containing_error_callees | containing_dynamic_callees
        no_callees = self.loader.get_all_method_ids() - has_calls

        extra = {BASIC_CALL_GRAPH_NODE_KIND.DYNAMIC_METHOD, BASIC_CALL_GRAPH_NODE_KIND.ERROR_METHOD}
        types = SimplyGroupedMethodTypes(
            no_callees - extra,
            only_direct_callees - extra,
            mixed_direct_callees - extra,
            only_dynamic_callees - extra,
            containing_dynamic_callees - extra,
            containing_error_callees - extra
        )
        # if self.options.debug:
        #     util.debug(f"Grouped methods:\n{types}")
        self.loader.save_grouped_methods(types)
        return types
    @profile
    def analyze_unit_method_parameters(self, unit_id, unit_gir):
        unit_methods = self.loader.convert_unit_id_to_method_ids(unit_id)
        for method_id in unit_methods:
            method_decl_stmt, parameter_decls, method_body = self.loader.get_splitted_method_gir(method_id)
            if util.is_available(parameter_decls):
                for row in parameter_decls:
                    self.loader.save_method_parameter(method_id, row)

    def is_cookiecutter_file(self, unit_path):
        if "{{" in unit_path:
            return True
        return False

    def run(self):
        if not self.options.quiet:
            print("\n###########  # Phase I: Basic Analysis #  ###########")
        unit_list = []
        # Analyze each unit's scope hierarchy and entry points
        for unit_info in self.loader.get_all_unit_info():
            if self.is_cookiecutter_file(unit_info.unit_path):
                continue
            unit_id = unit_info.module_id
            unit_list.append(unit_id)
            unit_gir = self.loader.get_unit_gir(unit_id)
            if util.is_empty(unit_gir):
                continue

            unit_scope = None
            unit_is_analyzed = False
            if self.options.incremental:
                # if self.options.debug:
                #     util.debug("Scope incremental:")
                previous_scope_analysis_pack = self.incremental_checker.previous_scope_hierarchy_analysis_results(unit_info)
                if previous_scope_analysis_pack:
                    unit_is_analyzed = True
                    unit_scope = UnitScopeHierarchyAnalysis(self.lian, self.loader, unit_id, unit_info, unit_gir).reuse_analysis(previous_scope_analysis_pack)

            if not unit_is_analyzed:
                unit_scope = UnitScopeHierarchyAnalysis(self.lian, self.loader, unit_id, unit_info, unit_gir).analyze()
            self.entry_points.collect_entry_points_from_unit_scope(unit_info, unit_scope)
            if not self.options.nomock:
                self.extern_system.install_mock_code_file(unit_info, unit_scope)

        self.loader.export_scope_hierarchy()
        self.loader.export_entry_points()

        if not self.options.nomock:
            self.extern_system.display_all_installed_rules()

        unit_list.reverse()
        import_analysis = ImportHierarchy(self.lian, self.loader, self.resolver, unit_list).run()
        TypeHierarchy(self.loader, self.resolver, unit_list).run()

        # Conduct basic analysis, i.e., context-insensitive and flow-insensitive analysis
        # reversed() is to improve cache hit rates
        #print("=== Analyzing def_use ===")
        unit_list.reverse()
        for unit_id in unit_list:
            external_symbol_id_collection = {}
            all_unit_methods = self.loader.convert_unit_id_to_method_ids(unit_id)
            if self.options.incremental:
                unit_is_analyzed = (self.incremental_checker.check_unit_id_analyzed(unit_id) is not None)
            else:
                unit_is_analyzed = False
            for method_id in all_unit_methods:
                if self.options.strict_parse_mode:
                    external_symbol_id_collection = {}
                    self.analyze_method(method_id, import_analysis, external_symbol_id_collection, unit_is_analyzed)
                    self.loader.save_method_external_symbol_id_collection(method_id, external_symbol_id_collection)
                else:
                    self.analyze_method(method_id, import_analysis, external_symbol_id_collection, unit_is_analyzed)
        self.loader.save_classified_method_call(self.basic_call_graph)
        self.group_methods_by_callee_types()

        return self
