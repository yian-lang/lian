#!/usr/bin/env python3

import pprint
import re
import networkx as nx
import pdb
from lian.config import config
from lian.core.resolver import Resolver
from lian.config.constants import (
    IMPORT_GRAPH_EDGE_KIND,
    LIAN_SYMBOL_KIND
)

from lian.common_structs import (
    SymbolNodeInImportGraph,
)
from lian.util import util
from lian.util.loader import Loader

INVALID = False
VALID = True

class ImportHierarchy:
    def __init__(self, lian, loader, resolver, unit_list):
        self.lian = lian
        self.options = self.lian.options
        self.is_strict_parse_mode = self.options.strict_parse_mode
        self.loader:Loader = loader
        self.resolver = resolver
        self.unit_list = unit_list
        self.analyzed_imported_unit_ids = set()
        self.import_graph = nx.DiGraph()
        self.import_deps = nx.DiGraph()

        self.symbol_id_to_symbol_node = {}
        self.module_name_to_symbol_nodes = {}

    def add_import_graph_node(self, symbol_type, symbol_id, symbol_name, parent_node_id = -1, unit_id = -1):
        import_node = SymbolNodeInImportGraph(
            scope_id = parent_node_id,
            symbol_type = symbol_type,
            symbol_id = symbol_id,
            symbol_name = symbol_name,
            unit_id = unit_id
        )
        self.symbol_id_to_symbol_node[symbol_id] = import_node
        if symbol_name not in self.module_name_to_symbol_nodes:
            self.module_name_to_symbol_nodes[symbol_name] = []
        self.module_name_to_symbol_nodes[symbol_name].append(import_node)
        self.add_import_graph_edge(parent_node_id, symbol_id, symbol_name, symbol_type = symbol_type)
        return import_node

    def add_import_graph_edge(
        self, parent_node_id, node_id, node_name,
        edge_kind = IMPORT_GRAPH_EDGE_KIND.INTERNAL_SYMBOL,
        import_stmt_id = -1, alias = "", symbol_type = None
    ):
        if alias == "":
            real_name = node_name
        else:
            real_name = alias
        if (
            parent_node_id in self.symbol_id_to_symbol_node
            and node_id in self.symbol_id_to_symbol_node
        ):
            self.import_graph.add_edge(parent_node_id, node_id, weight = edge_kind, site = import_stmt_id, real_name = real_name, symbol_type = symbol_type)
        elif edge_kind == IMPORT_GRAPH_EDGE_KIND.UNSOLVED_SYMBOL:
            self.import_graph.add_edge(parent_node_id, node_id, weight = edge_kind, site = import_stmt_id, real_name = real_name, symbol_type = symbol_type)

    def add_import_deps(self, unit_id, node_id):
        if self.loader.is_unit_id(node_id):
            self.import_deps.add_edge(unit_id, node_id)
            return

        import_unit_id = self.loader.convert_stmt_id_to_unit_id(node_id)
        if import_unit_id is not None and import_unit_id > 0:
            self.import_deps.add_edge(unit_id, import_unit_id)

    def initialize_import_graph(self):
        for module_item in self.loader.get_module_symbol_table():
            self.add_import_graph_node(
                symbol_type=module_item.symbol_type,
                symbol_id=module_item.module_id,
                symbol_name=module_item.symbol_name,
                parent_node_id=module_item.parent_module_id,
                unit_id=module_item.module_id
            )

    def is_private_attr(self, attrs):
        return "private" in attrs

    def search_public_symbols_from_scope_hierarchy(self, scope_hierarchy):
        internal_symbols = []

        worklist = [0]
        visited = set()
        public_scopes = set([0])
        while worklist:
            scope_id = worklist.pop(0)
            if scope_id in visited:
                continue
            visited.add(scope_id)

            scope_results = []
            if scope_id in public_scopes:
                scope_results = scope_hierarchy.slow_query(
                    (
                        scope_hierarchy.scope_id == scope_id
                    ) & (
                        scope_hierarchy.scope_kind.isin((
                            LIAN_SYMBOL_KIND.VARIABLE_DECL,
                            LIAN_SYMBOL_KIND.CLASS_KIND,
                            LIAN_SYMBOL_KIND.METHOD_KIND,
                            LIAN_SYMBOL_KIND.NAMESPACE_KIND,
                        ))
                    )
                )
            else:
                scope_results = scope_hierarchy.slow_query(
                    (
                        scope_hierarchy.scope_id == scope_id
                    ) & (
                        scope_hierarchy.scope_kind.isin((
                            LIAN_SYMBOL_KIND.CLASS_KIND,
                            LIAN_SYMBOL_KIND.METHOD_KIND,
                            LIAN_SYMBOL_KIND.NAMESPACE_KIND,
                        ))
                    )
                )

            for row in scope_results:
                if self.is_private_attr(row.attrs):
                    continue

                if row.scope_kind == LIAN_SYMBOL_KIND.METHOD_KIND:
                    if scope_id in public_scopes:
                        internal_symbols.append(row)
                    elif "static" in row.attrs:
                        internal_symbols.append(row)
                    continue

                internal_symbols.append(row)
                if row.scope_kind in (LIAN_SYMBOL_KIND.CLASS_KIND, LIAN_SYMBOL_KIND.NAMESPACE_KIND):
                    if row.scope_kind == LIAN_SYMBOL_KIND.NAMESPACE_KIND:
                        public_scopes.add(row.stmt_id)
                    worklist.append(row.stmt_id)

        return internal_symbols

    def analyze_unit_public_symbols(self, unit_id):
        # start analysis from scope_hierarchy
        scope_hierarchy = self.loader.get_unit_scope_hierarchy(unit_id)
        gir = self.loader.get_unit_gir(unit_id)
        if util.is_empty(scope_hierarchy) or util.is_empty(gir):
            return

        internal_symbols = self.search_public_symbols_from_scope_hierarchy(scope_hierarchy)
        for each_symbol in internal_symbols:
            if util.is_available(each_symbol.attrs) and "default" in each_symbol.attrs:
                each_symbol.name = "default"

            if each_symbol.name.startswith("%"):
                continue
            scope_id = each_symbol.scope_id
            if scope_id <= 0:
                scope_id = unit_id
            self.add_import_graph_node(
                symbol_type=each_symbol.scope_kind,
                symbol_id=each_symbol.stmt_id,
                symbol_name=each_symbol.name,
                parent_node_id=scope_id,
                unit_id=unit_id,
            )

    def validate_import_stmt(self, unit_info, stmt):
        unit_path = unit_info.original_path
        if not self.is_strict_parse_mode:
            if util.is_empty(stmt.name):
                # util.error(
                #     "Import Error: cannot use empty name in import"
                #     )
                return INVALID

            import_path = self.get_import_path_from_stmt(stmt)
            if "*" in import_path:
                if not re.match(r'^[^*]*\.\*$', import_path):
                    util.error(
                        "Import Error: '*' can only be used in the end of import path"
                    )
                    return INVALID
            return VALID

        if stmt.source.startswith(".") or stmt.name.startswith("."):
            util.error_and_quit_with_stmt_info(
                unit_path, stmt, "Import Error: cannot use relative path in import (remove the leading dot)"
            )
        if stmt.source.endswith(".") or stmt.name.endswith("."):
            util.error_and_quit_with_stmt_info(
                unit_path, stmt, "Import Error: wrong dot usage (remove the trailing dot)"
            )
        if "*" in stmt.source or "*" in stmt.name or "*" in stmt.alias:
            util.error_and_quit_with_stmt_info(
                unit_path, stmt, f"Import Error: cannot use '*' in import"
            )
        if stmt.operation == "from_import_stmt":
            if stmt.source == "":
                util.error_and_quit_with_stmt_info(
                    unit_path, stmt, f"Import Error: cannot use empty path in from..import"
                )
        if util.is_empty(stmt.name):
            util.error_and_quit_with_stmt_info(
                unit_path, stmt, f"Import Error: cannot use empty name in import"
            )

    def get_import_path_from_stmt(self, stmt):
        import_path = ""
        if util.is_available(stmt.source):
            import_path = stmt.source
        if util.is_available(stmt.name):
            import_path += "." + stmt.name
        return import_path

    def parse_import_path_from_module_worklist(self, import_path_list, initial_worklist):
        matched_nodes = []

        debug_flag = False
        if import_path_list[-1] == "A":
            debug_flag = True

        # 若导入路径列表或初始工作列表为空，直接返回
        if not import_path_list or not initial_worklist:
            return (matched_nodes, import_path_list)

        while import_path_list and initial_worklist:
            name_to_be_matched = import_path_list[0]
            new_worklist = []
            matched_nodes = []

            # 处理通配符 *
            if name_to_be_matched == "*":
                import_path_list.pop(0)
                for each_node in initial_worklist:
                    if each_node.symbol_type == LIAN_SYMBOL_KIND.UNIT_SYMBOL:
                        self.analyze_unit_import_stmts(each_node.symbol_id)
                return (initial_worklist, import_path_list)

            # 遍历初始工作列表，查找匹配的节点
            for candidate_node in initial_worklist:
                if candidate_node.symbol_name == name_to_be_matched:
                    if candidate_node.symbol_type == LIAN_SYMBOL_KIND.UNIT_SYMBOL:
                        self.analyze_unit_import_stmts(candidate_node.symbol_id)
                    matched_nodes.append(candidate_node)

            if len(matched_nodes) == 0:
                return (matched_nodes, import_path_list)

            import_path_list.pop(0)
            for candidate_node in matched_nodes:
                # 获取匹配节点的后继节点
                children_list = []
                if self.is_strict_parse_mode:
                    children_list = util.graph_successors_with_weight(self.import_graph, candidate_node.symbol_id, IMPORT_GRAPH_EDGE_KIND.INTERNAL_SYMBOL)
                else:
                    children_list = util.graph_successors(self.import_graph, candidate_node.symbol_id)
                if len(children_list) > 0:
                    for child_id in children_list:
                        new_worklist.append(self.symbol_id_to_symbol_node[child_id])

            initial_worklist = new_worklist

        return (matched_nodes, import_path_list)

    def parse_import_path_from_current_dir(self, import_path_str, parent_module_id):
        remaining_import_path = import_path_str.split(".")
        if len(remaining_import_path) == 0:
            return [], []

        child_module_ids = self.loader.convert_module_id_to_child_ids(parent_module_id)
        worklist = []
        for candidate_node in child_module_ids:
            candidate_node = self.symbol_id_to_symbol_node[candidate_node]
            worklist.append(candidate_node)

        return self.parse_import_path_from_module_worklist(remaining_import_path, worklist)

    def freely_parse_import_path(self, import_path):
        remaining_import_path = import_path.split(".")
        if len(remaining_import_path) == 0:
            return [], []

        name_to_be_matched = remaining_import_path[0]
        worklist = []
        # 根据 self.node_name_to_import_nodes 来搜索首节点
        if name_to_be_matched in self.module_name_to_symbol_nodes:
            for import_node in self.module_name_to_symbol_nodes[name_to_be_matched]:
                worklist.append(import_node)

        return self.parse_import_path_from_module_worklist(
            remaining_import_path, worklist
        )

    def check_import_stmt_analysis_results(self, unit_info, stmt, import_nodes, remaining):
        # 若没有剩余的导入路径，说明导入路径全部匹配成功
        if len(remaining) == 0:
            if len(import_nodes) != 0:
                if self.is_strict_parse_mode:
                    # 严格模式下，要求匹配节点唯一
                    if len(import_nodes) != 1:
                        util.error_and_quit_with_stmt_info(
                            unit_info.original_path, stmt, "Import Error: import module path is not unique"
                        )

                return list(import_nodes)

        # if self.is_strict_parse_mode:
        #     util.error_and_quit_with_stmt_info(
        #         unit_info.original_path, stmt, "Import Error: import module path not found"
        #     )
        return []

    def adjust_result_symbol_node(self, node, unit_id, stmt, alias):
        new_node = node.clone()
        new_node.unit_id = unit_id
        if len(alias) > 0:
            new_node.symbol_name = alias
        return new_node

    def analyze_import_stmt(self, unit_id, unit_info, stmt, external_symbols = []):
        # if unit_id == 13:
        # pdb.set_trace()
        if self.validate_import_stmt(unit_info, stmt) == INVALID:
            return external_symbols

        alias = ""
        import_path_str = self.get_import_path_from_stmt(stmt)
        if util.is_available(stmt.alias):
            alias = stmt.alias
        else:
            last_name = import_path_str.split(".")[-1]
            if "*" not in last_name and "." not in last_name:
                alias = last_name

        # 搜索相对路径
        levels_up = 0
        search_path = import_path_str
        
        if import_path_str.startswith("."):
            leading_dots = 0
            for char in import_path_str:
                if char == ".":
                    leading_dots += 1
                else:
                    break
            
            if leading_dots > 1:
                levels_up = leading_dots - 1
            
            search_path = import_path_str[leading_dots:]
            if search_path.startswith("."):
                search_path = search_path[1:]
        
        parent_module_id = unit_info.parent_module_id

        # Traverse up
        for _ in range(levels_up):
            if parent_module_id in self.symbol_id_to_symbol_node:
                parent_node = self.symbol_id_to_symbol_node[parent_module_id]
                if parent_node and parent_node.scope_id != -1:
                    parent_module_id = parent_node.scope_id
                else:
                    break # Hit root
            else:
                pass # Try best effort

        import_nodes, remaining = self.parse_import_path_from_current_dir(
            search_path, parent_module_id
        )
        import_nodes = self.check_import_stmt_analysis_results(
            unit_info, stmt, import_nodes, remaining
        )
        if import_nodes:
            for each_node in import_nodes:
                self.add_import_graph_edge(
                    unit_id, each_node.symbol_id, each_node.symbol_name,
                    edge_kind = IMPORT_GRAPH_EDGE_KIND.EXTERNAL_SYMBOL,
                    import_stmt_id = stmt.stmt_id, alias = alias, symbol_type = each_node.symbol_type
                )
                self.add_import_deps(unit_id, each_node.symbol_id)
                external_symbols.append(
                    self.adjust_result_symbol_node(each_node, unit_id, stmt, alias)
                )
            # done
            return external_symbols

        import_nodes = []
        remaining = []
        if self.is_strict_parse_mode:
            # 从跟目录开始搜索
            import_nodes, remaining = self.parse_import_path_from_current_dir(import_path_str, 0)
        else:
            import_nodes, remaining = self.freely_parse_import_path(import_path_str)
        import_nodes = self.check_import_stmt_analysis_results(unit_info, stmt, import_nodes, remaining)
        if import_nodes:
            for each_node in import_nodes:
                self.add_import_graph_edge(
                    unit_id, each_node.symbol_id, each_node.symbol_name,
                    edge_kind = IMPORT_GRAPH_EDGE_KIND.EXTERNAL_SYMBOL,
                    import_stmt_id = stmt.stmt_id, alias = alias, symbol_type = each_node.symbol_type
                )
                self.add_import_deps(unit_id, each_node.symbol_id)
                external_symbols.append(
                    self.adjust_result_symbol_node(each_node, unit_id, stmt, alias)
                )
            # done
            return external_symbols

        # if self.is_strict_parse_mode:
        #     util.error_and_quit_with_stmt_info(
        #         unit_info.original_path, stmt, "Import Error: import module path not found"
        #     )

        fake_node_id = self.loader.assign_new_unique_negative_id()
        fake_node = self.add_import_graph_node(
            symbol_type=LIAN_SYMBOL_KIND.UNKNOWN_KIND,
            symbol_id=fake_node_id,
            symbol_name=alias,
            parent_node_id=stmt.parent_stmt_id,
            unit_id=unit_id,
        )
        self.add_import_graph_edge(
            unit_id, fake_node_id, alias,
            edge_kind = IMPORT_GRAPH_EDGE_KIND.UNSOLVED_SYMBOL,
            import_stmt_id = stmt.stmt_id, symbol_type = fake_node.symbol_type
        )
        external_symbols.append(fake_node)

        return external_symbols

    def analyze_unit_import_stmts(self, unit_id):
        if unit_id in self.analyzed_imported_unit_ids:
            return
        self.analyzed_imported_unit_ids.add(unit_id)

        unit_info = self.loader.convert_module_id_to_module_info(unit_id)
        scope_hierarchy = self.loader.get_unit_scope_hierarchy(unit_id)
        if util.is_empty(scope_hierarchy):
            return

        import_stmts = scope_hierarchy.slow_query(
            (scope_hierarchy.scope_id == 0) &
            (scope_hierarchy.scope_kind == LIAN_SYMBOL_KIND.IMPORT_STMT)
        )
        results = []
        for each_stmt in import_stmts:
            self.analyze_import_stmt(unit_id, unit_info, each_stmt, results)


        self.loader.save_unit_export_symbols(unit_id, results)

    def debug_import_graph(self):
        graph = self.import_graph
        # 打印所有边
        print("All edges in the import graph:")

        for each_node in graph.nodes:
            out_edges = graph[each_node]
            for each_out_edge in out_edges:
                print(f"  {each_node} -> {each_out_edge}")

    @profile
    def run(self):
        # 把所有的文件和目录全部拉出来，构建初始版的import_graph（node：id， node info -> import_graph_nodes）
        self.initialize_import_graph()

        for unit_id in self.unit_list:
            # 开始分析文件内部所有public函数、class、全局变量等
            self.analyze_unit_public_symbols(unit_id)

        #self.debug_import_graph()

        for unit_id in self.unit_list:
            # 分析不同文件之间的索引
            self.analyze_unit_import_stmts(unit_id)

        self.loader.save_import_graph(self.import_graph)
        self.loader.save_import_graph_nodes(self.symbol_id_to_symbol_node)
        self.loader.save_import_deps(self.import_deps)
        #self.loader.export()
        return self

