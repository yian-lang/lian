#!/usr/bin/env python3

import pprint
import re
import networkx as nx

from lian.config import config
from lian.core.resolver import Resolver
from lian.config.constants import (
    LIAN_SYMBOL_KIND,
)

from lian.common_structs import (
    BasicGraph,
    MethodInClass,
    TypeGraphEdge,
    TypeNode,
)
from lian.util import util
from lian.util.loader import Loader

class TypeHierarchy:
    def __init__(self, loader, resolver, unit_list):
        self.loader: Loader = loader
        self.resolver: Resolver = resolver
        self.type_graph = BasicGraph()
        self.analyzed_type_hierarchy_ids = set()
        self.analyzed_class_ids = set()
        self.class_in_type_graph = set()
        self.class_to_methods = {}
        self.unit_list = unit_list

    def parse_class_decl_stmt(self, unit_id, stmt_id, stmt):
        result = []
        if util.is_available(stmt.supers):
            supers = re.findall(r"'(.*?)'", stmt.supers)
            counter = 0
            for each_name in supers:
                ids = self.resolver.resolve_class_name_to_ids(unit_id, stmt_id, each_name)
                if ids:
                    for each_id in ids:
                        result.append(
                            TypeNode(
                                name = stmt.name,
                                unit_id= unit_id,
                                class_stmt_id = stmt_id,
                                parent_name = each_name,
                                parent_id = each_id,
                                parent_index = counter
                            )
                        )
                else :
                    new_id = self.loader.assign_new_unique_negative_id()
                    result.append(
                        TypeNode(
                            name = stmt.name,
                            unit_id= unit_id,
                            class_stmt_id = stmt_id,
                            parent_id = new_id,
                            parent_name = each_name,
                            parent_index = counter
                        )
                    )
                counter += 1
        else :
            result.append(
                TypeNode(
                    name = stmt.name,
                    unit_id= unit_id,
                    class_stmt_id = stmt_id,
                    parent_id = -1,
                    parent_name = "virtual_parent",
                    parent_index = 0
                    )
                )
        return result

    def analyze_class_decl_and_save_result(self, unit_id, stmt_id, stmt):
        if stmt_id in self.class_in_type_graph:
            return
        self.class_in_type_graph.add(stmt_id)

        result = self.parse_class_decl_stmt(unit_id, stmt_id, stmt)
        for type_node in result:
            self.type_graph.add_edge(
                stmt_id,
                type_node.parent_id,
                TypeGraphEdge(
                    name = type_node.name,
                    parent_name = type_node.parent_name,
                    parent_pos = type_node.parent_index
                )
            )

    def analyze_method_in_class(self, class_decl_stmt, scope_hierarchy):
        method_decls = scope_hierarchy.slow_query(
            (scope_hierarchy.scope_id == class_decl_stmt.stmt_id) &
            ((scope_hierarchy.scope_kind == LIAN_SYMBOL_KIND.METHOD_KIND)|(scope_hierarchy.scope_kind == LIAN_SYMBOL_KIND.CLASS_KIND))
        )
        all_method_info = []
        for each_method in method_decls:
            all_method_info.append(MethodInClass(
                unit_id = each_method.unit_id,
                class_id = class_decl_stmt.stmt_id,
                name = each_method.name,
                stmt_id = each_method.stmt_id
            ))
        self.class_to_methods[class_decl_stmt.stmt_id] = all_method_info

    def analyze_type_hierarchy(self, unit_id):
        if unit_id in self.analyzed_type_hierarchy_ids:
            return
        self.analyzed_type_hierarchy_ids.add(unit_id)

        # start analysis from scope_hierarchy
        scope_hierarchy = self.loader.get_unit_scope_hierarchy(unit_id)
        if not scope_hierarchy:
            return

        # obtain class decls
        class_decl_stmts = scope_hierarchy.query_index_column_value("scope_kind", LIAN_SYMBOL_KIND.CLASS_KIND)

        for each_stmt in class_decl_stmts:
            # analyze each class decl
            self.analyze_class_decl_and_save_result(unit_id, each_stmt.stmt_id, each_stmt)

            # analyze method in class
            self.analyze_method_in_class(each_stmt, scope_hierarchy)

    def adjust_method_in_class_and_save(self, class_id):
        if class_id in self.analyzed_class_ids:
            return
        self.analyzed_class_ids.add(class_id)

        methods_in_class = []
        method_ids = set()

        if class_id in self.class_to_methods:
            methods_in_class = self.class_to_methods[class_id]
            for each_method in methods_in_class:
                method_ids.add(each_method.stmt_id)

        # adjust methods in class and save
        parent_ids = util.graph_successors(self.type_graph.graph, class_id)
        for each_parent_id in parent_ids:
            if each_parent_id == -1:
                continue
            self.adjust_method_in_class_and_save(each_parent_id)
            parent_methods = self.loader.get_methods_in_class(each_parent_id)
            for each_method in parent_methods:
                if each_method.stmt_id not in method_ids:
                    methods_in_class.append(
                        MethodInClass(
                            unit_id = each_method.unit_id,
                            class_id = each_parent_id,
                            name = each_method.name,
                            stmt_id = each_method.stmt_id
                        )
                    )
                    method_ids.add(each_method.stmt_id)

        self.loader.save_methods_in_class(class_id, methods_in_class)

    @profile
    def run(self):
        for unit_id in self.unit_list:
            self.analyze_type_hierarchy(unit_id)

        # adjust methods in class and save
        for each_node in self.type_graph.graph.nodes():
            if self.loader.is_class_decl(each_node):
                self.adjust_method_in_class_and_save(each_node)

        # save type graph
        self.loader.save_type_graph(self.type_graph)

