#!/usr/bin/env python3

import networkx as nx

from lian.config import config,schema
from lian.util import util
from lian.config.constants import CONTROL_FLOW_KIND
from lian.common_structs import (
    ControlFlowGraph,
    CFGNode,
    ComputeFrame
)
import lian.util.data_model as dm
from lian.util.loader import Loader
from lian.util.gir_block import GIRBlockViewer

class ControlFlowAnalysis:
    def __init__(self, loader: Loader, method_id: int, parameter_decls: GIRBlockViewer, method_body: GIRBlockViewer):
        self.loader: Loader = loader
        self.method_id: int = method_id
        self.parameter_decls: GIRBlockViewer = parameter_decls
        self.method_body: GIRBlockViewer = method_body
        self.cfg = ControlFlowGraph(self.method_id)

        self.label = []
        self.goto = []
        for stmt in method_body.query_operation("label_stmt"):
            self.label.append(stmt)
        for stmt in method_body.query_operation("goto_stmt"):
            self.goto.append(stmt)
                    
        self.stmt_handlers = {
            "if_stmt"       : self.analyze_if_stmt,
            "while_stmt"    : self.analyze_while_stmt,
            "dowhile_stmt"  : self.analyze_dowhile_stmt,
            "for_stmt"      : self.analyze_for_stmt,
            "forin_stmt"    : self.analyze_while_stmt,
            "for_value_stmt" : self.analyze_while_stmt,
            "break_stmt"    : self.analyze_break_stmt,
            "continue_stmt" : self.analyze_continue_stmt,
            "try_stmt"      : self.analyze_try_stmt,
            "switch_stmt"   : self.analyze_switch_stmt,
            "return_stmt"   : self.analyze_return_stmt,
            "yield"         : self.analyze_yield_stmt,
            "method_decl"   : self.analyze_method_decl_stmt,
            "class_decl"    : self.analyze_decl_stmt,
            "record_decl"   : self.analyze_decl_stmt,
            "interface_decl": self.analyze_decl_stmt,
            "struct_decl"   : self.analyze_decl_stmt,
        }

    def analyze(self):
        cfg = self.loader.get_method_cfg(self.method_id)
        if util.is_available(cfg):
            return cfg

        # last_stmts_of_init_block = self.analyze_init_block(self.parameter_decls)
        last_stmts_of_init_block = self.analyze_block(self.parameter_decls)
        last_stmts_of_body_block = self.analyze_block(self.method_body, last_stmts_of_init_block)
        if last_stmts_of_body_block:
            self.cfg.add_edge(last_stmts_of_body_block, -1, control_flow_type = CONTROL_FLOW_KIND.EMPTY)
        #util.debug("cfg "*20)
        # util.debug(list(self.cfg.graph.edges(data=True)))
        self.merge_multiple_edges_between_two_nodes()

        # adjust goto
        # - eliminate goto edge
        # - search label;
        # - connect new edge
        for goto in self.goto:
            if goto.stmt_id in self.cfg.graph:  # 检查节点是否存在
                self.cfg.graph.remove_edges_from(list(self.cfg.graph.out_edges(goto.stmt_id)))
            for label in self.label:
                if goto.name == label.name:
                    self.cfg.graph.add_edge(goto.stmt_id, label.stmt_id)


        self.loader.save_method_cfg(self.method_id, self.cfg.graph)
        return self.cfg.graph

    def merge_multiple_edges_between_two_nodes(self):
        # multiple_edges_exist_flag = False
        old_graph = self.cfg.graph
        # for u, v in old_graph.edges():
        #     if old_graph.number_of_edges(u, v) > 1:
        #         multiple_edges_exist_flag = True
        #         break

        # if not multiple_edges_exist_flag:
        #     return

        new_graph = nx.DiGraph()
        for u, v in old_graph.edges():
            if old_graph.number_of_edges(u, v) > 1:
                # total_weight = sum(old_graph[u][v][key]['weight'] for key in old_graph[u][v])
                new_graph.add_edge(u, v, weight = CONTROL_FLOW_KIND.EMPTY)
            else:
                if not new_graph.has_edge(u, v):
                    new_graph.add_edge(u, v, weight = old_graph[u][v][0]['weight'])
        self.cfg.graph = new_graph

    def read_block(self, block_id):
        return self.method_body.read_block(block_id)

    def boundary_of_multi_blocks(self, block: GIRBlockViewer, block_ids):
        return block.boundary_of_multi_blocks(block_ids)

    def analyze_if_stmt(self, current_block, current_stmt, parent_stmts, global_special_stmts):
        self.link_parent_stmts_to_current_stmt(parent_stmts, current_stmt)
        last_stmts_of_then_body = [CFGNode(current_stmt, CONTROL_FLOW_KIND.IF_TRUE)]
        then_body_id = current_stmt.then_body
        if not util.isna(then_body_id):
            then_body = self.read_block(then_body_id)
            if then_body and len(then_body) != 0:
                last_stmts_of_then_body = self.analyze_block(then_body, last_stmts_of_then_body, global_special_stmts)

        last_stmts_of_else_body = [CFGNode(current_stmt, CONTROL_FLOW_KIND.IF_FALSE)]
        else_body_id = current_stmt.else_body
        if not util.isna(else_body_id):
            else_body = self.read_block(else_body_id)
            if else_body and len(else_body) != 0:
                last_stmts_of_else_body = self.analyze_block(else_body, last_stmts_of_else_body, global_special_stmts)

        boundary = self.boundary_of_multi_blocks(current_block, [then_body_id, else_body_id])
        return (last_stmts_of_then_body + last_stmts_of_else_body, boundary)

    def deal_with_last_stmts_of_loop_body(
            self, current_stmt, last_stmts, special_stmts, global_special_stmts, current_stmt_edge = None
    ):
        last_stmt_nodes = []
        for each_last_stmt in last_stmts:
            if not isinstance(each_last_stmt, CFGNode):
                last_stmt_nodes.append(CFGNode(each_last_stmt, CONTROL_FLOW_KIND.LOOP_BACK))
            else:
                last_stmt_nodes.append(each_last_stmt)

        self.link_parent_stmts_to_current_stmt(last_stmt_nodes, current_stmt)

        result = []
        for counter in reversed(range(len(special_stmts))):
            node = special_stmts[counter]
            if node.operation == "break_stmt":
                result.append(node)
                del special_stmts[counter]
            elif node.operation == "continue_stmt":
                self.link_parent_stmts_to_current_stmt([CFGNode(node, CONTROL_FLOW_KIND.CONTINUE)], current_stmt)
                del special_stmts[counter]
        global_special_stmts.extend(special_stmts)
        if util.is_available(current_stmt.condition):
            if current_stmt.condition in ("true", "True"):
                return result
        result.append(CFGNode(current_stmt, CONTROL_FLOW_KIND.LOOP_FALSE))
        return result

    def analyze_while_stmt(self, current_block, current_stmt, parent_stmts, global_special_stmts):
        self.link_parent_stmts_to_current_stmt(parent_stmts, current_stmt)
        new_special_stmts = []
        body_id = current_stmt.body
        body = self.read_block(body_id)
        last_stmts_of_body = self.analyze_block(
            body,
            [CFGNode(current_stmt, CONTROL_FLOW_KIND.LOOP_TRUE)],
            new_special_stmts
        )
        last_stmts = self.deal_with_last_stmts_of_loop_body(
            current_stmt, last_stmts_of_body, new_special_stmts, global_special_stmts
        )

        if util.isna(current_stmt.else_body):
            boundary = self.boundary_of_multi_blocks(current_block, [body_id])
            return (last_stmts, boundary)

        else_body_id = current_stmt.else_body
        else_body = self.read_block(else_body_id)
        boundary = self.boundary_of_multi_blocks(current_block, [body_id, else_body_id])
        last_stmts_of_else_body = self.analyze_block(
            else_body,
            # TODO: should this be loop_false?
            [CFGNode(current_stmt, CONTROL_FLOW_KIND.LOOP_TRUE)],
            new_special_stmts
        )
        last_stmts.pop()
        return (last_stmts + last_stmts_of_else_body, boundary)

    def analyze_dowhile_stmt(self, current_block, current_stmt, parent_stmts, global_special_stmts):
        # self.link_parent_stmts_to_current_stmt(parent_stmts, current_stmt)
        body_id = current_stmt.body
        body = self.read_block(body_id)
        boundary = self.boundary_of_multi_blocks(current_block, [body_id])

        previous = parent_stmts[:]
        previous.append(
            CFGNode(current_stmt, CONTROL_FLOW_KIND.LOOP_TRUE)
        )

        new_special_stmts = []
        last_stmts_of_body = self.analyze_block(body, previous, new_special_stmts)

        last_stmts = self.deal_with_last_stmts_of_loop_body(
            current_stmt, last_stmts_of_body, new_special_stmts, global_special_stmts
        )

        return (last_stmts, boundary)


    def analyze_for_stmt(self, current_block, current_stmt, parent_stmts, global_special_stmts):
        # util.debug("analyze_for_stmt\n")
        # self.link_parent_stmts_to_current_stmt(parent_stmts, current_stmt)
        init_body_id = current_stmt.init_body
        condition_prebody_id = current_stmt.condition_prebody
        update_body_id = current_stmt.update_body

        init_body = self.read_block(init_body_id)
        condition_prebody = self.read_block(condition_prebody_id)
        update_body = self.read_block(update_body_id) 

        # deal with init_body
        # util.debug("for_init_body "*5)
        last_stmts = self.analyze_block(init_body, parent_stmts, global_special_stmts)

        # deal with condition_prebody
        # util.debug("for_condition_prebody "*5)
        last_stmts_condition_prebody = self.analyze_block(condition_prebody, last_stmts, global_special_stmts)

        # deal with for body
        #util.debug("for_body "*5)
        body_id = current_stmt.body
        body = self.read_block(body_id)
        boundary = self.boundary_of_multi_blocks(current_block, [body_id])

        new_special_stmts = []
        last_stmts = self.analyze_block(
            body,
            [CFGNode(current_stmt, CONTROL_FLOW_KIND.LOOP_TRUE)],
            new_special_stmts
        )

        # deal with update_body
        # util.debug("for_update_body "*5)
        # deal with break,return...
        if len(last_stmts)!=0:
            last_stmts = self.analyze_block(update_body, last_stmts, new_special_stmts)

            # deal with condition_prebody
            # util.debug("for_condition_prebody2 "*5)
            last_stmts = self.analyze_block(condition_prebody, last_stmts, new_special_stmts)

        # link condition_prebody and current_stmt
        # and also generate last_stmts
        # util.debug("deal_with_last_stmts_of_loop_body "*5)
        last_stmts = self.deal_with_last_stmts_of_loop_body(
            current_stmt, last_stmts + last_stmts_condition_prebody,
            new_special_stmts, global_special_stmts
        )

        return (last_stmts, boundary)

    def analyze_switch_stmt(self, current_block, current_stmt, parent_stmts, global_special_stmts):
        self.link_parent_stmts_to_current_stmt(parent_stmts, current_stmt)

        body_id = current_stmt.body
        # util.debug(f"body_id=current_stmt.body: {body_id}")
        body = self.read_block(body_id)
        boundary = self.boundary_of_multi_blocks(current_block, [body_id])

        case_stmt_set = []
        if body:
            case_stmt_set = body.query_field("parent_stmt_id", body_id)
        # util.debug(f"case_stmt_set = body.remove_blocks():{case_stmt_set}")

        last_stmts_of_previous_body = []
        special_stmts = []
        for case_stmt in case_stmt_set:
            # util.debug(f"-==-for case_stmt in case_stmt_set:{case_stmt}")
            # link swith and case/default
            self.link_parent_stmts_to_current_stmt([current_stmt], case_stmt)
            last_stmts_of_previous_body.append(case_stmt)

            case_body_id = case_stmt.body
            case_body = self.read_block(case_body_id)
            # util.debug(f"-==-case_body = self.read_block:\n{case_body}")

            last_stmts_of_previous_body = self.analyze_block(case_body, last_stmts_of_previous_body, special_stmts)

        return (last_stmts_of_previous_body + special_stmts, boundary)

    def analyze_try_stmt(self, current_block, current_stmt, parent_stmts, global_special_stmts):
        self.link_parent_stmts_to_current_stmt(parent_stmts, current_stmt)

        # 1. Try body
        last_stmts_of_body = self.analyze_block(
            self.read_block(current_stmt.body), [current_stmt], global_special_stmts
        )

        # 2. Catch clauses
        last_stmts_of_catch_body = []
        catch_body_id = current_stmt.catch_body
        if not util.isna(catch_body_id):
            catch_block = self.read_block(catch_body_id)
            catch_clauses = catch_block.query_field("parent_stmt_id", catch_body_id)
            for stmt in catch_clauses:
                # Link each catch clause directly from all ends of the try body
                self.link_parent_stmts_to_current_stmt(last_stmts_of_body, stmt)
                if stmt.operation == "catch_clause":
                    last_stmts_of_catch_body.extend(
                        self.analyze_block(
                            self.read_block(stmt.body), [CFGNode(stmt, CONTROL_FLOW_KIND.CATCH_TRUE)], global_special_stmts
                        )
                    )

        # 3. Else body
        last_stmts_of_else = []
        else_body_id = current_stmt.else_body
        if not util.isna(else_body_id):
            last_stmts_of_else = self.analyze_block(
                self.read_block(else_body_id),
                [CFGNode(s, CONTROL_FLOW_KIND.CATCH_FALSE) for s in last_stmts_of_body],
                global_special_stmts
            )
        else:
            last_stmts_of_else = last_stmts_of_body

        # 4. Finally body
        final_body_id = current_stmt.final_body
        if not util.isna(final_body_id):
            finally_parents = [CFGNode(s, CONTROL_FLOW_KIND.CATCH_FINALLY) for s in last_stmts_of_catch_body + last_stmts_of_else]
            last_stmts_of_finally = self.analyze_block(
                self.read_block(final_body_id), finally_parents, global_special_stmts
            )
            exit_stmts = last_stmts_of_finally
        else:
            exit_stmts = last_stmts_of_catch_body + last_stmts_of_else

        boundary = self.boundary_of_multi_blocks(current_block, [current_stmt.body, catch_body_id, else_body_id, final_body_id])
        return (exit_stmts, boundary)

    def analyze_method_decl_stmt(self, current_block, current_stmt, parent_stmts, global_special_stmts):
        self.link_parent_stmts_to_current_stmt(parent_stmts, current_stmt)
        boundary = self.boundary_of_multi_blocks(
            current_block,
            [
                current_stmt.parameters,
                current_stmt.init,
                current_stmt.body,
            ]
        )
        return ([current_stmt], boundary)

    def analyze_decl_stmt(self, current_block, current_stmt, parent_stmts, global_special_stmts):
        """
        class_decl,
        record_decl,
        interface_decl,
        enum_decl,
        enum_constants,
        annotation_type_decl,
        method_decl,
        """
        # static_member_field -> static_init -> member_field -> init -> constructor
        self.link_parent_stmts_to_current_stmt(parent_stmts, current_stmt)
        boundary = self.boundary_of_multi_blocks(
            current_block,
            [
                current_stmt.static_init,
                current_stmt.init,
                current_stmt.fields,
                current_stmt.methods,
                current_stmt.nested
            ]
        )
        last_stmts = [current_stmt]
        static_init_id = current_stmt.static_init
        if not util.isna(static_init_id):
            static_init_body = self.read_block(static_init_id)
            if len(static_init_body) != 0:
                last_stmts = self.analyze_block(static_init_body, [current_stmt], global_special_stmts)

        init_id = current_stmt.init
        if not util.isna(init_id):
            init_body = self.read_block(init_id)
            if len(init_body) != 0:
                last_stmts = self.analyze_block(init_body, last_stmts, global_special_stmts)

        methods_id = current_stmt.methods
        if not util.isna(methods_id):
            methods_body = self.read_block(methods_id)
            if len(methods_body) != 0:
                last_stmts = self.analyze_block(methods_body, last_stmts, global_special_stmts)

        nested_id = current_stmt.nested
        if not util.isna(nested_id):
            nested_body = self.read_block(nested_id)
            if len(nested_body) != 0:
                last_stmts = self.analyze_block(nested_body, last_stmts, global_special_stmts)

        return (last_stmts, boundary)

    def analyze_return_stmt(self, current_block, current_stmt, parent_stmts, global_special_stmts):
        self.link_parent_stmts_to_current_stmt(parent_stmts, current_stmt)
        self.cfg.add_edge(current_stmt, -1, CONTROL_FLOW_KIND.RETURN)

        return ([], -1)

    def analyze_break_stmt(self, current_block, current_stmt, parent_stmts, global_special_stmts):
        self.link_parent_stmts_to_current_stmt(parent_stmts, current_stmt)
        global_special_stmts.append(current_stmt)

        return ([], -1)

    def analyze_continue_stmt(self, current_block, current_stmt, parent_stmts, global_special_stmts):
        self.link_parent_stmts_to_current_stmt(parent_stmts, current_stmt)
        # self.cfg.add_edge(current_stmt.stmt_id, -1, ControlFlowKind.RETURN)
        global_special_stmts.append(current_stmt)
        return ([], -1)

    def analyze_yield_stmt(self, current_block, current_stmt, parent_stmts, global_special_stmts):
        self.link_parent_stmts_to_current_stmt([parent_stmts], current_stmt)
        self.link_parent_stmts_to_current_stmt([current_stmt], -1)
        boundary = current_stmt._index
        return ([current_stmt], boundary)

    def link_parent_stmts_to_current_stmt(self, parent_stmts: list, current_stmt):
        for node in parent_stmts:
            if isinstance(node, CFGNode):
                # Assumes node.stmt and node.edge are valid attributes for CFGNode
                self.cfg.add_edge(node.stmt, current_stmt, node.edge)
            else:
                # Links non-CFGNode items
                self.cfg.add_edge(node, current_stmt, CONTROL_FLOW_KIND.EMPTY)

    def analyze_init_block(self, current_block, parent_stmts = [], special_stmts = []):
        counter = 0
        previous = parent_stmts
        last_parameter_decl_stmts = []
        last_parameter_init_stmts = []
        first_init_stmt = True

        if util.is_empty(current_block):
            return previous

        while counter < len(current_block):
            current = current_block.access(counter)
            if current.operation == "parameter_decl":
                self.link_parent_stmts_to_current_stmt(parent_stmts, current)
                last_parameter_init_stmts.extend(previous)
                last_parameter_decl_stmts.append(CFGNode(current, CONTROL_FLOW_KIND.PARAMETER_UNINIT))
                previous = [current]
                counter += 1
                first_init_stmt = True
            else:
                handler = self.stmt_handlers.get(current.operation, None)
                if first_init_stmt:
                    previous = [CFGNode(previous, CONTROL_FLOW_KIND.PARAMETER_INIT)]
                    first_init_stmt = False
                if handler is None:
                    self.link_parent_stmts_to_current_stmt(previous, current)
                    previous = [current]
                    counter += 1
                else:
                    previous, boundary = handler(current_block, current, previous, special_stmts)
                    if boundary < 0:
                        break
                    counter = boundary + 1
                if counter >= len(current_block):
                    last_parameter_init_stmts.extend(previous)
        return last_parameter_decl_stmts + last_parameter_init_stmts

    def analyze_block(self, current_block: GIRBlockViewer, parent_stmts = [], special_stmts = []):
        """
        This function is going to deal with current block and extract its control flow graph.
        It returns the last statements inside this block.
        """

        previous = parent_stmts

        if util.is_empty(current_block):
            return previous
        
        current_range = current_block.get_range()
        pos = current_range.get_real_start_index()
        boundary = pos

        while pos < current_range.end:
            current = current_block.get_stmt_by_pos(pos)
            if util.is_empty(current):
                pos += 1
                continue
            handler = self.stmt_handlers.get(current.operation, None)
            if handler is None:
                self.link_parent_stmts_to_current_stmt(previous, current)
                previous = [current]
                pos += 1
            else:
                previous, boundary = handler(current_block, current, previous, special_stmts)
                if boundary < 0:
                    break
                pos = boundary + 1

        return previous
