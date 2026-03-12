#! /usr/bin/env python3
import json
import os, sys
from collections import deque

import lian.config.config as config
import networkx as nx

from lian.events.default_event_handlers.this_field_write import access_path_formatter
from lian.util import util
from lian.util.readable_gir import get_gir_str
from lian.taint.rule_manager import RuleManager, Rule
from lian.core.sfg_dumper import SFGDumper
from lian.config.constants import (
    ANALYSIS_PHASE_ID,
    SFG_NODE_KIND,
    SFG_EDGE_KIND,
    TAG_KEYWORD
)
from lian.taint.taint_structs import (
    TaintEnv,
    Flow,
)
import traceback

class PathFinder:
    """
    负责污点传播与路径重建的辅助类。
    将传播逻辑和路径查找从 TaintAnalysis 中拆分出来，保持主流程简洁。
    """

    def __init__(self, taint_analysis):
        self.ta = taint_analysis

    @property
    def sfg(self):
        return self.ta.sfg

    @property
    def taint_manager(self):
        return self.ta.taint_manager

    @property
    def rule_applier(self):
        return self.ta.rule_applier

    def _get_node_tag(self, u):
        """获取节点的污点标记。对于 STMT 节点，其标记来源于它所使用的 SYMBOL。"""
        if u.node_type == SFG_NODE_KIND.SYMBOL:
            return self.taint_manager.get_symbol_tag(u.node_id)
        elif u.node_type == SFG_NODE_KIND.STATE:
            return self.taint_manager.get_state_tag(u.node_id)
        elif u.node_type == SFG_NODE_KIND.STMT:
            u_tag = 0
            for pred in self.sfg.predecessors(u):
                edge_data = self.sfg.get_edge_data(pred, u)
                if edge_data:
                    for data in edge_data.values():
                        if data.edge_type == SFG_EDGE_KIND.SYMBOL_IS_USED:
                            u_tag |= self.taint_manager.get_symbol_tag(pred.node_id)
            return u_tag
        return 0

    def _enqueue(self, worklist, in_worklist, node):
        """将 node 放入 worklist（去重）。"""
        if node in in_worklist:
            return
        worklist.append(node)
        in_worklist.add(node)

    def _init_source_contamination(self, source, tag, worklist, in_worklist):
        """对初始 source 节点进行污染标记"""
        if source.node_type == SFG_NODE_KIND.SYMBOL:
            self.taint_manager.set_symbol_tag(source.node_id, tag)
            self._enqueue(worklist, in_worklist, source)
            # 污染变量对应的初始状态
            for v in self.sfg.successors(source):
                edge_data = self.sfg.get_edge_data(source, v)
                if edge_data:
                    for data in edge_data.values():
                        if data.edge_type == SFG_EDGE_KIND.SYMBOL_STATE:
                            self.taint_manager.set_states_tag([v.node_id], tag)
                            self._enqueue(worklist, in_worklist, v)
        elif source.node_type == SFG_NODE_KIND.STATE:
            self.taint_manager.set_states_tag([source.node_id], tag)
            self._enqueue(worklist, in_worklist, source)
        elif source.node_type == SFG_NODE_KIND.STMT:
            self._enqueue(worklist, in_worklist, source)

    def _propagate_from_symbol(self, u, u_tag, worklist, in_worklist):
        """处理从 SYMBOL 节点向下的传播"""
        for v in self.sfg.successors(u):
            edge_data = self.sfg.get_edge_data(u, v)
            if edge_data:
                for data in edge_data.values():
                    etype = data.edge_type
                    # 传播到状态或使用该变量的语句
                    if etype == SFG_EDGE_KIND.SYMBOL_STATE:
                        v_tag = self.taint_manager.get_state_tag(v.node_id)
                        if (u_tag | v_tag) != v_tag:
                            self.taint_manager.set_states_tag([v.node_id], u_tag | v_tag)
                            self._enqueue(worklist, in_worklist, v)
                    elif etype == SFG_EDGE_KIND.SYMBOL_IS_USED:
                        # STMT 的 tag 来自其 use 的 SYMBOL；当 SYMBOL 的 tag 发生变化时，重新处理该 STMT。
                        self._enqueue(worklist, in_worklist, v)
                    elif etype in (SFG_EDGE_KIND.SYMBOL_FLOW, SFG_EDGE_KIND.INDIRECT_SYMBOL_FLOW):
                        # SYMBOL -> SYMBOL 的数据流传播
                        if v.node_type != SFG_NODE_KIND.SYMBOL:
                            continue
                        v_tag = self.taint_manager.get_symbol_tag(v.node_id)
                        if (u_tag | v_tag) != v_tag:
                            self.taint_manager.set_symbol_tag(v.node_id, u_tag | v_tag)
                            self._enqueue(worklist, in_worklist, v)

    def _propagate_from_state(self, u, u_tag, worklist, in_worklist):
        """处理从 STATE 节点向下的传播"""
        # 1. 传播到指向该值的变量 (逆向回溯)
        for v in self.sfg.predecessors(u):
            edge_data = self.sfg.get_edge_data(v, u)
            if edge_data:
                for data in edge_data.values():
                    if data.edge_type in (SFG_EDGE_KIND.SYMBOL_STATE, SFG_EDGE_KIND.STATE_INCLUSION):
                        v_tag = self.taint_manager.get_symbol_tag(v.node_id)
                        if (u_tag | v_tag) != v_tag:
                            self.taint_manager.set_symbol_tag(v.node_id, u_tag | v_tag)
                            self._enqueue(worklist, in_worklist, v)

        # 2. 传播到其包含的子状态 (inclusion)
        for v in self.sfg.successors(u):
            if v.node_type == SFG_NODE_KIND.STATE:
                edge_data = self.sfg.get_edge_data(u, v)
                if edge_data:
                    for data in edge_data.values():
                        if data.edge_type in (SFG_EDGE_KIND.STATE_INCLUSION,
                                                            SFG_EDGE_KIND.INDIRECT_STATE_INCLUSION):
                            v_tag = self.taint_manager.get_state_tag(v.node_id)
                            if (u_tag | v_tag) != v_tag:
                                self.taint_manager.set_states_tag([v.node_id], u_tag | v_tag)
                                self._enqueue(worklist, in_worklist, v)

    def _propagate_from_stmt(self, u, u_tag, worklist, in_worklist):
        """处理从 STMT 节点向下的传播"""
        # 根据规则判断语句是否传播污点
        if self.rule_applier.apply_propagation_rules(u):
            for v in self.sfg.successors(u):
                edge_data = self.sfg.get_edge_data(u, v)
                if edge_data:
                    for data in edge_data.values():
                        # 传播到该语句定义的变量
                        if data.edge_type == SFG_EDGE_KIND.SYMBOL_IS_DEFINED:
                            v_tag = self.taint_manager.get_symbol_tag(v.node_id)
                            if (u_tag | v_tag) != v_tag:
                                self.taint_manager.set_symbol_tag(v.node_id, u_tag | v_tag)
                                # 只有当目标 SYMBOL 的 tag 发生变化时才入队，避免环路导致无限传播。
                                self._enqueue(worklist, in_worklist, v)
                            else:
                                # 逻辑补丁：如果该 SYMBOL 已经带着相同 tag，但本轮从未被处理过，
                                # 仍需入队一次以触发其后继 STMT 的分析（否则可能“永远不入队”）。
                                if getattr(self, "_processed_nodes", None) is not None and v not in self._processed_nodes:
                                    self._enqueue(worklist, in_worklist, v)
            # object_call_stmt: target = receiver.field(args)
            # 当 args 携带污点时，receiver 也可能被副作用污染（常见于可变对象的 method call）。
            # 在 SFG 中 receiver_symbol 是该 STMT 的前驱（SYMBOL_IS_USED, pos==0），这里将 u_tag 回写到 receiver。
            if getattr(u, "name", None) == "object_call_stmt":
                for pred in self.sfg.predecessors(u):
                    edge_data = self.sfg.get_edge_data(pred, u)
                    if not edge_data:
                        continue
                    for data in edge_data.values():
                        weight = data
                        if not weight:
                            continue
                        if weight.edge_type != SFG_EDGE_KIND.SYMBOL_IS_USED:
                            continue
                        # object_call 的 receiver 占用 pos==0
                        if getattr(weight, "pos", -1) != 0:
                            continue
                        if pred.node_type != SFG_NODE_KIND.SYMBOL:
                            continue
                        pred_tag = self.taint_manager.get_symbol_tag(pred.node_id)
                        if (u_tag | pred_tag) != pred_tag:
                            self.taint_manager.set_symbol_tag(pred.node_id, u_tag | pred_tag)
                            self._enqueue(worklist, in_worklist, pred)
                        else:
                            if getattr(self, "_processed_nodes", None) is not None and pred not in self._processed_nodes:
                                self._enqueue(worklist, in_worklist, pred)
                        # receiver 只有一个，找到即可
                        break


    def propagate_taint(self, source):
        """
        从给定的 source 开始在 SFG 中传播污点。
        返回为该 source 分配的位标记 (tag)。
        """
        tag_info = Rule(name=f"Source_{source.def_stmt_id}", operation="source_propagation", rule_id=id(source))
        tag = self.taint_manager.add_and_update_tag_bv(tag_info, 0)

        worklist = deque()
        in_worklist = set()
        # 记录本轮传播中“已经实际出队并处理过”的节点。
        # 用于修复：某些节点在进入传播前已带有目标 tag，但从未入队，导致其后继语句永远不被处理。
        self._processed_nodes = set()
        self._init_source_contamination(source, tag, worklist, in_worklist)

        # BFS 传播
        while worklist:
            u = worklist.popleft()
            in_worklist.discard(u)
            self._processed_nodes.add(u)
            # 给每个“实际处理过”的节点打标（用于导出 SFG 时染色）
            try:
                self.taint_manager.mark_processed_node(u)
            except Exception:
                pass
            u_tag = self._get_node_tag(u)

            if u_tag == 0:
                continue

            if u.node_type == SFG_NODE_KIND.SYMBOL:
                self._propagate_from_symbol(u, u_tag, worklist, in_worklist)
            elif u.node_type == SFG_NODE_KIND.STATE:
                self._propagate_from_state(u, u_tag, worklist, in_worklist)
            elif u.node_type == SFG_NODE_KIND.STMT:
                self._propagate_from_stmt(u, u_tag, worklist, in_worklist)
        # 清理本轮状态，避免跨 source 互相影响
        self._processed_nodes = set()
        return tag

    def reconstruct_define_use_path(self, source, sink):
        """
        采用深度优先的方式从 source 开始遍历 SFG 来寻找路径。
        当遍历到 sink_stmt 时，则找到路径；
        如果遍历完整个可达子图都没有遇到 sink，则选一条遍历过程中产生的路径，并加上 sink_stmt。
        """
        visited = set()
        longest_path = []

        def dfs(u, path_stmts):
            nonlocal longest_path
            if u in visited:
                return None
            visited.add(u)

            # 如果当前节点是语句，加入路径
            new_path = list(path_stmts)
            if u.node_type == SFG_NODE_KIND.STMT:
                if not new_path or new_path[-1] != u:
                    new_path.append(u)

            # 记录遍历过程中最长的一条路径作为备选
            if len(new_path) >= len(longest_path):
                longest_path = new_path

            # 到达终点
            if u == sink:
                return new_path

            # 深度优先遍历继承者
            for v in self.sfg.successors(u):
                result = dfs(v, new_path)
                if result:
                    return result

            return None

        final_path = dfs(source, [])

        if final_path is None:
            # 如果没找到 sink，选一条遍历到的路径并强行加上 sink
            if not longest_path or longest_path[-1] != sink:
                final_path = longest_path + [sink]
            else:
                final_path = longest_path

        flow = Flow()
        flow.source_stmt_id = source.def_stmt_id
        flow.sink_stmt_id = sink.def_stmt_id
        flow.parent_to_sink = final_path
        return flow


class TaintRuleApplier:
    def __init__(self, taint_analysis):
        self.taint_analysis = taint_analysis
        self.loader = taint_analysis.loader
        self.sfg = taint_analysis.sfg
        self.rule_manager = taint_analysis.rule_manager

    def apply_parameter_source_rules(self, node):
        stmt_id = node.def_stmt_id
        method_id = self.loader.convert_stmt_id_to_method_id(stmt_id)
        unit_id = self.loader.convert_stmt_id_to_unit_id(stmt_id)
        unit_info = self.loader.convert_module_id_to_module_info(unit_id)
        unit_path = unit_info.original_path
        unit_name = os.path.basename(unit_path)
        stmt = node.stmt
        # if not stmt.attrs:
        #     return False
        # if not isinstance(stmt.attrs, str):
        #     return False
        # attrs = stmt.attrs
        parameter_symbol = list(util.graph_successors(self.sfg, node))[0]
        for rule in self.rule_manager.all_sources:
            # if rule.unit_path and rule.unit_path != unit_path:
            #     continue
            if rule.unit_name and rule.unit_name != unit_name:
                continue
            if rule.line_num and rule.line_num != int(stmt.start_row + 1):
                continue
            if not rule.attr and rule.name == parameter_symbol.name:
                # print(rule.name)
                return True
            if rule.operation != "parameter_decl":
                continue
            # if rule.attr and rule.attr not in attrs:
            #     continue
            if rule.name == parameter_symbol.name:
                # print(rule.name)
                return True
        return False

    def apply_field_read_source_rules(self, node):
        # 找到类型为 symbol 的父节点，以及该 symbol 节点的类型为 state 的子节点
        symbol_node, state_nodes = self.taint_analysis.get_stmt_define_symbol_and_states_node(node)
        if not symbol_node or not state_nodes:
            return False

        for rule in self.rule_manager.all_sources:
            if rule.operation != "field_read":
                continue

            for state_node in state_nodes:
                # 格式化访问路径
                access_path = access_path_formatter(state_node.access_path)
                if access_path == rule.name:
                    # print(rule.name)
                    return True

        return False

    def apply_call_stmt_source_rules(self, node):
        stmt_id = node.def_stmt_id
        unit_id = self.loader.convert_stmt_id_to_unit_id(stmt_id)
        unit_info = self.loader.convert_module_id_to_module_info(unit_id)
        unit_path = unit_info.original_path
        unit_name = os.path.basename(unit_path)
        method_symbol_node, method_state_nodes = self.taint_analysis.get_stmt_used_symbol_and_state_by_pos(node)
        defined_symbol_node, defined_state_nodes = self.taint_analysis.get_stmt_define_symbol_and_states_node(node)
        if not method_symbol_node or not defined_symbol_node:
            return False

        tag_space_id = defined_symbol_node.node_id
        apply_rule_flag = False
        for rule in self.rule_manager.all_sources:
            if rule.unit_path and rule.unit_path != unit_path:
                continue
            if rule.unit_name and rule.unit_name != unit_name:
                continue
            if rule.line_num and rule.line_num != int(node.line_no + 1):
                continue
            if rule.operation != "call_stmt":
                continue
            tag_info = rule
            name = tag_info.name
            for state_node in method_state_nodes:
                state_access_path = state_node.access_path
                if isinstance(state_access_path, str):
                    continue
                access_path = access_path_formatter(state_access_path)

                if len(access_path) == 0:
                    access_path = method_symbol_node.name
                if access_path == name:
                    # print(rule.name)
                    apply_rule_flag = True
                    tag = self.taint_analysis.taint_manager.get_symbol_tag(tag_space_id)
                    new_tag = self.taint_analysis.taint_manager.add_and_update_tag_bv(tag_info=tag_info,
                                                                                      current_taint=tag)
                    self.taint_analysis.taint_manager.set_symbols_tag([tag_space_id], new_tag)
                    for defined_state_node in defined_state_nodes:
                        self.taint_analysis.taint_manager.set_states_tag([defined_state_node.node_id], new_tag)

        return apply_rule_flag

    def apply_object_call_stmt_source_rules(self, node):
        if node.node_type != SFG_NODE_KIND.STMT or node.name != "object_call_stmt":
            return False
        stmt = node.stmt
        stmt_id = node.def_stmt_id
        unit_id = self.loader.convert_stmt_id_to_unit_id(stmt_id)
        unit_info = self.loader.convert_module_id_to_module_info(unit_id)
        unit_path = unit_info.original_path
        unit_name = os.path.basename(unit_path)
        method_symbol_node, method_state_nodes = self.taint_analysis.get_stmt_used_symbol_and_state_by_pos(node, pos = 0)
        names = []
        if method_state_nodes and len(method_state_nodes) > 0:
            for state in method_state_nodes:
                names.append(util.access_path_formatter(state.access_path) + '.' + stmt.field)

        names.append(stmt.receiver_object + '.' + stmt.field)
        # print(name, stmt.start_row)
        for rule in self.rule_manager.all_sources:
            if rule.unit_path and rule.unit_path != unit_path:
                continue
            if rule.unit_name and rule.unit_name != unit_name:
                continue
            if rule.line_num and rule.line_num != int(node.line_no + 1):
                continue
            if rule.name in names:
                # print(rule.name)
                return True
        return False

    def should_apply_object_call_stmt_sink_rules(self, node):
        if node.node_type != SFG_NODE_KIND.STMT or node.name != "object_call_stmt":
            return False
        stmt = node.stmt
        stmt_id = node.def_stmt_id
        unit_id = self.loader.convert_stmt_id_to_unit_id(stmt_id)
        unit_info = self.loader.convert_module_id_to_module_info(unit_id)
        unit_path = unit_info.original_path
        unit_name = os.path.basename(unit_path)
        method_symbol_node, method_state_nodes = self.taint_analysis.get_stmt_used_symbol_and_state_by_pos(node)
        names = []
        if method_state_nodes and len(method_state_nodes) > 0:
            for state in method_state_nodes:
                names.append(util.access_path_formatter(state.access_path) + '.' + stmt.field)

        names.append(stmt.receiver_object + '.' + stmt.field)
        if stmt.field == "__init__":
            names.append("__init__")
        # print(name, stmt.start_row)
        for rule in self.rule_manager.all_sinks:
            if rule.unit_path and rule.unit_path != unit_path:
                continue
            if rule.unit_name and rule.unit_name != unit_name:
                continue
            if rule.line_num and rule.line_num != int(node.line_no + 1):
                continue
            if rule.name in names:
                return True
        return False

    def should_apply_call_stmt_sink_rules(self, node):
        if node.node_type != SFG_NODE_KIND.STMT or node.name != "call_stmt":
            return False
        method_symbol_node, method_state_nodes = self.taint_analysis.get_stmt_used_symbol_and_state_by_pos(node, pos=0)
        stmt_id = node.def_stmt_id
        unit_id = self.loader.convert_stmt_id_to_unit_id(stmt_id)
        unit_info = self.loader.convert_module_id_to_module_info(unit_id)
        unit_path = unit_info.original_path
        unit_name = os.path.basename(unit_path)
        for rule in self.rule_manager.all_sinks:
            if rule.operation != "call_stmt":
                continue
            # if rule.unit_path and rule.unit_path != unit_path:
            #     continue
            if rule.unit_name and rule.unit_name != unit_name:
                continue
            if rule.line_num and rule.line_num != int(node.line_no + 1):
                continue
            if not method_state_nodes:
                continue
            for state_node in method_state_nodes:
                # 检查函数名是否符合规则
                if self.check_method_name(rule.name, state_node):
                    return True

        return False
    def apply_rules_from_code(self, node, rules):
        stmt_id = node.def_stmt_id
        unit_id = self.loader.convert_stmt_id_to_unit_id(stmt_id)
        unit_info = self.loader.convert_module_id_to_module_info(unit_id)
        unit_path = unit_info.original_path

        for rule in rules:
            if rule.unit_path not in unit_path:
                continue
            if node.line_no + 1 != rule.line_num:
                continue
            if rule.symbol_name in node.operation:
                return True
        return False

    def apply_record_write_sink_rules(self, node):
        stmt_id = node.def_stmt_id
        unit_id = self.loader.convert_stmt_id_to_unit_id(stmt_id)
        unit_info = self.loader.convert_module_id_to_module_info(unit_id)
        unit_path = unit_info.original_path
        unit_name = os.path.basename(unit_path)
        if node.node_type != SFG_NODE_KIND.STMT or node.name != "record_write":
            return False

        for rule in self.rule_manager.all_sinks:
            if rule.operation != "record_write":
                continue
            if rule.unit_path and rule.unit_path != unit_path:
                continue
            if rule.unit_name and rule.unit_name != unit_name:
                continue
            if rule.line_num and rule.line_num != int(node.line_no + 1):
                continue
            if rule.key and rule.key == node.stmt.key:
                return True

        return False

    def apply_field_write_sink_rules(self, node):
        stmt_id = node.def_stmt_id
        unit_id = self.loader.convert_stmt_id_to_unit_id(stmt_id)
        unit_info = self.loader.convert_module_id_to_module_info(unit_id)
        unit_path = unit_info.original_path
        unit_name = os.path.basename(unit_path)
        if node.node_type != SFG_NODE_KIND.STMT or node.name != "field_write":
            return False

        for rule in self.rule_manager.all_sinks:
            if rule.operation != "field_write":
                continue
            if rule.unit_path and rule.unit_path != unit_path:
                continue
            if rule.unit_name and rule.unit_name != unit_name:
                continue
            if rule.line_num and rule.line_num != int(node.line_no + 1):
                continue
            if rule.name and rule.name in node.operation:
                return True

        return False

    def check_method_name(self, rule_name, method_state):
        state_access_path = method_state.access_path
        rule_name_parts = rule_name.split('.')
        if len(state_access_path) < len(rule_name_parts):
            return False
        # name匹配上
        for i, item in enumerate(reversed(rule_name_parts)):
            if item == TAG_KEYWORD.ANYNAME:
                continue
            if item != state_access_path[-i - 1].key:
                return False
        return True

    def apply_propagation_rules(self, node):
        stmt_id = node.def_stmt_id
        stmt = node.stmt
        operation = node.name

        # 默认认为赋值语句传播污点
        if operation in ["assign_stmt", "call_stmt", "object_call_stmt", "new_object", "forin_stmt", "field_read","field_write", "record_write","record_extend", "array_write", "array_extend", "array_append", "array_read"] :
            return True

        for rule in self.rule_manager.all_propagations:
            if rule.operation != operation:
                continue

            if operation == "field_read":
                # 1. 检查字段名列表 (field: [split, next, ...])
                if hasattr(stmt, 'field') and rule.field:
                    if stmt.field in rule.field:
                        return True
                # 2. 检查特定 target (target: request.query_string)
                symbol_node, state_nodes = self.taint_analysis.get_stmt_define_symbol_and_states_node(node)
                if state_nodes:
                    for state_node in state_nodes:
                        access_path = access_path_formatter(state_node.access_path)
                        if access_path == rule.target:
                            return True
                # 3. 简单的 src/dst 规则 (如 src: receiver)
                if not rule.field and not rule.target:
                    return True

            elif operation == "call_stmt":
                # 检查函数名是否符合规则
                method_symbol_node, method_state_nodes = self.taint_analysis.get_stmt_used_symbol_and_state_by_pos(node)
                if method_state_nodes:
                    for state_node in method_state_nodes:
                        if self.check_method_name(rule.name, state_node):
                            return True
                # 如果都没有匹配上，但规则确实是 call_stmt 且没有指定 name（较少见），可以返回 True
                if not rule.name:
                    return True

        return False

    def get_sink_tag_by_rules(self, node):
        sink_tag = 0
        vuln_type = None
        if node.node_type != SFG_NODE_KIND.STMT:
            return sink_tag,  vuln_type

        stmt_id = node.def_stmt_id
        stmt = node.stmt
        operation = node.name

        # 1. 寻找匹配的 sink 规则
        matching_rules = []
        if operation == "call_stmt":
            _, method_state_nodes = self.taint_analysis.get_stmt_used_symbol_and_state_by_pos(node)
            for rule in self.rule_manager.all_sinks:
                if rule.operation != "call_stmt":
                    continue
                if not method_state_nodes:
                    if rule.name == stmt.name:
                        matching_rules.append(rule)
                    continue
                for state_node in method_state_nodes:
                    if self.check_method_name(rule.name, state_node):
                        matching_rules.append(rule)
                        break
        elif operation == "object_call_stmt":
            method_symbol_node, method_state_nodes = self.taint_analysis.get_stmt_used_symbol_and_state_by_pos(node)
            name = None
            if method_state_nodes and len(method_state_nodes) > 0:
                name = util.access_path_formatter(method_state_nodes[0].access_path) + '.' + stmt.field

            name1 = stmt.receiver_object + '.' + stmt.field
            for rule in self.rule_manager.all_sinks:
                if rule.name in [name, name1, stmt.field]:
                    matching_rules.append(rule)
        elif operation == "field_write":
            used_symbol_nodes, used_state_nodes = self.taint_analysis.get_stmt_used_symbol_and_state_by_pos(node)
            for rule in self.rule_manager.all_sinks:
                if rule.operation != "field_write":
                    continue
                if rule.name in node.operation:
                    matching_rules.append(rule)
        elif operation == "field_write":
            used_symbol_nodes, used_state_nodes = self.taint_analysis.get_stmt_used_symbol_and_state_by_pos(node)
            for rule in self.rule_manager.all_sinks:
                if rule.operation != "field_write":
                    continue
                if rule.name in node.operation:
                    matching_rules.append(rule)

        # 2. 根据规则检查对应的 symbol 和 state
        for rule in matching_rules:
            targets = rule.target if isinstance(rule.target, list) else [rule.target]
            vuln_type = rule.vuln_type
            for target in targets:
                # target_pos = -1
                if target == TAG_KEYWORD.ARG0:
                    target_pos = 1
                elif target == TAG_KEYWORD.ARG1:
                    target_pos = 2
                elif target == TAG_KEYWORD.ARG2:
                    target_pos = 3
                elif target == TAG_KEYWORD.ARG3:
                    target_pos = 4
                elif target == TAG_KEYWORD.ARG4:
                    target_pos = 5
                elif target in [TAG_KEYWORD.RECEIVER, TAG_KEYWORD.TARGET]:
                    target_pos = 0

                for pred in self.sfg.predecessors(node):
                    edge_data = self.sfg.get_edge_data(pred, node)
                    if not edge_data: continue
                    for data in edge_data.values():
                        weight = data
                        if weight.edge_type != SFG_EDGE_KIND.SYMBOL_IS_USED:
                            continue

                        weight_pos = weight.pos
                        if operation == "object_call_stmt" and target_pos != 0:
                            weight_pos -= 1

                        # 匹配位置或者目标是通配符
                        if (target_pos != -1 and weight_pos == target_pos) or \
                            (target == TAG_KEYWORD.TARGET) or \
                            (not target):
                            sink_tag |= self.taint_analysis.get_symbol_with_states_tag(pred)
        # 应用codeql规则
        is_sink_node = False
        for rule in self.rule_manager.all_sinks_from_code:
            if node.line_no + 1 != rule.line_num:
                continue
            if rule.symbol_name in node.operation:
                is_sink_node = True
        if is_sink_node:
            for pred in self.sfg.predecessors(node):
                sink_tag |= self.taint_analysis.get_symbol_with_states_tag(pred)
        return sink_tag, vuln_type


class TaintAnalysis:
    def __init__(self, lian, options):
        self.lian = lian
        self.loader = self.lian.loader
        self.options = options
        self.default_settings = options.default_settings
        self.taint_manager: TaintEnv = None
        self.rule_manager = RuleManager(options.default_settings)
        self.current_entry_point = -1
        self.sfg = None
        self.rule_applier = TaintRuleApplier(self)
        self.path_finder = PathFinder(self)

    def _update_sfg(self, sfg):
        self.sfg = sfg
        self.rule_applier.sfg = sfg
        self.path_finder.ta = self

    def read_rules(self, operation, source_rules):
        """从src.yaml文件中获取field_read语句类型的规则, 并根据每条规则创建taint_bv"""
        rules = []

        for rule in source_rules:
            if rule.operation == operation:
                rules.append(rule)
        return rules

    def get_stmt_used_symbol_and_state_by_pos(self, node, pos = -1):
        if node.node_type != SFG_NODE_KIND.STMT:
            return None, None
        state_nodes = []
        predecessors = list(util.graph_predecessors(self.sfg, node))
        name_symbol_node = None
        if len(predecessors) == 0:
            return None, None
        for predecessor in predecessors:
            edge = self.sfg.get_edge_data(predecessor, node)

            if edge and edge['weight'].pos == pos:
                name_symbol_node = predecessor
        name_symbol_successors = list(util.graph_successors(self.sfg, name_symbol_node))
        for successor in name_symbol_successors:
            if successor.node_type == SFG_NODE_KIND.STATE:
                state_nodes.append(successor)
        return name_symbol_node, state_nodes

    def get_stmt_define_symbol_and_states_node(self, node):
        if node.node_type != SFG_NODE_KIND.STMT:
            return None, None
        successors = list(util.graph_successors(self.sfg, node))
        define_symbol_node = None
        for successor in successors:
            if successor.node_id == -1 or successor.name == "":
                continue
            edge = self.sfg.get_edge_data(node, successor)
            if edge and edge['weight'].edge_type == SFG_EDGE_KIND.SYMBOL_IS_DEFINED:
                define_symbol_node = successor
        define_symbol_successors = list(util.graph_successors(self.sfg, define_symbol_node))
        define_state_list = []
        for successor in define_symbol_successors:
            edge = self.sfg.get_edge_data(define_symbol_node, successor)
            if edge and edge['weight'].edge_type == SFG_EDGE_KIND.SYMBOL_STATE:
                define_state_list.append(successor)
        return define_symbol_node, define_state_list

    def find_sources(self):
        node_list = []
        # 应该包括所有的可能symbol和state节点作为sources
        # 这里应该应用source的规则
        # 遍历sfg
        for node in self.sfg.nodes:
            if node.node_type != SFG_NODE_KIND.STMT:
                continue
            if node.name == "call_stmt" and self.rule_applier.apply_call_stmt_source_rules(node):
                defined_symbol_node, defined_state_nodes = self.get_stmt_define_symbol_and_states_node(node)
                node_list.append(defined_symbol_node)
            elif node.name == "object_call_stmt" and self.rule_applier.apply_object_call_stmt_source_rules(node):
                defined_symbol_node, defined_state_nodes = self.get_stmt_define_symbol_and_states_node(node)
                node_list.append(defined_symbol_node)
            elif node.name == "parameter_decl" and self.rule_applier.apply_parameter_source_rules(node):
                defined_symbol_node, defined_state_nodes = self.get_stmt_define_symbol_and_states_node(node)
                node_list.append(defined_symbol_node)
            elif node.name == "field_read" and self.rule_applier.apply_field_read_source_rules(node):
                defined_symbol_node, defined_state_nodes = self.get_stmt_define_symbol_and_states_node(node)
                node_list.append(defined_symbol_node)
            # 为了兼容codeql规则
            else:
                rules = self.rule_manager.all_sources_from_code
                if self.rule_applier.apply_rules_from_code(node, rules):
                    defined_symbol_node, defined_state_nodes = self.get_stmt_define_symbol_and_states_node(node)
                    node_list.append(defined_symbol_node)

        return node_list

    def access_path_formatter(self, state_access_path):
        key_list = []
        for item in state_access_path:
            key = item.key
            key = key if isinstance(key, str) else str(key)
            if key != "":
                key_list.append(key)

        # 使用点号连接所有 key 值
        access_path = '.'.join(key_list)
        return access_path

    def find_sinks(self):
        # 找到所有的sink函数或者语句
        # 这里应该应用sink的规则
        node_list = []
        for node in self.sfg.nodes:
            if self.rule_applier.should_apply_call_stmt_sink_rules(
                node) or self.rule_applier.should_apply_object_call_stmt_sink_rules(node):
                node_list.append(node)
            elif self.rule_applier.apply_record_write_sink_rules(node):
                node_list.append(node)
            elif self.rule_applier.apply_field_write_sink_rules(node):
                node_list.append(node)
            else:
                rules = self.rule_manager.all_sinks_from_code
                if self.rule_applier.apply_rules_from_code(node, rules):
                    node_list.append(node)
        return node_list

    def check_method_name(self, rule_name, method_state):
        apply_flag = True

        state_access_path = method_state.access_path

        rule_name = rule_name.split('.')
        if len(state_access_path) < len(rule_name):
            return False
        # name匹配上
        for i, item in enumerate(reversed(rule_name)):
            if item == TAG_KEYWORD.ANYNAME:
                continue
            if item != state_access_path[-i - 1].key:
                apply_flag = False
                break

        return apply_flag

    def get_state_with_inclusion_tag(self, state_node):
        """获取 state 节点及其所有通过 inclusion 关系包含的子 state 节点的污点标记总和"""
        tag = 0
        state_worklist = deque([state_node])
        state_visited = {state_node}
        while state_worklist:
            curr_state = state_worklist.popleft()
            tag |= self.taint_manager.get_state_tag(curr_state.node_id)

            for next_state in self.sfg.successors(curr_state):
                if next_state.node_type == SFG_NODE_KIND.STATE and next_state not in state_visited:
                    s_edge_data = self.sfg.get_edge_data(curr_state, next_state)
                    if s_edge_data:
                        for s_data in s_edge_data.values():
                            if s_data.edge_type in (
                                    SFG_EDGE_KIND.STATE_INCLUSION,
                                    SFG_EDGE_KIND.INDIRECT_STATE_INCLUSION):
                                state_visited.add(next_state)
                                state_worklist.append(next_state)
                                break
        return tag

    def get_symbol_with_states_tag(self, symbol_node):
        """获取 symbol 节点及其指向的所有 state 节点的污点标记总和"""
        tag = self.taint_manager.get_symbol_tag(symbol_node.node_id)
        for v in self.sfg.successors(symbol_node):
            v_edge_data = self.sfg.get_edge_data(symbol_node, v)
            if v_edge_data:
                for v_data in v_edge_data.values():
                    if v_data.edge_type == SFG_EDGE_KIND.SYMBOL_STATE:
                        tag |= self.get_state_with_inclusion_tag(v)
        return tag

    def find_flows(self, sources, sinks):
        # 找到所有的taint flow
        # 每次处理一个 source 和 一个 sink 的组合
        flow_list = []
        dumped_sources = set()

        for source in sources:
            for sink in sinks:
                # 1. 污点传播 (针对单一 Source)
                # 为每一次 (source, sink) 组合使用独立的污点管理器，确保隔离
                original_manager = self.taint_manager
                self.taint_manager = TaintEnv()

                # 执行污点传播并获取该 source 的 tag
                tag = self.path_finder.propagate_taint(source)

                # 传播完成后，taint_manager 已包含污染的 SYMBOL/STATE；
                # 导出标色后的 SFG（同一个 source 的传播结果不依赖 sink，避免重复导出）。
                source_key = (self.current_entry_point, source.node_type, source.node_id, source.def_stmt_id)
                if source_key not in dumped_sources:
                    dumped_sources.add(source_key)
                    self.save_graph_to_dot(
                        graph=self.sfg,
                        entry_point=f"{self.current_entry_point}_taint_{source.def_stmt_id}",
                        phase_id=ANALYSIS_PHASE_ID.GLOBAL_SEMANTICS,
                        taint_manager=self.taint_manager
                    )
                    self.dump_tainted_sfg_by_method(
                        source=source,
                        phase_id=ANALYSIS_PHASE_ID.GLOBAL_SEMANTICS,
                        taint_manager=self.taint_manager
                    )
                # 2. Sink 检查 (针对单一 Sink)
                sink_tag, vuln_type = self.rule_applier.get_sink_tag_by_rules(sink)

                if (sink_tag & tag) != 0:
                    # print("found taint sink")
                    flow = self.path_finder.reconstruct_define_use_path(source, sink)
                    flow.vuln_type = vuln_type
                    flow_list.append(flow)

                # 恢复管理器
                self.taint_manager = original_manager

        return flow_list
    def save_graph_to_dot(self, graph, entry_point, phase_id, taint_manager=None):
        # 仅在用户开启 graph 输出时导出
        if not (getattr(self.options, "graph", False) or getattr(self.options, "complete_graph", False)):
            return

        if graph is None or len(graph) == 0:
            return

        dumper = SFGDumper(
            loader=self.loader,
            options=self.options,
            phase_id=phase_id,
            entry_point=entry_point,
            symbol_state_space=None,
            graph=graph,
            taint_manager=taint_manager
        )

        try:
            file_name = dumper.dump_to_file()
            if self.options.debug:
                util.debug(">>> Write state flow graph to dot file: ", file_name)
        except Exception:
            if not self.options.quiet:
                util.error("An error occurred while writing state flow graph to dot file.")
                traceback.print_exc()

    def _get_node_method_id(self, node):
        """
        尝试将 SFGNode 映射到其所属 method_id。
        优先使用 node.def_stmt_id -> method_id；无法映射时返回 -1。
        """
        try:
            if getattr(node, "def_stmt_id", -1) is None or node.def_stmt_id < 0:
                return -1
            return self.loader.convert_stmt_id_to_method_id(node.def_stmt_id)
        except Exception:
            return -1

    def split_sfg_by_method(self, graph):
        """
        将一个 entrypoint 的 SFG 按 method_id 拆分成多个子图。
        规则：
        - 节点归属：method_id = convert_stmt_id_to_method_id(node.def_stmt_id)
        - 边保留：仅保留两端节点属于同一 method_id 的边
        - 无法映射的节点（method_id == -1）归入 -1 组
        """
        method_to_nodes = {}
        for n in graph.nodes():
            mid = self._get_node_method_id(n)
            method_to_nodes.setdefault(mid, set()).add(n)

        method_to_subgraph = {}
        for mid, nodes in method_to_nodes.items():
            sg = nx.MultiDiGraph()
            sg.add_nodes_from(nodes)
            method_to_subgraph[mid] = sg

        for u, v, data in graph.edges( data=True):
            mu = self._get_node_method_id(u)
            mv = self._get_node_method_id(v)
            if mu != mv:
                continue
            method_to_subgraph[mu].add_edge(u, v, **data)

        return method_to_subgraph

    def dump_tainted_sfg_by_method(self, source, phase_id, taint_manager):
        """
        在污点传播完成后，将当前 entrypoint 的 SFG 按函数拆分并分别导出 dot。
        """
        if not (getattr(self.options, "graph", False) or getattr(self.options, "complete_graph", False)):
            return

        method_to_graph = self.split_sfg_by_method(self.sfg)
        for method_id, sub_g in method_to_graph.items():
            # method_id == -1 表示无法映射的“未知归属”节点集合
            if method_id >= 0:
                method_name = self.loader.convert_method_id_to_method_name(method_id)
                method_suffix = f"m{method_id}_{method_name}"
            else:
                method_suffix = "m_unknown"

            self.save_graph_to_dot(
                graph=sub_g,
                entry_point=f"{self.current_entry_point}_taint_{source.def_stmt_id}_{method_suffix}",
                phase_id=phase_id,
                taint_manager=taint_manager,
            )

    def get_all_forward_nodes(self, source):
        """
        从 source 开始，遍历 SFG 返回所有与 taint 有关的 symbol、state、stmt 节点。
        遵循传播逻辑：
        - SYMBOL -> STATE (SYMBOL_STATE), SYMBOL -> STMT (SYMBOL_IS_USED), SYMBOL -> SYMBOL (SYMBOL_FLOW)
        - STATE -> SYMBOL (逆向 SYMBOL_STATE), STATE -> STATE (STATE_INCLUSION/COPY)
        - STMT -> SYMBOL (SYMBOL_IS_DEFINED)
        """
        worklist = deque([source])
        visited = {source}

        while worklist:
            u = worklist.popleft()

            if u.node_type == SFG_NODE_KIND.SYMBOL:
                # 1. 向下传播到 STATE, STMT, 或其他 SYMBOL
                for v in self.sfg.successors(u):
                    if v in visited: continue
                    edge_data = self.sfg.get_edge_data(u, v)
                    if not edge_data: continue
                    for data in edge_data.values():
                        etype = data.edge_type
                        if etype in (SFG_EDGE_KIND.SYMBOL_STATE, SFG_EDGE_KIND.SYMBOL_IS_USED,
                                     SFG_EDGE_KIND.SYMBOL_FLOW, SFG_EDGE_KIND.INDIRECT_SYMBOL_FLOW):
                            visited.add(v)
                            worklist.append(v)
                            break

            elif u.node_type == SFG_NODE_KIND.STATE:
                # 1. 找到该值所属的所有 SYMBOL (逆着 SYMBOL_STATE 边)
                for v in self.sfg.predecessors(u):
                    if v in visited: continue
                    edge_data = self.sfg.get_edge_data(v, u)
                    if not edge_data: continue
                    for data in edge_data.values():
                        if data.edge_type == SFG_EDGE_KIND.SYMBOL_STATE:
                            visited.add(v)
                            worklist.append(v)
                            break
                # 2. 向下传播到包含的子状态
                for v in self.sfg.successors(u):
                    if v in visited: continue
                    edge_data = self.sfg.get_edge_data(u, v)
                    if not edge_data: continue
                    for data in edge_data.values():
                        etype = data.edge_type
                        if etype in (SFG_EDGE_KIND.STATE_INCLUSION, SFG_EDGE_KIND.INDIRECT_STATE_INCLUSION,
                                     SFG_EDGE_KIND.STATE_COPY):
                            visited.add(v)
                            worklist.append(v)
                            break

            elif u.node_type == SFG_NODE_KIND.STMT:
                # 1. 语句定义的变量受到污染
                for v in self.sfg.successors(u):
                    if v in visited: continue
                    edge_data = self.sfg.get_edge_data(u, v)
                    if not edge_data: continue
                    for data in edge_data.values():
                        if data.edge_type == SFG_EDGE_KIND.SYMBOL_IS_DEFINED:
                            visited.add(v)
                            worklist.append(v)
                            break
        return visited

    def get_all_backward_nodes(self, sink_symbol):
        """
        从 sink 的 symbol 开始，逆着 def_use 链遍历 SFG，返回所有与 sink symbol 有关的 symbol、stmt 节点。
        """
        if sink_symbol.node_type != SFG_NODE_KIND.SYMBOL:
            return set()

        worklist = deque([sink_symbol])
        visited = {sink_symbol}

        while worklist:
            u = worklist.popleft()

            # 逆着数据流方向查找前驱
            for v in self.sfg.predecessors(u):
                if v in visited: continue
                edge_data = self.sfg.get_edge_data(v, u)
                if not edge_data: continue

                is_related = False
                for data in edge_data.values():
                    etype = data.edge_type
                    if u.node_type == SFG_NODE_KIND.SYMBOL:
                        # SYMBOL 是被谁定义的 (STMT -> SYMBOL) 或 从哪个 SYMBOL 流过来的 (SYMBOL -> SYMBOL)
                        if etype in (SFG_EDGE_KIND.SYMBOL_IS_DEFINED,
                                     SFG_EDGE_KIND.SYMBOL_FLOW, SFG_EDGE_KIND.INDIRECT_SYMBOL_FLOW):
                            is_related = True
                    elif u.node_type == SFG_NODE_KIND.STMT:
                        # STMT 使用了哪个 SYMBOL (SYMBOL -> STMT)
                        if etype == SFG_EDGE_KIND.SYMBOL_IS_USED:
                            is_related = True

                    if is_related:
                        # 后向遍历仅关注 SYMBOL 和 STMT
                        if v.node_type in (SFG_NODE_KIND.SYMBOL, SFG_NODE_KIND.STMT):
                            visited.add(v)
                            worklist.append(v)
                        break
        return visited

    def print_and_write_flows(self, flows):
        print(f"Found {len(flows)} taint flows.")
        flow_json = []
        # 打印所有的污点流
        for each_flow in flows:
            source_stmt = self.loader.get_stmt_gir(each_flow.source_stmt_id)
            source_gir = get_gir_str(source_stmt)
            source_method_id = self.loader.convert_stmt_id_to_method_id(each_flow.source_stmt_id)
            source_method_name = self.loader.convert_method_id_to_method_name(source_method_id)

            sink_stmt = self.loader.get_stmt_gir(each_flow.sink_stmt_id)
            sink_gir = get_gir_str(sink_stmt)
            sink_line_no = int(sink_stmt.start_row)
            source_line_no = int(source_stmt.start_row)

            source_unit_id = self.loader.convert_stmt_id_to_unit_id(each_flow.source_stmt_id)
            source_file_path = self.loader.convert_unit_id_to_unit_path(source_unit_id)
            sink_unit_id = self.loader.convert_stmt_id_to_unit_id(each_flow.sink_stmt_id)
            sink_file_path = self.loader.convert_unit_id_to_unit_path(sink_unit_id)

            print(f"Found a flow to sink {sink_gir} on line {sink_line_no + 1}")
            print("\tSource :", source_gir, f"(in {source_method_name})")

            line_no = -1
            path_parent_source_node_list = []
            path_parent_source_file_node_list = []
            for node in reversed(each_flow.parent_to_source):
                stmt_id = node.def_stmt_id
                stmt = self.loader.get_stmt_gir(stmt_id)
                if stmt.start_row == line_no:
                    continue
                line_no = stmt.start_row
                gir_str = get_gir_str(stmt)

                method_id = self.loader.convert_stmt_id_to_method_id(stmt_id)
                method_name = self.loader.convert_method_id_to_method_name(method_id)
                path_node = "(" + gir_str + ")" + " on line " + str(int(line_no) + 1)
                unit_id = self.loader.convert_stmt_id_to_unit_id(stmt_id)
                file_path = self.loader.convert_unit_id_to_unit_path(unit_id)
                path_node_in_file = {
                    "start_line": int(stmt.start_row + 1),
                    "end_line": int(stmt.end_row + 1),
                    "file_path": file_path,
                    "gir": gir_str,
                    "stmt_id": int(stmt_id),
                }
                path_parent_source_node_list.append(path_node)
                path_parent_source_file_node_list.append(path_node_in_file)

            line_no = -1
            path_parent_sink_node_list = []
            path_parent_sink_file_node_list = []
            for node in each_flow.parent_to_sink:
                stmt_id = node.def_stmt_id
                stmt = self.loader.get_stmt_gir(stmt_id)
                if stmt.start_row == line_no:
                    continue
                line_no = stmt.start_row
                gir_str = get_gir_str(stmt)

                method_id = self.loader.convert_stmt_id_to_method_id(stmt_id)
                method_name = self.loader.convert_method_id_to_method_name(method_id)
                path_node = "(" + gir_str + ")" + " on line " + str(int(line_no) + 1)
                unit_id = self.loader.convert_stmt_id_to_unit_id(stmt_id)
                file_path = self.loader.convert_unit_id_to_unit_path(unit_id)
                path_node_in_file = {
                    "start_line": int(stmt.start_row + 1),
                    "end_line": int(stmt.end_row + 1),
                    "file_path": file_path,
                    "gir": gir_str,
                    "stmt_id": int(stmt_id),
                }
                path_parent_sink_node_list.append(path_node)
                path_parent_sink_file_node_list.append(path_node_in_file)

            if not self.is_sublist(path_parent_source_node_list, path_parent_sink_node_list):
                path_parent_sink_node_list = path_parent_source_node_list + path_parent_sink_node_list
            if not self.is_sublist(path_parent_source_file_node_list, path_parent_sink_file_node_list):
                path_parent_sink_file_node_list = path_parent_source_file_node_list + path_parent_sink_file_node_list
            print("\t\tData Flow:", path_parent_sink_node_list)

            flow_json.append({
                "source_stmt_id": int(each_flow.source_stmt_id),
                "sink_stmt_id": int(each_flow.sink_stmt_id),
                "source": source_gir,
                "sink": sink_gir,
                "source_line": source_line_no + 1,
                "sink_line": sink_line_no + 1,
                "source_file_path": source_file_path,
                "sink_file_path": sink_file_path,
                "data_flow": path_parent_sink_file_node_list,
                "vuln_type": each_flow.vuln_type,
            })

        output_dir = os.path.join(self.options.workspace, config.TAINT_OUTPUT_DIR)
        os.makedirs(output_dir, exist_ok=True)
        output_file = os.path.join(output_dir, "taint_data_flow.json")
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(flow_json, f, ensure_ascii=False, indent=2)
        print(f"Wrote taint data flows to {output_file}")

    def is_sublist(self, sub, lst):
        return str(sub)[1:-1] in str(lst)[1:-1]

    def run(self):
        if not self.options.quiet:
            print("\n########### # Phase IV: Taint Analysis # ##########")

        all_flows = []
        for method_id in self.loader.get_all_method_ids():
            self.current_entry_point = method_id
            self.sfg = self.loader.get_global_sfg_by_entry_point(method_id)
            self._update_sfg(self.sfg)
            if not self.sfg:
                continue
            self.taint_manager = TaintEnv()
            sources = self.find_sources()
            sinks = self.find_sinks()
            # print(sources, sinks)
            # if len(sources) > 0:
            #     for source in sources:
            #         print(source.name)
            # if len(sinks) > 0:
            #     for sink in sinks:
            #         print(sink.line_no)
            # print("entry:", self.loader.convert_method_id_to_method_name(method_id), method_id)
            flows = self.find_flows(sources, sinks)
            all_flows.extend(flows)

        if len(all_flows) == 0:
            print("No taint flows found.")
        else:
            if not self.options.quiet:
                self.print_and_write_flows(all_flows)
        return self

