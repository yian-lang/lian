#!/usr/bin/env python3

import ast
import pdb
import pprint
import traceback
from datetime import datetime
from lian.util import util
from lian.config import config
from lian.config import type_table
from lian.config.constants import (
    LIAN_INTERNAL,
    STATE_TYPE_KIND,
    LIAN_SYMBOL_KIND,
    CALLEE_TYPE,
    BASIC_CALL_GRAPH_NODE_KIND
)
from lian.common_structs import (
    StmtStatus,
    Symbol,
    State,
    ComputeFrame,
    MethodInternalCallee,
    BasicCallGraph,
    SymbolDefNode,
    StateDefNode
)
from lian.util.loader import Loader
from lian.core.resolver import Resolver
from lian.basics.import_hierarchy import ImportHierarchy

class StmtDefUseAnalysis:
    def __init__(self, loader:Loader, resolver: Resolver, basic_call_graph: BasicCallGraph, compute_frame: ComputeFrame, import_analysis:ImportHierarchy, external_symbol_id_collection):
        self.loader: Loader = loader
        self.resolver: Resolver = resolver
        self.basic_call_graph: BasicCallGraph = basic_call_graph
        self.symbol_state_space = compute_frame.symbol_state_space
        self.stmt_id_to_status = compute_frame.stmt_id_to_status
        self.method_id = compute_frame.method_id
        self.unit_id = loader.convert_method_id_to_unit_id(self.method_id)
        self.unit_info = loader.convert_module_id_to_module_info(self.unit_id)
        self.frame = compute_frame
        self.callees = compute_frame.basic_callees
        self.tmp_variable_to_define = {}
        self.each_stmt_defined_states = set()
        self.unit_lang = self.loader.convert_unit_id_to_lang_name(self.unit_id)
        self.external_symbol_id_collection = external_symbol_id_collection

        self.import_hierarchy_analysis = import_analysis

        self.def_use_analysis_handlers = {
            "comment_stmt"                          : self.comment_stmt_def_use,
            "package_stmt"                          : self.package_stmt_def_use,
            "assign_stmt"                           : self.assign_stmt_def_use,
            "call_stmt"                             : self.call_stmt_def_use,
            "object_call_stmt"                      : self.object_call_def_use,
            "echo_stmt"                             : self.echo_stmt_def_use,
            "exit_stmt"                             : self.exit_stmt_def_use,
            "return_stmt"                           : self.return_stmt_def_use,
            "yield_stmt"                            : self.yield_stmt_def_use,
            "sync_stmt"                             : self.sync_stmt_def_use,
            "label_stmt"                            : self.label_stmt_def_use,
            "throw_stmt"                            : self.throw_stmt_def_use,
            "try_stmt"                              : self.try_stmt_def_use,
            "catch_stmt"                            : self.catch_stmt_def_use,
            "asm_stmt"                              : self.asm_stmt_def_use,
            "assert_stmt"                           : self.assert_stmt_def_use,
            "pass_stmt"                             : self.pass_stmt_def_use,
            "with_stmt"                             : self.with_stmt_def_use,
            "await_stmt"                            : self.await_stmt_def_use,
            "global_stmt"                           : self.global_stmt_def_use,
            "nonlocal_stmt"                         : self.nonlocal_stmt_def_use,
            "type_cast_stmt"                        : self.type_cast_stmt_def_use,
            "type_alias_decl"                       : self.type_alias_decl_def_use,
            "phi_stmt"                              : self.phi_stmt_def_use,
            "unsafe_block"                          : self.unsafe_block_stmt_def_use,
            "block"                                 : self.block_stmt_def_use,
            "block_start"                           : self.block_start_stmt_def_use,

            "import_stmt"                           : self.import_stmt_def_use,
            "from_import_stmt"                      : self.from_import_stmt_def_use,
            "export_stmt"                           : self.export_stmt_def_use,
            "require_stmt"                          : self.require_stmt_def_use,

            "if_stmt"                               : self.if_stmt_def_use,
            "dowhile_stmt"                          : self.dowhile_stmt_def_use,
            "while_stmt"                            : self.while_stmt_def_use,
            "for_stmt"                              : self.for_stmt_def_use,
            "forin_stmt"                            : self.forin_stmt_def_use,
            "for_value_stmt"                        : self.for_value_stmt_def_use,
            "switch_stmt"                           : self.switch_stmt_def_use,
            "case_stmt"                             : self.case_stmt_def_use,
            "default_stmt"                          : self.default_stmt_def_use,
            "switch_type_stmt"                      : self.switch_type_stmt_def_use,
            "break_stmt"                            : self.break_stmt_def_use,
            "continue_stmt"                         : self.continue_stmt_def_use,
            "goto_stmt"                             : self.goto_stmt_def_use,

            "namespace_decl"                        : self.namespace_decl_def_use,
            "class_decl"                            : self.class_decl_def_use,
            "record_decl"                           : self.record_decl_def_use,
            "interface_decl"                        : self.interface_decl_def_use,
            "enum_decl"                             : self.enum_decl_def_use,
            "struct_decl"                           : self.struct_decl_def_use,
            "enum_constants"                        : self.enum_constants_def_use,
            "annotation_type_decl"                  : self.annotation_type_decl_def_use,
            "annotation_type_elements_decl"         : self.annotation_type_elements_decl_def_use,

            "parameter_decl"                        : self.parameter_decl_def_use,
            "variable_decl"                         : self.variable_decl_def_use,
            "method_decl"                           : self.method_decl_def_use,
            "method_header"                         : self.method_decl_def_use,

            "new_array"                             : self.new_array_def_use,
            "new_object"                            : self.new_object_def_use,
            "new_record"                            : self.new_record_def_use,
            "new_set"                               : self.new_set_def_use,
            "new_struct"                            : self.new_struct_def_use,

            "addr_of"                               : self.addr_of_def_use,
            "mem_read"                              : self.mem_read_def_use,
            "mem_write"                             : self.mem_write_def_use,
            "array_write"                           : self.array_write_def_use,
            "array_read"                            : self.array_read_def_use,
            "array_insert"                          : self.array_insert_def_use,
            "array_append"                          : self.array_append_def_use,
            "array_extend"                          : self.array_extend_def_use,
            "record_write"                          : self.record_write_def_use,
            "record_extend"                         : self.record_extend_def_use,
            "field_write"                           : self.field_write_def_use,
            "field_read"                            : self.field_read_def_use,
            "field_addr"                            : self.field_addr_def_use,
            "slice_write"                           : self.slice_write_def_use,
            "slice_read"                            : self.slice_read_def_use,
            "del_stmt"                              : self.del_stmt_def_use,
            "unset_stmt"                            : self.unset_stmt_def_use,
        }

    def analyze_stmt(self, stmt_id, stmt):
        # util.debug(f"stmt:{stmt}")
        self.each_stmt_defined_states = set()
        handler = self.def_use_analysis_handlers.get(stmt.operation)
        util.debug(f"handler:{handler}")
        print(stmt.operation)
        if handler is not None:
            return handler(stmt_id, stmt)
        return self.empty_def_use(stmt_id, stmt)

    def add_status_with_symbol_id_sync(self, stmt_id, stmt, status: StmtStatus, is_decl_stmt = False, is_parameter_decl_stmt = False):
        frame = self.frame      # for shortcut
        self.stmt_id_to_status[stmt_id] = status
        defined_symbol_index = status.defined_symbol
        defined_symbol: Symbol = self.symbol_state_space[defined_symbol_index]
        status.defined_states = self.each_stmt_defined_states
        if isinstance(defined_symbol, Symbol):
            defined_symbol_name = defined_symbol.name
            if defined_symbol_name.startswith(LIAN_INTERNAL.VARIABLE_DECL_PREF):
                if defined_symbol_name not in self.tmp_variable_to_define:
                    self.tmp_variable_to_define[defined_symbol_name] = stmt_id

                defined_symbol.source_unit_id = self.unit_id
                defined_symbol.symbol_id = self.tmp_variable_to_define[defined_symbol_name]
                self.frame.method_def_use_summary.local_symbol_ids.add(defined_symbol.symbol_id)

            elif is_parameter_decl_stmt:
                defined_symbol.source_unit_id = self.unit_id
                defined_symbol.symbol_id = stmt_id

                if stmt_id not in frame.defined_symbols:
                    frame.defined_symbols[stmt_id] = set()
                frame.defined_symbols[stmt_id].add(stmt_id)

            elif is_decl_stmt:
                defined_symbol.source_unit_id = self.unit_id
                defined_symbol.symbol_id = stmt_id
                return

            elif defined_symbol_name == LIAN_INTERNAL.THIS:
                defined_symbol.source_unit_id = self.unit_id
                this_symbol_id = self.frame.method_def_use_summary.this_symbol_id
                if this_symbol_id == -1:
                    this_symbol_id = self.loader.assign_new_unique_negative_id()
                    self.frame.method_def_use_summary.this_symbol_id = this_symbol_id
                defined_symbol.symbol_id = this_symbol_id

            elif defined_symbol_name == LIAN_INTERNAL.OBJECT:
                defined_symbol.source_unit_id = self.unit_id
                defined_symbol.symbol_id = config.BUILTIN_OBJECT_SYMBOL_ID 

            elif stmt.operation in ["nonlocal_stmt", "global_stmt"]:
                if stmt.operation == "global_stmt":
                    source_info = self.resolver.resolve_symbol_source_decl(
                        self.unit_id, stmt_id, defined_symbol.name,
                        source_symbol_must_be_global = True
                    )
                else:
                    source_info = self.resolver.resolve_symbol_source_decl(
                        self.unit_id, stmt_id, defined_symbol.name,
                        source_symbol_must_be_global = False
                    )
                if util.is_available(source_info):
                    defined_symbol.source_unit_id = source_info.source_unit_id
                    defined_symbol.symbol_id = source_info.source_symbol_id

                # Finishing nonlocal and global statements
                return

            else:
                source_info = self.resolver.resolve_symbol_source_decl(
                    self.unit_id, stmt.stmt_id, defined_symbol.name
                )

                #print(f"@@@@ {stmt} {source_info}")
                if util.is_available(source_info):
                    defined_symbol.source_unit_id = source_info.source_unit_id
                    symbol_id = source_info.source_symbol_id
                    if symbol_id == stmt.stmt_id:
                        if defined_symbol.name in self.external_symbol_id_collection:
                            symbol_id = self.external_symbol_id_collection[defined_symbol.name]
                        else:
                            symbol_id = self.loader.assign_new_unique_negative_id()
                            self.external_symbol_id_collection[defined_symbol.name] = symbol_id
                    defined_symbol.symbol_id = symbol_id
                    if symbol_id not in frame.defined_symbols:
                        frame.defined_symbols[symbol_id] = set()
                    frame.defined_symbols[symbol_id].add(stmt_id)
                    if symbol_id not in self.frame.method_def_use_summary.local_symbol_ids:
                        self.frame.method_def_use_summary.defined_external_symbol_ids.add(symbol_id)
                source_info = None

        for used_symbol_index in status.used_symbols:
            used_symbol = self.symbol_state_space[used_symbol_index]
            if not isinstance(used_symbol, Symbol):
                continue
            if used_symbol.name == LIAN_INTERNAL.THIS:
                used_symbol.source_unit_id = self.unit_id
                this_symbol_id = self.frame.method_def_use_summary.this_symbol_id
                if this_symbol_id == -1:
                    this_symbol_id = self.loader.assign_new_unique_negative_id()
                    self.frame.method_def_use_summary.this_symbol_id = this_symbol_id
                used_symbol.symbol_id = this_symbol_id
                continue
            if used_symbol.name == LIAN_INTERNAL.OBJECT:
                used_symbol.source_unit_id = self.unit_id
                continue
            if used_symbol.name.startswith(LIAN_INTERNAL.VARIABLE_DECL_PREF):
                used_symbol.source_unit_id = self.unit_id
                used_symbol.symbol_id = self.tmp_variable_to_define.get(used_symbol.name, (-1))
                continue

            # check its performance
            source_info = self.resolver.resolve_symbol_source_decl(
                self.unit_id, stmt_id, used_symbol.name
            )
            #print("source_info:", source_info, self.unit_id, self.method_id, stmt_id, used_symbol, stmt)
            if util.is_available(source_info):
                if source_info.source_symbol_id == stmt_id or source_info.source_symbol_id < 0:
                    if used_symbol.name in self.external_symbol_id_collection:
                        source_info.source_symbol_id = self.external_symbol_id_collection[used_symbol.name]
                    else:
                        source_info.source_symbol_id = self.loader.assign_new_unique_negative_id()
                        self.external_symbol_id_collection[used_symbol.name] = source_info.source_symbol_id

                used_symbol.source_unit_id = source_info.source_unit_id
                symbol_id = source_info.source_symbol_id
                used_symbol.symbol_id = symbol_id
                if symbol_id not in frame.used_symbols:
                    frame.used_symbols[symbol_id] = set()
                frame.used_symbols[symbol_id].add(stmt_id)
                if symbol_id not in self.frame.method_def_use_summary.local_symbol_ids:
                    self.frame.method_def_use_summary.used_external_symbol_ids.add(symbol_id)
            source_info = None

    def create_symbol_and_add_space(self, stmt_id, name, default_data_type = ""):
        if util.is_empty(name):
            return -1

        item = Symbol(stmt_id = stmt_id, name = name, default_data_type = default_data_type)
        index = self.symbol_state_space.add(item)
        return index

    def adjust_constant_string(self, value):
        if (isinstance(value, str) and len(value) >= 2 and value[0] in ("'", '"')
            and value[-1] in ("'", '"') and value[0] == value[-1]
        ):
            return value[1:-1]
        return value

    def create_state_and_add_space(
        self, stmt_id, value, data_type = "", state_type = STATE_TYPE_KIND.REGULAR
    ):
        if util.is_empty(value):
            return -1

        if not data_type:
            #print("value: ", value)
            data_type = type_table.determine_constant_type(value)
        if data_type == LIAN_INTERNAL.STRING:
            value = self.adjust_constant_string(value)

        item = State(stmt_id = stmt_id, value = value, data_type = data_type, state_type = state_type)
        index = self.symbol_state_space.add(item)
        util.add_to_dict_with_default_set(
            self.frame.defined_states,
            item.state_id,
            StateDefNode(index=index, state_id=item.state_id, stmt_id=stmt_id)
        )
        return index

    def create_symbol_or_state_and_add_space(
            self, stmt_id, name, default_data_type = "", state_type = STATE_TYPE_KIND.REGULAR
    ):
        if util.is_empty(name):
            return -1

        if util.is_variable(name):
            return self.create_symbol_and_add_space(stmt_id, name, default_data_type)
        index = self.create_state_and_add_space(stmt_id, name, default_data_type, state_type)
        self.each_stmt_defined_states.add(index)
        return index

    def empty_def_use(self, stmt_id, stmt):
        self.stmt_id_to_status[stmt_id] = StmtStatus(stmt_id)

    def comment_stmt_def_use(self, stmt_id, stmt):
        self.empty_def_use(stmt_id, stmt)

    def package_stmt_def_use(self, stmt_id, stmt):
        used_symbol_list = []
        for symbol in [stmt.name]:
            if not util.isna(symbol):
                used_symbol_list.append(
                    self.create_state_and_add_space(stmt_id, symbol)
                )
            else:
                used_symbol_list.append(-1)

        self.add_status_with_symbol_id_sync(
            stmt_id, stmt, StmtStatus(stmt_id, used_symbols = used_symbol_list)
        )

    def assign_stmt_def_use(self, stmt_id, stmt):
        used_symbol_list = []
        for symbol in [stmt.operand, stmt.operand2]:
            if not util.isna(symbol):
                used_symbol_list.append(
                    self.create_symbol_or_state_and_add_space(stmt_id, symbol)
                )
            else:
                used_symbol_list.append(-1)

        defined_symbol = self.create_symbol_and_add_space(stmt_id, stmt.target)
        self.add_status_with_symbol_id_sync(
            stmt_id, 
            stmt,
            StmtStatus(
                stmt_id,
                defined_symbol = defined_symbol,
                used_symbols = used_symbol_list
            )
        )

    def analyze_and_save_call_stmt_args(self, stmt_id, stmt, positional_arg_index, args_list, status):
        positional_args = []
        packed_positional_args = []
        named_args = []
        packed_named_args = []
        # args_list = []
        if not util.isna(stmt.positional_args):
            positional_args = args_list[:positional_arg_index]
            # print(args_list[0])
        elif not util.isna(stmt.packed_positional_args):
            packed_named_args = args_list[0]
        # print(positional_args)
        if not util.isna(stmt.packed_named_args):
            packed_named_args = args_list[positional_arg_index:]
        elif not util.isna(stmt.named_args):
            named_args = args_list[positional_arg_index:]

        used_symbols = status.used_symbols
        arg_symbol_list = used_symbols[1:]
        if stmt.operation == "object_call_stmt":
            arg_symbol_list = used_symbols[2:]
        callee_name_symbol_index = used_symbols[0]
        callee_name_symbol = self.symbol_state_space[callee_name_symbol_index]

        positional_args_info = []
        packed_positional_args_info = []
        named_args_info = []
        packed_named_args_info = []
        #print("stmt", stmt)
        #print("positional_args", positional_args)
        #print("args_list", args_list)
        #print(stmt_id)
        if positional_args and len(arg_symbol_list) > 0:
            for index, arg in enumerate(positional_args):
                if index >= len(arg_symbol_list):
                    continue
                index =  arg_symbol_list[index]
                arg_symbol = self.symbol_state_space[index]
                if isinstance(arg_symbol, State):
                    positional_args_info.append({"state_id": arg_symbol.state_id, "value": arg_symbol.value})
                else:
                    positional_args_info.append({"symbol_id": arg_symbol.symbol_id, "name": arg_symbol.name})

        elif packed_positional_args and len(arg_symbol_list) > 0:
            index =  arg_symbol_list[0]
            arg_symbol = self.symbol_state_space[index]
            packed_positional_args_info.append({"symbol_id": arg_symbol.symbol_id, "name": arg_symbol.name})

        if named_args and len(arg_symbol_list) > 0:
            args_keys = sorted(ast.literal_eval(stmt.named_args).keys())

            named_symbol_list = arg_symbol_list[positional_arg_index:]
            if named_symbol_list:
                for index, arg in enumerate(named_args):
                    if index >= len(named_symbol_list):
                        break
                    space_index =  named_symbol_list[index]
                    arg_symbol = self.symbol_state_space[space_index]
                    if isinstance(arg_symbol, State):
                        named_args_info.append({"state_id": arg_symbol.state_id, "value": arg_symbol.value, "key": args_keys[index]})
                    else:
                        named_args_info.append({"symbol_id": arg_symbol.symbol_id, "name": arg_symbol.name, "key": args_keys[index]})
        elif packed_named_args:
            index = used_symbols[-1]
            arg_symbol = self.symbol_state_space[index]
            if isinstance(arg_symbol, Symbol):
                packed_named_args_info.append({"symbol_id": arg_symbol.symbol_id, "name": arg_symbol.name})

        defined_symbol = self.symbol_state_space[status.defined_symbol]

        callee_symbol_id = -1
        if isinstance(callee_name_symbol, Symbol):
            callee_symbol_id = callee_name_symbol.symbol_id
        elif isinstance(callee_name_symbol, State):
            callee_symbol_id = callee_name_symbol.state_id
        call_format = {
            "unit_id": self.unit_id,
            "method_id": self.method_id,
            "stmt_id": stmt_id,
            "target_name": stmt.target,
            "target_symbol_id": defined_symbol.symbol_id,
            "callee_name": stmt.name,
            "callee_symbol_id": callee_symbol_id,
            "positional_args": str(positional_args_info),
            "packed_positional_args": str(packed_positional_args_info),
            "packed_named_args": str(packed_named_args_info),
            "named_args": str(named_args_info)
            }
        self.loader.save_stmt_id_to_call_stmt_format(stmt_id, call_format)
    
    def _process_call_stmt(self, stmt_id, stmt, is_object_call=False):
        # 1. 解析参数列表
        args_list = []
        if not util.isna(stmt.positional_args):
            args_list = ast.literal_eval(stmt.positional_args)
        elif not util.isna(stmt.packed_positional_args):
            args_list = [stmt.packed_positional_args]

        positional_arg_index = len(args_list)

        if not util.isna(stmt.packed_named_args):
            args_list.append(stmt.packed_named_args)
        elif not util.isna(stmt.named_args):
            args_dict = ast.literal_eval(stmt.named_args)
            for key in sorted(args_dict.keys()):
                args_list.append(args_dict[key])

        # 2. 构建 used_symbol_list
        used_symbol_list = []
        if is_object_call:
            # object_call: [receiver, field, *args]
            stmt_symbol_list = [stmt.receiver_object, stmt.field, *args_list]
            for i, symbol in enumerate(stmt_symbol_list):
                if i == 1 and not util.isna(symbol):  # field 是字符串常量
                    used_symbol_list.append(
                        self.create_state_and_add_space(
                            stmt_id, value=symbol, data_type=LIAN_INTERNAL.STRING
                        )
                    )
                elif not util.isna(symbol):
                    used_symbol_list.append(
                        self.create_symbol_or_state_and_add_space(stmt_id, symbol)
                    )
        else:
            # call_stmt: [name, *args]
            if stmt.name is None:
                stmt.name = "unknown"
            stmt_symbol_list = [stmt.name, *args_list]
            for symbol in stmt_symbol_list:
                if not util.isna(symbol):
                    used_symbol_list.append(
                        self.create_symbol_or_state_and_add_space(stmt_id, symbol)
                    )

        # 3. 创建目标符号（返回值变量）
        defined_symbol = self.create_symbol_and_add_space(stmt_id, stmt.target)
        status = StmtStatus(
            stmt_id,
            defined_symbol=defined_symbol,
            used_symbols=used_symbol_list
        )
        self.add_status_with_symbol_id_sync(stmt_id, stmt, status)

        # 4. 保存调用格式信息
        self.analyze_and_save_call_stmt_args(stmt_id, stmt, positional_arg_index, args_list, status)

        # 5. 处理调用图（callee 分析）
        if not used_symbol_list:
            return

        call_name_symbol_index = used_symbol_list[0]  # ✅ 修正：两种调用都取索引0
        call_name_symbol = self.symbol_state_space[call_name_symbol_index]

        if isinstance(call_name_symbol, Symbol):
            if call_name_symbol.symbol_id == -1:  # ✅ 优化：先检查None
                # 无法解析的调用
                self.basic_call_graph.add_edge(self.method_id, BASIC_CALL_GRAPH_NODE_KIND.ERROR_METHOD)
                internal_callee = MethodInternalCallee(
                    self.method_id,
                    CALLEE_TYPE.ERROR_CALLEE,
                    stmt_id,
                )
                self.callees.add(internal_callee)
            else:
                if (
                    self.loader.is_method_decl(call_name_symbol.symbol_id) 
                    or self.loader.is_class_decl(call_name_symbol.symbol_id)
                ):
                    # 直接调用
                    self.basic_call_graph.add_edge(self.method_id, call_name_symbol.symbol_id, stmt_id)
                    internal_callee = MethodInternalCallee(
                        self.method_id,
                        CALLEE_TYPE.DIRECT_CALLEE,
                        stmt_id,
                        call_name_symbol.symbol_id,
                        call_name_symbol_index
                    )
                    self.callees.add(internal_callee)
                else:
                    # 动态调用
                    self.basic_call_graph.add_edge(self.method_id, BASIC_CALL_GRAPH_NODE_KIND.DYNAMIC_METHOD, stmt_id)
                    internal_callee = MethodInternalCallee(
                        self.method_id,
                        CALLEE_TYPE.DYNAMIC_CALLEE,
                        stmt_id,
                        call_name_symbol.symbol_id,
                        call_name_symbol_index
                    )
                    self.callees.add(internal_callee)

    def call_stmt_def_use(self, stmt_id, stmt):
        self._process_call_stmt(stmt_id, stmt, is_object_call=False)

    def object_call_def_use(self, stmt_id, stmt):
        self._process_call_stmt(stmt_id, stmt, is_object_call=True)

    def echo_stmt_def_use(self, stmt_id, stmt):
        used_symbol_list = []
        for symbol in [stmt.name]:
            if not util.isna(symbol):
                used_symbol_list.append(
                    self.create_symbol_or_state_and_add_space(stmt_id, symbol)
                )
            else:
                used_symbol_list.append(-1)

        self.add_status_with_symbol_id_sync(
            stmt_id, stmt, StmtStatus(stmt_id, used_symbols = used_symbol_list)
        )

    def exit_stmt_def_use(self, stmt_id, stmt):
        used_symbol_list = []
        for symbol in [stmt.name]:
            if not util.isna(symbol):
                used_symbol_list.append(
                    self.create_symbol_or_state_and_add_space(stmt_id, symbol)
                )
            else:
                used_symbol_list.append(-1)

        self.add_status_with_symbol_id_sync(
            stmt_id, stmt, StmtStatus(stmt_id, used_symbols = used_symbol_list)
        )

    def return_stmt_def_use(self, stmt_id, stmt):
        used_symbol_list = []
        for symbol in [stmt.name]:
            if not util.isna(symbol):
                used_symbol_list.append(
                    self.create_symbol_or_state_and_add_space(stmt_id, symbol)
                )
            else:
                used_symbol_list.append(-1)

        self.add_status_with_symbol_id_sync(
            stmt_id, 
            stmt,
            StmtStatus(
                stmt_id,
                # defined_symbol = defined_symbol,
                used_symbols = used_symbol_list
            )
        )

        if len(used_symbol_list) != 0:
            returned_symbol = self.symbol_state_space[used_symbol_list[0]]
            if returned_symbol is not None and isinstance(returned_symbol, Symbol):
                self.frame.method_def_use_summary.return_symbol_ids.add(returned_symbol.symbol_id)

    def yield_stmt_def_use(self, stmt_id, stmt):
        self.return_stmt_def_use(stmt_id, stmt)

    def sync_stmt_def_use(self, stmt_id, stmt):
        self.empty_def_use(stmt_id, stmt)

    def try_stmt_def_use(self, stmt_id, stmt):
        self.empty_def_use(stmt_id, stmt)

    def catch_stmt_def_use(self, stmt_id, stmt):
        self.empty_def_use(stmt_id, stmt)

    def label_stmt_def_use(self, stmt_id, stmt):
        self.empty_def_use(stmt_id, stmt)

    def asm_stmt_def_use(self, stmt_id, stmt):
        defined_symbol = self.create_symbol_or_state_and_add_space(stmt_id, stmt.target)
        self.add_status_with_symbol_id_sync(
            stmt_id, stmt, StmtStatus(stmt_id, defined_symbol = defined_symbol)
        )

    def assert_stmt_def_use(self, stmt_id, stmt):
        used_symbol_list = []
        for symbol in [stmt.condition]:
            if not util.isna(symbol):
                used_symbol_list.append(
                    self.create_symbol_or_state_and_add_space(stmt_id, symbol)
                )
            else:
                used_symbol_list.append(-1)

        self.add_status_with_symbol_id_sync(
            stmt_id, 
            stmt,
            StmtStatus(
                stmt_id,
                used_symbols = used_symbol_list,
            )
        )

    def pass_stmt_def_use(self, stmt_id, stmt):
        self.empty_def_use(stmt_id, stmt)

    def throw_stmt_def_use(self, stmt_id, stmt):
        used_symbol_list = []
        for symbol in [stmt.name]:
            if not util.isna(symbol):
                used_symbol_list.append(
                    self.create_symbol_or_state_and_add_space(stmt_id, symbol)
                )
            else:
                used_symbol_list.append(-1)

        self.add_status_with_symbol_id_sync(
            stmt_id, 
            stmt,
            StmtStatus(
                stmt_id,
                used_symbols = used_symbol_list,
            )
        )

    def with_stmt_def_use(self, stmt_id, stmt):
        self.empty_def_use(stmt_id, stmt)

    def await_stmt_def_use(self, stmt_id, stmt):
        self.empty_def_use(stmt_id, stmt)

    def global_stmt_def_use(self, stmt_id, stmt):
        defined_symbol = self.create_symbol_and_add_space(stmt_id, stmt.name)
        self.add_status_with_symbol_id_sync(
            stmt_id, 
            stmt,
            StmtStatus(
                stmt_id,
                defined_symbol = defined_symbol
            )
        )

    def nonlocal_stmt_def_use(self, stmt_id, stmt):
        self.global_stmt_def_use(stmt_id, stmt)

    def type_cast_stmt_def_use(self, stmt_id, stmt):
        used_symbol_list = []
        for symbol in [stmt.source]:
            if not util.isna(symbol):
                used_symbol_list.append(
                    self.create_symbol_or_state_and_add_space(stmt_id, symbol)
                )
            else:
                used_symbol_list.append(-1)

        defined_symbol = self.create_symbol_and_add_space(stmt_id, stmt.target, stmt.data_type)
        self.add_status_with_symbol_id_sync(
            stmt_id, 
            stmt,
            StmtStatus(
                stmt_id,
                defined_symbol = defined_symbol,
                used_symbols = used_symbol_list
            )
        )

    def type_alias_decl_def_use(self, stmt_id, stmt):
        used_symbol_list = []
        for symbol in [stmt.data_type]:
            if not util.isna(symbol):
                used_symbol_list.append(
                    self.create_symbol_or_state_and_add_space(stmt_id, symbol)
                )
            else:
                used_symbol_list.append(-1)

        defined_symbol = self.create_symbol_or_state_and_add_space(
            stmt_id, stmt.name, stmt.data_type,
        )
        status = StmtStatus(
            stmt_id,
            defined_symbol = defined_symbol,
            used_symbols = used_symbol_list
        )
        self.add_status_with_symbol_id_sync(stmt_id, stmt, status, is_decl_stmt = True)

    def phi_stmt_def_use(self, stmt_id, stmt):
        used_symbol_list = []
        for symbol in stmt.phi_values:
            if not util.isna(symbol):
                used_symbol_list.append(
                    self.create_symbol_or_state_and_add_space(stmt_id, symbol)
                )
            else:
                used_symbol_list.append(-1)

        defined_symbol = self.create_symbol_and_add_space(stmt_id, stmt.target, stmt.data_type)
        self.add_status_with_symbol_id_sync(
            stmt_id, 
            stmt,
            StmtStatus(
                stmt,
                defined_symbol = defined_symbol,
                used_symbols = used_symbol_list
            )
        )

    def unsafe_block_stmt_def_use(self, stmt_id, stmt):
        self.empty_def_use(stmt_id, stmt)

    def block_stmt_def_use(self, stmt_id, stmt):
        self.empty_def_use(stmt_id, stmt)

    def block_start_stmt_def_use(self, stmt_id, stmt):
        self.empty_def_use(stmt_id, stmt)

    def from_import_stmt_def_use(self, stmt_id, stmt):
        used_symbol_list = []
        for symbol in [stmt.name]:
            if not util.isna(symbol):
                used_symbol_list.append(
                    self.create_state_and_add_space(stmt_id, symbol)
                )
            else:
                used_symbol_list.append(-1)

        self.common_import_def_use(stmt_id, stmt, used_symbol_list)

    def import_stmt_def_use(self, stmt_id, stmt):
        # print("analyzing import_stmt_def_use")
        used_symbol_list = []
        for symbol in [stmt.name]:
            if not util.isna(symbol):
                used_symbol_list.append(
                    self.create_state_and_add_space(stmt_id, symbol)
                )
            else:
                used_symbol_list.append(-1)
        self.common_import_def_use(stmt_id, stmt, used_symbol_list)

    def common_import_def_use(self, stmt_id, stmt, used_symbol_list):
        alias = stmt.alias
        if util.is_empty(alias):
            alias = stmt.name

        name = stmt.name.split(".")[-1]

        defined_symbol_index = self.create_symbol_and_add_space(stmt_id, alias)
        status = StmtStatus(
            stmt_id,
            defined_symbol = defined_symbol_index,
            used_symbols = used_symbol_list
        )
        self.stmt_id_to_status[stmt_id] = status

        defined_symbol = self.symbol_state_space[defined_symbol_index]
        if defined_symbol is None:
            return
        result = self.import_hierarchy_analysis.analyze_import_stmt(self.unit_id, self.unit_info, stmt)

        found_flag = False
        for each_node in result:
            if each_node.symbol_name == name:
                defined_symbol.source_unit_id = self.loader.convert_stmt_id_to_unit_id(each_node.symbol_id)
                defined_symbol.symbol_id = each_node.symbol_id
                found_flag = True
                break

        if not found_flag and util.is_available(defined_symbol):
            defined_symbol.source_unit_id = self.unit_id
            defined_symbol.symbol_id = self.loader.assign_new_unique_negative_id()

    def export_stmt_def_use(self, stmt_id, stmt):
        target = stmt.alias
        if util.is_empty(target):
            target = stmt.name

        used_symbol_list = []
        for symbol in [stmt.name]:
            if not util.isna(symbol):
                used_symbol_list.append(
                    self.create_symbol_or_state_and_add_space(stmt_id, symbol)
                )
            else:
                used_symbol_list.append(-1)

        defined_symbol_index = self.create_symbol_and_add_space(stmt_id, target)
        status = StmtStatus(stmt_id, used_symbols = used_symbol_list)
        self.stmt_id_to_status[stmt_id] = status
        if defined_symbol_index != -1:
            status.defined_symbol = defined_symbol_index
            defined_symbol = self.symbol_state_space[defined_symbol_index]
            name_symbol = self.symbol_state_space[status.used_symbols[0]]
            if isinstance(name_symbol, Symbol) and isinstance(defined_symbol, Symbol):
                defined_symbol.source_unit_id = name_symbol.source_unit_id
                defined_symbol.symbol_id = name_symbol.symbol_id

    def require_stmt_def_use(self, stmt_id, stmt):
        used_symbol_list = []
        for symbol in [stmt.name]:
            if not util.isna(symbol):
                used_symbol_list.append(
                    self.create_symbol_or_state_and_add_space(stmt_id, symbol)
                )
            else:
                used_symbol_list.append(-1)

        defined_symbol = self.create_symbol_or_state_and_add_space(
            stmt_id, stmt.target, LIAN_INTERNAL.REQUIRED_MODULE
        )

        self.add_status_with_symbol_id_sync(
            stmt_id, 
            stmt,
            StmtStatus(
                stmt_id,
                defined_symbol = defined_symbol,
                used_symbols = used_symbol_list
            )
        )

    def if_stmt_def_use(self, stmt_id, stmt):
        used_symbol_list = []
        for symbol in [stmt.condition]:
            if not util.isna(symbol):
                used_symbol_list.append(
                    self.create_symbol_or_state_and_add_space(stmt_id, symbol)
                )
            else:
                used_symbol_list.append(-1)

        self.add_status_with_symbol_id_sync(
            stmt_id, 
            stmt,
            StmtStatus(
                stmt_id,
                used_symbols = used_symbol_list
            )
        )

    def dowhile_stmt_def_use(self, stmt_id, stmt):
        used_symbol_list = []
        for symbol in [stmt.condition]:
            if not util.isna(symbol):
                used_symbol_list.append(
                    self.create_symbol_or_state_and_add_space(stmt_id, symbol)
                )
            else:
                used_symbol_list.append(-1)

        self.add_status_with_symbol_id_sync(
            stmt_id, 
            stmt,
            StmtStatus(
                stmt_id,
                used_symbols = used_symbol_list
            )
        )

    def while_stmt_def_use(self, stmt_id, stmt):
        used_symbol_list = []
        for symbol in [stmt.condition]:
            if not util.isna(symbol):
                used_symbol_list.append(
                    self.create_symbol_or_state_and_add_space(stmt_id, symbol)
                )
            else:
                used_symbol_list.append(-1)

        self.add_status_with_symbol_id_sync(
            stmt_id, 
            stmt,
            StmtStatus(
                stmt_id,
                used_symbols = used_symbol_list
            )
        )

    def for_stmt_def_use(self, stmt_id, stmt):
        used_symbol_list = []
        for symbol in [stmt.condition]:
            if not util.isna(symbol):
                used_symbol_list.append(
                    self.create_symbol_or_state_and_add_space(stmt_id, symbol)
                )
            else:
                used_symbol_list.append(-1)

        self.add_status_with_symbol_id_sync(
            stmt_id, 
            stmt,
            StmtStatus(
                stmt_id,
                used_symbols = used_symbol_list
            )
        )

    def forin_stmt_def_use(self, stmt_id, stmt):
        used_symbol_list = []
        for symbol in [stmt.receiver]:
            if not util.isna(symbol):
                used_symbol_list.append(
                    self.create_symbol_or_state_and_add_space(stmt_id, symbol)
                )
            else:
                used_symbol_list.append(-1)

        defined_symbol = self.create_symbol_or_state_and_add_space(stmt_id, stmt.name)
        self.add_status_with_symbol_id_sync(
            stmt_id, 
            stmt,
            StmtStatus(
                stmt_id,
                defined_symbol = defined_symbol,
                used_symbols = used_symbol_list
            )
        )

    def for_value_stmt_def_use(self, stmt_id, stmt):
        used_symbol_list = []
        for symbol in [stmt.target]:
            if not util.isna(symbol):
                used_symbol_list.append(
                    self.create_symbol_or_state_and_add_space(stmt_id, symbol)
                )
            else:
                used_symbol_list.append(-1)

        defined_symbol = self.create_symbol_or_state_and_add_space(stmt_id, stmt.name)
        self.add_status_with_symbol_id_sync(
            stmt_id, 
            stmt,
            StmtStatus(
                stmt_id,
                defined_symbol = defined_symbol,
                used_symbols = used_symbol_list
            )
        )

    def switch_stmt_def_use(self, stmt_id, stmt):
        used_symbol_list = []
        for symbol in [stmt.condition]:
            if not util.isna(symbol):
                used_symbol_list.append(
                    self.create_symbol_or_state_and_add_space(stmt_id, symbol)
                )
            else:
                used_symbol_list.append(-1)

        self.add_status_with_symbol_id_sync(
            stmt_id, 
            stmt,
            StmtStatus(
                stmt_id,
                used_symbols = used_symbol_list
            )
        )

    def case_stmt_def_use(self, stmt_id, stmt):
        used_symbol_list = []
        for symbol in [stmt.condition]:
            if not util.isna(symbol):
                used_symbol_list.append(
                    self.create_symbol_or_state_and_add_space(stmt_id, symbol)
                )
            else:
                used_symbol_list.append(-1)

        defined_symbol = -1
        is_decl = False
        if util.is_available(stmt.name):
            defined_symbol = self.create_symbol_or_state_and_add_space(
                stmt_id, stmt.name, LIAN_INTERNAL.CASE_AS
            )
            is_decl = True

        self.add_status_with_symbol_id_sync(
            stmt_id, 
            stmt,
            StmtStatus(
                stmt_id,
                defined_symbol = defined_symbol,
                used_symbols = used_symbol_list
            ),
            is_decl_stmt = is_decl
        )

    def default_stmt_def_use(self, stmt_id, stmt):
        self.empty_def_use(stmt_id, stmt)

    def switch_type_stmt_def_use(self, stmt_id, stmt):
        self.empty_def_use(stmt_id, stmt)

    def break_stmt_def_use(self, stmt_id, stmt):
        self.empty_def_use(stmt_id, stmt)

    def continue_stmt_def_use(self, stmt_id, stmt):
        self.empty_def_use(stmt_id, stmt)

    def goto_stmt_def_use(self, stmt_id, stmt):
        self.empty_def_use(stmt_id, stmt)

    def namespace_decl_def_use(self, stmt_id, stmt):
        defined_symbol = self.create_symbol_or_state_and_add_space(
            stmt_id, stmt.name, LIAN_INTERNAL.NAMESPACE_DECL
        )

        self.add_status_with_symbol_id_sync(
            stmt_id, 
            stmt,
            StmtStatus(
                stmt_id,
                defined_symbol = defined_symbol
            ),
            is_decl_stmt = True
        )
        symbol = self.symbol_state_space[defined_symbol]
        self.frame.method_def_use_summary.local_symbol_ids.add(symbol.symbol_id)

    def struct_decl_def_use(self, stmt_id, stmt):
        self.class_decl_def_use(stmt_id, stmt)

    def class_decl_def_use(self, stmt_id, stmt):
        defined_symbol = self.create_symbol_or_state_and_add_space(
            stmt_id, stmt.name, LIAN_INTERNAL.CLASS_DECL
        )
        self.add_status_with_symbol_id_sync(
            stmt_id, 
            stmt,
            StmtStatus(
                stmt_id,
                defined_symbol = defined_symbol
            ),
            is_decl_stmt = True
        )
        symbol = self.symbol_state_space[defined_symbol]
        self.frame.method_def_use_summary.local_symbol_ids.add(symbol.symbol_id)

    def record_decl_def_use(self, stmt_id, stmt):
        self.class_decl_def_use(stmt_id, stmt)

    def interface_decl_def_use(self, stmt_id, stmt):
        self.class_decl_def_use(stmt_id, stmt)

    def enum_decl_def_use(self, stmt_id, stmt):
        self.empty_def_use(stmt_id, stmt)

    def enum_constants_def_use(self, stmt_id, stmt):
        self.empty_def_use(stmt_id, stmt)

    def annotation_type_decl_def_use(self, stmt_id, stmt):
        self.empty_def_use(stmt_id, stmt)

    def annotation_type_elements_decl_def_use(self, stmt_id, stmt):
        self.empty_def_use(stmt_id, stmt)

    def parameter_decl_def_use(self, stmt_id, stmt):
        used_symbol_list = []
        if not util.isna(stmt.default_value):
            used_symbol_list.append(
                self.create_symbol_or_state_and_add_space(stmt_id, stmt.default_value)
            )

        defined_symbol = self.create_symbol_or_state_and_add_space(
            stmt_id, stmt.name, stmt.data_type, state_type = STATE_TYPE_KIND.ANYTHING
        )
        status = StmtStatus(
            stmt_id,
            defined_symbol = defined_symbol,
            used_symbols = used_symbol_list
        )
        self.add_status_with_symbol_id_sync(stmt_id, stmt, status, is_decl_stmt = True, is_parameter_decl_stmt = True)

        defined_symbol = self.symbol_state_space[status.defined_symbol]
        default_value_symbol_id = -1
        if status.used_symbols:
            defalut_value_symbol = self.symbol_state_space[status.used_symbols[0]]
            if isinstance(defalut_value_symbol, Symbol):
                default_value_symbol_id = defalut_value_symbol.symbol_id
        if isinstance(defined_symbol, Symbol):
            self.frame.method_def_use_summary.parameter_symbol_ids.add((defined_symbol.symbol_id, default_value_symbol_id))
            self.frame.method_def_use_summary.local_symbol_ids.add(defined_symbol.symbol_id)

    def variable_decl_def_use(self, stmt_id, stmt):
        defined_symbol = self.create_symbol_or_state_and_add_space(
            stmt_id, stmt.name, stmt.data_type, state_type = STATE_TYPE_KIND.UNSOLVED
        )
        status = StmtStatus(
            stmt_id,
            defined_symbol = defined_symbol
        )
        self.add_status_with_symbol_id_sync(stmt_id, stmt, status, is_decl_stmt = True)
        if status.defined_symbol != -1:
            symbol = self.symbol_state_space[status.defined_symbol]
            if isinstance(symbol, Symbol):
                self.frame.method_def_use_summary.local_symbol_ids.add(symbol.symbol_id)

    def method_decl_def_use(self, stmt_id, stmt):
        # self.empty_def_use(stmt_id, stmt)
        defined_symbol = self.create_symbol_or_state_and_add_space(
            stmt_id, stmt.name, LIAN_INTERNAL.METHOD_DECL
        )
        self.add_status_with_symbol_id_sync(
            stmt_id, 
            stmt,
            StmtStatus(
                stmt_id,
                defined_symbol = defined_symbol
            ),
            is_decl_stmt = True
        )
        symbol = self.symbol_state_space[defined_symbol]
        if isinstance(symbol, Symbol):
            self.frame.method_def_use_summary.local_symbol_ids.add(symbol.symbol_id)

    def new_array_def_use(self, stmt_id, stmt):
        used_symbol_list = []
        for symbol in [stmt.data_type, stmt.length]:
            if not util.isna(symbol):
                used_symbol_list.append(
                    self.create_symbol_or_state_and_add_space(stmt_id, symbol)
                )
            else:
                used_symbol_list.append(-1)
        defined_symbol = self.create_symbol_or_state_and_add_space(stmt_id, stmt.target, stmt.data_type)
        self.add_status_with_symbol_id_sync(
            stmt_id, 
            stmt,
            StmtStatus(
                stmt_id,
                defined_symbol = defined_symbol,
                used_symbols=used_symbol_list,
                # default_data_type = stmt.data_type
            )
        )

    def new_object_def_use(self, stmt_id, stmt):
        args_list = []

        if not util.isna(stmt.positional_args):
            args_list = ast.literal_eval(stmt.positional_args)

        used_symbol_list = []

        if util.is_available(stmt.init_value):
            for symbol in [stmt.data_type, stmt.init_value]:
                if not util.isna(symbol):
                    used_symbol_list.append(
                        self.create_symbol_or_state_and_add_space(stmt_id, symbol)
                    )
                else:
                    used_symbol_list.append(-1)
        else:
            for symbol in [stmt.data_type, *args_list]:
                if not util.isna(symbol):
                    used_symbol_list.append(
                        self.create_symbol_or_state_and_add_space(stmt_id, symbol)
                    )
                else:
                    used_symbol_list.append(-1)

        defined_symbol = self.create_symbol_or_state_and_add_space(stmt_id, stmt.target, stmt.data_type)
        self.add_status_with_symbol_id_sync(
            stmt_id, 
            stmt,
            StmtStatus(
                stmt_id,
                defined_symbol = defined_symbol,
                # default_data_type = stmt.data_type
                used_symbols = used_symbol_list
            ),
            #is_decl_stmt = True
        )

        status = self.stmt_id_to_status[stmt_id]
        type_symbol = self.symbol_state_space[status.used_symbols[0]]
        if not (type_symbol and isinstance(type_symbol, Symbol)):
            return
        if self.loader.is_method_decl(type_symbol.symbol_id): # 处理java中构造函数和类名同名的情况
            method_id = type_symbol.symbol_id
            class_id = self.loader.convert_method_id_to_class_id(method_id)
            method_name = self.loader.convert_method_id_to_method_name(method_id)
            class_name = self.loader.convert_class_id_to_class_name(class_id)
            if method_name == class_name:
                type_symbol.symbol_id = class_id

    def new_record_def_use(self, stmt_id, stmt):
        defined_symbol = self.create_symbol_or_state_and_add_space(stmt_id, stmt.target, stmt.data_type)
        self.add_status_with_symbol_id_sync(
            stmt_id, 
            stmt,
            StmtStatus(
                stmt_id,
                defined_symbol = defined_symbol,
                # default_data_type = stmt.data_type
            )
        )

    def new_set_def_use(self, stmt_id, stmt):
        defined_symbol = self.create_symbol_or_state_and_add_space(stmt_id, stmt.target, stmt.data_type)
        self.add_status_with_symbol_id_sync(
            stmt_id, 
            stmt,
            StmtStatus(
                stmt_id,
                defined_symbol = defined_symbol,
                # default_data_type = stmt.data_type
            )
        )

    def new_struct_def_use(self, stmt_id, stmt):
        defined_symbol = self.create_symbol_or_state_and_add_space(stmt_id, stmt.target, stmt.data_type)
        self.add_status_with_symbol_id_sync(
            stmt_id, 
            stmt,
            StmtStatus(
                stmt_id,
                defined_symbol = defined_symbol,
                # default_data_type = stmt.data_type
            )
        )

    def addr_of_def_use(self, stmt_id, stmt):
        used_symbol_list = []
        for symbol in [stmt.source, stmt.array, stmt.index, stmt.receiver, stmt.field]:
            if not util.isna(symbol):
                used_symbol_list.append(
                    self.create_symbol_or_state_and_add_space(stmt_id, symbol)
                )
            else:
                used_symbol_list.append(-1)

        defined_symbol = self.create_symbol_or_state_and_add_space(stmt_id, stmt.target)
        self.add_status_with_symbol_id_sync(
            stmt_id, 
            stmt,
            StmtStatus(
                stmt_id,
                defined_symbol = defined_symbol,
                used_symbols = used_symbol_list
            )
        )

    def mem_read_def_use(self, stmt_id, stmt):
        used_symbol_list = []
        for symbol in [stmt.address]:
            if not util.isna(symbol):
                used_symbol_list.append(
                    self.create_symbol_or_state_and_add_space(stmt_id, symbol)
                )
            else:
                used_symbol_list.append(-1)

        defined_symbol = self.create_symbol_or_state_and_add_space(stmt_id, stmt.target, stmt.data_type)
        self.add_status_with_symbol_id_sync(
            stmt_id, 
            stmt,
            StmtStatus(
                stmt_id,
                defined_symbol = defined_symbol,
                used_symbols = used_symbol_list
            )
        )

    def mem_write_def_use(self, stmt_id, stmt):
        used_symbol_list = []
        for symbol in [stmt.address, stmt.source]:
            if not util.isna(symbol):
                used_symbol_list.append(
                    self.create_symbol_or_state_and_add_space(stmt_id, symbol)
                )
            else:
                used_symbol_list.append(-1)

        # defined_symbol = self.create_symbol_state_and_add_space(stmt_id, stmt.address)
        self.add_status_with_symbol_id_sync(
            stmt_id, 
            stmt,
            StmtStatus(
                stmt_id,
                # defined_symbol = defined_symbol,
                used_symbols = used_symbol_list
            )
        )
    def array_write_def_use(self, stmt_id, stmt):
        used_symbol_list = []
        for symbol in [stmt.array, stmt.index, stmt.source]:
            if not util.isna(symbol):
                used_symbol_list.append(
                    self.create_symbol_or_state_and_add_space(stmt_id, symbol)
                )
            else:
                used_symbol_list.append(-1)

        defined_symbol = self.create_symbol_and_add_space(
            stmt_id, stmt.array, default_data_type = util.read_stmt_field(stmt.data_type)
        )

        self.add_status_with_symbol_id_sync(
            stmt_id, 
            stmt,
            StmtStatus(
                stmt_id,
                defined_symbol = defined_symbol,
                used_symbols = used_symbol_list
            )
        )

    def array_read_def_use(self, stmt_id, stmt):
        used_symbol_list = []
        for symbol in [stmt.array, stmt.index]:
            if not util.isna(symbol):
                used_symbol_list.append(
                    self.create_symbol_or_state_and_add_space(stmt_id, symbol)
                )
            else:
                used_symbol_list.append(-1)

        defined_symbol = self.create_symbol_or_state_and_add_space(
            stmt_id, stmt.target, util.read_stmt_field(stmt.data_type)
        )

        self.add_status_with_symbol_id_sync(
            stmt_id, 
            stmt,
            StmtStatus(
                stmt_id,
                defined_symbol = defined_symbol,
                used_symbols = used_symbol_list
            )
        )

    def array_insert_def_use(self, stmt_id, stmt):
        used_symbol_list = []
        for symbol in [stmt.array, stmt.source, stmt.index]:
            if not util.isna(symbol):
                used_symbol_list.append(
                    self.create_symbol_or_state_and_add_space(stmt_id, symbol)
                )
            else:
                used_symbol_list.append(-1)

        defined_symbol = self.create_symbol_or_state_and_add_space(
            stmt_id, stmt.array, default_data_type = LIAN_INTERNAL.ARRAY
        )

        self.add_status_with_symbol_id_sync(
            stmt_id, 
            stmt,
            StmtStatus(
                stmt_id,
                # NOTE: No output
                defined_symbol = defined_symbol,
                used_symbols = used_symbol_list
            )
        )

    def array_append_def_use(self, stmt_id, stmt):
        used_symbol_list = []
        for symbol in [stmt.array, stmt.source]:
            if not util.isna(symbol):
                used_symbol_list.append(
                    self.create_symbol_or_state_and_add_space(stmt_id, symbol)
                )
            else:
                used_symbol_list.append(-1)

        defined_symbol = self.create_symbol_or_state_and_add_space(
            stmt_id, stmt.array, default_data_type = LIAN_INTERNAL.ARRAY
        )

        self.add_status_with_symbol_id_sync(
            stmt_id, 
            stmt,
            StmtStatus(
                stmt_id,
                # NOTE: No output
                defined_symbol = defined_symbol,
                used_symbols = used_symbol_list
            )
        )

    def array_extend_def_use(self, stmt_id, stmt):
        used_symbol_list = []
        for symbol in [stmt.array, stmt.source]:
            if not util.isna(symbol):
                used_symbol_list.append(
                    self.create_symbol_or_state_and_add_space(stmt_id, symbol)
                )
            else:
                used_symbol_list.append(-1)

        defined_symbol = self.create_symbol_or_state_and_add_space(
            stmt_id, stmt.array, default_data_type = LIAN_INTERNAL.ARRAY
        )

        self.add_status_with_symbol_id_sync(
            stmt_id, 
            stmt,
            StmtStatus(
                stmt_id,
                # NOTE: No output
                defined_symbol = defined_symbol,
                used_symbols = used_symbol_list
            )
        )

    def record_extend_def_use(self, stmt_id, stmt):
        used_symbol_list = []
        for symbol in [stmt.record, stmt.source]:
            if not util.isna(symbol):
                used_symbol_list.append(
                    self.create_symbol_or_state_and_add_space(stmt_id, symbol)
                )
            else:
                used_symbol_list.append(-1)

        defined_symbol = self.create_symbol_or_state_and_add_space(stmt_id, stmt.record)
        status = StmtStatus(
            stmt_id,
            defined_symbol = defined_symbol,
            used_symbols = used_symbol_list
        )
        # self.debug_status(status)
        self.add_status_with_symbol_id_sync(stmt_id, stmt, status)

    def record_write_def_use(self, stmt_id, stmt):
        used_symbol_list = []
        for symbol in [stmt.receiver_record, stmt.key, stmt.value]:
            if not util.isna(symbol):
                used_symbol_list.append(
                    self.create_symbol_or_state_and_add_space(stmt_id, symbol)
                )
            else:
                used_symbol_list.append(-1)

        defined_symbol = self.create_symbol_or_state_and_add_space(stmt_id, stmt.receiver_record)
        status = StmtStatus(
            stmt_id,
            defined_symbol = defined_symbol,
            used_symbols = used_symbol_list
        )
        # self.debug_status(status)
        self.add_status_with_symbol_id_sync(stmt_id, stmt, status)

    def field_write_def_use(self, stmt_id, stmt):
        used_symbol_list = []
        for symbol in [stmt.receiver_object]:
            if not util.isna(symbol):
                used_symbol_list.append(
                    self.create_symbol_or_state_and_add_space(stmt_id, symbol)
                )
            else:
                used_symbol_list.append(-1)

        field_name = util.read_stmt_field(stmt.field)
        used_symbol_list.append(
            self.create_state_and_add_space(
                stmt_id,
                value = field_name,
                data_type = LIAN_INTERNAL.STRING,
                # state_type=
        ))

        for symbol in [stmt.source]:
            if not util.isna(symbol):
                used_symbol_list.append(
                    self.create_symbol_or_state_and_add_space(stmt_id, symbol)
                )
            else:
                used_symbol_list.append(-1)

        defined_symbol = self.create_symbol_or_state_and_add_space(stmt_id, stmt.receiver_object)
        self.add_status_with_symbol_id_sync(
            stmt_id, 
            stmt,
            StmtStatus(
                stmt_id,
                defined_symbol = defined_symbol,
                field_name = field_name,
                used_symbols = used_symbol_list
            )
        )

    def field_read_def_use(self, stmt_id, stmt):
        used_symbol_list = []
        for symbol in [stmt.receiver_object]:
            if not util.isna(symbol):
                used_symbol_list.append(
                    self.create_symbol_or_state_and_add_space(stmt_id, symbol)
                )
            else:
                used_symbol_list.append(-1)

        field_name = util.read_stmt_field(stmt.field)
        used_symbol_list.append(
            self.create_state_and_add_space(
                stmt_id,
                value=field_name,
                data_type=LIAN_INTERNAL.STRING,
                # state_type=
        ))
        defined_symbol = self.create_symbol_or_state_and_add_space(stmt_id, stmt.target)
        self.add_status_with_symbol_id_sync(
            stmt_id, 
            stmt,
            StmtStatus(
                stmt_id,
                defined_symbol = defined_symbol,
                field_name = field_name,
                used_symbols = used_symbol_list
            )
        )

    def field_addr_def_use(self, stmt_id, stmt):
        used_symbol_list = []
        for symbol in [stmt.data_type, stmt.name]:
            if not util.isna(symbol):
                used_symbol_list.append(
                    self.create_symbol_or_state_and_add_space(stmt_id, symbol)
                )
            else:
                used_symbol_list.append(-1)

        defined_symbol = self.create_symbol_or_state_and_add_space(stmt_id, stmt.target)
        self.add_status_with_symbol_id_sync(
            stmt_id, 
            stmt,
            StmtStatus(
                stmt_id,
                defined_symbol = defined_symbol,
                used_symbols = used_symbol_list
            )
        )

    def slice_write_def_use(self, stmt_id, stmt):
        used_symbol_list = []
        for symbol in [stmt.array, stmt.source, stmt.start, stmt.end, stmt.step]:
            if not util.isna(symbol):
                used_symbol_list.append(
                    self.create_symbol_or_state_and_add_space(stmt_id, symbol)
                )
            else:
                used_symbol_list.append(-1)
        defined_symbol = self.create_symbol_or_state_and_add_space(stmt_id, stmt.array)
        self.add_status_with_symbol_id_sync(
            stmt_id, 
            stmt,
            StmtStatus(
                stmt_id,
                defined_symbol = defined_symbol,
                used_symbols = used_symbol_list
            )
        )

    def slice_read_def_use(self, stmt_id, stmt):
        used_symbol_list = []
        for symbol in [stmt.array, stmt.start, stmt.end, stmt.step]:
            if not util.isna(symbol):
                used_symbol_list.append(
                    self.create_symbol_or_state_and_add_space(stmt_id, symbol)
                )
            else:
                used_symbol_list.append(-1)
        defined_symbol = self.create_symbol_or_state_and_add_space(stmt_id, stmt.target, LIAN_INTERNAL.ARRAY)
        self.add_status_with_symbol_id_sync(
            stmt_id, 
            stmt,
            StmtStatus(
                stmt_id,
                defined_symbol = defined_symbol,
                used_symbols = used_symbol_list
            )
        )

    def unset_stmt_def_use(self, stmt_id, stmt):
        used_symbol_list = []
        for symbol in [stmt.name]:
            if not util.isna(symbol):
                used_symbol_list.append(
                    self.create_symbol_or_state_and_add_space(stmt_id, symbol)
                )
            else:
                used_symbol_list.append(-1)

        self.add_status_with_symbol_id_sync(
            stmt_id, 
            stmt,
            StmtStatus(
                stmt_id,
                used_symbols = used_symbol_list
            )
        )

    def del_stmt_def_use(self, stmt_id, stmt):
        used_symbol_list = []
        for symbol in [stmt.name]:
            if not util.isna(symbol):
                used_symbol_list.append(
                    self.create_symbol_or_state_and_add_space(stmt_id, symbol)
                )
            else:
                used_symbol_list.append(-1)

        self.add_status_with_symbol_id_sync(
            stmt_id, 
            stmt,
            StmtStatus(
                stmt_id,
                used_symbols = used_symbol_list,
            )
        )
