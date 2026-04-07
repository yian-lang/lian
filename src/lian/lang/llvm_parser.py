from tree_sitter import Node

from lian.config.constants import (
    LIAN_INTERNAL
)
from lian.lang import common_parser
from lian.util import util

class Parser(common_parser.Parser):
    def init(self):
        self.LLVM_PREFIX = "$"
        self.data_type_cache = util.LRUCache(1000)
        self.value_cache = util.LRUCache(1000)

        self.CONSTANTS_MAP = {
            "true"                              : LIAN_INTERNAL.TRUE,
            "false"                             : LIAN_INTERNAL.FALSE,
            "null"                              : LIAN_INTERNAL.NULL,
            "none"                              : LIAN_INTERNAL.NULL,
            "undef"                             : LIAN_INTERNAL.UNDEFINED,
            "ptr"                               : LIAN_INTERNAL.POINTER,

            "mul"                               : "*",
            "fmul"                              : "*",
            "srem"                              : "%",
            "urem"                              : "%",
            "frem"                              : "%",
            "sdiv"                              : "/",
            "udiv"                              : "/",
            "fdiv"                              : "/",
            "lshr"                              : ">>",
            "ashr"                              : ">>",
            "shl"                               : "<<",
            "and"                               : "&",
            "or"                                : "|",
            "xor"                               : "^",

            "add"                               : "+",
            "fadd"                              : "+",
            "sub"                               : "-",
            "fsub"                              : "-",

            'eq'                                : "==",
            'oeq'                               : "==",
            'ueq'                               : "==",
            'seq'                               : "==",
            'ne'                                : "!=",
            'one'                               : "!=",
            'une'                               : "!=",
            'sne'                               : "!=",
            'gt'                                : ">",
            'ogt'                               : ">",
            'ugt'                               : ">",
            'sgt'                               : ">",
            'ge'                                : ">=",
            'oge'                               : ">=",
            'uge'                               : ">=",
            'sge'                               : ">=",
            'lt'                                : "<",
            'olt'                               : "<",
            'ult'                               : "<",
            'slt'                               : "<",
            'le'                                : "<=",
            'ole'                               : "<=",
            'ule'                               : "<=",
            'sle'                               : "<=",
        }

        self.LITERAL_MAP = {
            "true"                              : self.regular_constants,
            "false"                             : self.regular_constants,
            "null"                              : self.regular_constants,
            "none"                              : self.regular_constants,
            "undef"                             : self.regular_constants,
            "ptr"                               : self.regular_constants,
            "global_var"                        : self.variable_literal,
            "local_var"                         : self.variable_literal,
            "var"                               : self.variable_literal,
            # "poison"                            : self.regular_literal,
            # "zeroinitializer"                   : self.regular_literal,
            "comdat_ref"                        : self.regular_literal,
            "summary_ref"                       : self.regular_literal,
            "number"                            : self.number_literal,
            "float"                             : self.float_literal,
            "string"                            : self.string,
            "cstring"                           : self.string,
            "bin_op_keyword"                    : self.keyword_literal,
            "type_keyword"                      : self.keyword_literal,
        }

        self.DECLARATION_HANDLER_MAP = {
            "declare"                           : self.empty,
            "define"                            : self.function_definition,
            "global_global"                     : self.global_global,
            "global_type"                       : self.global_type,
            "struct_type"                       : self.struct_type,
            "packed_struct_type"                : self.packed_struct_type,
            "array_type"                        : self.array_type,
            "vector_type"                       : self.vector_type,

            "type"                              : self.type_entry,
        }

        self.STATEMENT_HANDLER_MAP = {
            "argument"                          : self.parse_argument,
            "instruction"                       : self.instruction_entry,
            "instruction_unreachable"           : self.unreachable_stmt,
            "instruction_ret"                   : self.ret_stmt,
            "instruction_br"                    : self.br_stmt,
            "instruction_resume"                : self.resume_stmt,
            "instruction_freeze"                : self.freeze_stmt,
            "instruction_indirectbr"            : self.indirectbr_stmt,
            "instruction_extractelement"        : self.extractelement_stmt,
            "instruction_insertelement"         : self.insertelement_stmt,
            "instruction_select"                : self.select_stmt,
            "instruction_shufflevector"         : self.shufflevector_stmt,
            "instruction_fneg"                  : self.fneg_stmt,
            "instruction_bin_op"                : self.bin_op_stmt,
            "instruction_switch"                : self.switch_stmt,
            "instruction_cleanupret"            : self.cleanupret_stmt,
            "instruction_catchret"              : self.catchret_stmt,
            "instruction_catchswitch"           : self.catchswitch_stmt,
            "instruction_catchpad"              : self.catchpad_stmt,
            "instruction_call"                  : self.call0_stmt,
            "instruction_invoke"                : self.call1_stmt,
            "instruction_callbr"                : self.call2_stmt,
            "instruction_icmp"                  : self.cmp_stmt,
            "instruction_fcmp"                  : self.cmp_stmt,
            "instruction_cast"                  : self.cast_stmt,
            "instruction_va_arg"                : self.va_arg_stmt,
            "instruction_phi"                   : self.phi_stmt,
            # "instruction_landingpad"        : self.landingpad_stmt,
            "instruction_alloca"                : self.alloca_stmt,
            "instruction_load"                  : self.load_stmt,
            "instruction_store"                 : self.store_stmt,
            "instruction_cmpxchg"               : self.cmpxchg_stmt,
            "instruction_atomicrmw"             : self.atomicrmw_expr,
            "instruction_fence"                 : self.fence_stmt,
            "instruction_getelementptr"         : self.getelementptr_stmt,
            "instruction_extractvalue"          : self.extractvalue_stmt,
            "instruction_insertvalue"           : self.insertvalue_stmt,

            "constant_cast"                     : self.cast_stmt,
            "constant_getelementptr"            : self.getelementptr_stmt,
            "constant_select"                   : self.select_stmt,
            "constant_icmp"                     : self.cmp_stmt,
            "constant_fcmp"                     : self.cmp_stmt,
            "constant_extractelement"           : self.extractelement_stmt,
            "constant_insertelement"            : self.insertelement_stmt,
            "constant_shufflevector"            : self.shufflevector_stmt,
            "constant_extractvalue"             : self.extractvalue_stmt,
            "constant_insertvalue"              : self.insertvalue_stmt,
            "constant_fneg"                     : self.fneg_stmt,
            "constant_bin_op"                   : self.bin_op_stmt,

            "module_asm"                        : self.module_asm_stmt,
            "label"                             : self.label_stmt,
        }

        self.EXPRESSION_HANDLER_MAP = {
            "struct_value"                      : self.struct_value,
            "packed_struct_value"               : self.packed_struct_value,
            "array_value"                       : self.array_value,
            "vector_value"                      : self.vector_value,
            "constant_expr"                     : self.constant_expr_value,

            "value"                             : self.value_entry,

            "blockaddress"                      : self.empty,
            "target_definition"                 : self.empty,
            "param_or_return_attrs"             : self.empty,
            "comdat"                            : self.empty,
            "source_file_name"                  : self.empty,
            "alias"                             : self.empty,
            "ifunc"                             : self.empty,
            "summary_entry"                     : self.empty,
            "unnamed_attr_grp"                  : self.empty,
            "use_list_order"                    : self.empty,
            "use_list_order_bb"                 : self.empty

        }

    def empty(self, node, statements, replacement = []):
        pass

    def obtain_literal_handler(self, node: Node):
        return self.LITERAL_MAP.get(node.type, None)

    def check_declaration_handler(self, node: Node):
        return self.DECLARATION_HANDLER_MAP.get(node.type, None)

    def check_expression_handler(self, node_type):
        return self.EXPRESSION_HANDLER_MAP.get(node_type, None)

    def is_comment(self, node: Node):
        return node.type in ["line_comment", "block_comment"]

    def is_identifier(self, node: Node):
        return node.type == "identifier"

    def keyword_literal(self, node, statements, replacement):
        name = self.read_node_text(node)
        if name in self.CONSTANTS_MAP:
            return self.CONSTANTS_MAP[name]
        return name

    def variable_literal(self, node, statements, replacement):
        name = self.read_node_text(node)
        name = name.replace(".", "_")
        if name[1].isdigit():
            return "_" + name[1:]
        if name[0] in ["%", "@"]:
            return self.LLVM_PREFIX + name[1:]
        return name

    def regular_literal(self, node: Node, statements: list, replacement: list):
        return self.read_node_text(node)

    def regular_constants(self, node: Node, statements: list, replacement: list):
        content = self.read_node_text(node)
        if content in self.CONSTANTS_MAP:
            return self.CONSTANTS_MAP[content]
        return content

    def number_literal(self, node: Node, statements: list, replacement: list):
        value = self.read_node_text(node)
        value = self.common_eval(value)
        return str(value)

    def float_literal(self, node: Node, statements: list, replacement: list):
        value = self.read_node_text(node)
        value = self.common_eval(value)
        return str(value)

    def string(self, node: Node, statements: list, replacement: list):
        return self.read_node_text(node)

    def is_literal(self, node: Node):
        return self.obtain_literal_handler(node) is not None

    def literal(self, node: Node, statements: list, replacement):
        handler = self.obtain_literal_handler(node)
        return handler(node, statements, replacement)

    def parse_type_and_value(self, node: Node, statements: list) -> tuple[str, str]:
        shadow_type = self.parse_only_type(node, statements)
        shadow_value = self.parse_only_value(node, statements)
        return (shadow_type, shadow_value)

    def parse_only_type(self, node, statements):
        data_type = self.find_child_by_type(node, "type")
        if data_type:
            # a = self.read_node_text(data_type)
            # cached_data_type = self.data_type_cache.get(a)
            # if cached_data_type:
            #     return cached_data_type
            shadow_data_type = self.parse(data_type, statements)
            # self.data_type_cache.put(data_type, shadow_data_type)
            return shadow_data_type
        return ""

    def parse_only_value(self, node: Node, statements: list) -> tuple[str, str]:
        value = self.find_child_by_type(node, "value")
        if value:
            # a = self.read_node_text(value)
            # cached_value = self.value_cache.get(a)
            # if cached_value:
            #     return cached_value
            shadow_value = self.parse(value, statements)
            # self.value_cache.put(a, shadow_value)
            return shadow_value
        return ""

    def function_definition(self, node: Node, statements: list):
        decl = self.create_empty_node_with_init_list("attrs", "parameters", "body")

        header = self.find_child_by_type(node, "function_header")
        data_type = self.find_child_by_type(header, "type")
        if data_type:
            decl["data_type"] = self.read_node_text(data_type)

        name = self.find_child_by_field(header, "name")
        decl["name"] = self.parse(name, statements)

        parameters = self.find_child_by_field(header, "arguments")
        self.parse(parameters, decl["parameters"])

        body = self.find_child_by_field(node, "body")
        self.parse(body, decl["body"])
        self.append_stmts(statements, node, {"method_decl": decl})

    def is_declaration(self, node: Node):
        return self.check_declaration_handler(node) is not None

    def declaration(self, node: Node, statements: list):
        handler = self.check_declaration_handler(node)
        return handler(node, statements)

    def module_asm_stmt(self, node: Node, statements: list):
        asm = self.find_child_by_type(node, "asm")
        if asm:
            data = self.read_node_text(asm)
            self.append_stmts(statements, node, {"asm_stmt": {"attrs": ["module"], "data": data}})

    def global_global(self, node: Node, statements: list):
        variable_node = self.find_child_by_type(node, "global_var")
        shadow_variable = self.parse(variable_node, statements)

        if len(shadow_variable) == 0:
            return

        type_and_value = self.find_child_by_type(node, "type_and_value")
        if not type_and_value:
            return

        type_node = self.find_child_by_type(type_and_value, "type")
        raw_type = self.read_node_text(type_node)

        shadow_type, shadow_value = self.parse_type_and_value(type_and_value, statements)


        if raw_type.startswith("%struct."):
            counter = -1
            while counter > -len(statements):
                stmt = statements[counter]
                if "field_write" in stmt:
                    if stmt["field_write"]["receiver_object"] == shadow_value:
                        stmt["field_write"]["receiver_object"] = shadow_variable
                elif "new_object" in stmt:
                    if stmt["new_object"]["target"] == shadow_value:
                        statements[counter] = {
                            "variable_decl": {
                                "data_type": shadow_type,
                                "name": shadow_variable
                            }
                        }
                        return
                counter-=1

        # # The following code is too slow
        # elif raw_type.startswith("["):
        #     counter = -1
        #     while counter > -len(statements):
        #         stmt = statements[counter]
        #         if "array_write" in stmt:
        #             if stmt["array_write"]["array"] == shadow_value:
        #                 stmt["array_write"]["array"] = shadow_variable
        #         elif "new_array" in stmt:
        #             if stmt["new_array"]["target"] == shadow_value:
        #                 statements[counter] = {
        #                     "variable_decl": {
        #                         "attrs": [LianInternal.ARRAY],
        #                         "data_type": f"{shadow_type}[]",
        #                         "name": shadow_variable
        #                     }
        #                 }
        #                 return
        #         counter-=1

        attrs = []
        if "[" in shadow_type:
            attrs.append(LIAN_INTERNAL.ARRAY)
        if "*" in shadow_type:
            attrs.append(LIAN_INTERNAL.POINTER)

        self.append_stmts(statements, node, {
            "variable_decl": {
                "attrs": attrs,
                "data_type": shadow_type,
                "name": shadow_variable
            }
        })

        if shadow_value:
            self.append_stmts(statements, node, {
                "assign_stmt": {
                    "target": shadow_variable,
                    "operand": shadow_value
                }
            })

        return shadow_variable

    def struct_type(self, node, statements):
        class_name = self.tmp_class()
        class_decl = self.create_empty_node_with_init_list("fields", "attrs")
        class_decl["name"] = class_name

        counter = 0

        body = self.find_child_by_type(node, "struct_body")
        if not body:
            return ""
        for each_child in body.named_children:
            if each_child.type != "type":
                continue

            raw_type = self.read_node_text(each_child)
            type_name = self.parse(each_child.children[0], statements)
            attrs = []
            if "[" in raw_type:
                attrs.append(LIAN_INTERNAL.ARRAY)
                type_name += "[]"
            if "*" in raw_type:
                attrs.append(LIAN_INTERNAL.POINTER)
                type_name += "*"
            class_decl["fields"].append({
                "variable_decl" : {
                    "attrs": attrs,
                    "data_type": type_name,
                    "name": f"_{counter}"
                }
            })
            counter += 1

        self.append_stmts(statements, node, {"struct_decl": class_decl})
        return class_name

    def packed_struct_type(self, node, statements):
        # class_name = self.struct_type(node, statements)
        # if len(statements) == 0:
        #     return class_name
        # new_node = statements[-1]
        # new_node["attrs"].append("packed_struct")

        # return class_name
        return self.struct_type(node, statements)

    def array_type(self, node, statements):
        body = self.find_child_by_type(node, "array_vector_body")
        if body is None:
            return

        number = self.find_child_by_type(body, "number")
        shadow_number = self.parse(number, statements)

        type_node = self.find_child_by_type(body, "type")
        shadow_type = self.parse(type_node, statements)

        type_name = ""
        brace_index = shadow_type.find("[")
        if brace_index == -1:
            type_name = f"{shadow_type}[{shadow_number}]"
        else:
            type_name = f"{shadow_type[:brace_index]}[{shadow_number}]{shadow_type[brace_index:]}"

        if "vscale" in node.children:
            type_name += "[]"

        return type_name

    def vector_type(self, node, statements):
        return self.array_type(node, statements)

    def global_type(self, node: Node, statements: list):
        name = self.find_child_by_type(node, "local_var")
        data_type = self.find_child_by_type(node, "type")

        shadow_name = self.parse(name, statements)
        shadow_type = self.parse(data_type, statements)

        if len(statements) == 0:
            return

        last_node = statements[-1]
        if last_node:
            if "struct_decl" in last_node:
                last_node["struct_decl"]["name"] = shadow_name
                return

            self.append_stmts(statements, node, {"type_alias_decl": {"name": shadow_name, "data_type": shadow_type}})

    def type_entry(self, node: Node, statements: list):
        type_node = node.children[0]
        shadow_type = self.parse(type_node, statements)


        raw_data = self.read_node_text(node)
        if "*" in raw_data:
            if "**" in raw_data:
                return shadow_type + "**"
            return shadow_type + "*"

        # if "[" in raw_data:
        #     return shadow_type + "[]"
        return shadow_type

    def check_statement_handler(self, node: Node):
        return self.STATEMENT_HANDLER_MAP.get(node.type, None)

    def is_statement(self, node: Node):
        return self.check_statement_handler(node) is not None

    def statement(self, node: Node, statements: list):
        handler = self.check_statement_handler(node)
        return handler(node, statements)

    def parse_type(self, node, statements) -> str:
        type_node = node.named_children[0]
        self.parse(type_node, statements)

    def value_entry(self, node, statements):
        if node.named_child_count == 0:
            content = self.read_node_text(node)
            return self.CONSTANTS_MAP.get(content, content)

        var = self.find_child_by_type(node, "var")
        if var:
            return self.parse(var, statements)

        return self.parse(node.named_children[0], statements)

    def struct_value(self, node, statements):
        operands = self.find_children_by_type(node, "type_and_value")
        if not operands:
            return

        struct_name = self.tmp_variable()
        self.append_stmts(statements, node, {"new_object": {"target": struct_name, "data_type": LIAN_INTERNAL.UNDEFINED}})

        counter = 0
        for each_operand in operands:
            shadow_type, shadow_value = self.parse_type_and_value(each_operand, statements)
            self.append_stmts(statements, node, {"field_write": {"receiver_object": struct_name, "field": f"_{counter}", "source": shadow_value}})

            counter += 1

        return struct_name

    def packed_struct_value(self, node, statements):
        struct_name = self.struct_value(node, statements)
        if struct_name:
            counter = -1
            while counter > -len(statements):
                stmt = statements[counter]
                if "new_object" in stmt:
                    if stmt["new_object"]["target"] == struct_name:
                        stmt["new_object"]["attrs"] = ["packed_struct"]
                        break
                counter-=1
        return struct_name

    def array_value(self, node, statements):
        operands = self.find_children_by_type(node, "type_and_value")
        if not operands:
            return

        array_name = self.tmp_variable()
        self.append_stmts(statements, node, {"new_array": {"target": array_name, "data_type": LIAN_INTERNAL.UNDEFINED}})

        counter = 0
        for each_operand in operands:
            shadow_type, shadow_value = self.parse_type_and_value(each_operand, statements)
            self.append_stmts(statements, node, {"array_write": {"array": array_name, "index": str(counter), "source": shadow_value}})
            counter += 1
        return array_name

    def vector_value(self, node, statements):
        return self.array_value(node, statements)

    def constant_expr_value(self, node, statements):
        return self.parse(node.children[0], statements)

    def parse_argument(self, argument: Node, statements: list):
        type_node = argument.children[0]
        if type_node.type != "type":
            return

        shadow_type = self.parse(type_node, statements)

        attrs = []
        if "*" in shadow_type:
            attrs.append(LIAN_INTERNAL.POINTER)
        elif "[" in shadow_type:
            attrs.append(LIAN_INTERNAL.ARRAY)

        value = self.find_child_by_type(argument, "value")
        shadow_value = self.parse(value, statements)
        self.append_stmts(statements, argument, {"parameter_decl": {"attrs": attrs, "data_type": shadow_type, "name": shadow_value}})

    def instruction_entry(self, node: Node, statements: list):
        left = self.find_child_by_type(node, "local_var")
        shadow_left = self.parse(left, statements)

        right = None
        for each_node in node.children:
            if each_node.type.startswith("instruction_"):
                right = each_node
                break
        if not right:
            return

        shadow_right = self.parse(right, statements)
        if shadow_left and shadow_right:
            self.append_stmts(statements, node, {"assign_stmt": {"target": shadow_left, "operand": shadow_right}})

    def unreachable_stmt(self, node: Node, statements: list):
        # self.append_stmts(statements, node, {"unreachable_stmt": {"target": ""}})
        pass

    def ret_stmt(self, node: Node, statements: list):
        type_and_value = self.find_child_by_type(node, "type_and_value")

        value = self.parse_only_value(type_and_value, statements)
        self.append_stmts(statements, node, {"return_stmt": {"name": value}})

        return value

    def br_stmt(self, node: Node, statements: list):
        type_and_values = self.find_children_by_type(node, "type_and_value")

        if len(type_and_values) == 1:
            target = self.parse_only_value(type_and_values[0], statements)
            self.append_stmts(statements, node, {"goto_stmt": {"name": target}})

        if len(type_and_values) < 3:
            return

        condition_part  = type_and_values[0]
        true_part = type_and_values[1]
        false_part = type_and_values[2]

        true_body = []
        false_body = []
        shadow_condition = self.parse_only_value(condition_part, statements)
        shadow_true_part = self.parse_only_value(true_part, true_body)
        shadow_false_part = self.parse_only_value(false_part, false_body)

        self.append_stmts(statements, node, {
            "if_stmt": {
                "condition": shadow_condition,
                "then_body": [{"goto_stmt": {"name": shadow_true_part}}],
                "else_body": [{"goto_stmt": {"name": shadow_false_part}}]
            }
        })

    def switch_stmt(self, node: Node, statements: list):
        type_and_values = self.find_children_by_type(node, "type_and_value")

        condition_part = type_and_values[0]
        condition = self.parse_only_value(condition_part, statements)

        default_part = type_and_values[1]
        default = self.parse_only_value(default_part, statements)

        switch_body = []
        self.append_stmts(statements, node, {"switch_stmt": {"condition": condition, "body": switch_body}})

        counter = 2
        while counter + 1  < len(type_and_values):
            case_condition = type_and_values[counter]
            shadow_case_condition = self.parse_only_value(case_condition, statements)
            case_target = type_and_values[counter + 1]
            shadow_case_target = self.parse_only_value(case_target, statements)

            switch_body.append({
                "case_stmt": {
                    "condition": shadow_case_condition,
                    "body": [{"goto_stmt": {"name": shadow_case_target}}]
                }
            })

            counter += 2

        switch_body.append({"default_stmt": {"body": [{"goto_stmt": {"name": default}}]}})

    def label_stmt(self, node, statements):
        name = self.read_node_text(node)
        if not name:
            return

        name = name.replace(".", "_")
        if name[0] in ["%", "@"]:
            name = self.LLVM_PREFIX + name[1:]
        name = "_" + name
        if name[-1] == ":":
            name = name[:-1]

        if name:
            self.append_stmts(statements, node, {
                "label_stmt": {
                    "name": name
                }
            })

    def resume_stmt(self, node: Node, statements: list):
        pass

    def freeze_stmt(self, node: Node, statements: list):
        pass

    def indirectbr_stmt(self, node: Node, statements: list):
        pass

    def extractelement_stmt(self, node: Node, statements: list):
        target = self.tmp_variable()
        type_and_values = self.find_children_by_type(node, "type_and_value")
        operand1 = self.parse_only_value(type_and_values[0], statements)
        operand2 = self.parse_only_value(type_and_values[1], statements)
        self.append_stmts(statements, node, {"array_read": {"target": target, "name": operand1, "index": operand2}})
        return target

    def insertelement_stmt(self, node: Node, statements: list):
        type_and_values = self.find_children_by_type(node, "type_and_value")
        type1, operand1 = self.parse_type_and_value(type_and_values[0], statements)
        operand2 = self.parse_only_value(type_and_values[1], statements)
        operand3 = self.parse_only_value(type_and_values[2], statements)
        if operand1:
            self.append_stmts(statements, node, {"array_insert": {"array": operand1, "index": operand3, "source": operand2}})
            return operand1

        target = self.tmp_variable()
        self.append_stmts(statements, node, {"new_array": {"target": target, "data_type": type1}})
        self.append_stmts(statements, node, {"array_insert": {"array": target, "index": operand3, "source": operand2}})
        return target

    def select_stmt(self, node: Node, statements: list):
        target = self.tmp_variable()
        type_and_values = self.find_children_by_type(node, "type_and_value")
        operand1 = self.parse_only_value(type_and_values[0], statements)
        operand2 = self.parse_only_value(type_and_values[1], statements)
        operand3 = self.parse_only_value(type_and_values[2], statements)
        self.append_stmts(statements, node, {
            "if_stmt" : {
                "condition" : operand1,
                "then_body": [{"assign_stmt": {"target": target, "operand": operand2}}],
                "else_body": [{"assign_stmt": {"target": target, "operand": operand3}}]
            }
        })
        return target

    def shufflevector_stmt(self, node: Node, statements: list):
        pass

    def fneg_stmt(self, node: Node, statements: list):
        target = self.tmp_variable()
        type_and_value = self.find_child_by_type(node, "type_and_value")
        operand = self.parse_only_value(type_and_value, statements)
        self.append_stmts(statements, node, {"assign_stmt": {"target": target, "operand": operand, "operator": "-"}})
        return target

    def bin_op_stmt(self, node: Node, statements: list):
        target = self.tmp_variable()
        inst_name = self.find_child_by_field(node, "inst_name")
        shadow_name = self.parse(inst_name, statements)

        type_and_value = self.find_child_by_type(node, "type_and_value")
        operand = self.parse_only_value(type_and_value, statements)
        value = self.find_child_by_type(node, "value")
        operand2 = self.parse(value, statements)
        self.append_stmts(statements, node, {"assign_stmt": {"target": target, "operator": shadow_name, "operand": operand, "operand2": operand2}})
        return target

    def cleanupret_stmt(self, node: Node, statements: list):
        pass

    def catchret_stmt(self, node: Node, statements: list):
        pass

    def catchswitch_stmt(self, node: Node, statements: list):
        pass

    def catchpad_stmt(self, node: Node, statements: list):
        pass

    def call0_stmt(self, node: Node, statements: list):
        args = self.find_child_by_field(node, "arguments")
        args_list = []
        if args and args.named_child_count > 0:
            for argument in args.named_children:
                type_node = argument.children[0]
                if type_node.type != "type":
                    continue

                value = self.find_child_by_type(argument, "value")
                shadow_value = self.parse(value, statements)
                args_list.append(shadow_value)

        target = self.tmp_variable()
        callee = self.find_child_by_field(node, "callee")

        data_type = self.find_child_by_type(node, "type")
        shadow_type = self.parse(data_type, statements)

        if callee.type == "inline_asm":
            data = self.find_child_by_type(callee, "asm")
            data_value = ""
            if data:
                data_value = self.read_node_text(data)
            extra = self.find_child_by_type(callee, "string")
            extra_value = ""
            if extra:
                extra_value = self.read_node_text(extra)
            self.append_stmts(statements, node, {
                "asm_stmt": {
                    "data_type": shadow_type,
                    "target": target,
                    "attrs": ["inline"],
                    "data": data_value,
                    "extra": extra_value,
                    "args": args_list,
                }
            })
            return target

        shadow_callee = self.parse(callee, statements)

        self.append_stmts(statements, node, {
            "call_stmt": {
                "target": target,
                "name": shadow_callee,
                "args": args_list,
                "data_type": shadow_type
            }
        })

        return target

    def call1_stmt(self, node: Node, statements: list):
        callee_name = self.call0_stmt(node, statements)
        if not callee_name:
            return

        try_body = []
        catch_body = []

        try_body.append(statements[-1])

        type_and_values = self.find_children_by_type(node, "type_and_value")
        normal_target = self.parse_only_value(type_and_values[0], try_body)
        exception_target = self.parse_only_value(type_and_values[1], catch_body)

        try_body.append({"goto_stmt": {"name": normal_target}})
        catch_body.append({"goto_stmt": {"name": exception_target}})

        statements[-1] = {
            "try_stmt": {
                "body": try_body,
                "catch_body": catch_body
            }
        }

        return callee_name

    def call2_stmt(self, node: Node, statements: list):
        callee_name = self.call0_stmt(node, statements)

        # true_body = []
        # false_body = []

        # type_and_values = self.find_children_by_type(node, "type_and_value")
        # true_target = type_and_values[0]
        # shadow_true_part = self.parse_only_value(true_target, true_body)
        # true_body.append({"goto_stmt": {"name": shadow_true_part}})

        # false_target = type_and_values[1]
        # shadow_false_part = self.parse_only_value(false_target, false_body)
        # false_body.append({"goto_stmt": {"name": shadow_false_part}})

        # self.append_stmts(statements, node, {
        #     "if_stmt": {
        #         "condition": target,
        #         "then_body": true_body,
        #         "else_body": false_body
        #     }
        # })

        return callee_name

    def cmp_stmt(self, node: Node, statements: list):
        target = self.tmp_variable()

        operator = ""
        icmp_cond = self.find_child_by_type(node, "icmp_cond")
        fcmp_cond = self.find_child_by_type(node, "fcmp_cond")
        if icmp_cond:
            operator = self.read_node_text(icmp_cond)
        else:
            operator = self.read_node_text(fcmp_cond)

        tvs = self.find_children_by_type(node, "type_and_value")

        operand1_value = self.parse_only_value(tvs[0], statements)

        operand2_value = None
        if len(tvs) > 1:
            operand2_value = self.parse_only_value(tvs[1], statements)
        else:
            operand2_tv = self.find_child_by_type(node, "value")
            operand2_value = self.parse(operand2_tv, statements)

        if operand2_value is None:
            return

        if operator in self.CONSTANTS_MAP:
            operator = self.CONSTANTS_MAP[operator]
        else:
            if operator == "false":
                return LIAN_INTERNAL.FALSE
            if operator == "true":
                return LIAN_INTERNAL.TRUE
            if operator == "nrd":
                pass
            if operator == "uno":
                pass
            return target

        self.append_stmts(statements, node, {
            "assign_stmt": {
                "target": target,
                "operand": operand1_value,
                "operator": operator,
                "operand2": operand2_value
            }
        })

        return target

    def cast_stmt(self, node: Node, statements: list):
        target = self.tmp_variable()

        action = self.find_child_by_field(node, "inst_name")
        action_value = ""
        if action:
            action_value = self.read_node_text(action)

        type_and_value = self.find_child_by_type(node, "type_and_value")
        data_type = self.find_child_by_type(node, "type")

        source = self.parse_only_value(type_and_value, statements)
        shadow_type = self.read_node_text(data_type)

        self.append_stmts(statements, node, {"type_cast_stmt": {"target": target, "data_type": shadow_type, "source": source, "cast_action": action_value}})

        return target

    def va_arg_stmt(self, node: Node, statements: list):
        target1 = self.tmp_variable()
        type_and_value = self.find_child_by_type(node, "type_and_value")
        data_type = self.find_child_by_type(node, "type")

        address = self.parse_only_value(type_and_value, statements)
        shadow_type = self.read_node_text(node)

        self.append_stmts(statements, node, {"mem_read": {"target": target1, "address": address}})
        target2 = self.tmp_variable()
        self.append_stmts(statements, node, {"call_stmt":{"target": target2, "name": "sizeof", "args": [shadow_type]}})
        self.append_stmts(statements, node, {"assign_stmt":{"target": address, "operator": "+", "operand": address, "operand2": target2}})

        return target1

    def phi_stmt(self, node: Node, statements: list):
        target = self.tmp_variable()
        data_type = self.find_child_by_type(node, "type")
        shadow_type = self.read_node_text(data_type)

        values = self.find_children_by_type(node, "value")
        labels = self.find_children_by_type(node, "local_var")

        phi_values = []
        phi_labels = []
        for i in range(len(values)):
            shadow_value = self.parse(values[i], statements)
            phi_values.append(shadow_value)

            shadow_label = self.parse(labels[i], statements)
            phi_labels.append(shadow_label)

        self.append_stmts(statements, node, {"phi_stmt": {"target": target, "phi_values": phi_values, "phi_labels": phi_labels}})

        return target

    def alloca_stmt(self, node: Node, statements: list):
        name = self.tmp_variable()
        data_type = self.find_child_by_type(node, "type")
        shadow_type = self.parse(data_type, statements)

        attrs = []

        type_and_value = self.find_child_by_type(node, "type_and_value")
        if type_and_value:
            shadow_value = self.parse_only_value(type_and_value, statements)
            if shadow_value:
                attrs.append(LIAN_INTERNAL.ARRAY)
                if shadow_value.isdigit():
                    shadow_value = int(shadow_value)
                    shadow_type = f"{shadow_type}[{shadow_value}]"
                else:
                    shadow_type = f"{shadow_type}[]"

        self.append_stmts(statements, node, {
            "variable_decl": {
                "data_type": shadow_type,
                "name": name
            }
        })

        target = self.tmp_variable()
        self.append_stmts(statements, node, {
            "addr_of": {
                "target": target,
                "source": name
            }
        })
        return target

    def load_stmt(self, node: Node, statements: list):
        target = self.tmp_variable()
        type_node = self.find_child_by_type(node, "type")
        shadow_type = self.parse(type_node, statements)

        type_and_value = self.find_child_by_type(node, "type_and_value")
        address = self.parse_only_value(type_and_value, statements)

        if address:
            self.append_stmts(statements, node, {"mem_read": {"target": target, "address": address, "data_type": shadow_type}})
            return target

    def store_stmt(self, node: Node, statements: list):
        operands = self.find_children_by_type(node, "type_and_value")
        shadow_source = self.parse_only_value(operands[0], statements)
        shadow_address = self.parse_only_value(operands[1], statements)

        if shadow_address and shadow_source:
            self.append_stmts(statements, node, {"mem_write": {"address": shadow_address, "source": shadow_source}})
            return shadow_source

    def cmpxchg_stmt(self, node: Node, statements: list):
        type_and_values = self.find_children_by_type(node, "type_and_value")
        ptr = type_and_values[0]
        cmp = type_and_values[1]
        new = type_and_values[2]

        target_ptr = self.tmp_variable()

        shadow_ptr = self.parse_only_value(ptr, statements)
        shadow_cmp = self.parse_only_value(cmp, statements)
        shadow_new = self.parse_only_value(new, statements)

        target = self.tmp_variable()

        operand1 = self.tmp_variable()
        operand2 = self.tmp_variable()

        self.append_stmts(statements, node, {
            "mem_read": {"target": operand1, "address": shadow_ptr}
        })
        self.append_stmts(statements, node, {
            "assign_stmt": {
                "target": operand2,
                "operator": "==",
                "operand": operand1,
                "operand2": shadow_cmp
            }
        })
        self.append_stmts(statements, node, {
            "if_stmt": {
                "condition": operand2,
                "then_body": [
                    {"mem_write": {"address": shadow_ptr, "source": shadow_new}}
                ],
            }
        })
        return shadow_ptr

    def atomicrmw_expr(self, node, statements):
        opcode = self.find_child_by_type(node, "atomic_bin_op_keyword")
        shadow_opcode = self.read_node_text(opcode)

        children = self.find_children_by_type(node, "type_and_value")
        if len(children) != 2:
            return

        pointer_node = children[0]
        value_node = children[0]

        pointer_type, pointer_addr = self.parse_type_and_value(pointer_node, statements)
        value_type, value_content = self.parse_type_and_value(pointer_node, statements)

        if shadow_opcode == "xchg":
            self.append_stmts(statements, node, {
                "mem_write": {
                    "address": pointer_addr,
                    "source": value_content
                }
            })
            return

        pointer_value = self.tmp_variable()
        self.append_stmts(statements, node, {
            "mem_read": {
                "target": pointer_value,
                "address": pointer_addr,
            }
        })
        target = self.tmp_variable()

        if shadow_opcode in ("add", "fadd"):
            self.append_stmts(statements, node, {
                "assign_stmt": {
                    "target": target,
                    "operand": pointer_value,
                    "operator": "+",
                    "operand2": value_content,
                }
            })
        elif shadow_opcode in ("sub", "fsub"):
            self.append_stmts(statements, node, {
                "assign_stmt": {
                    "target": target,
                    "operand": pointer_value,
                    "operator": "+",
                    "operand2": value_content,
                }
            })
        elif shadow_opcode == "and":
            self.append_stmts(statements, node, {
                "assign_stmt": {
                    "target": target,
                    "operand": pointer_value,
                    "operator": "&",
                    "operand2": value_content,
                }
            })
        elif shadow_opcode == "nand":
            tmp_var = self.tmp_variable()
            self.append_stmts(statements, node, [
                {
                    "assign_stmt": {
                        "target": tmp_var,
                        "operand": pointer_value,
                        "operator": "&",
                        "operand2": value_content,
                    }
                },
                {
                    "assign_stmt": {
                        "target": target,
                        "operator": "~",
                        "operand2": tmp_var,
                    }
                }
            ])
        elif shadow_opcode == "or":
            self.append_stmts(statements, node, {
                "assign_stmt": {
                    "target": target,
                    "operand": pointer_value,
                    "operator": "|",
                    "operand2": value_content,
                }
            })
        elif shadow_opcode == "xor":
            self.append_stmts(statements, node, {
                "assign_stmt": {
                    "target": target,
                    "operand": pointer_value,
                    "operator": "^",
                    "operand2": value_content,
                }
            })
        elif shadow_opcode in ("max", "umax", "fmax"):
            condition_var = self.tmp_variable()
            statements.extend([
                {
                    "assign_stmt": {
                        "target": condition_var,
                        "operand": pointer_value,
                        "operator": ">",
                        "operand2": value_content
                    }
                },
                {
                    "if_stmt": {
                        "condition": condition_var,
                        "then_body": [
                            {
                                "assign_stmt": {
                                    "target": target,
                                    "operand": pointer_value
                                }
                            }
                        ],
                        "else_body": [
                            {
                                "assign_stmt": {
                                    "target": target,
                                    "operand": value_content
                                }
                            }
                        ]
                    }
                }
            ])
        elif shadow_opcode in ("min", "umin", "fmin"):
            condition_var = self.tmp_variable()
            statements.extend([
                {
                    "assign_stmt": {
                        "target": condition_var,
                        "operand": pointer_value,
                        "operator": "<",
                        "operand2": value_content
                    }
                },
                {
                    "if_stmt": {
                        "condition": condition_var,
                        "then_body": [
                            {
                                "assign_stmt": {
                                    "target": target,
                                    "operand": pointer_value
                                }
                            }
                        ],
                        "else_body": [
                            {
                                "assign_stmt": {
                                    "target": target,
                                    "operand": value_content
                                }
                            }
                        ]
                    }
                }
            ])
        elif shadow_opcode == "uinc_wrap":
            condition_var = self.tmp_variable()
            statements.extend([
                {
                    "assign_stmt": {
                        "target": condition_var,
                        "operand": pointer_value,
                        "operator": ">=",
                        "operand2": value_content
                    }
                },
                {
                    "if_stmt": {
                        "condition": condition_var,
                        "then_body": [
                            {
                                "assign_stmt": {
                                    "target": target,
                                    "operand": 0
                                }
                            }
                        ],
                        "else_body": [
                            {
                                "assign_stmt": {
                                    "target": target,
                                    "operand": value_content,
                                    "operator": "+",
                                    "operand2": 1
                                }
                            }
                        ]
                    }
                }
            ])
        elif shadow_opcode == "udec_wrap":
            condition_var1 = self.tmp_variable()
            condition_var2 = self.tmp_variable()
            condition_var3 = self.tmp_variable()
            statements.extend([
                {
                    "assign_stmt": {
                        "target": condition_var1,
                        "operand": pointer_value,
                        "operator": "==",
                        "operand2": 0
                    }
                },
                {
                    "assign_stmt": {
                        "target": condition_var2,
                        "operand": pointer_value,
                        "operator": ">=",
                        "operand2": value_content
                    }
                },
                {
                    "assign_stmt": {
                        "target": condition_var3,
                        "operand": condition_var1,
                        "operator": "||",
                        "operand2": condition_var2
                    }
                },
                {
                    "if_stmt": {
                        "condition": condition_var3,
                        "then_body": [
                            {
                                "assign_stmt": {
                                    "target": target,
                                    "operand": 0
                                }
                            }
                        ],
                        "else_body": [
                            {
                                "assign_stmt": {
                                    "target": target,
                                    "operand": value_content,
                                    "operator": "-",
                                    "operand2": 1
                                }
                            }
                        ]
                    }
                }
            ])
        self.append_stmts(statements, node, {
            "mem_write" : {
                "address": pointer_addr,
                "source": target
            }
        })


    def fence_stmt(self, node: Node, statements: list):
        pass

    def find_next_type(self, raw_type):
        next_type = ""
        if raw_type.startswith("["):
            counter = 0
            # jump to x
            x_flag = False
            while counter < len(raw_type):
                if raw_type[counter] == "x":
                    x_flag = True
                counter += 1
                if x_flag:
                    break

            if not x_flag:
                return ""

            while counter < len(raw_type):
                if raw_type[counter] != " ":
                    return raw_type[counter:]
                counter += 1

        return next_type

    def getelementptr_stmt(self, node: Node, statements: list):
        operands = self.find_children_by_type(node, "type_and_value")
        if len(operands) <= 2:
            return

        base_type = self.parse_only_type(operands[0], statements)
        base_pointer = self.parse_only_value(operands[1], statements)
        first_index = self.parse_only_value(operands[2], statements)

        if first_index.isdigit():
            first_index = int(first_index)

        target = base_pointer
        if first_index != 0:
            tmp_var = self.tmp_variable()
            self.append_stmts(statements, node, {
                "array_read" : {
                    "target": tmp_var,
                    "array": target,
                    "index": str(first_index),
                }
            })
            tmp_var2 = self.tmp_variable()
            self.append_stmts(statements, node, {
                "addr_of": {
                    "target": tmp_var2,
                    "source": tmp_var
                }
            })
            target = tmp_var2

        raw_type = self.read_node_text(operands[0])
        if len(operands) >= 3:
            for each_operand in operands[3:]:
                each_index = self.parse_only_value(each_operand, statements)
                if each_index.isdigit():
                    each_index = int(each_index)

                tmp_var = self.tmp_variable()
                if raw_type.startswith("["):
                    self.append_stmts(statements, node, {
                        "array_read": {
                            "target": tmp_var,
                            "array": target,
                            "index": str(each_index)
                        }
                    })
                else:
                    field_name = each_index
                    if isinstance(each_index, int):
                        field_name = f"_{each_index}"
                    self.append_stmts(statements, node, {
                        "field_read": {
                            "target": tmp_var,
                            "receiver_object": target,
                            "field": field_name
                        }
                    })

                tmp_var2 = self.tmp_variable()
                self.append_stmts(statements, node, {
                    "addr_of": {
                        "target": tmp_var2,
                        "source": tmp_var
                    }
                })

                target = tmp_var2
                raw_type = self.find_next_type(raw_type)

        return target

    def extractvalue_stmt(self, node: Node, statements: list):
        target = self.tmp_variable()

        type_and_value = self.find_child_by_type(node, "type_and_value")
        number = self.find_child_by_type(node, "number")

        shadow_source = self.parse_only_value(type_and_value, statements)
        shadow_number = self.parse(number, statements)
        if shadow_number.isdigit():
            shadow_number = "_" + shadow_number

        self.append_stmts(statements, node, {"array_read": {"target": target, "source": shadow_source, "index": shadow_number}})

        return target

    def insertvalue_stmt(self, node: Node, statements: list):
        type_and_values = self.find_children_by_type(node, "type_and_value")
        number = self.find_child_by_type(node, "number")

        target = type_and_values[0]
        source = type_and_values[1]

        type1, shadow_target = self.parse_type_and_value(target, statements)
        shadow_source = self.parse_only_value(source, statements)
        shadow_number = self.parse(number, statements)

        if shadow_target:
            self.append_stmts(statements, node, {"array_insert": {"array": shadow_target, "index": shadow_number, "source": shadow_source}})
            return shadow_target

        target = self.tmp_variable()
        self.append_stmts(statements, node, {"new_array": {"target": target, "data_type": type1}})
        self.append_stmts(statements, node, {"array_insert": {"array": target, "index": shadow_number, "source": shadow_source}})
        return target

    def is_expression(self, node: Node):
        return self.check_expression_handler(node.type) is not None

    def expression(self, node: Node, statements: list):
        handler = self.check_expression_handler(node.type)
        return handler(node, statements)
