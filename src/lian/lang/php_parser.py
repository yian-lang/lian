#!/usr/bin/env python3

from tree_sitter import Node
from lian.lang import common_parser
from lian.util import util
from lian.config.constants import (
    LIAN_INTERNAL
)

class Parser(common_parser.Parser):
    def init(self):
        self.CONSTANTS_MAP = {
            "." : "+",
            "true": LIAN_INTERNAL.TRUE,
            "false": LIAN_INTERNAL.FALSE,
            "null": LIAN_INTERNAL.NULL,
        }

        self.LITERAL_MAP = {
            "int"                               : self.regular_number_literal,
            "integer"                           : self.regular_number_literal,
            "float"                             : self.regular_number_literal,
            "boolean"                           : self.regular_literal,
            "true"                              : self.regular_literal,
            "false"                             : self.regular_literal,
            "null"                              : self.regular_literal,
            "name"                              : self.string_literal,
            "namespace_name"                    : self.string_literal,
            "qualified_name"                    : self.qualified_name,
            "string"                            : self.string_literal,
            "string_content"                    : self.string_literal,
            "escape_sequence"                   : self.string_literal,
            "encapsed_string"                   : self.encapsed_string,
            "this"                              : self.this_literal,
            "super"                             : self.super_literal,
            "relative_scope"                    : self.relative_scope,
        }

        self.DECLARATION_HANDLER_MAP = {
            # "variable_name"                   : self.variable_declaration,
            "const_declaration"                 : self.const_declaration, # T
            "function_definition"               : self.function_declaration, # T
            "anonymous_declaration"             : self.function_declaration, # T
            "method_declaration"                : self.function_declaration, # T
            "class_declaration"                 : self.class_declaration, # T
            "interface_declaration"             : self.class_declaration, # T
            "trait_declaration"                 : self.trait_declaration,
            "enum_declaration"                  : self.enum_declaration, # T
            "namespace_definition"              : self.namespace_definition, # T
            "use_declaration"                   : self.use_declaration,
            "namespace_use_declaration"         : self.use_declaration,
            "global_declaration"                : self.global_declaration,
            "function_static_declaration"       : self.function_static_declaration,
        }

        self.EXPRESSION_HANDLER_MAP = {
            "throw_expression"                  : self.throw_expression, # T
            # "sequence_expression"               : self.sequence_expression,
            "match_expression"                  : self.match_expression, # T
            "unary_op_expression"               : self.unary_expression, # T
            # "error_suppression_expression"      : self.error_suppression_expression,
            "clone_expression"                  : self.clone_expression, # T
            "parenthesized_expression"          : self.parenthesized_expression,
            "class_constant_access_expression"  : self.scoped_property_and_class_constant_access_expression, # T
            "scoped_property_access_expression" : self.scoped_property_and_class_constant_access_expression, # T
            "print_intrinsic"                   : self.call_expression, # T
            "object_creation_expression"        : self.new_expression, # T
            "update_expression"                 : self.update_expression, # T
            "cast_expression"                   : self.cast_expression, # T
            "assignment_expression"             : self.assignment_expression, # T
            "augmented_assignment_expression"   : self.assignment_expression, # T
            "reference_assignment_expression"   : self.assignment_expression, # T
            "conditional_expression"            : self.conditional_expression, # T
            "member_access_expression"          : self.member_access_expression, # T
            "function_call_expression"          : self.call_expression, # T
            "scoped_call_expression"            : self.call_expression, # T
            "member_call_expression"            : self.call_expression, # T
            "nullsafe_member_call_expression"   : self.call_expression, # T
            "array_creation_expression"         : self.new_array, # T
            "shell_command_expression"          : self.shell_command_expression,
            "yield_expression"                  : self.yield_expression,
            "binary_expression"                 : self.binary_expression, # T
            "include_expression"                : self.include_expression, # T
            "include_once_expression"           : self.include_expression, # T
            "require_expression"                : self.require_expression, # T
            "require_once_expression"           : self.require_expression, # T


            "anonymous_function"                : self.function_declaration, # T
            "arrow_function"                    : self.function_declaration, # T
            "anonymous_class"                   : self.class_declaration, # T
            "subscript_expression"              : self.subscript_expression,

            "formal_parameters"                 : self.formal_parameters, # T

            # 将type放在此处处理
            "named_type"                        : self.named_type,
            "optional_type"                     : self.optional_type,
            "bottom_type"                       : self.regular_type,
            "union_type"                        : self.union_type,
            "intersection_type"                 : self.intersection_type,
            "disjunctive_normal_form_type"      : self.disjunctive_normal_form_type,

            "primitive_type"                    : self.regular_type,

        }

        self.STATEMENT_HANDLER_MAP = {
            "empty_statement"                   : self.empty_statement, # T
            "compound_statement"                : self.compound_statement, # T
            "named_label_statement"             : self.named_label_statement, # T
            "expression_statement"              : self.expression_statement, # T
            "if_statement"                      : self.if_statement, # T
            "switch_statement"                  : self.switch_statement,
            "while_statement"                   : self.while_statement, # T
            "do_statement"                      : self.dowhile_statement, # T
            "for_statement"                     : self.for_statement, # T
            "foreach_statement"                 : self.foreach_statement, # T
            "goto_statement"                    : self.goto_statement, # T
            "continue_statement"                : self.continue_statement, # T
            "break_statement"                   : self.break_statement, # T
            "return_statement"                  : self.return_statement, # T
            "try_statement"                     : self.try_statement,  # T
            "declare_statement"                 : self.declare_statement,
            "echo_statement"                    : self.echo_statement, # T
            "exit_statement"                    : self.exit_statement, # T
            "unset_statement"                   : self.unset_statement, # T
        }

    # def find_namespace_definition(self, node):
    #     while node is not None:
    #         if node.type == 'namespace_definition':
    #             return node
    #         node = node.parent
    #     return None

    def read_node_pref_children(self, node, stop_char):
        stop_char_list = [stop_char]
        if isinstance(stop_char, list):
            stop_char_list = stop_char

        prefix_children = []
        my_list = ["function", "fn"]
        for child in node.children:
            if not util.isna(child):
                content = self.read_node_text(child)
                # stop at parameters
                if content in stop_char_list:
                    break
                prefix_children.append(content)
        for item in my_list:
            while item in my_list:
                if item in prefix_children:
                    prefix_children.remove(item)
                else:
                    break
        return prefix_children

    def read_node_between_named_nodes(self, parent, node1, node2):
        return_list = []
        TAG1 = False
        for child in parent.children:
            if child == node2:
                break
            if TAG1:
                return_list.append(child)
            if child == node1:
                TAG1 = True
        return return_list

    def pack_args(self, node: Node, statements: list):
        tmp_var = self.tmp_variable()
        self.append_stmts(statements, node, {
            "new_array": {
                "target": tmp_var
            }
        })

        meet_splat = False
        for index, argtag in enumerate(node.named_children):
            for arg in argtag.named_children:
                if self.is_comment(arg):
                    continue

                if arg.type == "variadic_unpacking":
                    meet_splat = True
                    shadow_expr = self.parse(arg, statements)
                    self.append_stmts(statements, node, {"array_extend": {"array": tmp_var, "source": shadow_expr}})
                else:
                    if meet_splat:
                        shadow_expr = self.parse(arg, statements)
                        self.append_stmts(statements, node, {"array_append": {"array": tmp_var, "source": shadow_expr}})
                    else:
                        shadow_expr = self.parse(arg, statements)
                        self.append_stmts(statements, node, {"array_write": {"array": tmp_var, "index": str(index), "source": shadow_expr}})

        return tmp_var

    def is_comment(self, node):
        return node.type == "comment"

    """
        type部分
    """

    def regular_type(self, node: Node, statements: list):
        return self.read_node_text(node)

    def optional_type(self, node: Node, statements: list):
        child = node.named_children[0]
        return f"{self.read_node_text(child)}?"

    def union_type(self, node: Node, statements: list):
        return self.read_node_text(node)

    def disjunctive_normal_form_type(self, node, statements):
        return self.read_node_text(node)

    def intersection_type(self, node: Node, statements: list):
        return self.read_node_text(node)

    def named_type(self, node: Node, statements: list):
        child = node.children[0]
        shadow_type = self.parse(child, statements)
        return shadow_type

    """
        expression(含literal)部分
    """

    def is_identifier(self, node):
        return node.type == "variable_name" or node.type == "name"

    def regular_number_literal(self, node: Node, statements: list, replacement: list):
        value = self.read_node_text(node)
        value = self.common_eval(value)
        return str(value)

    def regular_literal(self, node: Node, statements: list, replacement: list):
        data = self.read_node_text(node)
        if data in self.CONSTANTS_MAP:
            return self.CONSTANTS_MAP[data]
        return data

    def this_literal(self, node: Node, statements: list, replacement: list):
        return self.global_this()

    def super_literal(self, node: Node, statements: list, replacement: list):
        return self.global_super()

    def encapsed_string(self, node: Node, statements: list, replacement: list):
        last_assign_result = ""
        if node.named_child_count >= 2:
            for index in range(len(node.named_children)):
                tmp_var = self.tmp_variable()
                shadow_oprand = self.parse(node.named_children[index], statements)
                if index == 0:
                    last_assign_result = shadow_oprand
                    continue
                self.append_stmts(statements, node, {"assign_stmt": {"target": tmp_var, "operator": "+", "operand": last_assign_result, "operand2": shadow_oprand}})
                last_assign_result = tmp_var
            return tmp_var

        else:
            for child in node.named_children:
                tmp_var = self.tmp_variable()
                shadow_oprand = self.parse(child, statements)
                self.append_stmts(statements, node, {"assign_stmt": {"target": tmp_var, "operand": shadow_oprand}})
                return tmp_var

    def string_literal(self, node: Node, statements: list, replacement: list):
        replacement = []
        for child in node.named_children:
            self.parse(child, statements, replacement)

        ret = self.read_node_text(node).replace('`', '"')
        if replacement:
            # 逐个进行替换，为了防止在字符串中的多个地方出现expr而发生误替换，因此将${expr}整体替换为${value}
            for r in replacement:
                (expr, value) = r
                ret = ret.replace("${" + self.read_node_text(expr) + "}", "${" + value + "}")

        ret = self.handle_hex_string(ret)
        return self.escape_string(ret)

    def qualified_name(self, node: Node, statements: list, replacement: list):
        namespace = self.find_child_by_field(node, "prefix")
        field = node.named_children[-1]
        tmp_var = self.tmp_variable()
        shadow_namespace = self.read_node_text(namespace)
        shadow_field = self.read_node_text(field)
        self.append_stmts(statements, node, {
            "namespace_read": {
                "target": tmp_var,
                "namespace": shadow_namespace,
                "field": shadow_field,
            }
        })
        return tmp_var

    def relative_scope(self, node: Node, statements: list, replacement: list):
        shadow_node = self.read_node_text(node)
        if shadow_node == "self":
            return self.global_this()
        elif shadow_node == "parent":
            return self.global_super()
        else:
            return shadow_node

    def summary_substitution(self, node: Node, statements: list, replacement: list):
        expr = node.named_children[0]
        shadow_expr = self.parse(expr, statements)
        replacement.append((expr, shadow_expr))
        return shadow_expr

    def throw_expression(self, node: Node, statements: list):
        shadow_expr = ""
        if node.named_child_count > 0:
            expr = node.named_children[0]
            shadow_expr = self.parse(expr, statements)
        self.append_stmts(statements, node, {"throw_stmt": {"name": shadow_expr}})

    def include_expression(self, node: Node, statements: list):
        tmp_var = self.tmp_variable()
        shadow_expr = ""
        if node.named_child_count > 0:
            expr = node.named_children[0]
            shadow_expr = self.parse(expr, statements)
        self.append_stmts(statements, node, {"call_stmt": {"target": tmp_var, "name": 'include', "positional_args": [shadow_expr]}})
        return tmp_var

    def require_expression(self, node: Node, statements: list):
        tmp_var = self.tmp_variable()
        shadow_expr = ""
        if node.named_child_count > 0:
            expr = node.named_children[0]
            shadow_expr = self.parse(expr, statements)
        self.append_stmts(statements, node, {"require_stmt": {"target": tmp_var, "name": shadow_expr}})
        # self.append_stmts(statements, node, {"call_stmt": {"target": tmp_var, "name": 'require', "positional_args": [shadow_expr]}})
        return tmp_var

    def scoped_property_and_class_constant_access_expression(self, node: Node, statements: list):
        tmp_var = self.tmp_variable()
        object = node.named_children[0]
        field = node.named_children[1]

        shadow_object = self.parse(object, statements)
        shadow_field = self.parse(field, statements)
        self.append_stmts(statements, node, {"field_read": {"target": tmp_var, "receiver_object": shadow_object, "field": shadow_field}})
        return tmp_var

    def double_question_mark(self, node: Node, target, operand1, operand2, statements):
        self.append_stmts(statements, node, {
            "if_stmt": {
                "condition": operand1,
                "then_body": [
                    {"assign_stmt": {"target": target, "operand": operand1} }
                ],
                "else_body": [
                    {"assign_stmt": {"target": target, "operand": operand2} }
                ]
            }
        })
        return target


    def binary_expression(self, node: Node, statements: list):
        left = self.find_child_by_field(node, "left")
        right = self.find_child_by_field(node, "right")
        operator = self.find_child_by_field(node, "operator")

        shadow_operator = self.read_node_text(operator)
        shadow_operator = self.CONSTANTS_MAP.get(shadow_operator, shadow_operator)

        shadow_left = self.parse(left, statements)
        shadow_right = self.parse(right, statements)

        tmp_var = self.tmp_variable()
        if shadow_operator == "??":
            return self.double_question_mark(node, tmp_var, shadow_left, shadow_right, statements)
        self.append_stmts(statements, node, {"assign_stmt": {"target": tmp_var, "operator": shadow_operator, "operand": shadow_left,
                                           "operand2": shadow_right}})

        return tmp_var

    def unary_expression(self, node: Node, statements: list):
        operand = self.find_child_by_field(node, "argument")
        shadow_operand = self.parse(operand, statements)
        operator = self.find_child_by_field(node, "operator")
        shadow_operator = self.read_node_text(operator)

        tmp_var = self.tmp_variable()

        self.append_stmts(statements, node, {"assign_stmt": {"target": tmp_var, "operator": shadow_operator, "operand": shadow_operand}})
        return tmp_var

    def cast_expression(self, node: Node, statements: list):
        type = self.find_child_by_field(node, "type")
        value = self.find_child_by_field(node, "value")
        shadow_type = self.read_node_text(type)
        shadow_value = self.parse(value, statements)

        tmp_var = self.tmp_variable()
        self.append_stmts(statements, node, {"type_cast_stmt": {"target": tmp_var, "data_type": shadow_type, "source": shadow_value}})
        return tmp_var

    def clone_expression(self, node: Node, statements: list):
        shadow_expr = ""
        if node.named_child_count > 0:
            expr = node.named_children[0]
            shadow_expr = self.parse(expr, statements)
        return shadow_expr

    def parenthesized_expression(self, node: Node, statements: list):
        shadow_expr = ""
        if node.named_child_count > 0:
            expr = node.named_children[0]
            shadow_expr = self.parse(expr, statements)
        return shadow_expr

    def update_expression(self, node: Node, statements: list):
        shadow_node = self.read_node_text(node)

        operator = "-"
        if "+" == shadow_node[0] or "+" == shadow_node[-1]:
            operator = "+"

        is_after = False
        if shadow_node[-1] == operator:
            is_after = True

        tmp_var = self.tmp_variable()

        expression = self.find_child_by_field(node, "argument")
        # 等号左边为array[index]或object.field时，先读后写
        if expression.type == "member_access_expression":
            shadow_object, field = self.parse_field(expression, statements)

            self.append_stmts(statements, node, {"field_read": {"target": tmp_var, "receiver_object": shadow_object, "field": field}})
            tmp_var2 = self.tmp_variable()
            self.append_stmts(statements, node, {"assign_stmt": {"target": tmp_var2, "operator": operator, "operand": tmp_var, "operand2": "1"}})
            self.append_stmts(statements, node, {"field_write": {"receiver_object": shadow_object, "field": field, "source": tmp_var2}})

            if is_after:
                return tmp_var
            return tmp_var2

        if expression.type == "subscript_expression":
            shadow_array, shadow_index = self.parse_array(expression, statements)

            self.append_stmts(statements, node, {"array_read": {"target": tmp_var, "array": shadow_array, "index": shadow_index}})
            tmp_var2 = self.tmp_variable()
            self.append_stmts(statements, node, {"assign_stmt": {"target": tmp_var2, "operator": operator, "operand": tmp_var, "operand2": "1"}})
            self.append_stmts(statements, node, {"array_write": {"array": shadow_array, "index": shadow_index, "source": tmp_var2}})

            if is_after:
                return tmp_var
            return tmp_var2

        shadow_expression = self.parse(expression, statements)

        # 注意下面两条gir指令的顺序
        # 如果++/--在后面，则tmp_var为原值
        if is_after:
            self.append_stmts(statements, node, {"assign_stmt": {"target": tmp_var, "operand": shadow_expression}})

        self.append_stmts(statements, node, {"assign_stmt": {"target": shadow_expression, "operator": operator,
                                           "operand": shadow_expression, "operand2": "1"}})

        # 如果++/--在前面，则tmp_var为更新后的值
        if not is_after:
            self.append_stmts(statements, node, {"assign_stmt": {"target": tmp_var, "operand": shadow_expression}})

        return tmp_var

    def assignment_expression(self, node: Node, statements: list):
        left = self.find_child_by_field(node, "left")
        right = self.find_child_by_field(node, "right")
        operator_list = []
        operator_list = self.read_node_between_named_nodes(node, left, right)
        operator = ''
        for op in operator_list:
            operator += self.read_node_text(op)

        shadow_operator = operator.replace("=", "")
        shadow_operator = self.CONSTANTS_MAP.get(shadow_operator, shadow_operator)

        shadow_right = self.parse(right, statements)

        ret_value = None
        if left.type == "member_access_expression":
            shadow_object, field = self.parse_field(left, statements)
            if not shadow_operator:
                self.append_stmts(statements, node, {"field_write": {"receiver_object": shadow_object, "field": field, "source": shadow_right}})
                return shadow_right

            tmp_var = self.tmp_variable()
            self.append_stmts(statements, node, {"field_read": {"target": tmp_var, "receiver_object": shadow_object, "field": field}})
            tmp_var2 = self.tmp_variable()
            if shadow_operator == "??":
                self.double_question_mark(node, tmp_var2, tmp_var, shadow_right, statements)
            elif shadow_operator == "&":
                self.append_stmts(statements, node, {"assign_stmt": {"target": tmp_var2, "operand": "&" + shadow_right}})
            else:
                self.append_stmts(statements, node, {"assign_stmt":
                                       {"target": tmp_var2, "operator": shadow_operator,
                                        "operand": tmp_var, "operand2": shadow_right}})
            self.append_stmts(statements, node, {"field_write": {"receiver_object": shadow_object, "field": field, "source": tmp_var2}})

            return tmp_var2

        # 未更改
        if left.type == "subscript_expression":
            shadow_array, shadow_index = self.parse_array(left, statements)

            if not shadow_operator:
                self.append_stmts(statements, node, {"array_write": {"array": shadow_array, "index": shadow_index, "source": shadow_right}})
                return shadow_right

            tmp_var = self.tmp_variable()
            self.append_stmts(statements, node, {"array_read": {"target": tmp_var, "array": shadow_array, "index": shadow_index}})
            tmp_var2 = self.tmp_variable()
            if shadow_operator == "??":
                self.double_question_mark(node, tmp_var2, tmp_var, shadow_right, statements)
            elif shadow_operator == "&":
                self.append_stmts(statements, node, {"assign_stmt": {"target": tmp_var2, "operand": "&" + shadow_right}})
            else:
                self.append_stmts(statements, node, {"assign_stmt":
                                   {"target": tmp_var2, "operator": shadow_operator,
                                    "operand": tmp_var, "operand2": shadow_right}})
            self.append_stmts(statements, node, {"array_write": {"array": shadow_array, "index": shadow_index, "source": tmp_var2}})

            return tmp_var2

        # 数组/list解构
        if left.type == "list_literal":
            index = 0
            for p in left.named_children:
                if self.is_comment(p):
                    continue

                pattern = self.parse(p, statements)

                self.append_stmts(statements, node, {"array_read": {"target": pattern, "array": shadow_right, "index": str(index)}})
                index += 1

            return shadow_right

        # TODO dynamic_variable_name,形式：${x} = 10,左边是一个动态变量
        # 其他情况下，左边直接读取文本
        shadow_left = self.read_node_text(left)
        if not shadow_operator:
            self.append_stmts(statements, node, {"variable_decl": {"name": shadow_left, "attrs": []}})
            self.append_stmts(statements, node, {"assign_stmt": {"target": shadow_left, "operand": shadow_right}})
        else:
            if shadow_operator == "??":
                self.double_question_mark(node, shadow_left, shadow_left, shadow_right, statements)
            elif shadow_operator == "&":
                self.append_stmts(statements, node, {"assign_stmt": {"target": shadow_left, "operand": "&" + shadow_right}})
            else:
                self.append_stmts(statements, node, {"assign_stmt": {"target": shadow_left, "operator": shadow_operator,
                                                   "operand": shadow_left, "operand2": shadow_right}})
        return shadow_left

    def parse_field(self, node: Node, statements: list):
        myobject = self.find_child_by_field(node, "object")
        shadow_object = self.parse(myobject, statements)

        field = self.find_child_by_field(node, "name")
        shadow_field = self.read_node_text(field)
        return (shadow_object, shadow_field)

    def member_access_expression(self, node: Node, statements: list):
        shadow_object, shadow_field = self.parse_field(node, statements)
        tmp_var = self.tmp_variable()
        self.append_stmts(statements, node, {"field_read": {"target": tmp_var, "receiver_object": shadow_object, "field": shadow_field}})
        return tmp_var

    def nullsafe_member_access_expression(self, node: Node, statements: list):
        shadow_object, shadow_field = self.parse_field(node, statements)
        tmp_var = self.tmp_variable()
        self.append_stmts(statements, node, {"field_read": {"target": tmp_var, "receiver_object": shadow_object, "field": shadow_field}})
        return tmp_var

    def subscript_expression(self, node: Node, statements: list):
        array = node.named_children[0]
        shadow_array = self.parse(array, statements)

        if node.named_child_count > 1:
            subscript = node.named_children[1]
        else:
            tmp_array = self.tmp_variable()
            self.append_stmts(statements, node, {"array_read": {"target": tmp_array, "array": shadow_array, "index": ""}})
            return tmp_array

        tmp_array = self.tmp_variable()
        shadow_index = self.parse(subscript, statements)
        self.append_stmts(statements, node, {"array_read": {"target": tmp_array, "array": shadow_array, "index": shadow_index}})
        shadow_array = tmp_array
        return tmp_array

    def parse_array(self, node: Node, statements: list):
        array = node.named_children[0]
        shadow_object = self.parse(array, statements)
        if node.named_child_count > 1:
            index = node.named_children[1]
            shadow_index = self.parse(index, statements)

        else:
            shadow_index = None

        return (shadow_object, shadow_index)

    def call_expression(self, node: Node, statements: list):
        args_list = []

        # 单独处理print
        if node.type == "print_intrinsic":
            name = "print"
            args = node.named_children[0]
            args_list.append(args)
            shadow_name = name
            tmp_return = self.tmp_variable()
            self.append_stmts(statements, node, {"call_stmt": {"target": tmp_return, "name": shadow_name, "args": args_list}})
            return tmp_return

        # 处理MyClass::myMethod
        elif node.type == "scoped_call_expression":
            object = self.find_child_by_field(node, "scope")
            field = self.find_child_by_field(node, "name")
            args = self.find_child_by_field(node, "arguments")

            shadow_object = self.parse(object, statements)
            shadow_field = self.parse(field, statements)

            tmp_var = self.tmp_variable()
            shadow_name = tmp_var
            self.append_stmts(statements, node, {"field_read": {"target": tmp_var, "receiver_object": shadow_object, "field": shadow_field}})

        # 处理object->field
        elif node.type == "member_call_expression" or node.type == "nullsafe_member_call_expression":
            object = self.find_child_by_field(node, "object")
            field = self.find_child_by_field(node, "name")
            args = self.find_child_by_field(node, "arguments")
            shadow_object = self.parse(object, statements)
            shadow_field = self.parse(field, statements)

            tmp_var = self.tmp_variable()
            shadow_name = tmp_var
            self.append_stmts(statements, node, {"field_read": {"target": tmp_var, "receiver_object": shadow_object, "field": shadow_field}})

        # 处理普通函数调用
        else:
            name = self.find_child_by_field(node, "function")
            shadow_name = self.parse(name, statements)

            args = self.find_child_by_field(node, "arguments")

        # 处理参数列表，主要处理解包
        positional_args = []
        packed_positional_args = None
        if args.named_child_count > 0:
            NEED_PACK = False
            for arg in args.named_children:
                list_splat_children = self.find_children_by_type(arg, "variadic_unpacking")
                if list_splat_children:
                    NEED_PACK = True
            for arg in args.named_children:
                if self.is_comment(arg):
                    continue

                if NEED_PACK:
                    packed_positional_args = self.pack_args(args, statements)
                    break

                else:
                    packed_positional_args = None
                    for child in arg.named_children:
                        if child.type not in ["variadic_unpacking"]:
                            shadow_expr = self.parse(child, statements)
                            positional_args.append(shadow_expr)

        tmp_return = self.tmp_variable()
        self.append_stmts(statements, node,
            {
                "call_stmt": {
                    "target": tmp_return,
                    "name": shadow_name,
                    "positional_args": positional_args,
                    "packed_positional_args": packed_positional_args,
                }
            }
        )

        return tmp_return

    def shell_command_expression(self, node: Node, statements: list):
        command = node.named_children[0]
        shadow_command = self.parse(command, statements)
        tmp_var = self.tmp_variable()
        self.append_stmts(statements, node, {
            "call_stmt": {
                "target": tmp_var,
                "name": "shell",
                "positional_args": shadow_command
            }
        })
        return tmp_var

    # 以[]的形式创建新数组，例如let arr = [1, 2, 3]
    def new_array(self, node: Node, statements: list):
        # 创建数组
        tmp_var = self.tmp_variable()
        self.append_stmts(statements, node, {"new_array": {"target": tmp_var}})

        # 写入数组
        index = 0
        for child in node.named_children:
            if self.is_comment(child):
                continue

            if child.named_child_count == 2:
                key = child.named_children[0]
                value = child.named_children[1]
                shadow_key = self.read_node_text(key)
            elif child.named_child_count == 1:
                key = index
                value = child.named_children[0]
                shadow_key = key
            else:
                break

            shadow_value = self.read_node_text(value)
            shadow_child = self.parse(child, statements)
            self.append_stmts(statements, node, {"field_write": {"receiver_object": tmp_var, "field": str(shadow_key), "source": shadow_child}})
            index += 1

        return tmp_var

    # 解析Object {} 中的key-value
    def parse_pair(self, node: Node, statements: list):
        key = self.find_child_by_field(node, "key")
        value = self.find_child_by_field(node, "value")

        if key.type == "property_identifier":
            shadow_key = self.read_node_text(key)
        else:
            shadow_key = self.parse(key, statements)
        shadow_value = self.parse(value, statements)

        return (shadow_key, shadow_value)

    def new_expression(self, node: Node, statements: list):
        gir_node = {}
        qualified_name = self.find_child_by_type(node, "qualified_name")
        anonymous_class = self.find_child_by_type(node, "anonymous_class")
        prefix = []
        name = None
        if qualified_name:
            prefix = self.find_child_by_field(qualified_name, "prefix")
            name = self.find_child_by_type(qualified_name, "name")

        if prefix:
            shadow_object = self.read_node_text(prefix)
            shadow_field = self.read_node_text(name)
            shadow_mytype = shadow_object + "." + shadow_field
        elif anonymous_class: # 处理匿名类
            shadow_mytype = self.parse(anonymous_class, statements)
        else:
            name = node.named_children[0]
            shadow_mytype = self.read_node_text(name)

        gir_node["data_type"] = shadow_mytype

        arguments = self.find_child_by_type(node, "arguments")
        arguments_list = []
        if arguments:
            if arguments.named_child_count > 0:
                for arg in arguments.named_children:
                    if self.is_comment(arg):
                        continue

                    shadow_arg = self.parse(arg, statements)
                    if shadow_arg:
                        arguments_list.append(shadow_arg)
        else:
            arguments_list.append("")

        gir_node["args"] = arguments_list

        tmp_var = self.tmp_variable()
        gir_node["target"] = tmp_var

        self.append_stmts(statements, node, {"new_object": gir_node})

        return tmp_var

    def yield_expression(self, node: Node, statements: list):
        shadow_expr = ""
        if node.named_child_count > 0:
            expr = node.named_children[0]
            shadow_expr = self.parse(expr, statements)

        self.append_stmts(statements, node, {"yield_stmt": {"target": shadow_expr}})
        return shadow_expr

    def conditional_expression(self, node: Node, statements: list):
        consequence = self.find_child_by_field(node, "body")
        condition = self.find_child_by_field(node, "condition")
        alternative = self.find_child_by_field(node, "alternative")

        shadow_condition = self.parse(condition, statements)

        then_body = []
        else_body = []

        tmp_var = self.tmp_variable()

        shadow_consequence = self.parse(consequence, then_body)
        then_body.append({"assign_stmt": {"target": tmp_var, "operand": shadow_consequence}})

        shadow_alternative = self.parse(alternative, else_body)
        else_body.append({"assign_stmt": {"target": tmp_var, "operand": shadow_alternative}})

        self.append_stmts(statements, node, {"if_stmt": {"condition": shadow_condition, "then_body": then_body, "else_body": else_body}})
        return tmp_var

    def switch_statement(self, node: Node, statements: list):
        switch_ret = self.tmp_variable()

        # is_switch_rule = False
        switch_block = self.find_child_by_field(node, "body")
        condition = self.find_child_by_field(node, "condition")
        shadow_condition = self.parse(condition, statements)

        switch_stmt_list = []

        self.append_stmts(statements, node, {"switch_stmt": {"condition": shadow_condition, "body": switch_stmt_list}})

        for child in switch_block.named_children:
            if self.is_comment(child):
                continue

            if child.type == "default_statement":
                new_body = []
                if child.named_child_count > 0:
                    for each_stmt in child.named_children:
                        self.parse(each_stmt, new_body)
                    switch_stmt_list.append({"default_stmt": {"body": new_body}})
                continue

            if child.named_child_count > 0:
                new_body = []
                new_condition = child.named_children[0]
                shadow_new_condition = self.parse(new_condition, statements)

                if shadow_new_condition:
                    switch_stmt_list.append({"case_stmt": {"condition": shadow_new_condition, "body": new_body}})

                    if child.named_child_count > 1:
                        for each_stmt in child.named_children[1:]:
                            self.parse(each_stmt, new_body)

    def match_expression(self, node: Node, statements: list):
        switch_ret = self.tmp_variable()

        # is_switch_rule = False
        switch_block = self.find_child_by_field(node, "body")
        condition = self.find_child_by_field(node, "condition")
        shadow_condition = self.parse(condition, statements)

        switch_stmt_list = []

        self.append_stmts(statements, node, {"switch_stmt": {"condition": shadow_condition, "body": switch_stmt_list}})

        for child in switch_block.named_children:
            if self.is_comment(child):
                continue

            if child.type == "match_default_expression":
                new_body = []
                expr = self.find_child_by_field(child, "return_expression")
                shadow_return = self.parse(expr, new_body)
                new_body.append({"assign_stmt": {"target": switch_ret, "operand": shadow_return}})
                new_body.append({"break_stmt": {"name": ""}})
                switch_stmt_list.append({"default_stmt": {"body": new_body}})
                continue

            label = child.named_children[0]
            if label.named_child_count == 0:
                continue

            counter = 0
            while counter < len(label.named_children):
                new_body = []
                new_condition = label.named_children[counter]
                shadow_new_condition = self.parse(new_condition, statements)
                switch_stmt_list.append({"case_stmt": {"condition": shadow_new_condition, "body": new_body}})

                if (counter + 1) == len(label.named_children):
                    expr = self.find_child_by_field(child, "return_expression")
                    shadow_return = self.parse(expr, new_body)

                    if not shadow_return:
                        break

                    new_body.append({"assign_stmt": {"target": switch_ret, "operand": shadow_return}})
                    new_body.append({"break_stmt": {"name": ""}})

                counter += 1

        return switch_ret



    """
        statement部分
    """
    def parse_alternative(self, alter_list, statements):
        if len(alter_list) == 0:
            return

        node = alter_list[0]

        if node.type == "else_clause":
            child = self.find_child_by_field(node, "body")
            self.parse(child, statements)
            # if child:
            #     for stmt in child.named_children:
            #         self.parse(stmt, statements)
            return

        condition_part = self.find_child_by_field(node, "condition")
        true_part = self.find_child_by_field(node, "body")

        true_body = []
        #self.sync_tmp_variable(statements, true_body)
        false_body = []
        #self.sync_tmp_variable(statements, false_body)

        shadow_condition = self.parse(condition_part, statements)
        self.parse(true_part, true_body)
        self.parse_alternative(alter_list[1:], false_body)
        self.append_stmts(statements, node, {"if_stmt": {"condition": shadow_condition, "then_body": true_body,
                                  "else_body": false_body}})

    def if_statement(self, node: Node, statements: list):
        condition_part = self.find_child_by_field(node, "condition")
        true_part = self.find_child_by_field(node, "body")
        false_part = self.find_children_by_field(node, "alternative")

        true_body = []
        #self.sync_tmp_variable(statements, true_body)
        false_body = []
        #self.sync_tmp_variable(statements, false_body)

        shadow_condition = self.parse(condition_part, statements)
        self.parse(true_part, true_body)
        self.parse_alternative(false_part, false_body)

        self.append_stmts(statements, node, {"if_stmt": {"condition": shadow_condition, "then_body": true_body, "else_body": false_body}})

    def fake_if_statement(self, node, statements, false_body):
        condition_part = self.find_child_by_field(node, "condition")
        true_part = self.find_child_by_field(node, "body")

        shadow_condition = self.parse(condition_part, statements)
        true_body = []
        self.parse(true_part, true_body)

        self.append_stmts(statements, node, {"if_stmt": {"condition": shadow_condition, "then_body": true_body, "else_body": false_body}})

    def else_if_statement_list(self, node_list: list, statements: list):
        if len(node_list) == 0:
            return

        stmt_list = statements

        while len(node_list) != 0:
            current_node = node_list.pop(0)
            if current_node.type == "else_clause":
                self.parse(self.find_child_by_field(current_node, "body"), stmt_list)
                break

            # else_if_clause
            false_body = []
            self.fake_if_statement(current_node, stmt_list, false_body)

            stmt_list = false_body

    def while_statement(self, node: Node, statements: list):
        condition = self.find_child_by_field(node, "condition")
        body = self.find_child_by_field(node, "body")

        new_condition_init = []

        shadow_condition = self.parse(condition, new_condition_init)

        new_while_body = []
        self.parse(body, new_while_body)

        # 保证了条件变量名的一致性
        statements.extend(new_condition_init)
        new_while_body.extend(new_condition_init)   # 有必要，比如条件为(i++ < 5)

        self.append_stmts(statements, node, {"while_stmt": {"condition": shadow_condition, "body": new_while_body}})

    def dowhile_statement(self, node: Node, statements: list):
        body = self.find_child_by_field(node, "body")
        condition = self.find_child_by_field(node, "condition")

        do_body = []
        self.parse(body, do_body)
        shadow_condition = self.parse(condition, do_body)

        self.append_stmts(statements, node, {"dowhile_stmt": {"body": do_body, "condition": shadow_condition}})

    def for_statement(self, node: Node, statements: list):
        init = self.find_child_by_field(node, "initialize")
        condition = self.find_child_by_field(node, "condition")
        update = self.find_child_by_field(node, "update")

        init_body = []
        condition_init = []
        update_body = []

        self.parse(init, init_body)
        shadow_condition = self.parse(condition, condition_init)
        self.parse(update, update_body)

        for_body = []

        block = self.find_child_by_field(node, "body")
        self.parse(block, for_body)

        self.append_stmts(statements, node, {
            "for_stmt": {
                "init_body": init_body,
                "condition_prebody": condition_init,
                "condition": shadow_condition,
                "update_body": update_body,
                "body": for_body
            }
        })

    def foreach_statement(self, node: Node, statements: list):
        receiver = node.named_children[0]
        shadow_receiver = self.parse(receiver, statements)

        name = node.named_children[1]
        shadow_name = self.parse(name, statements)

        body = self.find_child_by_field(node, "body")
        for_body = []
        self.parse(body, for_body)

        self.append_stmts(statements, node, {"variable_decl": {"attrs": [], "name": shadow_name}})
        self.append_stmts(statements, node, {
            "for_value_stmt": {
                "name": shadow_name,
                "target": shadow_receiver,
                "body": for_body
            }
        })

    def break_statement(self, node: Node, statements: list):
        shadow_name = ""
        name = None
        if len(node.named_children) != 0:
            name = node.children[0]
        if name:
            shadow_name = self.parse(name, statements)

        self.append_stmts(statements, node, {"break_stmt": {"name": shadow_name}})

    def continue_statement(self, node: Node, statements: list):
        shadow_name = ""
        name = None
        if len(node.named_children) != 0:
            name = node.children[0]
        if name:
            shadow_name = self.parse(name, statements)

        self.append_stmts(statements, node, {"continue_stmt": {"name": shadow_name}})

    def return_statement(self, node: Node, statements: list):
        shadow_name = ""
        name = None
        if len(node.named_children) != 0:
            name = node.children[1]
        if name:
            shadow_name = self.parse(name, statements)

        self.append_stmts(statements, node, {"return_stmt": {"name": shadow_name}})
        return shadow_name

    def echo_statement(self, node: Node, statements: list):
        shadow_name = ""
        name = None
        if len(node.named_children) != 0:
            name = node.named_children[0]
        if name:
            shadow_name = self.parse(name, statements)

        self.append_stmts(statements, node, {"echo_stmt": {"name": shadow_name}})

    def exit_statement(self, node: Node, statements: list):
        shadow_name = ""
        name = None
        if len(node.named_children) != 0:
            name = node.children[0]
        if name:
            shadow_name = self.read_node_text(name)

        self.append_stmts(statements, node, {"exit_stmt": {"name": shadow_name}})

    def unset_statement(self, node: Node, statements: list):
        shadow_name = ""
        name = None
        if len(node.named_children) == 0:
            return

        for child in node.named_children:
            shadow_expr = self.parse(child, statements)
            self.append_stmts(statements, node, {"unset_stmt": {"name": shadow_expr}})

    def goto_statement(self, node: Node, statements: list):
        name = self.read_node_text(node.children[1])
        self.append_stmts(statements, node, {"goto_stmt": {"name": name}})

    def try_statement(self, node: Node, statements: list):
        try_op = {}
        try_body = []
        catch_body = []
        finally_body = []

        # 处理try
        body = self.find_child_by_field(node, "body")
        self.parse(body, try_body)
        try_op["body"] = try_body

        # 处理catch
        catch_clauses = self.find_children_by_type(node, "catch_clause")
        for catch_clause in catch_clauses:
            except_clause = {}
            exception_name = self.find_child_by_field(catch_clause, "type")
            if exception_name:
                shadow_name = self.parse(exception_name, statements)
                except_clause["expcetion"] = shadow_name

            shadow_except_clause_body = []
            except_clause_body = self.find_child_by_field(catch_clause, "body")
            self.parse(except_clause_body, shadow_except_clause_body)

            except_clause["body"] = shadow_except_clause_body
            catch_body.append({"catch_stmt": except_clause})

        try_op["catch_body"] = catch_body

        finally_clauses = self.find_children_by_type(node, "finally_clause")
        if len(finally_clauses) > 0:
            finally_clause_body = self.find_child_by_field(finally_clauses[0], "body")
            self.parse(finally_clause_body, finally_body)
            try_op["final_body"] = finally_body

        self.append_stmts(statements, node, {"try_stmt": try_op})

    def declare_statement(self, node: Node, statements: list):
        # TODO: Is this important?
        declare = self.create_empty_node_with_init_list("body")
        for each_stmt in node.named_children:
            self.parse(each_stmt, declare["body"])

        # the declare body has been prepared, but ..
        # statements.extend({"declare": declare["body"]})

    def compound_statement(self, node: Node, statements: list):
        stmts = node.named_children
        for stmt in stmts:
            if self.is_comment(stmt):
                continue
            self.parse(stmt, statements)

    def named_label_statement(self, node: Node, statements: list):
        name = node.named_children[0]
        shadow_name = self.read_node_text(name)
        self.append_stmts(statements, node, {"label_stmt": {"name": shadow_name}})

        # stmt = self.find_child_by_field(node, "body")
        # self.parse(stmt, statements)

    def is_variable_decl(self, node: Node):
        return len(node.children) == 2 and node.children[0].type == "variable_name"

    # TODO 这里const关键字不是放在field中，暂时不知道怎样取值
    def expression_statement(self, node: Node, statements: list):
        if self.is_variable_decl(node):
            self.parse_variable_name(node, statements)
        else:
            stmts = node.named_children

            for stmt in stmts:
                self.parse(stmt, statements)

    def empty_statement(self, node: Node, statements: list):
        return ""


    """
        declaration部分
    """

    def const_declaration(self, node: Node, statements: list):
        modifiers = self.read_node_pref_children(node, "const")
        modifiers.append("const")
        type = self.find_child_by_field(node, "type")
        shadow_type = self.read_node_text(type)

        const_element = self.find_children_by_type(node, "const_element")
        if const_element:
            for each_element in const_element:
                name = each_element.children[0]
                value = each_element.children[2]
                shadow_name = self.read_node_text(name)
                shadow_value = self.parse(value, statements)
                if shadow_name:
                    self.append_stmts(statements, node, {"variable_decl": {"attrs": modifiers, "data_type": shadow_type, "name": shadow_name}})
                    if shadow_value:
                        self.append_stmts(statements, node, {"assign_stmt": {"target": shadow_name, "operand": shadow_value}})

    def function_declaration(self, node: Node, statements: list):
        gir_node = {}
        attrs = self.read_node_pref_children(node, 'function')
        shadow_children = list(map(self.read_node_text, node.children))
        if "static" in shadow_children:
            if "static" not in attrs:
                attrs.append("static")
        gir_node["attrs"] = attrs

        name = self.find_child_by_field(node, "name")
        if name:
            gir_node["name"] = self.read_node_text(name)
        else:
            gir_node["name"] = self.tmp_method()

        # field: parameters and init
        gir_node["parameters"] = []
        parameters = self.find_child_by_field(node, "parameters")
        if parameters:
            self.formal_parameters(parameters, gir_node["parameters"])

        data_type = self.find_child_by_field(node, "return_type")
        gir_node["data_type"] = self.parse(data_type, statements)

        # 预先创建body，anonymous_function_use_clause中的内容需要解析到body内
        gir_node["body"] = []
        # optional field: use clause
        anonymous_function_use_clause = self.find_child_by_type(node, "anonymous_function_use_clause")
        if anonymous_function_use_clause:
            for child in anonymous_function_use_clause.named_children:
                shadow_name = self.parse(child, statements)
                gir_node["body"].append({"nonlocal_stmt": {"target": shadow_name}})
                gir_node["body"].append({"copy_stmt": {"target": "$" + shadow_name, "source": shadow_name}})

        # field: body
        body = self.find_child_by_field(node, "body")
        if node.type == "arrow_function":
            shadow_expr = self.parse(body, gir_node["body"])
            gir_node["body"].append({"return_stmt": {"name": shadow_expr}})
        else:
            if body:
                for stmt in body.named_children:
                    if self.is_comment(stmt):
                        continue
                    self.parse(stmt, gir_node["body"])

        self.append_stmts(statements, node, {"method_decl": gir_node})

        return gir_node["name"]

    def parse_variable_name(self, node: Node, statements: list):
        variable_name = self.find_child_by_type(node, "variable_name")
        shadow_name = self.read_node_text(variable_name)
        self.append_stmts(statements, node, {"variable_decl": {"name": shadow_name}})
        return shadow_name

    def formal_parameters(self, node: Node, statements: list):
        for parameter in node.named_children:
            if self.is_comment(parameter):
                continue

            attrs = []
            attr1 = self.find_child_by_field(parameter, "attributes")
            attr2 = self.find_child_by_field(parameter, "visibility")
            attr3 = self.find_child_by_field(parameter, "readonly")
            for each_attr in [attr1, attr2, attr3]:
                if each_attr:
                    attrs.append(self.read_node_text(each_attr))

            data_type = self.find_child_by_field(parameter, "type")
            name = self.find_child_by_field(parameter, "name")
            value = self.find_child_by_field(parameter, "default_value")
            shadow_data_type = self.parse(data_type, statements)
            shadow_name = self.parse(name, statements)
            shadow_value = self.parse(value, statements)

            if parameter.type == "variadic_parameter":   # 处理形参列表中的剩余参数(...arg)
                attrs.append(LIAN_INTERNAL.PACKED_POSITIONAL_PARAMETER)

            self.append_stmts(statements, node, {
                "parameter_decl": {
                    "attrs": attrs,
                    "data_type": shadow_data_type,
                    "name": shadow_name,
                    "default_value": shadow_value
                }
            })

    def namespace_definition(self, node: Node, statements: list):
        name = self.find_child_by_field(node, "name")
        body = self.find_child_by_field(node, "body")
        shadow_name = self.parse(name, statements)
        if body:
            shadow_body = []
            self.parse(body, shadow_body)
            self.append_stmts(statements, node, {"namespace_decl": {"name": shadow_name, "body": shadow_body}})
        else:
            self.append_stmts(statements, node, {"namespace_decl": {"name": shadow_name}})

    def trait_declaration(self, node: Node, statements: list):
        gir_node = {}

        gir_node["attrs"] = self.read_node_pref_children(node, "trait")
        gir_node["data_type"] = "array"
        gir_node["parameters"] = []

        if node.type in self.CLASS_TYPE_MAP:
            gir_node["attrs"].append(self.CLASS_TYPE_MAP[node.type])

        # field: name
        name = self.find_child_by_field(node, "name")
        shadow_name = ""
        if name:
            shadow_name = self.read_node_text(name)
        else:
            shadow_name = self.tmp_variable()
        gir_node["name"] = shadow_name

        # trait_body
        body = self.find_child_by_field(node, "body")
        self.trait_body(body, gir_node, statements)

        self.append_stmts(statements, node, {"method_decl": gir_node})
        return gir_node["name"]

    def trait_body(self, node, gir_node, statements):
        gir_node["body"] = []
        ret_list = []

        if not node or node.named_child_count == 0:
            return

        for each_decl in node.named_children:
            if each_decl.type == "property_declaration":
                attrs = []
                for each_child in each_decl.children:
                    # TODO 扩展type list
                    if each_child.type in ["type", "primitive_type", "property_element"]:
                        break
                    attrs.append(self.read_node_text(each_child))

                data_type = self.find_child_by_field(each_decl, "type")
                shadow_data_type = self.parse(data_type, statements)

                all_elements = self.find_children_by_type(each_decl, "property_element")
                for each_element in all_elements:
                    new_name = self.find_child_by_field(each_element, "name")
                    shadow_new_name = self.parse(new_name, gir_node["body"])
                    if shadow_new_name:
                        gir_node["body"].append({
                            "variable_decl": {
                                "attrs": attrs,
                                "data_type": shadow_data_type,
                                "name": shadow_new_name,
                            }
                        })
                    default_value = self.find_child_by_field(each_element, "default_value")
                    shadow_default_value = self.parse(default_value, gir_node["body"])
                    if shadow_default_value:
                        gir_node["body"].append({"assign_stmt": {"target": shadow_new_name, "operand": shadow_default_value}})
                    ret_list.append(shadow_new_name)

            elif each_decl.type == "const_declaration":
                modifiers = self.read_node_pref_children(each_decl, "const")
                modifiers.append("const")
                type = self.find_child_by_field(each_decl, "type")
                shadow_type = self.read_node_text(type)

                const_element = self.find_children_by_type(each_decl, "const_element")
                if const_element:
                    for each_element in const_element:
                        name = each_element.children[0]
                        shadow_name = self.read_node_text(name)
                        if shadow_name:
                            gir_node["body"].append({"variable_decl": {"attrs": modifiers, "data_type": shadow_type, "name": shadow_name}})
                            ret_list.append(shadow_name)

            elif each_decl.type == "method_declaration":
                method_node = {}
                attrs = self.read_node_pref_children(each_decl, 'function')
                shadow_children = list(map(self.read_node_text, each_decl.children))
                if "static" in shadow_children:
                    if "static" not in attrs:
                        attrs.append("static")
                method_node["attrs"] = attrs

                func_name = self.find_child_by_field(each_decl, "name")
                # 转换成匿名函数赋值。methodA(){} ==> $methodA = function(){}
                method_node["name"] = self.tmp_method()

                # field: parameters and init
                method_node["parameters"] = []
                parameters = self.find_child_by_field(each_decl, "parameters")
                if parameters:
                    self.formal_parameters(parameters, method_node["parameters"])

                data_type = self.find_child_by_field(each_decl, "return_type")
                method_node["data_type"] = self.parse(data_type, statements)

                # 预先创建body，anonymous_function_use_clause中的内容需要解析到body内
                method_node["body"] = []

                # field: body
                body = self.find_child_by_field(each_decl, "body")
                if body:
                    for stmt in body.named_children:
                        if self.is_comment(stmt):
                            continue
                        self.parse(stmt, method_node["body"])

                create_var_name = "$" + self.read_node_text(func_name)
                gir_node["body"].append({"method_decl": method_node})
                gir_node["body"].append({"variable_decl": {
                    "attrs": [],
                    "data_type": '',
                    "name": create_var_name,
                }})
                gir_node["body"].append({"assign_stmt": {
                    "data_type": '',
                    "target": create_var_name,
                    "operand": method_node["name"]
                }})

                ret_list.append(create_var_name)

        arr_name = self.tmp_variable()
        gir_node["body"].append({"new_array": {"target": arr_name}})
        for index, elem in enumerate(ret_list):
            gir_node["body"].append({"array_write": {
                "target": arr_name,
                "index": str(index),
                "source": elem,
            }})
        gir_node["body"].append({"return_stmt": {"name": arr_name}})

    def use_declaration(self, node: Node, statements: list):
        # use namespace
        if node.type == "namespace_use_declaration":
            for namespace_use_clause in node.named_children:
                prefix_name = namespace_use_clause.named_children[0]
                namespace = self.find_child_by_field(prefix_name, "prefix")
                field = self.find_child_by_type(prefix_name, "name")
                alias = self.find_child_by_field(namespace_use_clause, "alias")

                shadow_namespace = self.parse(namespace, statements)
                shadow_field = self.parse(field, statements)
                shadow_alias = self.parse(alias, statements)
                if alias:
                    self.append_stmts(statements, node, {"from_import_stmt": {"name": shadow_field, "alias": shadow_alias, "source": shadow_namespace}})
                else:
                    self.append_stmts(statements, node, {"from_import_stmt": {"name": shadow_field, "source": shadow_namespace}})

    def parse_namespace(self, child_list, subname):
        tmp_var = self.tmp_variable()
        for index, child in enumerate(child_list):
            if index == 0:
                shadow_name = tmp_var
            else:
                shadow_name += "\\" + self.read_node_text(child)
        return shadow_name

    def global_declaration(self, node: Node, statements: list):
        for name in node.named_children:
            gir_node = {}
            gir_node["attrs"] = []
            gir_node["data_type"] = []
            gir_node["name"] = []

            gir_node["attrs"].append("global")
            gir_node["name"] = self.read_node_text(name)
            self.append_stmts(statements, node, {
                "variable_decl": gir_node
            })

    def function_static_declaration(self, node: Node, statements: list):
        for static_decl in node.named_children:
            name = self.find_child_by_field(static_decl, "name")
            value = self.find_child_by_field(static_decl, "value")
            shadow_name = self.parse(name, statements)

            self.append_stmts(statements, node, {"variable_decl": {
                "attrs": ['static'],
                "name": shadow_name,
            }})

            if value:
                shadow_value = self.parse(value, statements)
                self.append_stmts(statements, node, {"assign_stmt": {
                    "target": shadow_name,
                    "operand": shadow_value,
                }})

    def enum_declaration(self, node: Node, statements: list):
        gir_node = {}
        gir_node["attrs"] = []
        gir_node["fields"] = []
        gir_node["methods"] = []
        gir_node["nested"] = []

        # attrs
        attrs = self.find_child_by_field(node, "attributes")
        if attrs:
            gir_node["attrs"].append(self.read_node_text(attrs))

        child = self.find_child_by_field(node, "name")
        gir_node["name"] = self.read_node_text(child)

        # TODO type
        type = ""
        type_list = ["primitive_type"]
        for child in node.named_children:
            if child.type in type_list:
                type = self.read_node_text(child)

        # supers
        gir_node["supers"] = []
        class_implements = self.find_child_by_type(node, "class_interface_clause")
        if class_implements:
            for each_child in class_implements.named_children:
                if each_child == "implements":
                    continue
                gir_node["supers"].append(self.read_node_text(each_child))

        # body
        child = self.find_child_by_field(node, "body")
        self.enum_body(child, gir_node, type, statements)

        self.append_stmts(statements, node, {"enum_decl": gir_node})

    def enum_body(self, node, gir_node, type, statements):
        class_init = []
        class_static_init = []
        gir_node["fields"] = []
        gir_node["methods"] = []
        gir_node["nested"] = []

        methods_body = gir_node["methods"]

        if not node or node.named_child_count == 0:
            return

        for each_decl in node.named_children:
            if each_decl.type == "enum_case":
                receiver_object = self.global_this()
                extra = class_init
                enum_constant = {}
                enum_constant["attrs"] = []
                enum_constant["name"] = []

                attrs = self.find_child_by_field(each_decl, "attributes")
                if attrs:
                    enum_constant["attrs"].extend(self.read_node_text(attrs))

                name = self.find_child_by_field(each_decl, "name")
                enum_constant["name"] = self.read_node_text(name)
                gir_node["fields"].append({
                    "variable_decl": {
                        "attrs"        : [],
                        "data_type"   : type,
                        "name"        : enum_constant["name"],
                    }
                })

                value = self.find_child_by_field(each_decl, "value")
                shadow_value = self.read_node_text(value)

                extra.append({
                    "field_write": {
                        "receiver_object"   : receiver_object,
                        "field"             : enum_constant["name"],
                        "source"            : shadow_value,
                    }
                })
            elif each_decl.type == "method_declaration":
                self.function_declaration(each_decl, methods_body)
            elif each_decl.type == "use_declaration":
                for name in each_decl.named_children:
                    create_var_name = self.tmp_variable()
                    create_call_ret = self.tmp_variable()
                    shadow_name = self.parse(name, statements)
                    class_init.append({"variable_decl": {"attrs": [], "data_type": '', "name": create_var_name}})
                    class_init.append({"call_stmt": {"target": create_call_ret, "name": shadow_name}})
                    class_init.append({"assign_stmt": {"target": create_var_name, "operand": create_call_ret}})

        if class_init:
            methods_body.insert(0, {"method_decl":{"name": LIAN_INTERNAL.CLASS_INIT, "body": class_init}})
        if class_static_init:
            methods_body.insert(0, {"method_decl":{"name": LIAN_INTERNAL.CLASS_STATIC_INIT, "body": class_init}})

    CLASS_TYPE_MAP = {
        "class_declaration": "class",
        "interface_declaration": "interface",
    }

    def class_declaration(self, node: Node, statements: list):
        gir_node = {}

        gir_node["nested"] = []
        gir_node["attrs"] = self.read_node_pref_children(node, "class")

        if node.type in self.CLASS_TYPE_MAP:
            gir_node["attrs"].append(self.CLASS_TYPE_MAP[node.type])

        # field: name
        name = self.find_child_by_field(node, "name")
        shadow_name = ""
        if name:
            shadow_name = self.read_node_text(name)
        else:
            shadow_name = self.tmp_class() # 匿名类
        gir_node["name"] = shadow_name

        # field: supers
        gir_node["supers"] = []
        class_extends = self.find_child_by_type(node, "base_clause")
        class_implements = self.find_child_by_type(node, "class_interface_clause")
        if class_extends:
            for each_child in class_extends.named_children:
                if each_child == "extends":
                    continue
                gir_node["supers"].append(self.read_node_text(each_child))
        if class_implements:
            for each_child in class_implements.named_children:
                if each_child == "implements":
                    continue
                gir_node["supers"].append(self.read_node_text(each_child))

        # class_body
        body = self.find_child_by_field(node, "body")
        self.class_body(body, gir_node, statements)

        self.append_stmts(statements, node, {"class_decl": gir_node})
        return shadow_name

    def class_body(self, node, gir_node, statements):
        class_init = []
        class_static_init = []
        gir_node["methods"] = []
        gir_node["fields"] = []
        gir_node["nested"] = []

        methods_body = gir_node["methods"]

        if not node or node.named_child_count == 0:
            return

        for each_decl in node.named_children:
            if each_decl.type == "property_declaration":
                self.member_property_decl(each_decl, gir_node, statements, class_init, class_static_init)
            elif each_decl.type == "const_declaration":
                self.member_const_declaration(each_decl, gir_node, statements, class_init, class_static_init)
            elif each_decl.type == "method_declaration":
                self.function_declaration(each_decl, methods_body)
            elif each_decl.type == "use_declaration":
                for name in each_decl.named_children:
                    create_var_name = self.tmp_variable()
                    create_call_ret = self.tmp_variable()
                    shadow_name = self.parse(name, statements)
                    class_init.append({"variable_decl": {"attrs": [], "data_type": '', "name": create_var_name}})
                    class_init.append({"call_stmt": {"target": create_call_ret, "name": shadow_name}})
                    class_init.append({"assign_stmt": {"target": create_var_name, "operand": create_call_ret}})

        if class_init:
            methods_body.insert(0, {"method_decl":{"name": LIAN_INTERNAL.CLASS_INIT, "body": class_init}})
        if class_static_init:
            methods_body.insert(0, {"method_decl":{"name": LIAN_INTERNAL.CLASS_STATIC_INIT, "body": class_init}})

    def member_property_decl(self, each_decl, gir_node, statements, class_init, class_static_init):
        attrs = []
        for each_child in each_decl.children:
            # TODO 扩展type list
            if each_child.type in ["type", "primitive_type", "property_element"]:
                break
            attrs.append(self.read_node_text(each_child))

        target_body = class_init
        if "static" in attrs:
            target_body = class_static_init

        data_type = self.find_child_by_field(each_decl, "type")
        shadow_data_type = self.parse(data_type, statements)

        all_elements = self.find_children_by_type(each_decl, "property_element")
        for each_element in all_elements:
            new_name = self.find_child_by_field(each_element, "name")
            shadow_new_name = self.parse(new_name, target_body)
            if shadow_new_name:
                gir_node["fields"].append({
                    "variable_decl": {
                        "attrs": attrs,
                        "data_type": shadow_data_type,
                        "name": shadow_new_name,
                    }
                })
            default_value = self.find_child_by_field(each_element, "default_value")
            shadow_default_value = self.parse(default_value, target_body)
            if shadow_default_value:
                target_body.append({"assign_stmt": {"target": shadow_new_name, "operand": shadow_default_value}})

        # # TODO 处理hooks
        # all_hooks = self.find_child_by_type(each_decl, "property_hook_list")
        # if all_hooks:
        #     for each_hook in all_hooks:
        #         name = self.find_child_by_type(each_hook, "name")
        #         body = self.find_child_by_field(each_hook, "body")
        #         shadow_name = self.parse(name, target_body)

    def member_const_declaration(self, each_decl, gir_node, statements, class_init, class_static_init):
        modifiers = self.read_node_pref_children(each_decl, "const")
        modifiers.append("const")
        type = self.find_child_by_field(each_decl, "type")
        shadow_type = self.read_node_text(type)

        const_element = self.find_children_by_type(each_decl, "const_element")
        if const_element:
            for each_element in const_element:
                name = each_element.children[0]
                value = each_element.children[2]
                shadow_name = self.read_node_text(name)
                shadow_value = self.parse(value, statements)
                if shadow_name:
                    gir_node["fields"].append({"variable_decl": {"attrs": modifiers, "data_type": shadow_type, "name": shadow_name}})
                    if shadow_value:
                        class_init.append({"assign_stmt": {"target": shadow_name, "operand": shadow_value}})


    def field_definition(self, node: Node, statements: list):
        attrs = []
        shadow_children = list(map(self.read_node_text, node.children))
        if "static" in shadow_children:
            attrs.append("static")

        attribute = self.find_child_by_type(node, "visibility_modifier")
        if attribute:
            attrs.append(self.read_node_text(attribute))
        prop_elem = self.find_child_by_type(node, "property_element")
        prop_name = self.find_child_by_type(prop_elem, "variable_name")
        shadow_name = self.parse(prop_name, statements)
        shadow_value = ''

        init_value = self.find_child_by_field(prop_elem, "default_value")
        if init_value:
            shadow_value = self.parse(init_value, statements)
            self.append_stmts(statements, node, {"field_write": {"receiver_object": self.global_this(),
                                               "field": shadow_name, "source": shadow_value}})

        # 最后加入variable_decl，是为了便于之后将其从init移入fields
        self.append_stmts(statements, node, {"variable_decl": {"attrs": attrs, "name": shadow_name}})
        return (shadow_name, shadow_value)

    def obtain_literal_handler(self, node):
        return self.LITERAL_MAP.get(node.type, None)

    def is_literal(self, node):
        return self.obtain_literal_handler(node) is not None

    def literal(self, node: Node, statements: list, replacement: list):
        handler = self.obtain_literal_handler(node)
        return handler(node, statements, replacement)

    def check_declaration_handler(self, node):
        return self.DECLARATION_HANDLER_MAP.get(node.type, None)

    def is_declaration(self, node):
        return self.check_declaration_handler(node) is not None

    def declaration(self, node: Node, statements: list):
        handler = self.check_declaration_handler(node)
        return handler(node, statements)

    def check_expression_handler(self, node):
        return self.EXPRESSION_HANDLER_MAP.get(node.type, None)

    def is_expression(self, node):
        return self.check_expression_handler(node) is not None

    def expression(self, node: Node, statements: list):
        handler = self.check_expression_handler(node)
        return handler(node, statements)

    def check_statement_handler(self, node):
        return self.STATEMENT_HANDLER_MAP.get(node.type, None)

    def is_statement(self, node):
        return self.check_statement_handler(node) is not None

    def statement(self, node: Node, statements: list):
        handler = self.check_statement_handler(node)
        return handler(node, statements)
