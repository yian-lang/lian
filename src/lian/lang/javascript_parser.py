#!/usr/bin/env python3

import re
from tree_sitter import Node
from lian.lang import common_parser
from lian.util import util
from lian.config.constants import LIAN_INTERNAL

import os

class Parser(common_parser.Parser):
    def obtain_literal_handler(self, node):
        LITERAL_MAP = {
            "number"                            : self.regular_number_literal,
            "true"                              : self.regular_literal,
            "false"                             : self.regular_literal,
            "null"                              : self.regular_literal,
            "undefined"                         : self.regular_literal,
            "regex"                             : self.regular_literal,
            "template_string"                   : self.template_string,
            "string"                            : self.string_literal,
            "string_fragment"                   : self.string_literal,
            "escape_sequence"                   : self.string_literal,
            "summary_string"                    : self.string_literal,
            "summary_substitution"              : self.summary_substitution,
            "this"                              : self.this_literal,
            "super"                             : self.super_literal,
        }

        return LITERAL_MAP.get(node.type, None)

    def check_declaration_handler(self, node):
        DECLARATION_HANDLER_MAP = {
            "function_declaration"            : self.function_declaration,
            "generator_function_declaration"  : self.function_declaration,
            "class_declaration"               : self.class_declaration,
            "lexical_declaration"             : self.variable_declaration,
            "variable_declaration"            : self.variable_declaration,
        }

        return DECLARATION_HANDLER_MAP.get(node.type, None)

    def check_expression_handler(self, node):
        EXPRESSION_HANDLER_MAP = {
            "subscript_expression"              : self.subscript_expression,
            "member_expression"                 : self.member_expression,
            "object"                            : self.new_object,
            # "object_pattern"                    : self.object_pattern,
            "array"                             : self.new_array,
            "function_expression"               : self.function_declaration,
            "arrow_function"                    : self.function_declaration,
            "generator_function"                : self.function_declaration,
            "class"                             : self.class_declaration,
            # "meta_property"
            "call_expression"                   : self.call_expression,
            "decorator_call_expression"         : self.call_expression,
            # "glimmer_template"
            "assignment_expression"             : self.assignment_expression,
            "augmented_assignment_expression"   : self.assignment_expression,
            "await_expression"                  : self.await_expression,
            "unary_expression"                  : self.unary_expression,
            "binary_expression"                 : self.binary_expression,
            "ternary_expression"                : self.ternary_expression,
            "update_expression"                 : self.update_expression,
            "new_expression"                    : self.new_expression,
            "yield_expression"                  : self.yield_expression,
        }

        return EXPRESSION_HANDLER_MAP.get(node.type, None)

    def check_statement_handler(self, node):
        STATEMENT_HANDLER_MAP = {
            "export_statement"            : self.export_statement,
            "import_statement"            : self.import_statement,
            # "debugger_statement"          : self.debugger_statement,
            "if_statement"                : self.if_statement,
            "switch_statement"            : self.switch_statement,
            "for_statement"               : self.for_statement,
            "for_in_statement"            : self.each_statement,
            "while_statement"             : self.while_statement,
            "do_statement"                : self.dowhile_statement,
            "try_statement"               : self.try_statement,
            "with_statement"              : self.with_statement,
            "break_statement"             : self.break_statement,
            "continue_statement"          : self.continue_statement,
            "return_statement"            : self.return_statement,
            "throw_statement"             : self.throw_statement,
            "empty_statement"             : self.empty_statement,
            "labeled_statement"           : self.labeled_statement,
        }
        return STATEMENT_HANDLER_MAP.get(node.type, None)

    def parse_path(self, path):
        """
        解析文件路径，返回一个由目录组成的字符串（用点号分隔）和不带后缀的文件名。

        :param path: 文件的完整路径（可以是绝对路径、相对路径或仅文件名）
        :return: (dirpath, filename) 其中 dirpath 是由目录组成的字符串，filename 是不带后缀的文件名
        """
        # 处理相对路径
        if path.startswith('./'):
            path = path[2:]

        # 分割路径为目录和文件名
        dir_path, full_filename = os.path.split(path)

        # 用于存储所有目录名
        directories = []

        # 如果路径是绝对路径，去掉开头的斜杠
        if os.path.isabs(path):
            dir_path = dir_path[1:]

        # 循环分割目录，直到没有更多目录
        while dir_path:
            dir_path, dir_name = os.path.split(dir_path)
            # 去掉路径起始位置的 .
            if dir_name and dir_name != '".' and dir_name!= "'.":
                directories.append(dir_name)

        # 反转目录列表，使其从根目录到最内层目录
        directories.reverse()

        # 使用点号连接所有目录名
        dirpath = '.'.join(directories) if directories else ''

        # 分离文件名和后缀
        filename, _ = os.path.splitext(full_filename)

        return dirpath, filename

    def pack_args(self, node, statements: list):
        tmp_var = self.tmp_variable()
        self.append_stmts(statements, node, {
            "new_array": {
                "target": tmp_var
            }
        })

        meet_splat = False
        for index, arg in enumerate(node.named_children):
            if self.is_comment(arg):
                continue

            if arg.type == "spread_element":
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
        expression(含literal)部分
    """

    def is_identifier(self, node):
        identifier_list = [
            "identifier",
            "property_identifier",
            "private_property_identifier"
        ]
        return node.type in identifier_list

    def regular_number_literal(self, node: Node, statements: list, replacement: list):
        value = self.read_node_text(node)
        value = self.common_eval(value)
        return str(value)

    def regular_literal(self, node: Node, statements: list, replacement: list):
        return self.read_node_text(node)

    def this_literal(self, node: Node, statements: list, replacement: list):
        return self.global_this()

    def super_literal(self, node: Node, statements: list, replacement: list):
        return self.global_super()

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

    def template_string(self, node: Node, statements: list, replacement: list):
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

    def summary_substitution(self, node: Node, statements: list, replacement: list):
        expr = node.named_children[0]
        shadow_expr = self.parse(expr, statements)
        replacement.append((expr, shadow_expr))
        return shadow_expr

    def binary_expression(self, node: Node, statements: list):
        left = self.find_child_by_field(node, "left")
        right = self.find_child_by_field(node, "right")
        operator = self.find_child_by_field(node, "operator")

        shadow_operator = self.read_node_text(operator)

        shadow_left = self.parse(left, statements)
        shadow_right = self.parse(right, statements)

        tmp_var = self.tmp_variable()
        self.append_stmts(statements, node, {
            "assign_stmt": {
                "target": tmp_var, "operator": shadow_operator, "operand": shadow_left, "operand2": shadow_right
            }})

        return tmp_var

    def unary_expression(self, node: Node, statements: list):
        operand = self.find_child_by_field(node, "argument")
        shadow_operand = self.parse(operand, statements)
        operator = self.find_child_by_field(node, "operator")
        shadow_operator = self.read_node_text(operator)

        tmp_var = self.tmp_variable()

        self.append_stmts(statements, node, {"assign_stmt": {"target": tmp_var, "operator": shadow_operator, "operand": shadow_operand}})
        return tmp_var

    def ternary_expression(self, node: Node, statements: list):
        condition = self.find_child_by_field(node, "condition")
        consequence = self.find_child_by_field(node, "consequence")
        alternative = self.find_child_by_field(node, "alternative")

        condition = self.parse(condition, statements)

        then_body = []
        else_body = []
        tmp_var = self.tmp_variable()

        expr1 = self.parse(consequence, then_body)
        then_body.append({"assign_stmt": {"target": tmp_var, "operand": expr1}})

        expr2 = self.parse(alternative, else_body)
        else_body.append({"assign_stmt": {"target": tmp_var, "operand": expr2}})

        self.append_stmts(statements, node, {"if_stmt": {"condition": condition, "then_body": then_body, "else_body": else_body}})
        return tmp_var

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
        if expression.type == "member_expression":
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
        operator = self.find_child_by_field(node, "operator")
        shadow_operator = self.read_node_text(operator).replace("=", "")

        shadow_right = self.parse(right, statements)

        if left.type == "member_expression":
            object = self.find_child_by_field(left, "object")
            field = self.find_child_by_field(left, "property")
            shadow_object, shadow_field = self.parse_field(left, statements)
            if not shadow_operator:
                # 处理module.exports
                if shadow_object == "module" and shadow_field == "exports":
                    self.append_stmts(statements, node, {
                        "export_stmt": {
                            "name": shadow_right
                        }
                    })
                    return

                # 处理exports.xxx
                elif shadow_object == "exports":
                    self.append_stmts(statements, node, {
                        "export_stmt": {
                            "name": shadow_right,
                            "alias": shadow_field
                        }
                    })
                    return shadow_field

                # 处理module.exports.xxx
                elif object.type == "member_expression":
                    object2 = self.find_child_by_field(object, "object")
                    field2 = self.find_child_by_field(object, "property")
                    shadow_object2 = self.read_node_text(object2)
                    shadow_field2 = self.read_node_text(field2)
                    if shadow_object2 == "module" and shadow_field2 == "exports":
                        self.append_stmts(statements, node, {
                            "export_stmt": {"name": shadow_right, "alias": shadow_field}
                        })
                        return shadow_field
                    else:
                        self.append_stmts(statements, node,
                            {"field_write": {"receiver_object": shadow_object, "field": shadow_field, "source": shadow_right}})
                        return shadow_right

                # 其他情况正常处理
                else:
                    self.append_stmts(statements, node, {
                        "field_write": {
                            "receiver_object": shadow_object,
                            "field": shadow_field,
                            "source": shadow_right
                        }
                    })
                    return shadow_right

            tmp_var = self.tmp_variable()
            self.append_stmts(statements, node, {"field_read": {"target": tmp_var, "receiver_object": shadow_object, "field": shadow_field}})
            tmp_var2 = self.tmp_variable()
            self.append_stmts(statements, node, {"assign_stmt":
                                   {"target": tmp_var2, "operator": shadow_operator,
                                    "operand": tmp_var, "operand2": shadow_right}})
            self.append_stmts(statements, node, {"field_write": {"receiver_object": shadow_object, "field": shadow_field, "source": tmp_var2}})

            return tmp_var2

        if left.type == "subscript_expression":
            shadow_array, shadow_index = self.parse_array(left, statements)

            if not shadow_operator:
                self.append_stmts(statements, node, {"array_write": {"array": shadow_array, "index": shadow_index, "source": shadow_right}})
                return shadow_right

            tmp_var = self.tmp_variable()
            self.append_stmts(statements, node, {"array_read": {"target": tmp_var, "array": shadow_array, "index": shadow_index}})
            tmp_var2 = self.tmp_variable()
            self.append_stmts(statements, node, {"assign_stmt": {"target": tmp_var2, "operator": shadow_operator,
                                    "operand": tmp_var, "operand2": shadow_right}})
            self.append_stmts(statements, node, {"array_write": {"array": shadow_array, "index": shadow_index, "source": tmp_var2}})

            return tmp_var2

        # 数组解构
        if left.type == "array_pattern":
            index = 0
            # 处理空格
            previous_was_comma = False
            encountered_open_bracket = False

            for p in left.children:
                if self.is_comment(p):
                    previous_was_comma = False
                    encountered_open_bracket = False
                    continue
                elif p.type == "[" or p.type == "]":
                    previous_was_comma = False
                    encountered_open_bracket = True
                    continue
                elif p.type == ",":
                    if previous_was_comma or encountered_open_bracket:
                        index += 1
                    previous_was_comma = True
                    encountered_open_bracket = False
                    continue
                else:
                    previous_was_comma = False
                    encountered_open_bracket = False
                    elem = self.parse(p, statements)
                    self.append_stmts(statements, node, {"array_read": {"target": elem, "array": shadow_right, "index": str(index)}})
                index += 1

            return shadow_right

        # 对象解构
        if left.type == "object_pattern":
            for p in left.named_children:
                if self.is_comment(p):
                    continue

                if p.type == "shorthand_property_identifier_pattern":
                    pattern = self.read_node_text(p)

                    self.append_stmts(statements, node, {"field_read": {"target": pattern, "receiver_object": shadow_right, "field": pattern}})
                elif p.type == "pair_pattern":
                    left_child = self.find_child_by_field(p, "key")
                    right_child = self.find_child_by_field(p, "value")

                    shadow_left_child = self.property_name(left_child, statements)
                    shadow_right_child = self.parse(right_child, statements)

                    self.append_stmts(statements, node, {"field_read": {"target": shadow_right_child, "receiver_object": shadow_right, "field": shadow_left_child}})

            return shadow_right

        shadow_left = self.read_node_text(left)
        if not shadow_operator:
            self.append_stmts(statements, node, {"variable_decl": {"name": shadow_left, "attrs": ["global"]}})
            self.append_stmts(statements, node, {"assign_stmt": {"target": shadow_left, "operand": shadow_right}})
        else:
            self.append_stmts(statements, node, {"assign_stmt": {"target": shadow_left, "operator": shadow_operator,
                                               "operand": shadow_left, "operand2": shadow_right}})
        return shadow_left

    def parse_field(self, node: Node, statements: list):
        myobject = self.find_child_by_field(node, "object")
        field = self.find_child_by_field(node, "property")
        shadow_object = self.parse(myobject, statements)
        shadow_field = self.parse(field, statements)

        return (shadow_object, shadow_field)

    def member_expression(self, node: Node, statements: list):
        shadow_object, shadow_field = self.parse_field(node, statements)
        tmp_var = self.tmp_variable()
        self.append_stmts(statements, node, {"field_read": {"target": tmp_var, "receiver_object": shadow_object, "field": shadow_field}})
        return tmp_var

    def parse_array(self, node: Node, statements: list):
        array = self.find_child_by_field(node, "object")
        shadow_object = self.parse(array, statements)

        index = self.find_child_by_field(node, "index")
        shadow_index = self.parse(index, statements)
        return (shadow_object, shadow_index)

    # 使用[]方式访问Object，本质上与数组访问相同
    def subscript_expression(self, node: Node, statements: list):
        array = self.find_child_by_field(node, "object")
        shadow_array = self.parse(array, statements)
        subscript = self.find_child_by_field(node, "index")

        if subscript is None:
            tmp_array = self.tmp_variable()
            self.append_stmts(statements, node, {"array_read": {"target": tmp_array, "array": shadow_array, "index": ""}})
            return tmp_array

        tmp_array = self.tmp_variable()
        shadow_index = self.parse(subscript, statements)
        self.append_stmts(statements, node, {"array_read": {"target": tmp_array, "array": shadow_array, "index": shadow_index}})
        shadow_array = tmp_array
        return tmp_array

    def call_expression(self, node: Node, statements: list):
        if node.type == "decorator_call_expression":
            return


        name = self.find_child_by_field(node, "function")
        if name.type == "member_expression":
           shadow_object, shadow_name = self.parse_field(name, statements)
        else:
            shadow_name = self.parse(name, statements)

        args = self.find_child_by_field(node, "arguments")

        # 处理参数列表，主要处理解包
        positional_args = []
        packed_positional_args = None
        if args.named_child_count > 0:
            spread_elem_children = self.find_children_by_type(args, "spread_element")
            if spread_elem_children:
                packed_positional_args = self.pack_args(args, statements)
            else:
                for child in args.named_children:
                    if child.type not in ["spread_element"]:
                        shadow_expr = self.parse(child, statements)
                        positional_args.append(shadow_expr)

        tmp_return = self.tmp_variable()

        if name.type == "member_expression":
            self.append_stmts(statements, node, {
                "object_call_stmt": {"target": tmp_return, "field": shadow_name, "receiver_object": shadow_object,
                                "positional_args": positional_args,
                        "packed_positional_args": packed_positional_args,}})
        else:
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

    # 以[]的形式创建新数组，例如let arr = [1, 2, 3]
    def new_array(self, node: Node, statements: list):
        # 创建数组
        tmp_var = self.tmp_variable()
        self.append_stmts(statements, node, {"new_array": {"target": tmp_var}})

        # 写入数组
        index = 0
        previous_was_comma = False
        encountered_open_bracket = False
        meet_spread = False
        for p in node.children:
            if self.is_comment(p):
                previous_was_comma = False
                encountered_open_bracket = False
                continue
            if p.type == "[" or p.type == "]":
                previous_was_comma = False
                encountered_open_bracket = True
                continue
            if p.type == ",":
                if previous_was_comma or encountered_open_bracket:
                    index += 1
                previous_was_comma = True
                encountered_open_bracket = False
                continue
            previous_was_comma = False
            encountered_open_bracket = False
            if p.type == "spread_element":
                meet_spread = True
                pattern = self.parse(p, statements)
                self.append_stmts(statements, node, {"array_extend": {"array": tmp_var, "source": pattern}})

            else:
                if meet_spread:
                    pattern = self.parse(p, statements)
                    self.append_stmts(statements, node, {"array_append": {"array": tmp_var, "source": pattern}})
                else:
                    pattern = self.parse(p, statements)
                    self.append_stmts(statements, node, {"field_write": {"receiver_object": tmp_var, "field": str(index), "source": pattern}})
            index += 1
        # for child in node.named_children:
        #     if self.is_comment(child):
        #         continue

        #     shadow_child = self.parse(child, statements)
        #     self.append_stmts(statements, node, {"array_write": {"array": tmp_var, "index": str(index), "source": shadow_child}})
        #     index += 1

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

    # 以{}的形式创建Object，例如let obj = { name: "Alice"}
    def new_object(self, node: Node, statements: list):
        # 创建Object
        tmp_var = self.tmp_variable()
        self.append_stmts(statements, node, {"new_object": {"data_type": LIAN_INTERNAL.OBJECT, "target": tmp_var}})

        # 写入Object
        for child in node.named_children:
            if self.is_comment(child):
                continue

            shadow_key = ""
            shadow_value = ""

            if child.type == "pair":
                # 处理键值对
                shadow_key, shadow_value = self.parse_pair(child, statements)
            elif child.type == "method_definition":
                """
                    处理方法定义, 例如下面的sayHello方法, 这里的处理方式为:
                        将sayHello当作obj的一个field, field对应的value为一个名为sayHello的函数
                    const obj = {
                        sayHello(){

                        }
                    }
                """
                name = self.find_child_by_field(child, "name")
                shadow_key = self.property_name(name, statements)
                shadow_value = self.function_declaration(child, statements)
            elif child.type == "spread_element":
                shadow_key = shadow_value = self.parse(child.named_children[0], statements)
                self.append_stmts(statements, node, {"record_extend": {"record": tmp_var, "source": shadow_key}})
            elif child.type == "shorthand_property_identifier":
                shadow_key = shadow_value = self.read_node_text(child)

                self.append_stmts(statements, node, {"field_read": {"target": shadow_key, "receiver_object": tmp_var, "field": shadow_key}})

            self.append_stmts(statements, node, {"field_write": {"receiver_object": tmp_var, "field": shadow_key, "source": shadow_value}})

        return tmp_var

    # 处理new data_type(args)
    def new_expression(self, node: Node, statements: list):
        gir_node = {}

        mytype = self.find_child_by_field(node, "constructor")
        if mytype is None:
            tmp_var = self.tmp_variable()
            gir_node["data_type"] = ""
            gir_node["args"] = []
            gir_node["target"] = tmp_var
            self.append_stmts(statements, node, {"new_object": gir_node})
            return tmp_var
        shadow_mytype = self.read_node_text(mytype)
        gir_node["data_type"] = shadow_mytype

        arguments = self.find_child_by_field(node, "arguments")
        arguments_list = []
        # 处理形如 new Date，可以不加参数
        if arguments:
            if arguments.named_child_count > 0:
                for arg in arguments.named_children:
                    if self.is_comment(arg):
                        continue

                    shadow_arg = self.parse(arg, statements)
                    if shadow_arg:
                        arguments_list.append(shadow_arg)

        gir_node["positional_args"] = arguments_list

        tmp_var = self.tmp_variable()
        gir_node["target"] = tmp_var

        self.append_stmts(statements, node, {"new_object": gir_node})
        return tmp_var

    def await_expression(self, node: Node, statements: list):
        expr = node.named_children[0]
        shadow_expr = self.parse(expr, statements)

        self.append_stmts(statements, node, {"await_stmt": {"target": shadow_expr}})
        return shadow_expr

    def yield_expression(self, node: Node, statements: list):
        shadow_expr = ""
        if node.named_child_count > 0:
            expr = node.named_children[0]
            shadow_expr = self.parse(expr, statements)

        self.append_stmts(statements, node, {"yield_stmt": {"name": shadow_expr}})
        return shadow_expr



    """
        statement部分
    """

    def return_statement(self, node: Node, statements: list):
        shadow_name = "undefined"   # 单用return时，返回undefined
        if node.named_child_count > 0:
            name = node.named_children[0]
            shadow_name = self.parse(name, statements)

        self.append_stmts(statements, node, {"return_stmt": {"name": shadow_name}})
        return shadow_name

    def if_statement(self, node: Node, statements: list):
        condition_part = self.find_child_by_field(node, "condition")
        true_part = self.find_child_by_field(node, "consequence")
        false_part = self.find_child_by_field(node, "alternative")

        true_body = []

        shadow_condition = self.parse(condition_part, statements)
        self.parse(true_part, true_body)

        if false_part:
            false_body = []
            self.parse(false_part, false_body)
            self.append_stmts(statements, node, {"if_stmt": {"condition": shadow_condition, "then_body": true_body, "else_body": false_body}})
        else:
            self.append_stmts(statements, node, {"if_stmt": {"condition": shadow_condition, "then_body": true_body}})

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
        init = self.find_child_by_field(node, "initializer")
        condition = self.find_child_by_field(node, "condition")
        update = self.find_child_by_field(node, "increment")

        init_body = []
        condition_init = []
        update_body = []

        self.parse(init, init_body)
        shadow_condition = self.parse(condition, condition_init)
        self.parse(update, update_body)

        for_body = []

        block = self.find_child_by_field(node, "body")
        self.parse(block, for_body)

        self.append_stmts(statements, node, {"for_stmt":
                               {"init_body": init_body,
                                "condition_prebody": condition_init,
                                "condition": shadow_condition,
                                "update_body": update_body,
                                "body": for_body}})

    def each_statement(self, node: Node, statements: list):
        kind = self.find_child_by_field(node, "kind")
        modifiers = self.read_node_text(kind).split()

        name = self.find_child_by_field(node, "left")
        shadow_name = self.parse(name, statements)

        operator = self.find_child_by_field(node, "operator")
        shadow_operator = self.read_node_text(operator)

        receiver = self.find_child_by_field(node, "right")
        shadow_receiver = self.parse(receiver, statements)

        body = self.find_child_by_field(node, "body")
        for_body = []
        self.parse(body, for_body)

        self.append_stmts(statements, node, {"variable_decl": {"attrs": modifiers, "name": shadow_name}})
        if shadow_operator == "in":
            self.append_stmts(statements, node, {
                "forin_stmt": {
                    "attrs": modifiers,
                    "name": shadow_name,
                    "receiver": shadow_receiver,
                    "body": for_body
                }
            })
        else:
            self.append_stmts(statements, node, {
                "for_value_stmt": {
                    "attrs": modifiers,
                    "name": shadow_name,
                    "target": shadow_receiver,
                    "body": for_body
                }
            })

        # child = self.find_child_by_field(node, "kind")
        # modifiers = self.read_node_text(child).split()

        # # target = self.tmp_variable()

        # left = self.find_child_by_field(node, "left")
        # for_body = []
        # if left.type == "array_pattern":
        #     '''
        #         for (const [key, value] of iterable) {
        #             console.log(value);
        #         }
        #         对于这种形式的语句, forin_stmt指令中的name为一个临时变量,
        #             在body中将该临时变量解构赋值给key与value
        #     '''
        #     shadow_name = self.tmp_variable()

        #     index = 0
        #     # 处理空格
        #     previous_was_comma = False
        #     encountered_open_bracket = False

        #     for p in left.children:
        #         if self.is_comment(p):
        #             previous_was_comma = False
        #             encountered_open_bracket = False
        #             continue
        #         elif p.type == "[" or p.type == "]":
        #             previous_was_comma = False
        #             encountered_open_bracket = True
        #             continue
        #         elif p.type == ",":
        #             if previous_was_comma or encountered_open_bracket:
        #                 index += 1
        #             previous_was_comma = True
        #             encountered_open_bracket = False
        #             continue
        #         else:
        #             previous_was_comma = False
        #             encountered_open_bracket = False
        #             elem = self.parse(p, statements)
        #             self.append_stmts(statements, node, {"array_read": {"target": elem, "array": shadow_name, "index": str(index)}})
        #         index += 1
        # else:
        #     shadow_name = self.parse(left, statements)

        # right = self.find_child_by_field(node, "right")
        # shadow_value = self.parse(right, statements)

        # self.append_stmts(statements, node, {"assign_stmt": {"target": target, "operand": '0'}})
        # length = self.tmp_variable()
        # self.append_stmts(statements, node, {"call_stmt": {"target": length, "name": "len", "positional_args": [shadow_value]}})
        # condition = self.tmp_variable()
        # self.append_stmts(statements, node, {"assign_stmt": {"target": condition, "operand": target, "operand2": length, "operator": '<'}})

        # # condition = self.tmp_variable()
        # tmp_var = self.tmp_variable()
        # for_body.append({"array_read": {"target": tmp_var, "array": shadow_value, "index": target}})
        # for_body.append({"assign_stmt": {"target": shadow_name, "operand": tmp_var}})
        # for_body.append({"assign_stmt": {"target": target, "operand": target, "operand2": '1', "operator": '+'}})
        # body = self.find_child_by_field(node, "body")
        # self.parse(body, for_body)

        # self.append_stmts(statements, node, {"while_stmt": {"attrs": modifiers, "condition": condition, "body": for_body}})

    def break_statement(self, node: Node, statements: list):
        shadow_name = ""
        name = self.find_child_by_field(node, "label")
        if name:
            shadow_name = self.read_node_text(name)

        self.append_stmts(statements, node, {"break_stmt": {"name": shadow_name}})

    def continue_statement(self, node: Node, statements: list):
        shadow_name = ""
        name = self.find_child_by_field(node, "label")
        if name:
            shadow_name = self.read_node_text(name)

        self.append_stmts(statements, node, {"continue_stmt": {"name": shadow_name}})

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
        catch_clause = self.find_child_by_field(node, "handler")
        if catch_clause:
            catch_op = {}
            shadow_catch_clause_body = []

            condition = self.find_child_by_field(catch_clause, "parameter")
            if condition:
                if condition.type == "array_pattern":
                    # 处理例如catch([a, b])

                    shadow_condition = self.tmp_variable()
                    shadow_catch_clause_body.append({"parameter_decl": {"attrs": [], "name": shadow_condition}})
                    index = 0
                    # 处理空格
                    previous_was_comma = False
                    encountered_open_bracket = False

                    for p in condition.children:
                        if self.is_comment(p):
                            previous_was_comma = False
                            encountered_open_bracket = False
                            continue
                        elif p.type == "[" or p.type == "]":
                            previous_was_comma = False
                            encountered_open_bracket = True
                            continue
                        elif p.type == ",":
                            if previous_was_comma or encountered_open_bracket:
                                index += 1
                            previous_was_comma = True
                            encountered_open_bracket = False
                            continue
                        else:
                            previous_was_comma = False
                            encountered_open_bracket = False
                            elem = self.parse(p, statements)
                            shadow_catch_clause_body.append({"array_read": {"target": elem, "array": shadow_condition, "index": str(index)}})
                        index += 1

                elif condition.type == "object_pattern":
                    # 处理例如catch({a, b})或catch({a: v1, b: v2})

                    shadow_condition = self.tmp_variable()
                    shadow_catch_clause_body.append({"parameter_decl": {"attrs": [], "name": shadow_condition}})

                    for p in condition.named_children:
                        if self.is_comment(p):
                            continue

                        if p.type == "shorthand_property_identifier_pattern":
                            name = self.read_node_text(p)

                            shadow_catch_clause_body.append({"field_read": {"target": name, "receiver_object": shadow_condition, "field": name}})
                        elif p.type == "pair_pattern":
                            left_child = self.find_child_by_field(p, "key")
                            right_child = self.find_child_by_field(p, "value")

                            shadow_left_child = self.property_name(left_child, statements)
                            shadow_right_child = self.parse(right_child, catch_body)

                            shadow_catch_clause_body.append({"field_read": {"target": shadow_right_child, "receiver_object": shadow_condition, "field": shadow_left_child}})

                else:
                    shadow_condition = self.parse(condition, catch_body)

                catch_op["exception"] = shadow_condition

            catch_clause_body = self.find_child_by_field(catch_clause, "body")
            self.parse(catch_clause_body, shadow_catch_clause_body)
            catch_op["body"] = shadow_catch_clause_body
            catch_body.append({"catch_clause": catch_op})

        try_op["catch_body"] = catch_body

        # 处理finally
        finally_clause = self.find_child_by_field(node, "finalizer")
        if finally_clause:
            finally_clause_body = self.find_child_by_field(finally_clause, "body")
            self.parse(finally_clause_body, finally_body)
        try_op["final_body"] = finally_body

        self.append_stmts(statements, node, {"try_stmt": try_op})

    def throw_statement(self, node: Node, statements: list):
        shadow_expr = ""
        if node.named_child_count > 0:
            expr = node.named_children[0]
            shadow_expr = self.parse(expr, statements)
        self.append_stmts(statements, node, {"throw_stmt": {"name": shadow_expr}})

    def labeled_statement(self, node: Node, statements: list):
        name = self.find_child_by_field(node, "label")

        shadow_name = self.read_node_text(name)
        self.append_stmts(statements, node, {"label_stmt": {"name": shadow_name}})

        stmt = self.find_child_by_field(node, "body")
        self.parse(stmt, statements)

    def with_statement(self, node: Node, statements: list):
        obj = self.find_child_by_field(node, "object")
        body = self.find_child_by_field(node, "body")

        shadow_obj = self.parse(obj, statements)

        with_body = []
        self.parse(body, with_body)

        # 由于with_init不适用于JavaScript，因此这里给with_stmt加了一个名为name的field
        self.append_stmts(statements, node, {"with_stmt": {"name": shadow_obj, "body": with_body}})

    def switch_statement(self, node: Node, statements: list):
        condition = self.find_child_by_field(node, "value")
        shadow_condition = self.parse(condition, statements)

        switch_block = self.find_child_by_field(node, "body")

        switch_stmt_list = []

        for child in switch_block.named_children:
            if self.is_comment(child):
                continue

            stmts = self.find_children_by_field(child, "body")
            if child.type == "switch_default":
                if len(stmts) == 0:
                    continue

                new_body = []
                for default_stmt in stmts:
                    self.parse(default_stmt, new_body)

                switch_stmt_list.append({"default_stmt": {"body": new_body}})
            else:   # case语句
                case_condition = self.find_child_by_field(child, "value")
                shadow_case_condition = self.parse(case_condition, statements)

                if len(stmts) == 0:
                    switch_stmt_list.append({"case_stmt": {"condition": shadow_case_condition}})
                    continue

                new_body = []
                for case_stmt in stmts:
                    self.parse(case_stmt, new_body)

                switch_stmt_list.append({"case_stmt": {"condition": shadow_case_condition, "body": new_body}})

        self.append_stmts(statements, node, {"switch_stmt": {"condition": shadow_condition, "body": switch_stmt_list}})

    def import_statement(self, node: Node, statements: list):
        # 为import_stmt和import_as_stmt加了一个名为source的field

        import_clause = self.find_child_by_type(node, "import_clause")
        import_source = self.find_child_by_field(node, "source")

        source_str = self.parse(import_source, statements)

        if source_str is not None:
            # Handle quotes and extension
            if source_str.startswith("\"") and source_str.endswith("\""):
                 source_str = source_str[1:-1]
            source_str = os.path.normpath(source_str)
            if source_str.endswith(".js"):
                source_str = source_str[:-3]
            if source_str.startswith("./"):
                source_str = "." + source_str[2:]
            elif source_str.startswith("../"):
                prefix = "."
                while source_str.startswith("../"):
                    prefix += "."
                    source_str = source_str[3:]
                source_str = prefix + source_str

            source_str = source_str.replace("/", ".") # for linux
            source_str = source_str.replace("\\", ".") # for windows
        # side effect import, 格式为: import "module-name";
        if not import_clause:
            self.append_stmts(statements, node, {"import_stmt": {"module_path": source_str, "attrs": ['init']}})
            return

        # 如何区分import x from "yyy" 与import {x} from "yyy"
        for import_clause_child in import_clause.named_children:
            if self.is_comment(import_clause_child):
                continue

            # default import, 格式为: import name from "module-name";
            if import_clause_child.type == "identifier":
                shadow_name = self.parse(import_clause_child, statements)
                self.append_stmts(statements, node, {"from_import_stmt": {"name": shadow_name, "source": source_str}})

            # namespace import, 格式为: import * as alias from "module-name";
            elif import_clause_child.type == "namespace_import":
                alias = self.find_child_by_type(import_clause_child, "identifier")
                shadow_alias = self.parse(alias, statements)
                self.append_stmts(statements, node, {"from_import_stmt": {"name": "*", "alias": shadow_alias, "source": source_str}})

            # named import, 格式为：import { name [as alias], ... } from "module-name";
            else:
                import_specifiers = self.find_children_by_type(import_clause_child, "import_specifier")
                # 属于另一种格式的side effect import
                if len(import_specifiers) == 0:
                    self.append_stmts(statements, node, {"import_stmt": {"module_path": source_str, "attrs": ['init']}})
                else:
                    for specifier in import_specifiers:
                        name = self.find_child_by_field(specifier, "name")
                        shadow_name = self.parse(name, statements)

                        alias = self.find_child_by_field(specifier, "alias")
                        if alias:
                            shadow_alias = self.parse(alias, statements)
                            self.append_stmts(statements, node, {"from_import_stmt": {"name": shadow_name, "alias": shadow_alias, "source": source_str}})
                        else:
                            self.append_stmts(statements, node, {"from_import_stmt": {"name": shadow_name, "source": source_str}})

    # source_str为None时对应export {...}，不为None时对应export {...} from ...
    def parse_export_clause(self, node, statements, source_str=None):
        export_specifiers = self.find_children_by_type(node, "export_specifier")

        if len(export_specifiers) == 0:
            # {}中没有内容，因此name为""
            # 执行这种代码会运行source_str中的内容，相当于另一种形式的side effect import
            if source_str:
                self.append_stmts(statements, node, {"import_stmt": {"name": "", "module_path": source_str, "attrs": ['init']}})
        else:
            for specifier in export_specifiers:     # specifier的格式为：name [as alias]
                name = self.find_child_by_field(specifier, "name")
                shadow_name = self.parse(name, statements)

                alias = self.find_child_by_field(specifier, "alias")
                shadow_alias = self.parse(alias, statements)
                if source_str != None:
                    self.append_stmts(statements, node, {"from_export_stmt": {"name": shadow_name, "alias": shadow_alias, "source": source_str}})
                else:
                    self.append_stmts(statements, node, {"export_stmt": {"name": shadow_name, "alias": shadow_alias}})

    def export_statement(self, node: Node, statements: list):
        export_source = self.find_child_by_field(node, "source")

        if export_source:   # 带有from字句
            source_str = self.parse(export_source, statements)
            if source_str is not None:
                source_str = os.path.normpath(source_str)
                if source_str[-4:-1] == ".js":
                    source_str = source_str[:-4]
                    source_str = source_str[1:]
                source_str = source_str.replace("/", ".") # for linux
                source_str = source_str.replace("\\", ".") # for windows
                for str in source_str:
                    if str != '.':
                        break
                    else:
                        source_str = source_str[1:]
                namespace_export = self.find_child_by_type(node, "namespace_export")

            if namespace_export:
                # 格式为：export * as ... from ...
                alias = namespace_export.named_children[-1]    # 索引取-1可以将comment过滤掉
                shadow_alias = self.parse(alias, statements)
                # self.append_stmts(statements, node, {"from_import_stmt": {"name": "*", "alias": shadow_alias, "module_path": source_str}})
                # self.append_stmts(statements, node, {"export_stmt": {"name": "*", "alias": shadow_alias, "module_path": source_str}})
                self.append_stmts(statements, node, {"from_export_stmt": {"name": "*", "alias": shadow_alias, "source": source_str}})
            else:
                export_clause = self.find_child_by_type(node, "export_clause")
                if export_clause:
                    # 格式为：export { name1 , /* …, */ nameN } from ...
                    #       或者：export { import1 as name1, import2 as name2, /* …, */ nameN } from ...
                    self.parse_export_clause(export_clause, statements, source_str)
                else:
                    # 格式为：export * from ...
                    self.append_stmts(statements, node, {"from_export_stmt": {"name": "*", "source": source_str}})

        else:   # 不带from字句
            export_clause = self.find_child_by_type(node, "export_clause")
            if export_clause:
                # 格式为：export { name1, /* …, */ nameN }
                #       或者：export { variable1 as name1, variable2 as name2, /* …, */ nameN }
                self.parse_export_clause(export_clause, statements)
            else:
                declaration = self.find_child_by_field(node, "declaration")
                if declaration: # 这里不可能存在default
                    # 格式为：export [default] declaration
                    # 解析declaration语句得到的返回值，只是用于辅助确定定义了哪些变量
                    declared_list = self.parse(declaration, statements)

                    for i in range(len(declared_list)):
                        self.append_stmts(statements, node, {"export_stmt": {"name": declared_list[i]}})
                else:
                    value = self.find_child_by_field(node, "value")
                    # 格式为： export default .....
                    if value:
                        shadow_value = self.parse(value, statements)
                        self.append_stmts(statements, node, {"export_stmt": {"name": shadow_value, "attrs": ['default']}})

    def empty_statement(self, node: Node, statements: list):
        return ""


    """
        declaration部分
    """

    # 处理let/const/var变量声明
    def variable_declaration(self, node: Node, statements: list):
        attrs = []
        kind = self.find_child_by_field(node, "kind")
        if kind:    # 使用let/const声明
            shadow_kind = self.read_node_text(kind)
            attrs.append(shadow_kind)
        else:   # 使用var声明
            attrs.append("var")

        # 用于返回声明的变量名，以便export语句导出
        return_vals = []

        # 逐个处理，先声明（variable_decl），如果有初始值，再进行赋值
        declarators = node.named_children
        for child in declarators:
            if self.is_comment(child):
                continue

            name = self.find_child_by_field(child, "name")
            value = self.find_child_by_field(child, "value")
            if name is None:
                continue

            shadow_value = self.parse(value, statements)
            if name.type == "identifier":
                shadow_name = self.read_node_text(name)
                return_vals.append(shadow_name)
                self.append_stmts(statements, node, {"variable_decl": {"attrs": attrs, "name": shadow_name}})

                if shadow_value:
                    self.append_stmts(statements, node, {"assign_stmt": {"target": shadow_name, "operand": shadow_value}})

            elif name.type == "array_pattern":  # 数组解构
                index = 0
                # 处理空格
                previous_was_comma = False
                encountered_open_bracket = False

                for p in name.children:
                    if self.is_comment(p):
                        previous_was_comma = False
                        encountered_open_bracket = False
                        continue
                    elif p.type == "[" or p.type == "]":
                        previous_was_comma = False
                        encountered_open_bracket = True
                        continue
                    elif p.type == ",":
                        if previous_was_comma or encountered_open_bracket:
                            index += 1
                        previous_was_comma = True
                        encountered_open_bracket = False
                        continue
                    elif p.type == "rest_pattern":
                        previous_was_comma = False
                        encountered_open_bracket = False
                        name = p.named_children[-1]
                        shadow_name = self.parse(name, statements)
                        self.append_stmts(statements, node, {"variable_decl": {"attrs": attrs, "name": shadow_name}})
                        self.append_stmts(statements, node, {"assign": {"target": shadow_name, "operand": shadow_value}})
                    else:
                        previous_was_comma = False
                        encountered_open_bracket = False
                        elem = self.parse(p, statements)
                        self.append_stmts(statements, node, {"variable_decl": {"attrs": attrs, "name": elem}})
                        self.append_stmts(statements, node, {"array_read": {"target": elem, "array": shadow_value, "index": str(index)}})
                    index += 1

            elif name.type == "object_pattern": # 对象解构
                for p in name.named_children:
                    if self.is_comment(p):
                        continue

                    if p.type == "shorthand_property_identifier_pattern":
                        # 例如： const {name, age} = {name: "tom", age: 18}
                        pattern = self.read_node_text(p)

                        return_vals.append(pattern)

                        self.append_stmts(statements, node, {"variable_decl": {"attrs": attrs, "name": pattern}})

                        if shadow_value:
                            self.append_stmts(statements, node, {"field_read": {"target": pattern, "receiver_object": shadow_value, "field": pattern}})

                    elif p.type == "pair_pattern":
                        # 例如： const {name: n, age: a} = {name: "tom", age: 18}
                        left_child = self.find_child_by_field(p, "key")
                        right_child = self.find_child_by_field(p, "value")

                        shadow_left_child = self.property_name(left_child, statements)
                        shadow_right_child = self.parse(right_child, statements)

                        return_vals.append(shadow_right_child)

                        self.append_stmts(statements, node, {"variable_decl": {"attrs": attrs, "name": shadow_right_child}})

                        if shadow_value:
                            self.append_stmts(statements, node, {"field_read": {"target": shadow_right_child, "receiver_object": shadow_value, "field": shadow_left_child}})

                    elif p.type == "object_assignment_pattern":
                        left_child = self.find_child_by_field(p, "left")
                        right_child = self.find_child_by_field(p, "right")

                        shadow_left_child = self.read_node_text(left_child)
                        shadow_right_child = self.parse(right_child, statements)

                        return_vals.append(shadow_right_child)

                        self.append_stmts(statements, node, {"variable_decl": {"attrs": attrs, "name": shadow_left_child}})
                        self.append_stmts(statements, node, {"assign_stmt": {"target": shadow_left_child, "operand": shadow_right_child}})

        return return_vals

    def read_node_pref_children(self, node, stop_char):
        prefix_children = []
        for child in node.children:
            if not util.isna(child):
                content = self.read_node_text(child)
                # stop at parameters
                if content == stop_char:
                    break
                prefix_children.append(content)
        for item in ["function"]:
            while item in prefix_children:
                prefix_children.remove(item)
        return prefix_children

    def function_declaration(self, node: Node, statements: list, from_class_body = False):
        gir_node = {}

        # field: attrs
        gir_node["attrs"] = []

        shadow_children = self.read_node_pref_children(node, "(")
        if "async" in shadow_children:
            gir_node["attrs"].append("async")
        # 处理generator_function
        if "*" in shadow_children:
            gir_node["attrs"].append(LIAN_INTERNAL.GENERATOR_DECL)

        # 以下三个专门用于method_definition
        if "static" in shadow_children:
            gir_node["attrs"].append("static")
        if "get" in shadow_children:
            gir_node["attrs"].append("get")
        if "set" in shadow_children:
            gir_node["attrs"].append("set")

        # field: name
        name = self.find_child_by_field(node, "name")
        if not name:    # function_expression与arrow_function
            shadow_name = self.tmp_method() # 为匿名函数起一个临时名字
        elif node.type == "method_definition":
            if from_class_body:
                shadow_name =  self.property_name(name, statements)
                # 处理私有方法
                if shadow_name.startswith("#"):
                    gir_node["attrs"].append("private")
                    shadow_name = shadow_name[1:]
            else:
                shadow_name = self.tmp_method()
        else:
            shadow_name = self.read_node_text(name)
        gir_node["name"] = shadow_name

        # field: parameters and init
        gir_node["parameters"] = []
        simple_param = self.find_child_by_field(node, "parameter")

        if simple_param:    # arrow_function, 仅有单个参数，外层没有"()"
            shadow_name = self.read_node_text(simple_param)
            gir_node["parameters"].append({"parameter_decl": {"attrs": [], "name": shadow_name}})

        else:
            parameters = self.find_child_by_field(node, "parameters")
            for child in parameters.named_children:
                if self.is_comment(child):
                    continue

                self.formal_parameter(child, gir_node["parameters"])

        # field: body
        gir_node["body"] = []
        body = self.find_child_by_field(node, "body")
        if (self.is_expression(body) or self.is_literal(body) or self.is_identifier(body)):
            # 函数体为表达式时(arrow_function)
            shadow_expr = self.parse(body, gir_node["body"])
            gir_node["body"].append({"return_stmt": {"name": shadow_expr}})
        else:
            # 函数体为代码块时
            self.parse(body, gir_node["body"])

        self.append_stmts(statements, node, {"method_decl": gir_node})
        if (node.type == "function_declaration"
            or node.type == "generator_function_declaration"):
            return [shadow_name]    # 仅供export_statement使用
        else:
            return shadow_name

    def formal_parameter(self, node: Node, statements: list):
        attrs = []

        if node.type == "assignment_pattern":
            name = self.find_child_by_field(node, "left")
            value = self.find_child_by_field(node, "right")

            shadow_name = self.parse(name, statements)
            shadow_value = self.parse(value, statements)

            self.append_stmts(statements, node, {"parameter_decl": {"attrs": attrs, "name": shadow_name, "default_value": shadow_value}})

        elif node.type == "rest_pattern":   # 处理形参列表中的剩余参数(...arg)
            attrs.append(LIAN_INTERNAL.PACKED_POSITIONAL_PARAMETER)
            name = node.named_children[-1]
            shadow_name = self.parse(name, statements)
            self.append_stmts(statements, node, {"parameter_decl": {"attrs": attrs, "name": shadow_name}})

        elif node.type == "array_pattern":
            tmp_arr = self.tmp_variable()
            my_arr = []
            index = 0
            # 处理空格
            previous_was_comma = False
            encountered_open_bracket = False

            for p in node.children:
                if self.is_comment(p):
                    previous_was_comma = False
                    encountered_open_bracket = False
                    continue
                elif p.type == "[" or p.type == "]":
                    previous_was_comma = False
                    encountered_open_bracket = True
                    continue
                elif p.type == ",":
                    if previous_was_comma or encountered_open_bracket:
                        my_arr.append(" ")
                        index += 1
                    previous_was_comma = True
                    encountered_open_bracket = False
                    continue
                else:
                    previous_was_comma = False
                    encountered_open_bracket = False
                    elem = self.parse(p, statements)
                    my_arr.append(elem)
                    self.append_stmts(statements, node, {"array_read": {"target": elem, "array": tmp_arr, "index": str(index)}})
                index += 1
                for elem in my_arr:
                    self.append_stmts(statements, node, {"parameter_decl": {"attrs": attrs, "name": elem}})

        elif node.type == "object_pattern":
            tmp_var = self.tmp_variable()
            self.append_stmts(statements, node, {"parameter_decl": {"attrs": attrs, "name": tmp_var}})
            for p in node.named_children:
                if self.is_comment(p):
                    continue

                if p.type == "shorthand_property_identifier_pattern":
                    pattern = self.read_node_text(p)
                    self.append_stmts(statements, node, {"field_read": {"receiver_object": tmp_var, "field": pattern, "target": pattern}})
                elif p.type == "pair_pattern":
                    left_child = self.find_child_by_field(p, "key")
                    right_child = self.find_child_by_field(p, "value")

                    shadow_left_child = self.property_name(left_child, statements)
                    shadow_right_child = self.parse(right_child, statements)
                    self.append_stmts(statements, node, {"field_read": {"receiver_object": tmp_var, "field": shadow_left_child, "target": shadow_right_child}})

        else:
            shadow_name = self.parse(node, statements)
            self.append_stmts(statements, node, {"parameter_decl": {"attrs": attrs, "name": shadow_name}})

    def class_declaration(self, node: Node, statements: list):
        gir_node = {}

        # field: attrs
        gir_node["attrs"] = ["class"]

        # field: name
        name = self.find_child_by_field(node, "name")
        if name:
            shadow_name = self.read_node_text(name)
        else:
            shadow_name = self.tmp_class() # 匿名类
        gir_node["name"] = shadow_name

        # field: type_parameters
        gir_node["type_parameters"] = []

        # field: supers
        gir_node["supers"] = []
        class_heritage = self.find_child_by_type(node, "class_heritage")
        if class_heritage:
            expr = class_heritage.named_children[-1]
            shadow_expr = self.parse(expr, statements)
            gir_node["supers"].append(shadow_expr)

        # class_body
        body = self.find_child_by_field(node, "body")
        self.class_body(body, gir_node)

        self.append_stmts(statements, node, {"class_decl": gir_node})
        if node.type == "class":
            return shadow_name
        else:
            return [shadow_name]    # 仅供export_statement使用

    def class_body(self, node, gir_node):
        gir_node["fields"] = []
        gir_node["methods"] = []
        gir_node["nested"] = []
        init_class_method_body = []
        static_init_class_method_body = []

        # field_definition
        field_defs = self.find_children_by_type(node, "field_definition")
        for field_def in field_defs:
            statements = []
            extra = init_class_method_body
            shadow_children = list(map(self.read_node_text, field_def.children))
            if "static" in shadow_children:
                extra = static_init_class_method_body

            self.field_definition(field_def, statements)

            if statements:
                for stmt in statements:
                    if "variable_decl" in stmt:
                        gir_node["fields"].append(stmt)
                    elif "constant_decl" in stmt:
                        gir_node["fields"].append(stmt)
                    else:
                        extra.append(stmt)

        # class_static_block
        static_blocks = self.find_children_by_type(node, "class_static_block")
        for static_block in static_blocks:
            self.parse(static_block, static_init_class_method_body)

        if init_class_method_body:
            gir_node["methods"].insert(0,
                {
                    "method_decl":{
                        "name": LIAN_INTERNAL.CLASS_INIT,
                        "body": init_class_method_body
                    }
                }
            )

        if static_init_class_method_body:
            gir_node["methods"].insert(0,
                {
                    "method_decl":{
                        "name": LIAN_INTERNAL.CLASS_STATIC_INIT,
                        "body": static_init_class_method_body
                    }
                }
            )

        # method_definition
        method_defs = self.find_children_by_type(node, "method_definition")
        for method_def in method_defs:
            self.function_declaration(method_def, gir_node["methods"], True)

    def field_definition(self, node: Node, statements: list):
        attrs = []
        shadow_children = list(map(self.read_node_text, node.children))
        if "static" in shadow_children:
            attrs.append("static")

        prop_name = self.find_child_by_field(node, "property")
        shadow_name = self.property_name(prop_name, statements)

        init_value = self.find_child_by_field(node, "value")
        if init_value:
            shadow_value = self.parse(init_value, statements)
            self.append_stmts(statements, node, {"field_write": {"receiver_object": self.global_this(),
                                               "field": shadow_name, "source": shadow_value}})

        # 最后加入variable_decl，是为了便于之后将其从init移入fields
        self.append_stmts(statements, node, {"variable_decl": {"attrs": attrs, "name": shadow_name}})

    def property_name(self, node: Node, statements: list):
        if (node.type == "property_identifier" or
                node.type == "private_property_identifier" or
                node.type == "computed_property_name"):
            shadow_name = self.read_node_text(node)
        else:
            shadow_name = self.parse(node, statements)

        return shadow_name

    def is_literal(self, node):
        return self.obtain_literal_handler(node) is not None

    def literal(self, node: Node, statements: list, replacement: list):
        handler = self.obtain_literal_handler(node)
        return handler(node, statements, replacement)

    def is_declaration(self, node):
        return self.check_declaration_handler(node) is not None

    def declaration(self, node: Node, statements: list):
        handler = self.check_declaration_handler(node)
        return handler(node, statements)

    def is_expression(self, node):
        return self.check_expression_handler(node) is not None

    def expression(self, node: Node, statements: list):
        handler = self.check_expression_handler(node)
        return handler(node, statements)

    def is_statement(self, node):
        return self.check_statement_handler(node) is not None

    def statement(self, node: Node, statements: list):
        handler = self.check_statement_handler(node)
        return handler(node, statements)
