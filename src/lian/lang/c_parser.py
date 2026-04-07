#!/usr/bin/env python3

import re
#from lian.src.lian.config.constants import LianInternalDataType
import lian.lang.common_parser as common_parser
from lian.util import util
from lian.config.constants import LIAN_INTERNAL

class Parser(common_parser.Parser):
    def init(self):
        self.CONSTANTS_MAP = {
            "null"                          : LIAN_INTERNAL.NULL,
            "true"                          : LIAN_INTERNAL.TRUE,
            "false"                         : LIAN_INTERNAL.FALSE,
        }

        self.LITERAL_MAP = {
            "number_literal"                : self.regular_number_literal,
            "true"                          : self.regular_literal,
            "false"                         : self.regular_literal,
            "char_literal"                  : self.char_literal,
            "null_literal"                  : self.regular_literal,
            "identifier"                    : self.regular_literal,
            "field_identifier"              : self.regular_literal,
            "string_literal"                : self.string_literal,
            "concatenated_string"           : self.concatenated_string,
            "storage_class_specifier"       : self.regular_literal,
            "type_qualifier"                : self.regular_literal,
            "ms_call_modifier"              : self.regular_literal,
            "ms_pointer_modifier"           : self.regular_literal,
            "initializer_list"              : self.initializer_list,
        }

        self.EXPRESSION_HANDLER_MAP = {
            "assignment_expression"         : self.assignment_expression,
            "binary_expression"             : self.binary_expression,
            "pointer_expression"            : self.pointer_expression,
            "subscript_expression"          : self.array,
            "field_expression"              : self.field,
            "call_expression"               : self.call_expression,
            "update_expression"             : self.update_expression,
            "cast_expression"               : self.cast_expression,
            "sizeof_expression"             : self.sizeof_expression,
            "unary_expression"              : self.unary_expression,
            "offsetof_expression"           : self.offsetof_expression,
            "generic_expression"            : self.generic_expression,
            "conditional_expression"        : self.conditional_expression,
            "compound_literal_expression"   : self.compound_literal_expression,
            "alignof_expression"            : self.alignof_expression,
            "gnu_asm_expression"            : self.gnu_asm_expression,
            "parenthesized_expression"      : self.parenthesized_expression,

        }

        self.DECLARATION_HANDLER_MAP = {
            "function_definition"           : self.function_declaration,
            "type_definition"               : self.type_definition,
            "parameter_declaration"         : self.parameter_declaration,
            "struct_specifier"              : self.struct_specifier,
            "union_specifier"               : self.struct_specifier,
            "declaration"                   : self.variable_declaration,
            "enum_specifier"                : self.enum_declaration,
        }

        self.STATEMENT_HANDLER_MAP = {
            "return_statement"              : self.return_statement,
            "if_statement"                  : self.if_statement,
            "while_statement"               : self.while_statement,
            "for_statement"                 : self.for_statement,
            "switch_statement"              : self.switch_statement,
            "break_statement"               : self.break_statement,
            "continue_statement"            : self.continue_statement,
            "goto_statement"                : self.goto_statement,
            "do_statement"                  : self.dowhile_statement,
            "labeled_statement"             : self.label_statement,
            "attributed_statement"          : self.attributed_statement,
            "case_statement"                : self.case_statement,
            "seh_try_statement"             : self.seh_try_statement,
            "seh_leave_statement"           : self.seh_leave_statement,
        }


    # 判断是不是“表达式”类型
    def is_expression(self, node):
        # return False
        # 去“表达式”分发方法字典中查看是否有对应类型
        return self.check_expression_handler(node) is not None

    # 处理“表达式”类型，找到对应的方法并执行
    def expression(self, node, statements):
        handler = self.check_expression_handler(node)
        return handler(node, statements)

    # "表达式"类型分发方法
    def check_expression_handler(self, node):
        # 分发方法字典
        return self.EXPRESSION_HANDLER_MAP.get(node.type, None)

    def assignment_expression(self, node, statements):
        left = self.find_child_by_field(node, "left")

        while left.type == "parenthesized_expression":
            # assert left.named_child_count == 1
            left = left.named_children[0]

        operator = self.find_child_by_field(node, "operator")
        # 不存"="
        shadow_operator = self.read_node_text(operator).replace("=", "")

        right = self.find_child_by_field(node, "right")
        # 等号右边可能还是一长串表达式，交给parse函数去递归处理。处理思路是将一长串表达式拆成多个binary_assignment，每一个二元运算的结果记作一个临时变量，如 %1
        shadow_right = self.parse(right, statements)

        # 处理等号左边
        # 数组情况 arr[i] = ...
        if left.type == "subscript_expression":
            shadow_array, shadow_index = self.parse_array(left, statements)
            # 只有=时
            if not shadow_operator:
                self.append_stmts(statements,  node, {"array_write":
                    {"array": shadow_array, "index": shadow_index, "source": shadow_right}}
                )
                return shadow_right

            # 如+=这种，左侧变量也参与计算
            tmp_var = self.tmp_variable()
            self.append_stmts(statements,  node, {"array_read": {"target": tmp_var, "array": shadow_array, "index": shadow_index}})
            tmp_var2 = self.tmp_variable()
            self.append_stmts(statements,  node, {"assign_stmt":
                                   {"target": tmp_var2, "operator": shadow_operator, "operand": tmp_var,
                                    "operand2": shadow_right}})
            self.append_stmts(statements,  node, {"array_write": {"array": shadow_array, "index": shadow_index, "source": tmp_var2}})
            return tmp_var2

        # 字段情况 x.f = ...
        if left.type == "field_expression":
            shadow_argument, shadow_field = self.parse_field(left, statements)
            # 只有=时
            if not shadow_operator:
                self.append_stmts(statements,  node, {"field_write": {"receiver_object": shadow_argument, "field": shadow_field, "source": shadow_right}})
                return shadow_right

            # 如+=这种，左侧变量也参与计算
            tmp_var = self.tmp_variable()
            self.append_stmts(statements,  node, {"field_read": {"target": tmp_var, "receiver_object": shadow_argument, "field": shadow_field}})
            tmp_var2 = self.tmp_variable()
            self.append_stmts(statements,  node, {"assign_stmt":
                {"target": tmp_var2, "operator": shadow_operator, "operand": tmp_var,
                "operand2": shadow_right}})
            self.append_stmts(statements,  node, {"field_write": {"receiver_object": shadow_argument, "field": shadow_field, "source": tmp_var2}})
            return tmp_var2

        # 左侧是指针情况
        if left.type == "pointer_expression":
            shadow_argument = self.parse_pointer(left, statements)
            # 只有=时
            if not shadow_operator:
                self.append_stmts(statements,  node, {"mem_write": {"address": shadow_argument, "source": shadow_right}})
                return shadow_right

            # 如+=这种，左侧变量也参与计算
            tmp_var = self.tmp_variable()
            self.append_stmts(statements,  node, {"mem_read": {"target": tmp_var, "address": shadow_argument}})
            tmp_var2 = self.tmp_variable()
            self.append_stmts(statements,  node, {"assign_stmt": {
                "target": tmp_var2, "operator": shadow_operator, "operand": tmp_var, "operand2": shadow_right}})
            self.append_stmts(statements,  node, {"mem_write": {"address": shadow_argument, "source": tmp_var2}})
            return tmp_var2

        # 其他情况直接解析左侧
        shadow_left = self.parse(left)
        # 只有"="时
        if not shadow_operator:
            self.append_stmts(statements,  node, {"assign_stmt": {"target": shadow_left, "operand": shadow_right}})
        # "+="这种，左侧变量也参与计算
        else:
            self.append_stmts(statements,  node, {"assign_stmt": {
                "target": shadow_left, "operator": shadow_operator,
                "operand": shadow_left, "operand2": shadow_right}})

        return shadow_left

    def binary_expression(self, node, statements):
        left = self.find_child_by_field(node, "left")
        right = self.find_child_by_field(node, "right")
        operator = self.find_child_by_field(node, "operator")

        shadow_operator = self.read_node_text(operator)
        # 左右可能仍然是表达式，需进一步处理
        shadow_left = self.parse(left, statements)
        shadow_right = self.parse(right, statements)

        # 返回一个临时变量存储中间结果，如 %1=b+c
        tmp_var = self.tmp_variable()
        self.append_stmts(statements,  node, {"assign_stmt": {"target": tmp_var, "operator": shadow_operator,
                                           "operand": shadow_left, "operand2": shadow_right}})
        return tmp_var

    # 指针 *和&都是
    def pointer_expression(self, node, statements):
        operator = self.find_child_by_field(node, "operator")
        operator = self.read_node_text(operator)
        tmp_var = self.tmp_variable()
        shadow_argument = self.parse_pointer(node, statements)
        # *
        if (operator == "*"):
            self.append_stmts(statements,  node, {"mem_read": {"target": tmp_var, "address": shadow_argument}})
        # &
        elif (operator == "&"):
            self.append_stmts(statements,  node, {"addr_of": {"target": tmp_var, "source": shadow_argument}})

        return tmp_var

    # 提取指针中的成分
    def parse_pointer(self, node, statements):
        argument = self.find_child_by_field(node, "argument")
        # 可能有多重指针
        shadow_argument = self.parse(argument, statements)
        return shadow_argument

    # 从数组元素中提取出数组名和下标
    def parse_array(self, node, statements):
        array = self.find_child_by_field(node, "argument")
        shadow_array = self.parse(array, statements)
        index = self.find_child_by_field(node, "index")
        shadow_index = self.parse(index, statements)
        return (shadow_array, shadow_index)

    # 用于处理表达式中的数组类型，将数组元素读出，保存到一个临时变量中，如%1=arr[i]
    def array(self, node, statements):
        tmp_var = self.tmp_variable()
        shadow_array, shadow_index = self.parse_array(node, statements)
        self.append_stmts(statements,  node, {"array_read": {"target": tmp_var, "array": shadow_array, "index": shadow_index}})
        return tmp_var

    # 从字段变量中提取出对象名和字段名
    def parse_field(self, node, statements):
        argument = self.find_child_by_field(node, "argument")
        # argument中可能还有多层嵌套，比如a.b.c.d。此处处理逻辑区别于java(java需对super进行处理，而这里直接交给parse递归解析即可)
        shadow_argument = self.parse(argument, statements)
        field = self.find_child_by_field(node, "field")
        shadow_field = self.read_node_text(field)
        return (shadow_argument, shadow_field)

    # 用于处理表达式中的字段类型，将字段内容读出保存到一个临时变量中 如 %1=a.b
    def field(self, node, statements):
        tmp_var = self.tmp_variable()
        shadow_argument, shadow_field = self.parse_field(node, statements)
        self.append_stmts(statements,  node, {"field_read": {"target": tmp_var, "receiver_object": shadow_argument, "field": shadow_field}})
        return tmp_var

    # 处理函数调用
    def call_expression(self, node, statements):
        function = self.find_child_by_field(node, "function")
        shadow_name = self.parse(function)

        arguments = self.find_child_by_field(node, "arguments")
        arg_list = []

        if arguments.named_child_count > 0:
            for child in arguments.named_children:
                if self.is_comment(child):
                    continue
                arg_list.append(self.parse(child, statements))

        tmp_return = self.tmp_variable()
        self.append_stmts(statements,  node, {"call_stmt": {"target": tmp_return, "name": shadow_name, "positional_args": arg_list}})

        # 返回到全局变量
        return tmp_return

    # expression++ , expression--
    def update_expression(self, node, statements):
        shadow_node = self.read_node_text(node)

        update_operator = self.find_child_by_field(node, "operator")
        operator_text = self.read_node_text(update_operator)

        operator = ""
        if "++" == operator_text:
            operator = "+"
        elif "--" == operator_text:
            operator = "-"
        else:
            util.debug("update expression符号解析错误：不是++也不是--")
        # 判断++在前or在后
        is_after = False
        if shadow_node[-1] == operator:
            is_after = True

        tmp_var = self.tmp_variable()

        expression = self.find_child_by_field(node, "argument")

        while expression.type == "parenthesized_expression":
            # assert operand.named_child_count == 1
            expression = expression.named_children[0]

        if expression.type == "field_expression":
            shadow_object, field = self.parse_field(expression, statements)

            self.append_stmts(statements,  node, {"field_read": {"target": tmp_var, "receiver_object": shadow_object, "field": field}})
            tmp_var2 = self.tmp_variable()
            self.append_stmts(statements,  node, {"assign_stmt": {"target": tmp_var2, "operator": operator, "operand": tmp_var, "operand2": "1"}})
            self.append_stmts(statements,  node, {"field_write": {"receiver_object": shadow_object, "field": field, "source": tmp_var2}})

            # 对于后置形式，返回表达式原本的值
            if is_after:
                return tmp_var
            # 对于前置形式，返回更新后的值
            return tmp_var2

        if expression.type == "subscript_expression":
            shadow_array, shadow_index = self.parse_array(expression, statements)

            self.append_stmts(statements,  node, {"array_read": {"target": tmp_var, "array": shadow_array, "index": shadow_index}})
            tmp_var2 = self.tmp_variable()
            self.append_stmts(statements,  node,
                {"assign_stmt": {"target": tmp_var2, "operator": operator, "operand": tmp_var, "operand2": "1"}})
            self.append_stmts(statements,  node, {"array_write": {"array": shadow_array, "index": shadow_index, "source": tmp_var2}})

            if is_after:
                return tmp_var
            return tmp_var2

        shadow_expression = self.parse(expression, statements)
        self.append_stmts(statements,  node, {"assign_stmt": {"target": tmp_var, "operand": shadow_expression}})
        self.append_stmts(statements,  node, {"assign_stmt": {"target": shadow_expression, "operator": operator,
                                           "operand": shadow_expression, "operand2": "1"}})

        # 对于后置形式，返回表达式原本的值
        if is_after:
            return tmp_var
        # 对于前置形式，返回更新后的值
        return shadow_expression


    # 类型转换表达式
    def cast_expression(self, node, statements):
        attrs = []
        value = self.find_child_by_field(node, "value")
        shadow_value = self.parse(value, statements)
        type_descriptor = self.find_child_by_field(node, "type")
        # 抓取修饰词
        self.search_for_modifiers(type_descriptor, attrs)
        _type_specifier = self.find_child_by_field(type_descriptor, "type")
        shadow_type = self.parse(_type_specifier, statements)
        if _abstract_declarator:=self.find_child_by_field(type_descriptor, "declarator"):
            shadow_abstract_declarator = self.read_node_text(_abstract_declarator)
            shadow_type = f"{shadow_type}{shadow_abstract_declarator}"
            self.search_for_modifiers(_abstract_declarator, attrs)

        # 首先将要转换的表达式赋给一个临时变量，随后对临时变量进行类型转换，从而保留原本表达式(可能是变量)的类型不变。
        tmp = self.tmp_variable()
        self.append_stmts(statements,  node, {"type_cast_stmt" : {"target" : tmp, "data_type" : shadow_type, "source" : shadow_value}})
        return tmp

    def sizeof_expression(self,node,statements):
        value = self.find_child_by_field(node,"value")
        type_descriptor = self.find_child_by_field(node,"type")
        shadow_value = 0
        if value:
            shadow_value = self.parse(value,statements)
        elif type_descriptor:
            shadow_value = self.parse(type_descriptor,statements)
        tmp = self.tmp_variable()
        self.append_stmts(statements,  node, {"assign_stmt":{"target":tmp, "operator":"sizeof", "operand":shadow_value}})
        return tmp

    # ~a 翻译成 assign_stmt %v0, ~, a
    def unary_expression(self, node, statements):
        operand = self.find_child_by_field(node, "argument")
        shadow_operand = self.parse(operand, statements)
        operator = self.find_child_by_field(node, "operator")
        shadow_operator = self.read_node_text(operator)

        tmp_var = self.tmp_variable()

        self.append_stmts(statements,  node, {"assign_stmt": {"target": tmp_var, "operator": shadow_operator, "operand": shadow_operand}})
        return tmp_var

    # offset_height = offsetof(struct Person, height);
    def offsetof_expression(self, node, statements):
        type_discriptor = self.find_child_by_field(node, "type")
        type_discriptor_name = self.parse(type_discriptor, statements)
        # 两个域，一个是type，一个是field
        field = self.find_child_by_field(node, "member")
        field_discriptor_name = self.parse(field, statements)

        tmp_return = self.tmp_variable()

        self.append_stmts(statements,  node, {"field_addr": {"target": tmp_return, "data_type": type_discriptor_name, "name": field_discriptor_name}})
        return tmp_return

    def generic_expression(self, node, statements):
        type_list = []
        expr_list = []
        children = node.named_children
        variable_descriptor = self.parse(children[0], statements)
        type_list = [self.read_node_text(children[i]) for i in range(len(children)) if i % 2 != 0]
        expr_list = [self.parse(children[i], statements) for i in range(len(children)) if i % 2 == 0 and i != 0]

        tmp_return = self.tmp_variable()
        self.append_stmts(statements,  node, {"switch_type_stmt": {"target": tmp_return, "condition": variable_descriptor, "type_list": type_list, "expr_list": expr_list}})

        return tmp_return

    def conditional_expression(self, node, statements):
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

        self.append_stmts(statements,  node, {"if_stmt": {"condition": condition, "then_body": then_body, "else_body": else_body}})
        return tmp_var

    def compound_literal_expression(self, node, statements):
        # 当成new去处理
        # 和offsetof表达式类似，也是两个域，一个是type，一个是value
        array_list = []

        type_discriptor = self.find_child_by_field(node, "type")
        type_discriptor_name = self.read_node_text(type_discriptor)
        declarators = self.find_children_by_field(type_discriptor, "declarator")
        declarator = type_discriptor
        while child_declarator := self.find_child_by_field(declarator, "declarator"):
            if child_declarator.type == "abstract_array_declarator":
                array_list.append("array")
            declarator = child_declarator

        field = self.find_child_by_field(node, "value")
        tmp_return = self.initializer_list(field, statements, array_list)


        return tmp_return

    def alignof_expression(self, node, statements):
        type_descriptor = self.find_child_by_field(node, "type")
        type_descriptor_name = self.read_node_text(type_descriptor)

        tmp_return = self.tmp_variable()

        self.append_stmts(statements,  node, {"call_stmt": {"target": tmp_return, "name": "alignof", "type_name": type_descriptor_name}})
        return tmp_return

    def gnu_asm_expression(self, node, statements):
        def get_list(target):
            ret = []
            if target:
                if target.named_child_count > 0:
                    for child in target.children:
                        shadow_variable = self.parse(child, statements)
                        if shadow_variable:
                            ret.append(self.read_node_text(child))
            return ret

        assembly_code = self.find_child_by_field(node, "assembly_code")
        shadow_assembly_code = self.parse(assembly_code)

        output_operands = self.find_child_by_field(node, "output_operands")
        output_operands_list = get_list(output_operands)

        input_operands = self.find_child_by_field(node, "input_operands")
        input_operands_list = get_list(input_operands)

        clobbers = self.find_child_by_field(node, "clobbers")
        registers_list = get_list(clobbers)

        goto_labels = self.find_child_by_field(node, "goto_labels")
        labels_list = get_list(goto_labels)

        self.append_stmts(statements,  node, {
            "asm_stmt": {
                "assembly_code": shadow_assembly_code,
                "output_operands": output_operands_list,
                "input_operands": input_operands_list,
                "registers": registers_list,
                "labels": labels_list
            }})

        return 0

    def parenthesized_expression(self, node, statements):
        return self.parse(node.children[1], statements)

    # 标识符
    def is_identifier(self, node):
        return node.type in [
            "identifier",
            "type_identifier",
            "primitive_type",
            "storage_class_specifier",
            "ms_call_modifier",
            "ms_pointer_modifier",
            "type_qualifier",
            "field_identifier",
            "statement_identifier",
        ]

    # 常量
    def is_literal(self, node):
        return self.obtain_literal_handler(node) is not None

    def literal(self, node, statements, replacement):
        handler = self.obtain_literal_handler(node)
        return handler(node, statements, replacement)

    def obtain_literal_handler(self, node):
        return self.LITERAL_MAP.get(node.type, None)

    # 数字常量
    def regular_number_literal(self, node, statements, replacement):
        value = self.read_node_text(node)
        value = self.common_eval(value)
        return str(value)

    def regular_literal(self, node, statements, replacement):
        content = self.read_node_text(node)
        return self.CONSTANTS_MAP.get(content, content)

    def concatenated_string(self, node, statements, replacement):
        replacement = []
        ret = ""

        for child in node.named_children:
            if child.type == "string_literal":
                parsed = self.parse(child, statements, replacement)
                ret += parsed[1:-1]


        if replacement:
            for r in replacement:
                (expr, value) = r
                ret = ret.replace(self.read_node_text(expr), value)

        ret = self.handle_hex_string(ret)

        return self.escape_string(ret)

    # FIXME: 字符串常量(不完善)
    def string_literal(self, node, statements, replacement):
        return self.read_node_text(node)

    def char_literal(self, node, statements, replacement):
        return self.read_node_text(node)

    # 声明类型
    def is_declaration(self, node):
        # return False
        return self.check_declaration_handler(node) is not None

    def declaration(self, node, statements):
        handler = self.check_declaration_handler(node)
        return handler(node, statements)

    def check_declaration_handler(self, node):
        return self.DECLARATION_HANDLER_MAP.get(node.type, None)

    # 用于寻找所有modifiers，并添加到modifiers列表中。其可能位于ast的不同层级。
    def search_for_modifiers(self, input_node, modifiers):
        for m in ["storage_class_specifier", "type_qualifier", "attribute_specifier", "attribute_declaration",
                  "ms_declspec_modifier"]:
            ms = self.find_children_by_type(input_node, m)
            for m in ms:
                modifiers.append(self.read_node_text(m))

    def function_declaration(self, node, statements):
        # 处理方法前的修饰符
        modifiers = []
        self.search_for_modifiers(node, modifiers)
        func_decl = self.find_child_by_field(node, "declarator")
        if attr_spec := self.find_child_by_type(func_decl, "attribute_specifier"):
            attr_arg_list = self.find_child_by_type(attr_spec, "argument_list")
            if attr_arg_list.named_child_count > 0:
                for a in attr_arg_list.named_children:
                    shadow_a = self.parse(a, statements)
                    modifiers.append(shadow_a)

        # 返回值类型
        mytype = self.find_child_by_field(node, "type")
        shadow_type = self.read_node_text(mytype)

        # 要迭代找到function_declarator节点，其内容如func(int a,int b)
        child = self.find_child_by_field(node, "declarator")
        while child.type != "function_declarator":
            # 返回值是指针类型
            if child.type == "pointer_declarator":
                shadow_type += "*"
                modifiers.append(LIAN_INTERNAL.POINTER)
            child = self.find_child_by_field(child, "declarator")
        if child.type != "function_declarator":
            util.debug("错误,找不到function_declarator")
            return
        # 函数名位于function_declarator下的declarator字段
        name = self.find_child_by_field(child, "declarator")
        shadow_name = self.read_node_text(name)

        all_parameters = []
        # 形参列表位于declarator字段下的parameters字段，内容如(int a,int b)
        parameters = self.find_child_by_field(child, "parameters")
        if parameters and parameters.named_child_count > 0:
            for p in parameters.named_children:
                if self.is_comment(p):
                    continue

                # 每个p的类型都是parameter_declaration。解析形参的结果会放在init列表中
                self.parse(p, all_parameters)

        new_body = []
        #self.sync_tmp_variable(new_body, init)
        body = self.find_child_by_field(node, "body")
        self.parse(body, new_body)

        self.append_stmts(statements,  node, {"method_decl": {"attrs": modifiers, "data_type": shadow_type, "name": shadow_name,
                                           "parameters": all_parameters, "body": new_body}})

    # 处理参数声明。对应java的formal_parameter
    def parameter_declaration(self, node, statements):
        modifiers = []
        # 用来保存类型相关的attr，如struct、union、array、pointer。这是互斥的，只可能选择一个。比如结构体数组的attr是数组，而不是结构体。
        type_modifiers = []

        # 把parameter_declaration顶层的modifiers读出
        self.search_for_modifiers(node, modifiers)

        mytype = self.find_child_by_field(node, "type")
        shadow_type = self.read_node_text(mytype)

        # 以结构体为形参，如struct Point p
        if mytype.type == "struct_specifier":
            type_modifiers = ["struct"]
            shadow_type = shadow_type.replace("struct ", "")
        # 以联合体为形参，如union Data d
        if mytype.type == "union_specifier":
            type_modifiers = ["union"]
            shadow_type = shadow_type.replace("union ", "")
        # 以枚举类型为形参，如enum Color color
        if mytype.type == "enum_specifier":
            type_modifiers = ["enum"]
            shadow_type = shadow_type.replace("enum ", "")

        # 对应于参数中type之外的部分。其下可以对应多种_declarator规则。
        declarator = self.find_child_by_field(node, "declarator")
        if declarator:
        # 考虑多重、嵌套情况。逐层declarator解析。直到找到最底层的declarator，才是参数名。
            while child_declarator := self.find_child_by_field(declarator, "declarator"):
                # util.debug("--------------------------------declarator类型：" + declarator.type)

                # 找出嵌套情况中的modifiers
                self.search_for_modifiers(declarator, modifiers)

                # 以数组作为形参，如int x[]，int x[][]
                if declarator.type == "array_declarator":
                    shadow_type += "[]"
                    # 后面的modifiers会取代之前的，最后只留下最里面的，即这个参数的attr(可能有bug，要找反例)。比如指针数组的attr应该是数组，结构体指针的attr应该是指针
                    type_modifiers = ["array"]

                # 以指针作为形参，如int *p，int **p。之后和assignment_expression中对指针的处理方式统一，先read出来
                if declarator.type == "pointer_declarator":
                    shadow_type += "*"
                    type_modifiers = ["pointer"]

                # 以函数指针作为形参 如int (*operation)(int, int)
                if declarator.type == "function_declarator":
                    # 直接将函数指针原型当成type
                    shadow_type += self.read_node_text(declarator)
                    type_modifiers = ["pointer"]
                    # 跳掉下面的括号
                    child_declarator = self.find_child_by_field_type(
                        declarator, "declarator", "pointer_declarator")

                declarator = child_declarator

        # 找到最底层的declarator
        shadow_name = self.read_node_text(declarator)

        # 将类型attr并入modifiers
        modifiers.extend(type_modifiers)

        self.append_stmts(statements,  node, {"parameter_decl": {"attrs": modifiers, "data_type": shadow_type, "name": shadow_name}})


    STRUCT_TYPE_MAP = {
        "struct_specifier": "struct",
        "union_specifier": "union"
    }

    # 处理结构体/联合体声明
    def struct_specifier(self, node, statements):
        gir_node = {}
        gir_node["attrs"] = []

        # Struct或Union
        if node.type in self.STRUCT_TYPE_MAP:
            gir_node["attrs"].append(self.STRUCT_TYPE_MAP[node.type])

        self.search_for_modifiers(node, gir_node["attrs"])

        name = self.find_child_by_field(node, "name")
        if name:
            shadow_name = self.read_node_text(name)
        else:
            shadow_name = self.tmp_variable()
        gir_node["name"] = shadow_name

        body = self.find_child_by_field(node, "body")
        if body:
            self.struct_body(body, gir_node)
            self.append_stmts(statements,  node, {f"{self.STRUCT_TYPE_MAP[node.type]}_decl": gir_node})

        return gir_node["name"]

    # 用于处理结构体或联合体的body部分
    def struct_body(self, node, gir_node):
        if field_decls := self.find_children_by_type(node, "field_declaration"):
            gir_node["fields"] = []
            for field_decl in field_decls:
                field_statements = []

                attrs = []
                self.search_for_modifiers(field_decl, attrs)
                # for decl_modifiers in ["storage_class_specifier", "type_qualifier", "attribute_specifier", "attribute_declaration", "ms_declspec_modifier"]:
                #     if modifiers := self.find_children_by_type(field_decl, decl_modifiers):
                #         for m in modifiers:
                #             attrs.append(self.read_node_text(m))

                decl_type = self.find_child_by_field(field_decl, "type")
                if decl_type.type == "struct_specifier":
                    attrs.append("struct")
                elif decl_type.type == "union_specifier":
                    attrs.append("union")
                shadow_decl_type = self.read_node_text(decl_type)

                # 一个function_declarator下可能有多个declarator 比如int a,*b;
                declarators = self.find_children_by_field(
                    field_decl, "declarator")
                for declarator in declarators:
                    # 比如pointer，array等
                    type_attr = []
                    shadow_decl_type_copy = shadow_decl_type
                    attr_copy = attrs.copy()

                    while child_declarator := self.find_child_by_field(declarator, "declarator"):
                        if declarator.type == "pointer_declarator":
                            shadow_decl_type_copy += "*"
                            # 和函数形参中的处理逻辑一样，只保留最内层的type_attr，比如指针数组就是一个数组
                            type_attr = ["pointer"]
                        if declarator.type == "array_declarator":
                            # 判断是否是最外层的数组
                            if type_attr != ["array"]:
                                # 用正则表达式去掉数组名
                                array_size = re.sub(
                                    r'^\w+', '', self.read_node_text(declarator))
                                shadow_decl_type_copy += array_size
                                type_attr = ["array"]

                        # 找到最底层的declarator，存着变量名
                        declarator = child_declarator

                    # 最底层的declarator才是field_identifier，即变量名
                    shadow_declarator = self.read_node_text(declarator)

                    attr_copy.extend(type_attr)
                    # 注意，当向字典中传入一个可变对象(比如这边的attr字段传的是一个列表)，它实际上传入的是当前这个变量attr_copy指向的对象引用，类似于C中指针的概念
                    self.append_stmts(field_statements,  node, {"variable_decl" :
                                             {"attrs": attr_copy,
                                              "data_type": shadow_decl_type_copy,
                                              "name": shadow_declarator}})


                gir_node["fields"].extend(field_statements)

    def struct_array(self, node, struct_name, statements):
        tmp_var = self.tmp_variable()
        self.append_stmts(statements,  node, {"new_array" : {"data_type": struct_name,
                                          "target": tmp_var}})
        index = 0
        for child_list in node.children:
            #这里只能用笨办法找成员struct的名字，懒得找
            if child_list.type == "initializer_list":
                tmp_struct = self.tmp_variable()
                child_count = child_list.named_child_count
                self.append_stmts(statements,  node, {"new_struct":{"data_type" :struct_name, "target":tmp_struct}})
                for index in range(child_count):
                    value = self.parse(child_list.named_child(index), statements)
                    self.append_stmts(statements,  node, {"field_write" :
                                       {"receiver_object" : tmp_struct,
                                        "field" : "not found yet",
                                        "source" : value}})
                self.append_stmts(statements,  node, {"array_write":
                                   {"array" : tmp_var,
                                    "source" : tmp_struct,
                                    "index" : str(index)}})
            index = index + 1

    def initializer_list(self, node, statements, array_list):
        tmp_var = self.tmp_variable()
        is_array = True
        data_type = ""
        if len(array_list) != 0 and array_list[-1] != "array":
            data_type = array_list[-1]
            array_list.pop()
        if len(array_list) != 0 and array_list[0] == "array":
            self.append_stmts(statements,  node, {"new_array" : { "data_type" : data_type, "target": tmp_var}})
            array_list.pop()
        else:
            self.append_stmts(statements,  node, {"new_struct": { "data_type" : data_type, "target":tmp_var}})
            is_array = False
        index = 0
        for child_list in node.children:
            if child_list.type == "initializer_list":
                result = self.initializer_list(child_list, statements, array_list)

                if is_array:
                    self.append_stmts(statements,  node, {"array_write":
                                       {"array" : tmp_var,
                                        "source" : result,
                                        "index" : str(index)}})
                else:
                    self.append_stmts(statements,  node, {"field_write" :
                                       {"receiver_object" : tmp_var,
                                        "field" : str(index),
                                        "source" : result}})
                index = index + 1

            elif child_list.type == "initializer_pair":
                designator = self.find_child_by_field(child_list, "designator")
                value = self.find_child_by_field(child_list, "value")
                value = self.parse(value, statements)
                shadow_designator= self.parse(designator,[])
                self.append_stmts(statements,  node, {"field_write" :
                                   {"receiver_object" : tmp_var,
                                    "field" : shadow_designator,
                                    "source" : value}})

            else:
                value = self.parse(child_list, statements)
                if value:
                    if is_array:
                        self.append_stmts(statements,  node, {"array_write":
                                           {"array" : tmp_var,
                                            "source" : value,
                                            "index" : str(index)}})
                    else:
                        self.append_stmts(statements,  node, {"field_write" :
                                           {"receiver_object" : tmp_var,
                                            "field" : str(index),
                                            "source" : value}})
                    index = index + 1

        return tmp_var

    def type_definition(self, node, statements):
        mytype = self.find_child_by_field(node, "type")
        source_type = self.read_node_text(mytype)
        declarators = self.find_child_by_field(node, "declarator")
        target = self.read_node_text(declarators)
        while child_declarator := self.find_child_by_field(declarators, "declarator"):
            declarators = child_declarator
            target = self.read_node_text(child_declarator)
            self.append_stmts(statements,  node, {"type_alias_decl" : {"name" : target, "data_type" : source_type}})

    def internal_struct_init(self, node, statements, value, mytype, struct_name):
        struct_or_union = "struct" if mytype.type == "struct_specifier" else "union"
        # 此时，相应的结构体类型声明的处理应该已经结束了。因此去已经处理的statements列表中找到对应的结构体类型，取出里面的字段名，并赋值
        tmp_var_id = self.tmp_variable()

        self.append_stmts(statements,  node, {"new_struct" :{"data_type" :struct_name, "target" : tmp_var_id}})
        # 处理stru = {.field1 = value1,.field2 = value2}的初始化情况
        initializer_pairs = self.find_children_by_type(value,"initializer_pair")
        if initializer_pairs:
            for initializer_pair in initializer_pairs:
                designator = self.find_child_by_field(initializer_pair,"designator")
                init_value = self.find_child_by_field(initializer_pair,"value")
                shadow_designator= self.parse(designator,[])
                shadow_init_value = self.parse(init_value,statements)
                self.append_stmts(statements,  node, {"field_write":
                            {"receiver_object": tmp_var_id, "field": shadow_designator, "source": shadow_init_value}})

        else:
            for stmt in statements:
                if f"{struct_or_union}_decl" in stmt and stmt[f"{struct_or_union}_decl"]["name"] == struct_name.split(' ')[0]:
                    members = stmt[f"{struct_or_union}_decl"]["fields"]
                    # 先判断初始化语句和成员数量是否匹配
                    if len(members) < value.named_child_count:
                        util.debug(f"{struct_name}初始化时的成员数量有误，应该是{len(members)}个成员，",
                                   "但初始化语句中有{value.named_child_count}个成员")
                        continue

                    value_number = value.named_child_count
                    for field_index,field_member_list in enumerate(members):
                        if value_number == 0:
                            continue
                        # field_member_list是一个包含单个字典的列表，其中的元素才是我们要的字典
                        field_member = field_member_list[0]
                        # util.debug(f"field_index: {field_index} , field_member: {field_member}")
                        if any("variable_decl" in member for member in field_member):
                            field_name = field_member["variable_decl"]["name"]
                            field_value = self.parse(value.named_child(field_index), statements)
                            self.append_stmts(statements,  node, {"field_write":
                                                    {"receiver_object": tmp_var_id, "field": field_name,
                                                    "source": field_value}})
                            value_number = value_number - 1
                    break  # 找到第一个struct即可
                else:
                    util.debug(f"ERROR=========处理{struct_or_union}变量初始化时出现错误，找不到对应的{struct_or_union}类型！")
        return tmp_var_id

    def array_declaration(self, node, statements, value, modifiers, shadow_type):
        middle_result = None
        array_node = node
        array_dimensions = []
        #处理声明时赋值情况
        #提取右边的值
        if value and value.type == "initializer_list" and value.named_child_count > 0:
            element = []
            times = 0
            def recursive_search_element(n):
                for child in n.children:
                    if child.type == "initializer_list":
                        recursive_search_element(child)
                    else:
                        child = self.parse(child, statements)
                        if child is not None:
                            element.append(child)
            recursive_search_element(value)
            middle_result = element
        #提取维度信息
        tmp_value = value

        while True:
            #  如果有初始赋值语句，则用其推断维度。原因是有些数组声明时可能不会显式声明size节点
            if value:
                size = len(middle_result)
                array_dimensions.append(size)
                tmp_value = self.find_child_by_type(tmp_value, "initializer_list")
                if tmp_value is None:
                    break
                continue  # 就不用size节点了
            else:
                size = self.find_child_by_field(array_node, "size")
                size = 1
                array_dimensions.append(size)
                """ if size:
                    size = int(self.read_node_text(size))
                    array_dimensions.append(size) """
                array_node = self.find_child_by_type(array_node, "array_declarator")
                if array_node is None:
                    # 使用size节点得到的维度数组是反过来的，需要将其逆置
                    array_dimensions.reverse()
                    break

        array_dimensions_len = len(array_dimensions)

        for current_dim_index in range(array_dimensions_len):  # current_dim_index 0~len-1
            inner_array_create_count = 1

            # 计算需要创建几个当前层级的数组
            for e in array_dimensions[:array_dimensions_len - 1 - current_dim_index]:
                inner_array_create_count *= e
            # util.debug(f"第{current_dim_index}轮，需要创建{inner_array_create_count}个数组")

            new_middle_result = []  # 存储本轮的结果，用作在下一轮前替换middle_result

            # 创建当前层级数组
            for array_create_id in range(inner_array_create_count):
                inner_array_tmp_var = self.tmp_variable()
                self.append_stmts(statements,  node, {"new_array": {"attrs": modifiers, "data_type": shadow_type,
                                                    "target": inner_array_tmp_var}})
                # 若有赋值操作
                if value:
                    index = 0
                    current_arr_size = array_dimensions[-(current_dim_index + 1)]  # 当前维度的数组的大小。注意负索引从-1开始计数
                    for i in range(current_arr_size):
                        self.append_stmts(statements,  node, {"array_write": {"array": inner_array_tmp_var,
                                                            "index": str(index), "source": middle_result[
                                current_arr_size * array_create_id + i]}})
                        index += 1
                    # 将临时数组名保存，之后给外层数组赋值
                    new_middle_result.append(inner_array_tmp_var)

            middle_result = new_middle_result
            shadow_type = f"{shadow_type}[]"
        shadow_value = inner_array_tmp_var
        return shadow_value
    # 变量、常量、数组、指针声明
    def variable_declaration(self, node, statements):

        modifiers = []
        self.search_for_modifiers(node, modifiers)
        mytype = self.find_child_by_field(node, "type")
        shadow_mytype = self.read_node_text(mytype)
        self.search_for_modifiers(mytype,modifiers)

         # 枚举类型变量声明
        if mytype.type == "enum_specifier":
            enum_name = self.enum_declaration(mytype, statements)
            shadow_mytype = enum_name
        # 结构体类型变量声明
        elif mytype.type in ["struct_specifier","union_specifier"]:
            struct_name = self.struct_specifier(mytype,statements)
            shadow_mytype = struct_name

        declarators = self.find_children_by_field(node, "declarator")
        for declarator in declarators:
            shadow_type = shadow_mytype
            shadow_value = None
            has_init = False
            value = self.find_child_by_field(declarator, "value")
            if value != None and value.type == "compound_literal_expression":
                value = self.find_child_by_field(value, "value")
            #处理嵌套的declarator
            array_list = []
            while child_declarator := self.find_child_by_field(declarator, "declarator"):
                if declarator.type == "array_declarator":
                    has_init = True
                    array_list.append("array")
                elif declarator.type == "function_declarator":
                    return
                elif declarator.type == "pointer_declarator":
                    shadow_type += '*'
                #干掉了search_for_modifier,attr没意思
                declarator = child_declarator
            array_list.append(shadow_type)
            if value is None:
                pass
            elif value.type == "initializer_list":
                has_init = True
                shadow_value = self.initializer_list(value, statements, array_list)
            else:
                has_init = True
                shadow_value = self.parse(value, statements)
            name = self.read_node_text(declarator)

            self.append_stmts(statements,  node, {"variable_decl":
                               {"attrs": modifiers,
                                "data_type": shadow_type,
                                "name": name}})
            if has_init:
                if value and (value.type == "number_literal" or value.type == "char_literal"):
                    value = self.parse(value, statements)
                    self.append_stmts(statements,  node, {"assign_stmt":
                                   {"target": name,
                                    "operand": value,
                                    "data_type": shadow_type}})
                else:
                    self.append_stmts(statements,  node, {"assign_stmt":
                                    {"target": name,
                                        "operand": shadow_value,
                                        "data_type": shadow_type}})


    def enum_declaration(self, node, statements):
        # 枚举体的名称
        child_node = ["name", "underlying_type"]
        children = {}
        attrs = []
        enum_constants = []
        for cn in child_node:
            child = self.find_child_by_field(node, cn)
            if child:
                shadow_child = f"shadow_{cn}"
                # util.debug(f"enum_declaration----当前处理的节点内容为：{self.read_node_text(child)}")
                children[shadow_child] = self.parse(child, statements)
        if children.get("shadow_underlying_type"):
            attrs.append(children["shadow_underlying_type"])
        # optional($.attribute_specifier),
        if attribute_specifier := self.find_child_by_type(node, "attribute_specifier"):
            attrs.append(self.read_node_text(attribute_specifier))
        name = children["shadow_name"] if children.get("shadow_name") else self.tmp_variable()

        # 处理枚举类型体
        body = self.find_child_by_field(node, "body")
        # 如果没有body，则不算枚举类型声明，而只是枚举类型变量声明
        if body:
            self.enum_body(body, enum_constants)
            self.append_stmts(statements,  node, {"enum_decl": {"name": name, "attrs": attrs, "enum_constants": enum_constants}})
        return f"name"

    def enum_body(self, node, enum_constants_list):
        enumerator_children = self.find_children_by_type(node, "enumerator")
        for enumerator in enumerator_children:
            name = self.find_child_by_field(enumerator, "name")
            value = self.find_child_by_field(enumerator, "value")
            shadow_name = self.read_node_text(name)
            shadow_value = self.parse(value, list) if value else ""
            enum_constants_list.append({"enum_constant": {"name": shadow_name, "value": shadow_value}})

    # ----------------------------------------------------------------------------

    # 语句
    def is_statement(self, node):
        return self.check_statement_handler(node) is not None

    def statement(self, node, statements):
        handler = self.check_statement_handler(node)
        return handler(node, statements)

    def check_statement_handler(self, node):
        return self.STATEMENT_HANDLER_MAP.get(node.type, None)

    def return_statement(self, node, statements):
        shadow_name = ""
        if node.named_child_count > 0:
            name = node.named_children[0]
            shadow_name = self.parse(name, statements)

        self.append_stmts(statements,  node, {"return_stmt": {"name": shadow_name}})
        return shadow_name

    def if_statement(self, node, statements):
        condition_part = self.find_child_by_field(node, "condition")
        # 第一个if的then部分
        true_part = self.find_child_by_field(node, "consequence")
        # 第一个if的else部分。多层else if的嵌套也在这里
        false_part = self.find_child_by_field(node, "alternative")

        true_body = []
        #self.sync_tmp_variable(statements, true_body)
        false_body = []
        #self.sync_tmp_variable(statements, false_body)

        shadow_condition = self.parse(condition_part, statements)
        self.parse(true_part, true_body)
        self.parse(false_part, false_body)

        self.append_stmts(statements,  node, {"if_stmt": {"condition": shadow_condition, "then_body": true_body, "else_body": false_body}})

    def while_statement(self, node, statements):
        condition = self.find_child_by_field(node, "condition")
        body = self.find_child_by_field(node, "body")

        new_condition_init = []

        #self.sync_tmp_variable(new_condition_init, statements)
        shadow_condition = self.parse(condition, new_condition_init)

        new_while_body = []
        #self.sync_tmp_variable(new_while_body, statements)
        self.parse(body, new_while_body)

        #statements.extend(new_condition_init)
        #new_while_body.extend(new_condition_init)

        self.append_stmts(statements,  node, {"while_stmt": {
            "condition": shadow_condition, "condition_prebody": new_condition_init, "body": new_while_body
        }})

    def for_statement(self, node, statements):
        init_children = self.find_children_by_field(node, "initializer")
        step_children = self.find_children_by_field(node, "update")

        condition = self.find_child_by_field(node, "condition")

        init_body = []
        condition_init = []
        step_body = []

        #self.sync_tmp_variable(init_body, statements)
        #self.sync_tmp_variable(condition_init, statements)
        #self.sync_tmp_variable(step_body, statements)

        shadow_condition = self.parse(condition, condition_init)
        for child in init_children:
            # FIXME: 处理C中的declaration
            self.parse(child, init_body)

        for child in step_children:
            self.parse(child, step_body)

        for_body = []
        #self.sync_tmp_variable(for_body, statements)

        body_compound = self.find_child_by_field(node, "body")
        self.parse(body_compound, for_body)

        self.append_stmts(statements,  node, {"for_stmt":
                               {"init_body": init_body,
                                "condition": shadow_condition,
                                "condition_prebody": condition_init,
                                "update_body": step_body,
                                "body": for_body}})

    def switch_statement(self, node, statements):
        # 标记return为switch_return
        switch_ret = self.tmp_variable()

        switch_body = self.find_child_by_field(node, "body")
        condition = self.find_child_by_field(node, "condition")
        shadow_condition = self.parse(condition, statements)

        case_stmt_list = []
        #self.sync_tmp_variable(statements, case_stmt_list)
        self.append_stmts(statements,  node, {"switch_stmt": {"condition": shadow_condition, "body": case_stmt_list}})

        # 对每个case_statement都遍历一遍c中，每个case标签只能有一个
        for case in switch_body.named_children:
            # util.debug(f"nnnnnnnnnnn----case.children[0]_text is : {self.read_node_text(case.children[0])}")  # case or default

            if case.type == "comment":
                continue
            if self.read_node_text(case.children[0]) == "case":
                label = self.find_child_by_field(case, "value")
                case_init = []
                #self.sync_tmp_variable(statements, case_init)
                shadow_label = self.parse(label, case_init)
                if case_init != []:
                    statements.insert(-1, case_init)

                    # for c in case.children:
                    #     util.debug(self.read_node_text(c)+"///")
                    '''
                    case///
                    2///
                    :///
                    c = 4;///
                    break;///
                    '''

                # 如果该case statement中只有标签
                if label == case.named_children[-1]:
                    case_stmt_list.append({"case_stmt": {"condition": shadow_label}})

                # 除了标签之外有其他内容
                else:
                    new_body = []
                    #self.sync_tmp_variable(statements, new_body)
                    # 遍历所有语句
                    for stmt in case.named_children[1:]:
                        self.parse(stmt, new_body)
                    case_stmt_list.append({"case_stmt": {"condition": shadow_label, "body": new_body}})


            # default部分
            elif self.read_node_text(case.children[0]) == "default":
                new_body = []
                #self.sync_tmp_variable(statements, new_body)
                # 遍历所有语句
                for stmt in case.named_children:
                    self.parse(stmt, new_body)
                case_stmt_list.append({"default_stmt": {"body": new_body}})

        return switch_ret  # ?

    def dowhile_statement(self, node, statements):
        body = self.find_child_by_field(node, "body")
        condition = self.find_child_by_field(node, "condition")

        do_body = []
        #self.sync_tmp_variable(do_body, statements)
        self.parse(body, do_body)
        condition_body = []
        shadow_condition = self.parse(condition, condition_body)

        self.append_stmts(statements, node, {"dowhile_stmt": {
            "body": do_body, "condition_prebody": condition_body, "condition": shadow_condition
        }})

    def break_statement(self, node, statements):
        self.append_stmts(statements,  node, {"break_stmt": {}})

    def continue_statement(self, node, statements):
        self.append_stmts(statements,  node, {"continue_stmt": {}})

    def goto_statement(self, node, statements):
        label = self.find_child_by_field(node, "label")
        label_text = self.read_node_text(label)
        self.append_stmts(statements,  node, {"goto_stmt": {"name": label_text}})

    def label_statement(self, node, statements):
        label = self.find_child_by_field(node, "label")
        shadow_label = self.read_node_text(label)
        self.append_stmts(statements,  node, {"label_stmt": {"name": shadow_label}})

        if node.named_child_count > 1:
            stmt = node.named_children[1]
            self.parse(stmt, statements)

    def attributed_statement(self, node, statements):
        # attributed_statement = "attribute_declaration"* statement
        # attr_decls = []
        # for child in node.named_children:
        #     if child.type == "attribute_declaration":
        #         self.parse(child, attr_decls)
        #     else: # attr_decl到头之后是statememt，先把attr_decl放进去
        #         self.append_stmts(statements,  node, {"attributed_stmt": attr_decls})
        #         self.parse(child, statements)
        return ""

    def case_statement(self, node, statements):
        # case_statement = "case" "(" expression ")" statement ("default" statement)?

        body = []
        if self.read_node_text(node.children[0]) == "default":
            for child in node.named_children:
                self.parse(child, body)
            self.append_stmts(statements,  node, {"default_stmt": {"body": body}})
        else:
            value = self.find_child_by_field(node, "value")
            shadow_value = self.parse(value, statements)
            for child in node.named_children[1:]:
                self.parse(child, body)
            self.append_stmts(statements,  node, {"case_stmt": {"condition": shadow_value, "body": body}})

        return 0

    def seh_try_statement(self, node, statements):
        try_op = {}

        body = self.find_child_by_field(node, "body")
        try_body = []
        self.parse(body, try_body)
        try_op["body"] = try_body

        except_clause = self.find_child_by_type(node, "seh_except_clause")
        if except_clause:
            filter = self.find_child_by_field(except_clause, "filter")
            shadow_filter = self.parse(filter, statements)
            body = self.find_child_by_field(except_clause, "body")
            shadow_body = []
            self.parse(body, shadow_body)
            try_op["except_clause"] = [{"filter": shadow_filter, "body": shadow_body}]
        else:
            finally_clause = self.find_child_by_type(node, "seh_finally_clause")
            body = self.find_child_by_field(finally_clause, "body")
            shadow_body = []
            self.parse(body, shadow_body)
            try_op["finally_clause"] = [{"body": shadow_body}]

        self.append_stmts(statements,  node, {"try_stmt": try_op})

        return 0

    def seh_leave_statement(self, node, statements):
        # self.append_stmts(statements,  node, {"leave_stmt": {}})
        return 0
    # ----------------------------------------------------------------------------

    def is_comment(self, node):
        # 判断是否//开头。 但会不会把printf("//xxxx")也给屏蔽了
        if self.read_node_text(node).startswith("//"):
            return True
        return False
