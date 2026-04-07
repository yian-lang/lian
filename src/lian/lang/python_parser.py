#!/usr/bin/env python3

import re
from tree_sitter import Node

from lian.config import config
from lian.util import util
from lian.config.constants import LIAN_INTERNAL
from lian.lang import common_parser


class Parser(common_parser.Parser):
    def init(self):
        self.CONSTANTS_MAP = {
            "None"                              : LIAN_INTERNAL.NULL,
            "True"                              : LIAN_INTERNAL.TRUE,
            "False"                             : LIAN_INTERNAL.FALSE,
        }

        self.LITERAL_MAP = {
            "integer"                           : self.regular_number_literal,
            "float"                             : self.regular_number_literal,
            "true"                              : self.regular_literal,
            "false"                             : self.regular_literal,
            "none"                              : self.regular_literal,
            "string"                            : self.string,
            "string_content"                    : self.string_literal,
            "concatenated_string"               : self.concatenated_string,
            "interpolation"                     : self.interpolation,
            "identifier"                        : self.regular_literal,
        }

        self.DECLARATION_HANDLER_MAP = {
            "function_definition"               : self.function_definition,
            "class_definition"                  : self.class_definition,
            "decorated_definition"              : self.decorated_definition,
        }

        self.EXPRESSION_HANDLER_MAP = {
            "await"                             : self.await_expression,
            "expression_list"                   : self.expression_list,
            "pattern_list"                      : self.pattern_list,
            "lambda"                            : self.lambda_expression,
            "conditional_expression"            : self.conditional_expression,
            "named_expression"                  : self.named_expression,
            "as_pattern"                        : self.as_pattern,
            "call"                              : self.call_expression,
            "list"                              : self.list_expression,
            "set"                               : self.list_expression,
            "list_pattern"                      : self.list_expression,
            "tuple"                             : self.tuple_expression,
            "tuple_pattern"                     : self.tuple_expression,
            "dictionary"                        : self.dictionary,
            "subscript"                         : self.subscript,
            "attribute"                         : self.attribute,
            "assignment"                        : self.assignment,
            "augmented_assignment"              : self.assignment,
            "list_comprehension"                : self.list_set_dictionary_comprehension,
            "dictionary_comprehension"          : self.list_set_dictionary_comprehension,
            "set_comprehension"                 : self.list_set_dictionary_comprehension,
            "generator_expression"              : self.list_set_dictionary_comprehension,
            "binary_operator"                   : self.binary_comparison_operator,
            "comparison_operator"               : self.binary_comparison_operator,
            "not_operator"                      : self.not_operator,
            "boolean_operator"                  : self.boolean_operator,
            "unary_operator"                    : self.unary_operator,
        }

        self.STATEMENT_HANDLER_MAP = {
            "future_import_statement"           : self.from_import_statement,
            "import_statement"                  : self.import_statement,
            "import_from_statement"             : self.from_import_statement,
            "assert_statement"                  : self.assert_statement,
            "expression_statement"              : self.expression_statement,
            "return_statement"                  : self.return_statement,
            "delete_statement"                  : self.delete_statement,
            "raise_statement"                   : self.raise_statement,
            "pass_statement"                    : self.pass_statement,
            "break_statement"                   : self.break_statement,
            "continue_statement"                : self.continue_statement,
            "global_statement"                  : self.global_statement,
            "nonlocal_statement"                : self.nonlocal_statement,
            "type_alias_statement"              : self.type_alias_statement,
            "if_statement"                      : self.if_statement,
            "for_statement"                     : self.for_statement,
            "while_statement"                   : self.while_statement,
            "try_statement"                     : self.try_statement,
            "with_statement"                    : self.with_statement,
            "match_statement"                   : self.match_statement,
            "yield"                             : self.yield_statement,
        }

    def is_comment(self, node):
        return node.type in ["line_comment", "block_comment"]

    def is_identifier(self, node):
        return node.type == "identifier" or node.type == "keyword_identifier"

    def regular_number_literal(self, node: Node, statements: list, replacement):
        value = self.read_node_text(node)
        value = self.common_eval(value)
        return str(value)

    def regular_literal(self, node: Node, statements: list, replacement):
        content = self.read_node_text(node)
        return self.CONSTANTS_MAP.get(content, content)

    def string(self, node: Node, statements: list, replacement):
        last_assign_result = ""
        start_end_tag = ["string_start", "string_end"]
        if node.named_child_count > 3:
            for index in range(len(node.named_children)):
                cur_node = node.named_children[index]
                if cur_node.type in start_end_tag:
                    continue
                tmp_var = self.tmp_variable()
                shadow_oprand = self.parse(cur_node, statements)
                if index == 1:
                    last_assign_result = shadow_oprand
                    continue
                if shadow_oprand:
                    self.append_stmts(statements, node, {"assign_stmt": {"target": tmp_var, "operator": "+", "operand": last_assign_result, "operand2": shadow_oprand}})
                    last_assign_result = tmp_var
            return tmp_var

        for child in node.named_children:
            if child.type in start_end_tag:
                continue
            tmp_var = self.tmp_variable()
            shadow_oprand = self.parse(child, statements)
            # self.append_stmts(statements, node, {"assign_stmt": {"target": tmp_var, "operand": shadow_oprand}}
            return shadow_oprand

    def concatenated_string(self, node: Node, statements: list, replacement):
        pass

    def interpolation(self, node: Node, statements: list, replacement):
        child = node.named_children[0]
        if child.type == "expression_list":
            if child.named_child_count > 0:
                for expr in child.named_children:
                    shadow_expr = self.parse(expr, statements)
                    replacement.append((expr, shadow_expr))
        else:
            expr = node.named_children[0]
            shadow_expr = self.parse(expr, statements)
            replacement.append((expr, shadow_expr))

        return shadow_expr

    def string_literal(self, node: Node, statements: list, replacement):
        replacement = []
        for child in node.named_children:
            self.parse(child, statements, replacement)

        ret = self.read_node_text(node)
        if replacement:
            for r in replacement:
                (expr, value) = r
                ret = ret.replace(self.read_node_text(expr), value)

        ret = self.handle_hex_string(ret)

        return self.escape_string(ret)

    def is_constant_literal(self, node):
        return node.type in [
            "string",
            "concatenated_string",
            "integer",
            "float",
            "true",
            "false",
            "none",
        ]

    def obtain_literal_handler(self, node):
        return self.LITERAL_MAP.get(node.type, None)

    def is_literal(self, node):
        return self.obtain_literal_handler(node) is not None

    def literal(self, node: Node, statements: list, replacement):
        handler = self.obtain_literal_handler(node)
        return handler(node, statements, replacement)

    def function_definition(self, node: Node, statements: list):
        modifiers = []
        parent = node.parent

        decorator_point, start_col = node.start_point
        if parent.type == "decorated_definition":
            decorator_nodes = self.find_children_by_type(parent, "decorator")
            first_decorator = decorator_nodes[0]
            decorator_point, start_col = first_decorator.start_point
            for decorator_node in decorator_nodes:
                identifier_node = self.find_child_by_type(decorator_node, "identifier")
                identifier = self.read_node_text(identifier_node)
                modifiers.append(identifier)

        if node.named_child_count > 0 and self.read_node_text(node.children[0]) == "async":
            modifiers.append("async")

        return_type = self.find_child_by_field(node, "return_type")
        if return_type:
            shadow_return_type = self.read_node_text(return_type)
        else:
            shadow_return_type = None

        method_name = self.find_child_by_field(node, "name")
        shadow_method_name = self.read_node_text(method_name)

        parameter_decls = []
        attrs = []

        parameters = self.find_child_by_field(node, "parameters")
        if parameters and parameters.named_child_count > 0:
            positional_separator = self.find_child_by_type(parameters, "positional_separator")
            only_positional = False
            if positional_separator:
                only_positional = True
            only_keyword = False
            for parameter in parameters.named_children:
                attrs = []
                if only_positional:
                    attrs.append(LIAN_INTERNAL.POSITIONAL_ONLY_PARAMETER)

                if only_keyword:
                    attrs.append(LIAN_INTERNAL.KEYWORLD_ONLY_PARAMETER)

                if self.is_comment(parameter):
                    continue

                parameter_node_type = parameter.type
                if parameter_node_type == "identifier":
                    parameter_decls.append(self.add_col_row_info(
                        parameter, {"parameter_decl": {"name": self.read_node_text(parameter), "attrs": attrs}}
                    ))

                elif parameter_node_type == "typed_parameter":
                    if parameter.named_child_count > 0:
                        parameter_name = parameter.named_children[0]
                        shadow_parameter_name = self.parse(parameter_name, statements)

                        parameter_type = self.find_child_by_field(parameter, "type")
                        shadow_type = self.read_node_text(parameter_type)
                        if parameter_name.type == "dictionary_splat_pattern":
                            attrs.append(LIAN_INTERNAL.PACKED_NAMED_PARAMETER)
                        parameter_decls.append(self.add_col_row_info(
                            parameter,
                            {"parameter_decl": {
                                "data_type": shadow_type, "name": shadow_parameter_name, "attrs": attrs
                            }}
                        ) )

                elif parameter_node_type == "default_parameter":
                    parameter_name = self.find_child_by_field(parameter, "name")
                    parameter_value = self.find_child_by_field(parameter, "value")

                    shadow_parameter_name = self.parse(parameter_name, statements)
                    if self.is_literal(parameter_value) and parameter_value.type != "identifier":
                        shadow_value = self.parse(parameter_value, statements)
                        parameter_decls.append(self.add_col_row_info(
                            parameter,
                            {"parameter_decl": {
                                "name": shadow_parameter_name, "attrs": attrs, "default_value": shadow_value
                            }}
                        ))

                    else:
                        tmp_body = []
                        shadow_value = self.parse(parameter_value, tmp_body)
                        # first_char = shadow_value[0]
                        # if first_char in ["%", "$", "@"]:
                        #     self.append_stmts(statements, node, {"variable_decl": {"name": shadow_value}}
                        #     tmp_parameter = shadow_value
                        # else:
                        #     tmp_parameter = self.tmp_variable()
                        #     self.append_stmts(statements, node, {"variable_decl": {"name": tmp_parameter}}
                        #     self.append_stmts(statements, node, {"assign_stmt": {"target": tmp_parameter, "operand": shadow_value}}
                        tmp_parameter = self.default_value_variable()
                        # tmp_parameter += LianInternal.TRANS_VARIABLE_SUFF
                        self.append_stmts(statements,
                            node, {"variable_decl": {"name": tmp_parameter}}
                        )
                        statements.extend(tmp_body)
                        self.append_stmts(statements,
                            node,
                            {"assign_stmt": {"target": tmp_parameter, "operand": shadow_value}}
                        )
                        parameter_decls.append(self.add_col_row_info(
                            parameter,
                            {"parameter_decl": {
                                "name": shadow_parameter_name, "attrs": attrs, "default_value": tmp_parameter
                            }}
                        ))

                elif parameter_node_type == "typed_default_parameter":
                    parameter_name = self.find_child_by_field(parameter, "name")
                    parameter_value = self.find_child_by_field(parameter, "value")
                    parameter_type = self.find_child_by_field(parameter, "type")

                    shadow_parameter_type = self.read_node_text(parameter_type)
                    shadow_parameter_name = self.parse(parameter_name, statements)

                    if self.is_literal(parameter_value) and parameter_value.type != "identifier":
                        shadow_value = self.parse(parameter_value, statements)
                        parameter_decls.append(self.add_col_row_info(parameter, {
                            "parameter_decl": {
                                "data_type"     : shadow_parameter_type,
                                "name"          : shadow_parameter_name,
                                "attrs"          : attrs,
                                "default_value" : shadow_value}}))

                    else:
                        tmp_body = []
                        shadow_value = self.parse(parameter_value, tmp_body)
                        tmp_parameter = shadow_value
                        if shadow_value:
                            if shadow_value[0] in ["%", "$", "@"]:
                                statements.insert(
                                    len(statements) - 1, {"variable_decl": {"name": shadow_value}}
                                )
                                statements.extend(tmp_body)
                            else:
                                tmp_parameter = self.tmp_variable()
                                self.append_stmts(statements,
                                    node, {"variable_decl": {"name": tmp_parameter}}
                                )
                                statements.extend(tmp_body)
                                self.append_stmts(statements,
                                    node, {"assign_stmt": {"target": tmp_parameter, "operand": shadow_value}}
                                )

                        parameter_decls.append(self.add_col_row_info(parameter, {
                            "parameter_decl": {
                                "data_type"     : shadow_parameter_type,
                                "name"          : shadow_parameter_name,
                                "attrs"          : attrs,
                                "default_value" : tmp_parameter}}))

                elif parameter_node_type == "list_splat_pattern":
                    parameter_name = parameter.named_children[0]
                    shadow_parameter_name = self.parse(parameter_name, statements)
                    attrs.append(LIAN_INTERNAL.PACKED_POSITIONAL_PARAMETER)
                    parameter_decls.append(self.add_col_row_info(parameter, {"parameter_decl": {"name": shadow_parameter_name, "attrs": attrs}}))
                    only_keyword = True

                elif parameter_node_type == "dictionary_splat_pattern":
                    parameter_name = parameter.named_children[0]
                    shadow_parameter_name = self.parse(parameter_name, statements)
                    attrs.append(LIAN_INTERNAL.PACKED_NAMED_PARAMETER)
                    parameter_decls.append(self.add_col_row_info(parameter, {"parameter_decl": {"name": shadow_parameter_name, "attrs": attrs}}))

                elif parameter_node_type == "positional_separator":
                    only_positional = False

                elif parameter_node_type == "keyword_separator":
                    only_keyword = True

        new_body = []
        #self.sync_tmp_variable(new_body, init)
        child = self.find_child_by_field(node, "body")
        if child:
            for stmt in child.named_children:
                if self.is_comment(stmt):
                    continue

                self.parse(stmt, new_body)

        self.append_stmts(statements,
            node,
            {
                "method_decl": {
                    "attrs": modifiers,
                    "decorators": decorator_point,
                    "data_type": shadow_return_type,
                    "name": shadow_method_name,
                    "parameters": parameter_decls,
                    "body": new_body
                }
            }
        )
        return shadow_method_name

    def class_definition(self, node: Node, statements: list):
        gir_node = {}

        gir_node["attrs"] = []
        gir_node["methods"] = []
        gir_node["fields"] = []
        gir_node["supers"] = []
        gir_node["nested"] = []


        child = self.find_child_by_field(node, "name")
        if child:
            gir_node["name"] = self.read_node_text(child)

        child = self.find_child_by_field(node, "type_parameters")
        if child:
            type_parameters = self.read_node_text(child)
            gir_node["type_parameters"] = type_parameters[1:-1]

        child = self.find_child_by_field(node, "superclasses")
        if child :
            superclass = child.named_children
            for super in superclass:
                if super.type == "subscript":
                    gir_node["supers"].append(self.read_node_text(super))
                elif super.type != "keyword_argument":
                    parent_class = self.parse(super, statements)
                    gir_node["supers"].append(parent_class)

        body = self.find_child_by_field(node, "body")
        init_class_method = {}
        init_class_method_body = []
        static_init_class_method_body = []
        for child in body.named_children:
            if child.type == "function_definition":
                methods = []
                self.parse(child, methods)
                i = 0
                while i < len(methods):
                    stmt = methods[i]
                    if "method_decl" not in stmt:
                        init_class_method_body.append(stmt)
                    else:
                        gir_node["methods"].append(stmt)
                    i += 1

            elif child.type == "class_definition":
                self.parse(child, gir_node["nested"])

            elif child.type == "decorated_definition":
                decorated_defs = []
                self.parse(child, decorated_defs)
                for decorated_stmt in decorated_defs:
                    if "method_decl" in decorated_stmt:
                        gir_node["methods"].append(decorated_stmt)
                    else:
                        static_init_class_method_body.append(decorated_stmt)

            else:
                tmp_stmts = []
                self.parse(child, tmp_stmts)
                for stmt in tmp_stmts:
                    if "variable_decl" in stmt:
                        gir_node["fields"].append(stmt)
                    elif "assign_stmt" in stmt:
                        field = stmt["assign_stmt"]
                        static_init_class_method_body.append(self.add_col_row_info(node, {
                            "field_write": {
                                "receiver_object"   : self.current_class(),
                                "field"             : field["target"],
                                "source"            : field["operand"]}}))


        statements.extend(init_class_method_body)

        if len(static_init_class_method_body) > 0:
            gir_node["methods"].insert(0,
            {
                "method_decl":{
                    "name": LIAN_INTERNAL.CLASS_STATIC_INIT,
                    "body": static_init_class_method_body
                }
            })
        self.append_stmts(statements, node, {"class_decl": gir_node})

        return gir_node["name"]

    def decorated_definition(self, node: Node, statements: list):
        definition = self.find_child_by_field(node, "definition")
        name = self.parse(definition, statements)
        #
        # decorator = self.find_child_by_type(node, "decorator")
        # shadow_decorator = self.parse(decorator, statements)

        # target = self.tmp_variable()
        # self.append_stmts(statements,
        #     node, {"call_stmt": {"target": target, "name": shadow_decorator, "positional_args": [name]}}
        # )
        # self.append_stmts(statements,
        #     node, {"assign_stmt": {"target": name, "operand": target}}
        # )

    def check_declaration_handler(self, node):
        return self.DECLARATION_HANDLER_MAP.get(node.type, None)

    def is_declaration(self, node):
        return self.check_declaration_handler(node) is not None

    def declaration(self, node: Node, statements: list):
        handler = self.check_declaration_handler(node)
        return handler(node, statements)

    def await_expression(self, node: Node, statements: list):
        shadow_expr = ""
        if node.named_child_count > 0:
            expr = node.named_children[0]
            shadow_expr = self.parse(expr, statements)
        self.append_stmts(statements, node, {"await_stmt": {"target": shadow_expr}})
        return shadow_expr

    def expression_list(self, node: Node, statements: list):
        shadow_expr_list = []
        if node.named_child_count > 0:
            for expr in node.named_children:
                shadow_expr = self.parse(expr, statements)
                shadow_expr_list.append(shadow_expr)

        tmp_var = self.tmp_variable()
        self.append_stmts(statements, node, {"new_array": {"target": tmp_var, "attrs": ["tuple"]}})
        if len(shadow_expr_list) > 0:
            for index, item in enumerate(shadow_expr_list):
                self.append_stmts(statements, node, {"array_write": {"array": tmp_var, "index": str(index), "source": item}})

        return tmp_var

    def pattern_list(self, node: Node, statements: list):
        shadow_pattern_list = []
        if node.named_child_count > 0:
            for pattern in node.named_children:
                shadow_pattern = self.parse(pattern, statements)
                shadow_pattern_list.append(shadow_pattern)

        tmp_var = self.tmp_variable()
        self.append_stmts(statements, node, {"new_array": {"target": tmp_var}})
        if len(shadow_pattern_list) > 0:
            for index, item in enumerate(shadow_pattern_list):
                self.append_stmts(statements, node, {"array_write": {"array": tmp_var, "index": str(index), "source": item}})

        return tmp_var

    def call_expression(self, node: Node, statements: list):
        tmp_call = self.tmp_variable()
        call_name = self.find_child_by_field(node, "function")
        receiver_name = None
        field_name = None
        if call_name.type == "attribute":
            receiver_name, field_name = self.parse_field(call_name, statements)
        else:
            shadow_call_name = self.parse(call_name, statements)

        args = self.find_child_by_field(node, "arguments")
        if args.named_child_count == 0:
            if call_name.type == "attribute":
                self.append_stmts(
                    statements,
                    node,
                    {"object_call_stmt": {"target": tmp_call, "field": field_name, "receiver_object": receiver_name}}
                )
                return tmp_call
            else:
                self.append_stmts(
                    statements,
                    node,
                    {"call_stmt": {"target": tmp_call, "name": shadow_call_name}}
                )
                return tmp_call

        positional_args = []
        named_args = None
        packed_array_args = None
        packed_record_args = None


        if args.type == "argument_list":
            list_splat_children = self.find_children_by_type(args, "list_splat")
            if list_splat_children:
                packed_array_args = self.list_expression(args, statements)

            else:
                for child in args.named_children:
                    if child.type not in ["list_splat", "dictionary_splat", "keyword_argument"]:
                        shadow_expr = self.parse(child, statements)
                        if shadow_expr:
                            positional_args.append(shadow_expr)

            dictionary_splats = self.find_children_by_type(args, "dictionary_splat")
            if dictionary_splats:
                packed_record_args = self.tmp_variable()
                self.append_stmts(statements, node, {"new_record": {"target": packed_record_args}})
                for child in dictionary_splats:
                    shadow_expr = self.parse(child.named_children[0], statements)
                    self.append_stmts(statements, node, {"record_extend": {"record": packed_record_args, "source": shadow_expr}})

                keyword_arguments = self.find_children_by_type(args, "keyword_argument")
                for child in keyword_arguments:
                    parameter_name = self.find_child_by_field(child, "name")
                    parameter_value = self.find_child_by_field(child, "value")

                    shadow_parameter_name = self.parse(parameter_name, statements)
                    shadow_value = self.parse(parameter_value, statements)
                    self.append_stmts(statements, node, {"record_write": {"receiver_record": packed_record_args, "key": shadow_parameter_name, "value": shadow_value}})

            else:
                keyword_arguments = self.find_children_by_type(args, "keyword_argument")
                if keyword_arguments:
                    named_args = {}
                    for child in keyword_arguments:
                        name = self.find_child_by_field(child, "name")
                        value = self.find_child_by_field(child, "value")

                        shadow_parameter_name = self.parse(name, statements)
                        shadow_value = self.parse(value, statements)
                        named_args[shadow_parameter_name] = shadow_value
                    # named_args.append((shadow_parameter_name, shadow_value))

        if named_args is not None:
            named_args = str(named_args)

        if call_name.type == "attribute":
            self.append_stmts(statements, node, {"object_call_stmt": {
                "receiver_object":receiver_name,
                "target": tmp_call,
                "field": field_name,
                "positional_args": positional_args,
                "packed_positional_args": packed_array_args,
                "packed_named_args": packed_record_args,
                "named_args": named_args}
            })

        else:
            self.append_stmts(statements, node, {"call_stmt": {
                "target": tmp_call,
                "name": shadow_call_name,
                "positional_args": positional_args,
                "packed_positional_args": packed_array_args,
                "packed_named_args": packed_record_args,
                "named_args": named_args}
            })

        return tmp_call

    def lambda_expression(self, node: Node, statements: list):
        tmp_func = self.tmp_method()

        parameter_decls = []
        tmp_body = []
        parameters = self.find_child_by_field(node, "parameters")
        if parameters and parameters.named_child_count > 0:
            positional_separator = self.find_child_by_type(parameters, "positional_separator")
            only_positional = False
            if positional_separator:
                only_positional = True
            only_keyword = False
            for parameter in parameters.named_children:
                attrs = []
                if only_positional:
                    attrs.append(LIAN_INTERNAL.POSITIONAL_ONLY_PARAMETER)

                if only_keyword:
                    attrs.append(LIAN_INTERNAL.KEYWORLD_ONLY_PARAMETER)

                if self.is_comment(parameter):
                    continue

                parameter_node_type = parameter.type
                if parameter_node_type == "identifier":
                    parameter_decls.append(self.add_col_row_info(node, {"parameter_decl": {"name": self.read_node_text(parameter), "attrs": attrs}}))

                elif parameter_node_type == "typed_parameter":
                    shadow_parameter_name = ""
                    if parameter.named_child_count > 0:
                        parameter_name = parameter.named_children[0]
                        shadow_parameter_name = self.parse(parameter_name, statements)

                    parameter_type = self.find_child_by_field(parameter, "type")
                    shadow_type = self.read_node_text(parameter_type)

                    parameter_decls.append(self.add_col_row_info(node, {"parameter_decl": {"data_type": shadow_type, "name": shadow_parameter_name, "attrs": attrs}}))

                elif parameter_node_type == "default_parameter":
                    parameter_name = self.find_child_by_field(parameter, "name")
                    parameter_value = self.find_child_by_field(parameter, "value")

                    shadow_parameter_name = self.parse(parameter_name, statements)
                    if self.is_literal(parameter_value) and parameter_value.type != "identifier":
                        shadow_value = self.parse(parameter_value, statements)
                        parameter_decls.append(self.add_col_row_info(node, {"parameter_decl": {"name": shadow_parameter_name, "attrs": attrs, "default_value": shadow_value}}))

                    else:
                        tmp_body = []
                        shadow_value = self.parse(parameter_value, tmp_body)
                        # first_char = shadow_value[0]
                        # if first_char in ["%", "$", "@"]:
                        #     self.append_stmts(statements, node, {"variable_decl": {"name": shadow_value}}
                        #     tmp_parameter = shadow_value
                        # else:
                        #     tmp_parameter = self.tmp_variable()
                        #     self.append_stmts(statements, node, {"variable_decl": {"name": tmp_parameter}}
                        #     self.append_stmts(statements, node, {"assign_stmt": {"target": tmp_parameter, "operand": shadow_value}}
                        tmp_parameter = self.default_value_variable()
                        # tmp_parameter += LianInternal.TRANS_VARIABLE_SUFF
                        self.append_stmts(statements, node, {"variable_decl": {"name": tmp_parameter}})
                        statements.extend(tmp_body)
                        self.append_stmts(statements, node, {"assign_stmt": {"target": tmp_parameter, "operand": shadow_value}})
                        parameter_decls.append(self.add_col_row_info(node, {"parameter_decl": {"name": shadow_parameter_name, "attrs": attrs, "default_value": tmp_parameter}}))

                elif parameter_node_type == "typed_default_parameter":
                    parameter_name = self.find_child_by_field(parameter, "name")
                    parameter_value = self.find_child_by_field(parameter, "value")
                    parameter_type = self.find_child_by_field(parameter, "type")

                    shadow_parameter_type = self.read_node_text(parameter_type)
                    shadow_parameter_name = self.parse(parameter_name, statements)

                    if self.is_literal(parameter_value) and parameter_value.type != "identifier":
                        shadow_value = self.parse(parameter_value, statements)
                        parameter_decls.append(self.add_col_row_info(node, {
                            "parameter_decl": {
                                "data_type"     : shadow_parameter_type,
                                "name"          : shadow_parameter_name,
                                "attrs"          : attrs,
                                "default_value" : shadow_value}}))

                    else:
                        tmp_body = []
                        shadow_value = self.parse(parameter_value, tmp_body)
                        tmp_parameter = shadow_value
                        if shadow_value:
                            first_char = shadow_value[0]
                            if first_char in ["%", "$", "@"]:
                                statements.insert(len(statements) - 1, {"variable_decl": {"name": shadow_value}})
                            else:
                                tmp_parameter = self.tmp_variable()
                                self.append_stmts(statements, node, {"variable_decl": {"name": shadow_value}})
                                statements.extend(tmp_body)
                                self.append_stmts(statements, node, {"assign_stmt": {"target": tmp_parameter, "operand": shadow_value}})

                        parameter_decls.append(self.add_col_row_info(node, {
                            "parameter_decl": {
                                "data_type"     : shadow_parameter_type,
                                "name"          : shadow_parameter_name,
                                "attrs"          : attrs,
                                "default_value" : tmp_parameter}}))

                elif parameter_node_type == "list_splat_pattern":
                    parameter_name = parameter.named_children[0]
                    shadow_parameter_name = self.parse(parameter_name, statements)
                    attrs.append(LIAN_INTERNAL.PACKED_POSITIONAL_PARAMETER)
                    parameter_decls.append(self.add_col_row_info(node, {"parameter_decl": {"name": shadow_parameter_name, "attrs": attrs}}))
                    only_keyword = True

                elif parameter_node_type == "dictionary_splat_pattern":
                    parameter_name = parameter.named_children[0]
                    shadow_parameter_name = self.parse(parameter_name, statements)
                    attrs.append(LIAN_INTERNAL.PACKED_NAMED_PARAMETER)
                    parameter_decls.append(self.add_col_row_info(node, {"parameter_decl": {"name": shadow_parameter_name, "attrs": attrs}}))

                elif parameter_node_type == "positional_separator":
                    only_positional = False

                elif parameter_node_type == "keyword_separator":
                    only_keyword = True

        statements.extend(tmp_body)

        new_body = []
        body = self.find_child_by_field(node, "body")
        shadow_return = self.parse(body, new_body)
        new_body.append(self.add_col_row_info(node, {"return_stmt": {"name": shadow_return}}))

        # if self.is_expression(body):
        #     shadow_expr = self.parse(body, new_body)
        #     new_body.append({"return_stmt": {"name": shadow_expr}})
        # else:
        #     for stmt in body.named_children:
        #         if self.is_comment(stmt):
        #             continue

        #         shadow_expr = self.parse(body, new_body)
        #         if stmt == body.named_children[-1]:
        #             new_body.append({"return_stmt": {"name": shadow_expr}})

        self.append_stmts(statements, node, {"method_decl": {"name": tmp_func, "parameters": parameter_decls, "body": new_body}})

        return tmp_func

    def conditional_expression(self, node: Node, statements: list):
        consequence = node.named_children[0]
        condition = node.named_children[1]
        alternative = node.named_children[2]

        condition = self.parse(condition, statements)

        body = []
        elsebody = []

        #self.sync_tmp_variable(statements, body)
        #self.sync_tmp_variable(statements, elsebody)
        tmp_var = self.tmp_variable()

        expr1 = self.parse(consequence, body)
        body.append(self.add_col_row_info(node, {"assign_stmt": {"target": tmp_var, "operand": expr1}}))

        expr2 = self.parse(alternative, elsebody)
        elsebody.append(self.add_col_row_info(node, {"assign_stmt": {"target": tmp_var, "operand": expr2}}))

        self.append_stmts(statements, node, {"if_stmt": {"condition": condition, "then_body": body, "else_body": elsebody}})
        return tmp_var

    def named_expression(self, node: Node, statements: list):
        name = self.find_child_by_field(node, "name")
        shadow_name = self.parse(name, statements)

        value = self.find_child_by_field(node, "value")
        shadow_value = self.parse(value, statements)

        self.append_stmts(statements, node, {"assign_stmt": {"target": shadow_name, "operand": shadow_value}})

        return shadow_name

    def as_pattern(self, node: Node, statements: list):
        expr = node.named_children[0]
        shadow_expr = self.parse(expr, statements)

        alias = self.find_child_by_field(node, "alias")
        alias_name = self.read_node_text(alias)
        self.append_stmts(statements, node, {"variable_decl": {"name": alias_name}})
        shadow_alias = self.parse(alias, statements)

        self.append_stmts(statements, node, {"assign_stmt": {"target": shadow_alias, "operand": shadow_expr}})
        return shadow_alias

    def list_expression(self, node: Node, statements: list):
        tmp_var = self.tmp_variable()
        if node.type == "set":
            self.append_stmts(statements, node, {"new_array": {"target": tmp_var, "attrs": ["set"]}})
        self.append_stmts(statements, node, {"new_array": {"target": tmp_var}})
        if node.named_child_count == 0:
            return tmp_var

        meet_splat = False
        for index, item in enumerate(node.named_children):
            if self.is_comment(item):
                continue

            if item.type == "list_splat":
                meet_splat = True
                shadow_expr = self.parse(item, statements)
                self.append_stmts(statements, node, {"array_extend": {"array": tmp_var, "source": shadow_expr}})

            elif item.type == "dictionary_splat" or item.type == "keyword_argument":
                continue

            else:
                if meet_splat:
                    shadow_expr = self.parse(item, statements)
                    self.append_stmts(statements, node, {"array_append": {"array": tmp_var, "source": shadow_expr}})
                else:
                    shadow_expr = self.parse(item, statements)
                    self.append_stmts(statements, node, {"array_write": {"array": tmp_var, "index": str(index), "source": shadow_expr}})

        return tmp_var

    def tuple_expression(self, node: Node, statements: list):
        tmp_var = self.tmp_variable()
        self.append_stmts(statements, node, {"new_array": {"target": tmp_var, "attrs": ["tuple"]}})
        if node.named_child_count == 0:
            return tmp_var

        meet_splat = False
        for index, item in enumerate(node.named_children):
            if self.is_comment(item):
                continue

            if item.type == "list_splat":
                meet_splat = True
                shadow_expr = self.parse(item.named_children[0], statements)
                self.append_stmts(statements, node, {"array_extend": {"array": tmp_var, "source": shadow_expr}})

            else:
                if meet_splat:
                    shadow_expr = self.parse(item, statements)
                    self.append_stmts(statements, node, {"array_append": {"array": tmp_var, "source": shadow_expr}})
                else:
                    shadow_expr = self.parse(item, statements)
                    self.append_stmts(statements, node, {"array_write": {"array": tmp_var, "index": str(index), "source": shadow_expr}})

        return tmp_var

    def dictionary(self, node: Node, statements: list):
        tmp_var = self.tmp_variable()
        self.append_stmts(statements, node, {"new_record": {"target": tmp_var}})
        if node.named_child_count == 0:
            return tmp_var

        for item in node.named_children:
            if item.type == "pair":
                key = self.find_child_by_field(item, "key")
                value = self.find_child_by_field(item, "value")

                shadow_key = self.parse(key, statements)
                shadow_value = self.parse(value, statements)

                self.append_stmts(statements, node, {"record_write": {"receiver_record": tmp_var, "key": shadow_key, "value": shadow_value}})

            elif item.type == "dictionary_splat":
                shadow_expr = self.parse(item.named_children[0], statements)
                self.append_stmts(statements, node, {"record_extend": {"record": tmp_var, "source": shadow_expr}})

        return tmp_var

    def subscript(self, node: Node, statements: list):
        array = self.find_child_by_field(node, "value")
        shadow_array = self.parse(array, statements)
        subscripts = self.find_children_by_field(node, "subscript")
        is_slice = False

        if subscripts is None:
            tmp_array = self.tmp_variable()
            self.append_stmts(statements, node, {"array_read": {"target": tmp_array, "array": shadow_array, "index": ""}})
            return tmp_array
        for subscript in subscripts:
            if subscript.type == "slice":
                is_slice = True
                tmp_slice = self.tmp_variable()
                start, end, step = self.parse_slice(subscript)
                self.append_stmts(statements, node, {"slice_read": {"target": tmp_slice, "array": shadow_array, "start": str(start), "end": str(end), "step": str(step) }})
                shadow_array = tmp_slice
            else:
                is_slice = False
                tmp_array = self.tmp_variable()
                shadow_index = self.parse(subscript, statements)
                self.append_stmts(statements, node, {"array_read": {"target": tmp_array, "array": shadow_array, "index": shadow_index}})
                shadow_array = tmp_array
        if is_slice:
            return tmp_slice
        else:
            return tmp_array

    def attribute(self, node: Node, statements: list):
        tmp_var = self.tmp_variable()
        shadow_object, shadow_field = self.parse_field(node, statements)
        self.append_stmts(statements, node, {"field_read": {"target": tmp_var, "receiver_object": shadow_object, "field": shadow_field}})
        return tmp_var

    def parse_slice(self, node):
        start, end, step = None, None, None
        index_list = node.children
        colon_indices = []
        for i, symbol in enumerate(index_list):
            if self.read_node_text(symbol) == ':':
                colon_indices.append(i)
        if len(colon_indices) == 1:
            start = None if colon_indices[0] == 0 else index_list[colon_indices[0] - 1]
            end = None if colon_indices[0] + 1 == len(index_list) else index_list[colon_indices[0] + 1]
        elif len(colon_indices) == 2:
            start = None if colon_indices[0] == 0 else index_list[colon_indices[0] - 1]
            end = None if colon_indices[0] + 1 == colon_indices[1] else index_list[colon_indices[1] - 1]
            step = None if colon_indices[1] + 1 == len(index_list) else index_list[colon_indices[1] + 1]
        start = self.parse(start)
        end = self.parse(end)
        step = self.parse(step)
        return start, end, step

    def parse_comprehension_clauses(self, body: Node, target, clauses: list[Node], statements: list):
        if len(clauses) == 0:
            return
        elif len(clauses) == 1:
            clause = clauses.pop(0)
            if clause.type == "for_in_clause":
                modifiers = []
                if clause.named_child_count > 0 and self.read_node_text(clause.children[0]) == "async":
                    modifiers.append("async")
                name = self.find_child_by_field(clause, "left")
                right = self.find_child_by_field(clause, "right")
                # shadow_left = self.parse(left, statements)
                shadow_right = self.parse(right, statements)
                pattern_list = []
                if name.type == "pattern_list":
                    shadow_name = self.tmp_variable()
                    for each_child in name.named_children:
                        pattern_list.append(self.parse(each_child, statements))
                else:
                    shadow_name = self.parse(name, statements)
                for_body = []
                for index, shadow_pattern in enumerate(pattern_list):
                    for_body.append(self.add_col_row_info(clause, {"variable_decl": {"name": shadow_pattern}}))
                    for_body.append(self.add_col_row_info(clause, {
                        "array_read": {
                            "array": shadow_name,
                            "index": str(index),
                            "target": shadow_pattern
                        }
                    }))
                if body.type == "pair":
                    key = self.find_child_by_field(body, "key")
                    value = self.find_child_by_field(body, "value")
                    shadow_key = self.parse(key, for_body)
                    shadow_value = self.parse(value, for_body)
                    for_body.append(self.add_col_row_info(body, {"record_write": {"receiver_record": target, "key": shadow_key, "value": shadow_value}}))
                else:
                    shadow_body = self.parse(body, for_body)
                    for_body.append(self.add_col_row_info(body, {"array_append": {"array": target, "source":shadow_body}}))
                self.append_stmts(statements, clause, {"variable_decl": {"name": shadow_name}})

                self.append_stmts(statements, body, {"forin_stmt":
                                        {"attr": modifiers,
                                         "name": shadow_name,
                                         "receiver": shadow_right,
                                         "body": for_body}})
            else:
                expr = clause.named_children[0]
                shadow_condition = self.parse(expr, statements)
                true_body = []
                if body.type == "pair":
                    key = self.find_child_by_field(body, "key")
                    value = self.find_child_by_field(body, "value")
                    shadow_key = self.parse(key, true_body)
                    shadow_value = self.parse(value, true_body)
                    true_body.append(self.add_col_row_info(body, {"record_write": {"receiver_record": target, "key": shadow_key, "value": shadow_value}}))
                else:
                    shadow_body = self.parse(body, true_body)
                    true_body.append(self.add_col_row_info(body, {"array_append": {"array": target, "source": shadow_body}}))
                self.append_stmts(statements, body, {"if_stmt": {"condition": shadow_condition, "then_body": true_body}})
        else:
            clause = clauses.pop(0)
            if clause.type == "for_in_clause":
                modifiers = []
                if clause.named_child_count > 0 and self.read_node_text(clause.children[0]) == "async":
                    modifiers.append("async")
                left = self.find_child_by_field(clause, "left")
                right = self.find_child_by_field(clause, "right")
                shadow_left = self.parse(left, statements)
                shadow_right = self.parse(right, statements)
                for_body = []
                self.parse_comprehension_clauses(body, target, clauses, for_body)
                self.append_stmts(statements, body, {"forin_stmt":
                                        {"attr": modifiers,
                                         "name": shadow_left,
                                         "receiver": shadow_right,
                                         "body": for_body}})
            else:
                expr = clause.named_children[0]
                shadow_condition = self.parse(expr, statements)
                true_body = []
                self.parse_comprehension_clauses(body, target, clauses, true_body)
                self.append_stmts(statements, body, {"if_stmt": {"condition": shadow_condition, "then_body": true_body}})

    def list_set_dictionary_comprehension(self, node: Node, statements: list):
        tmp_var = self.tmp_variable()
        if node.type == "dictionary_comprehension":
            self.append_stmts(statements, node, {"new_record": {"target": tmp_var}})
        else:
            self.append_stmts(statements, node, {"new_array": {"target": tmp_var}})
        body = self.find_child_by_field(node, "body")
        comprehension_clauses = [x for x in node.named_children[1:] if x.type == "for_in_clause" or x.type == "if_clause"]
        self.parse_comprehension_clauses(body, tmp_var, comprehension_clauses, statements)

        return tmp_var

    def evaluate_literal_binary_expression(self, root, statements):
        node_list = [root]
        nodes_to_be_computed = []
        binary_expr_value_map = {}

        if not root:
            return

        # determine if it is a real literal_binary_expression
        while (len(node_list) > 0):
            node = node_list.pop()
            if not node:
                return

            if node.id in binary_expr_value_map:
                # This node cannot be evaluated
                if binary_expr_value_map.get(node.id) is None:
                    return
                continue

            if not self.is_constant_literal(node) and node.type != "binary_expression":
                return

            # literal
            if self.is_constant_literal(node):
                continue

            operator = self.find_child_by_field(node, "operator")
            left = self.find_child_by_field(node, "left")
            right = self.find_child_by_field(node, "right")

            node_list.append(left)
            node_list.append(right)

            if self.is_constant_literal(left) and self.is_constant_literal(right):
                shadow_operator = self.read_node_text(operator)
                shadow_left = self.parse(left, statements)
                shadow_right = self.parse(right, statements)
                content = shadow_left + shadow_operator + shadow_right
                value = self.common_eval(content)
                if value is None:
                    binary_expr_value_map[node.id] = None
                    binary_expr_value_map[root.id] = None
                    return

                if self.is_string(shadow_left):
                    value = self.escape_string(value)

                binary_expr_value_map[node.id] = value
                nodes_to_be_computed.append(node)

        # conduct evaluation from bottom to top
        while len(nodes_to_be_computed) > 0:
            node = nodes_to_be_computed.pop(0)
            if node == root:
                return binary_expr_value_map[root.id]

            parent = node.parent
            if not parent or parent.type not in ["binary_operator", "comparison_operator"]:
                return

            nodes_to_be_computed.append(parent)

            if parent.id in binary_expr_value_map:
                continue

            left = self.find_child_by_field(parent, "left")
            right = self.find_child_by_field(parent, "right")

            if not left or not right:
                return

            shadow_left = None
            shadow_right = None

            if left.id in binary_expr_value_map:
                shadow_left = binary_expr_value_map.get(left.id)
            elif self.is_constant_literal(left):
                shadow_left = self.parse(left, statements)
            else:
                return

            if right.id in binary_expr_value_map:
                shadow_right = binary_expr_value_map.get(right.id)
            elif self.is_constant_literal(right):
                shadow_right = self.parse(right, statements)
            else:
                return

            eval_content = ""
            try:
                eval_content = str(shadow_left) + str(shadow_operator) + str(shadow_right)
            except:
                return
            value = self.common_eval(eval_content)
            if value is None:
                return

            if self.is_string(shadow_left):
                value = self.escape_string(value)

            if isinstance(value, str):
                if len(value) > config.STRING_MAX_LEN:
                    return value[:-1] + '..."'

            binary_expr_value_map[parent.id] = value

        return binary_expr_value_map.get(root.id)

    def binary_comparison_operator(self, node: Node, statements: list):
        evaluated_value = self.evaluate_literal_binary_expression(node, statements)
        if evaluated_value is not None:
            return evaluated_value

        left = node.named_children[0]
        right = node.named_children[-1]
        if node.type == "binary_operator":
            operator = self.find_child_by_field(node, "operator")
        else:
            operator = self.find_child_by_field(node, "operators")

        shadow_operator = self.read_node_text(operator)
        shadow_left = self.parse(left, statements)
        shadow_right = self.parse(right, statements)

        tmp_var = self.tmp_variable()
        self.append_stmts(statements, node, {"assign_stmt": {"target": tmp_var, "operator": shadow_operator, "operand": shadow_left,
                                           "operand2": shadow_right}})

        return tmp_var

    def unary_operator(self, node: Node, statements: list):
        operand = self.find_child_by_field(node, "argument")
        shadow_operand = self.parse(operand, statements)
        operator = self.find_child_by_field(node, "operator")
        shadow_operator = self.read_node_text(operator)

        tmp_var = self.tmp_variable()

        self.append_stmts(statements, node, {"assign_stmt": {"target": tmp_var, "operator": shadow_operator, "operand": shadow_operand}})
        return tmp_var

    def not_operator(self, node: Node, statements: list):
        arg = self.find_child_by_field(node, "argument")
        shadow_arg = self.parse(arg, statements)

        tmp_var = self.tmp_variable()
        self.append_stmts(statements, node, {"assign_stmt": {"target": tmp_var, "operator": "not", "operand": shadow_arg}})

        return tmp_var

    def boolean_operator(self, node: Node, statements: list):
        left = node.named_children[0]
        right = node.named_children[-1]
        operator = self.find_child_by_field(node, "operator")

        shadow_operator = self.read_node_text(operator)
        shadow_left = self.parse(left, statements)
        shadow_right = self.parse(right, statements)

        tmp_var = self.tmp_variable()
        self.append_stmts(statements, node, {"assign_stmt": {"target": tmp_var, "operator": shadow_operator, "operand": shadow_left,
                                           "operand2": shadow_right}})

        return tmp_var

    def parse_type(self, node: Node, statements: list):
        if not node:
            return ""

        node = node.named_children[0]
        if node.type == "generic_type":
            identifier = self.find_child_by_type(node, "identifier")
            type_parameter = self.find_child_by_type(node, "type_parameter")

            shadow_identifier = self.parse(identifier)
            if shadow_identifier == "tuple" or shadow_identifier == "Tuple":
                return self.tuple_expression(type_parameter, statements)

            if shadow_identifier == "list" or shadow_identifier == "List":
                return self.list_expression(type_parameter, statements)

        elif node.type == "union_type":
            tmp_var = self.tmp_variable()
            children = self.find_children_by_type(node, "type")
            left = children[0]
            right = children[1]

            shadow_left = self.parse(left, statements)
            shadow_right = self.parse(right, statements)

            self.append_stmts(statements, node, {"assign_stmt": {"target": tmp_var, "operator": "|",
                                               "operand": shadow_left, "operand2": shadow_right}})
            return tmp_var

        elif node.type == "member_type":
            type = self.find_child_by_type(node, "type")
            identifier = self.find_child_by_type(node, "identifier")

            shadow_array = self.parse_type(type, statements)
            shadow_index = self.parse(identifier, statements)
            tmp_var = self.tmp_variable()
            self.append_stmts(statements, node, {"field_read": {"target": tmp_var, "receiver_object": shadow_array, "field": shadow_index}})
            return tmp_var

        else:
            return self.parse(node, statements)

    def check_expression_handler(self, node):
        return self.EXPRESSION_HANDLER_MAP.get(node.type, None)

    def is_expression(self, node):
        return self.check_expression_handler(node) is not None

    def expression(self, node: Node, statements: list):
        handler = self.check_expression_handler(node)
        return handler(node, statements)

    def import_statement(self, node: Node, statements: list):
        import_name = node.named_children
        for child in import_name:
            if child.type == "dotted_name":
                self.append_stmts(statements, node, {"import_stmt": {"name": self.read_node_text(child)}})
            else:
                name = self.read_node_text(self.find_child_by_field(child, "name"))
                alias = self.read_node_text(self.find_child_by_field(child, "alias"))
                self.append_stmts(statements, node, {"import_stmt": {"name": name, "alias": alias}})

    def from_import_statement(self, node: Node, statements: list):
        module_name = ""
        import_name = ""
        if node.type == "import_from_statement":
            # 形如import a.b.c.d，在gir中会被翻译成from a.b.c.d import a_b_c_D
            module_name = self.read_node_text(self.find_child_by_field(node, "module_name"))
            import_name = node.named_children[1:]
        elif node.type == "future_import_statement":
            module_name = "__future__"
            import_name = node.named_children

        for child in import_name:
            if child.type == "dotted_name":
                self.append_stmts(statements, node, {"from_import_stmt": {"source": module_name, "name": self.read_node_text(child)}})
            elif child.type == "wildcard_import":
                name = '*'
                self.append_stmts(statements, node, {"from_import_stmt": {"source": module_name, "name": name}})
            elif child.type == "comment":
                  # bad_case:
                  #     from langchain_community.utilities import (
                  #         SearchApiAPIWrapper,  # noqa: F401 会将注释错误当成一个child
                  #         SerpAPIWrapper,  # noqa: F401
                  #     )
                continue
            else:
                name = self.read_node_text(self.find_child_by_field(child, "name"))
                alias = self.read_node_text(self.find_child_by_field(child, "alias"))
                self.append_stmts(statements, node, {"from_import_stmt": {"source": module_name, "name": name, "alias": alias}})

    def assert_statement(self, node: Node, statements: list):
        expr = node.named_children[0]
        shadow_expr = self.parse(expr, statements)

        self.append_stmts(statements, node, {"assert_stmt": {"condition": shadow_expr}})

    def return_statement(self, node: Node, statements: list):
        shadow_name = ""
        if node.named_child_count > 0:
            name = node.named_children[0]
            shadow_name = self.parse(name, statements)

        self.append_stmts(statements, node, {"return_stmt": {"name": shadow_name}})
        return shadow_name

    def yield_statement(self, node: Node, statements: list):
        expressions = None
        for child in node.named_children:
            if child.type != "yield":
                expressions = child
                break
        
        if expressions:
            shadow_expr = self.parse(expressions, statements)
            self.append_stmts(statements, node, {"yield_stmt": {"target": shadow_expr}})
        else:
            self.append_stmts(statements, node, {"yield_stmt": {"target": ""}})

    def delete_statement(self, node: Node, statements: list):
        expression_list = self.find_child_by_type(node, "expression_list")
        shadow_expr = ""
        if expression_list:
            if expression_list.named_child_count > 0:
                for child in expression_list.named_children:
                    shadow_expr = self.parse(child, statements)
                    self.append_stmts(statements, node, {"del_stmt": {"name": shadow_expr}})
        else:
            for child in node.named_children:
                shadow_expr = self.parse(child, statements)
                self.append_stmts(statements, node, {"del_stmt": {"name": shadow_expr}})

    def raise_statement(self, node: Node, statements: list):
        shadow_expr = ""
        if node.named_child_count > 0:
            expr = node.named_children[0]
            shadow_expr = self.parse(expr, statements)
        self.append_stmts(statements, node, {"throw_stmt": {"name": shadow_expr}})

    def pass_statement(self, node: Node, statements: list):
        self.append_stmts(statements, node, {"pass_stmt": {}})

    def break_statement(self, node: Node, statements: list):
        self.append_stmts(statements, node, {"break_stmt": {"name": ""}})

    def continue_statement(self, node: Node, statements: list):
        self.append_stmts(statements, node, {"continue_stmt": {"name": ""}})

    def global_statement(self, node: Node, statements: list):
        shadow_expr = ""
        if node.named_child_count > 0:
            for child in node.named_children:
                shadow_expr = self.parse(child, statements)
                self.append_stmts(statements, node, {"global_stmt": {"name": shadow_expr}})

    def nonlocal_statement(self, node: Node, statements: list):
        shadow_expr = ""
        if node.named_child_count > 0:
            expr = node.named_children[0]
            shadow_expr = self.parse(expr, statements)
        self.append_stmts(statements, node, {"nonlocal_stmt": {"name": shadow_expr}})

    def type_alias_statement(self, node: Node, statements: list):
        types = self.find_children_by_type(node, "type")
        type1 = self.parse_type(types[0], statements)
        type2 = self.parse_type(types[1], statements)
        self.append_stmts(statements, node, {"type_alias_decl": {"name": type1, "data_type": type2}})

    def parse_alternative(self, alter_list, statements):
        if len(alter_list) == 0:
            return

        node = alter_list[0]

        if node.type == "else_clause":
            child = self.find_child_by_field(node, "body")
            if child:
                for stmt in child.named_children:
                    self.parse(stmt, statements)
            return

        condition_part = self.find_child_by_field(node, "condition")
        true_part = self.find_child_by_field(node, "consequence")

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
        true_part = self.find_child_by_field(node, "consequence")
        false_part = self.find_children_by_field(node, "alternative")

        true_body = []
        #self.sync_tmp_variable(statements, true_body)
        false_body = []
        #self.sync_tmp_variable(statements, false_body)

        shadow_condition = self.parse(condition_part, statements)
        self.parse(true_part, true_body)
        self.parse_alternative(false_part, false_body)

        self.append_stmts(statements, node, {"if_stmt": {"condition": shadow_condition, "then_body": true_body, "else_body": false_body}})

    # def for_statement(self, node: Node, statements: list):
    #     target = self.tmp_variable()
    #     modifiers = []
    #     if node.named_child_count > 0 and self.read_node_text(node.children[0]) == "async":
    #         modifiers.append("async")

    #     name = self.find_child_by_field(node, "left")
    #     shadow_name = self.parse(name, statements)

    #     value = self.find_child_by_field(node, "right")
    #     shadow_value = self.parse(value, statements)

    #     self.append_stmts(statements, node, {"assign_stmt": {"target": target, "operand": '0'}}
    #     length = self.tmp_variable()
    #     self.append_stmts(statements, node, {"call_stmt": {"target": length, "name": "len", "positional_args": [shadow_value]}}
    #     condition = self.tmp_variable()
    #     self.append_stmts(statements, node, {"assign_stmt": {"target": condition, "operand": target, "operand2": length, "operator": '<'}}

    #     for_body = []
    #     condition = self.tmp_variable()
    #     tmp_var = self.tmp_variable()
    #     for_body.append({"array_read": {"target": tmp_var, "array": shadow_value, "index": target}})
    #     for_body.append({"assign_stmt": {"target": shadow_name, "operand": tmp_var}})
    #     for_body.append({"assign_stmt": {"target": target, "operand": target, "operand2": '1', "operator": '+'}})
    #     body = self.find_child_by_field(node, "body")
    #     self.parse(body, for_body)

    #     self.append_stmts(statements, node, {"while_stmt": {"attrs": modifiers, "condition": condition, "body": for_body}}

    def for_statement(self, node: Node, statements: list):
        modifiers = []
        if node.named_child_count > 0 and self.read_node_text(node.children[0]) == "async":
            modifiers.append("async")

        name = self.find_child_by_field(node, "left")
        pattern_list = []
        if name.type == "pattern_list":
            shadow_name = self.tmp_variable()
            for each_child in name.named_children:
                pattern_list.append(self.parse(each_child, statements))
        else:
            shadow_name = self.parse(name, statements)

        value = self.find_child_by_field(node, "right")
        shadow_value = self.parse(value, statements)

        for_body = []
        for index, shadow_pattern in enumerate(pattern_list):
            for_body.append(self.add_col_row_info(node, {"variable_decl": {"name": shadow_pattern}}))
            for_body.append(self.add_col_row_info(node, {
                "array_read":{
                    "array" : shadow_name,
                    "index" : str(index),
                    "target": shadow_pattern
                    }
                }))

        body = self.find_child_by_field(node, "body")
        self.parse(body, for_body)

        # TODO: 当name是一个可迭代对象，需要在body起始位置添加array_read

        self.append_stmts(statements, node, {"variable_decl": {"name": shadow_name}})
        self.append_stmts(statements, node, {"forin_stmt":
                               {"attrs": modifiers,
                                "name": shadow_name,
                                "receiver": shadow_value,
                                "body": for_body}})

    def while_statement(self, node: Node, statements: list):
        condition = self.find_child_by_field(node, "condition")
        body = self.find_child_by_field(node, "body")
        alternative = self.find_child_by_field(node, "alternative")

        new_condition_init = []
        shadow_condition = self.parse(condition, new_condition_init)

        new_while_body = []
        #self.sync_tmp_variable(new_while_body, statements)
        self.parse(body, new_while_body)

        statements.extend(new_condition_init)
        new_while_body.extend(new_condition_init)

        new_else_body = []
        #self.sync_tmp_variable(new_else_body, statements)
        if alternative is not None:
            for stmt in alternative.named_children:
                self.parse(stmt, new_else_body)

        self.append_stmts(statements, node, {"while_stmt": {"condition": shadow_condition, "body": new_while_body, "else_body": new_else_body}})

    def try_statement(self, node: Node, statements: list):
        try_op = {}
        try_body = []
        catch_body = []
        else_body = []
        finally_body = []

        #self.sync_tmp_variable(try_body, statements)
        body = self.find_child_by_field(node, "body")
        self.parse(body, try_body)
        try_op["body"] = try_body

        #self.sync_tmp_variable(catch_body, statements)
        except_clauses = self.find_children_by_type(node, "except_clause")
        if except_clauses:
            for clause in except_clauses:
                except_clause = {}

                condition = clause.children[1 : -2]
                if len(condition) > 0:
                    if condition[0].type == "as_pattern":
                        expr = condition[0].named_children[0]
                        shadow_expr = self.parse(expr, catch_body)

                        alias = self.find_child_by_field(condition[0], "alias")
                        shadow_alias = self.parse(alias, catch_body)

                        except_clause["expcetion"] = shadow_expr
                        except_clause["as"] = shadow_alias
                    else:
                        shadow_condition = self.parse(condition[0], catch_body)
                        except_clause["expcetion"] = shadow_condition

                shadow_except_clause_body = []
                except_clause_body = clause.children[-1]
                self.parse(except_clause_body, shadow_except_clause_body)
                except_clause["body"] = shadow_except_clause_body
                catch_body.append({"catch_clause": except_clause})
        try_op["catch_body"] = catch_body

        #self.sync_tmp_variable(else_body, statements)
        else_clause = self.find_child_by_type(node, "else_clause")
        if else_clause:
            else_clause_body = else_clause.children[-1]
            self.parse(else_clause_body, else_body)
        try_op["else_body"] = else_body

        #self.sync_tmp_variable(finally_body, statements)
        finally_clause = self.find_child_by_type(node, "finally_clause")
        if finally_clause:
            finally_clause_body = finally_clause.children[-1]
            self.parse(finally_clause_body, finally_body)
        try_op["final_body"] = finally_body

        self.append_stmts(statements, node, {"try_stmt": try_op})

    def with_statement(self, node: Node, statements: list):
        modifiers = []
        if node.named_child_count > 0 and self.read_node_text(node.children[0]) == "async":
            modifiers.append("async")

        with_clause = self.find_child_by_type(node, "with_clause")
        with_init = []
        for with_item in with_clause.named_children:
            value = self.find_child_by_field(with_item, "value")
            self.parse(value, with_init)

        body = self.find_child_by_field(node, "body")
        new_body = []
        #self.sync_tmp_variable(new_body, statements)
        for stmt in body.named_children:
            self.parse(stmt, new_body)

        self.append_stmts(statements, node, {"with_stmt": {"attrs": modifiers, "init_body": with_init, "update_body": new_body}})

    def match_statement(self, node: Node, statements: list):
        switch_ret = self.tmp_variable()
        condition = self.find_child_by_field(node, "subject")
        shadow_condition = self.parse(condition, statements)

        switch_stmt_list = []
        #self.sync_tmp_variable(statements, switch_stmt_list)
        self.append_stmts(statements, node, {"switch_stmt": {"condition": shadow_condition, "body": switch_stmt_list}})

        body = self.find_child_by_field(node, "body")
        alternatives = self.find_children_by_field(body, "alternative")
        for alternative in alternatives:
            case_init = []
            new_body = []
            #self.sync_tmp_variable(statements, new_body)
            case_patterns = self.find_children_by_type(alternative, "case_pattern")
            consequence = self.find_child_by_field(alternative, "consequence")
            if self.read_node_text(case_patterns[0]) == "_":
                self.parse(consequence, new_body)
                switch_stmt_list.append(self.add_col_row_info(node, {"default_stmt": {"body": new_body}}))
                continue
            for case_pattern in case_patterns:
                shadow_condition = self.parse(case_pattern, case_init)
                if case_init != []:
                    statements.extend(case_init)
                if case_pattern != case_patterns[-1]:
                    switch_stmt_list.append(self.add_col_row_info(node, {"case_stmt": {"condition": shadow_condition}}))
                else:
                    self.parse(consequence, new_body)
                    switch_stmt_list.append(self.add_col_row_info(node, {"case_stmt": {"condition": shadow_condition, "body": new_body}}))

        return switch_ret

    def expression_statement(self, node: Node, statements: list):
        assign = self.find_child_by_type(node, "assignment")
        if assign is None:
            assign = self.find_child_by_type(node, "augmented_assignment")
        if assign:
            left = self.find_child_by_field(assign, "left")
            right = self.find_child_by_field(assign, "right")
            type = self.find_child_by_field(assign, "type")
            operator = self.find_child_by_field(assign, "operator")
            shadow_operator = self.read_node_text(operator).replace("=", "")
            shadow_right = self.parse(right, statements)
            if type:
                type = self.read_node_text(type)
            else:
                type = None
            if left.type == "attribute":
                shadow_object, field = self.parse_field(left, statements)
                if not shadow_operator:
                    self.append_stmts(statements, node,
                        {"field_write": {"receiver_object": shadow_object, "field": field, "source": shadow_right}})
                    return shadow_right

                tmp_var = self.tmp_variable()
                self.append_stmts(statements, node, {"field_read": {"target": tmp_var, "receiver_object": shadow_object, "field": field, }})
                tmp_var2 = self.tmp_variable()
                self.append_stmts(statements, node, {"assign_stmt":
                                       {"target": tmp_var2, "operator": shadow_operator,
                                        "operand": tmp_var, "operand2": shadow_right}})
                self.append_stmts(statements, node, {"field_write": {"receiver_object": shadow_object, "field": field, "source": tmp_var2}})

                return tmp_var2

            elif left.type == "subscript":
                tmp_var = self.tmp_variable()
                array = self.find_child_by_field(left, "value")
                shadow_array = self.parse(array, statements)
                subscripts = self.find_children_by_field(left, "subscript")
                is_slice = False

                if subscripts and len(subscripts) == 1:
                    subscript = subscripts[0]
                    if subscript.type == "slice":
                        start, end, step = self.parse_slice(subscript)
                        is_slice = True
                    else:
                        shadow_index = self.parse(subscript, statements)
                else:
                    for subscript in subscripts[:-1]:
                        if subscript.type == "slice":
                            tmp_slice = self.tmp_variable()
                            start, end, step = self.parse_slice(subscript)
                            self.append_stmts(statements, node, {"slice_read": {"target": tmp_slice, "array": shadow_array, "start": str(start), "end": str(end), "step": str(step) }})
                            shadow_array = tmp_slice
                        else:
                            tmp_array = self.tmp_variable()
                            shadow_index = self.parse(subscript, statements)
                            self.append_stmts(statements, node, {"array_read": {"target": tmp_array, "array": shadow_array, "index": shadow_index}})
                            shadow_array = tmp_array
                    last_subscript = subscripts[-1]
                    if last_subscript.type == "slice":
                        is_slice = True
                        start, end, step = self.parse_slice(last_subscript)
                    else:
                        is_slice = False
                        shadow_index = self.parse(last_subscript, statements)

                if not shadow_operator:
                    if is_slice:
                        self.append_stmts(statements, node, {"slice_write": {"array": shadow_array, "source": shadow_right, "start": str(start), "end": str(end), "step": str(step) }})
                    else:
                        self.append_stmts(statements, node, {"array_write": {"array": shadow_array, "index": shadow_index, "source": shadow_right}})
                    return shadow_right

                tmp_var = self.tmp_variable()
                if is_slice:
                    self.append_stmts(statements, node, {"slice_read": {"target": tmp_var, "array": shadow_array, "start": str(start), "end": str(end), "step": str(step) }})
                else:
                    self.append_stmts(statements, node, {"array_read": {"target": tmp_var, "array": shadow_array, "index": shadow_index}})
                tmp_var2 = self.tmp_variable()
                self.append_stmts(statements, node, {"assign_stmt":
                                       {"target": tmp_var2, "operator": shadow_operator,
                                        "operand": tmp_var, "operand2": shadow_right}})
                if is_slice:
                    self.append_stmts(statements, node, {"slice_write": {"array": shadow_array, "source": tmp_var2, "start": str(start), "end": str(end), "step": str(step) }})
                else:
                    self.append_stmts(statements, node, {"array_write": {"array": shadow_array, "index": shadow_index, "source": tmp_var2}})

                return tmp_var2

            elif left.type == "tuple_pattern":
                pattern_count = left.named_child_count
                if not shadow_operator:
                    for index in range(pattern_count):
                        tmp_var = self.tmp_variable()
                        self.append_stmts(statements, node, {"array_read": {"target": tmp_var, "array": shadow_right, "index": str(index), }})
                        tmp_body = []
                        pattern = self.parse(left.named_children[index], tmp_body)
                        self.append_stmts(statements, node, {"variable_decl": {"data_type": type, "name": pattern}})
                        statements.extend(tmp_body)
                        self.append_stmts(statements, node, {"assign_stmt": {"target": pattern, "operand": tmp_var}})
                    return shadow_right

                tmp_var = self.tmp_variable()
                for index in range(pattern_count):
                    tmp_var = self.tmp_variable()
                    self.append_stmts(statements, node, {"array_read": {"target": tmp_var, "array": shadow_right, "index": str(index), }})
                    pattern = self.parse(left.named_children[index])
                    tmp_var2 = self.tmp_variable()
                    self.append_stmts(statements, node, {"assign_stmt":
                                           {"target": tmp_var2, "operator": shadow_operator,
                                            "operand": pattern, "operand2": tmp_var}})
                    self.append_stmts(statements, node, {"assign_stmt": {"target": pattern, "operand": tmp_var2}})
                return shadow_right

            elif left.type == "list_pattern" or left.type == "pattern_list":
                pattern_count = left.named_child_count
                has_splat = False
                if not shadow_operator:
                    for index in range(pattern_count):
                        if left.named_children[index].type == "list_splat_pattern":
                            has_splat = True
                            tmp_var = self.tmp_variable()
                            start = index
                            end = -(pattern_count - index - 1)
                            self.append_stmts(statements, node, {"slice_read": {"target": tmp_var, "array": shadow_right, "start": str(start), "end": str(end), "step": "", }})
                            pattern = self.parse(left.named_children[index])
                            self.append_stmts(statements, node, {"assign_stmt": {"target": pattern, "operand": tmp_var}})
                            continue
                        if has_splat:
                            index = -(pattern_count - index)
                        tmp_var = self.tmp_variable()
                        self.append_stmts(statements, node, {"array_read": {"target": tmp_var, "array": shadow_right, "index": str(index), }})
                        tmp_body = []
                        pattern = self.parse(left.named_children[index], tmp_body)
                        self.append_stmts(statements, node, {"variable_decl": {"data_type": type, "name": pattern}})
                        statements.extend(tmp_body)
                        self.append_stmts(statements, node, {"assign_stmt": {"target": pattern, "operand": tmp_var}})
                    return shadow_right

                tmp_var = self.tmp_variable()
                for index in range(pattern_count):
                    if left.named_children[index].type == "list_splat_pattern":
                        has_splat = True
                        tmp_var = self.tmp_variable()
                        start = index
                        end = -(pattern_count - index - 1)
                        self.append_stmts(statements, node, {"slice_read": {"target": tmp_var, "array": shadow_right, "start": str(start), "end": str(end), "step": "", }})
                        tmp_var2 = self.tmp_variable()
                        pattern = self.parse(left.named_children[index])
                        self.append_stmts(statements, node, {"assign_stmt":
                                               {"target": tmp_var2, "operator": shadow_operator,
                                                "operand": pattern, "operand2": tmp_var}})
                        self.append_stmts(statements, node, {"assign_stmt": {"target": pattern, "operand": tmp_var2}})
                        continue

                    if has_splat:
                        index = -(pattern_count - index)
                    tmp_var = self.tmp_variable()
                    self.append_stmts(statements, node, {"array_read": {"target": tmp_var, "array": shadow_right, "index": str(index), }})
                    pattern = self.parse(left.named_children[index])
                    tmp_var2 = self.tmp_variable()
                    self.append_stmts(statements, node, {"assign_stmt":
                                           {"target": tmp_var2, "operator": shadow_operator,
                                            "operand": pattern, "operand2": tmp_var}})
                    self.append_stmts(statements, node, {"assign_stmt": {"target": pattern, "operand": tmp_var2}})
                return shadow_right
            else:
                shadow_left = self.read_node_text(left)
                if not shadow_operator:
                    self.append_stmts(statements, node, {"variable_decl": {"data_type": type, "name": shadow_left}})
                    self.append_stmts(statements, node, {"assign_stmt": {"target": shadow_left, "operand": shadow_right}})
                else:
                    self.append_stmts(statements, node, {"assign_stmt": {"target": shadow_left, "operator": shadow_operator,
                                                       "operand": shadow_left, "operand2": shadow_right}})
                return shadow_left

        if node.named_child_count > 0:
            for child in node.named_children:
                if child.type != "assignment" and child.type != "augmented_assignment":
                    self.parse(child, statements)

    def assignment(self, node: Node, statements: list):
        assign = node
        if assign is None:
            assign = self.find_child_by_type(node, "augmented_assignment")
        if assign:
            left = self.find_child_by_field(assign, "left")
            right = self.find_child_by_field(assign, "right")
            type = self.find_child_by_field(assign, "type")
            operator = self.find_child_by_field(assign, "operator")
            shadow_operator = self.read_node_text(operator).replace("=", "")
            shadow_right = self.parse(right, statements)
            if type:
                type = self.read_node_text(type)
            else:
                type = None
            if left.type == "attribute":
                shadow_object, field = self.parse_field(left, statements)
                if not shadow_operator:
                    self.append_stmts(statements, node,
                                      {"field_write": {"receiver_object": shadow_object, "field": field,
                                                       "source": shadow_right}})
                    return shadow_right

                tmp_var = self.tmp_variable()
                self.append_stmts(statements, node, {
                    "field_read": {"target": tmp_var, "receiver_object": shadow_object, "field": field, }})
                tmp_var2 = self.tmp_variable()
                self.append_stmts(statements, node, {"assign_stmt":
                                                         {"target": tmp_var2, "operator": shadow_operator,
                                                          "operand": tmp_var, "operand2": shadow_right}})
                self.append_stmts(statements, node, {
                    "field_write": {"receiver_object": shadow_object, "field": field, "source": tmp_var2}})

                return tmp_var2

            elif left.type == "subscript":
                tmp_var = self.tmp_variable()
                array = self.find_child_by_field(left, "value")
                shadow_array = self.parse(array, statements)
                subscripts = self.find_children_by_field(left, "subscript")
                is_slice = False

                if subscripts and len(subscripts) == 1:
                    subscript = subscripts[0]
                    if subscript.type == "slice":
                        start, end, step = self.parse_slice(subscript)
                        is_slice = True
                    else:
                        shadow_index = self.parse(subscript, statements)
                else:
                    for subscript in subscripts[:-1]:
                        if subscript.type == "slice":
                            tmp_slice = self.tmp_variable()
                            start, end, step = self.parse_slice(subscript)
                            self.append_stmts(statements, node, {
                                "slice_read": {"target": tmp_slice, "array": shadow_array, "start": str(start),
                                               "end": str(end), "step": str(step)}})
                            shadow_array = tmp_slice
                        else:
                            tmp_array = self.tmp_variable()
                            shadow_index = self.parse(subscript, statements)
                            self.append_stmts(statements, node, {
                                "array_read": {"target": tmp_array, "array": shadow_array, "index": shadow_index}})
                            shadow_array = tmp_array
                    last_subscript = subscripts[-1]
                    if last_subscript.type == "slice":
                        is_slice = True
                        start, end, step = self.parse_slice(last_subscript)
                    else:
                        is_slice = False
                        shadow_index = self.parse(last_subscript, statements)

                if not shadow_operator:
                    if is_slice:
                        self.append_stmts(statements, node, {
                            "slice_write": {"array": shadow_array, "source": shadow_right, "start": str(start),
                                            "end": str(end), "step": str(step)}})
                    else:
                        self.append_stmts(statements, node, {
                            "array_write": {"array": shadow_array, "index": shadow_index, "source": shadow_right}})
                    return shadow_right

                tmp_var = self.tmp_variable()
                if is_slice:
                    self.append_stmts(statements, node, {
                        "slice_read": {"target": tmp_var, "array": shadow_array, "start": str(start), "end": str(end),
                                       "step": str(step)}})
                else:
                    self.append_stmts(statements, node,
                                      {"array_read": {"target": tmp_var, "array": shadow_array, "index": shadow_index}})
                tmp_var2 = self.tmp_variable()
                self.append_stmts(statements, node, {"assign_stmt":
                                                         {"target": tmp_var2, "operator": shadow_operator,
                                                          "operand": tmp_var, "operand2": shadow_right}})
                if is_slice:
                    self.append_stmts(statements, node, {
                        "slice_write": {"array": shadow_array, "source": tmp_var2, "start": str(start), "end": str(end),
                                        "step": str(step)}})
                else:
                    self.append_stmts(statements, node, {
                        "array_write": {"array": shadow_array, "index": shadow_index, "source": tmp_var2}})

                return tmp_var2

            elif left.type == "tuple_pattern":
                pattern_count = left.named_child_count
                if not shadow_operator:
                    for index in range(pattern_count):
                        tmp_var = self.tmp_variable()
                        self.append_stmts(statements, node, {
                            "array_read": {"target": tmp_var, "array": shadow_right, "index": str(index), }})
                        tmp_body = []
                        pattern = self.parse(left.named_children[index], tmp_body)
                        self.append_stmts(statements, node, {"variable_decl": {"data_type": type, "name": pattern}})
                        statements.extend(tmp_body)
                        self.append_stmts(statements, node, {"assign_stmt": {"target": pattern, "operand": tmp_var}})
                    return shadow_right

                tmp_var = self.tmp_variable()
                for index in range(pattern_count):
                    tmp_var = self.tmp_variable()
                    self.append_stmts(statements, node,
                                      {"array_read": {"target": tmp_var, "array": shadow_right, "index": str(index), }})
                    pattern = self.parse(left.named_children[index])
                    tmp_var2 = self.tmp_variable()
                    self.append_stmts(statements, node, {"assign_stmt":
                                                             {"target": tmp_var2, "operator": shadow_operator,
                                                              "operand": pattern, "operand2": tmp_var}})
                    self.append_stmts(statements, node, {"assign_stmt": {"target": pattern, "operand": tmp_var2}})
                return shadow_right

            elif left.type == "list_pattern" or left.type == "pattern_list":
                pattern_count = left.named_child_count
                has_splat = False
                if not shadow_operator:
                    for index in range(pattern_count):
                        if left.named_children[index].type == "list_splat_pattern":
                            has_splat = True
                            tmp_var = self.tmp_variable()
                            start = index
                            end = -(pattern_count - index - 1)
                            self.append_stmts(statements, node, {
                                "slice_read": {"target": tmp_var, "array": shadow_right, "start": str(start),
                                               "end": str(end), "step": "", }})
                            pattern = self.parse(left.named_children[index])
                            self.append_stmts(statements, node,
                                              {"assign_stmt": {"target": pattern, "operand": tmp_var}})
                            continue
                        if has_splat:
                            index = -(pattern_count - index)
                        tmp_var = self.tmp_variable()
                        self.append_stmts(statements, node, {
                            "array_read": {"target": tmp_var, "array": shadow_right, "index": str(index), }})
                        tmp_body = []
                        pattern = self.parse(left.named_children[index], tmp_body)
                        self.append_stmts(statements, node, {"variable_decl": {"data_type": type, "name": pattern}})
                        statements.extend(tmp_body)
                        self.append_stmts(statements, node, {"assign_stmt": {"target": pattern, "operand": tmp_var}})
                    return shadow_right

                tmp_var = self.tmp_variable()
                for index in range(pattern_count):
                    if left.named_children[index].type == "list_splat_pattern":
                        has_splat = True
                        tmp_var = self.tmp_variable()
                        start = index
                        end = -(pattern_count - index - 1)
                        self.append_stmts(statements, node, {
                            "slice_read": {"target": tmp_var, "array": shadow_right, "start": str(start),
                                           "end": str(end), "step": "", }})
                        tmp_var2 = self.tmp_variable()
                        pattern = self.parse(left.named_children[index])
                        self.append_stmts(statements, node, {"assign_stmt":
                                                                 {"target": tmp_var2, "operator": shadow_operator,
                                                                  "operand": pattern, "operand2": tmp_var}})
                        self.append_stmts(statements, node, {"assign_stmt": {"target": pattern, "operand": tmp_var2}})
                        continue

                    if has_splat:
                        index = -(pattern_count - index)
                    tmp_var = self.tmp_variable()
                    self.append_stmts(statements, node,
                                      {"array_read": {"target": tmp_var, "array": shadow_right, "index": str(index), }})
                    pattern = self.parse(left.named_children[index])
                    tmp_var2 = self.tmp_variable()
                    self.append_stmts(statements, node, {"assign_stmt":
                                                             {"target": tmp_var2, "operator": shadow_operator,
                                                              "operand": pattern, "operand2": tmp_var}})
                    self.append_stmts(statements, node, {"assign_stmt": {"target": pattern, "operand": tmp_var2}})
                return shadow_right
            else:
                shadow_left = self.read_node_text(left)
                if not shadow_operator:
                    self.append_stmts(statements, node, {"variable_decl": {"data_type": type, "name": shadow_left}})
                    self.append_stmts(statements, node,
                                      {"assign_stmt": {"target": shadow_left, "operand": shadow_right}})
                else:
                    self.append_stmts(statements, node,
                                      {"assign_stmt": {"target": shadow_left, "operator": shadow_operator,
                                                       "operand": shadow_left, "operand2": shadow_right}})
                return shadow_left

        if node.named_child_count > 0:
            for child in node.named_children:
                if child.type != "assignment" and child.type != "augmented_assignment":
                    self.parse(child, statements)

    def parse_field(self, node: Node, statements: list):
        myobject = self.find_child_by_field(node, "object")
        shadow_object = self.parse(myobject, statements)

        # to deal with super
        remaining_content = self.read_node_text(node).replace(self.read_node_text(myobject) + ".", "").split(".")[:-1]
        if remaining_content:
            for child in remaining_content:
                tmp_var = self.tmp_variable()
                self.append_stmts(statements, node, {"field_read": {"target": tmp_var, "receiver_object": shadow_object, "field": child}})
                shadow_object = tmp_var

        field = self.find_child_by_field(node, "attribute")
        shadow_field = self.read_node_text(field)
        return (shadow_object, shadow_field)



    def check_statement_handler(self, node):
        return self.STATEMENT_HANDLER_MAP.get(node.type, None)

    def is_statement(self, node):
        return self.check_statement_handler(node) is not None

    def statement(self, node: Node, statements: list):
        handler = self.check_statement_handler(node)
        return handler(node, statements)
