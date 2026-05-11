 #!/usr/bin/env python3

from lian.config.constants import LIAN_INTERNAL
from lian.lang import common_parser


class Parser(common_parser.Parser):
    def init(self):
        self.LITERAL_MAP = {
            # go语言中没有literal，true、false等被视为expression，为优化代码将其视为literal
            "identifier"                        : self.regular_literal,
            "true"                              : self.regular_literal,
            "false"                             : self.regular_literal,
            "nil"                               : self.regular_literal,
            "iota"                              : self.regular_literal,

            "composite_literal"                 : self.composite_literal,

            "int_literal"                       : self.regular_number_literal,
            "float_literal"                     : self.regular_number_literal,
            "imaginary_literal"                 : self.regular_number_literal,
            "rune_literal"                      : self.hex_float_literal,
            "raw_string_literal"                : self.raw_string_literal,
            "interpreted_string_literal"        : self.interpreted_string_literal,

            "func_literal"                      : self.func_literal,
        }

        self.DECLARATION_HANDLER_MAP = {
            "package_clause":                   self.package_declaration,
            "import_declaration":               self.import_declaration,
            "function_declaration":             self.function_declaration,
            "method_declaration":               self.method_declaration,
            "parameter_declaration":            self.parameter_declaration,
            "variadic_parameter_declaration":   self.variadic_parameter_declaration,
        }

        self.EXPRESSION_HANDLER_MAP = {
            "binary_expression"                 : self.binary_expression,
            "unary_expression"                  : self.unary_expression,
            "selector_expression"               : self.selector_expression,
            "index_expression"                  : self.index_expression,
            "slice_expression"                  : self.slice_expression,
            "call_expression"                   : self.call_expression,
            "type_assertion_expression"         : self.type_assertion_expression,
            "type_conversion_expression"        : self.type_conversion_expression,

            "expression_list"                   : self.expression_list,
        }

        self.STATEMENT_HANDLER_MAP = {
            "const_declaration":                self.const_declaration,
            "type_declaration":                 self.type_declaration,
            "var_declaration":                  self.var_declaration,
            "send_statement":                   self.send_statement,
            "inc_statement":                    self.inc_statement,
            "dec_statement":                    self.dec_statement,
            "short_var_declaration":            self.short_var_declaration,
            "assignment_statement":             self.assignment_statement,
            "return_statement":                 self.return_statement,
            "labeled_statement":                self.label_statement,
            "if_statement":                     self.if_statement,
            "goto_statement":                   self.goto_statement,
            "go_statement":                     self.go_statement,
            "defer_statement":                  self.defer_statement,
            "for_statement":                    self.for_statement,
            "fallthrough_statement":            self.fallthrough_statement,
            "break_statement":                  self.break_statement,
            "continue_statement":               self.continue_statement,
            "expression_switch_statement":      self.expression_switch_statement,
            "type_switch_statement":            self.type_switch_statement,
            "select_statement":                 self.select_statement,
        }

        self.TYPE_HANDLER_MAP = {
            "parenthesized_type":               self.parenthesized_type,
            "type_identifier":                  self.type_identifier,
            "generic_type":                     self.generic_type,
            "qualified_type":                   self.qualified_type,
            "pointer_type":                     self.pointer_type,
            "struct_type":                      self.struct_type,
            "interface_type":                   self.interface_type,
            "array_type":                       self.array_type,
            "slice_type":                       self.slice_type,
            "map_type":                         self.map_type,
            "channel_type":                     self.channel_type,
            "function_type":                    self.function_type,
            "union_type":                       self.union_type,
            "negated_type":                     self.negated_type,
        }

    def is_comment(self, node):
        return node.type in ["comment", "line_comment", "block_comment"]

    def is_identifier(self, node):
        return node.type == "identifier"

    def obtain_literal_handler(self, node):
        return self.LITERAL_MAP.get(node.type, None)

    def is_literal(self, node):
        return self.obtain_literal_handler(node) is not None

    def literal(self, node, statements, replacement):
        handler = self.obtain_literal_handler(node)
        return handler(node, statements, replacement)

    def check_declaration_handler(self, node):
        return self.DECLARATION_HANDLER_MAP.get(node.type, None)

    def is_declaration(self, node):
        return self.check_declaration_handler(node) is not None

    def declaration(self, node, statements):
        handler = self.check_declaration_handler(node)
        return handler(node, statements)

    def check_expression_handler(self, node):
        return self.EXPRESSION_HANDLER_MAP.get(node.type, None)

    def is_expression(self, node):
        return self.check_expression_handler(node) is not None

    def expression(self, node, statements):
        handler = self.check_expression_handler(node)
        return handler(node, statements)

    def check_statement_handler(self, node):
        return self.STATEMENT_HANDLER_MAP.get(node.type, None)

    def is_statement(self, node):
        return self.check_statement_handler(node) is not None

    def statement(self, node, statements):
        handler = self.check_statement_handler(node)
        return handler(node, statements)

    def check_type_handler(self, node):
        return self.TYPE_HANDLER_MAP.get(node.type, None)

    def is_type(self, node):
        return self.check_type_handler(node) is not None

    def parse_type(self, node, statements):
        if not node:
            return ""
        handler = self.check_type_handler(node)
        if not handler:
            return self.read_node_text(node)
        return handler(node, statements)

    def interpreted_string_literal(self, node, statements, replacement):
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

    def raw_string_literal(self, node, statements, replacement):
        return self.read_node_text(node)

    def regular_number_literal(self, node, statements, replacement):
        value = self.read_node_text(node)
        value = self.common_eval(value)
        return str(value)

    def hex_float_literal(self, node, statements, replacement):
        value = self.read_node_text(node)
        try:
            value = float.fromhex(value)
        except:
            pass
        return str(value)

    def composite_literal(self, node, statements, replacement):
        type_node = self.find_child_by_field(node, "type")
        body_node = self.find_child_by_field(node, "body")
        type_info = self.simple_type(type_node, statements)
        body_content = []
        if body_node:
            self.literal_value(body_node, body_content, statements)
        tmp_var = self.tmp_variable()

        if type_node.type in ["array_type","slice_type"]:
            self.append_stmts(statements, node, {"new_array": {"target": tmp_var}})
            if len(body_content) > 0:
                for index, item in enumerate(body_content):
                    self.append_stmts(statements, node,
                                      {"array_write": {"array": tmp_var, "index": str(index), "source": item}})
        else:
            self.append_stmts(statements, node, {"composite_literal":{
                "type": type_info,
                "composite_body": body_content
            }})

        return tmp_var

    def literal_value(self, node, body_content, outer_stmts):
        for child in node.named_children:
            if self.is_comment(child):
                continue
            self.parse_element(child, body_content, outer_stmts)

    def parse_element(self, node, body_content, outer_stmts):
        for child in node.named_children:
            if self.is_comment(child):
                continue
            if child.type == "literal_value":
                self.literal_value(child, body_content, outer_stmts)
            elif child.type == "literal_element":
                self.parse_element(child, body_content, outer_stmts)
            else:
                # intermediate stmts go to outer_stmts, only the ref goes to body_content
                pre_stmts = []
                ret = self.parse(child, pre_stmts)
                outer_stmts.extend(pre_stmts)
                body_content.append(ret)

    def func_literal(self, node, statements, replacement):
        new_parameters = []
        child = self.find_child_by_field(node, "parameters")
        if child and child.named_child_count > 0:
            for p in child.named_children:
                if self.is_comment(p):
                    continue

                self.parse(p, new_parameters)

        new_parameters1 = []
        child = self.find_child_by_field(node, "result")
        if child:
            if child.type == "parameter_list":
                if child.named_child_count > 0:
                    for p in child.named_children:
                        if self.is_comment(p):
                            continue

                        self.parse(p, new_parameters1)
            else:
                new_parameters1 = self.simple_type(child, statements)

        new_body = []
        child = self.find_child_by_field(node, "body")
        if child:
            for stmt in child.named_children:
                if self.is_comment(stmt):
                    continue

                self.parse(stmt, new_body)

        tmp_var = self.tmp_variable()
        self.append_stmts(statements, node,
            {"method_decl": {"name": tmp_var, "parameters": new_parameters, "data_type": str(new_parameters1), "body": new_body}})

        return tmp_var

    def package_declaration(self, node, statements):
        name = self.read_node_text(node.named_children[0])
        if name:
            self.append_stmts(statements, node, {"package_stmt": {"name": name}})

    def import_declaration(self, node, statements):
        import_text = self.read_node_text(node.named_children[0])
        lines = import_text.strip().strip("()").replace('\n', ';').split(';')
        for line in lines:
            line = line.strip()
            if not line:
                continue
            if '"' in line:
                parts = line.split('"')
                if len(parts) == 3:
                    package = parts[1]
                    alias = parts[0].strip()
                    if alias:
                        self.append_stmts(statements, node, {"import_stmt": {"alias": alias, "name": package}})
                    else:
                        self.append_stmts(statements, node, {"import_stmt": {"name": package}})

    def parameter_declaration(self, node, statements):
        mytype = self.find_child_by_field(node, "type")
        shadow_type = self.parse_type(mytype, statements)

        name = self.find_children_by_field(node, "name")
        if not name:
            # TODO: 为什么没有名字
            self.append_stmts(statements, node, {"parameter_decl": {"data_type": shadow_type}})
        for child in name:
            self.append_stmts(statements, node, {"parameter_decl": {"name": self.read_node_text(child), "data_type": shadow_type}})

    def variadic_parameter_declaration(self, node, statements):
        mytype = self.find_child_by_field(node, "type")
        shadow_type = self.parse_type(mytype, statements)

        name = self.find_child_by_field(node, "name")
        if name:
            shadow_name = self.read_node_text(name)
            self.append_stmts(statements, node, {"parameter_decl": {"attrs": ["variadic"], "name": shadow_name, "type": shadow_type}})
        else:
            self.append_stmts(statements, node, {"parameter_decl": {"attrs": ["variadic"], "type": shadow_type}})

    def function_declaration(self, node, statements):
        child = self.find_child_by_field(node, "name")
        name = self.read_node_text(child)

        type_parameters_node = self.find_child_by_field(node, "type_parameters")
        type_parameters = ""
        if type_parameters_node:
            type_parameters = self.read_node_text(type_parameters_node)[1:-1]

        new_parameters = []
        child = self.find_child_by_field(node, "parameters")
        if child and child.named_child_count > 0:
            for p in child.named_children:
                if self.is_comment(p):
                    continue

                self.parse(p, new_parameters)

        new_parameters1 = []
        child = self.find_child_by_field(node, "result")
        if child:
            if child.type == "parameter_list":
                if child.named_child_count > 0:
                    for p in child.named_children:
                        if self.is_comment(p):
                            continue

                        self.parse(p, new_parameters1)
            else:
                new_parameters1 = self.simple_type(child, statements)

        new_body = []
        child = self.find_child_by_field(node, "body")
        if child:
            for stmt in child.named_children:
                if self.is_comment(stmt):
                    continue

                self.parse(stmt, new_body)

        self.append_stmts(statements, node,
            {"method_decl": {"name": name, "type_parameters": type_parameters,
                             "parameters": new_parameters, "data_type": str(new_parameters1), "body": new_body}})

    def method_declaration(self, node, statements):
        receiver_parameter = []
        child = self.find_child_by_field(node, "receiver")
        if child and child.named_child_count > 0:
            for p in child.named_children:
                if self.is_comment(p):
                    continue
                self.parse(p, receiver_parameter)

        child = self.find_child_by_field(node, "name")
        name = self.read_node_text(child)

        new_parameters = []
        child = self.find_child_by_field(node, "parameters")
        if child and child.named_child_count > 0:
            for p in child.named_children:
                if self.is_comment(p):
                    continue

                self.parse(p, new_parameters)

        new_parameters1 = []
        child = self.find_child_by_field(node, "result")
        if child:
            if child.type == "parameter_list":
                if child.named_child_count > 0:
                    for p in child.named_children:
                        if self.is_comment(p):
                            continue

                        self.parse(p, new_parameters1)
            else:
                new_parameters1 = self.simple_type(child, statements)

        new_body = []
        child = self.find_child_by_field(node, "body")
        if child:
            for stmt in child.named_children:
                if self.is_comment(stmt):
                    continue

                self.parse(stmt, new_body)

        self.append_stmts(statements, node,
            {"method_decl": {"attrs": str(receiver_parameter), "name": name,
                             "parameters": new_parameters, "data_type": str(new_parameters1), "body": new_body}})

    def regular_literal(self, node, statements, replacement):
        return self.read_node_text(node)

    def parse_array(self, node, statements):
        array = self.find_child_by_field(node, "operand")
        shadow_array = self.parse(array, statements)
        index = self.find_child_by_field(node, "index")
        shadow_index = self.parse(index, statements)

        return (shadow_array, shadow_index)

    def parse_field(self, node, statements):
        operand = self.find_child_by_field(node, "operand")
        shadow_object = self.parse(operand, statements)
        field = self.find_child_by_field(node, "field")
        shadow_field = self.read_node_text(field)

        return (shadow_object, shadow_field)

    def parse_mem(self, node, statements):
        address = self.find_child_by_field(node, "operand")
        shadow_address = self.parse(address, statements)

        return shadow_address

    def const_declaration(self, node, statements):
        for child in node.named_children:
            if self.is_comment(child):
                continue
            names = self.find_children_by_field(child, "name")
            shadow_name = []
            for name in names:
                if name.type == "identifier":
                    shadow_name.append(self.read_node_text(name))

            mytype = self.find_child_by_field(child, "type")
            shadow_type = ""
            if mytype:
                shadow_type = self.parse_type(mytype, statements)

            for s_name in shadow_name:
                self.append_stmts(statements, node, {"variable_decl": {"attrs": ["const"], "data_type": shadow_type, "name": s_name}})

            myvalue = self.find_child_by_field(child, "value")
            shadow_value = []
            if myvalue:
                shadow_value = self.parse(myvalue, statements)
                if not isinstance(shadow_value, list):
                    shadow_value = [shadow_value]
                for s_name, s_value in zip(shadow_name, shadow_value):
                    self.append_stmts(statements, node, {"assign_stmt": {"target": s_name, "operand": s_value}})

    def type_declaration(self, node, statements):
        for child in node.named_children:
            if self.is_comment(child):
                continue
            if child.type not in ["type_spec", "type_alias"]:
                continue
            name_node = self.find_child_by_field(child, "name")
            shadow_name = self.read_node_text(name_node)

            type_node = self.find_child_by_field(child, "type")
            shadow_type = self.parse_type(type_node, statements)

            type_parameters = ""
            type_parameters_node = self.find_child_by_field(child, "type_parameters")
            if type_parameters_node:
                type_parameters = self.read_node_text(type_parameters_node)[1:-1]

            self.append_stmts(statements, node, {"type_decl": {"name": shadow_name, "type_parameters": type_parameters, "type": shadow_type}})

    def var_declaration(self, node, statements):
        for child in node.named_children:
            if self.is_comment(child):
                continue
            names = self.find_children_by_field(child, "name")
            shadow_name = []
            for name in names:
                if name.type == "identifier":
                    shadow_name.append(self.read_node_text(name))

            shadow_type = []
            mytype = self.find_child_by_field(child, "type")
            if mytype:
                shadow_type = self.parse_type(mytype, statements)

            for s_name in shadow_name:
                self.append_stmts(statements, node, {"variable_decl": {"data_type": shadow_type, "name": s_name}})

            myvalue = self.find_child_by_field(child, "value")
            shadow_value = []
            if myvalue:
                shadow_value = self.parse(myvalue, statements)
                if not isinstance(shadow_value, list):
                    shadow_value = [shadow_value]
                for s_name, s_value in zip(shadow_name, shadow_value):
                    self.append_stmts(statements, node, {"assign_stmt": {"target": s_name, "operand": s_value}})

    def send_statement(self, node, statements):
        channel = self.find_child_by_field(node, "channel")
        # shadow_channel = self.parse(channel, statements)
        value = self.find_child_by_field(node, "value")
        shadow_value = self.parse(value, statements)

        if channel.type == "index_expression":
            shadow_array, shadow_index = self.parse_array(channel, statements)
            self.append_stmts(statements, node, {"array_write": {"array": shadow_array, "index": shadow_index, "source": shadow_value}})
        elif channel.type == "selector_expression":
            shadow_object, shadow_field = self.parse_field(channel, statements)
            self.append_stmts(statements, node, {"field_write": {"receiver_object": shadow_object, "field": shadow_field, "source": shadow_value}})
        else:
            shadow_channel = self.parse(channel, statements)
            self.append_stmts(statements, node, {"assign_stmt": {"target": shadow_channel, "operand": shadow_value}})

        # self.append_stmts(statements, node, {"send_stmt": {"target": shadow_channel, "value": shadow_value}})

    def inc_statement(self, node, statements):
        target = self.parse(node.named_children[0], statements)
        self.append_stmts(statements, node, {"assign_stmt": {"target": target, "operator": '+', "operand": target, 'operand2': '1'}})


    def dec_statement(self, node, statements):
        target = self.parse(node.named_children[0], statements)
        self.append_stmts(statements, node, {"assign_stmt": {"target": target, "operator": '-', "operand": target, 'operand2': '1'}})

    def short_var_declaration(self, node, statements):
        left = self.find_child_by_field(node, "left")
        right = self.find_child_by_field(node, "right")
        shadow_left_list = []
        shadow_right_list = []
        if left.named_child_count > 0:
            for child in left.named_children:
                if self.is_comment(child):
                    continue
                shadow_left_list.append(self.read_node_text(child))

        shadow_right_list = self.parse(right, statements)
        if not isinstance(shadow_right_list, list):
            shadow_right_list = [shadow_right_list]
        for name, value in zip(shadow_left_list, shadow_right_list):
            self.append_stmts(statements, node, {"variable_decl": {"data_type": "", "name": name}})
            self.append_stmts(statements, node, {"assign_stmt": {"target": name, "operand": value}})

    def assignment_statement(self, node, statements):
        left = self.find_child_by_field(node, "left")
        right = self.find_child_by_field(node, "right")
        operator = self.find_child_by_field(node, "operator")
        shadow_operator = self.read_node_text(operator).replace("=", "")

        shadow_left_list = []
        shadow_right_list = []

        if left.named_child_count > 0:
            for child in left.named_children:
                if self.is_comment(child):
                    continue
                shadow_left_list.append(child)
        if right.named_child_count > 0:
            for child in right.named_children:
                if self.is_comment(child):
                    continue
                shadow_right = self.parse(child, statements)
                shadow_right_list.append(shadow_right)

        if len(shadow_left_list) == 1:
            if shadow_left_list[0].type == "unary_expression" and self.read_node_text(self.find_child_by_field(shadow_left_list[0], "operator")) == "*":
                shadow_address = self.parse_mem(shadow_left_list[0], statements)
                if not shadow_operator:
                    self.append_stmts(statements, node,
                        {"mem_write": {"address": shadow_address, "source": shadow_right_list[0]}})
                else:
                    tmp_var0 = self.tmp_variable()
                    self.append_stmts(statements, node, {"mem_read": {"target": tmp_var0, "address": shadow_address}})
                    tmp_var = self.tmp_variable()
                    self.append_stmts(statements, node, {"assign_stmt": {"target": tmp_var, "operator": shadow_operator,
                                                    "operand": tmp_var0, "operand2": shadow_right_list[0]}})
                    self.append_stmts(statements, node,
                        {"mem_write": {"address": shadow_address, "source": tmp_var}})

            elif shadow_left_list[0].type == "index_expression":
                shadow_array, shadow_index = self.parse_array(shadow_left_list[0], statements)
                if not shadow_operator:
                    self.append_stmts(statements, node,
                        {"array_write": {"array": shadow_array, "index": shadow_index, "source": shadow_right_list[0]}})
                else:
                    tmp_var0 = self.tmp_variable()
                    self.append_stmts(statements, node, {"array_read": {"target": tmp_var0, "array": shadow_array, "index": shadow_index}})
                    tmp_var = self.tmp_variable()
                    self.append_stmts(statements, node, {"assign_stmt": {"target": tmp_var, "operator": shadow_operator,
                                                    "operand": tmp_var0, "operand2": shadow_right_list[0]}})
                    self.append_stmts(statements, node,
                        {"array_write": {"array": shadow_array, "index": shadow_index, "source": tmp_var}})

            elif shadow_left_list[0].type == "selector_expression":
                shadow_object, shadow_field = self.parse_field(shadow_left_list[0], statements)
                if not shadow_operator:
                    # shadow_field = self.read_node_text(field)
                    self.append_stmts(statements, node,
                        {"field_write": {"receiver_object": shadow_object, "field": shadow_field, "source": shadow_right_list[0]}})
                else:
                    tmp_var0 = self.tmp_variable()
                    self.append_stmts(statements, node, {"field_read": {"target": tmp_var0, "receiver_object": shadow_object, "field": shadow_field}})
                    tmp_var = self.tmp_variable()
                    self.append_stmts(statements, node, {"assign_stmt": {"target": tmp_var, "operator": shadow_operator,
                                                    "operand": tmp_var0, "operand2": shadow_right_list[0]}})
                    self.append_stmts(statements, node,
                        {"field_write": {"receiver_object": shadow_object, "field": shadow_field, "source": tmp_var}})

            else:
                shadow_left = self.parse(shadow_left_list[0], statements)
                if not shadow_operator:
                    self.append_stmts(statements, node, {"assign_stmt": {"target": shadow_left, "operand": shadow_right_list[0]}})
                else:
                    self.append_stmts(statements, node, {"assign_stmt": {"target": shadow_left, "operator": shadow_operator,
                                                    "operand": shadow_left, "operand2": shadow_right_list[0]}})
        elif len(shadow_right_list) == 1:
            for i, left_expr in enumerate(shadow_left_list):
                if shadow_left_list[i].type == "unary_expression" and self.read_node_text(self.find_child_by_field(shadow_left_list[0], "operator")) == "*":
                    shadow_address = self.parse_mem(shadow_left_list[i], statements)
                    if not shadow_operator:
                        tmp_var1 = self.tmp_variable()
                        self.append_stmts(statements, node, {"array_read": {"target": tmp_var1, "array": shadow_right_list[0], "index": str(i)}})
                        self.append_stmts(statements, node,
                            {"mem_write": {"address": shadow_address, "source": tmp_var1}})
                    else:
                        tmp_var0 = self.tmp_variable()
                        self.append_stmts(statements, node, {"mem_read": {"target": tmp_var0, "address": shadow_address}})
                        tmp_var1 = self.tmp_variable()
                        self.append_stmts(statements, node, {"array_read": {"target": tmp_var1, "array": shadow_right_list[0], "index": str(i)}})
                        tmp_var = self.tmp_variable()
                        self.append_stmts(statements, node, {"assign_stmt": {"target": tmp_var, "operator": shadow_operator,
                                                        "operand": tmp_var0, "operand2": tmp_var1}})
                        self.append_stmts(statements, node, {"mem_write": {"address": shadow_address, "source": tmp_var}})

                elif shadow_left_list[i].type == "index_expression":
                    shadow_array, shadow_index = self.parse_array(shadow_left_list[i], statements)
                    if not shadow_operator:
                        tmp_var1 = self.tmp_variable()
                        self.append_stmts(statements, node, {"array_read": {"target": tmp_var1, "array": shadow_right_list[0], "index": str(i)}})
                        self.append_stmts(statements, node,
                            {"array_write": {"array": shadow_array, "index": shadow_index, "source": tmp_var1}})
                    else:
                        tmp_var0 = self.tmp_variable()
                        self.append_stmts(statements, node, {"array_read": {"target": tmp_var0, "array": shadow_array, "index": shadow_index}})
                        tmp_var1 = self.tmp_variable()
                        self.append_stmts(statements, node, {"array_read": {"target": tmp_var1, "array": shadow_right_list[0], "index": str(i)}})
                        tmp_var = self.tmp_variable()
                        self.append_stmts(statements, node, {"assign_stmt": {"target": tmp_var, "operator": shadow_operator,
                                                        "operand": tmp_var0, "operand2": tmp_var1}})
                        # self.append_stmts(statements, node, {"assign_stmt": {"target": tmp_var, "operator": shadow_operator,
                        #                                 "operand": tmp_var0, "operand2": shadow_right_list[0]+"["+str(i)+"]"}})
                        self.append_stmts(statements, node,
                            {"array_write": {"array": shadow_array, "index": shadow_index, "source": tmp_var}})

                elif shadow_left_list[i].type == "selector_expression":
                    shadow_object, shadow_field = self.parse_field(shadow_left_list[i], statements)
                    if not shadow_operator:
                        # shadow_field = self.read_node_text(field)
                        tmp_var1 = self.tmp_variable()
                        self.append_stmts(statements, node, {"array_read": {"target": tmp_var1, "array": shadow_right_list[0], "index": str(i)}})
                        self.append_stmts(statements, node,
                            {"field_write": {"receiver_object": shadow_object, "field": shadow_field, "source": tmp_var1}})
                    else:
                        tmp_var0 = self.tmp_variable()
                        self.append_stmts(statements, node, {"field_read": {"target": tmp_var0, "receiver_object": shadow_object, "field": shadow_field}})
                        tmp_var1 = self.tmp_variable()
                        self.append_stmts(statements, node, {"array_read": {"target": tmp_var1, "array": shadow_right_list[0], "index": str(i)}})
                        tmp_var = self.tmp_variable()
                        self.append_stmts(statements, node, {"assign_stmt": {"target": tmp_var, "operator": shadow_operator,
                                                        "operand": tmp_var0, "operand2": tmp_var1}})
                        # self.append_stmts(statements, node, {"assign_stmt": {"target": tmp_var, "operator": shadow_operator,
                        #                                 "operand": tmp_var0, "operand2": shadow_right_list[0]+"["+str(i)+"]"}})
                        self.append_stmts(statements, node,
                            {"field_write": {"receiver_object": shadow_object, "field": shadow_field, "source": tmp_var}})
                else:
                    shadow_left = self.parse(left_expr, statements)
                    if not shadow_operator:
                        tmp_var = self.tmp_variable()
                        self.append_stmts(statements, node, {"array_read": {"target": tmp_var, "array": shadow_right_list[0], "index": str(i)}})
                        self.append_stmts(statements, node, {"assign_stmt": {"target": shadow_left, "operand": tmp_var}})
                    else:
                        tmp_var = self.tmp_variable()
                        self.append_stmts(statements, node, {"array_read": {"target": tmp_var, "array": shadow_right_list[0], "index": str(i)}})
                        self.append_stmts(statements, node, {"assign_stmt": {"target": shadow_left, "operator": shadow_operator,
                                                        "operand": shadow_left, "operand2": tmp_var}})
        else:
            tmp_var_list = []
            for i, right_expr in enumerate(shadow_right_list):
                if right_expr.startswith(LIAN_INTERNAL.VARIABLE_DECL_PREF):
                    tmp_var_list.append(right_expr)
                else:
                    tmp_var_list.append(self.tmp_variable())
                    self.append_stmts(statements, node, {"assign_stmt": {"target": tmp_var_list[i], "operand": shadow_right_list[i]}})
            for i, left_expr in enumerate(shadow_left_list):
                if shadow_left_list[i].type == "unary_expression" and self.read_node_text(self.find_child_by_field(shadow_left_list[0], "operator")) == "*" and i < len(shadow_right_list):
                    shadow_address = self.parse_mem(shadow_left_list[i], statements)
                    if not shadow_operator:
                        self.append_stmts(statements, node,
                            {"mem_write": {"array": shadow_address, "source": tmp_var_list[i]}})
                    else:
                        tmp_var0 = self.tmp_variable()
                        self.append_stmts(statements, node, {"mem_read": {"target": tmp_var0, "address": shadow_address}})
                        tmp_var = self.tmp_variable()
                        self.append_stmts(statements, node, {"assign_stmt": {"target": tmp_var, "operator": shadow_operator,
                                                        "operand": tmp_var0, "operand2": tmp_var_list[i]}})
                        self.append_stmts(statements, node,
                            {"mem_write": {"address": shadow_address, "source": tmp_var}})

                elif shadow_left_list[i].type == "index_expression" and i < len(shadow_right_list):
                    shadow_array, shadow_index = self.parse_array(shadow_left_list[i], statements)
                    if not shadow_operator:
                        self.append_stmts(statements, node,
                            {"array_write": {"array": shadow_array, "index": shadow_index, "source": tmp_var_list[i]}})
                    else:
                        tmp_var0 = self.tmp_variable()
                        self.append_stmts(statements, node, {"array_read": {"target": tmp_var0, "array": shadow_array, "index": shadow_index}})
                        tmp_var = self.tmp_variable()
                        self.append_stmts(statements, node, {"assign_stmt": {"target": tmp_var, "operator": shadow_operator,
                                                        "operand": tmp_var0, "operand2": tmp_var_list[i]}})
                        self.append_stmts(statements, node,
                            {"array_write": {"array": shadow_array, "index": shadow_index, "source": tmp_var}})

                elif shadow_left_list[i].type == "selector_expression" and i < len(shadow_right_list):
                    shadow_object, shadow_field = self.parse_field(shadow_left_list[i], statements)
                    if not shadow_operator:
                        # shadow_field = self.read_node_text(field)
                        self.append_stmts(statements, node,
                            {"field_write": {"receiver_object": shadow_object, "field": shadow_field, "source": tmp_var_list[i]}})
                    else:
                        tmp_var0 = self.tmp_variable()
                        self.append_stmts(statements, node, {"field_read": {"target": tmp_var0, "receiver_object": shadow_object, "field": shadow_field}})
                        tmp_var = self.tmp_variable()
                        self.append_stmts(statements, node, {"assign_stmt": {"target": tmp_var, "operator": shadow_operator,
                                                        "operand": tmp_var0, "operand2": tmp_var_list[i]}})
                        self.append_stmts(statements, node,
                            {"field_write": {"receiver_object": shadow_object, "field": shadow_field, "source": tmp_var}})
                elif i < len(shadow_right_list):
                    shadow_left = self.parse(left_expr, statements)
                    if not shadow_operator:
                        self.append_stmts(statements, node, {"assign_stmt": {"target": shadow_left, "operand": tmp_var_list[i]}})
                    else:
                        self.append_stmts(statements, node, {"assign_stmt": {"target": shadow_left, "operator": shadow_operator,
                                                        "operand": shadow_left, "operand2": tmp_var_list[i]}})
                else:
                    break

    def return_statement(self, node, statements):
        init = []
        returns = []
        child = self.find_child_by_type(node, "expression_list")
        returns.append(self.parse(child,init))
        for expr in init:
            self.append_stmts(statements, node, expr)
        for target in returns:
            self.append_stmts(statements, node, {"return": {"target": target}})

    def expression_list(self, node, statements):
        tmp_var_list = []
        expressions = []
        if node.named_child_count == 1:
            for child in node.named_children:
                if self.is_comment(child):
                    continue
                return self.parse(child, statements)
        elif node.named_child_count > 1:
            for child in node.named_children:
                if self.is_comment(child):
                    continue
                tmp_var_list.append(self.parse(child, statements))
        return tmp_var_list

    def binary_expression(self, node, statements):
        left = self.find_child_by_field(node, "left")
        right = self.find_child_by_field(node, "right")
        operator = self.find_child_by_field(node, "operator")

        shadow_operator = self.read_node_text(operator)

        shadow_left = self.parse(left, statements)
        shadow_right = self.parse(right, statements)

        tmp_var = self.tmp_variable()
        self.append_stmts(statements, node, {"assign_stmt": {"target": tmp_var, "operator": shadow_operator, "operand": shadow_left,
                                           "operand2": shadow_right}})

        return tmp_var

    def unary_expression(self, node, statements):
        operand = self.find_child_by_field(node, "operand")
        shadow_operand = self.parse(operand, statements)
        operator = self.find_child_by_field(node, "operator")
        shadow_operator = self.read_node_text(operator)

        tmp_var = self.tmp_variable()

        if shadow_operator == "*":
            self.append_stmts(statements, node, {"mem_read": {"target": tmp_var, "address": shadow_operand}})
        else:
            self.append_stmts(statements, node, {"assign_stmt": {"target": tmp_var, "operator": shadow_operator, "operand": shadow_operand}})
        return tmp_var

    def selector_expression(self, node, statements):
        operand = self.find_child_by_field(node, "operand")
        shadow_operand = ""
        shadow_operand = self.parse(operand, statements)

        field = self.find_child_by_field(node, "field")
        shadow_field = self.read_node_text(field)
        tmp_var = self.tmp_variable()
        self.append_stmts(statements, node, {"field_read": {"target": tmp_var, "receiver_object": shadow_operand, "field": shadow_field}})
        shadow_operand = tmp_var
        return shadow_operand

    def index_expression(self, node, statements):
        operand = self.find_child_by_field(node, "operand")
        index = self.find_child_by_field(node, "index")

        shadow_operand = self.parse(operand, statements)
        shadow_index = self.parse(index, statements)

        tmp_var = self.tmp_variable()
        self.append_stmts(statements, node, {"array_read": {"target": tmp_var, "receiver_object": shadow_operand,
                                           "index": shadow_index}})
        return tmp_var

    def slice_expression(self, node, statements):
        operand = self.find_child_by_field(node, "operand")
        shadow_operand = self.parse(operand, statements)

        start = self.find_child_by_field(node, "start")
        shadow_start = self.parse(start, statements)

        end = self.find_child_by_field(node, "end")
        shadow_end = self.parse(end, statements)

        capacity = self.find_child_by_field(node, "capacity")
        shadow_capacity = self.parse(capacity, statements)

        tmp_var = self.tmp_variable()
        self.append_stmts(statements, node, {"slice_stmt": {"target": tmp_var, "array": shadow_operand, "start": shadow_start,
                                           "end": shadow_end, "step": shadow_capacity}})
        return tmp_var

    def call_expression(self, node, statements):
        function = self.find_child_by_field(node, "function")
        receiver_name = None
        field_name = None
        shadow_function = None
        if function.type == "selector_expression":
            receiver_name, field_name = self.parse_field(function, statements)
        else:
            shadow_function = self.parse(function, statements)

        args_list = []
        type_arguments = []
        args = self.find_child_by_field(node, "arguments")

        if function.type == "selector_expression" or shadow_function not in ["new", "make"]:
            type_arguments_node = self.find_child_by_field(node, "type_arguments")
            if type_arguments_node:
                for child in type_arguments_node.children[1:-1]:
                    if self.is_type(child):
                        type_arguments.append(self.parse_type(child, statements))

            for child in args.named_children:
                if self.is_comment(child):
                    continue

                shadow_variable = self.parse(child, statements)
                if shadow_variable:
                    args_list.append(shadow_variable)

        else:
            args_list.append(self.parse_type(args.children[1], statements))
            for child in args.named_children[2:]:
                if self.is_comment(child):
                    continue

                shadow_variable = self.parse(child, statements)
                if shadow_variable:
                    args_list.append(shadow_variable)

        tmp_var = self.tmp_variable()
        attrs = []
        if function.type == "selector_expression":
            self.append_stmts(statements, node, {"object_call_stmt": {
                "receiver_object":receiver_name,
                "target": tmp_var,
                "field": field_name,
                "attrs": attrs,
                "type_parameters": type_arguments,
                "args": args_list,}
            })
        else:
            self.append_stmts(statements, node, {"call_stmt": {"attrs": attrs, "target": tmp_var, "name": shadow_function, "type_parameters": type_arguments, "args": args_list}})

        return tmp_var

    def type_assertion_expression(self, node, statements):
        operand = self.find_child_by_field(node, "operand")
        shadow_operand = self.parse(operand, statements)

        mytype = self.find_child_by_field(node, "type")
        shadow_type = self.parse_type(mytype, statements)

        tmp_var = self.tmp_variable()
        self.append_stmts(statements, node, {"type_assertion": {"target": tmp_var, "operand": shadow_operand, "type": shadow_type[0]}})

        return tmp_var

    def type_conversion_expression(self, node, statements):
        mytype = self.find_child_by_field(node, "type")
        shadow_type = self.parse_type(mytype, statements)

        operand = self.find_child_by_field(node, "operand")
        shadow_operand = self.parse(operand, statements)

        tmp_var = self.tmp_variable()
        # self.append_stmts(statements, node, {"type_conversion": {"target": tmp_var, "type": shadow_type, "operand": shadow_operand}})
        self.append_stmts(statements, node, {"type_cast_stmt": {"target": tmp_var, "data_type": shadow_type, "source": shadow_operand}})
        return shadow_operand
        # return tmp_var

    def parenthesized_type(self, node, statements):
        type_text = self.parse_type(node.children[1], statements)
        return type_text
        # type_info = ["parenthesized_type", type_text]
        # return type_info

    def type_identifier(self, node, statements):
        return self.read_node_text(node)
        # type_text = self.read_node_text(node)
        # # type_info = ["type_identifier", type_text]
        # return type_text

    def generic_type(self, node, statements):
        type_node = self.find_child_by_field(node, "type")
        type_info = ["generic_type"]

        if type_node.type == "type_identifier":
            type_info.append(self.type_identifier(type_node, statements))
        elif type_node.type == "qualified_type":
            type_info.append(self.qualified_type(type_node, statements))
        elif type_node.type == "union_type":
            type_info.append(self.union_type(type_node, statements))
        elif type_node.type == "negated_type":
            type_info.append(self.negated_type(type_node, statements))

        type_arguments_node = self.find_child_by_field(node, "type_arguments")
        type_arguments = []
        for child in type_arguments_node.children[1:-1]:
            if self.is_type(child):
                type_arguments.append(self.parse_type(child, statements))

        type_info.append(type_arguments)
        return type_info

    def qualified_type(self, node, statements):
        package_node = self.find_child_by_field(node, "package")
        name_node = self.find_child_by_field(node, "name")
        package_text = self.read_node_text(package_node)
        name_text = self.read_node_text(name_node)
        type_info = ["qualified_type", {"package": package_text, "name": name_text}]
        return type_info

    def pointer_type(self, node, statements):
        type_text = self.parse_type(node.children[1], statements)
        type_info = ["pointer_type", type_text]
        return type_info

    def struct_type(self, node, statements):
        type_info = ["struct_type"]
        field_declaration_list_node = node.children[1]

        for child in field_declaration_list_node.children[1:-1]:
            if child.type == "field_declaration":
                name = []
                tag_text = []
                tag_node = self.find_child_by_field(child, "tag")
                if tag_node:
                    tag_text = self.parse(tag_node, statements)

                name_children = self.find_children_by_field(child, "name")
                if name_children:
                    for name_child in name_children:
                        name = self.read_node_text(name_child)

                    type_node = self.find_child_by_field(child, "type")
                    type_text = self.parse_type(type_node, statements)
                    type_info.append({"name": name, "type": type_text, "tag": tag_text})

                else:
                    type_node = self.find_child_by_field(child, "type")
                    if type_node.type == "qualified_type":
                        type_text = self.qualified_type(type_node, statements)
                    elif type_node.type == "generic_type":
                        type_text = self.generic_type(type_node, statements)
                    else:
                        type_text = self.type_identifier(type_node, statements)
                    type_info.append({"type": type_text, "tag": tag_text})

        return type_info

    def interface_type(self, node, statements):
        type_info = ["interface_type"]
        for child in node.children[2:-1]:
            if child.type == "method_spec":
                interface_body = ["method_spec"]
                name_node = self.find_child_by_field(child, "name")
                name_text = self.read_node_text(name_node)

                parameters_node = self.find_child_by_field(child, "parameters")
                new_parameters = []
                if parameters_node and parameters_node.named_child_count > 0:
                    for p in parameters_node.named_children:
                        if self.is_comment(p):
                            continue

                        self.parse(p, new_parameters)

                result_node = self.find_child_by_field(child, "result")
                result = []
                if result_node:
                    if result_node.type == "parameter_list":
                        if result_node.named_child_count > 0:
                            for p in result_node.named_children:
                                if self.is_comment(p):
                                    continue

                                self.parse(p, result)
                    else:
                        result = self.simple_type(result_node, statements)

                interface_body.append({"name": name_text, "parameters": new_parameters, "result": result})
                type_info.append(interface_body)

            elif child.type == "struct_elem":
                interface_body = ["struct_elem"]
                for struct_child in child.children:
                    if struct_child.type == "struct_term":
                        if struct_child.children[0].type != "struct_type":
                            interface_body.append(self.read_node_text(struct_child.children[0]))
                            interface_body.append(self.struct_type(struct_child.children[1], statements))
                        else:
                            interface_body.append(self.struct_type(struct_child.children[0], statements))
                type_info.append(interface_body)

            elif child.type == "constraint_elem":
                interface_body = ["constraint_elem"]
                interface_body.append(self.simple_type(child.children[0], statements))
                type_info.append(interface_body)

        return type_info

    def array_type(self, node, statements):
        element_node = self.find_child_by_field(node, "element")
        length_node = self.find_child_by_field(node, "length")
        element_type = self.parse_type(element_node, statements)
        length_expr = self.parse(length_node, statements)
        type_info = ["array_type", {"element": element_type, "length": length_expr}]
        return type_info

    def slice_type(self, node, statements):
        element_node = self.find_child_by_field(node, "element")
        element_type = self.parse_type(element_node, statements)
        type_info = ["slice_type", {"element": element_type}]
        return type_info

    def map_type(self, node, statements):
        key_node = self.find_child_by_field(node, "key")
        value_node = self.find_child_by_field(node, "value")
        key_type = self.parse_type(key_node, statements)
        value_type = self.parse_type(value_node, statements)
        type_info = ["map_type", {"key": key_type, "value": value_type}]
        return type_info

    def channel_type(self, node, statements):
        value_node = self.find_child_by_field(node, "value")
        value_type = self.parse_type(value_node, statements)
        type_info = ["channel_type", {"value": value_type}]
        return type_info

    def function_type(self, node, statements):
        type_info = ["function_type"]
        new_parameters = []
        child = self.find_child_by_field(node, "parameters")
        if child and child.named_child_count > 0:
            for p in child.named_children:
                if self.is_comment(p):
                    continue

                self.parse(p, new_parameters)

        new_parameters1 = []
        child = self.find_child_by_field(node, "result")
        if child:
            if child.type == "parameter_list":
                if child.named_child_count > 0:
                    for p in child.named_children:
                        if self.is_comment(p):
                            continue

                        self.parse(p, new_parameters1)
            else:
                new_parameters1 = self.simple_type(child, statements)
        type_info.append({"parameters": new_parameters, "result": new_parameters1})
        return type_info

    def union_type(self, node, statements):
        union1_type = self.parse_type(node.children[0], statements)
        union2_type = self.parse_type(node.children[2], statements)
        type_info = ["union_type", [union1_type, union2_type]]
        return type_info

    def negated_type(self, node, statements):
        type_text = self.parse_type(node.children[1], statements)
        type_info = ["negated_type", type_text]
        return type_info

    def simple_type(self, node, statements):
        type_kind = node.type
        type_info = []

        if type_kind == "map_type":
            type_info = self.map_type(node, statements)

        elif type_kind == "slice_type":
            type_info = self.slice_type(node, statements)

        elif type_kind == "array_type":
            type_info = self.array_type(node, statements)

        elif type_kind == "implicit_length_array_type":
            element_node = self.find_child_by_field(node, "element")
            element_type = self.parse_type(element_node, statements)

            type_info = ["implicit_length_array_type", {"element": element_type}]

        elif type_kind == "struct_type":
            type_info = self.struct_type(node, statements)

        elif type_kind == "type_identifier":
            type_info = self.type_identifier(node, statements)

        elif type_kind == "generic_type":
            type_info = self.generic_type(node, statements)

        elif type_kind == "qualified_type":
            type_info = self.qualified_type(node, statements)

        return type_info

    def label_statement(self, node, statements):
        name = node.named_children[0]

        self.append_stmts(statements, node, {"label_stmt": {"name": self.read_node_text(name)}})

        if node.named_child_count > 1:
            stmt = node.named_children[1]
            self.parse(stmt, statements)

    def if_statement(self, node, statements):
        initializer = self.find_child_by_field(node, "initializer")
        self.parse(initializer, statements)
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

    def goto_statement(self, node, statements):
        name = node.named_children[0]
        self.append_stmts(statements, node, {"goto_stmt": {"name": self.read_node_text(name)}})

    def go_statement(self, node, statements):
        func = node.named_children[0]
        function = self.find_child_by_field(func, "function")
        shadow_function = self.parse(function, statements)

        args_list = []
        type_arguments = []
        args = self.find_child_by_field(func, "arguments")

        if shadow_function not in ["new", "make"]:
            type_arguments_node = self.find_child_by_field(func, "type_arguments")
            if type_arguments_node:
                for child in type_arguments_node.children[1:-1]:
                    if self.is_type(child):
                        type_arguments.append(self.parse_type(child, statements))

            for child in args.named_children:
                if self.is_comment(child):
                    continue

                shadow_variable = self.parse(child, statements)
                if shadow_variable:
                    args_list.append(shadow_variable)

        else:
            args_list.append(self.parse_type(args.children[1], statements))
            for child in args.named_children[2:]:
                if self.is_comment(child):
                    continue

                shadow_variable = self.parse(child, statements)
                if shadow_variable:
                    args_list.append(shadow_variable)

        tmp_var = self.tmp_variable()
        attrs = ["go"]
        self.append_stmts(statements, node, {"call_stmt": {"attrs": attrs, "target": tmp_var, "name": shadow_function, "type_parameters": type_arguments, "args": args_list}})

    def defer_statement(self, node, statements):
        func = node.named_children[0]
        function = self.find_child_by_field(func, "function")
        shadow_function = self.parse(function, statements)

        args_list = []
        type_arguments = []
        args = self.find_child_by_field(func, "arguments")

        if shadow_function not in ["new", "make"]:
            type_arguments_node = self.find_child_by_field(func, "type_arguments")
            if type_arguments_node:
                for child in type_arguments_node.children[1:-1]:
                    if self.is_type(child):
                        type_arguments.append(self.parse_type(child, statements))

            for child in args.named_children:
                if self.is_comment(child):
                    continue

                shadow_variable = self.parse(child, statements)
                if shadow_variable:
                    args_list.append(shadow_variable)

        else:
            args_list.append(self.parse_type(args.children[1], statements))
            for child in args.named_children[2:]:
                if self.is_comment(child):
                    continue

                shadow_variable = self.parse(child, statements)
                if shadow_variable:
                    args_list.append(shadow_variable)

        tmp_var = self.tmp_variable()
        attrs = ["defer"]
        self.append_stmts(statements, node, {"call_stmt": {"attrs": attrs, "target": tmp_var, "name": shadow_function, "type_parameters": type_arguments, "args": args_list}})

    def for_statement(self, node, statements):
        _clause = node.named_children[0]
        if _clause.type == "for_clause":
            init_children = self.find_children_by_field(_clause, "initializer")
            step_children = self.find_children_by_field(_clause, "update")

            condition = self.find_child_by_field(_clause, "condition")

            init_body = []
            condition_init = []
            step_body = []

            shadow_condition = self.parse(condition, condition_init)
            for child in init_children:
                self.parse(child, init_body)

            for child in step_children:
                self.parse(child, step_body)

            for_body = []

            block = self.find_child_by_field(node, "body")
            self.parse(block, for_body)

            self.append_stmts(statements, node, {"for_stmt":
                                {"init_body": init_body,
                                    "condition": shadow_condition,
                                    "condition_prebody": condition_init,
                                    "update_body": step_body,
                                    "body": for_body}})

        elif _clause.type == "range_clause":
            left = self.find_child_by_field(_clause, "left")
            shadow_left = self.parse(left, statements)

            right = self.find_child_by_field(_clause, "right")
            shadow_right = self.parse(right, statements)

            for_body = []

            if len(shadow_left) == 1:
                self.append_stmts(statements, node, {"forin_stmt":
                                    {"name": shadow_left[0],
                                    "receiver": shadow_right,
                                    "body": for_body}})
            else:
                tmp_var = self.tmp_variable()
                for i, child in enumerate(shadow_left):
                    self.append_stmts(for_body, node, {"array_read": {"target": child, "array": tmp_var, "index": str(i)}})
                self.append_stmts(statements, node, {"forin_stmt":
                                    {"name": tmp_var,
                                    "receiver": shadow_right,
                                    "body": for_body}})

            block = self.find_child_by_field(node, "body")
            self.parse(block, for_body)

        else:
            init_body = []
            condition_init = []
            step_body = []
            for_body = []

            shadow_condition = self.parse(_clause, condition_init)

            block = self.find_child_by_field(node, "body")
            self.parse(block, for_body)
            self.append_stmts(statements, node, {"for_stmt":
                                {"init_body": init_body,
                                    "condition": shadow_condition,
                                    "condition_prebody": condition_init,
                                    "update_body": step_body,
                                    "body": for_body}})

    def fallthrough_statement(self, node, statments):
        statments.append({"fallthrough_stmt": {}})

    def break_statement(self, node, statements):
        shadow_name = ""
        if node.named_child_count > 0:
            name = node.named_children[0]
            shadow_name = self.read_node_text(name)

        self.append_stmts(statements, node, {"break_stmt": {"name": shadow_name}})

    def continue_statement(self, node, statements):
        shadow_name = ""
        if node.named_child_count > 0:
            name = node.named_children[0]
            shadow_name = self.read_node_text(name)

        self.append_stmts(statements, node, {"continue_stmt": {"name": shadow_name}})

    def expression_switch_statement(self, node, statements):
        initializer = self.find_child_by_field(node, "initializer")
        self.parse(initializer, statements)
        value0 = self.find_child_by_field(node, "value")
        condition = self.parse(value0, statements)

        switch_stmt_list = []
        for _case in node.named_children:
            if _case.type == "expression_case":
                value = self.find_child_by_field(_case, "value")
                shadow_condition = self.parse(value, statements)
                if not isinstance(shadow_condition, list):
                    shadow_condition = [shadow_condition]
                new_body = []
                for child in _case.named_children[1:]:
                    if self.is_comment(child):
                        continue
                    else:
                        self.parse(child, new_body)
                for child in shadow_condition[:-1]:
                    switch_stmt_list.append({"case_stmt": {"condition": child}})
                switch_stmt_list.append({"case_stmt": {"condition": shadow_condition[-1], "body": new_body}})
            elif _case.type == "default_case":
                new_body = []
                for child in _case.named_children:
                    if self.is_comment(child):
                            continue
                    else:
                        #self.sync_tmp_variable(statements, new_body)
                        self.parse(child, new_body)
                switch_stmt_list.append({"default_stmt": {"body": new_body}})

        self.append_stmts(statements, node, {"switch_stmt": {"condition": condition, "switch_body": switch_stmt_list}})

    def type_switch_statement(self, node, statements):
        initializer = self.find_child_by_field(node, "initializer")
        self.parse(initializer, statements)

        value0 = self.find_child_by_field(node, "value")
        condition = self.parse(value0, statements)
        tmp_var = self.tmp_variable()
        self.append_stmts(statements, node, {"gettype_stmt": {"target": tmp_var, "operand": condition}})

        alias_node = self.find_child_by_field(node, "alias")
        if alias_node:
            value1 = self.parse(alias_node, statements)
            self.append_stmts(statements, node, {"assign_stmt": {"target": value1, "operand": tmp_var}})

        switch_stmt_list = []
        for _case in node.named_children:
            if _case.type == "type_case":
                value = self.find_children_by_field(_case, "type")
                new_body = []
                for child in _case.named_children:
                    if not self.is_type(child):
                        if self.is_comment(child):
                            continue
                        else:
                            #self.sync_tmp_variable(statements, new_body)
                            self.parse(child, new_body)
                for child in value[:-1]:
                    if self.read_node_text(child) != ',':
                        switch_stmt_list.append({"case_stmt": {"condition": self.parse_type(child, statements)}})
                switch_stmt_list.append({"case_stmt": {"condition": self.parse_type(value[-1], statements), "body": new_body}})
            elif _case.type == "default_case":
                new_body = []
                for child in _case.named_children:
                    if self.is_comment(child):
                            continue
                    else:
                        #self.sync_tmp_variable(statements, new_body)
                        self.parse(child, new_body)
                switch_stmt_list.append({"default_stmt": {"body": new_body}})

        if alias_node:
            self.append_stmts(statements, node, {"switch_stmt": {"condition": value1, "switch_body": switch_stmt_list}})
        else:
            self.append_stmts(statements, node, {"switch_stmt": {"condition": tmp_var, "switch_body": switch_stmt_list}})

    def select_statement(self, node, statements):
        condition = ""
        switch_stmt_list = []
        for _case in node.named_children:
            if _case.type == "communication_case":
                shadow_stmt = self.find_child_by_field(_case, "communication")
                if shadow_stmt.type == "send_statement":
                    send_body = []
                    channel = self.find_child_by_field(shadow_stmt, "channel")
                    value = self.find_child_by_field(shadow_stmt, "value")

                    # shadow_channel = self.parse(channel, statements)
                    shadow_value = self.parse(value, statements)

                    if channel.type == "index_expression":
                        shadow_array, shadow_index = self.parse_array(channel, statements)
                        send_body.append([{"array_write": {"array": shadow_array, "index": shadow_index, "source": shadow_value}}])
                    elif channel.type == "selector_expression":
                        shadow_object, shadow_field = self.parse_field(channel, statements)
                        send_body.append([{"field_write": {"object": shadow_object, "field": shadow_field, "source": shadow_value}}])
                    else:
                        shadow_channel = self.parse(channel, statements)
                        send_body.append([{"assign_stmt": {"target": shadow_channel, "operand": shadow_value}}])
                    new_body = []
                    for child in _case.named_children[1:]:
                        if self.is_comment(child):
                            continue
                        else:
                            #self.sync_tmp_variable(statements, new_body)
                            self.parse(child, new_body)

                    switch_stmt_list.append({"case_stmt": {"condition": send_body,
                                             "body": new_body}})

                elif shadow_stmt.type == "receive_statement":
                    receive_body = []
                    left = self.find_child_by_field(shadow_stmt, "left")
                    right = self.find_child_by_field(shadow_stmt, "right")

                    # shadow_left = self.parse(left, statements)
                    shadow_right = self.parse(right, statements)
                    if left:
                        if left.named_child_count == 1:
                            left = left.named_children[0]
                            if left.type == "index_expression":
                                shadow_array, shadow_index = self.parse_array(left, statements)
                                receive_body.append([{"array_write": {"array": shadow_array, "index": shadow_index, "source": shadow_right}}])
                            elif left.type == "selector_expression":
                                shadow_object, shadow_field = self.parse_field(left, statements)
                                receive_body.append([{"field_write": {"receiver_object": shadow_object, "field": shadow_field, "source": shadow_right}}])
                            else:
                                shadow_left = self.parse(left, statements)
                                receive_body.append([{"assign_stmt": {"target": shadow_left, "operand": shadow_right}}])
                        else:
                            shadow_left_list = []
                            if left.named_child_count > 0:
                                for child in left.named_children:
                                    if self.is_comment(child):
                                        continue
                                    shadow_left_list.append(child)
                            for i, left_expr in enumerate(shadow_left_list):
                                if left_expr.type == "index_expression":
                                    shadow_array, shadow_index = self.parse_array(left_expr, statements)
                                    tmp_var1 = self.tmp_variable()
                                    receive_body.append([{"array_read": {"target": tmp_var1, "array": shadow_right, "index": str(i)}}])
                                    receive_body.append([{"array_write": {"array": shadow_array, "index": shadow_index, "source": tmp_var1}}])
                                elif left_expr.type == "selector_expression":
                                    shadow_object, shadow_field = self.parse_field(left_expr, statements)
                                    tmp_var1 = self.tmp_variable()
                                    receive_body.append([{"array_read": {"target": tmp_var1, "array": shadow_right, "index": str(i)}}])
                                    receive_body.append([{"field_write": {"receiver_object": shadow_object, "field": shadow_field, "source": shadow_right}}])
                                else:
                                    shadow_left = self.parse(left_expr, statements)
                                    tmp_var1 = self.tmp_variable()
                                    receive_body.append([{"array_read": {"target": tmp_var1, "array": shadow_right, "index": str(i)}}])
                                    receive_body.append([{"assign_stmt": {"target": shadow_left, "operand": tmp_var1}}])
                    else:
                        receive_body.append(shadow_right)
                    new_body = []
                    for child in _case.named_children[1:]:
                        if self.is_comment(child):
                            continue
                        else:
                            #self.sync_tmp_variable(statements, new_body)
                            self.parse(child, new_body)

                    switch_stmt_list.append({"case_stmt": {"condition": receive_body,
                                             "body": new_body}})
            elif _case.type == "default_case":
                new_body = []
                for child in _case.named_children:
                    if self.is_comment(child):
                        continue
                    else:
                        #self.sync_tmp_variable(statements, new_body)
                        self.parse(child, new_body)
                switch_stmt_list.append({"default_stmt": {"body": new_body}})

        self.append_stmts(statements, node, {"switch_stmt": {"condition": condition, "switch_body": switch_stmt_list}})
