#!/usr/bin/env python3

from lian.config import config
from lian.lang import common_parser
from lian.config.constants import LIAN_INTERNAL


class Parser(common_parser.Parser):
    def init(self):
        self.CONSTANTS_MAP = {
            "byte"                                  : "i8",
            "char"                                  : "i8",
            "short"                                 : "i16",
            "int"                                   : "i32",
            "long"                                  : "i64",
            "float"                                 : "f32",
            "double"                                : "f64",
        }

        self.LITERAL_MAP = {
            "decimal_integer_literal"               : self.regular_number_literal,
            "hex_integer_literal"                   : self.regular_number_literal,
            "octal_integer_literal"                 : self.regular_number_literal,
            "binary_integer_literal"                : self.regular_number_literal,
            "decimal_floating_point_literal"        : self.regular_number_literal,
            "hex_floating_point_literal"            : self.hex_float_literal,
            "true"                                  : self.regular_literal,
            "false"                                 : self.regular_literal,
            "character_literal"                     : self.character_literal,
            "null_literal"                          : self.regular_literal,
            "class_literal"                         : self.regular_literal,
            "identifier"                            : self.regular_literal,
            "this"                                  : self.this_literal,
            "super"                                 : self.super_literal,
            "string_literal"                        : self.string_literal,
            "string_fragment"                       : self.string_literal,
            "escape_sequence"                       : self.string_literal,
            "string_interpolation"                  : self.string_interpolation
        }

        self.EXPRESSION_HANDLER_MAP = {
            "assignment_expression"                 : self.assignment_expression,
            "binary_expression"                     : self.binary_expression,
            "instanceof_expression"                 : self.instanceof_expression,
            "unary_expression"                      : self.unary_expression,
            "ternary_expression"                    : self.ternary_expression,
            "update_expression"                     : self.update_expression,
            "cast_expression"                       : self.cast_expression,
            "lambda_expression"                     : self.lambda_expression,
            "switch_expression"                     : self.switch_expression,
            "template_expression"                   : self.template_expression,
            "field_access"                          : self.field,
            "array_access"                          : self.array,
            "method_invocation"                     : self.call_expression,
            "explicit_constructor_invocation"       : self.call_expression,
            "array_creation_expression"             : self.new_array,
            "object_creation_expression"            : self.new_object,
            "marker_annotation"                     : self.annotation,
            "annotation"                            : self.annotation,
            "receiver_parameter"                    : self.ignore,
            "formal_parameter"                      : self.formal_parameter,
            "spread_parameter"                      : self.arg_list,
            "array_initializer"                     : self.array_initializer,
        }

        self.DECLARATION_HANDLER_MAP = {
            "package_declaration"                   : self.package_declaration,
            "import_declaration"                    : self.import_declaration,
            "variable_declaration"                  : self.variable_declaration,
            "local_variable_declaration"            : self.variable_declaration,
            "field_declaration"                     : self.variable_declaration,
            "constant_declaration"                  : self.variable_declaration,
            "class_declaration"                     : self.class_declaration,
            "interface_declaration"                 : self.class_declaration,
            "record_declaration"                    : self.class_declaration,
            "constructor_declaration"               : self.method_declaration,
            "compact_constructor_declaration"       : self.method_declaration,
            "method_declaration"                    : self.method_declaration,
            "enum_declaration"                      : self.enum_declaration,
            "annotation_type_declaration"           : self.annotation_type_declaration
        }

        self.STATEMENT_HANDLER_MAP = {
            "labeled_statement"                     : self.label_statement,
            "if_statement"                          : self.if_statement,
            "while_statement"                       : self.while_statement,
            "for_statement"                         : self.for_statement,
            "enhanced_for_statement"                : self.each_statement,
            "assert_statement"                      : self.assert_statement,
            "do_statement"                          : self.dowhile_statement,
            "break_statement"                       : self.break_statement,
            "continue_statement"                    : self.continue_statement,
            "return_statement"                      : self.return_statement,
            "yield_statement"                       : self.yield_statement,
            "throw_statement"                       : self.throw_statement,
            "try_statement"                         : self.try_statement,
            "try_with_resources_statement"          : self.try_statement,
        }

    def is_comment(self, node):
        return node.type in ["line_comment", "block_comment"]

    def is_identifier(self, node):
        return node.type == "identifier"

    def string_literal(self, node, statements, replacement):
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

    def string_interpolation(self, node, statements, replacement):
        expr = node.named_children[0]
        shadow_expr = self.parse(expr, statements)
        replacement.append((expr, shadow_expr))
        return shadow_expr

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

    def regular_literal(self, node, statements, replacement):
        content = self.read_node_text(node)
        return self.CONSTANTS_MAP.get(content, content)

    def character_literal(self, node, statements, replacement):
        value = self.read_node_text(node)
        return "'%s'" % value

    def this_literal(self, node, statements, replacement):
        return self.global_this()

    def super_literal(self, node, statements, replacement):
        return self.global_super()

    def is_constant_literal(self, node):
        return node.type in [
            "decimal_integer_literal",
            "hex_integer_literal",
            "octal_integer_literal",
            "binary_integer_literal",
            "decimal_floating_point_literal",
            "hex_floating_point_literal",
            "true",
            "false",
            "character_literal",
            "null_literal",
            "class_literal",
            "string_literal",
            "string_interpolation",
        ]

    CLASS_TYPE_MAP = {
        "class_declaration": "class",
        "interface_declaration": "interface",
        "record_declaration": "record",
    }

    def class_declaration(self, node, statements):
        gir_node = self.create_empty_node_with_init_list("attrs", "fields", "nested", "supers", "methods")

        if node.type in self.CLASS_TYPE_MAP:
            gir_node["attrs"].append(self.CLASS_TYPE_MAP[node.type])

        child = self.find_child_by_type(node, "modifiers")
        modifiers = self.read_node_text(child).split()
        gir_node["attrs"].extend(modifiers)

        child = self.find_child_by_field(node, "name")
        if child:
            gir_node["name"] = self.read_node_text(child)

        child = self.find_child_by_field(node, "type_parameters")
        if child:
            type_parameters = self.read_node_text(child)
            gir_node["type_parameters"] = type_parameters[1:-1]

        if (gir_node["attrs"][0] == "record"):
            init = []
            gir_node["parameters"] = []
            child = self.find_child_by_field(node, "parameters")
            if child and child.named_child_count > 0:
                # need to deal with parameters
                for p in child.named_children:
                    self.parse(p, init)
                    if len(init) > 0:
                        parameter = init[-1]
                        gir_node["fields"].append({
                            "variable_decl": {
                                "attrs": ["private", "final"],
                                "data_type": parameter["parameter_decl"]["data_type"],
                                "name": parameter["parameter_decl"]["name"]}})
                        gir_node["parameters"].append(parameter)

        child = self.find_child_by_field(node, "superclass")
        if child:
            superclass = self.read_node_text(child)
            parent_class = superclass.replace("extends", "").split()[0]
            gir_node["supers"].append(parent_class)

        for name in ["interfaces", "permits"]:
            child = self.find_child_by_field(node, name)
            if not child:
                continue

            for c in child.named_children[0].named_children:
                class_name = self.read_node_text(c)
                gir_node["supers"].append(class_name)

        for name in ["extends_interfaces"]:
            child = self.find_child_by_type(node, name)
            if not child:
                continue

            for c in child.named_children[0].named_children:
                name = self.read_node_text(c)
                gir_node["supers"].append(name)

        child = self.find_child_by_field(node, "body")
        self.class_body(child, gir_node)

        self.append_stmts(statements, node, {f"{self.CLASS_TYPE_MAP[node.type]}_decl": gir_node})

    def class_body(self, node, gir_node):
        if not node:
            return

        init_class_method_body = []
        static_init_class_method_body = []

        # static_member_field -> static_init -> member_field -> init -> constructor
        children = self.find_children_by_type(node, "field_declaration")
        children.extend(self.find_children_by_type(node, "constant_declaration"))
        if children:
            for child in children:
                statements = []
                target_body = init_class_method_body
                receiver_object = self.global_this()
                modifiers = self.find_child_by_type(child, "modifiers")
                if modifiers:
                    if "static" in self.read_node_text(modifiers).split():
                        target_body = static_init_class_method_body
                        receiver_object = self.current_class()

                #self.sync_tmp_variable(statements, target_body)

                self.parse(child, statements)
                for stmt in statements:
                    if "variable_decl" in stmt:
                        gir_node["fields"].append(stmt)
                    elif "assign_stmt" in stmt:
                        field = stmt["assign_stmt"]
                        target_body.append({
                            "field_write": {
                                "receiver_object"   : receiver_object,
                                "field"             : field["target"],
                                "source"            : field["operand"]}})
                    else:
                        target_body.append(stmt)

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
                        "name": "%static_init_class%",
                        "body": static_init_class_method_body
                    }
                }
            )

        subtypes = ["constructor_declaration", "compact_constructor_declaration", "method_declaration"]
        for st in subtypes:
            tmp_method_decl = []
            children = self.find_children_by_type(node, st)
            if not children:
                continue

            for child in children:
                self.parse(child, tmp_method_decl)

            # for tmp_stmt in tmp_method_decl:
            #     if "method_decl"in tmp_stmt:
            #         if "static" not in tmp_stmt["method_decl"].get("modifiers", ""):
            #             if "parameter_decls" in tmp_stmt["method_decl"]:
            #                 tmp_stmt["method_decl"]["parameter_decls"].insert(0, {"parameter_decl": {"name": "this", "attrs": [LianInternal.CURRENT_INSTANCE]}})
            #             else:
            #                 tmp_stmt["method_decl"]["parameter_decls"] = [{"parameter_decl": {"name": "this", "attrs": [LianInternal.CURRENT_INSTANCE]}}]

            gir_node["methods"].extend(tmp_method_decl)

        if ("attrs" in gir_node and gir_node["attrs"] and gir_node["attrs"][0] == "record" and gir_node[
            "parameters"]):
            for parameter in gir_node["parameters"]:
                parameter_name = parameter["parameter_decl"]["name"]
                is_name_in_methods = False
                for method in gir_node["methods"]:
                    if parameter_name == method["method_decl"]["name"]:
                        is_name_in_methods = True
                        break
                if not is_name_in_methods:
                    variable = self.tmp_variable()
                    gir_node["methods"].append({"method_decl": {
                        "data_type": parameter["parameter_decl"]["data_type"],
                        "name": parameter_name,
                        "type_parameters": "",
                        "body": [
                            {"field_read": {
                                "target": variable,
                                "receiver_object": self.global_this(),
                                "field": parameter_name
                            }
                            },
                            {"return": {
                                "target": variable
                            }
                            }
                        ]
                    }})

        subtypes = ["class_declaration", "interface_declaration", "record_declaration",
                    "annotation_type_declaration", "enum_declaration"]
        for st in subtypes:
            children = self.find_children_by_type(node, st)
            if not children:
                continue

            if "nested" not in gir_node:
                gir_node["nested"] = []
            for child in children:
                self.parse(child, gir_node["nested"])

    def method_declaration(self, node, statements):
        child = self.find_child_by_type(node, "modifiers")
        modifiers = self.read_node_text(child).split()

        child = self.find_child_by_field(node, "type_parameters")
        type_parameters = self.read_node_text(child)[1:-1]

        child = self.find_child_by_field(node, "type")
        mytype = self.read_node_text(child)

        child = self.find_child_by_field(node, "name")
        name = self.read_node_text(child)

        init = []
        child = self.find_child_by_field(node, "parameters")
        if child and child.named_child_count > 0:
            # need to deal with parameters
            for p in child.named_children:
                if self.is_comment(p):
                    continue

                current_parameter_stmts = []
                self.parse(p, current_parameter_stmts)
                init.extend(current_parameter_stmts)

        new_body = []
        #self.sync_tmp_variable(new_body, init)
        child = self.find_child_by_field(node, "body")
        if child:
            for stmt in child.named_children:
                if self.is_comment(stmt):
                    continue

                self.parse(stmt, new_body)

        # if new_body:
        self.append_stmts(statements, node, {
            "method_decl": {
                "attrs": modifiers, "data_type": mytype, "name": name, "type_parameters": type_parameters,
                "parameters": init, "body": new_body
            }
        })

    def package_declaration(self, node, statements):
        name = self.read_node_text(node.named_children[0])
        if name:
            self.append_stmts(statements, node, {"package_stmt": {"name": name}})

    def import_declaration(self, node, statements):
        name = self.read_node_text(node).split()[-1][:-1]
        if not name:
            return

        if "." not in name:
            self.append_stmts(statements, node, {"import_stmt": {"name": name}})
            return

        import_path = name.split(".")
        if len(import_path) > 1:
            prefix = ".".join(import_path[:-1])
            self.append_stmts(statements, node, {"from_import_stmt": {"source": prefix, "name": import_path[-1]}})

    def parse_field(self, node, statements):
        myobject = self.find_child_by_field(node, "object")
        shadow_object = self.parse(myobject, statements)

        # to deal with super
        remaining_content = self.read_node_text(node).replace(self.read_node_text(myobject) + ".", "").split(".")[:-1]
        if remaining_content:
            for child in remaining_content:
                tmp_var = self.tmp_variable()
                self.append_stmts(statements, node, {"field_read": {"target": tmp_var, "receiver_object": shadow_object, "field": child}})
                shadow_object = tmp_var

        field = self.find_child_by_field(node, "field")
        shadow_field = self.read_node_text(field)
        return (shadow_object, shadow_field)

    def parse_array(self, node, statements):
        array = self.find_child_by_field(node, "array")
        shadow_array = self.parse(array, statements)
        index = self.find_child_by_field(node, "index")
        shadow_index = self.parse(index, statements)

        return (shadow_array, shadow_index)

    def array(self, node, statements):
        tmp_var = self.tmp_variable()
        shadow_array, shadow_index = self.parse_array(node, statements)
        self.append_stmts(statements, node, {"array_read": {"target": tmp_var, "array": shadow_array, "index": shadow_index}})
        return tmp_var

    def field(self, node, statements):
        tmp_var = self.tmp_variable()
        shadow_object, shadow_field = self.parse_field(node, statements)
        self.append_stmts(statements, node, {"field_read": {"target": tmp_var, "receiver_object": shadow_object, "field": shadow_field}})
        return tmp_var

    def assignment_expression(self, node, statements):
        left = self.find_child_by_field(node, "left")
        right = self.find_child_by_field(node, "right")
        operator = self.find_child_by_field(node, "operator")
        shadow_operator = self.read_node_text(operator).replace("=", "")

        shadow_right = self.parse(right, statements)

        if left.type == "field_access":
            shadow_object, field = self.parse_field(left, statements)
            if not shadow_operator:
                self.append_stmts(statements, node, {"field_write": {"receiver_object": shadow_object, "field": field, "source": shadow_right}})
                return shadow_right

            tmp_var = self.tmp_variable()
            self.append_stmts(statements, node, {"field_read": {"target": tmp_var, "receiver_object": shadow_object, "field": field, }})
            tmp_var2 = self.tmp_variable()
            self.append_stmts(statements, node, {"assign_stmt":
                                   {"target": tmp_var2, "operator": shadow_operator,
                                    "operand": tmp_var, "operand2": shadow_right}})
            self.append_stmts(statements, node, {"field_write": {"receiver_object": shadow_object, "field": field, "source": tmp_var2}})

            return tmp_var2

        if left.type == "array_access":
            shadow_array, shadow_index = self.parse_array(left, statements)

            if not shadow_operator:
                self.append_stmts(statements, node, {"array_write": {"array": shadow_array, "index": shadow_index, "source": shadow_right}})
                return shadow_right

            tmp_var = self.tmp_variable()
            self.append_stmts(statements, node, {"array_read": {"target": tmp_var, "array": shadow_array, "index": shadow_index, }})
            tmp_var2 = self.tmp_variable()
            self.append_stmts(statements, node, {"assign_stmt":
                                   {"target": tmp_var2, "operator": shadow_operator,
                                    "operand": tmp_var, "operand2": shadow_right}})
            self.append_stmts(statements, node, {"array_write": {"array": shadow_array, "index": shadow_index, "source": tmp_var2}})

            return tmp_var2

        shadow_left = self.read_node_text(left)
        if not shadow_operator:
            self.append_stmts(statements, node, {"assign_stmt": {"target": shadow_left, "operand": shadow_right}})
        else:
            self.append_stmts(statements, node, {"assign_stmt": {"target": shadow_left, "operator": shadow_operator,
                                               "operand": shadow_left, "operand2": shadow_right}})
        return shadow_left

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
            if not parent or parent.type != "binary_expression":
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

    def binary_expression(self, node, statements):
        evaluated_value = self.evaluate_literal_binary_expression(node, statements)
        if evaluated_value is not None:
            return evaluated_value

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

    def instanceof_expression(self, node, statements):
        left = self.find_child_by_field(node, "left")
        shadow_left = self.parse(left, statements)
        # how to deal with right?
        # check the detail at java.grammar.js
        right = self.find_child_by_field(node, "right")

        tmp_var = self.tmp_variable()
        if right:
            self.append_stmts(statements, node, {"assign_stmt":
                                   {"target": tmp_var, "operator": "instanceof", "operand": shadow_left,
                                    "operand2": self.read_node_text(right)}})
        else:
            record_pattern = self.find_child_by_field(node, "pattern")
            if not record_pattern:
                return ""

            # how to deal with this record pattern
            self.append_stmts(statements, node, {"assign_stmt":
                                   {"target": tmp_var, "operator": "instanceof",
                                    "operand": shadow_left, "operand2": self.read_node_text(record_pattern)}})

        return tmp_var

    def unary_expression(self, node, statements):
        operand = self.find_child_by_field(node, "operand")
        shadow_operand = self.parse(operand, statements)
        operator = self.find_child_by_field(node, "operator")
        shadow_operator = self.read_node_text(operator)

        tmp_var = self.tmp_variable()

        self.append_stmts(statements, node, {"assign_stmt": {"target": tmp_var, "operator": shadow_operator, "operand": shadow_operand}})
        return tmp_var

    def ternary_expression(self, node, statements):

        condition = self.find_child_by_field(node, "condition")
        consequence = self.find_child_by_field(node, "consequence")
        alternative = self.find_child_by_field(node, "alternative")

        condition = self.parse(condition, statements)

        body = []
        elsebody = []

        #self.sync_tmp_variable(statements, body)
        #self.sync_tmp_variable(statements, elsebody)
        tmp_var = self.tmp_variable()

        expr1 = self.parse(consequence, body)
        body.append({"assign_stmt": {"target": tmp_var, "operand": expr1}})

        expr2 = self.parse(alternative, elsebody)
        body.append({"assign_stmt": {"target": tmp_var, "operand": expr2}})

        self.append_stmts(statements, node, {"if": {"condition": condition, "body": body, "elsebody": elsebody}})
        return tmp_var

    def update_expression(self, node, statements):
        shadow_node = self.read_node_text(node)

        operator = "-"
        if "+" == shadow_node[0] or "+" == shadow_node[-1]:
            operator = "+"

        is_after = False
        if shadow_node[-1] == operator:
            is_after = True

        tmp_var = self.tmp_variable()

        expression = node.named_children[0]
        if expression.type == "field_access":
            shadow_object, field = self.parse_field(expression, statements)

            self.append_stmts(statements, node, {"field_read": {"target": tmp_var, "receiver_object": shadow_object, "field": field}})
            tmp_var2 = self.tmp_variable()
            self.append_stmts(statements, node, {"assign_stmt": {"target": tmp_var2, "operator": operator, "operand": tmp_var, "operand2": "1"}})
            self.append_stmts(statements, node, {"field_write": {"receiver_object": shadow_object, "field": field, "source": tmp_var2}})

            if is_after:
                return tmp_var
            return tmp_var2

        if expression.type == "array_access":
            shadow_array, shadow_index = self.parse_array(expression, statements)

            self.append_stmts(statements, node, {"array_read": {"target": tmp_var, "array": shadow_array, "index": shadow_index}})
            tmp_var2 = self.tmp_variable()
            self.append_stmts(statements, node, {"assign_stmt": {"target": tmp_var2, "operator": operator, "operand": tmp_var, "operand2": "1"}})
            self.append_stmts(statements, node, {"array_write": {"array": shadow_array, "index": shadow_index, "source": tmp_var2}})

            if is_after:
                return tmp_var
            return tmp_var2

        shadow_expression = self.parse(expression, statements)
        if is_after:
            self.append_stmts(statements, node, {"assign_stmt": {"target": tmp_var, "operand": shadow_expression}})
            self.append_stmts(statements, node, {"assign_stmt": {"target": shadow_expression, "operator": operator,
                                            "operand": shadow_expression, "operand2": "1"}})
            return tmp_var
        else:
            self.append_stmts(statements, node, {"assign_stmt": {"target": shadow_expression, "operator": operator,
                                            "operand": shadow_expression, "operand2": "1"}})
            return shadow_expression

    def cast_expression(self, node, statements):
        value = self.find_child_by_field(node, "value")
        shadow_value = self.parse(value, statements)

        types = self.find_children_by_field(node, "type")
        tmp_var = self.tmp_variable()
        for t in types:
            self.append_stmts(statements, node, {"type_cast_stmt": {"target": tmp_var, "data_type": self.read_node_text(t), "source" : shadow_value}})

        return tmp_var

    def lambda_expression(self, node, statements):
        tmp_func = self.tmp_method()

        parameters = []
        tmp_body = []
        child = self.find_child_by_field(node, "parameters")
        if child.named_child_count == 0:
            parameters.append({"parameter_decl": {"name": self.read_node_text(child)}})
        else:
            for p in child.named_children:
                if self.is_comment(p):
                    continue

                self.parse(p, tmp_body)
                if len(tmp_body) > 0:
                    parameters.append(tmp_body.pop())

        new_body = []
        body = self.find_child_by_field(node, "body")
        if self.is_expression(body):
            shadow_expr = self.parse(body, new_body)
            new_body.append({"return": {"target": shadow_expr}})
        else:
            for stmt in body.named_children:
                if self.is_comment(stmt):
                    continue

                shadow_expr = self.parse(body, new_body)
                if stmt == body.named_children[-1]:
                    new_body.append({"return": {"target": shadow_expr}})

        self.append_stmts(statements, node, {"method_decl": {"name": tmp_func, "parameters": parameters, "body": new_body}})

        return tmp_func

    """
    # need break
    switch (day) {
        case MONDAY:
        case FRIDAY:
        case SUNDAY:
            numLetters = 6;
            break;

    # no break
    numLetters = switch (day) {
            case MONDAY, FRIDAY, SUNDAY -> 6;
    """

    def switch_expression(self, node, statements):
        switch_ret = self.tmp_variable()

        is_switch_rule = False
        switch_block = self.find_child_by_field(node, "body")
        for child in switch_block.named_children:
            if self.is_comment(child):
                continue

            if child.type == "switch_rule":
                is_switch_rule = True

            break

        condition = self.find_child_by_field(node, "condition")
        shadow_condition = self.parse(condition, statements)

        switch_stmt_list = []
        #self.sync_tmp_variable(statements, switch_stmt_list)

        self.append_stmts(statements, node, {"switch_stmt": {"condition": shadow_condition, "body": switch_stmt_list}})

        for child in switch_block.named_children:
            if self.is_comment(child):
                continue

            if self.read_node_text(child.children[0]) == "default":
                new_body = []
                #self.sync_tmp_variable(statements, new_body)
                if child.named_child_count <= 1:
                    continue

                shadow_return = None
                for child_index in range(child.named_child_count):
                    if child_index < 1:
                        continue
                    expression_block = child.named_children[child_index]
                    shadow_return = self.parse(expression_block, new_body)

                if is_switch_rule:
                    new_body.append({"assign_stmt": {"target": switch_ret, "operand": shadow_return}})

                switch_stmt_list.append({"default_stmt": {"body": new_body}})
            else:
                label = child.named_children[0]
                for case_condition in label.named_children:
                    if self.is_comment(case_condition):
                        continue

                    # case_init = []
                    ## self.sync_tmp_variable(statements, case_init)
                    shadow_condition = self.parse(case_condition, statements)
                    if case_condition != label.named_children[-1]:
                        # if case_init != []:
                        #     statements.insert(-1, case_init)
                        switch_stmt_list.append({"case_stmt": {"condition": shadow_condition}})
                    else:
                        if child.named_child_count > 1:
                            new_body = []
                            #self.sync_tmp_variable(statements, new_body)
                            for stat in child.named_children[1:]:
                                shadow_return = self.parse(stat, new_body)
                                if is_switch_rule:
                                    new_body.append({"assign_stmt": {"target": switch_ret, "operand": shadow_return}})
                                    new_body.append({"break_stmt": {}})
                            # if case_init != []:
                            #     statements.insert(-1, case_init)

                            switch_stmt_list.append({"case_stmt": {"condition": shadow_condition, "body": new_body}})
                        else:
                            # if case_init != []:
                            #     statements.insert(-1, case_init)
                            switch_stmt_list.append({"case_stmt": {"condition": shadow_condition}})

        return switch_ret

    def template_expression(self, node, statements):
        template_processor = self.find_child_by_field(node, "template_processor")
        shadow_template_processor = self.parse(template_processor, statements)
        template_argument = self.find_child_by_field(node, "template_argument")
        # shadow_template_argument = self.parse(template_argument, statements)
        last_assign_result = ""
        if template_argument.named_child_count >= 2:
            for index in range(len(template_argument.named_children)):
                tmp_var = self.tmp_variable()
                shadow_oprand = self.parse(template_argument.named_children[index], statements)
                if index == 0:
                    last_assign_result = shadow_oprand
                    continue
                self.append_stmts(statements, node, {"assign_stmt": {"target": tmp_var, "operator": "+", "operand": last_assign_result, "operand2": shadow_oprand}})
                last_assign_result = tmp_var
            return tmp_var

        else:
            for child in template_argument.named_children:
                tmp_var = self.tmp_variable()
                shadow_oprand = self.parse(child, statements)
                self.append_stmts(statements, node, {"assign_stmt": {"target": tmp_var, "operand": shadow_oprand}})
                return tmp_var

    def call_expression(self, node, statements):
        # SomeClass.super.<ArgType>genericMethod()

        if node.type == "explicit_constructor_invocation":
            name = self.find_child_by_field(node, "constructor")
        else:
            name = self.find_child_by_field(node, "name")
        shadow_name = self.parse(name, statements)

        shadow_object = ""
        myobject = self.find_child_by_field(node, "object")
        type_text = ""


        args = self.find_child_by_field(node, "arguments")
        args_list = []

        if args.named_child_count > 0:
            for child in args.named_children:
                if self.is_comment(child):
                    continue

                shadow_variable = self.parse(child, statements)
                if shadow_variable:
                    args_list.append(shadow_variable)

        tmp_return = self.tmp_variable()
        if myobject:
            shadow_object = self.parse(myobject, statements)
            # type_arguments = self.find_child_by_field(node, "type_arguments")
            # if type_arguments:
            #     type_text = self.read_node_text(type_arguments)[1:-1]

            # tmp_var = self.tmp_variable()
            # self.append_stmts(statements, node, {
            #     "field_read": {"target": tmp_var, "receiver_object": shadow_object, "field": shadow_name}})
            # shadow_name = tmp_var
            self.append_stmts(statements, node, {"object_call_stmt": {"target": tmp_return, "field": shadow_name, "receiver_object": shadow_object, "positional_args": args_list}})
        else:
            self.append_stmts(statements, node, {"call_stmt": {"target": tmp_return, "name": shadow_name, "type_parameters": type_text, "positional_args": args_list}})

        return tmp_return

    def new_array(self, node, statements):
        mytype = self.find_child_by_field(node, "type")
        shadow_type = self.read_node_text(mytype)

        tmp_var = self.tmp_variable()
        self.append_stmts(statements, node, {"new_array": {"type": shadow_type, "target": tmp_var}})

        value = self.find_child_by_field(node, "value")
        if value and value.named_child_count > 0:
            index = 0
            for child in value.named_children:
                if self.is_comment(child):
                    continue

                shadow_child = self.parse(child, statements)
                self.append_stmts(statements, node, {"array_write": {"array": tmp_var, "index": str(index), "source": shadow_child}})
                index += 1

        return tmp_var

    def new_object(self, node, statements):
        gir_node = {}

        type_parameters = self.find_child_by_field(node, "type_arguments")
        if type_parameters:
            gir_node["type_parameters"] = self.read_node_text(type_parameters)[1:-1]

        mytype = self.find_child_by_field(node, "type")
        gir_node["data_type"] = self.read_node_text(mytype)

        arguments = self.find_child_by_field(node, "arguments")
        arguments_list = []
        if arguments.named_child_count > 0:
            for arg in arguments.named_children:
                if self.is_comment(arg):
                    continue

                shadow_arg = self.parse(arg, statements)
                if shadow_arg:
                    arguments_list.append(shadow_arg)

        gir_node["positional_args"] = arguments_list

        class_body = self.find_child_by_type(node, "class_body")
        if class_body and class_body.named_child_count > 0:
            tmp_class_name = self.tmp_class()
            new_body = {}
            new_body["fields"] = []
            new_body["methods"] = []
            new_body["nested"] = []

            self.class_body(class_body, new_body)
            self.append_stmts(statements, node, {
                "class_decl": {
                    "name": tmp_class_name,
                    "supers": [gir_node["data_type"]],
                    "fields": new_body["fields"],
                    "methods": new_body["methods"]
                }
            })
            gir_node["data_type"] = tmp_class_name

        tmp_var = self.tmp_variable()
        gir_node["target"] = tmp_var

        self.append_stmts(statements, node, {"new_object": gir_node})

        return tmp_var

    def annotation(self, node, statements):
        return self.read_node_text(node)

    def ignore(self, node=None, statements=[], replacement=[]):
        pass

    def formal_parameter(self, node, statements):
        child = self.find_child_by_type(node, "modifiers")
        modifiers = self.read_node_text(child).split()

        mytype = self.find_child_by_field(node, "type")
        shadow_type = self.read_node_text(mytype)

        if "[]" in shadow_type:
            modifiers.append("array")

        name = self.find_child_by_field(node, "name")
        shadow_name = self.read_node_text(name)

        self.append_stmts(statements, node, {"parameter_decl": {"attrs": modifiers, "data_type": shadow_type, "name": shadow_name}})

    def arg_list(self, node, statements):
        child = self.find_child_by_type(node, "modifiers")
        modifiers = self.read_node_text(child).split()
        modifiers.append(LIAN_INTERNAL.PACKED_POSITIONAL_PARAMETER)

        type_index = 0
        if child:
            type_index = 1

        mytype = node.named_children[type_index]
        shadow_type = self.read_node_text(mytype)

        if "[]" in shadow_type:
            modifiers.append("array")

        name = node.named_children[type_index + 1]
        shadow_name = self.read_node_text(name)

        self.append_stmts(statements, node, {"parameter_decl": {"attrs": modifiers, "data_type": shadow_type, "name": shadow_name}})

    def array_initializer(self, node, statements):
        tmp_var = self.tmp_variable()
        self.append_stmts(statements, node, {"new_array": {"target": tmp_var}})

        if node.named_child_count > 0:
            index = 0
            for item in node.named_children:
                if self.is_comment(item):
                    continue

                source = self.parse(item, statements)
                self.append_stmts(statements, node, {"array_write": {"array": tmp_var, "index": str(index), "source": source}})
                index += 1
        return tmp_var

    def label_statement(self, node, statements):
        name = node.named_children[0]

        shadow_name = self.parse(name, statements)
        self.append_stmts(statements, node, {"label_stmt": {"name": shadow_name}})

        if node.named_child_count > 1:
            stmt = node.named_children[1]
            self.parse(stmt, statements)

    def if_statement(self, node, statements):
        condition_part = self.find_child_by_field(node, "condition")
        true_part = self.find_child_by_field(node, "consequence")
        false_part = self.find_child_by_field(node, "alternative")

        true_body = []
        #self.sync_tmp_variable(statements, true_body)

        shadow_condition = self.parse(condition_part, statements)
        self.parse(true_part, true_body)
        if false_part:
            false_body = []
            #self.sync_tmp_variable(statements, false_body)
            self.parse(false_part, false_body)
            self.append_stmts(statements, node, {"if_stmt": {"condition": shadow_condition, "then_body": true_body, "else_body": false_body}})
        else:
            self.append_stmts(statements, node, {"if_stmt": {"condition": shadow_condition, "then_body": true_body}})

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

        self.append_stmts(statements, node, {
            "while_stmt": {
                "condition": shadow_condition, "condition_prebody": new_condition_init, "body": new_while_body
            }
        })

    def for_statement(self, node, statements):
        init_children = self.find_children_by_field(node, "init")
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
            self.parse(child, init_body)

        for child in step_children:
            self.parse(child, step_body)

        for_body = []
        #self.sync_tmp_variable(for_body, statements)

        block = self.find_child_by_field(node, "body")
        self.parse(block, for_body)

        self.append_stmts(statements, node, {"for_stmt":
                               {"init_body": init_body,
                                "condition": shadow_condition,
                                "condition_prebody": condition_init,
                                "update_body": step_body,
                                "body": for_body}})

    def each_statement(self, node, statements):
        child = self.find_child_by_type(node, "modifiers")
        modifiers = self.read_node_text(child).split()

        mytype = self.find_child_by_field(node, "type")
        shadow_type = self.read_node_text(mytype)

        name = self.find_child_by_field(node, "name")
        shadow_name = self.parse(name, statements)

        value = self.find_child_by_field(node, "value")
        shadow_value = self.parse(value, statements)

        for_body = []
        #self.sync_tmp_variable(statements, for_body)

        body = self.find_child_by_field(node, "body")
        self.parse(body, for_body)

        self.append_stmts(statements, node, {"forin_stmt":
                               {"attrs": modifiers,
                                "data_type": shadow_type,
                                "name": shadow_name,
                                "receiver": shadow_value,
                                "body": for_body}})

    def assert_statement(self, node, statements):
        expr = node.named_children[0]
        shadow_expr = self.parse(expr, statements)

        self.append_stmts(statements, node, {"assert_stmt": {"condition": shadow_expr}})

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
        shadow_name = ""
        if node.named_child_count > 0:
            name = node.named_children[0]
            shadow_name = self.parse(name, statements)

        self.append_stmts(statements, node, {"break_stmt": {"name": shadow_name}})

    def continue_statement(self, node, statements):
        shadow_name = ""
        if node.named_child_count > 0:
            name = node.named_children[0]
            shadow_name = self.parse(name, statements)

        self.append_stmts(statements, node, {"continue_stmt": {"name": shadow_name}})

    def return_statement(self, node, statements):
        shadow_name = ""
        if node.named_child_count > 0:
            name = node.named_children[0]
            shadow_name = self.parse(name, statements)

        self.append_stmts(statements, node, {"return_stmt": {"name": shadow_name}})
        return shadow_name

    def yield_statement(self, node, statements):
        shadow_expr = ""
        if node.named_child_count > 0:
            expr = node.named_children[0]
            shadow_expr = self.parse(expr, statements)

        self.append_stmts(statements, node, {"yield_stmt": {"name": shadow_expr}})
        return shadow_expr

    def throw_statement(self, node, statements):
        shadow_expr = ""
        if node.named_child_count > 0:
            expr = node.named_children[0]
            shadow_expr = self.parse(expr, statements)
        self.append_stmts(statements, node, {"throw_stmt": {"name": shadow_expr}})

    def try_statement(self, node, statements):
        try_op = {}
        try_body = []
        catch_body = []
        else_body = []
        finally_body = []

        # try-with-resources: try ( ...resources... ) { ... }
        # tree-sitter-java commonly uses node type "resource_specification" under try_statement.
        # We parse the resources first and inject the resulting statements at the beginning of try body
        # so the variables are in-scope for the try block and downstream analyses can see them.
        resource_spec = self.find_child_by_type(node, "resource_specification")
        if not resource_spec:
            # Some grammars may expose resources as a field.
            resource_spec = self.find_child_by_field(node, "resources")
        if resource_spec:
            for res in resource_spec.named_children:
                # Resources are typically local_variable_declaration or identifier.
                # local_variable_declaration is already mapped to variable_declaration, so parse() will emit GIR.
                mytype = self.find_child_by_field(res, "type")
                shadow_type = self.read_node_text(mytype)
                name = self.find_child_by_field(res, "name")
                name = self.read_node_text(name)
                self.append_stmts(try_body, node,
                                  {"variable_decl": {"data_type": shadow_type, "name": name}})
                value_node = self.find_child_by_field(res, "value")
                shadow_value = self.parse(value_node, try_body)

                self.append_stmts(try_body, node, {"assign_stmt": {"target": name, "operand": shadow_value}})
        # Parse try body block and append after resources
        body = self.find_child_by_field(node, "body")
        if body:
            self.parse(body, try_body)
        try_op["body"] = try_body

        #self.sync_tmp_variable(catch_body, statements)
        # Java uses "catch_clause" (but keep backward compatibility with old "except_clause" naming).
        catch_clauses = self.find_children_by_type(node, "catch_clause")
        if not catch_clauses:
            catch_clauses = self.find_children_by_type(node, "except_clause")

        if catch_clauses:
            for clause in catch_clauses:
                catch_clause = {}

                if clause.type == "catch_clause":
                    # Prefer structured fields if available.
                    param = self.find_child_by_field(clause, "parameter")
                    if not param:
                        param = self.find_child_by_type(clause, "catch_formal_parameter")
                    if param:
                        catch_clause["exception"] = self.read_node_text(param)
                else:
                    # Legacy fallback (kept to avoid breaking existing outputs).
                    condition = clause.children[1: -2]
                    if len(condition) > 0:
                        shadow_condition = self.parse(condition[0], catch_body)
                        catch_clause["expcetion"] = shadow_condition

                shadow_catch_clause_body = []
                clause_body = self.find_child_by_field(clause, "body")
                if not clause_body and len(clause.children) > 0:
                    clause_body = clause.children[-1]
                self.parse(clause_body, shadow_catch_clause_body)
                catch_clause["body"] = shadow_catch_clause_body
                catch_body.append({"catch_clause": catch_clause})
        try_op["catch_body"] = catch_body

        #self.sync_tmp_variable(finally_body, statements)
        finally_clause = self.find_child_by_type(node, "finally_clause")
        if finally_clause:
            finally_clause_body = finally_clause.children[-1]
            self.parse(finally_clause_body, finally_body)
        try_op["final_body"] = finally_body

        self.append_stmts(statements, node, {"try_stmt": try_op})

    def variable_declaration(self, node, statements):
        child = self.find_child_by_type(node, "modifiers")
        modifiers = self.read_node_text(child).split()

        mytype = self.find_child_by_field(node, "type")
        shadow_type = self.read_node_text(mytype)

        declarators = self.find_children_by_field(node, "declarator")
        for child in declarators:
            has_init = False
            name = self.find_child_by_field(child, "name")
            name = self.read_node_text(name)
            value = self.find_child_by_field(child, "value")
            shadow_value = None
            if value:
                has_init = True
                shadow_value = self.parse(value, statements)

            self.append_stmts(statements, node, {"variable_decl": {"attrs": modifiers, "data_type": shadow_type, "name": name}})
            if has_init:
                self.append_stmts(statements, node, {"assign_stmt": {"target": name, "operand": shadow_value}})

    def enum_declaration(self, node, statements):
        gir_node = {}
        gir_node["attrs"] = []
        gir_node["fields"] = []
        gir_node["methods"] = []
        gir_node["nested"] = []

        modifiers = self.find_child_by_type(node, "modifiers")
        gir_node["attrs"].extend(self.read_node_text(modifiers).split())

        enum_name = self.find_child_by_field(node, "name")
        shadow_name = self.read_node_text(enum_name)
        gir_node["name"] = shadow_name

        gir_node["supers"] = []
        interfaces = self.find_child_by_field(node, "interfaces")
        if (interfaces and interfaces.named_child_count > 0):
            for interface in interfaces.named_children[0].named_children:
                if self.is_comment(interface):
                    continue
                interface_name = self.read_node_text(interface)
                gir_node["supers"].append(interface_name)

        enum_body = self.find_child_by_field(node, "body")
        self.enum_body(enum_body, gir_node, shadow_name)

        self.append_stmts(statements, node, {"enum_decl": gir_node})

    def enum_body(self, node, gir_node, enum_name):
        enum_body_declarations = self.find_child_by_type(node, "enum_body_declarations")
        if enum_body_declarations:
            self.class_body(enum_body_declarations, gir_node)

        init_class_method_body = []
        static_init_class_method_body = []

        children = self.find_children_by_type(node, "enum_constant")
        if children:
            for child in children:
                # enum_constant为new_object指令准备
                target_body = init_class_method_body
                receiver_object = self.global_this()
                enum_constant = {}
                enum_constant["attrs"] = []
                enum_constant["target"] = ''
                enum_constant["data_type"] = ''
                enum_constant["args"] = []

                modifiers = self.find_child_by_type(child, "modifiers")
                shadow_modifiers = self.read_node_text(modifiers).split()
                if shadow_modifiers:
                    if "static" in shadow_modifiers:
                        target_body = static_init_class_method_body
                        receiver_object = self.current_class()

                enum_constant["attrs"].extend(shadow_modifiers)


                # self.parse(child, stmt_list)
                # for stmt in stmt_list:
                #     if "variable_decl" in stmt:
                #         gir_node["fields"].append(stmt)
                #     elif "assign_stmt" in stmt:
                #         field = stmt["assign_stmt"]
                #         target_body.append({
                #             "field_write": {
                #                 "receiver_object"   : receiver_object,
                #                 "field"             : field["target"],
                #                 "source"            : field["operand"]}})
                #     else:
                #         target_body.append(stmt)

                name = self.find_child_by_field(child, "name")
                shadow_name = self.read_node_text(name)
                tmp_var = self.tmp_variable()
                enum_constant["target"] = tmp_var

                arguments = self.find_child_by_field(child, "arguments")
                arguments_list = []
                if arguments:
                    if arguments.named_child_count > 0:
                        for arg in arguments.named_children:
                            if self.is_comment(arg):
                                continue

                            shadow_arg = self.parse(arg, target_body)
                            if shadow_arg:
                                arguments_list.append(shadow_arg)

                enum_constant["args"] = arguments_list
                enum_constant["data_type"] = enum_name

                # 没有body，相当于创建了一个enum的实例。
                # 有body，相当于创建了一个新的匿名类，继承了原先的enum类。enum constant是这个匿名类的一个实例
                body = self.find_child_by_field(child, "body")
                if body:
                    # 准备匿名类class_decl指令
                    new_class = {}
                    new_class["attrs"] = []
                    new_class["name"] = ''
                    new_class["supers"] = []
                    new_class["fields"] = []
                    new_class["methods"] = []
                    new_class["nested"] = []

                    cls_name = self.tmp_class()
                    new_class["name"] = cls_name
                    new_class["supers"] = enum_name
                    self.class_body(body, new_class)
                    target_body.append({"class_decl": new_class})
                    enum_constant["data_type"] = new_class["name"]

                target_body.append({"new_object": enum_constant})
                gir_node["fields"].append({
                    "variable_decl": {
                        'attrs': [],
                        "data_type": enum_name,
                        "name": shadow_name
                    }
                })
                target_body.append({
                    "field_write": {
                        "receiver_object"   : receiver_object,
                        "field"             : shadow_name,
                        "source"            : enum_constant["target"]
                    }
                })

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
                            "name": "%static_init_class%",
                            "body": static_init_class_method_body
                        }
                    }
                )

    def annotation_type_declaration(self, node, statements):
        gir_node = {}
        gir_node["attrs"] = []
        gir_node["fields"] = []
        gir_node["nested"] = []
        gir_node["annotation_type_elements"] = []
        gir_node["methods"] = []

        child = self.find_child_by_type(node, "modifiers")
        modifiers = self.read_node_text(child).split()
        gir_node["attrs"].extend(modifiers)

        child = self.find_child_by_field(node, "name")
        gir_node["name"] = self.read_node_text(child)

        child = self.find_child_by_field(node, "body")
        self.annotation_type_body(child, gir_node)

        self.append_stmts(statements, node, {"annotation_type_decl": gir_node})

    def annotation_type_body(self, node, gir_node):
        if not node:
            return

        init_class_method_body = []
        static_init_class_method_body = []
        children = self.find_children_by_type(node, "constant_declaration")
        if children:
            for child in children:
                statements = []

                target_body = init_class_method_body
                modifiers = self.find_child_by_type(child, "modifiers")
                if modifiers:
                    if "static" in self.read_node_text(modifiers).split():
                        target_body = static_init_class_method_body

                #self.sync_tmp_variable(statements, target_body)

                self.parse(child, statements)
                if statements:
                    to_be_deleted = []
                    for tmp_counter, stmt in enumerate(statements):
                        if "variable_decl" in stmt:
                            gir_node["fields"].append(stmt)
                            to_be_deleted.append(tmp_counter)
                        else:
                            target_body.append(stmt)

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
                        "name": "%static_init_class%",
                        "body": static_init_class_method_body
                    }
                }
            )

        children = self.find_children_by_type(node, "annotation_type_element_declaration")
        if (children):
            annotation_type_elements = []
            for child in children:
                modifiers = self.find_child_by_type(child, "modifiers")
                modifiers = self.read_node_text(modifiers).split()

                mytype = self.find_child_by_field(child, "type")
                shadow_type = self.read_node_text(mytype)

                name = self.find_child_by_field(child, "name")
                name = self.read_node_text(name)

                is_dimensions = self.find_child_by_field(child, "dimensions") is not None
                value = self.find_child_by_field(child, "value")

                if not value:
                    continue
                if is_dimensions and value and value.named_child_count > 0:
                    annotation_type_elements.append(
                        {"new_array": {"attrs": modifiers, "type": shadow_type, "target": name}})
                    index = 0
                    for child in value.named_children:
                        if self.is_comment(child):
                            continue

                        shadow_child = self.parse(child, annotation_type_elements)
                        annotation_type_elements.append(
                            {"array_write": {"array": name, "index": str(index), "source": shadow_child}})
                        index += 1
                else:
                    shadow_value = self.parse(value, annotation_type_elements)
                    annotation_type_elements.append({"annotation_type_elements_decl":
                                                         {"attrs": modifiers, "data_type": shadow_type, "name": name,
                                                          "value": shadow_value}})
            gir_node["annotation_type_elements"].extend(annotation_type_elements)

        subtypes = ["class_declaration", "interface_declaration",
                    "annotation_type_declaration", "enum_declaration"]
        for st in subtypes:
            children = self.find_children_by_type(node, st)
            if not children:
                continue

            for child in children:
                self.parse(child, gir_node["nested"])

    def obtain_literal_handler(self, node):
        return self.LITERAL_MAP.get(node.type, None)

    def check_expression_handler(self, node):
        return self.EXPRESSION_HANDLER_MAP.get(node.type, None)

    def check_declaration_handler(self, node):
        return self.DECLARATION_HANDLER_MAP.get(node.type, None)

    def check_statement_handler(self, node):
        return self.STATEMENT_HANDLER_MAP.get(node.type, None)

    def is_literal(self, node):
        return self.obtain_literal_handler(node) is not None

    def is_expression(self, node):
        return self.check_expression_handler(node) is not None

    def is_statement(self, node):
        return self.check_statement_handler(node) is not None

    def is_declaration(self, node):
        return self.check_declaration_handler(node) is not None

    def literal(self, node, statements, replacement):
        handler = self.obtain_literal_handler(node)
        return handler(node, statements, replacement)

    def expression(self, node, statements):
        handler = self.check_expression_handler(node)
        return handler(node, statements)

    def declaration(self, node, statements):
        handler = self.check_declaration_handler(node)
        return handler(node, statements)

    def statement(self, node, statements):
        handler = self.check_statement_handler(node)
        return handler(node, statements)
