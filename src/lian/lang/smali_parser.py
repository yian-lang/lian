#!/usr/bin/env python3

from lian.lang import common_parser
import re

type_list = ['variable', 'parameter', 'number', 'string', 'float', 'character', 'identifier', 'list', 'body', 'class_identifier']
label_list = {}
switch_table={}
unsolved_switch={}
array_data_list={}
unsolved_array_data={}
latest_label = None
tmp_exception = None
class Parser(common_parser.Parser):
    def is_comment(self, node):
        return node.type == "comment"
        #pass

    def is_identifier(self, node):
        return node.type == "identifier" or node.type == "variable" or node.type == "parameter"
        # pass

    def obtain_literal_handler(self, node):
        LITERAL_MAP = {
            "number":self.regular_number_literal,
            "float" : self.regular_number_literal,
            "NaN":self.regular_literal,
            "Infinity":self.regular_literal,
            "string":self.string_literal,
            "boolean":self.regular_literal,
            "character":self.character_literal,
            "null":self.regular_literal
        }
        return LITERAL_MAP.get(node.type, None)

    def is_literal(self, node):
        return self.obtain_literal_handler(node) is not None

    def literal(self, node, statements, replacement):
        handler = self.obtain_literal_handler(node)
        return handler(node, statements, replacement)

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

    def character_literal(self, node, statements, replacement):
        value = self.read_node_text(node)
        return "'%s'" % value

    def regular_number_literal(self, node, statements, replacement):
        value = self.read_node_text(node)
        #value=re.compile(r'[LlSsTtf]').sub("",value)
        value = self.common_eval(value)
        return self.read_node_text(node)

    def regular_literal(self, node, statements, replacement):
        return self.read_node_text(node)

    def check_declaration_handler(self, node):
        DECLARATION_HANDLER_MAP = {
            "class_definition": self.class_definition,
            "method_definition": self.method_definition,
            "field_definition": self.field_definition,
            "local_directive": self.variable_directive,
            "param_directive": self.param_directive,
            "parameter_directive": self.parameter_directive,
            "array_data_directive": self.array_data_directive,
            "annotation_directive": self.annotation_directive,
            "line_directive": self.notmatch_directive,
            "locals_directive": self.notmatch_directive,
            "registers_directive": self.notmatch_directive,
            "end_local_directive": self.end_local_directive,
            "restart_local_directive": self.restart_local_directive,
            "prologue_directive": self.notmatch_directive,
            "epilogue_directive": self.notmatch_directive,
            "source_directive": self.notmatch_directive,
            "catch_directive":self.catch_directive,
            "catchall_directive":self.catch_directive,
            "packed_switch_directive": self.packed_switch_directive,
            "sparse_switch_directive": self.sparse_switch_directive,
        }
        return DECLARATION_HANDLER_MAP.get(node.type, None)

    def is_declaration(self, node):
        return self.check_declaration_handler(node) is not None

    def declaration(self, node, statements):
        handler = self.check_declaration_handler(node)
        return handler(node, statements)

    def check_expression_handler(self, node):
        EXPRESSION_HANDLER_MAP = {
            "expression": self.primary_expression
        }

        return EXPRESSION_HANDLER_MAP.get(node.type, None)

    def is_expression(self, node):
        return self.check_expression_handler(node) is not None

    def expression(self, node, statements):
        handler = self.check_expression_handler(node)
        return handler(node, statements)

    def check_statement_handler(self, node):
        STATEMENT_HANDLER_MAP = {
            "label" : self.label_statement,
            "jmp_label": self.label_statement,
        }
        return STATEMENT_HANDLER_MAP.get(node.type, None)

    def is_statement(self, node):
        return self.check_statement_handler(node) is not None

    def statement(self, node, statements):
        handler = self.check_statement_handler(node)
        return handler(node, statements)

    def primary_expression(self, node, statements):
        opcode = self.find_child_by_type(node, "opcode")
        shadow_opcode = self.read_node_text(opcode)
        values = {}
        for type in type_list:
            values[type] = []
        for type in type_list:
            values[type].extend(self.find_children_by_type(node, type))
        if shadow_opcode == "nop":
            return ''
        elif re.compile(r'^move.*').match(shadow_opcode):
            if "result" in shadow_opcode in shadow_opcode:
                v0 = self.read_node_text(values["variable"][0])
                global tmp_return
                self.append_stmts(statements, node, {"assign_stmt": {"target": v0, "operand": tmp_return, "operator": "result"}})
            elif "exception" in shadow_opcode:
                v0 = self.read_node_text(values["variable"][0])
                self.append_stmts(statements, node, {"assign_stmt": {"target": v0, "operand": tmp_exception, "operator": "exception"}})
            else:
                v0 = self.read_node_text(values["variable"][0])
                v1 = self.read_node_text(values["variable"][1])
                self.append_stmts(statements, node, {"assign_stmt": {"target": v0, "operand": v1}})
            return v0
        elif re.compile(r'^return.*').match(shadow_opcode):
            if "void" in shadow_opcode:
                self.append_stmts(statements, node, {"return_stmt": {"name": ''}})
                return ''
            else:
                v0 = self.read_node_text(values["variable"][0])
                self.append_stmts(statements, node, {"return_stmt": {"name": v0}})
                return v0
        elif re.compile(r'^const.*').match(shadow_opcode):
            v0 = self.read_node_text(values["variable"][0])
            if 'string' in shadow_opcode:
                string = self.find_child_by_type(values["string"][0], 'string_fragment')
                shadow_string = self.read_node_text(string)
                self.append_stmts(statements, node, {"assign_stmt": {"target": v0, "operand": shadow_string}})
            elif 'class' in shadow_opcode:
                class_identifier = values['class_identifier'][0]
                shadow_class = self.read_node_text(class_identifier)
                self.append_stmts(statements, node, {"assign_stmt": {"target": v0, "operand": shadow_class}})
            else:
                number = values["number"][0]
                shadow_number = self.read_node_text(number)
                self.append_stmts(statements, node, {"assign_stmt": {"target": v0, "operand": shadow_number}})
            return v0
        elif re.compile(r'^check.*').match(shadow_opcode):
            v0 = self.read_node_text(node.named_children[1])
            class_identifier = node.named_children[2]
            shadow_class = self.read_node_text(class_identifier)
            self.append_stmts(statements, node, {"type_cast_stmt": {"target": self.tmp_variable(), "data_type": shadow_class, "source":v0,"error":self.tmp_variable()}})
            return v0
        elif shadow_opcode == "instance-of":
            v1 = self.read_node_text(values["variable"][1])
            v2 = self.read_node_text(values["variable"][1])
            tmp_var = self.tmp_variable()
            self.append_stmts(statements, node, {"assign_stmt":
                                   {"target": tmp_var, "operator": "instanceof", "operand": v1,
                                    "operand2": v2}})
            v0 = self.read_node_text(values["variable"][0])
            self.append_stmts(statements, node, {"assign_stmt": {"target": v0, "operand": tmp_var}})
            return v0
        elif shadow_opcode == 'array-length':
            v0 = self.read_node_text(values["variable"][0])
            v1 = self.read_node_text(values["variable"][1])
            self.append_stmts(statements, node, {"assign_stmt": {"target": v0, "operand": v1, "operator": "array-length"}})
            return v0
        elif re.compile(r'^new.*').match(shadow_opcode):
            if shadow_opcode == "new-instance":
                gir_node = {}
                mytype = self.read_node_text(values['class_identifier'][0])
                gir_node["data_type"] = mytype
                tmp_var = self.tmp_variable()
                gir_node["target"] = tmp_var
                self.append_stmts(statements, node, {"new_object": gir_node})
                v0 = self.read_node_text(values["variable"][0])
                self.append_stmts(statements, node, {"assign_stmt": {"target": v0, "operand": tmp_var}})
                return v0
            else:
                type = self.read_node_text(node.named_children[3])
                v0 = self.read_node_text(node.named_children[1])
                v1 = self.read_node_text(node.named_children[2])
                tmp_var = self.tmp_variable()
                self.append_stmts(statements, node, {"new_array": {"type": type, "attrs": v1, "target": tmp_var}})
                self.append_stmts(statements, node, {"assign_stmt": {"target": v0, "operand": tmp_var}})
                return v0
        elif re.compile(r'^filled.*').match(shadow_opcode):
            if "range" in shadow_opcode:
                type = self.read_node_text(self.find_child_by_type_type(node, "array_type", "primitive_type"))
                range_node = self.read_node_text(self.find_child_by_type(node,"range"))
                matches = re.findall(r'v(\d+)', range_node)
                tmp_var = self.tmp_variable()
                self.append_stmts(statements, node, {"new_array": {"type": type, "target": tmp_var}})
                for i in range(int(matches[0]),int(matches[1])+1):
                    self.append_stmts(statements, node, {"assign_stmt": {"target": f'v{i}', "operand": tmp_var, "operator": "filled-new-array/range"}})
                return tmp_var
            else:
                type = self.read_node_text(self.find_child_by_type_type(node, "array_type", "primitive_type"))
                type = self.read_node_text(self.find_child_by_type_type(node, "array_type", "primitive_type"))
                list = self.find_child_by_type(node, "list")
                vs = self.find_children_by_type(list,"variable")
                tmp_var = self.tmp_variable()
                self.append_stmts(statements, node, {"new_array": {"type": type, "target": tmp_var}})
                for i in range(len(vs)):
                    name = self.read_node_text(vs[i])
                    self.append_stmts(statements, node, {"assign_stmt": {"target": name, "operand": f'{tmp_var}[{i}]'}})
                return tmp_var
        elif re.compile(r'^fill-.*').match(shadow_opcode):
            v0 = self.read_node_text(node.named_children[1])
            array_label = self.read_node_text(node.named_children[2])
            if array_label in array_data_list.keys():
                shadow_values= array_data_list[array_label]
                for i in range(len(shadow_values)):
                    self.append_stmts(statements, node, {"array_write": {"array": v0 , "index":i , "src":shadow_values[i] }})
            else:
                unsolved_array_data[array_label] = {'array': v0, 'stmt_id':len(statements)}
            return v0
        elif re.compile(r'^throw.*').match(shadow_opcode):
            shadow_expr = self.read_node_text(values["variable"][0])
            self.append_stmts(statements, node, {"throw_stmt": {"name": shadow_expr}})
            return
        elif re.compile(r'^goto.*').match(shadow_opcode):
            label = self.read_node_text(self.find_child_by_type(node, "label"))
            self.append_stmts(statements, node, {"goto_stmt": {"name": label}})
            return
        elif re.search(r'-switch$', shadow_opcode):
            p0 = self.read_node_text(node.named_children[1])
            switch_label = self.read_node_text(node.named_children[2])
            cases = None
            if switch_label in switch_table:
                cases = switch_table[switch_label]
            else:
                unsolved_switch[switch_label]= len(statements)
            self.append_stmts(statements, node, {"switch_stmt": {"condition": p0, "body": cases}})
            return p0
        elif re.compile(r'^cmp.*').match(shadow_opcode):
            v0 = self.read_node_text(values["variable"][0])
            v1 = self.read_node_text(values["variable"][1])
            v2 = self.read_node_text(values["variable"][2])
            tmp_var = self.tmp_variable()
            if 'cmpl' in shadow_opcode:
                self.append_stmts(statements, node, {"assign_stmt": {"target": tmp_var, "operator": '<', "operand": v1,"operand2": v2}})
            else:
                self.append_stmts(statements, node, {"assign_stmt": {"target": tmp_var, "operator": '>', "operand": v1,"operand2": v2}})
            self.append_stmts(statements, node, {"assign_stmt": {"target": v0, "operand": tmp_var}})
            return v0
        elif re.compile(r'^if-.*').match(shadow_opcode):
            op = re.findall(r'if-([^ \n\r\t]+)', shadow_opcode)
            v0 = self.read_node_text(node.named_children[1])
            if 'z' not in op[0]:
                v1 = self.read_node_text(node.named_children[2])
            else:
                v1 = "0"
            tmp_var = self.tmp_variable()
            self.append_stmts(statements, node, {"assign_stmt": {"target": tmp_var, "operator": op[0], "operand": v0,"operand2": v1}})
            label = self.read_node_text(self.find_child_by_type(node, "label"))
            self.append_stmts(statements, node, {"if_stmt":{"condition": tmp_var,"then_body":[{"goto_stmt": {"name": label}}]}})
            return tmp_var
        elif re.compile(r'^aget.*').match(shadow_opcode):
            v0 = self.read_node_text(values["variable"][0])
            v1 = self.read_node_text(values["variable"][1])
            v2 = self.read_node_text(values["variable"][2])
            self.append_stmts(statements, node, {"array_read": {"target": v0, "array": v1, "index": v2}})
            return v0
        elif re.compile(r'^aput.*').match(shadow_opcode):
            v0 = self.read_node_text(values["variable"][0])
            v1 = self.read_node_text(values["variable"][1])
            v2 = self.read_node_text(values["variable"][2])
            self.append_stmts(statements, node, {"array_write": {"array": v1, "index": v2, "src": v0}})
            return v0

        elif re.compile(r'^invoke.*').match(shadow_opcode) or shadow_opcode=='execute-inline' or shadow_opcode=='excute-inline-range':
            #global tmp_return
            tmp_return=self.tmp_variable()
            args_list = []
            args=node.named_children[1]
            if 'range' in shadow_opcode:
                start=self.read_node_text(self.find_child_by_field(args,"start"))
                end=self.read_node_text(self.find_child_by_field(args,"end"))
                s=start[1:]
                e=end[1:]
                register_type=start[0]
                for arg_num in range(int(s), int(e)+1):
                    arg=register_type+str(arg_num)
                    args_list.append(arg)
            else:
                if args.named_child_count > 0:
                    for child in args.named_children:
                        shadow_variable = self.parse(child, statements)
                        if shadow_variable:
                            args_list.append(shadow_variable)
            function=self.find_child_by_type(node.named_children[2],"full_method_signature")
            method = self.find_child_by_type(function,"method_signature")
            class_type=self.read_node_text(function.named_children[0])
            method_name = self.read_node_text(self.find_child_by_type(method,"method_identifier"))
            data_type = self.read_node_text(method.named_children[-1])
            if 'polymorphic' in shadow_opcode:
                prototype=self.read_node_text(node.named_children[3])
            else :
                prototype=""
            self.append_stmts(statements, node, {"call_stmt": {"target": tmp_return, "name": method_name, "args": args_list,"data_type":data_type,"prototype":prototype}})

        elif re.compile(r'^rsub.*').match(shadow_opcode):
            dest = self.parse(node.named_children[1], statements)
            source1 = self.parse(node.named_children[2], statements)
            source2 = self.parse(node.named_children[3], statements)
            self.append_stmts(statements, node, {"assign_stmt": {"target": dest, "operator": '-', "operand": source2,"operand2": source2}})
            return dest
        elif re.compile(r'^add.*/2addr').match(shadow_opcode):
            return self.binary_expression_2addr(node, statements, "+")
        elif re.compile(r'^sub.*/2addr').match(shadow_opcode):
            return self.binary_expression_2addr(node, statements, "-")
        elif re.compile(r'^mul.*/2addr').match(shadow_opcode):
            return self.binary_expression_2addr(node, statements, "*")
        elif re.compile(r'^div.*/2addr').match(shadow_opcode):
            return self.binary_expression_2addr(node, statements, "/")
        elif re.compile(r'^rem.*/2addr').match(shadow_opcode):
            return self.binary_expression_2addr(node, statements, "%")
        elif re.compile(r'^and.*/2addr').match(shadow_opcode):
            return self.binary_expression_2addr(node, statements, "&")
        elif re.compile(r'^or.*/2addr').match(shadow_opcode):
            return self.binary_expression_2addr(node, statements, "|")
        elif re.compile(r'^xor.*/2addr').match(shadow_opcode):
            return self.binary_expression_2addr(node, statements, "^")
        elif re.compile(r'^shl.*/2addr').match(shadow_opcode):
            return self.binary_expression_2addr(node, statements, "<<")
        elif re.compile(r'^shr.*/2addr').match(shadow_opcode):
            return self.binary_expression_2addr(node, statements, ">>")
        elif re.compile(r'^ushr.*/2addr').match(shadow_opcode):
            return self.binary_expression_2addr(node, statements, ">>>")
        elif re.compile(r'^add.*[^/2addr]').match(shadow_opcode):
            return self.binary_expression(node, statements, "+")
        elif re.compile(r'^sub.*[^/2addr]').match(shadow_opcode):
            return self.binary_expression(node, statements, "-")
        elif re.compile(r'^mul.*[^/2addr]').match(shadow_opcode):
            return self.binary_expression(node, statements, "*")
        elif re.compile(r'^div.*[^/2addr]').match(shadow_opcode):
            return self.binary_expression(node, statements, "/")
        elif re.compile(r'^rem.*[^/2addr]').match(shadow_opcode):
            return self.binary_expression(node, statements, "%")
        elif re.compile(r'^and.*[^/2addr]').match(shadow_opcode):
            return self.binary_expression(node, statements, "&")
        elif re.compile(r'^or.*[^/2addr]').match(shadow_opcode):
            return self.binary_expression(node, statements, "|")
        elif re.compile(r'^xor.*[^/2addr]').match(shadow_opcode):
            return self.binary_expression(node, statements, "^")
        elif re.compile(r'^shl.*[^/2addr]').match(shadow_opcode):
            return self.binary_expression(node, statements, "<<")
        elif re.compile(r'^shr.*[^/2addr]').match(shadow_opcode):
            return self.binary_expression(node, statements, ">>")
        elif re.compile(r'^ushr.*[^/2addr]').match(shadow_opcode):
            return self.binary_expression(node, statements, ">>>")

        elif re.compile(r'^neg.*').match(shadow_opcode):
            return self.unary_expression(node, statements, "-")
        elif re.compile(r'^not.*').match(shadow_opcode):
            return self.unary_expression(node, statements, "~")
        elif re.compile(r'^iput.*').match(shadow_opcode) or shadow_opcode=='instance-get':
            source = self.parse(node.named_children[1], statements)
            receiver_object = self.parse(node.named_children[2], statements)
            field=self.find_child_by_type(node.named_children[3],"field_identifier")
            shadow_field=self.read_node_text(field)
            self.append_stmts(statements, node, {"field_write": {"receiver_object": receiver_object, "field": shadow_field, "source": source}})
        elif re.compile(r'^iget.*').match(shadow_opcode) or shadow_opcode=='instance-get':
            target = self.parse(node.named_children[1], statements)
            receiver_object = self.parse(node.named_children[2], statements)
            field=self.find_child_by_type(node.named_children[3],"field_identifier")
            shadow_field=self.read_node_text(field)
            self.append_stmts(statements, node, {"field_read": {"target": target, "receiver_object": receiver_object, "field": shadow_field}})
        elif re.compile(r'^sget.*').match(shadow_opcode) or shadow_opcode=='static-get':
            target = self.parse(node.named_children[1], statements)
            source = node.named_children[2]
            receiver_object = self.find_child_by_type(source,"class_identifier")
            shadow_receiver_object=self.read_node_text(receiver_object)
            field = self.find_child_by_type(source,"field_identifier")
            shadow_field = self.read_node_text(field)
            self.append_stmts(statements, node, {"field_read": {"target": target, "receiver_object": shadow_receiver_object, "field": shadow_field}})
        elif re.compile(r'^sput.*').match(shadow_opcode) or shadow_opcode=='static-put':
            source = self.parse(node.named_children[1], statements)
            target = node.named_children[2]
            receiver_object = self.find_child_by_type(target,"class_identifier")
            shadow_receiver_object=self.read_node_text(receiver_object)
            field = self.find_child_by_type(target,"field_identifier")
            shadow_field = self.read_node_text(field)
            self.append_stmts(statements, node, {"field_write": {"receiver_object": shadow_receiver_object, "field": shadow_field, "source": source}})

        elif shadow_opcode in ['int-to-long','int-to-float','int-to-double','long-to-int',
                               'long-to-float','long-to-double','float-to-int','float-to-long',
                               'float-to-double','double-to-int','double-to-long',
                               'double-to-float','int-to-byte','int-to-char','int-to-short']:
            return self.unary_expression(node, statements, 'cast')


    def unary_expression(self, node, statements,op):
        dest = self.parse(node.named_children[1], statements)
        source = self.parse(node.named_children[2], statements)
        self.append_stmts(statements, node, {"assign_stmt": {"target": dest, "operator": op, "operand": source}})
        return dest

    def binary_expression_2addr(self, node, statements, op):
        dest = self.parse(node.named_children[1], statements)
        source = self.parse(node.named_children[2], statements)
        self.append_stmts(statements, node, {"assign_stmt": {"target": dest, "operator": op, "operand": dest,"operand2": source}})
        return dest

    def binary_expression(self, node, statements, op):
        dest = self.parse(node.named_children[1], statements)
        source1 = self.parse(node.named_children[2], statements)
        source2 = self.parse(node.named_children[3], statements)
        self.append_stmts(statements, node, {"assign_stmt": {"target": dest, "operator": op, "operand": source1,"operand2": source2}})
        return dest

    def param_directive(self, node, statements):
        name = self.read_node_text(self.find_child_by_type(node, "parameter"))
        annotation_list = self.find_children_by_type(node, "annotation_directive")
        if len(annotation_list):
            for annotation in annotation_list:
                self.annotation_directive(annotation, statements)
        else:
            shadow_value = self.read_node_text(node.named_children[1])
            self.append_stmts(statements, node, {"parameter_decl": {"name": name}})
            self.append_stmts(statements, node, {"assign_stmt": {"target": name, "operand": shadow_value}})
        return name

    def parameter_directive(self, node, statements):
        name = self.read_node_text(node.named_children[0])
        self.append_stmts(statements, node, {"parameter_decl": {"name": name}})
        annotation_list = self.find_children_by_type(node, "annotation_directive")
        if len(annotation_list):
            for annotation in annotation_list:
                self.annotation_directive(annotation, statements)
        return

    def variable_directive(self, node, statements):
        shadow_register = self.read_node_text(node.named_children[0])
        if node.named_children[1]:
            shadow_local = self.read_node_text(node.named_children[1])
            shadow_data_type = self.read_node_text(node.named_children[2])
            if self.find_child_by_type(node, "array_type"):
                array_node = self.find_child_by_type(node, "array_type")
                shadow_data_type = self.read_node_text(array_node)
                self.append_stmts(statements, node, {"variable_decl": {"name": shadow_local, "attrs": ["array"], "data_type": shadow_data_type}})
            else:
                self.append_stmts(statements, node, {"variable_decl": {"name": shadow_local, "data_type": shadow_data_type}})
            self.append_stmts(statements, node, {"assign_stmt": {"target": shadow_local, "operand": shadow_register}})
        else:
            self.append_stmts(statements, node, {"variable_decl": {"name": shadow_register}})
        return

    def annotation_directive(self, node, statements):
        shadow_annotation_visibility = self.read_node_text(node.named_children[0])
        shadow_class_identifier = self.read_node_text(node.named_children[1])
        annotation_property_list = node.named_children[2:]
        gir_init_dict = {}
        for annotation_property in annotation_property_list:
            annotation_key = annotation_property.named_children[0]
            annotation_value = self.find_child_by_type(annotation_property, "annotation_value")
            gir_init_dict[self.read_node_text(annotation_key)] = self.read_node_text(annotation_value)
        self.append_stmts(statements, node, {"annotation_type_decl": {"attrs": [shadow_annotation_visibility], "name": shadow_class_identifier, "init": [gir_init_dict]}})
        return

    def notmatch_directive(self, node, statements):
        return

    def restart_local_directive(self, node, statements):
        register = self.read_node_text(node.named_children[0])
        self.append_stmts(statements, node, {"variable_decl": { "name": register }})
        return register

    def end_local_directive(self, node, statements):
        register = self.read_node_text(node.named_children[0])
        self.append_stmts(statements, node, {"del_stmt": { "name": register }})

    def label_statement(self, node, statements):
        label= self.read_node_text(node)
        self.append_stmts(statements, node, {"label_stmt": { "name": label }})
        label_list[label]= len(statements)
        global latest_label
        latest_label = label

    def packed_switch_directive(self, node, statements):
        global latest_label
        switch_label = latest_label
        condition = self.read_node_text(self.find_child_by_type(node, "number"))
        if '0x' in condition:
            shadow_condition = int(condition,base=16)
        else:
            shadow_condition = int(condition,base=10)
        cases = []
        for child in node.named_children:
            if child.type == "label" or child.type == "jmp_label":
                label = self.read_node_text(child)
                cases.append({"case_stmt": {"condition": str(shadow_condition), "body": [{"goto_stmt": {"name": label}}]}})
                shadow_condition += 1
        switch_table[switch_label] = cases
        if switch_label in unsolved_switch.keys():
            stmt_id = unsolved_switch[switch_label]
            del unsolved_switch[switch_label]
            statements[stmt_id]["switch_stmt"]['body']= cases

    def sparse_switch_directive(self, node, statements):
        global latest_label
        switch_label = latest_label
        conditions = self.find_children_by_type(node, "number")
        labels = self.find_children_by_type(node, "label")
        cases = []
        for condition,label in zip(conditions,labels):
            shadow_condition = self.read_node_text(condition)
            shadow_label = self.read_node_text(label)
            cases.append({"case_stmt": {"condition": str(shadow_condition), "body": [{"goto_stmt": {"name": shadow_label}}]}})
        switch_table[switch_label] = cases
        if switch_label in unsolved_switch.keys():
            stmt_id = unsolved_switch[switch_label]
            del(unsolved_switch[switch_label])
            statements[stmt_id]["switch_stmt"]['body']= cases

    def array_data_directive(self, node, statements):
        element_width = self.find_child_by_field(node, "element_width")
        values = self.find_children_by_field(node,"value")
        global latest_label
        array_data_label= latest_label
        shadow_values = []
        for value in values:
            shadow_values.append(self.read_node_text(value))
        array_data_list[array_data_label] = shadow_values
        if array_data_label in unsolved_array_data.keys():
            stmt_id = unsolved_array_data[array_data_label]["stmt_id"]
            array = unsolved_array_data[array_data_label]["array"]
            del(unsolved_array_data[array_data_label])
            for i in range(len(shadow_values)):
                statements.insert(stmt_id, {"array_write": {"array": array , "index":i , "src":shadow_values[i] }})
                stmt_id += 1

    def catch_directive(self, node, statements):
        exception= self.read_node_text(self.find_child_by_type(node,"class_identifier"))
        global tmp_exception
        tmp_exception = exception
        labels=[]
        for child in node.named_children:
            if child.type == "label" or child.type == "jmp_label":
                labels.append(self.read_node_text(child))
        try_start_label = labels[0]
        try_end_label = labels[1]
        handler_label = labels[2]
        stmt_start_id = label_list[try_start_label]
        stmt_end_id = label_list[try_end_label]
        body=[]
        for id in range(stmt_start_id,stmt_end_id-1):
            body.append(statements[id])
        del(statements[stmt_start_id:stmt_end_id-1])
        if exception is not None:
            catch_body=[{"catch_clause":{"exception":exception,"body":[{"goto_stmt":{"name":handler_label}}]}}]
        else:
            catch_body=[{"catch_stmt":{"body":[{"goto_stmt":{"name":handler_label}}]}}]
        self.append_stmts(statements, node, {"try_stmt":{"body":body,"catch_body":catch_body}})
        for key,value in label_list.items():
            if value > stmt_end_id:
                label_list[key] -= stmt_end_id - stmt_start_id - 1
        for key,value in unsolved_switch.items():
            if value > stmt_end_id:
                unsolved_switch[key] -= stmt_end_id - stmt_start_id - 1
        for key,value in unsolved_array_data.items():
            if value["stmt_id"] > stmt_end_id:
                unsolved_array_data[key]["stmt_id"] -= stmt_end_id - stmt_start_id - 1

    def class_definition(self,node, statements):
        class_directive = self.find_child_by_type(node, "class_directive")
        access_modifiers=self.find_child_by_type(class_directive,"access_modifiers")
        attrs=[]
        if access_modifiers is not None:
            access_modifier = self.find_children_by_type(access_modifiers,"access_modifier")
            for modifier in access_modifier:
                attrs.append(self.read_node_text(modifier))
        class_name = self.read_node_text(self.find_child_by_type(class_directive,"class_identifier"))
        supers =[]
        super_class = self.read_node_text(self.find_child_by_type_type(node,"super_directive","class_identifier"))
        supers.append(super_class)
        interfaces = self.find_children_by_type(node,"implements_directive")
        for interface in interfaces:
            interface_name = self.read_node_text(self.find_child_by_type(interface,"class_identifier"))
            supers.append(interface_name)
        methods = []
        fields = []
        static_init = []
        init = []
        for child in node.named_children:
            if child.type == "method_definition":
                self.parse(child,methods)
            if child.type == "field_definition":
                self.field_definition(child,fields,static_init,init,statements)
            if child.type == "annotation_directive":
                self.parse(child,statements)
        self.append_stmts(statements, node, {"class_decl":{"attrs":attrs,"name":class_name,"supers":supers,"static_init":static_init,"init":init,"fields":fields,"methods":methods}})

    def method_definition(self,node, statements):
        access_modifiers=self.find_children_by_type(node,"access_modifier")
        attrs=[]
        for modifier in access_modifiers:
            attrs.append(self.read_node_text(modifier))
        if 'constructor' in self.read_node_text(node):
            attrs.append('constructor')
        method_signature = self.find_child_by_type(node,"method_signature")
        method_name = self.read_node_text(self.find_child_by_type(method_signature,"method_identifier"))
        data_type = self.read_node_text(method_signature.named_children[-1])
        parameter=self.find_child_by_type(method_signature,"parameters")
        parameters_type =[]
        if parameter:
            for p in parameter.named_children:
                parameters_type.append(self.read_node_text(p))
        type_index=0
        parameters=[]
        init=[]
        body=[]
        for child in node.named_children:
            temp_parameters=[]
            if child.type == "method_signature" or child.type == "access_modifier":
                pass
            elif child.type == "param_directive":
                self.param_directive(child,temp_parameters)
            elif child.type == "parameter_directive":
                self.parameter_directive(child,temp_parameters)
            else:
                self.parse(child,body)
            for para in temp_parameters:
                if "parameter_decl" in para:
                    shadow_type=parameters_type[type_index]
                    type_index+=1
                    para["parameter_decl"]["data_type"] = shadow_type
                    parameters.append(para)
                elif "assign_stmt" in para:
                    init.append(para)
                else:
                    body.append(para)
        while type_index<len(parameters_type):
            shadow_type=parameters_type[type_index]
            type_index+=1
            parameters.append({"parameter_decl":{"name":None,"data_type":shadow_type}})
        self.append_stmts(statements, node, {"method_decl":{"attrs":attrs,"data_type":data_type,"name":method_name,"parameters":parameters,"body":body}})


    def field_definition(self,node, fields,static_init,init,body):
        access_modifiers=self.find_child_by_type(node,"access_modifiers")
        attrs=[]
        if access_modifiers is not None:
            access_modifier = self.find_children_by_type(access_modifiers,"access_modifier")
            for modifier in access_modifier:
                attrs.append(self.read_node_text(modifier))
        field_identifier = self.read_node_text(self.find_child_by_type(node,"field_identifier"))
        field_type = self.read_node_text(self.find_child_by_type(node,"field_type"))
        shadow_value = None
        for child in node.named_children:
            if child.type != "access_modifiers" and child.type != "field_identifier" and child.type != "field_type" and child.type!= "annotation_directive":
                shadow_value = self.read_node_text(child)
            if child.type == "annotation_directive":
                self.parse(child,body)
        fields.append({"variable_decl":{"attrs":attrs,"name":field_identifier,"type":field_type}})
        if shadow_value:
            if "static" in attrs:
                static_init.append({"field_write": {"receiver_object": self.global_this(),
                                                          "field": field_identifier, "source": shadow_value}})
            else:
                init.append({"field_write": {"receiver_object": self.global_this(),
                                                          "field": field_identifier, "source": shadow_value}})
