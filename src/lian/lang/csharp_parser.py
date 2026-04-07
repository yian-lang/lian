#!/usr/bin/env python3

from lian.lang import common_parser
import copy

class Parser(common_parser.Parser):
    def is_comment(self, node):
        return node.type in ["comment"]

    def is_identifier(self, node):
        return node.type == "identifier"

    def is_literal(self, node):
        return self.obtain_literal_handler(node) is not None

    def literal(self, node, statements, replacement):
        handler = self.obtain_literal_handler(node)
        return handler(node, statements, replacement)

    def is_declaration(self, node):
        return self.check_declaration_handler(node) is not None

    def declaration(self, node, statements):
        handler = self.check_declaration_handler(node)
        return handler(node, statements)

    def is_expression(self, node):
        return self.check_expression_handler(node) is not None

    def expression(self, node, statements):
        handler = self.check_expression_handler(node)
        return handler(node, statements)

    def check_declaration_handler(self, node):
        DECLARATION_HANDLER_MAP = {
            "field_declaration":                self.variable_declaration,
            "variable_declaration":             self.variable_declaration,
            "class_declaration":                self.class_declaration,
            "record_declaration":               self.class_declaration,
            "interface_declaration":            self.class_declaration,
            "enum_declaration":                 self.enum_declaration,
            "constructor_declaration":          self.method_declaration,
            "method_declaration":               self.method_declaration,
            "destructor_declaration":           self.destructor_declaration,
            "property_declaration":             self.property_declaration,
        }
        return DECLARATION_HANDLER_MAP.get(node.type, None)

    def variable_declaration(self, node, statements):
        modifier = self.find_children_by_type(node, "modifier")
        modifiers = []
        # 如果有modifier，证明是field_declaration
        if modifier:
            node = self.find_child_by_type(node, "variable_declaration")
            for modifier_ in modifier:
                modifier_ = self.read_node_text(modifier_)
                modifiers.append(modifier_)
        declarators = self.find_children_by_type(node, "variable_declarator")

        for declarator in declarators:
            has_init = False
            type_node = self.find_child_by_field(node, "type")
            shadow_type = self.read_node_text(type_node)
            name = self.find_child_by_field(declarator, "name")
            name = self.read_node_text(name)
            bracket = self.find_child_by_type(declarator, "bracketed_argument_list")
            equals = self.find_child_by_type(declarator, "equals_value_clause")
            if equals and equals.named_child_count > 0:
                value = equals.named_children[0]
            else:
                value = 0
            if value:
                has_init = True
            if value and '[' in shadow_type and ']' in shadow_type:
                tmp_var = self.tmp_variable()
                self.append_stmts(statements, node, {"new_array": {"type": shadow_type, "target": tmp_var}})

                if value and value.named_child_count > 0:
                    index = 0
                    for item in value.named_children:
                        if self.is_comment(item):
                            continue
                        source = self.parse(item, statements)
                        self.append_stmts(statements, node, {"array_write": {"array": tmp_var, "index": str(index), "source": source}})
                        index += 1
                shadow_value = tmp_var
            else:
                shadow_value = self.parse(value, statements)

            if shadow_type.startswith('u'):
                modifiers.append('unsigned')
            else:
                modifiers.append('signed')
            self.append_stmts(statements, node, {"variable_decl": {"attrs": modifiers, "data_type": shadow_type, "name": name}})

            if has_init:
                self.append_stmts(statements, node, {"assign_stmt": {"target": name, "operand": shadow_value}})
        return

    def enum_declaration(self,node,statements):
        gir_node ={}
        gir_node["attrs"] = []
        gir_node["init"] = []
        gir_node["static_init"] = []
        gir_node["fields"] = []
        gir_node["member_methods"] = []
        gir_node["enum_c onstants"] = []
        gir_node["nested"] = []
        for i in node.named_children:
            if i.type == "attribute_list":
                self.attribute_list(node,gir_node["attrs"])
            if i.type == "modifier":
                self.attribute_list(node,gir_node["attrs"])

        child = self.find_child_by_type(node, "base_list")
        gir_node["attrs"].extend(self.read_node_text(child).split())
        child= self.find_child_by_field(node, "name")
        gir_node["name"] = self.read_node_text(child)

        gir_node["supers"] = []
        child = self.find_child_by_field(node, "body")
        self.enum_member_declaration_list(child, gir_node["static_init"])
        self.append_stmts(statements, node, {"enum_decl": gir_node})

    def enum_member_declaration_list(self,node,statements):
        for i in node.named_children:
            if i.type=="enum_member_declaration":
                self.enum_member_declaration(i,statements)

    def enum_member_declaration(self,node,statements):
        buffer ={}
        buffer["attrs"]=[]
        for j in node.named_children:
            if j.type == "attribute_list":
                self.attribute_list(j,buffer["attrs"])
        child = self.find_child_by_field(node,'name')
        child_name= self.read_node_text(child)
        buffer["name"] = self.read_node_text(child)
        child_value = ""
        self.append_stmts(statements, node, {"variable_decl":buffer})
        if self.find_child_by_field(node,'value'):
            child = self.find_child_by_field(node,'value')
            child_value = self.read_node_text(child)
            self.append_stmts(statements, node, {"assign_stmt":{"target":child_name,"operand":child_value}})


    CLASS_TYPE_MAP = {
        "class_declaration": "class",
        "interface_declaration": "interface",
        "record_declaration": "record",
    }

    def class_declaration(self, node, statements):
        gir_node = {}
        gir_node["attrs"] = []
        gir_node["name"] = []
        # gir_node["supers"] = []
        # gir_node["type_parameters"] = []
        gir_node["static_init"] = []
        gir_node["init"] = []
        gir_node["fields"] = []
        gir_node["member_methods"] = []
        gir_node["nested"] = []

        if node.type in self.CLASS_TYPE_MAP:
            gir_node["attrs"].append(self.CLASS_TYPE_MAP[node.type])

        # 取出所有modifier信息，加入attribute信息中
        modifier = self.find_children_by_type(node, "modifier")
        for child in modifier:
            modifier_content = self.read_node_text(child)
            gir_node["attrs"].append(modifier_content)

        name = self.find_child_by_field(node, "name")
        name = self.read_node_text(name)
        gir_node["name"] = name

        # 泛型的定义，如果没有可以不输出
        type_params = self.find_child_by_field(node, "type_parameters")
        type_params = self.read_node_text(type_params)
        if type_params:
            gir_node["type_parameters"] = type_params

        # record_declaration
        if (gir_node["attrs"][0] == 'record'):
            gir_node["parameters"] = []
            child = self.find_child_by_field(node, "parameters")
            if child:
                child = child.named_children
                for p in child:
                    type_ = self.find_child_by_type(p, "_parameter_type_with_modifiers")
                    if type_:
                        type_ = self.find_child_by_field(type_, "type")
                    name = self.find_child_by_field(p, "name")
                    shadow_type = self.parse(p, type_)
                    shadow_name = self.parse(p, name)
                    gir_node["fields"].append({
                        "variable_decl": {
                            "attrs": ["private", "final"],
                            "data_type": shadow_type,
                            "name": shadow_name}})

        # 继承类，grammar的base对应此处的supers
        bases = self.find_children_by_field(node, "bases")
        for base in bases:
            superclass = self.read_node_text(base)
            # 去掉': '
            superclass = superclass[2:]
            gir_node["supers"] = superclass

        # 调用class_body函数来进一步分割body部分
        body = self.find_child_by_field(node, "body")
        self.class_body(body, gir_node)

        self.append_stmts(statements, node, {f"{self.CLASS_TYPE_MAP[node.type]}_decl": gir_node})

    def class_body(self, node, gir_node):
        if not node:
            return
        field = node.named_children
        decl = []
        for child in field:
            if("declaration" in child.type):
                decl.append(child)

        for child in decl:
            statements = []
            extra = gir_node["init"]
            modifiers = self.find_child_by_type(child, "modifiers")
            if modifiers:
                if "static" in self.read_node_text(modifiers).split():
                    extra = gir_node["static_init"]

            self.parse(child, statements)
            if statements:
                for stmt in statements:
                    if "variable_decl" in stmt:
                        gir_node["fields"].append(stmt)
                    elif "constant_decl" in stmt:
                        gir_node["fields"].append(stmt)
                    elif "field_decl" in stmt:
                        gir_node["fields"].append(stmt)
                    elif "property_decl" in stmt:
                        gir_node["fields"].append(stmt)
                    elif "assign_stmt" in stmt:
                        field = stmt["assign_stmt"]
                        extra.append({"field_write": {"receiver_object": self.global_this(),
                                                        "field": field["target"], "source": field["operand"]}})

        init = self.find_children_by_type(node, "block")
        if init:
            for child in init:
                if "static" in init:
                    self.parse(child, gir_node["static_init"])
                else:
                    self.parse(child, gir_node["init"])

        subtypes = ["constructor_declaration", "method_declaration", "destructor_declaration"]
        for st in subtypes:
            children = self.find_children_by_type(node, st)
            if not children:
                continue

            for child in children:
                self.parse(child, gir_node["member_methods"])

        subtypes = ["class_declaration", "interface_declaration", "enum_declaration", "record_declaration"]
        for st in subtypes:
            children = self.find_children_by_type(node, st)
            if not children:
                continue

            for child in children:
                self.parse(child, gir_node["nested"])
            return

    def attribute_list(self,node,statements):
        self.append_stmts(statements, node, self.read_node_text(node))


    def method_declaration(self, node, statements):

        child = self.find_child_by_type(node, "modifiers")
        modifiers = []
        for i in node.named_children:

            if i.type == "attribute_list":

                self.attribute_list(i,modifiers)
            if i.type == "modifier":
                self.attribute_list(i,modifiers)

        type_parameters =[]
        if self.find_child_by_field(node, "type_parameters"):
            child=  self.find_child_by_field(node, "type_parameters")
            type_parameters = self.read_node_text(child)[1:-1]

        child = self.find_child_by_field(node, "type")
        mytype = self.read_node_text(child)

        child = self.find_child_by_field(node, "name")
        name = self.read_node_text(child)

        new_parameters = []
        init = []
        child = self.find_child_by_field(node, "parameters")
        if child and child.named_child_count > 0:
            # need to deal with parameters

            self.parameter_list(child, init)
            if len(init) > 0:
                new_parameters.append(init.pop())

        variable_constraint = []
        for i in node.named_children:

            if i.type == "type_parameter_constraints_clause":
                self.type_parameter_constraints_clause(node,variable_constraint)
        new_body = []
        child = self.find_child_by_type(node, "block")
        if child:
            for stmt in child.named_children:
                if self.is_comment(stmt):
                    continue

                self.parse(stmt, new_body)
        self.append_stmts(statements, node,
            {"method_decl": {"attrs": modifiers, "data_type": mytype, "name": name, "type_parameters": type_parameters,
                             "parameters": new_parameters, "init": init, "body": new_body}})
        for i in variable_constraint:
            self.append_stmts(statements, node, i)

    def type_parameter_constraints_clause(self,node,statements):
        name = self.find_child_by_field(node,"target")
        attrs = self.find_child_by_field(node,"constraints")
        attr_text = self.read_node_text(attrs)
        self.append_stmts(statements, node, {"variable_decl":{"attrs":attr_text,"name":name}})

        # statements[name]=attr_text

    def parameter_list(self,node,statements):


        for child in node.named_children:
            if self.is_comment(child):
                continue
            value =''
            attrs =''
            data_type = ''
            param = child
            name = self.find_child_by_field(param,"name")
            name = self.read_node_text(name)
            for ch in param.children:
                if ch.type == 'attribute_list':
                    attrs= self.read_node_text(ch)
            if self.find_child_by_type(param,"predefined_type"):

                modifier = self.find_child_by_type(param,"predefined_type")
                data_type= self.read_node_text(modifier)
            if self.find_child_by_type(param,"equals_value_clause"):
                value_node = self.find_child_by_type(param,"equals_value_clause")
                value = self.read_node_text(value_node)[1:]

            self.append_stmts(statements, node, {"parameter_decl":{"attrs":attrs,"data_type":data_type, "name":name}})
            if value !='':
                self.append_stmts(statements, node, {"assign_stmt":{"data_type":data_type,"target":name,"operator":"=","operand":value}})


        # statements[name]=attr_text

    def namespace_declaration(self, node, statements):
        child = self.find_child_by_field(node, "name")
        name = self.read_node_text(child)

        new_body = []
        child = self.find_child_by_field(node, "body")
        if child:
            for decl in child.named_children:
                if self.is_comment(decl):
                    continue
                self.parse(decl, new_body)

        self.append_stmts(statements, node, {"namespace_decl": {"name": name, "body": new_body}})

    def struct_declaration(self, node, statements):

        child = self.find_child_by_type(node, "modifiers")
        modifiers = []
        for i in node.named_children:

            if i.type == "attribute_list":

                self.attribute_list(i,modifiers)
            if i.type == "modifier":
                self.attribute_list(i,modifiers)

        name = self.find_child_by_field(node, "name")
        name = self.read_node_text(name)

        field_body = []
        child = self.find_child_by_field(node, "body")
        if child:
            for decl in child.named_children:
                if self.is_comment(decl):
                    continue
                self.parse(decl, field_body)

        self.append_stmts(statements, node, {"struct_decl": {"attrs": modifiers, "name": name, "body": field_body}})

    def destructor_declaration(self, node, statements):
        attrs = []
        child = self.find_child_by_type(node, "attribute_list")
        attrs = self.read_node_text(child).strip('[]').split(',')
        attrs.append("protected")
        attrs.append("override")
        if '' not in attrs:
            attrs.extend(attrs)

        new_parameters = []
        init = []
        child = self.find_child_by_field(node, "parameters")
        if child and child.named_child_count > 0:
            # need to deal with parameters
            for p in child.named_children:
                if self.is_comment(p):
                    continue

                self.parse(p, init)
                if len(init) > 0:
                    new_parameters.append(init.pop())

        try_body = []
        child = node.children[-1]
        if child:
            for stmt in child.named_children:
                if self.is_comment(stmt):
                    continue

                self.parse(stmt, try_body)

        final_body = []
        tmp_var0 = self.tmp_variable()
        tmp_var1 = self.tmp_variable()
        final_body.append({"field_read": {"target": tmp_var0, "receiver_object": '@base', "field": tmp_var1 }})
        final_body.append({"call_stmt": {"target": tmp_var1, "name": 'Finalize', "args": ''}})

        body = []
        body.append({"try_stmt":{"body":try_body, "final_body": final_body}})

        self.append_stmts(statements, node, {"method_decl": {"attrs": attrs, "data_type": 'void', "name": 'Finalize', "parameters": '[]', "body": body}})



    def property_declaration(self, node, statements):
        modifier = self.find_children_by_type(node, "modifier")
        node_type = self.find_child_by_field(node, "type")
        name = self.find_child_by_field(node, "name")

        accessors = self.find_child_by_field(node, "accessors")
        if accessors:
            accessors = self.find_children_by_type(accessors, "accessor_declaration")
            for accessor in accessors:
                accessor_modifier = self.find_children_by_field(accessor, "modifier")
                accessor_name = self.find_child_by_field(accessor, "name")

        else:
            value = self.find_child_by_field(node, "value")

        return


    def check_statement_handler(self, node):
        STATEMENT_HANDLER_MAP = {
            "labeled_statement":            self.label_statement,
            "if_statement":                 self.if_statement,
            "while_statement":              self.while_statement,
            "for_statement":                self.for_statement,
            "for_each_statement":           self.each_statement,
            "goto_statement":               self.goto_statement,
            "do_statement":                 self.dowhile_statement,
            "break_statement":              self.break_statement,
            "continue_statement":           self.continue_statement,
            "return_statement":             self.return_statement,
            "yield_statement":              self.yield_statement,
            "throw_statement":              self.throw_statement,
            "try_statement":                self.try_statement,
            "using_statement":              self.using_statement,
            "yield_statement":              self.yield_statement,
            "switch_statement":             self.switch_statement,
            "empty_statement":              self.empty_statement,
            "checked_statement":            self.checked_statement,
        }
        return STATEMENT_HANDLER_MAP.get(node.type, None)

    def label_statement(self, node, statements):
        name = node.named_children[0]

        shadow_name = self.parse(name, statements)
        self.append_stmts(statements, node, {"label_stmt":{"name": shadow_name}})

        if node.named_child_count > 1:
            # 递归处理后续的statement部分
            stmt = node.named_children[1]
            self.parse(stmt, statements)

    def if_statement(self, node, statements):
        condition = self.find_child_by_field(node, "condition")
        consequence = self.find_child_by_field(node, "consequence")
        alternative = self.find_child_by_field(node, "alternative")

        true_body = []
        shadow_condition = self.parse(condition, statements)
        # 单独取出consequence部分的statement存入body中
        self.parse(consequence, true_body)
        if alternative:
            false_body = []
            # 取alternative部分的statement存入body中
            self.parse(alternative, false_body)
            self.append_stmts(statements, node, {"if_stmt": {"condition": shadow_condition, "then_body": true_body, "else_body": false_body}})
        else:
            self.append_stmts(statements, node, {"if_stmt": {"condition": shadow_condition, "then_body": true_body}})

    def while_statement(self, node, statements):
        condition = self.find_child_by_field(node, "condition")
        body = self.find_child_by_field(node, "body")

        condition_body = []
        shadow_condition = self.parse(condition, condition_body)

        while_body = []
        self.parse(body, while_body)
        # condition部分往往是一个assignment_statement，应该先加入statement中
        statements.extend(condition_body)

        self.append_stmts(statements, node, {"while_stmt": {"condition": shadow_condition, "body": while_body}})

    def for_statement(self, node, statements):
        initialization = self.find_child_by_field(node, "initializer")

        condition = self.find_child_by_field(node, "condition")
        update = self.find_child_by_field(node, "update")
        for_block = self.find_child_by_field(node, "body")

        init_body, condition_init, update_body, for_body = [], [], [], []

        # 赋值过程存入initialize_body中
        shadow_condition = self.parse(condition, condition_init)

        self.parse(initialization, init_body)

        # 多个更新参数
        self.parse(update, update_body)

        self.parse(for_block, for_body)

        self.append_stmts(statements, node, {"for_stmt":{"init":init_body,
                                        "condition": shadow_condition,
                                        "condition_body": condition_init,
                                        "step": update_body,
                                        "body": for_body}})

    def each_statement(self, node, statements):

        mytype = self.find_child_by_field(node, "type")
        shadow_type = self.read_node_text(mytype)

        value = self.find_child_by_field(node, "right")
        shadow_value = self.parse(value, statements)

        for_body = []

        name = self.find_child_by_field(node, "left")
        if name.named_child_count > 1:
            shadow_name = self.parse(name, statements)
        else:
            tuple_names = name.named_children
            tmp_var = self.tmp_variable()
            shadow_name = tmp_var
            shadow_index = 0
            for element in tuple_names:
                identifier = self.read_node_text(element)
                for_body.append({"array_read": {"target": identifier, "array": tmp_var, "index": shadow_index}})
                shadow_index += 1

        body = self.find_child_by_field(node, "body")
        self.parse(body, for_body)

        self.append_stmts(statements, node, {"forin_stmt":
                               {"data_type": shadow_type,
                                "name": shadow_name,
                                "receiver": shadow_value,
                                "body": for_body}})

    def goto_statement(self, node, statements):
        nodetext = self.read_node_text(node)
        if nodetext.find("case") >= 0:
            shadow_name = "case "
        elif nodetext.find("default") >= 0:
            shadow_name = "default"
        else:
            shadow_name = ""

        if node.named_child_count > 0:
            name = node.named_children[0]
            shadow_ret = self.parse(name, statements)
            shadow_name += shadow_ret

        self.append_stmts(statements, node, {"goto_stmt": {"name": shadow_name}})


    def yield_statement(self, node, statements):
        shadow_expr = ""
        if node.named_child_count > 0:
            expr = node.named_children[0]
            shadow_expr = self.parse(expr, statements)

        self.append_stmts(statements, node, {"yield_stmt": {"name": shadow_expr}})

    def using_statement(self, node, statements):
        using_body = self.find_child_by_field(node, "body")
        shadow_body = []
        self.parse(using_body, shadow_body)

        declare = self.find_children_by_type(node, "variable_declaration")
        argument = self.find_children_by_type(node, "_expression")
        for item in declare:
            argument.append(item)

        for child in argument:
            shadow_argument = []
            self.parse(child, shadow_argument)

        self.append_stmts(statements, node, {"using_stmt": {"target": shadow_argument,
                                          "body": shadow_body}})
        return


    def dowhile_statement(self,node,statements):
        condition = self.find_child_by_field(node,"condition")
        body = self.find_child_by_field(node,"body")
        shadow_body = []

        self.parse(body,shadow_body)


        shadow_condition = self.parse(condition,statements)
        self.append_stmts(statements, node, {"dowhile_stmt":{"condition":shadow_condition,
                                           "body":shadow_body
                                           }})


    def break_statement(self,node,statements):
        self.append_stmts(statements, node, {"break_stmt":{}})
        return

    def try_statement(self,node,statements):
        body = self.find_child_by_field(node,"body")
        shadow_body = []
        self.parse(body,shadow_body)
        self.append_stmts(statements, node, {"try_stmt":{"body":shadow_body}})
        for i in range(1,node.named_child_count):
            if node.named_children[i].type =="catch_clause":
                self.catch_clause(node.named_children[i],statements)
            else:
                # finally clause
                self.finally_clause(node,statements)

    def catch_clause(self,node,statements):
        body = self.find_child_by_field(node,"body")
        shadow_body = []
        shadow_except=""
        self.parse(body,shadow_body)
        # doesn't takke into account catch declaration
        if self.find_child_by_type(node,'catch_filter_clause'):
            exception = self.find_child_by_type(node,'catch_filter_clause')
            shadow_except =exception.find_child_by_type(node,'_expression')

        self.append_stmts(statements, node, {"catch_clause":{"exception":shadow_except,"body":shadow_body}})
        return

    def finally_clause(self,node,statements):
        body = self.find_child_by_type(node,"block")
        shadow_body = []
        self.parse(body,shadow_body)

        self.append_stmts(statements, node, {"final_stmt":{"body":shadow_body}})
        return

    def return_statement(self, node, statements):
        shadow_name = ""
        if node.named_child_count > 0:
            name = node.named_children[0]
            shadow_name = self.parse(name, statements)

        self.append_stmts(statements, node, {"return_stmt": {"name": shadow_name}})
        return shadow_name



    def continue_statement(self, node, statements):
        shadow_name = ""
        self.append_stmts(statements, node, {"continue_stmt": {"name": shadow_name}})



    def throw_statement(self, node, statements):
        shadow_expr = ""
        if node.named_child_count > 0:
            expr = node.named_children[0]
            shadow_expr = self.parse(expr, statements)
        self.append_stmts(statements, node, {"throw_stmt": {"name": shadow_expr}})

    def checked_statement(self,node,statements):
        body = node.named_children[0]
        shadow_body = []
        self.parse(body, shadow_body)

        nodetext = self.read_node_text(node.children[0])
        if nodetext == 'checked':
            self.append_stmts(statements, node, {'with_stmt':{"with_init":"checked","body":shadow_body}})
        else:
            self.append_stmts(statements, node, {'with_stmt':{"with_init":"unchecked","body":shadow_body}})

    def empty_statement(self,node,statements):
        return

    def switch_statement(self, node, statements):
        switch_ret = self.tmp_variable()

        condition = self.find_child_by_field(node, "value")
        switch_condition = self.parse(condition, statements)

        switch_stmt_list = []

        switch_block = self.find_child_by_field(node, "body")
        for child in switch_block.named_children:
            if self.is_comment(child):
                continue

            if self.read_node_text(child.children[0]) == "default:":
                new_body = []
                if child.named_child_count <= 1:
                    continue

                expression_block = child.named_children[1]
                shadow_return = self.parse(expression_block, new_body)

                switch_stmt_list.append({"default_stmt": {"body": new_body}})
            else:
                label = child.named_children[0]
                for case_condition in label.named_children:
                    if self.is_comment(case_condition):
                        continue

                    shadow_condition = self.parse(case_condition, statements)
                    if case_condition != label.named_children[-1]:
                        # if case_init != []:
                        #     statements.insert(-1, case_init)
                        switch_stmt_list.append({"case_stmt": {"condition": shadow_condition}})
                    else:
                        if child.named_child_count > 1:
                            new_body = []
                            for stat in child.named_children[1:]:
                                shadow_return = self.parse(stat, new_body)
                            # if case_init != []:
                            #     statements.insert(-1, case_init)

                            switch_stmt_list.append({"case_stmt": {"condition": shadow_condition, "body": new_body}})
                        else:
                            # if case_init != []:
                            #     statements.insert(-1, case_init)
                            switch_stmt_list.append({"case_stmt": {"condition": shadow_condition}})

        self.append_stmts(statements, node, {"switch_stmt": {"condition": switch_condition, "body": switch_stmt_list}})
        return switch_ret






    def is_statement(self, node):
        return self.check_statement_handler(node) is not None

    def statement(self, node, statements):
        handler = self.check_statement_handler(node)
        return handler(node, statements)

    def regular_number_literal(self, node, statements, replacement):
        value = self.read_node_text(node)
        value = self.common_eval(value)
        return str(value)

    def regular_literal(self, node, statements, replacement):
        return self.read_node_text(node)

    def character_literal(self, node, statements, replacement):
        value = self.read_node_text(node)
        return "'%s'" % value

    def this_literal(self, node, statements, replacement):
        return self.global_this()

    def base_literal(self, node, statements, replacement):
        return "@base"

    def string_literal(self, node, statements, replacement):
        replacement = []
        for child in node.named_children:
            self.parse(child, statements, replacement)

        ret = self.read_node_text(node)
        if replacement:
            for r in replacement:
                expr, value = r
                ret = ret.replace(expr, value)

        ret = self.handle_hex_string(ret)
        return self.escape_string(ret)

    def interpolation(self, node, statements, replacement):
        expr = node.named_children[0]
        shadow_expr = self.parse(expr, statements)
        replacement.append([self.read_node_text(expr), shadow_expr])
        return shadow_expr

    def obtain_literal_handler(self, node):
        LITERAL_MAP = {
            "null_literal"                      : self.regular_literal,
            "boolean_literal"                   : self.regular_literal,
            "character_literal"                 : self.character_literal,
            "integral_literal"                  : self.regular_number_literal,
            "integer_literal"                   : self.regular_number_literal,
            "real_literal"                      : self.regular_number_literal,
            "string_literal"                    : self.string_literal,
            "raw_string_literal"                : self.string_literal,
            "verbatim_string_literal"           : self.string_literal,
            "this_expression"                   : self.this_literal,
            "base_expression"                   : self.base_literal,
            "global"                            : self.regular_literal,
            "interpolated_string_expression"    : self.string_literal,
            "interpolation"                     : self.interpolation
        }
        return LITERAL_MAP.get(node.type, None)




    def check_expression_handler(self, node):
        EXPRESSION_HANDLER_MAP = {
            "assignment_expression"     : self.assignment_expression,
            "binary_expression"         : self.binary_expression,
            "lambda_expression"         : self.lambda_expression,
            "as_expression"             : self.as_expression,
            "throw_expression"          : self.throw_expression,
            "default_expression"        : self.default_expression,
            "switch_expression "     : self.switch_expression,
            "switch_expression_arm"     : self.switch_expression_arm,
            "parenthesized_expression"  : self.parenthesized_expression,
            "postfix_unary_expression"  : self.postfix_unary_expression,
            "prefix_unary_expression"   : self.prefix_unary_expression,
            "size_of_expression"        : self.size_of_expression,
            "type_of_expression"        : self.type_of_expression,
            "qualified_name"            : self.member_expression,
            "member_access_expression"  : self.member_expression,
            "with_expression"           : self.with_expression,
            "invocation_expression"     : self.invocation_expression,
            "cast_expression"           : self.cast_expression,
            "ref_expression"            : self.ref_expression,
            "conditional_expression"    : self.conditional_expression,
            "range_expression"          : self.range_expression,
            "element_access_expression" : self.element_access_expression,
            "is_pattern_expression"     : self.is_pattern_expression,
            "array_creation_expression" : self.new_array,
            "initializer_expression"    :self.initializer_expression,
            "object_creation_expression": self.object_creation_expression,
            "tuple_expression"          : self.tuple_expression,
        }
        return EXPRESSION_HANDLER_MAP.get(node.type, None)

    def tuple_expression(self, node, statements):
            tmp_var = self.tmp_variable()
            for argument in node.name_children:
                name = self.find_child_by_field(argument, "name")
                shadow_index = 0
                for element in tuple_names:
                    self.append_stmts(statements, node, {"array_read": {"target": name, "array": tmp_var, "index": shadow_index}})
                    shadow_index += 1

            return tmp_var

    def assignment_expression(self, node, statements):
        left = self.find_child_by_field(node, "left")
        right = self.find_child_by_field(node, "right")
        operator = node.named_children[1]
        '''if tmp_operator != '=':
            operator = node.named_children[1] + node.named_children[2]
        else:
            operator = node.named_children[1]'''
        # operator = self.find_child_by_type(assignment_operator)
        shadow_operator = self.read_node_text(operator).replace("=", "")

        shadow_right = self.parse(right, statements)
        if left.type == "member_access_expression":
            shadow_object, field = self.member_access(left, statements)
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

        if left.type == "element_access_expression":
            shadow_array, shadow_index = self.parse_array(left, statements)

            if not shadow_operator:
                self.append_stmts(statements, node,
                    {"array_write": {"array": shadow_array, "index": shadow_index, "source": shadow_right}})
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


    def lambda_expression(self, node, statements):
        tmp_func = self.tmp_method()

        parameters = []
        # tmp_body = []
        child = self.find_child_by_field(node, "parameters")
        # if child.named_child_count == 0:
        for param in child.named_children:
            parameters.append({"parameter_decl": {"name": self.read_node_text(param)}})
        '''else:
            for p in child.named_children:
                if self.is_comment(p):
                    continue

                self.parse(p, tmp_body)
                if len(tmp_body) > 0:
                    parameters.append(tmp_body.pop())'''

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

    def as_expression(self, node, statements):
        left = self.find_child_by_field(node, "left")
        right = self.find_child_by_field(node, "right")
        operator = self.find_child_by_field(node, "operator")

        shadow_left = self.parse(left, statements)
        shadow_right = self.parse(right, statements)

        tmp_var = self.tmp_variable()
        self.append_stmts(statements, node, {"assign_stmt": {"target": tmp_var, "operator": "as", "operand": shadow_left, "operand2": shadow_right}})

        return tmp_var

    def element_access_expression(self, node, statements):
        tmp_var = self.tmp_variable()
        shadow_array, shadow_index = self.parse_array(node, statements)
        self.append_stmts(statements, node, {"array_read": {"target": tmp_var, "array": shadow_array, "index": shadow_index}})
        return tmp_var

    def parse_array(self, node, statements):
        array = self.find_child_by_field(node, "expression")
        subscript = self.find_child_by_field(node, "subscript")
        index = self.find_child_by_type(subscript, "argument")
        shadow_array = self.parse(array, statements)
        shadow_index = self.parse(index, statements)
        return (shadow_array, shadow_index)

    # def element_binding_expression(self, node, statements):
    #    tmp_var = self.tmp_variable()
    #    subscript = self.find_child_by_type(bracketed_argument_list)
    #    argument = self.find_child_by_type(subscript, "argument")
    #    shadow_argument = self.parse(argument, statements)


    def throw_expression(self, node, statements):
        shadow_expr = ""
        if node.named_child_count > 0:
            expr = node.named_children[0]
            shadow_expr = self.parse(expr, statements)
        self.append_stmts(statements, node, {"assign_stmt": {"target": shadow_expr}})

    def size_of_expression(self, node, statements):
        typenode = self.find_child_by_field(node, "type")
        type = self.read_node_text(typenode)
        tmp_var = self.tmp_variable()
        self.append_stmts(statements, node, {"assign_stmt": {"target": tmp_var, "operator": "size_of",
        "operand": type}})
        return tmp_var

    def type_of_expression(self, node, statements):
        typenode = self.find_child_by_field(node, "type")
        type = self.read_node_text(typenode)
        tmp_var = self.tmp_variable()
        self.append_stmts(statements, node, {"assign_stmt": {"target": tmp_var, "operator": "type_of",
        "operand": type}})
        return tmp_var

    def member_access(self, node, statements):
        children = node.named_children
        myobject = children[0]
        shadow_object = self.parse(myobject, statements)
        field = children[1]
        shadow_field = self.read_node_text(field)
        return (shadow_object, shadow_field)

    def member_expression(self, node, statements):
        tmp_var = self.tmp_variable()
        shadow_object, shadow_field = self.member_access(node, statements)
        self.append_stmts(statements, node, {"field_read": {"target": tmp_var, "receiver_object": shadow_object, "field": shadow_field}})
        return tmp_var

    def with_expression(self, node, statements):
        object = node.named_children[0]
        shadow_object = self.parse(object, statements)
        tmp_var = self.tmp_variable()
        self.append_stmts(statements, node, {"assign_stmt": {"target": tmp_var, "operand": shadow_object}})
        if node.named_child_count > 1:
            for child in node.named_children[1].named_children:
                field = self.read_node_text(child.named_children[0])
                value = self.parse(child.named_children[1], statements)
                self.append_stmts(statements, node, {"field_write": {"receiver_object": tmp_var, "field": field, "source": value}})
        return tmp_var

    def invocation_expression(self, node, statements):
        function = self.find_child_by_field(node, "function")
        shadow_name = self.parse(function, statements)

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
        self.append_stmts(statements, node, {"call_stmt": {"target": tmp_return, "name": shadow_name, "args": args_list}})

        return tmp_return

    def new_array(self, node, statements):
        mytype = self.find_child_by_field(node, "type")
        shadow_type = self.read_node_text(mytype)

        tmp_var = self.tmp_variable()
        self.append_stmts(statements, node, {"new_array": {"type": shadow_type, "target": tmp_var}})

        if node.named_child_count > 1:
            value = node.named_children[1]
            if value.named_child_count > 0:
                index = 0
                for child in value.named_children:
                    if self.is_comment(child):
                        continue

                    shadow_child = self.parse(child, statements)
                    self.append_stmts(statements, node, {"array_write": {"array": tmp_var, "index": str(index), "source": shadow_child}})
                    index += 1

        return tmp_var

    def conditional_expression(self, node, statements):
        condition = self.find_child_by_field(node, "condition")
        consequence = self.find_child_by_field(node, "consequence")
        alternative = self.find_child_by_field(node, "alternative")
        condition = self.parse(condition, statements)

        body = []
        elsebody = []
        tmp_var = self.tmp_variable()

        expr1 = self.parse(consequence, body)
        body.append({"assign_stmt": {"target": tmp_var, "operand": expr1}})

        expr2 = self.parse(alternative, elsebody)
        body.append({"assign_stmt": {"target": tmp_var, "operand": expr2}})

        self.append_stmts(statements, node, {"if": {"condition": condition, "body": body, "elsebody": elsebody}})
        return tmp_var

    def prefix_unary_expression(self, node, statements):
        shadow_node = self.read_node_text(node)
        tmp_var = self.tmp_variable()
        shadow_expression = self.parse(node.named_children[0], statements)
        if shadow_node[0] == '+' and shadow_node[1] == '+':
            shadow_operator = '+'
            self.append_stmts(statements, node, {"assign_stmt": {"target": tmp_var, "operand": shadow_expression}})
            self.append_stmts(statements, node, {"assign_stmt": {"target": shadow_expression, "operator": shadow_operator, "operand": shadow_expression, "operand2": "1"}})
        elif shadow_node[0] == '-' and shadow_node[1] == '-':
            shadow_operator = '-'
            self.append_stmts(statements, node, {"assign_stmt": {"target": tmp_var, "operand": shadow_expression}})
            self.append_stmts(statements, node, {"assign_stmt": {"target": shadow_expression, "operator": shadow_operator, "operand": shadow_expression, "operand2": "1"}})
        else:
            operator = shadow_node[0]
            shadow_operator = operator
            operand = shadow_node[1]
            self.append_stmts(statements, node, {"assign_stmt": {"target": tmp_var, "operator": shadow_operator, "operand": shadow_expression}})
        return tmp_var

    def postfix_unary_expression(self, node, statements):
        shadow_node = self.read_node_text(node)

        operator = ""
        # 末个为+，则为两个加号，否则为两个减号
        if "+" == shadow_node[-1]:
            operator = "+"
        elif "-" == shadow_node[-1]:
            operator = "-"

        tmp_var = self.tmp_variable()

        expression = node.named_children[0]
        # 若is_after为false，则expression分割后的部分为需要的部分
        shadow_expression = self.parse(expression, statements)

        self.append_stmts(statements, node, {"assign_stmt": {"target": tmp_var, "operand": shadow_expression}})
        self.append_stmts(statements, node, {"assign_stmt": {"target": shadow_expression, "operator": operator, "operand": shadow_expression, "operand2": "1"}})

        return tmp_var

    def default_expression(self,node,statements):
        variable= self.tmp_variable()
        default_type = node.find_child_by_field(node,'type')
        self.append_stmts(statements, node, {"call_stmt":{"tuple":variable,"name":"default","data_type":default_type}})

    def parenthesized_expression(self,node,statements):
        variable = self.tmp_variable()
        shadow_expr=''
        expr = node.named_children[0]
        shadow_expr = self.parse(expr,statements)

        self.append_stmts(statements, node, {"assign_stmt":{
            "target": variable, "operand": shadow_expr
        }})
        return variable

    def cast_expression(self, node, statements):
        value = self.find_child_by_field(node, "value")
        shadow_value = self.parse(value, statements)

        types = self.find_children_by_field(node, "type")
        for t in types:
            self.append_stmts(statements, node,
                {"assign_stmt": {
                    "target": shadow_value, "operator":"cast", "oprand": self.read_node_text(t)
                }}
            )
        return shadow_value

    def switch_expression(self,node,statements):

        switch_ret =self.tmp_variable()

        condition_element = node.named_children[0]
        switch_stmt_list = []
        for i in range(1,len(node.named_children)):
            if self.is_comment(node.named_children[i]):
                continue
            else:
                buffer= node.name_children[i]
                value=[]
                value.append( self.switch_expression_arm(buffer,statements))
        self.append_stmts(statements, node, {"switch_stmt": {"condition": condition_element, "body": value}})
        return switch_ret

    def switch_expression_arm(self,node,statements):
        tmp_var = self.tmp_variable()
        # not completed because clause is yet to be adopted
        # clause = self.find_child_by_type(buffer,"when_clause")
        # if clause is not None:
        #     self.parse(buffer,statement)
        expr = node.named_children[1]
        pattern = self.find_child_by_type(node, "_pattern")
        shadow_expr= self.parse(expr,statements)
        shadow_pattern = self.pattern(node.named_children[0],statements)
        self.append_stmts(statements, node, {"assign_stmt": {"target": tmp_var, "operator": "=>",\
            "operand":shadow_pattern,\
            "operand2":shadow_expr}})
        return tmp_var


    def pattern(self,node,statements):

        tmp_var = self.tmp_variable()
        if node.type == "constant_pattern":
            res = self.parse(node.named_children[0],statements)
            return res
        if node.type == "type_pattern":
            res =self.read_node_text(node.named_children[0])
            return res
        if node.type == "and_pattern" or node.type == "or_pattern":
            left = self.find_child_by_field(node,'left')
            operator= node.children[1]
            right= self.find_child_by_field(node,'right')
            tmp_var = self.tmp_variable()

            shadow_left = self.pattern(left,statements)
            shadow_right=  self.pattern(right,statements)
            self.append_stmts(statements, node, {"assign_stmt": {"target": tmp_var, "operator": self.read_node_text(operator), "operand": shadow_left,
                                           "operand2": shadow_right}})
            return tmp_var

    def is_pattern_expression(self,node,statements):
        tmp_var =self.tmp_variable()
        expr = self.find_child_by_field(node,'expression')
        patt = self.find_child_by_field(node,'pattern')
        shadow_expr = self.parse(expr,statements)
        shadow_patt = self.pattern(patt.named_children[0],statements)
        self.append_stmts(statements, node, {"assign_stmt": {"target": tmp_var, "operator": "is_pattern", "operand": shadow_expr,
                                           "operand2": shadow_patt}})
        return tmp_var


    def ref_expression(self,node,statements):
        tmp_var = self.tmp_variable()
        expr = self.find_child_by_type(node,"_expression")
        out_expr = self.parse(expr, statements)
        self.append_stmts(statements, node, {"variable_decl": {"attrs": ["ref"], "data": out_expr}})

    def range_expression(self,node,statements):
        tmp_var= self.tmp_variable()
        if node.child_count ==3:
            min_node = node.children[0]
            min = self.parse(min_node,statements)
            max_node = node.children[2]
            max= self.parse(max_node,statements)
            self.append_stmts(statements, node, {"assign_stmt": {"target": tmp_var, "operator": "..", "operand": min,
                                           "operand2": max}})
            return
        if  node.child_count ==2 and self.read_node_text(node.children[0])=='..':
            min = -float('inf')
            max_node = node.children[2]
            max= self.parse(max_node,statements)
            self.append_stmts(statements, node, {"assign_stmt": {"target": tmp_var, "operator": "..", "operand": min,
                                           "operand2": max}})
            return
        if node.child_count ==2 and self.read_node_text(node.children[1])=='..':
            min_node = node.children[0]
            min = self.parse(min_node,statements)
            max= float('inf')
            self.append_stmts(statements, node, {"assign_stmt": {"target": tmp_var, "operator": "..", "operand": min,
                                           "operand2": max}})
            return
        else:
            min = -float('inf')
            max = float('inf')
            self.append_stmts(statements, node, {"assign_stmt": {"target": tmp_var, "operator": "..", "operand": min,
                                           "operand2": max}})

            return


    def object_creation_expression(self,node,statements):
        type = self.find_child_by_field(node,'type')
        type_out = self.read_node_text(type)
        arguments = self.find_child_by_field(node,'arguments')
        initializer = self.find_child_by_field(node,'initializer')
        arguments_out=[]
        gir_node= {}
        gir_node["data_type"] =type_out
        gir_node["init"]= ""
        tmp_var = self.tmp_variable()
        if arguments is not None and arguments.named_child_count>0:
            for i in arguments.named_children:

                arguments_out.append(self.argument(i,statements))
        gir_node["args"]= arguments_out
        if initializer is not None :
            initializer_return = self.parse(initializer,statements)
            gir_node["init"]= initializer_return
        gir_node["target"]=tmp_var
        self.append_stmts(statements, node, {"new_object":gir_node})
        return tmp_var
    def argument(self,node,statements):
        name = self.find_child_by_field(node,'name')
        if name and node.child_count==3:
            operator = node.children[1]
            expression = node.children[2]
            expression_out = self.parse(expression,statements)
            tmp_var = self.tmp_variable()
            self.append_stmts(statements, node, {"assign_stmt": {"target": tmp_var, "operator": operator, "operand": name,
                                            "operand2": expression}})
            return tmp_var
        if node.child_count==1:
            expression = node.children[0]
            expression_out = self.parse(expression,statements)
            return expression_out

    def initializer_expression(self,node,statements):
        storage =[]
        for i in node.named_children:
            storage.append(self.parse(i,statements))
        return storage
