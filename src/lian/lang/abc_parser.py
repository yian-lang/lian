#!/usr/bin/env python3
from ast import arguments
import sys, os

from lian.config import config
from lian.lang import common_parser
from lian.config.constants import ABC_INTERNAL as AnalyzerInternal
from lian.config.constants import LIAN_INTERNAL
from lian.util import util


class Parser(common_parser.Parser):

    def init(self):
        self.original_name_to_tmp_name = {}
        self.current_func = None
        self.ananymous_func_to_scope = {}
        self.DECLARATION_HANDLER_MAP = {
            "function_declaration": self.function_declaration,
            # "variable_declaration"          : self.variable_declaration
        }

        self.STATEMENT_HANDLER_MAP = {
            "assignment_statement": self.assignment_statement,
            "sta_statement": self.sta_statement,
            "lda_statement": self.lda_statement,
            "ldastr_statement": self.ldastr_statement,
            "ldundefiened_statement": self.ldconst_statement,
            "ldnull_statement": self.ldconst_statement,
            "ldtrue_statement": self.ldconst_statement,
            "ldfalse_statement": self.ldconst_statement,
            "ldhole_statement": self.ldconst_statement,
            "ldlexvar_statement": self.ldlexvar_statement,
            "ldlocalmodulevar_statement": self.ldlocalmodulevar_statement,
            "ldai_statement": self.ldai_statement,
            "fldai_statement": self.ldai_statement,
            "ldobjbyname_statement": self.ldobjbyname_statement,
            "ldobjbyvalue_statement": self.ldobjbyvalue_statement,
            "ldexternalmodulevar_statement": self.ldexternalmodulevar_statement,
            "ldsuperbyname_statement": self.ldsuperbyname_statement,
            "ldglobal_statement": self.ldglobal_statement,
            "call_statement": self.call_statement,
            "callthis0_statement": self.call_statement,
            "callthis1_statement": self.call_statement,
            "callthis2_statement": self.call_statement,
            "callthis3_statement": self.call_statement,
            "callthisrange_statement": self.callrange_statement,
            "callrange_statement": self.callrange_statement,
            "supercallthisrange_statement": self.callrange_statement,
            "callarg0_statement": self.call_statement,
            "callarg1_statement": self.call_statement,
            "callargs2_statement": self.call_statement,
            "callargs3_statement": self.call_statement,
            'callruntime_statement': self.call_statement,
            "getiterator_statement": self.getiterator_statement,
            "definefunc_statement": self.definefunc_statement,
            "definemethod_statement": self.definemethod_statement,
            "definefieldbyname_statement": self.definefieldbyname_statement,
            "definefieldbyvalue_statement": self.definefieldbyvalue_statement,
            "defineclass_statement": self.defineclass_statement,
            "mov_statement": self.mov_statement,
            "tryldglobalbyname_statement": self.tryldglobalbyname_statement,
            "stlexvar_statement": self.stlexvar_statement,
            "stmodulevar_statement": self.stmodulevar_statement,
            "stownbyindex_statement": self.stownbyindex_statement,
            "stownbyname_statement": self.stownbyname_statement,
            "stobjbyname_statement": self.stobjbyname_statement,
            "stobjbyvalue_statement": self.stobjbyvalue_statement,
            "ifhole_statement": self.ifhole_statement,
            "returnundefined_statement": self.returnundefined_statement,
            "return_statement": self.return_statement,
            "new_array_statement": self.new_array_statement,
            "newobjrange_statement": self.newobjrange_statement,
            "newenv_statement": self.newenv_statement,
            "poplexenv_statement": self.poplexenv_statement,
            "add_statement": self.add_statement,
            "sub_statement": self.sub_statement,
            "dec_statement": self.dec_statement,
            "mul_statement": self.mul_statement,
            "div_statement": self.div_statement,
            "mod_statement": self.mod_statement,
            "eq_statement": self.eq_statement,
            "noteq_statement": self.noteq_statement,
            "less_statement": self.less_statement,
            "lesseq_statement": self.lesseq_statement,
            "greater_statement": self.greater_statement,
            "greatereq_statement": self.greatereq_statement,
            "and_statement": self.and_statement,
            "or_statement": self.or_statement,
            "xor_statement": self.xor_statement,
            "tonumeric_statement": self.tonumeric_statement,
            "condition_statement": self.condition_statement,
            "strictnoteq_statement": self.strictnoteq_statement,
            "stricteq_statement": self.stricteq_statement,
            "inc_statement": self.inc_statement,
            "dec_statement": self.dec_statement,
            "while_statement": self.while_statement,
            "copyrestargs_statement": self.copyrestargs_statement,
            "supercallspread_statement": self.supercallspread_statement,
            "throwcallwrong_statement": self.throw_statement,
            "throwifnotobject_statement": self.throw_statement,
            "throw_statement": self.throw_statement,
            "neg_statement": self.neg_statement,
            "nor_statement": self.nor_statement,
            "asyncfunctionenter_statement": self.asyncfunctionenter_statement,
            "asyncfunctionawaituncaught_statement": self.asyncfunctionawaituncaught_statement,
            "asyncfunctionreject_statement": self.asyncfunctionreject_statement,
            "asyncfunctionresolve_statement": self.asyncfunctionresolve_statement,
            "suspendgenerator_statement": self.suspendgenerator_statement,
            "resumegenerator_statement": self.resumegenerator_statement,
            "getresumemode_statement": self.getresumemode_statement,
            "createemptyarray_statement": self.createemptyarray_statement,
            "createobjectwithbuffer_statement": self.createobjectwithbuffer_statement,
            "createemptyobject_statement": self.createemptyobject_statement,
            "isin_statement": self.isin_statement,
            "jeqz_statement": self.jmp_statement,
            "jnez_statement": self.jmp_statement,
            "jmp_statement": self.jmp_statement,
            "getmodulenamespace_statement": self.getmodulenamespace_statement,
            "module_literal": self.module_literal,
            "scope_literal": self.scope_literal,
            "module_record": self.module_record,
            "checkholebyname_statement": self.checkholebyname_statement,
            "label_statement": self.label_statement,
            "instanceof_statement": self.instanceof_statement,
            "catch_statement": self.catch_statement,
            "comment": self.comment_statement,
            "isfalse_statement": self.isfalse_statement,
            "istrue_statement": self.istrue_statement,
            "typeof_statement": self.typeof_statement,
            "definegettersetter_statement": self.definegettersetter_statement,
            "dynamic_import": self.dynamicimport_statement,
            "ERROR": self.error_statement,
        }

        self.EXPRESSION_HANDLER_MAP = {
            "expression": self.expression_wrapper,
            "identifier": self.identifier_expression,
            "parenthesized_lvalue": self.parenthesized_lvalue_expression,
        }

    def check_expression_handler(self, node):
        return self.EXPRESSION_HANDLER_MAP.get(node.type, None)

    def check_declaration_handler(self, node):
        return self.DECLARATION_HANDLER_MAP.get(node.type, None)

    def check_statement_handler(self, node):
        return self.STATEMENT_HANDLER_MAP.get(node.type, None)

    def function_declaration(self, node, statements):
        header_node = self.find_child_by_type(node, "function_header")
        header_info = self.function_header(header_node)
        if header_info is None:
            header_info = "unknown"
        body_statements = []
        body_node = self.find_child_by_type(node, "function_body")

        body_statements = self.function_body(body_node)
        body_statements.insert(0, {
            "variable_decl": {
                "name": "tmp"
            }
        })
        body_statements.insert(0, {
            "variable_decl": {
                "name": "acc"
            }
        })
        self.append_stmts(statements, node, {
            "method_decl": {
                **header_info,
                "body": body_statements
            }
        })

        return

    def function_header(self, node):
        # self.print_tree(node)
        name_node = self.find_child_by_type(node, "function_name_type1")
        if name_node is None:
            return
        path_node = self.find_child_by_field(name_node, "file_path")
        total_name_node = self.find_child_by_field(name_node, "name")
        scope_name = []
        if total_name_node.type == "identifier":
            function_name = self.read_node_text(total_name_node)
        else:
            scope_node = self.find_child_by_field(total_name_node, "scope_name")
            scope_text = self.read_node_text(scope_node)
            # print(scope_text)
            if scope_text != '*':
                for child in scope_node.named_children:
                    if child.type == "scope_type":
                        continue
                    repeat_node = self.find_child_by_field(child, "repeat_index")
                    repeat_index = ""
                    if repeat_node:
                        repeat_index = '^' + self.read_node_text(repeat_node)

                    type_node = self.find_child_by_type(child, "scope_type")
                    type = self.read_node_text(type_node)

                    if self.find_child_by_type(child, "scope_id") or self.find_child_by_type(child, "identifier"):
                        # if child.type == "scope_name" and not self.find_child_by_field(child, "repeat_index") and :
                        if len(child.named_children) < 2:
                            continue
                        name_node = child.named_children[1]
                        if name_node.type == "identifier":
                            longname = 0
                            name = self.read_node_text(name_node)
                        else:
                            longname = 1
                            name = self.read_node_text(name_node)[1:]
                        scope_name.append({"type": type, "name": name + repeat_index, "longname": longname})
                    else:
                        name = AnalyzerInternal.ANONYMOUS + repeat_index
                        scope_name.append({"type": type, "name": name, "longname": 0})

            function_name_node = self.find_child_by_field(total_name_node, "function_name")
            repeat_node = self.find_child_by_field(total_name_node, "repeat_index")
            repeat_index = ""
            if repeat_node:
                repeat_index = '^' + self.read_node_text(repeat_node)
            # print(self.read_node_text(repeat_node))
            if function_name_node:
                function_name = self.read_node_text(function_name_node) + repeat_index
            else:

                total_name = self.read_node_text(total_name_node)
                function_name = total_name

                if total_name in self.original_name_to_tmp_name:
                    function_name = self.original_name_to_tmp_name[total_name]
        self.current_func = function_name
        file_path = self.read_node_text(path_node)

        parameters = []
        params_node = self.find_child_by_field(node, "parameters")
        explicit_params_node = params_node.named_children[3:]
        if explicit_params_node:
            for param_node in explicit_params_node:
                param_info = self.parameter(param_node)
                parameters.append(param_info)

        # return_type_node = self.find_child_by_field(node, "return_type")
        # if return_type_node:
        #     return_type = self.type_expression(return_type_node)
        # else:
        #     return_type = None
        # print(function_name)
        return {
            # "data_type": return_type,
            "path": file_path,
            "name": function_name,
            "scope_name": scope_name,
            "parameters": parameters,
        }

    #                 、
    def definefunc_statement(self, node, statements):
        # self.print_tree(node)
        # print(node.start_point)

        decl_node = self.find_child_by_type(node, "method_decl")
        func_name_node = self.find_child_by_type(decl_node, "function_name_type1")
        name_node = self.find_child_by_field(func_name_node, "name")
        func_name = self.find_child_by_field(name_node, "function_name")
        name = self.read_node_text(name_node)
        # print(name)
        if func_name:
            name = self.read_node_text(func_name)
        #
        if not self.find_child_by_field(name_node, "function_name"):
            name = self.tmp_method()
            # repeat_id = ""
            # repeat_node = self.find_child_by_field(name_node, "repeat_index")
            # if repeat_node:
            #     repeat_id = self.read_node_text(repeat_node)
            # name += repeat_id
        # print(name)
        self.ananymous_func_to_scope[name] = self.current_func

        self.original_name_to_tmp_name[self.read_node_text(name_node)] = name
        self.append_stmts(statements, node, {
            "assign_stmt": {
                "target": "acc",
                "operand": name
            }
        })

    def function_body(self, node):
        body_statements = []
        for child in node.named_children:
            # if self.is_declaration(child):
            #     self.declaration(child, body_statements)
            # if self.is_statement(child):
            self.statement(child, body_statements)

        return body_statements

    def parameter(self, node):

        name_node = self.find_child_by_field(node, "name")
        param_name = self.read_node_text(name_node)
        type_node = self.find_child_by_field(node, "type")
        param_type = self.type_expression(type_node)

        return {
            "parameter_decl": {
                "data_type": param_type,
                "name": param_name,
            }
        }

    def type_expression(self, node):
        if node.type == "primitive_type":
            return self.read_node_text(node)
        elif node.type == "tuple_type":
            elements = [self.type_expression(child) for child in node.named_children]
            return f"({', '.join(elements)})"
        else:
            return self.read_node_text(node)

    def assignment_statement(self, node, statements):
        left_node = self.find_child_by_field(node, "left")
        right_node = self.find_child_by_field(node, "right")

        left_expr = self.lvalue(left_node, statements) if left_node else None

        if right_node:
            right_expr = self.expression(right_node, statements)
        else:
            right_expr = None

        self.append_stmts(statements, node, {
            "assign_stmt": {
                "target": left_expr,
                "operand": right_expr
            }
        })

    def return_statement(self, node, statements):
        value_node = self.find_child_by_field(node, "value")
        value = self.expression(value_node, statements) if value_node else None

        self.append_stmts(statements, node, {
            "return_stmt": {
                "name": value
            }
        })

    def call_statement(self, node, statements):
        call_type = node.type

        if call_type in ["callthis1_statement", "callthis2_statement", "callthis3_statement"]:
            arguments_nodes = node.named_children[2:]
        elif call_type in ["callarg1_statement", "callargs2_statement", "callargs3_statement"]:
            arguments_nodes = node.named_children[1:]
        else:
            arguments_nodes = []
        arguments = []
        for arg_node in arguments_nodes:
            arguments.append(self.read_node_text(arg_node))

        self.append_stmts(statements, node, {
            "call_stmt": {
                "target": "acc",
                "name": "acc",
                "positional_args": arguments
            }
        })

    def callrange_statement(self, node, statements):
        arguments = []
        this = ""
        if node.type in ["callthisrange_statement", "callrange_statement", "supercallthisrange_statement"]:
            range_node = self.find_child_by_field(node, "args_number")
            arg_range = self.read_node_text(range_node)

            this_node = self.find_child_by_field(node, "arg_start")
            this = self.read_node_text(this_node)
            arg_start_id = self.var_to_argid(this) + 1

            for i in range(arg_start_id, arg_start_id + int(arg_range, 16)):
                arguments.append(self.argid_to_var(i))

            self.append_stmts(statements, node, {
                "call_stmt": {
                    "target": "acc",
                    "name": "acc",
                    "positional_args": arguments
                }
            })
        # elif node.type == "supercallthisrange_statement":

        #     self.append_stmts(statements, node, {
        #         "assign_stmt": {
        #             "operand":AnalyzerInternal.THIS,
        #             "target":this
        #         }
        #     })

    def getiterator_statement(self, node, statements):
        self.append_stmts(statements, node, {
            "call_stmt": {
                "target": "acc",
                "name": "getiterator",
                "positional_args": ["acc"]
            }
        })

    def argid_to_var(self, argid):
        return f"v{argid}"

    def var_to_argid(self, var):
        return int(var[1:])

    def sta_statement(self, node, statements):
        register_node = self.find_child_by_field(node, "register")
        register_name = self.read_node_text(register_node)
        self.append_stmts(statements, node, {
            "variable_decl": {
                "name": register_name,
            }
        })
        self.append_stmts(statements, node, {
            "assign_stmt": {
                "operand": "acc",
                "target": register_name
            }
        })

    def lda_statement(self, node, statements):
        register_node = self.find_child_by_field(node, "register")
        register_name = self.read_node_text(register_node)
        self.append_stmts(statements, node, {
            "variable_decl": {
                "name": register_name,
            }
        })
        self.append_stmts(statements, node, {
            "assign_stmt": {
                "operand": register_name,
                "target": "acc"
            }
        })

    def ldastr_statement(self, node, statements):
        string_node = node.named_children[0]
        string = self.read_node_text(string_node)
        if '@normalized:N&&&' in string:
            string = (string
                      .replace('@normalized:N&&&', '')
                      .replace('&', '')
                      .replace('/', '.')
                      .replace('"', ''))
            self.append_stmts(statements, node, {
                "assign_stmt": {
                    "operand": string,
                    "target": "acc"
                }
            })
        else:
            self.append_stmts(statements, node, {
                "assign_stmt": {
                    "operand": f'"{string}"',
                    "target": "acc"
                }
            })

    def ldai_statement(self, node, statements):
        imm_node = self.find_child_by_field(node, "imm")
        imm = self.read_node_text(imm_node)
        imm = str(util.hex_to_decimal(imm))
        self.append_stmts(statements, node, {
            "assign_stmt": {
                "operand": imm,
                "target": "acc"
            }
        })

    def mov_statement(self, node, statements):
        v1_node = self.find_child_by_field(node, "v1")
        v2_node = self.find_child_by_field(node, "v2")
        v1_name = self.read_node_text(v1_node)
        v2_name = self.read_node_text(v2_node)
        if v2_name == "a2":
            v2_name = AnalyzerInternal.THIS
        self.append_stmts(statements, node, {
            "variable_decl": {
                "name": v1_name,
            }
        })
        self.append_stmts(statements, node, {
            "assign_stmt": {
                "operand": v2_name,
                "target": v1_name
            }
        })

    def tryldglobalbyname_statement(self, node, statements):
        object_field = self.find_child_by_field(node, "object")
        object_name = self.read_node_text(object_field)

        self.append_stmts(statements, node, {
            "field_read": {
                "receiver_object": "os",
                "field": object_name,
                "target": "acc"
            }
        })

    def ldlexvar_statement(self, node, statements):
        lexi_env_node = self.find_child_by_field(node, "lexi_env")
        slot_node = self.find_child_by_field(node, "slot")
        lexi_env = self.read_node_text(lexi_env_node)
        lexi_env_deci = int(lexi_env, 16)
        slot = self.read_node_text(slot_node)
        slot_deci = int(slot, 16)

        # self.append_stmts(statements, node, {
        #     "ldlexvar":{
        #         "lex_env_id":str(lexi_env_deci),
        #         "index":str(slot_deci),
        #     }
        # })

        self.append_stmts(statements, node, {
            "ldlexvar": {
                "lex_env_id": str(lexi_env_deci),
                "index": str(slot_deci),
            }
        })

    def ldlocalmodulevar_statement(self, node, statements):
        pass

    def stlexvar_statement(self, node, statements):
        lexi_env_node = self.find_child_by_field(node, "lexi_env")
        slot_node = self.find_child_by_field(node, "slot")
        lexi_env = self.read_node_text(lexi_env_node)
        lexi_env_deci = int(lexi_env, 16)
        slot = self.read_node_text(slot_node)
        slot_deci = int(slot, 16)

        self.append_stmts(statements, node, {
            "stlexvar": {
                "lex_env_id": str(lexi_env_deci),
                "index": str(slot_deci),
            }
        })

    def stmodulevar_statement(self, node, statements):
        pass

    def stownbyindex_statement(self, node, statements):
        object_node = self.find_child_by_field(node, "object")
        field_node = self.find_child_by_field(node, "index")
        object_name = self.read_node_text(object_node)
        field_name = self.read_node_text(field_node)
        self.append_stmts(statements, node, {
            "field_write": {
                "source": "acc",
                "receiver_object": object_name,
                "field": field_name,
            }
        })

    #   acc                B            A                    。
    def stownbyname_statement(self, node, statements):
        object_node = self.find_child_by_field(node, "object")
        field_node = self.find_child_by_field(node, "name")
        object_name = self.read_node_text(object_node)
        field_name = self.read_node_text(field_node)
        self.append_stmts(statements, node, {
            "record_write": {
                "value": "acc",
                "receiver_record": object_name,
                "key": field_name,
            }
        })

    #   acc                B            A                    。
    def stobjbyname_statement(self, node, statements):
        object_node = self.find_child_by_field(node, "object")
        field_node = self.find_child_by_field(node, "field")
        object_name = self.read_node_text(object_node)
        field_name = self.read_node_text(field_node)
        self.append_stmts(statements, node, {
            "field_write": {
                "source": "acc",
                "receiver_object": object_name,
                "field": field_name,
            }
        })

    def stobjbyvalue_statement(self, node, statements):
        object_node = self.find_child_by_field(node, "object")
        index_node = self.find_child_by_field(node, "index")
        object_name = self.read_node_text(object_node)
        index_name = self.read_node_text(index_node)
        self.append_stmts(statements, node, {
            "array_write": {
                "array": object_name,
                "index": index_name,
                "source": "acc"
            }
        })

    #
    def ldobjbyname_statement(self, node, statements):
        field_node = self.find_child_by_field(node, "object")
        field_name = self.read_node_text(field_node)
        self.append_stmts(statements, node, {
            "field_read": {
                "receiver_object": "acc",
                "field": field_name,
                "target": "tmp"
            }
        })
        self.append_stmts(statements, node, {
            "assign_stmt": {
                "operand": "tmp",
                "target": "acc"
            }
        })

    def ldobjbyvalue_statement(self, node, statements):
        array_node = self.find_child_by_field(node, "object")
        array_name = self.read_node_text(array_node)
        self.append_stmts(statements, node, {
            "array_read": {
                "array": array_name,
                "index": "acc",
                "target": "acc"
            }
        })

    #     acc        hole，          ：A      undefined。
    def ifhole_statement(self, node, statements):
        pass

    def ldconst_statement(self, node, statements):
        operand = ""
        if node.type == "ldundefiened_statement":
            operand = AnalyzerInternal.UNDEFINED
        elif node.type == "ldnull_statement":
            operand = AnalyzerInternal.NULL
        elif node.type == "ldtrue_statement":
            operand = AnalyzerInternal.TRUE
        elif node.type == "ldfalse_statement":
            operand = AnalyzerInternal.FALSE
        elif node.type == "ldhole_statement":
            operand = AnalyzerInternal.HOLE
        self.append_stmts(statements, node, {
            "assign_stmt": {
                "target": "acc",
                "operand": operand
            }
        })

    def returnundefined_statement(self, node, statements):
        self.append_stmts(statements, node, {
            "return_stmt": {
                "name": "undefined"
            }
        })

    def return_statement(self, node, statements):
        self.append_stmts(statements, node, {
            "return_stmt": {
                "name": "acc"
            }
        })

    def definemethod_statement(self, node, statements):
        pass

    def definefieldbyname_statement(self, node, statements):
        field_node = self.find_child_by_field(node, "field")
        object_node = self.find_child_by_field(node, "object")
        field = self.read_node_text(field_node)
        object = self.read_node_text(object_node)
        self.append_stmts(statements, node, {
            "field_write": {
                "receiver_object": object,
                "field": field,
                "source": "acc"}
        })

    def definefieldbyvalue_statement(self, node, statements):
        pass

    #         field_node = self.find_child_by_field(node, "field")
    #         object_node = self.find_child_by_field(node, "object")
    #         field = self.read_node_text(field_node)
    #         object = self.read_node_text(object_node)
    #         self.append_stmts(statements, node, {
    #             "array_write": {
    # }
    #         })

    # this instruction has not finished yet
    def defineclass_statement(self, node, statements):
        # self.print_tree(node)
        parent_node = self.find_child_by_field(node, "super")
        method_node = self.find_child_by_type(node, "literal")
        constructor_node = self.find_child_by_field(node, "class_name")
        prefix_name_node = self.find_child_by_type(constructor_node, "function_name_type1")
        full_name_node = self.find_child_by_field(prefix_name_node, "name")
        class_name_node = self.find_child_by_field(full_name_node, "function_name")
        class_name = self.read_node_text(class_name_node)
        parent_node = self.find_child_by_field(node, "super")
        parent_var = self.read_node_text(parent_node)
        self.append_stmts(statements, node, {
            "define_class": {
                "target": "acc",
                "operand": class_name,
                "parent": parent_var,
            }
        })
        # self.append_stmts(statements, node, {
        #     "class_decl": {
        #         "name": class_name,
        #     }
        # })
        # for index, element_node in enumerate(method_node.named_children):
        #     if index > 0 & index % 2 == 1:
        #         field_node = element_node.named_children[1]
        #         field= self.read_node_text(field_node)
        #     elif index > 0 & index % 2 == 0:
        #         value_node = element_node.named_children[1]
        #         value = self.read_node_text(value_node)
        #         self.append_stmts(statements, node, {
        #             "field_write": {
        #                 "receiver_object": "acc",
        #                 "field": field,
        #                 "source": value
        #             }
        #         })
        # self.append_stmts(statements, node, {
        #     "assign_stmt": {
        #         "target": "%vvacc",
        #         "operand": class_name
        #     }
        # })

    def new_array_statement(self, node, statements):
        array_node = self.find_child_by_type(node, "literal")
        length_node = self.find_child_by_field(array_node, "length")
        length = self.read_node_text(length_node)
        tmp_var = self.tmp_variable()
        self.append_stmts(statements, node, {"new_array": {"target": tmp_var}})
        for index, element_node in enumerate(array_node.named_children):
            if index > 0:
                value_node = element_node.named_children[1]
                value = self.read_node_text(value_node)
                self.append_stmts(statements, node, {
                    "array_write": {
                        "array": tmp_var,
                        "index": str(index),
                        "source": value
                    }
                })
        self.append_stmts(statements, node, {
            "assign_stmt": {
                "target": "acc",
                "operand": tmp_var
            }
        })

    def newobjrange_statement(self, node, statements):
        type_node = self.find_child_by_field(node, "object")
        type = self.read_node_text(type_node)
        self.append_stmts(statements, node, {
            "new_object": {
                "target": "acc",
                "data_type": type
            }
        })

    def newobjrange_statement(self, node, statements):
        arguments = []

        range_node = self.find_child_by_field(node, "param_num")
        param_range = self.read_node_text(range_node)

        object_node = self.find_child_by_field(node, "object")
        object = self.read_node_text(object_node)
        arg_start_id = self.var_to_argid(object) + 1

        for i in range(arg_start_id, arg_start_id + int(param_range, 16) - 1):
            arguments.append(self.argid_to_var(i))

        self.append_stmts(statements, node, {
            "call_stmt": {
                "target": "acc",
                "name": object,
                "positional_args": arguments
            }
        })

    def isfalse_statement(self, node, statements):
        ACC = "acc"
        self.append_stmts(statements, node, {
            "assign_stmt": {
                "target": ACC,
                "operand": "false",
                "operand2": ACC,
                "operator": "=="
            }
        })
        return ACC

    def istrue_statement(self, node, statements):
        ACC = "acc"
        self.append_stmts(statements, node, {
            "assign_stmt": {
                "target": ACC,
                "operand": "true",
                "operand2": ACC,
                "operator": "=="
            }
        })
        return ACC

    def typeof_statement(self, node, statements):
        ACC = "acc"
        self.append_stmts(statements, node, {
            "assign_stmt": {
                "target": ACC,
                "operand": ACC,
                "operator": "typeof"
            }
        })

    def definegettersetter_statement(self, node, statements):
        pass

    def add_statement(self, node, statements):
        register_node = self.find_child_by_field(node, "register")
        register_name = self.read_node_text(register_node)

        self.append_stmts(statements, node, {
            "assign_stmt": {
                "target": "acc",
                "operand": "acc",
                "operand2": register_name,
                "operator": "+"
            }
        })
        return "acc"

    def sub_statement(self, node, statements):
        register_node = self.find_child_by_field(node, "register")
        register_name = self.read_node_text(register_node)

        self.append_stmts(statements, node, {
            "assign_stmt": {
                "target": "acc",
                "operand": "acc",
                "operand2": register_name,
                "operator": "-"
            }
        })
        return "acc"

    def dec_statement(self, node, statements):
        self.append_stmts(statements, node, {
            "assign_stmt": {
                "target": "acc",
                "operand": "acc",
                "operand2": "1",
                "operator": "-"
            }
        })

    def mul_statement(self, node, statements):
        register_node = self.find_child_by_field(node, "register")
        register_name = self.read_node_text(register_node)

        self.append_stmts(statements, node, {
            "assign_stmt": {
                "target": "acc",
                "operand": "acc",
                "operand2": register_name,
                "operator": "*"
            }
        })
        return "acc"

    def div_statement(self, node, statements):
        register_node = self.find_child_by_field(node, "register")
        register_name = self.read_node_text(register_node)

        self.append_stmts(statements, node, {
            "assign_stmt": {
                "target": "acc",
                "operand": "acc",
                "operand2": register_name,
                "operator": "/"
            }
        })
        return "acc"

    def mod_statement(self, node, statements):
        register_node = self.find_child_by_field(node, "register")
        register_name = self.read_node_text(register_node)

        self.append_stmts(statements, node, {
            "assign_stmt": {
                "target": "acc",
                "operand": "acc",
                "operand2": register_name,
                "operator": "%"
            }
        })
        return "acc"

    def eq_statement(self, node, statements):
        register_node = self.find_child_by_field(node, "register")
        register_name = self.read_node_text(register_node)

        self.append_stmts(statements, node, {
            "assign_stmt": {
                "target": "acc",
                "operand": "acc",
                "operand2": register_name,
                "operator": "=="
            }
        })
        return "acc"

    def noteq_statement(self, node, statements):
        register_node = self.find_child_by_field(node, "register")
        register_name = self.read_node_text(register_node)

        self.append_stmts(statements, node, {
            "assign_stmt": {
                "target": "acc",
                "operand": "acc",
                "operand2": register_name,
                "operator": "!="
            }
        })
        return "acc"

    def less_statement(self, node, statements):
        register_node = self.find_child_by_field(node, "register")
        register_name = self.read_node_text(register_node)

        self.append_stmts(statements, node, {
            "assign_stmt": {
                "target": "acc",
                "operand": "acc",
                "operand2": register_name,
                "operator": "<"
            }
        })
        return "acc"

    def lesseq_statement(self, node, statements):
        register_node = self.find_child_by_field(node, "register")
        register_name = self.read_node_text(register_node)

        self.append_stmts(statements, node, {
            "assign_stmt": {
                "target": "acc",
                "operand": "acc",
                "operand2": register_name,
                "operator": "<="
            }
        })
        return "acc"

    def greater_statement(self, node, statements):
        register_node = self.find_child_by_field(node, "register")
        register_name = self.read_node_text(register_node)

        self.append_stmts(statements, node, {
            "assign_stmt": {
                "target": "acc",
                "operand": "acc",
                "operand2": register_name,
                "operator": ">"
            }
        })
        return "acc"

    def greatereq_statement(self, node, statements):
        register_node = self.find_child_by_field(node, "register")
        register_name = self.read_node_text(register_node)

        self.append_stmts(statements, node, {
            "assign_stmt": {
                "target": "acc",
                "operand": "acc",
                "operand2": register_name,
                "operator": ">="
            }
        })
        return "acc"

    def and_statement(self, node, statements):
        register_node = self.find_child_by_field(node, "register")
        register_name = self.read_node_text(register_node)

        self.append_stmts(statements, node, {
            "assign_stmt": {
                "target": "acc",
                "operand": "acc",
                "operand2": register_name,
                "operator": "&"
            }
        })
        return "acc"

    def or_statement(self, node, statements):
        register_node = self.find_child_by_field(node, "register")
        register_name = self.read_node_text(register_node)

        self.append_stmts(statements, node, {
            "assign_stmt": {
                "target": "acc",
                "operand": "acc",
                "operand2": register_name,
                "operator": "|"
            }
        })
        return "acc"

    def xor_statement(self, node, statements):
        register_node = self.find_child_by_field(node, "register")
        register_name = self.read_node_text(register_node)

        self.append_stmts(statements, node, {
            "assign_stmt": {
                "target": "acc",
                "operand": "acc",
                "operand2": register_name,
                "operator": "^"
            }
        })
        return "acc"

    def tonumeric_statement(self, node, statements):
        pass

    def condition_statement(self, node, statements):
        register_node = self.find_child_by_field(node, "register")
        register_name = self.read_node_text(register_node)

        self.append_stmts(statements, node, {
            "assign_stmt": {
                "target": "acc",
                "operand": "acc",
                "operand2": "register_name",
                "operator": "!="
            }
        })

    def stricteq_statement(self, node, statements):
        register_node = self.find_child_by_field(node, "register")
        register_name = self.read_node_text(register_node)

        self.append_stmts(statements, node, {
            "assign_stmt": {
                "target": "acc",
                "operand": "acc",
                "operand2": register_name,
                "operator": "=="
            }
        })

    def strictnoteq_statement(self, node, statements):
        register_node = self.find_child_by_field(node, "register")
        register_name = self.read_node_text(register_node)

        self.append_stmts(statements, node, {
            "assign_stmt": {
                "target": "acc",
                "operand": "acc",
                "operand2": register_name,
                "operator": "!="
            }
        })

    def inc_statement(self, node, statements):
        self.append_stmts(statements, node, {
            "assign_stmt": {
                "target": "acc",
                "operand": "acc",
                "operand2": "1",
                "operator": "+"
            }
        })

    def dec_statement(self, node, statements):
        self.append_stmts(statements, node, {
            "assign_stmt": {
                "target": "acc",
                "operand": "acc",
                "operand2": "1",
                "operator": "-"
            }
        })

    def while_statement(self, node, statements):
        pass

    def copyrestargs_statement(self, node, statements):
        self.append_stmts(statements, node, {
            "assign_stmt": {
                "target": "acc",
            }
        })

    def supercallspread_statement(self, node, statements):
        self.append_stmts(statements, node, {
            "call_stmt": {
                "name": "acc",
                "target": "acc"
            }
        })

    def throw_statement(self, node, statements):
        pass

    def asyncfunctionenter_statement(self, node, statements):
        pass

    def neg_statement(self, node, statements):
        self.append_stmts(statements, node, {
            "assign_stmt": {
                "target": "acc",
                "operand": "acc",
                "operator": "-"
            }
        })

    def nor_statement(self, node, statements):
        self.append_stmts(statements, node, {
            "assign_stmt": {
                "target": "acc",
                "operand": "acc",
                "operator": "~"
            }
        })

    def newenv_statement(self, node, statements):
        list = []
        literal_node = self.find_child_by_type(node, "literal")
        for index, element_node in enumerate(literal_node.named_children):
            if index > 0 and index % 2 == 0:
                variable_node = element_node.named_children[1]
                variable_name = self.read_node_text(variable_node)
                variable_name = variable_name[1:-1]
                if variable_name == "this":
                    variable_name = AnalyzerInternal.THIS
                list.append(variable_name)
        self.append_stmts(statements, node, {
            "newlexenv": {
                "variable_list": list
            }
        })

    def poplexenv_statement(self, node, statements):
        pass

    def checkholebyname_statement(self, node, statements):
        name_node = self.find_child_by_field(node, "name")
        name = self.read_node_text(name_node)
        self.append_stmts(statements, node, {
            "checkholebyname": {
                "name": name
            }
        })

    def asyncfunctionawaituncaught_statement(self, node, statements):
        pass

    def asyncfunctionreject_statement(self, node, statements):
        pass

    def asyncfunctionresolve_statement(self, node, statements):
        pass

    def suspendgenerator_statement(self, node, statements):
        pass

    def resumegenerator_statement(self, node, statements):
        pass

    def getresumemode_statement(self, node, statements):
        pass

    def createemptyarray_statement(self, node, statements):
        self.append_stmts(statements, node, {
            "new_array": {
                "target": "acc",
            }
        })

    def createobjectwithbuffer_statement(self, node, statements):
        fields_node = self.find_child_by_type(node, "literal")
        length_node = self.find_child_by_field(fields_node, "length")
        length = self.read_node_text(length_node)
        tmp_var = self.tmp_variable()
        self.append_stmts(statements, node, {"new_object": {"target": "acc"}})
        field = ""
        for index, element_node in enumerate(fields_node.named_children):
            if len(element_node.named_children) < 2:
                continue
            if index > 0 and index % 2 == 1:
                field_node = element_node.named_children[1]
                field = self.read_node_text(field_node)
            elif index > 0 and index % 2 == 0:

                value_node = element_node.named_children[1]
                value = self.read_node_text(value_node)
                self.append_stmts(statements, node, {
                    "field_write": {
                        "receiver_object": "acc",
                        "field": field,
                        "source": value
                    }
                })

    def createemptyobject_statement(self, node, statements):
        self.append_stmts(statements, node, {
            "new_object": {
                "target": "acc",
            }
        })

    def isin_statement(self, node, statements):
        pass

    def jmp_statement(self, node, statements):
        jmp_type = node.type
        target_node = self.find_child_by_field(node, "target")
        target_name = self.read_node_text(target_node)
        then_body = []
        then_body.append({
            "goto_stmt": {
                "name": target_name
            }
        })
        if jmp_type == "jmp_statement":
            self.append_stmts(statements, node, {
                "goto_stmt": {
                    "name": target_name
                }
            })
        elif jmp_type == "jeqz_statement":
            tmp_var = self.tmp_variable()
            self.append_stmts(statements, node, {
                "assign_stmt": {
                    "target": tmp_var,
                    "operand": "acc",
                    "operator": "==",
                    "operand2": "0"
                }

            })
            self.append_stmts(statements, node, {
                "if_stmt": {
                    "condition": tmp_var,
                    "then_body": then_body
                }
            })
        elif jmp_type == "jnez_statement":
            tmp_var = self.tmp_variable()
            self.append_stmts(statements, node, {
                "assign_stmt": {
                    "target": tmp_var,
                    "operand": "acc",
                    "operator": "!=",
                    "operand2": "0"
                }

            })
            self.append_stmts(statements, node, {
                "if_stmt": {
                    "condition": tmp_var,
                    "then_body": then_body
                }
            })

    def ldexternalmodulevar_statement(self, node, statements):
        slot_node = self.find_child_by_field(node, "slot")
        slot_name = self.read_node_text(slot_node)
        self.append_stmts(statements, node, {
            "ldexternalmodulevar": {
                "index": slot_name,
            }
        })

    def ldsuperbyname_statement(self, node, statements):
        pass

    def ldglobal_statement(self, node, statements):
        pass
        # name_node = self.find_child_by_field(node, "name")
        # name = self.read_node_text(name_node)
        # self.append_stmts(statements, node, {
        #     "ldglobal":{
        #         "name":name
        #     }
        # })

    def getmodulenamespace_statement(self, node, statements):
        slot_node = self.find_child_by_field(node, "slot")
        slot_name = self.read_node_text(slot_node)
        self.append_stmts(statements, node, {
            "getmodulenamespace": {
                "slot": slot_name,
            }
        })

    def label_statement(self, node, statements):
        label_name = self.read_node_text(node)
        label_name = label_name.replace(":", "")
        self.append_stmts(statements, node, {
            "label_stmt": {
                "name": label_name
            }
        })

    def instanceof_statement(self, node, statements):
        pass

    def catch_statement(self, node, statements):
        pass

    def comment_statement(self, node, statements):
        pass

    def dynamicimport_statement(self, node, statements):
        pass

    def module_literal(self, node, statements):
        module_literal = {}
        module_request_array = []
        module_tag_array = []

        idnode = self.find_child_by_field(node, "idnumber")
        module_request_node = self.find_child_by_type(node, "module_request_array")
        module_tag = self.find_children_by_field(node, "module_tag")
        id = self.read_node_text(idnode)
        module_literal["id"] = id

        for module in module_request_node.named_children:
            reference_node = self.find_child_by_type(module, "module_reference")
            module_node = reference_node.named_children[0]
            type = module_node.type
            path_node = module_node.named_children[0]
            path = self.read_node_text(path_node)
            path = path.replace('/', '.')
            module_request_array.append({"module_type": type, "path": path})
        module_literal["module_request_array"] = module_request_array

        for module in module_tag:
            tag_node = module.named_children[0]
            module_type = tag_node.type
            local_name_node = tag_node.named_children[0]
            local_name = self.read_node_text(local_name_node)
            if module_type == "regular_import_type":
                import_name_node = tag_node.named_children[1]
                module_path = tag_node.named_children[2]
                specific_module = module_path.named_children[0]
                import_type = specific_module.type
                module_path = specific_module.named_children[0]
                specific_path = self.read_node_text(module_path)
                specific_path = specific_path.replace('/', '.')
                tag_record = {
                    "tag_type": module_type,
                    "local_name": local_name,
                    "import_name": self.read_node_text(import_name_node),
                    "module_path": specific_path,
                    "module_type": import_type
                }
            elif module_type == "local_export_tag":
                export_name_node = tag_node.named_children[1]
                tag_record = {
                    "tag_type": module_type,
                    "local_name": local_name,
                    "export_name": self.read_node_text(export_name_node),
                }
            elif module_type == "namespace_import_tag":
                module_path = tag_node.named_children[1]
                specific_module = module_path.named_children[0]
                import_type = specific_module.type
                module_path = specific_module.named_children[0]
                specific_path = self.read_node_text(module_path)
                specific_path = specific_path.replace('/', '.')
                tag_record = {
                    "tag_type": module_type,
                    "local_name": local_name,
                    "module_path": self.read_node_text(module_path),
                    "module_type": import_type
                }
            elif module_type in ["indirect_import_type", "star_export_tag"]:
                continue
            module_tag_array.append(tag_record)

        module_literal["module_tag_array"] = module_tag_array
        self.append_stmts(statements, node, {
            "module_literal": module_literal
        })

    def scope_literal(self, node, statements):
        idnode = self.find_child_by_field(node, "idnumber")
        id = self.read_node_text(idnode)
        scope_literal = []
        for child in node.named_children:
            if child.type == "scope_tag":
                name_node = self.find_child_by_field(child, "value")
                name = self.read_node_text(name_node)
                if name.startswith('"') and name.endswith('"'):
                    name = name[1:-1]
                scope_literal.append(name)

        self.append_stmts(statements, node, {
            "module_literal": {
                "id": id,
                "scope_name_array": scope_literal
            }
        })

    def module_record(self, node, statements):

        module_record = {}
        path_node = self.find_child_by_type(node, "path")
        path = self.read_node_text(path_node)
        module_record["path"] = path

        fields = self.find_children_by_type(node, "field")
        for field in fields:
            field_node = self.find_child_by_type(field, "field_name")
            field_name = self.read_node_text(field_node)
            idnode = self.find_child_by_type(field, "hexi")
            id = self.read_node_text(idnode)
            module_record[field_name] = id
        self.append_stmts(statements, node, {
            "module_record": module_record
        })

    def module_reference(self, node, statements):
        module_node = node.named_children[0]
        type = module_node.type
        path_node = module_node.named_children[0]
        return self.read_node_text(node)

    def expression_wrapper(self, node, statements):
        if len(node.named_children) == 1:
            return self.expression(node.named_children[0], statements)
        else:
            print("Unexpected expression node with multiple children")
            return {"unknown_expression": self.read_node_text(node)}

    def error_statement(self, node, statements):
        pass

    def identifier_expression(self, node, statements):
        return self.read_node_text(node)

    def parenthesized_lvalue_expression(self, node, statements):
        lvalue = self.lvalue(node, statements)
        return lvalue

    def is_comment(self, node):
        return node.type in ["line_comment", "block_comment", "comment"]

    def is_identifier(self, node):
        return node.type == "identifier"

    def is_literal(self, node):
        return self.obtain_literal_handler(node) is not None

    def is_expression(self, node):
        return self.check_expression_handler(node) is not None

    def is_statement(self, node):

        return self.check_statement_handler(node) is not None

    def is_declaration(self, node):
        return self.check_declaration_handler(node) is not None

    def obtain_literal_handler(self, node):
        LITERAL_MAP = {
        }
        return LITERAL_MAP.get(node.type, None)

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
        # self.print_tree(node)
        if (node.type == "statement"):
            node = node.children[0]

        handler = self.check_statement_handler(node)
        return handler(node, statements)


ABCParser = Parser
