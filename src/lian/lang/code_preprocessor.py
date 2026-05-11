import ast
import copy
import pdb
import pprint
from lian.config.constants import ABC_INTERNAL as AnalyzerInternal
from lian.util import util
class prepare_code:
    def __init__(self, ananymous_func_to_scope = {}):
        self.module_literal = []
        self.module_record = []
        self.class_to_parent = {}
        self.ananymous_func = []
        self.ananymous_func_to_scope = ananymous_func_to_scope
    def integrate(self, code):

        integrated_code = []
        method_code = []
        for stmt in code:
            if "method_decl" in stmt:
                method_code.append(stmt)
            elif "module_literal" in stmt:
                self.module_literal.append(stmt)
            elif "module_record" in stmt:
                self.module_record.append(stmt)

        for func in method_code:
            path = func["method_decl"]["path"]

            # 删除handler_begin与handler_end中间的catch代码
            body_without_catch = []
            handler_label_stack = []
            for stmt in func["method_decl"]["body"]:
                # if self.is_try_label_stmt(stmt):
                #     continue
                if self.is_goto_handler_end_stmt(stmt):
                    continue
                if self.is_handler_begin_label_stmt(stmt):
                    handler_label_stack.append("handler_begin")
                elif self.is_handler_end_label_stmt(stmt):
                    if len(handler_label_stack) != 0:
                        handler_label_stack.pop()
                        continue
                if len(handler_label_stack) == 0:
                    body_without_catch.append(stmt)
            func["method_decl"]["body"] = body_without_catch

            # 标记ldexternal指令属于哪个module
            for i in range(len(func["method_decl"]["body"])):
                instruction = func["method_decl"]["body"][i]
                literal_id = ""

                if "ldexternalmodulevar" in instruction:
                    hexi_index = instruction["ldexternalmodulevar"]["index"]
                    index = int(hexi_index, 16)
                    for record in self.module_record:
                        if record["module_record"]["path"] == path:
                            literal_id = record["module_record"]["moduleRecordIdx"]
                            break
                    for literal in self.module_literal:
                        if literal["module_literal"]["id"] == literal_id:
                            module_tag_array = literal["module_literal"]["module_tag_array"]
                            tag = module_tag_array[index]
                            start_row = instruction["ldexternalmodulevar"]["start_row"]
                            end_row = instruction["ldexternalmodulevar"]["end_row"]
                            func["method_decl"]["body"][i] = {
                                "field_read":{
                                    "receiver_object":tag["module_path"],
                                    "field":tag["import_name"],
                                    "target": "acc",
                                    "start_row": start_row,
                                    "end_row": end_row,
                                }
                            }
                            break

                elif "getmodulenamespace" in instruction:
                    hexi_index = instruction["getmodulenamespace"]["slot"]
                    index = int(hexi_index, 16)
                    for record in self.module_record:
                        if record["module_record"]["path"] == path:
                            literal_id = record["module_record"]["moduleRecordIdx"]
                            break
                    for literal in self.module_literal:
                        if literal["module_literal"]["id"] == literal_id:
                            module_request_array = literal["module_literal"]["module_request_array"]
                            tag = module_request_array[index]
                            func["method_decl"]["body"][i] = {
                                "assign_stmt":{
                                    "operand":tag["path"],
                                    "target": "acc"
                                }
                            }
                            break
        #将函数整合到不同的module中
        for func in method_code:
            path = func["method_decl"]["path"]
            scope = func["method_decl"]["scope_name"]
            function_name = func["method_decl"]["name"]
            has_path = False
            for module in integrated_code:
                if module["class_decl"]["name"] == path:
                    has_path = True
                    module["class_decl"]["methods"].append(func)
                    break
            if not has_path:
                integrated_code.append({
                    "class_decl": {
                        "name": path,
                        "methods": [func]
                    }
                })
        new_integrated_code = self.intergrate_method_in_module(integrated_code)

            
        return new_integrated_code

    def intergrate_method_in_module(self, integrated_code):
        new_intergrated_code = []
        for module in integrated_code:
            method_to_lexenv = {}
            methods = module["class_decl"]["methods"]
            new_module = {"class_decl":{'name':module["class_decl"]["name"],'methods':[]}}
            for method in methods:
                scope = method["method_decl"]["scope_name"]
                path = method["method_decl"]["path"]
                func_name = method["method_decl"]["name"]

                # 不需要找所在类的函数有：main函数，全局函数
                if func_name == "func_main_0" or func_name.startswith("#") or len(scope) == 0:
                    if func_name == "func_main_0" and "lex_env" in method["method_decl"]:
                        new_module["class_decl"]["lex_env"] = method["method_decl"]["lex_env"]
                    new_module["class_decl"]["methods"].append(method)
                    continue
                scope_list = self.determine_scope(scope, path)
                scope_name = scope_list[0]["name"]
                if scope_list[0]["type"] == "class":
                    scope_name = scope_list[0]["name"]
                    parent_name = ""
                    if scope_name in self.class_to_parent:
                        parent_name = self.class_to_parent[scope_name]
                    if "nested" not in new_module["class_decl"] :
                        self.add_nest_class(new_module, scope_name, method, parent_name)
                    else:
                        has_class = False
                        for nested_class in new_module["class_decl"]["nested"]:
                            if nested_class["class_decl"]["name"] == scope_name:
                                has_class = True

                                if not self.find_function_target_scope(scope_list[1:], nested_class, method):
                                    self.find_ananymous_function_target_scope(scope_list[1:], nested_class, method) 

                        if not has_class:
                            self.add_nest_class(new_module, scope_name, method, parent_name)
                else:
                    for parent_method in new_module["class_decl"]["methods"]:
                        if parent_method["method_decl"]["name"] == scope_name:
                            parent_method["method_decl"]["body"].insert(0, method)
                            break
                    
            new_intergrated_code.append(new_module)
        return new_intergrated_code

    # 根据scope放置函数
    def find_function_target_scope(self, scope_list, methods_or_body, method):

        if len(scope_list) == 0:
            if "method_decl" in methods_or_body:
                methods_or_body["method_decl"]["body"].insert(0, method)
                self.ananymous_func.append(method)
                return True
            elif "class_decl" in methods_or_body:
                methods_or_body["class_decl"]["methods"].append(method)
                self.ananymous_func.append(method)
                return True
            return False
        result = False
        if "method_decl" in methods_or_body:
            for stmt in methods_or_body["method_decl"]["body"]:
                if "method_decl" not in stmt:
                    continue
                if stmt["method_decl"]["name"] == scope_list[0]["name"]:
                    result = self.find_function_target_scope(scope_list[1:], stmt, method)
                    break
        elif "class_decl" in methods_or_body:
            for stmt in methods_or_body["class_decl"]["methods"]:
                if "method_decl" not in stmt:
                    continue
                if stmt["method_decl"]["name"] == scope_list[0]["name"]:
                    result = self.find_function_target_scope(scope_list[1:], stmt, method)
                    break
        return result

    # 根据scope放置函数失败，则根据definefunc来放置函数
    def find_ananymous_function_target_scope(self, scope_list, methods_or_body, method):
        func_name = method["method_decl"]["name"]
        # print(func_name)
        # print(method["method_decl"]["scope_name"])
        # print(self.ananymous_func_to_scope)
        if func_name not in self.ananymous_func_to_scope:
            return
        parent_func = self.ananymous_func_to_scope[func_name]

        for func in self.ananymous_func:
            if func["method_decl"]["name"] == parent_func:
                func["method_decl"]["body"].insert(0, method)
                self.ananymous_func.append(method)
                break



    def determine_scope(self, scope_list, path):
        # 未处理namespace，longname
        # 在这里处理longname
        # print(scope_list)
        # print(path)
        # print(self.module_record)
        literal_id = 0
        for record in self.module_record:
            if record["module_record"]["path"] == path:
                literal_id = record["module_record"]["scopeNames"]
                break

        scope_name_array = None
        for literal in self.module_literal:
            if literal["module_literal"]["id"] == literal_id:
                scope_name_array = literal["module_literal"]["scope_name_array"]
                break

        for scope in scope_list:
            # scope为class
            if scope["type"] == "~":
                scope["type"] = "class"
            # scope为function
            elif scope["type"] != "&":
                scope["type"] = "function"

            if scope["longname"] == 1:
                scope["name"] = scope["name"].replace('^', '')
                dec_index = int(scope["name"], 16)
                if not scope_name_array or dec_index > len(scope_name_array):
                    break
                scope["name"] = scope_name_array[dec_index]

        return scope_list
                # module_tag_array = literal["module_literal"]["module_tag_array"]
                # tag = module_tag_array[index]
                # func["method_decl"]["body"][i] = {
                #     "field_read":{
                #         "receiver_object":tag["module_path"],
                #         "field":tag["import_name"],
                #         "target": "acc"
                #     }
                # }


# 处理词法环境， 父类， 去除对分析无影响的指令
    def preprocess(self, code):

        for func in code:
            if "method_decl" not in func:
                continue
            current_lexenv = []
            # all_lexenv = {}

            for i in range(len(func["method_decl"]["body"])):
                instruction = func["method_decl"]["body"][i]
                # variable = "unknown"
                if "newlexenv" in instruction:
                    current_lexenv = instruction["newlexenv"]["variable_list"]
                    func["method_decl"]["lex_env"] = current_lexenv
                elif "ldlexvar" in instruction:
                    # if instruction["ldlexvar"]["lexi_env"] == "0" and len(current_lexenv) != 0:
                    #     slot = instruction["ldlexvar"]["index"]
                    #     variable = current_lexenv[int(slot)]
                    #     if variable == '"this"':
                    #         variable = AnalyzerInternal.THIS
                    # else :
                    #     lexvar_addr = "lexi_env" + instruction["ldlexvar"]["lexi_env"] + "slot" + instruction["ldlexvar"]["index"]

                    #     next_instruction = func["method_decl"]["body"][i + 1]

                    #     if "checkholebyname" in next_instruction:
                    #         variable = next_instruction["checkholebyname"]["name"]
                    #         all_lexenv[lexvar_addr] = variable
                    func["method_decl"]["body"][i] = {
                        "assign_stmt":{
                            "type":"ldlexvar",
                            "lex_env_id":instruction["ldlexvar"]["lex_env_id"],
                            "index":instruction["ldlexvar"]["index"],
                            "start_row": instruction["ldlexvar"]["start_row"],
                            "end_row": instruction["ldlexvar"]["end_row"],
                            "start_col": instruction["ldlexvar"]["start_col"],
                            "end_col": instruction["ldlexvar"]["end_col"],
                        }
                    }
                elif "stlexvar" in instruction:
                    # if instruction["stlexvar"]["lexi_env"] == "0" and len(current_lexenv) != 0:
                    #     slot = instruction["stlexvar"]["index"]
                    #     variable = current_lexenv[int(slot)]
                    # else :
                    #     lexvar_addr = "lexi_env" + instruction["stlexvar"]["lexi_env"] + "slot" + instruction["stlexvar"]["index"]
                    #     if lexvar_addr in all_lexenv:
                    #         variable = all_lexenv[lexvar_addr]
                    func["method_decl"]["body"][i] = {
                        "assign_stmt":{
                            "type":"stlexvar",
                            "lex_env_id":instruction["stlexvar"]["lex_env_id"],
                            "index":instruction["stlexvar"]["index"],
                        }
                    }

        variable_pool = {}
        for func in code:
            if self.is_func_main_0(func):
                for instruction in func["method_decl"]["body"]:

                    if self.is_checkholebyname_stmt(instruction):
                        stmt = instruction["checkholebyname"]
                        variable_pool["acc"] = stmt["name"]
                    if self.is_define_class_stmt(instruction):
                        stmt = instruction["define_class"]
                        variable_pool[stmt["target"]] = stmt["operand"]
                        self.class_to_parent[stmt["operand"]] = variable_pool[stmt["parent"]]
                    if self.is_load_ViewPU(instruction):
                        variable_pool["acc"] = "ViewPU"
                    elif "assign_stmt" in instruction and "type" not in instruction["assign_stmt"]:
                        stmt = instruction["assign_stmt"]
                        if stmt["operand"] not in variable_pool:
                            variable_pool[stmt["operand"]] = ""
                        if stmt["operand"] == AnalyzerInternal.HOLE:
                            variable_pool[stmt["target"]] = ""
                        else:
                            variable_pool[stmt["target"]] = variable_pool[stmt["operand"]]

        for func in code:
            if "method_decl" not in func:
                continue
            new_body = []
            for instruction in func["method_decl"]["body"]:
                if self.is_checkholebyname_stmt(instruction):
                    continue
                if self.is_newlexenv_stmt(instruction):
                    continue
                if self.is_define_class_stmt(instruction):
                    continue
                new_body.append(instruction)
            func["method_decl"]["body"] = new_body
        return code

    def run(self, code):
        code = self.preprocess(code)
        integrated_code = self.integrate(code)
        return integrated_code

    def find_lex_var(self, flatten_stmt):
        for stmt in flatten_stmt:
            parent_not_found = False
            if "type" not in stmt:
                continue
            lex_env_id = int(stmt["lex_env_id"])
            index = int(stmt["index"])
            lex_env = []
            parent_stmt_id = stmt["parent_stmt_id"]

            while lex_env_id >= 0:
                parent_stmt = self.find_parent_stmt(flatten_stmt, parent_stmt_id)
                if parent_stmt is None:
                    parent_not_found = True
                    break
                parent_stmt_id = parent_stmt["parent_stmt_id"]
                if "lex_env" in parent_stmt and len(parent_stmt["lex_env"]) != 0:
                    lex_env_id -= 1
                    lex_env = parent_stmt["lex_env"]
            try:
                lex_env = ast.literal_eval(lex_env)
            except ValueError as e:
                print(f"error: {e}，raw: {lex_env}")
                continue
            if parent_not_found or index >= len(lex_env):
                stmt["target"] = "unknown"
                stmt["operand"] = "unknown"
                # util.debug("lex_env not found", "instruction type:", stmt["type"], stmt["start_row"])
                stmt.pop("type")
                continue
            if stmt["type"] == "ldlexvar":
                stmt.pop("type")
                stmt["target"] = "acc"
                stmt["operand"] = lex_env[index]
            elif stmt["type"] == 'stlexvar':
                stmt.pop("type")
                stmt["operand"] = "acc"
                if lex_env[index] == AnalyzerInternal.THIS:
                    lex_env[index] = "esfdsfvdf"
                stmt["target"] = lex_env[index]
        return flatten_stmt

    def find_parent_stmt(self, flatten_stmt, parent_stmt_id):
        for stmt in flatten_stmt:
            if stmt["stmt_id"] == parent_stmt_id:
                return stmt

    def add_nest_class(self, new_module, scope_name, method, parent_name):
        if "nested" not in new_module["class_decl"] :
            new_module["class_decl"]["nested"] = [{"class_decl": {"name": scope_name, "methods": [method], "supers":[parent_name]}}]
        else:
            new_module["class_decl"]["nested"].append({"class_decl": {"name": scope_name, "methods": [method], "supers":[parent_name]}})

    def is_load_ViewPU(self, stmt):
        if "assign_stmt" in stmt:
            if "operand" in stmt["assign_stmt"] and stmt["assign_stmt"]["operand"] == "ViewPU":
                return True
        return False

    def is_checkholebyname_stmt(self, stmt):
        if "checkholebyname" in stmt:
            return True
        return False

    def is_newlexenv_stmt(self, stmt):
        if "newlexenv" in stmt:
            return True
        return False

    def is_define_class_stmt(self, stmt):
        if "define_class" in stmt:
            return True
        return False

    def is_try_label_stmt(self, stmt):
        if "label_stmt" in stmt and stmt["label_stmt"]["name"].startswith("try"):
            return True
        return False

    def is_goto_handler_end_stmt(self, stmt):
        if "goto_stmt" in stmt and stmt["goto_stmt"]["name"].startswith("handler_end"):
            return True
        return False

    def is_handler_begin_label_stmt(self, stmt):
        if "label_stmt" in stmt and stmt["label_stmt"]["name"].startswith("handler_begin"):
            return True
        return False

    def is_handler_end_label_stmt(self, stmt):
        if "label_stmt" in stmt and stmt["label_stmt"]["name"].startswith("handler_end"):
            return True
        return False

    def is_func_main_0(self, func):
        if "method_decl" in func and func["method_decl"]["name"] == "func_main_0":
            return True
        return False



                
        
