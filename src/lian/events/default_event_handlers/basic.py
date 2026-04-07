#!/usr/bin/env python3

import re
import struct
import ast
import dataclasses

from lian.events.handler_template import EventData
from lian.util import util
import lian.events.event_return as er
from lian.config import type_table
from lian.config.constants import (
    LIAN_INTERNAL
)

WORD_CHARACTERS_CONFIG = {
    'php'           : r'a-zA-Z0-9_$',
    'javascript'    : r'a-zA-Z0-9_$',

    "default"       : r'a-zA-Z0-9_'
}

THIS_NAME_CONFIG = {
    "php"           : "$this",
    "default"       : "this",
}

def replace_percent_symbol_in_mock(data: EventData):
    code = data.in_data
    pattern = r'([a-zA-Z0-9])%([a-zA-Z])'
    def replacement(match):
        a = match.group(1)
        b = match.group(2)
        return f'{a}_1_{b}'
    data.out_data = re.sub(pattern, replacement, code)

    return er.EventHandlerReturnKind.SUCCESS

def remove_php_comments(data: EventData):
    code = data.in_data
    code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
    code = re.sub(r'//.*?\n', '\n', code)
    data.out_data = code
    return er.EventHandlerReturnKind.SUCCESS

def preprocess_php_namespace(data: EventData):
    code = data.in_data
    pattern = r'^(?P<indent>\s*)namespace\s+(?P<name>[^;]+);(?P<after_indent>\s*)(?P<code>.*?)(?=\n\s*namespace\s+|\Z|\?>)'

    def replacer(match):
        indent = match.group('indent')
        name = match.group('name').strip()
        after_indent = match.group('after_indent')
        code = match.group('code').strip()
        return f'{indent}namespace {name} {{\n{indent}{after_indent}{code}\n{indent}}}\n'

    modified_code = re.sub(pattern, replacer, code, flags=re.DOTALL | re.MULTILINE)
    data.out_data = modified_code
    return er.EventHandlerReturnKind.SUCCESS

def preprocess_php_namespace_2(data: EventData):
    code = data.in_data
    namespace_pattern = r'namespace\s+(\S+)\s*\{((?:(?!namespace\s+\S+\s*\{).)*)\}'

    def replacer(match):
        namespace_name = match.group(1)
        namespace_content = match.group(2).strip()

        pattern = r'\b(?<!\\)([a-zA-Z_][a-zA-Z0-9_]*(\\[a-zA-Z_][a-zA-Z0-9_]*))\b'

        def inner_replacer(match):
            name = match.group(1)
            return f'\\{namespace_name}\\{name}'

        modified_content = re.sub(pattern, inner_replacer, namespace_content, flags=re.MULTILINE | re.DOTALL)

        return f'namespace {namespace_name} {{\n{modified_content}\n}}'

    modified_code = re.sub(namespace_pattern, replacer, code, flags=re.MULTILINE | re.DOTALL)
    data.out_data = modified_code
    return er.EventHandlerReturnKind.SUCCESS

def preprocess_llvm_float_value(data: EventData):
    code = data.in_data
    matches = re.finditer(r'\b(float|bfloat|x86_fp80|fp128|ppc_fp128) 0x([0-9A-Fa-f]+)\b', code)
    for match in matches:
        float_name = match.group(1)
        hex_string = match.group(2)
        int_value = int(hex_string, 16)
        float_value = struct.unpack('>d', int_value.to_bytes(8, byteorder='big'))[0]
        formatted_float = float(format(float_value, ".4f"))
        code = code.replace(match.group(0), f"{float_name} {formatted_float}")
    data.out_data = code
    return er.EventHandlerReturnKind.SUCCESS

def preprocess_abc_loop(data: EventData):
    code = data.in_data
    label_pattern = re.compile(r"^jump_label_\d+:")
    jmp_pattern = re.compile(r"jmp\s+(jump_label_\d+)")
    # Used to store defined jump_labels
    defined_labels = set()

    # Processed code
    processed_lines = []

    # Process code line by line
    for line_number, line in enumerate(code.splitlines(), start=1):
        # Check if it defines a jump_label
        label_match = label_pattern.match(line.strip())
        if label_match:
            label = label_match.group(0)[:-1]  # Remove colon
            defined_labels.add(label)

        # Check if it is a jmp statement
        jmp_match = jmp_pattern.search(line)
        if jmp_match:
            target_label = jmp_match.group(1)
            if target_label in defined_labels:  # Loop structure: the target label is already defined
                line = line.replace("jmp", "jmp_loop")

        # Add to results
        processed_lines.append(line)

    # Output results
    processed_code = "\n".join(processed_lines)

def preprocess_python_import_statements(data: EventData):
    # """
    # def a():
    #     import a.b.c, g
    #     a.b.c()
    #     g()

    # import l
    # import h.i.j, k.l.m, n
    # h.i.j.some_func()
    # k.l.m.other_func()
    # n.some_method()
    # a.b.c.e()

    # should be converted to ==============>>>>>>

    # """
    # def a():
    #     from a.b.c import a_b_c
    #     import g
    #     a_b_c()
    #     g()
    # import l
    # from h.i.j import h_i_j
    # from k.l.m import k_l_m
    # import n
    # h_i_j.some_func()
    # k_l_m.other_func()
    # n.some_method()
    # a_b_c.e()
    # """
    code = data.in_data
    lines = code.splitlines()  # Split code into lines for easier processing
    replacements = {}  # Dictionary to map original names to new names
    processed_lines = []  # To collect all processed lines of code

    # Track index where imports were originally found
    for line in lines:
        # Preserve leading spaces (indentation)
        stripped_line = line.lstrip()
        leading_spaces = line[:len(line) - len(stripped_line)]

        if stripped_line.startswith('import '):
            # Extract import names after 'import'
            import_names = re.sub(r"^import", "", stripped_line, count=1)
            import_names = import_names.split(',')
            import_names = [name.strip() for name in import_names]

            new_imports = []  # To collect new import lines

            # Process each import name
            for name in import_names:
                if '.' in name:
                    # Replace dots with underscores for names with dots
                    new_name = name.replace('.', '_')
                    replacements[name] = new_name
                    # Add new formatted import statement, preserving indentation
                    new_imports.append(f'{leading_spaces}from {name} import {new_name}')
                else:
                    # Keep original for names without dots, preserving indentation
                    new_imports.append(f'{leading_spaces}import {name}')

            # Add the transformed imports instead of the original line
            processed_lines.extend(new_imports)
        else:
            # Apply replacements for non-import lines
            for old_name, new_name in replacements.items():
                old_name = re.escape(old_name)
                # Replace old name with the new name in the current line
                if re.search(rf'\b{old_name}\b', line):
                    line = re.sub(rf'\b{old_name}\b', new_name, line)

            # Append the line after processing replacements
            processed_lines.append(line)

    # Rebuild the code from the processed lines
    data.out_data = '\n'.join(processed_lines)
    return er.EventHandlerReturnKind.SUCCESS

def replace_this(obj, this_name):
    if isinstance(obj, list):
        for i, item in enumerate(obj):
            if isinstance(item, (list, dict)):
                replace_this(item, this_name)
            elif isinstance(item, str) and item == this_name:
                obj[i] = LIAN_INTERNAL.THIS

    elif isinstance(obj, dict):
        for key, value in obj.items():
            if "key" == "attrs":
                continue

            if isinstance(value, (list, dict)):
                replace_this(value, this_name)
            elif isinstance(value, str) and value == this_name:
                obj[key] = LIAN_INTERNAL.THIS

def unify_this(data: EventData):
    code = data.in_data
    this_name = THIS_NAME_CONFIG.get(data.lang, THIS_NAME_CONFIG["default"])
    replace_this(code, this_name)
    data.out_data = code
    return er.EventHandlerReturnKind.SUCCESS

def find_python_method_first_parameter(method_decl):
    if "attrs" in method_decl["method_decl"] and "staticmethod" in method_decl["method_decl"]["attrs"]:
        return ""
    if "method_decl" in method_decl:
        method_decl = method_decl["method_decl"]

        if "parameters" in method_decl:
            parameters = method_decl["parameters"]
            counter = 0
            while counter < len(parameters):
                stmt = parameters[counter]
                if "parameter_decl" in stmt:
                    method_decl["parameters"] = parameters[counter + 1 :]
                    return stmt["parameter_decl"].get("name", "")

                counter += 1
    return ""

def adjust_python_self(obj, first_parameter_name = "", new_name = LIAN_INTERNAL.THIS, under_class_decl = False):
    if isinstance(obj, list):
        for i, item in enumerate(obj):
            if isinstance(item, (list, dict)):
                adjust_python_self(item, first_parameter_name, new_name, under_class_decl)
            elif under_class_decl and isinstance(item, str) and item == first_parameter_name:
                obj[i] = LIAN_INTERNAL.THIS

    elif isinstance(obj, dict):
        if "class_decl" in obj:
            current_class = obj["class_decl"]
            if "methods" in current_class:
                for each_method in current_class["methods"]:
                    first_one = find_python_method_first_parameter(each_method)
                    if "attrs" not in each_method["method_decl"]:
                        continue
                    if first_one and "body" in each_method["method_decl"] and  "staticmethod" not in each_method["method_decl"]["attrs"]:
                        adjust_python_self(each_method["method_decl"]["body"], first_one, under_class_decl = True)

        elif "method_decl" in obj:
            if "body" in obj["method_decl"] and "attrs" not in obj["method_decl"]:
                adjust_python_self(obj["method_decl"]["body"])
            if "attrs" in obj["method_decl"] and "staticmethod" not in obj["method_decl"]["attrs"]:
                adjust_python_self(obj["method_decl"]["body"])
        else:
            for key, value in obj.items():
                if key == "attrs":
                    continue
                if isinstance(value, (list, dict)):
                    adjust_python_self(value, first_parameter_name, new_name, under_class_decl)
                elif first_parameter_name and isinstance(value, str) and value == first_parameter_name:
                    obj[key] = LIAN_INTERNAL.THIS

def unify_python_self(data: EventData):
    code  = data.in_data
    adjust_python_self(code)
    data.out_data = code
    return er.EventHandlerReturnKind.SUCCESS

def add_main_func(data: EventData):
    in_data = data.in_data
    out_data = []
    top_stmts = []
    regular_stmts = []
    last_stmt_id = -1
    length = len(in_data)
    index = 0
    exclude_stmts = ("import_stmt", "from_import_stmt", "export_stmt", "type_alias_decl")

    while index < length:
        stmt = in_data[index]
        last_stmt_id = max(last_stmt_id, stmt["stmt_id"])
        if stmt["parent_stmt_id"] == 0:
            if stmt["operation"].endswith("_decl") or stmt["operation"] in exclude_stmts:
                # if stmt["operation"] == "method_decl":
                #     top_stmts.append(stmt)
                regular_stmts.append(stmt)
                index += 1
            else:
                top_stmts.append(stmt)
                index += 1
                while index < length and in_data[index]["parent_stmt_id"] != 0:
                    cur_top_stmt = in_data[index]
                    top_stmts.append(cur_top_stmt)
                    last_stmt_id = max(last_stmt_id, cur_top_stmt["stmt_id"])
                    index += 1
        else:
            regular_stmts.append(stmt)
            index += 1
    out_data = regular_stmts

    if len(top_stmts) == 0:
        return

    main_method_stmt_id = last_stmt_id + 1
    main_method_body_id = last_stmt_id + 2
    out_data.append({
        'operation': 'method_decl',
        'parent_stmt_id': 0,
        'stmt_id': main_method_stmt_id,
        'name': LIAN_INTERNAL.UNIT_INIT,
        'body': main_method_body_id
    })

    out_data.append({
        'operation': 'block_start',
        'stmt_id': main_method_body_id,
        'parent_stmt_id': main_method_stmt_id
    })

    for stmt in top_stmts:
        if stmt["parent_stmt_id"] == 0:
            stmt["parent_stmt_id"] = main_method_body_id
        out_data.append(stmt)

    out_data.append({
        'operation': 'block_end',
        'stmt_id': main_method_body_id,
        'parent_stmt_id': main_method_stmt_id
    })

    data.out_data = out_data
    return er.EventHandlerReturnKind.SUCCESS


def unify_data_type(data: EventData):
    code = data.in_data

    type_info = type_table.get_lang_type_table(data.lang)
    if type_info:
        for row in code:
            if "data_type" not in row or not row["data_type"]:
                continue

            dt = row["data_type"]
            if "*" in dt or "[" in dt:
                for i in range(len(dt) - 1, -1, -1):
                    if dt[i] == '*':
                        row["data_type"] = dt[:i]
                        if "attrs" not in row:
                            attrs = []
                        else:
                            attrs = ast.literal_eval(row["attrs"])
                        util.add_to_dict_with_default_list(row, "attrs", LIAN_INTERNAL.POINTER)
                        break
                    elif dt[i] == '[':
                        row["data_type"] = dt[:i]
                        if "attrs" not in row:
                            attrs = []
                        else:
                            attrs = ast.literal_eval(row["attrs"])
                        attrs.append(LIAN_INTERNAL.ARRAY)
                        row["attrs"] = str(attrs)
                        break

            dt = row["data_type"]
            if dt in type_info:
                row["data_type"] = type_info[dt]

    data.out_data = code
    return er.EventHandlerReturnKind.SUCCESS
