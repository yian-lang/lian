#!/usr/bin/env python3
# system modules
import ast
import os
import re
import sys
import pandas as pd
import numpy as np
import networkx as nx
import math
import keyword
import hashlib
import dis

from lian.config import config

def is_empty(element):
    #print("is_empty:", element)
    if element is None:
        return True
    if isinstance(element, (int, float)):
        return math.isnan(element)
    if isinstance(element, (pd.DataFrame, np.ndarray)):
        return element.size == 0
    if not element:
        return True
    return False

def isna(element):
    if element is None:
        return True
    if isinstance(element, (int, float)):
        return math.isnan(element)
    if not element:
        return True
    return False

def is_none(element):
    return is_empty(element)

def is_available(element):
    return not is_empty(element)

def strict_eval(content):
    bytecode =compile(content, "", "eval")
    for insn in dis.get_instructions(bytecode):
        if "CALL" in insn.opname:
            error_and_quit(f"Found dangerous content to be evaluated: f{content}")

    return ast.literal_eval(content, {}, {}).encode('utf-8', errors='ignore').decode('utf-8')

class EmptyObject:
    pass

def file_md5(filename, chunksize=65536):
    m = hashlib.md5()
    with open(filename, 'rb') as f:
        while chunk := f.read(chunksize):
            m.update(chunk)
    return m.hexdigest()

def error_and_quit(*msg):
    sys.stdout.flush()
    sys.stderr.write(f"[ERROR]: {' '.join(str(item) for item in msg)}\n")
    sys.exit(-1)

def convert_stmt_to_str(stmt):
    if not hasattr(stmt, "_schema"):
        return ""
    stmt_item_list = [str(stmt.stmt_id)]
    for key, pos in stmt._schema.items():
        if key in [
            "data_type",
            "stmt_id",
            "parent_stmt_id",
            "start_row",
            "start_col",
            "end_row",
            "end_col",
            "unit_id",
            "row_index",
        ]:
            continue
        value = stmt._row[pos]
        if is_available(value):
            # 将非字符串类型的值转换为字符串
            stmt_item_list.append(str(value))
    stmt_str = " ".join(stmt_item_list)
    return stmt_str.replace("\n", "").replace("\r", "")

def error_and_quit_with_stmt_info(unit_path, stmt, *msg):
    sys.stderr.write(f"{' '.join(str(item) for item in msg)}\n")
    sys.stderr.write(f"--> {unit_path}:{int(stmt.start_row + 1)}\n")
    sys.stderr.write(f"    {convert_stmt_to_str(stmt)}\n")
    sys.exit(-1)

def error(*msg):
    # logging.error('这是一条debug级别的日志')
    sys.stderr.write(f"[ERROR]: {' '.join(str(item) for item in msg)}\n")

def debug(*msg):
    if config.DEBUG_FLAG:
        sys.stdout.write(f"[DEBUG]: {' '.join(str(item) for item in msg)}\n")

def warn(*msg):
    sys.stdout.write(f"[WARNING]: {''.join(str(item) for item in msg)}\n")

def log(*msg):
    print(*msg)

def remove_comments_and_newlines(input_string):
    # Remove single-line comments (// ...)
    input_string = re.sub(r'\/\/[^\n]*', '', input_string)

    # Remove multi-line comments (/* ... */)
    input_string = re.sub(r'\/\*[\s\S]*?\*\/', '', input_string)

    # Remove newline symbols and extra whitespaces
    input_string = re.sub(r'\n|\r|\s+', '', input_string)

    return input_string

def cut_string(input_string, last_element, max_length=1000):
    if not input_string:
        return ""

    last_plus_index = input_string[:max_length].rfind(last_element)

    if last_plus_index != -1:
        return input_string[:last_plus_index]

    return input_string[:max_length]

def count_lines_of_code(code_file, ignore_comments_spaceline=False):
    with open(code_file, 'r') as file:
        lines = file.readlines()

    if not ignore_comments_spaceline:
        return len(lines)

    code_lines = 0
    in_multiline_comment = False
    for line in lines:
        line = line.strip()
        if not line:
            continue

        if line in ["{", "}"]:
            continue
        if line.startswith('//'):
            continue
        if line.startswith('/*'):
            in_multiline_comment = True
        if line.endswith('*/'):
            in_multiline_comment = False
            continue
        if in_multiline_comment:
            continue
        code_lines += 1

    return code_lines

def replace_path_ext(input_path, new_ext):
    return os.path.splitext(input_path)[0] + new_ext

def generate_method_signature(method_info):
    return ""

def calc_path_distance(path1, path2):
    # Split the paths into components
    components1 = path1.split('/')
    components2 = path2.split('/')

    # Count the differing components
    length = max(len(components1), len(components2))

    distance = 0
    for i in range(length):
        if i >= len(components1) or i >= len(components2) or components1[i] != components2[i]:
            distance += 1

    return distance

FIRST_VAR_CHARS = {"%", "@", "$", "_"}
def is_variable(name):
    if isinstance(name, str) and len(name) > 0:
        # TODO: 程序中的关键字不能作为变量名。但因编程语言而异，此处排除了python中的关键字。
        if keyword.iskeyword(name) and name not in ["as", "is"]:
            return False
        first_char = name[0]
        if first_char in FIRST_VAR_CHARS or first_char.isalpha():
            return True

    return False

def is_quoted_properly(s):
    if isinstance(s, (int, np.int64)):
        return False
    if len(s) < 2:  # 如果字符串长度小于2，无法成对出现引号
        return False
    return (s[0] == s[-1]) and (s[0] in ("'", '"'))

def remove_outer_quotes(s):
    if (s.startswith("'") and s.endswith("'")) or (s.startswith('"') and s.endswith('"')):
        return s[1:-1]
    return s

def merge_list(first, second):
    return list(dict.fromkeys(first + second))

class SimpleEnum:
    def __init__(self, args):
        self._members = {}
        self._reverse_lookup = {}
        if isinstance(args, list):
            # Initialization from list
            for i, name in enumerate(args):
                self._members[name] = i
                self._reverse_lookup[i] = name
                setattr(self, name, i)
        elif isinstance(args, dict):
            # Initialization from dictionary
            for name, value in args.items():
                self._members[name] = value
                self._reverse_lookup[value] = name  # Assuming the values are unique and hashable
                setattr(self, name, value)

    def __getitem__(self, value):
        return self._reverse_lookup[value]

    def reverse(self, value):
        return self._reverse_lookup[value]

    def __getattr__(self, item):
        return self._members[item]

    def __contains__(self, name):
        return name in self._reverse_lookup

    def __iter__(self):
        return iter(self._reverse_lookup)

    def __repr__(self):
        return f"SimpleEnum({self._members})"

    def map(self, name):
        return self._members[name]


def graph_predecessors(graph, node):
    if node in graph.nodes():
        return list(graph.predecessors(node))
    return []

def graph_successors(graph, node):
    if node in graph:
        return list(graph.successors(node))
    return []

def graph_successors_with_weight(graph, node, weight):
    """
    返回图中指定节点具有指定权重的后继节点列表。

    参数:
    - graph: networkx.DiGraph 或其他类型的图
    - node: 要查询的节点
    - weight: 边的权重值

    返回:
    - list: 所有出边权重等于 weight 的后继节点列表
    """
    if node not in graph:
        return []

    external_successors = []
    for neighbor, data in graph[node].items():
        if data.get('weight') == weight:
            external_successors.append(neighbor)
    return external_successors

def graph_successors_with_edge_attrs(graph, node, attr_dict: dict):
    """
    返回图中指定节点具有指定属性边的后继节点列表。

    参数:
    - graph: networkx.DiGraph 或其他类型的图
    - node: 要查询的节点
    - attr_dict: {边的属性字段: 属性值}

    返回:
    - list: 满足attr_dict的二元组(出边, 后继节点)的列表
    """
    if node not in graph:
        return []
    successors = []
    for neighbor, data in graph[node].items():
        matched = True
        for key, value in attr_dict.items():
            # 只要有一个属性不满足，就匹配失败
            if data.get(key) != value:
                matched = False
                break
        if matched:
            successors.append((data, neighbor))
    return successors

def get_graph_edge_weight(graph: nx.DiGraph, src_stmt, dst_stmt):
    if type(src_stmt) in (int, np.int64):
        src_stmt_id = src_stmt
    else:
        src_stmt_id = src_stmt.stmt_id

    if type(dst_stmt) in (int, np.int64):
        dst_stmt_id = dst_stmt
    else:
        dst_stmt_id = dst_stmt.stmt_id

    edge_data = graph.get_edge_data(src_stmt_id, dst_stmt_id)
    if edge_data is not None:
        weight = edge_data.get('weight', None)
        return weight
    else:
        return None

def find_cfg_last_nodes(graph):
    leaf_stmts = set()
    for stmt, out_degree in graph.out_degree():
        if out_degree == 0:
            leaf_stmts.add(stmt)

    if -1 in leaf_stmts:
        leaf_stmts.remove(-1)
        leaf_stmts.update(graph_predecessors(graph, -1))
    return list(leaf_stmts)

def find_cfg_first_nodes(graph):
    root_stmts = []
    for stmt, in_degree in graph.in_degree():
        if in_degree == 0:
            root_stmts.append(stmt)

    return root_stmts

def list_to_dict_with_index(array):
    result = {}
    for index, key in enumerate(array):
        result[key] = index
    return result

def find_graph_nodes_with_zero_in_degree(graph):
    results = set()
    for node, in_degree in graph.in_degree():
        if in_degree == 0:
            results.add(node)
    return results

def find_graph_nodes_with_zero_out_degree(graph):
    results = set()
    for node, out_degree in graph.out_degree():
        if out_degree == 0:
            results.add(node)
    return results

def find_graph_nodes_with_available_out_degree(graph):
    all_nodes = set(graph.nodes())
    leaves = find_graph_nodes_with_zero_out_degree(graph)
    return all_nodes - leaves

def map_index_to_new_index(old_indexes, old_index_to_new_index):
    is_list = True
    new_indexes = []
    if isinstance(old_indexes, (int, np.int64)):
        return old_index_to_new_index.get(old_indexes, old_indexes)

    if isinstance(old_indexes, set):
        is_list = False
        new_indexes = set()

    for index in old_indexes:
        new_index = old_index_to_new_index.get(index, index)
        if is_list:
            new_indexes.append(new_index)
        else:
            new_indexes.add(new_index)
    return new_indexes

class CacheNode:
    def __init__(self, _id, _data):
        self._id = _id
        self._data = _data
        self.prev = None
        self.next = None

class LRUCache:
    def __init__(self, capacity):
        self.capacity = capacity
        self.cache = {}
        self.head = CacheNode(-1, None)
        self.tail = CacheNode(-1, None)
        self.head.next = self.tail
        self.tail.prev = self.head

    def get(self, _id):
        if _id in self.cache:
            node = self.cache[_id]
            self._remove_node(node)
            self._add_node(node)
            return node._data
        return None

    def contain(self, _id):
        return _id in self.cache

    def put(self, _id, _data):
        if _id in self.cache:
            self._remove_node(self.cache[_id])
        node = CacheNode(_id, _data)
        self._add_node(node)
        self.cache[_id] = node
        if len(self.cache) > self.capacity:
            removed_node = self.head.next
            self._remove_node(removed_node)
            del self.cache[removed_node._id]

    def remove(self, _id):
        if _id in self.cache:
            self._remove_node(self.cache[_id])
            del self.cache[_id]

    def _remove_node(self, node):
        prev_node = node.prev
        next_node = node.next
        prev_node.next = next_node
        next_node.prev = prev_node

    def _add_node(self, node):
        last_node = self.tail.prev
        last_node.next = node
        self.tail.prev = node
        node.prev = last_node
        node.next = self.tail

    def clean(self):
        self.cache = {}
        self.head = CacheNode(-1, None)
        self.tail = CacheNode(-1, None)
        self.head.next = self.tail
        self.tail.prev = self.head


def read_stmt_field(stmt_field, default=""):
    if isna(stmt_field):
        return default
    return stmt_field

def add_to_dict_with_default_set(d, key, value):
    if key not in d:
        d[key] = set()
    else:
        if d[key] is None:
            d[key] = set()

    if isinstance(value, (set, list)):
        d[key].update(value)
    else:
        d[key].add(value)

def add_to_dict_with_default_list(d, key, value):
    if key not in d:
        d[key] = []
    else:
        if d[key] is None:
            d[key] = []

    if isinstance(value, (set, list)):
        d[key].extend(value)
    else:
        print(d, key, d[key])
        d[key].append(value)

def add_to_list_with_default_set(l: list, index, value):
    if index < 0 and index + len(l) < 0:
        return False

    if index >= len(l):
        l.extend([set() for _ in range(index + 1 - len(l))])
    elif l[index] is None:
        l[index] = set()

    if isinstance(value, (set, list)):
        l[index].update(value)
    else:
        l[index].add(value)
    return True

def str_to_int(s):
    try:
        num = float(s)
        if num.is_integer():
            return int(num)
        else:
            return None
    except ValueError:
        return None

def process_string(s):
    if type(s) != str:
        return s
    s = re.sub(r'[\n\t\r]', '', s)

    special_chars = ['\\', '\"', "\'"]
    for char in special_chars:
        s = s.replace(char, f"\\{char}")

    return s
def determine_comment_line(lang_name, comment_start, lines):
        line_end = 0

        while comment_start > 0:
            line = lines[comment_start].lstrip()
            if lang_name == 'java':
                if  line.startswith('//') or line.startswith('/*') and line.endswith('*/'):
                    comment_start -= 1
                elif line.endswith("*/"):
                    line_end = 1
                    comment_start -= 1
                elif line.startswith("/*"):
                    line_end = 0
                    comment_start -= 1
                else:
                    if line_end == 0:
                        break
                    else:
                        comment_start -= 1
            elif lang_name == 'python':
                if  line.startswith('#'):
                    comment_start -= 1
                elif line.endswith("'''") and line.startswith("'''") and len(line)>5:
                    comment_start -= 1
                elif line.endswith('"""') and line.startswith('"""') and len(line)>5:
                    comment_start -= 1
                elif line.endswith("'''") or line.endswith('"""'):
                    if line_end == 0:
                        line_end = 1
                        comment_start -= 1
                    else:
                        line_end = 0
                        comment_start -= 1
                elif line.startswith("'''") or line.startswith('"""'):
                    # 处理多行字符串注释
                    line_end = 0
                    comment_start -= 1
                else:
                    if line_end == 0:
                        break
                    else:
                        comment_start -= 1

        return comment_start + 1

def int_to_bytes(v: int) -> bytes:
    """for serializing big int"""
    if v == 0 or v is None:
        return b'\x00'
    length = (v.bit_length() + 7) // 8
    return v.to_bytes(length, byteorder='big', signed=False)

def bytes_to_int(b: bytes) -> int:
    """for deserializing big int"""
    if b is None:
        return 0
    return int.from_bytes(b, byteorder='big', signed=False)

def check_file_processing_flag_and_extract_lang(file_name, requirement):
    processing_flag = False
    default_lang = ""
    if file_name == requirement:
        processing_flag = True
    elif file_name.endswith("-" + requirement):
        default_lang = file_name.split("-")[0]
        processing_flag = True
        if len(default_lang) == 0:
            error("Invalid entry point file name: " + file_name)
            processing_flag = False
    return (processing_flag, default_lang)

class FakeSpace:
    def __init__(self, space):
        self.space = space

    def to_dict(self, _id = 0):
        return self.space

def replace_weight_to_label_in_dot(file_name):
    with open(file_name, 'r') as file:
        lines = file.readlines()

    for i, line in enumerate(lines):
        if ', weight=' in line:
            lines[i] = line.replace(', weight=', ', label=')

    with open(file_name, 'w') as file:
        file.writelines(lines)

def access_path_formatter(access_path):
    if isinstance(access_path, str):
        return access_path

    parts = []
    for p in access_path:
        key_value = getattr(p, 'key', p)
        parts.append(str(key_value))
    return ".".join(parts)
