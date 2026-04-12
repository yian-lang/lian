#!/usr/bin/env python3
from collections import namedtuple
import json
import math
import os
import ast
import re

import networkx as nx
import pprint
import numpy
from bisect import insort

import pandas as pd
from dataclasses import dataclass

from lian.util.data_model import DataModel
from lian.config import schema
from lian.util import util
from lian.util import readable_gir
from lian.config import config
from lian.taint.rule_manager import RuleManager, Rule
from lian.config.constants import (
    IMPORT_GRAPH_EDGE_KIND,
    SYMBOL_OR_STATE,
    LIAN_SYMBOL_KIND,
    GIR_COLUMNS_TO_BE_ADDED,
    ANALYSIS_PHASE_ID,
)
from lian.common_structs import (
    BasicGraph,
    CallSite,
    State,
    StateDefNode,
    Symbol,
    ControlFlowGraph,
    SymbolDefNode,
    SymbolGraph,
    StmtStatus,
    SymbolStateSpace,
    BitVectorManager,
    CallGraph,
    UnitSymbolDeclSummary,
    MethodDefUseSummary,
    MethodSummaryTemplate,
    MethodInternalCallee,
    SimplyGroupedMethodTypes,
    ParameterMapping,
    AccessPoint,
    MethodSummaryInstance,
    MethodInClass,
    CallPath,
    SymbolNodeInImportGraph,
    TypeNode,
    StateFlowGraph,
    SFGNode,
    SFGEdge,
    CallSite,
)

def json_dict_value_list_to_set_hook(d):
    # 遍历字典的每个 value
    for key, value in d.items():
        if isinstance(value, list):
            d[key] = set(value)
    return d

@dataclass
class ActiveItem:
    flattened_item: DataModel
    data_model: dict

class ModuleSymbolsLoader:
    """
    This loader is used to manage module information, including directories and files.
    """
    def __init__(self, options, path):
        self.options = options
        self.path = path
        self.module_symbol_table = None
        #self.cache = util.LRUCache(capacity = config.TMP_UNIT_INFO_CACHE_CAPABILITY)
        self.init_self()

    def init_self(self):
        self.module_id_to_module_info = {}
        self.unit_id_to_lang = {}
        self.module_name_to_module_ids = {}
        self.module_id_to_children_ids = {}
        self.module_unit_ids = set()
        self.all_module_ids = set()
        self.module_dir_ids = set()
        self.unit_path_to_id = {}
        self.unit_id_to_path = {}

    def save(self, module_symbol_results):
        self.module_symbol_table = DataModel(module_symbol_results)
        self._do_cache()

    def restore(self):
        self.module_symbol_table = DataModel().load(self.path)
        self._do_cache()

    def _do_cache(self):
        assert self.module_symbol_table is not None

        self.init_self()

        for row in self.module_symbol_table:
            module_id = row.module_id

            if row.symbol_type == LIAN_SYMBOL_KIND.UNIT_SYMBOL:
                self.module_unit_ids.add(module_id)

            # cache all module ids
            self.all_module_ids.add(module_id)

            # cache all lines
            self.module_id_to_module_info[module_id] = row

            # cache module_name_to_module_ids
            if row.symbol_name not in self.module_name_to_module_ids:
                self.module_name_to_module_ids[row.symbol_name] = set()
            self.module_name_to_module_ids[row.symbol_name].add(module_id)

            # cache unit_id_to_lang
            if util.is_available(row.lang):
                self.unit_id_to_lang[module_id] = row.lang

            # cache module_id_to_children_ids
            if row.parent_module_id not in self.module_id_to_children_ids:
                self.module_id_to_children_ids[row.parent_module_id] = set()
            self.module_id_to_children_ids[row.parent_module_id].add(module_id)

            # cache unit_path_to_id and unit_id_to_path
            if util.is_available(row.unit_path) and row.symbol_type == LIAN_SYMBOL_KIND.UNIT_SYMBOL:
                self.unit_path_to_id[row.unit_path] = module_id
                self.unit_id_to_path[module_id] = row.unit_path

        self.module_dir_ids = self.all_module_ids - self.module_unit_ids

    def export(self):
        if util.is_available(self.module_symbol_table):
            self.module_symbol_table.save(self.path)

    def is_module_id(self, module_id):
        return module_id in self.all_module_ids

    def is_unit_id(self, unit_id):
        return unit_id in self.module_unit_ids

    def is_module_dir_id(self, module_dir_id):
        return module_dir_id in self.module_dir_ids

    def get_all_module_ids(self):
        return self.all_module_ids

    def get_module_symbol_table(self):
        return self.module_symbol_table

    def convert_unit_id_to_unit_lang_name(self, unit_id):
        return self.unit_id_to_lang.get(unit_id, "unknown")

    def convert_module_id_to_module_info(self, module_id):
        return self.module_id_to_module_info.get(module_id, None)

    def convert_module_id_to_child_ids(self, module_id):
        return self.module_id_to_children_ids.get(module_id, set())

    def get_all_unit_info(self):
        assert self.module_symbol_table is not None
        if len(self.module_symbol_table) == 0:
            return []

        all_units = self.module_symbol_table.query_index_column_value("symbol_type", LIAN_SYMBOL_KIND.UNIT_SYMBOL)
        if len(all_units) == 0:
            return []

        all_units = all_units.slow_query(all_units.unit_ext.isin(self.options.lang_extensions))
        if len(all_units) == 0:
            return []
        
        if hasattr(self.options, "benchmark") and self.options.benchmark:
            all_units = all_units.slice(0, config.MAX_BENCHMARK_FILES)

        return all_units
    
    def get_all_unit_ids(self):
        unit_ids = set()
        for each_unit in self.get_all_unit_info():
            unit_ids.add(each_unit.module_id)
        return unit_ids

    def convert_unit_path_to_unit_id(self, unit_path):
        if not unit_path:
            return -1
        for path in  self.unit_path_to_id:
            if path and path.endswith(unit_path):
                return self.unit_path_to_id[path]
        return -1

    def convert_unit_id_to_unit_path(self, unit_id):
        return self.unit_id_to_path.get(unit_id, None)

class GeneralLoader:
    """
    This loader is a general loader template. For child classes, they should implement the following methods:
    1. query_flattened_item_when_loading: when loading data from storage to memory, query the item from the bundle data
    2. unflatten_item_dataframe_when_loading: when loading data from storage to memory, unflatten the item dataframe to restore its original structure
    3. flatten_item_when_saving: when saving data from memory to storage, flatten the item content

    Arguments:
        options: the options of Lian
        item_schema: the schema of the item
        bundle_path_summary: the summary of the bundle path
        item_cache_capacity: the capacity of the item cache
        bundle_cache_capacity: the capacity of the bundle cache

    Methods:
        get: load the item from the storage
        save: save the item to the living bundle
        export: export the items in the living bundle to the storage
    """
    def __init__(self, options, item_schema, bundle_path_summary, item_cache_capacity, bundle_cache_capacity):
        # use this to find the path of the corresponding bundle
        self.options = options
        self.item_schema = item_schema
        self.bundle_path_summary = bundle_path_summary
        self.loader_indexing_path = f"{self.bundle_path_summary}.{config.LOADER_INDEXING_PATH}"

        # caching cfg of method_a/symbol_graph of method_b/
        self.item_cache = util.LRUCache(item_cache_capacity)
        # caching dead cfg_bundle/symbol_graph_bundle...
        self.bundle_cache = util.LRUCache(bundle_cache_capacity)
        # active bundle of item1, item2 ...
        self.active_bundle = {}
        self.active_bundle_length = 0
        self.item_id_to_bundle_id = {}
        self.bundle_count = 0

    def query_flattened_item_when_loading(self, item_id, bundle_data):
        return None

    def unflatten_item_dataframe_when_loading(self, _id, item_df):
        return item_df

    def flatten_item_when_saving(self, _id, item_content):
        return None

    def convert_active_bundle_to_dataframe(self):
        accumulated_rows = []
        for key in sorted(self.active_bundle.keys()):
            value = self.active_bundle[key]
            accumulated_rows.extend(value.flattened_item)

        return DataModel(accumulated_rows, columns=self.item_schema)

    def get_bundle_path(self, bundle_id):
        return f"{self.bundle_path_summary}.bundle{bundle_id}"

    def new_bundle_id(self):
        result = self.bundle_count
        self.bundle_count += 1
        return result
    
    def contain(self, _id):
        return _id in self.item_id_to_bundle_id

    def get_raw_item_by_id(self, _id):
        if self.item_cache.contain(_id):
            return self.item_cache.get(_id)

        bundle_id = self.item_id_to_bundle_id.get(_id, None)
        if bundle_id is None:
            return None

        if bundle_id == -1:
            # the item should be in the active bundle at this moment
            result = self.active_bundle.get(_id, None)
            if util.is_available(result):
                if result.data_model is None:
                    result.data_model = DataModel(result.flattened_item, columns=self.item_schema)
                dm = result.data_model
                self.item_cache.put(_id, dm)
                return dm
            return None

        # read this item from existing bundles
        bundle_data = None
        if self.bundle_cache.contain(bundle_id):
            bundle_data = self.bundle_cache.get(bundle_id)
        else:
            bundle_path = self.get_bundle_path(bundle_id)
            bundle_data = DataModel().load(bundle_path)
            self.bundle_cache.put(bundle_id, bundle_data)

        item_df = self.query_flattened_item_when_loading(_id, bundle_data)
        self.item_cache.put(_id, item_df)
        return item_df 
    
    def get_item_by_id(self, _id):        
        item_df = self.get_raw_item_by_id(_id)
        if not isinstance(item_df, DataModel):
            return item_df
        return self.unflatten_item_dataframe_when_loading(_id, item_df)

    def get_all(self):
        all_results = {}
        for item_id in self.item_id_to_bundle_id:
            all_results[item_id] = self.get_raw_item_by_id(item_id)
        return all_results

    def remove_unit_id(self, _id):
        self.item_cache.remove(_id)
        if _id in self.item_id_to_bundle_id:
            bundle_id = self.item_id_to_bundle_id[_id]
            del self.item_id_to_bundle_id[_id]

            if bundle_id == -1:
                # in active bundle
                del self.active_bundle[_id]
            else:
                # in storage
                self.bundle_cache.remove(bundle_id)
                bundle_path = self.get_bundle_path(bundle_id)
                bundle_data = DataModel().load(bundle_path)
                bundle_data.remove_rows("unit_id", _id)
                bundle_data.save(bundle_path)

    def save(self, _id, item_content):
        flattened_item = self.flatten_item_when_saving(_id, item_content)
        #self.item_cache.put(_id, flattened_item)
        self.active_bundle[_id] = ActiveItem(flattened_item = flattened_item, data_model = None)
        self.item_id_to_bundle_id[_id] = -1
        self.active_bundle_length += len(flattened_item)
        if self.active_bundle_length > config.MAX_ROWS:
            self.export()
        return item_content

    def export(self):
        if self.active_bundle_length > 0:
            new_bundle_id = self.new_bundle_id()
            bundle_df = self.convert_active_bundle_to_dataframe()
            bundle_path = f"{self.bundle_path_summary}.bundle{new_bundle_id}"
            bundle_df.save(bundle_path)

            self.bundle_cache.put(new_bundle_id, bundle_df)
            for item_id, bundle_id in self.item_id_to_bundle_id.items():
                if bundle_id == -1:
                    self.item_id_to_bundle_id[item_id] = new_bundle_id

            self.active_bundle = {}
            self.active_bundle_length = 0

        #self.item_cache.clean()

    def export_indexing(self):
        results = []
        for (key, value) in self.item_id_to_bundle_id.items():
            results.append([key, value])

        DataModel(results, columns = schema.loader_indexing_schema).save(self.loader_indexing_path)

    def restore_indexing(self):
        if not os.path.exists(self.loader_indexing_path):
            return

        df = DataModel().load(self.loader_indexing_path)
        for row in df:
            data = row.raw_data()
            # TODO
            #  TEMPORARY FIX, EXPECTED TO BE IMPROVED LATER
            #  This is due to pandas feather format saving tuples but loading numpy.ndarray
            try:
                self.item_id_to_bundle_id[data[0]] = data[1]
                self.bundle_count = max(self.bundle_count, data[1] + 1)
            except TypeError:
                key_tuple = tuple(data[0])
                self.item_id_to_bundle_id[key_tuple] = data[1]
                self.bundle_count = max(self.bundle_count, data[1] + 1)


class UnitLevelLoader(GeneralLoader):
    """
    This loader is used to manage unit-level data content
    """
    def query_flattened_item_when_loading(self, unit_id, bundle_data):
        flattened_item = bundle_data.query_index_column_value("unit_id", unit_id)
        return flattened_item

    def flatten_item_when_saving(self, unit_id, item_content):
        results = []
        for item in item_content:
            to_dict_result = item
            if not isinstance(item, dict):
                to_dict_result = item.to_dict()
            if not hasattr(to_dict_result, "unit_id"):
                to_dict_result["unit_id"] = unit_id
            results.append(to_dict_result)
        return results

class UnitGIRLoader(UnitLevelLoader):
    def export(self):
        if self.active_bundle_length > 0:
            new_bundle_id = self.new_bundle_id()
            bundle_df = self.convert_active_bundle_to_dataframe()
            bundle_path = f"{self.bundle_path_summary}.bundle{new_bundle_id}"
            bundle_df.save(bundle_path)

            for item_id, bundle_id in self.item_id_to_bundle_id.items():
                if bundle_id == -1:
                    self.item_id_to_bundle_id[item_id] = new_bundle_id

            self.active_bundle = {}
            self.active_bundle_length = 0

class ScopeHierarchyLoader(UnitLevelLoader):
    pass

class UnitIDToExportSymbolsLoader(UnitLevelLoader):
    def unflatten_item_dataframe_when_loading(self, _id, item_df):
        unit_export_symbol = {}
        for row in item_df:
            node = SymbolNodeInImportGraph(
                scope_id=row.scope_id,
                symbol_type=row.symbol_type,
                symbol_id=row.symbol_id,
                symbol_name=row.symbol_name,
                unit_id=row.unit_id,
            )
            unit_export_symbol[row.symbol_name] = node
        return unit_export_symbol
    
class ClassIDToMethodInfoLoader(UnitLevelLoader):
    pass

class ClassIDToMembersLoader(UnitLevelLoader):
    def save_all(self, class_id_to_members:dict):
        for class_id in class_id_to_members:
            self.save(class_id, class_id_to_members[class_id])

    def flatten_item_when_saving(self, class_id, item_content):
        results = []
        for field_name in item_content:
            results.append({
                "class_id": class_id,
                "field_name": field_name,
                "field_states": list(item_content[field_name])
            })
        return results

    def unflatten_item_dataframe_when_loading(self, _id, item_df):
        field_name_to_states = {}
        for row in item_df:
            field_name_to_states[row.field_name] = set(row.field_states)
        return field_name_to_states
    # def save(self, class_id, class_members_dict:dict):
    #     class_members_series = pd.Series(class_members_dict, dtype = object)
    #     class_members_df = DataModel(class_members_series, columns=["members"])
    #     self.item_cache.put(class_id, class_members_df)
    #
    #     self.active_bundle[class_id] = (class_members_df, class_members_dict)
    #     self.item_id_to_bundle_id[class_id] = -1
    #     self.active_bundle_length += len(class_members_dict)
    #
    #     if self.active_bundle_length > config.MAX_ROWS:
    #         self.export()
    #
    #     return class_members_df


class SymbolNameToScopeIDsLoader(GeneralLoader):
    def query_flattened_item_when_loading(self, unit_id, bundle_data):
        flattened_item = bundle_data.query_index_column_value("unit_id", unit_id)
        return flattened_item

    def flatten_item_when_saving(self, unit_id, symbol_name_to_scope_ids):
        results = []
        for symbol_name in symbol_name_to_scope_ids:
            results.append({
                "unit_id": unit_id,
                "symbol_name": symbol_name,
                "scope_ids": list(symbol_name_to_scope_ids[symbol_name])
            })
        return results

    def unflatten_item_dataframe_when_loading(self, _id, item_df):
        symbol_name_to_scope_ids = {}
        for row in item_df:
            symbol_name_to_scope_ids[row.symbol_name] = set(row.scope_ids)
        return symbol_name_to_scope_ids

class ScopeIDToSymbolInfoLoader(GeneralLoader):
    def query_flattened_item_when_loading(self, unit_id, bundle_data):
        flattened_item = bundle_data.query_index_column_value("unit_id", unit_id)
        return flattened_item

    def flatten_item_when_saving(self, unit_id, scope_id_to_symbol_info):
        results = []
        for scope_id in scope_id_to_symbol_info:
            symbol_names = []
            symbol_stmt_ids = []
            value = scope_id_to_symbol_info[scope_id]
            for name in sorted(value.keys()):
                symbol_names.append(name)
                symbol_stmt_ids.append(value[name])

            results.append({
                "unit_id": unit_id,
                "scope_id": scope_id,
                "symbol_names": symbol_names,
                "symbol_stmt_ids": symbol_stmt_ids
            })

        return results

    def unflatten_item_dataframe_when_loading(self, _id, item_df):
        scope_id_to_symbol_info = {}
        for row in item_df:
            results = {}
            for index, name in enumerate(row.symbol_names):
                results[name] = row.symbol_stmt_ids[index]
            scope_id_to_symbol_info[row.scope_id] = results
        return scope_id_to_symbol_info

class ScopeIDToAvailableScopeIDsLoader(GeneralLoader):
    def query_flattened_item_when_loading(self, unit_id, bundle_data):
        flattened_item = bundle_data.query_index_column_value("unit_id", unit_id)
        return flattened_item

    def flatten_item_when_saving(self, unit_id, scope_id_to_available_scope_ids):
        results = []
        for scope_id in scope_id_to_available_scope_ids:
            results.append({
                "unit_id": unit_id,
                "scope_id": scope_id,
                "available_scope_ids": list(scope_id_to_available_scope_ids[scope_id])
            })
        return results

    def unflatten_item_dataframe_when_loading(self, _id, item_df):
        scope_id_to_available_scope_ids = {}
        for row in item_df:
            scope_id_to_available_scope_ids[row.scope_id] = set(row.available_scope_ids)
        return scope_id_to_available_scope_ids

class UnitSymbolDeclSummaryLoader:
    def __init__(self, symbol_name_to_scope_ids_loader, scope_id_to_symbol_info_loader, scope_id_to_available_scope_ids_loader):
        self.symbol_name_to_scope_ids_loader = symbol_name_to_scope_ids_loader
        self.scope_id_to_symbol_info_loader = scope_id_to_symbol_info_loader
        self.scope_id_to_available_scope_ids_loader = scope_id_to_available_scope_ids_loader

    def get(self, unit_id):
        return UnitSymbolDeclSummary(
            unit_id,
            self.symbol_name_to_scope_ids_loader.get_item_by_id(unit_id),
            self.scope_id_to_symbol_info_loader.get_item_by_id(unit_id),
            self.scope_id_to_available_scope_ids_loader.get_item_by_id(unit_id)
        )

    def save(self, unit_id, summary: UnitSymbolDeclSummary):
        self.symbol_name_to_scope_ids_loader.save(unit_id, summary.symbol_name_to_scope_ids)
        self.scope_id_to_symbol_info_loader.save(unit_id, summary.scope_id_to_symbol_info)
        self.scope_id_to_available_scope_ids_loader.save(unit_id, summary.scope_id_to_available_scope_ids)

    def export(self):
        self.symbol_name_to_scope_ids_loader.export()
        self.scope_id_to_symbol_info_loader.export()
        self.scope_id_to_available_scope_ids_loader.export()

class StmtIDToScopeIDLoader:
    def __init__(self, path):
        self.stmt_id_to_scope_id = {}
        self.path = path

    def save(self, stmt_id_to_scope_id):
        if len(stmt_id_to_scope_id) == 0:
            return
        self.stmt_id_to_scope_id.update(stmt_id_to_scope_id)

    def get(self, stmt_id):
        return self.stmt_id_to_scope_id.get(stmt_id, -1)

    def export(self):
        if len(self.stmt_id_to_scope_id) == 0:
            return
        results = []
        for (stmt_id, scope_id) in self.stmt_id_to_scope_id.items():
            results.append([stmt_id, scope_id])
        DataModel(results, columns = schema.stmt_id_to_scope_id_schema).save(self.path)

    def restore(self):
        df = DataModel().load(self.path)
        for row in df:
            stmt_id = row.stmt_id
            scope_id = row.scope_id
            self.stmt_id_to_scope_id[stmt_id] = scope_id

class SymbolNameToDeclIDsLoader(GeneralLoader):
    def query_flattened_item_when_loading(self, unit_id, bundle_data):
        flattened_item = bundle_data.query_index_column_value("unit_id", unit_id)
        return flattened_item

    def flatten_item_when_saving(self, unit_id, symbol_name_to_decl_ids):
        results = []
        for symbol_name in symbol_name_to_decl_ids:
            results.append({
                "unit_id": unit_id,
                "symbol_name": symbol_name,
                "decl_ids": list(symbol_name_to_decl_ids[symbol_name])
            })
        return results

    def unflatten_item_dataframe_when_loading(self, _id, item_df):
        symbol_name_to_scope_ids = {}
        for row in item_df:
            symbol_name_to_scope_ids[row.symbol_name] = set(row.decl_ids)
        return symbol_name_to_scope_ids

class CallStmtIDToCallFormatInfoLoader:
    def __init__(self, path):
        self.call_stmt_id_to_call_format_info = {}
        self.path = path

    def get_map_call_stmt_id_to_call_format_info(self):
        return self.call_stmt_id_to_call_format_info

    def save(self, call_stmt_id, call_format_info):
        self.call_stmt_id_to_call_format_info[call_stmt_id] = call_format_info

    def get(self, call_stmt_id):
        return self.call_stmt_id_to_call_format_info.get(call_stmt_id, None)

    def export(self):
        if len(self.call_stmt_id_to_call_format_info) == 0:
            return

        results = []
        for (stmt_id, call_format_info) in self.call_stmt_id_to_call_format_info.items():
            results.append(call_format_info)
        DataModel(results).save(self.path)

    def restore(self):
        df = DataModel().load(self.path)
        for row in df:
            self.call_stmt_id_to_call_format_info[row.stmt_id] = row

class MethodIDToMethodDeclFormatLoader:
    def __init__(self, path):
        self.method_id_to_method_decl_format = {}
        self.path = path

    def save(self, method_id, method_decl_format):
        self.method_id_to_method_decl_format[method_id] = method_decl_format

    def get(self, method_id):
        return self.method_id_to_method_decl_format.get(method_id, None)

    def export(self):
        if len(self.method_id_to_method_decl_format) == 0:
            return

        results = []
        for (method_id, method_decl_format) in self.method_id_to_method_decl_format.items():
            results.append(method_decl_format)
        DataModel(results).save(self.path)

    def restore(self):
        df = DataModel().load(self.path)
        for row in df:
            self.method_id_to_method_decl_format[row.method_id] = row

class UnitIDToStmtIDLoader:
    def __init__(self, path):
        self.unit_id_to_stmt_ids = {}
        self.stmt_id_to_unit_id = {}
        self.path = path

    def save(self, unit_id, all_ids):
        if len(all_ids) == 0:
            return

        self.unit_id_to_stmt_ids[unit_id] = all_ids
        for stmt_id in all_ids:
            self.stmt_id_to_unit_id[stmt_id] = unit_id

    def get(self, stmt_id):
        return self.stmt_id_to_unit_id.get(stmt_id, -1)

    def convert_one_to_many(self, unit_id):
        return self.unit_id_to_stmt_ids.get(unit_id, [])

    def get_all_stmt_ids(self):
        return self.stmt_id_to_unit_id.keys()

    def get_all_unit_ids(self):
        return self.unit_id_to_stmt_ids.keys()

    def export(self):
        if len(self.unit_id_to_stmt_ids) == 0:
            return

        results = []
        for (unit_id, stmt_ids) in self.unit_id_to_stmt_ids.items():
            results.append([unit_id, min(stmt_ids), max(stmt_ids)])
        DataModel(results, columns = schema.unit_id_to_stmt_id_schema).save(self.path)

    def restore(self):
        df = DataModel().load(self.path)
        for row in df:
            unit_id = row.unit_id
            min_stmt_id = row.min_stmt_id
            max_stmt_id = row.max_stmt_id
            stmt_ids = range(min_stmt_id, max_stmt_id + 1)
            self.unit_id_to_stmt_ids[unit_id] = stmt_ids
            for stmt_id in stmt_ids:
                self.stmt_id_to_unit_id[stmt_id] = unit_id

class OneToManyMapLoader:
    def __init__(self, path, schema):
        self.path = path
        self.schema = schema
        self.one_to_many = {}
        self.many_to_one = {}

    def save(self, one, many):
        if len(many) == 0:
            return

        if isinstance(many, set):
            many = list(many)

        self.one_to_many[one] = many

        if isinstance(many, (int, float, str)):
            self.many_to_one[many] = one
        else:
            for each_id in many:
                self.many_to_one[each_id] = one

    def convert_one_to_many(self, one):
        return self.one_to_many.get(one, [])

    def convert_many_to_one(self, item_in_many):
        return self.many_to_one.get(item_in_many, -1)

    def get_all_items_in_many(self):
        return self.many_to_one.keys()

    def get_all_items_in_one(self):
        return self.one_to_many.keys()

    def export(self):
        if len(self.one_to_many) == 0:
            return

        results = []
        for (one, many) in self.one_to_many.items():
            results.append([one, many])
        DataModel(results, columns = self.schema).save(self.path)

    def restore(self):
        df = DataModel().load(self.path)
        for row in df:
            one, many = row.raw_data()
            self.one_to_many[one] = many
            for item_in_many in many:
                self.many_to_one[item_in_many] = one

class UnitIDToMethodIDLoader(OneToManyMapLoader):
    def __init__(self, path):
        super().__init__(path, schema.unit_id_to_method_id_schema)

    def is_method_decl(self, stmt_id):
        return stmt_id in self.many_to_one

    def add_method_id_to_unit_id(self, method_id, unit_id):
        if unit_id in self.one_to_many:
            self.one_to_many[unit_id].append(method_id)
        else:
            self.one_to_many[unit_id] = [method_id]

        self.many_to_one[method_id] = unit_id

class ClassIdToNameLoader(OneToManyMapLoader):
    def __init__(self, path):
        super().__init__(path, schema.class_id_to_class_name_schema)

    def save(self, class_name, class_id):
        if class_name not in self.one_to_many:
            self.one_to_many[class_name] = set()
        self.one_to_many[class_name].add(class_id)
        self.many_to_one[class_id] = class_name

class MethodIDToMethodNameLoader(OneToManyMapLoader):
    def __init__(self, path):
        super().__init__(path, schema.method_id_to_method_name_schema)

    def save(self, method_name, method_id):
        if method_name not in self.one_to_many:
            self.one_to_many[method_name] = set()
        self.one_to_many[method_name].add(method_id)
        self.many_to_one[method_id] = method_name

class UnitIDToClassIDLoader(OneToManyMapLoader):
    def __init__(self, path):
        super().__init__(path, schema.unit_id_to_class_id_schema)

    def is_class_decl(self, stmt_id):
        return stmt_id in self.many_to_one
    
class ClassIDToStmtIDLoader(OneToManyMapLoader):
    def __init__(self, path):
        super().__init__(path, schema.class_id_to_stmt_id_schema)

class MethodIDToStmtIDLoader(OneToManyMapLoader):
    def __init__(self, path):
        super().__init__(path, schema.method_id_to_stmt_id_schema)

class UnitIDToNamespaceIDLoader(OneToManyMapLoader):
    def __init__(self, path):
        super().__init__(path, schema.unit_id_to_namespace_id_schema)

    def is_namespace_decl(self, stmt_id):
        return stmt_id in self.many_to_one

class UnitIDToVariableIDLoader(OneToManyMapLoader):
    def __init__(self, path):
        super().__init__(path, schema.unit_id_to_variable_ids_schema)

    def is_variable_decl(self, stmt_id):
        return stmt_id in self.many_to_one

class UnitIDToImportStmtIDLoader(OneToManyMapLoader):
    def __init__(self, path):
        super().__init__(path, schema.unit_id_to_import_stmt_id_schema)

    def is_import_stmt(self, stmt_id):
        return stmt_id in self.many_to_one

class MethodIDToParameterIDLoader(OneToManyMapLoader):
    def __init__(self, path):
        super().__init__(path, schema.method_id_to_parameter_id_schema)

    def is_parameter_decl(self, stmt_id):
        return stmt_id in self.many_to_one

    def is_parameter_decl_of_method(self, stmt_id, method_id):
        parameters = self.convert_one_to_many(method_id)
        return stmt_id in parameters

class ClassIDToMethodIDLoader(OneToManyMapLoader):
    def __init__(self, path):
        super().__init__(path, schema.class_id_to_method_id_schema)

    def is_method_decl(self, stmt_id):
        return stmt_id in self.many_to_one

    def is_method_decl_of_class(self, stmt_id, class_id):
        methods = self.convert_one_to_many(class_id)
        return stmt_id in methods

class ClassIDToFieldIDLoader(OneToManyMapLoader):
    def __init__(self, path):
        super().__init__(path, schema.class_id_to_field_id_schema)

    def is_field_decl(self, stmt_id):
        return stmt_id in self.many_to_one

    def is_field_decl_of_class(self, stmt_id, class_id):
        fields = self.convert_one_to_many(class_id)
        return stmt_id in fields

class ClassIDToMethodsLoader(OneToManyMapLoader):
    def __init__(self, path):
        super().__init__(path, schema.class_id_to_methods_schema)

    def save(self, class_id, methods):
        if len(methods) == 0:
            return

        if not isinstance(methods, list):
            return

        self.one_to_many[class_id] = methods
        for each_method in methods:
            self.many_to_one[each_method.stmt_id] = class_id

    def is_method_decl_of_class(self, method_stmt_id, class_id):
        if method_stmt_id in self.many_to_one:
            return self.many_to_one[method_stmt_id] == class_id
        return False

    def export(self):
        if len(self.one_to_many) == 0:
            return

        results = []
        for (class_id, methods) in self.one_to_many.items():
            for each_method in methods:
                results.append([
                    each_method.unit_id, each_method.class_id, each_method.name, each_method.stmt_id
                ])
        DataModel(results, columns = schema.class_id_to_methods_schema).save(self.path)

    def restore(self):
        df = DataModel().load(self.path)
        for row in df:
            unit_id, class_id, method_name, method_stmt_id = row.raw_data()
            method = MethodInClass(
                unit_id, class_id, method_name, method_stmt_id
            )
            self.many_to_one[method_stmt_id] = class_id
            if class_id not in self.one_to_many:
                self.one_to_many[class_id] = []
            self.one_to_many[class_id].append(method)

class ExternalSymbolIDCollectionLoader:
    def __init__(self, path):
        self.path = path
        self.method_id_to_external_symbol_id_collection = {}

    def save_external_symbol_id_collection(self, method_id, external_symbol_id_collection):
        results = set()
        if isinstance(external_symbol_id_collection, dict):
            for symbol_name, symbol_id in external_symbol_id_collection.items():
                results.add(symbol_id)
        elif isinstance(external_symbol_id_collection, list):
            results = set(external_symbol_id_collection)
        else:
            results = external_symbol_id_collection
        self.method_id_to_external_symbol_id_collection[method_id] = results

    def get_external_symbol_id_collection(self, method_id):
        return self.method_id_to_external_symbol_id_collection.get(method_id, {})

    def export(self):
        if len(self.method_id_to_external_symbol_id_collection) == 0:
            return
        results = []
        for (method_id, external_symbol_id_collection) in self.method_id_to_external_symbol_id_collection.items():
            results.append({
                'method_id': method_id,
                'external_symbol_id_collection': external_symbol_id_collection
            })
        DataModel(results).save(self.path)

    def restore(self):
        df = DataModel().load(self.path)
        for row in df:
            self.method_id_to_external_symbol_id_collection[row.method_id] = row.external_symbol_id_collection


class EntryPointsLoader:
    def __init__(self, path):
        self.path = path
        self.entry_points = set()

    def save(self, entry_points):
        self.entry_points |= set(entry_points)

    def get_entry_points(self):
        return self.entry_points

    def export(self):
        if len(self.entry_points) == 0:
            return
        DataModel([{
            'entry_points': list(self.entry_points)
        }]).save(self.path)

    def restore(self):
        df = DataModel().load(self.path)
        row = df.access(0)
        data = row.raw_data()
        self.entry_points = set(data[0])

class CFGLoader(GeneralLoader):
    def query_flattened_item_when_loading(self, method_id, bundle_data):
        flattened_item = bundle_data.query_index_column_value("method_id", method_id)
        return flattened_item

    def unflatten_item_dataframe_when_loading(self, method_id, item_df):
        cfg = ControlFlowGraph(method_id)
        for row in item_df:
            cfg.add_edge(row.src_stmt_id, row.dst_stmt_id, row.control_flow_type)
        return cfg.graph

    def flatten_item_when_saving(self, method_id, cfg: nx.DiGraph):
        edges = []
        old_edges = cfg.edges(data='weight', default = 0)
        for e in old_edges:
            edges.append((
                method_id,
                e[0],
                e[1],
                0 if util.is_empty(e[2]) else e[2]
            ))
        return edges

##############################################################
# The following is to deal with the results of basic analysis
##############################################################
class MethodLevelAnalysisResultLoader(GeneralLoader):
    def query_flattened_item_when_loading(self, _id, bundle_data):
        if type(_id) == tuple:
            flattened_item = bundle_data.query_index_column_value("hash_id", hash(_id))
        elif hasattr(_id, 'caller_id') and hasattr(_id, 'call_stmt_id') and hasattr(_id, 'callee_id'):
            flattened_item = bundle_data.query_index_column_value("hash_id", hash(_id))
        else:
            flattened_item = bundle_data.query_index_column_value("method_id", _id)
        return flattened_item

    def export_indexing(self):
        results = []
        for (key, value) in self.item_id_to_bundle_id.items():
            if isinstance(key, CallSite):
                serializable_key = key.to_tuple()
            else:
                serializable_key = key
            results.append([serializable_key, value])

        DataModel(results, columns = schema.loader_indexing_schema).save(self.loader_indexing_path)

    def restore_indexing(self):
        if not os.path.exists(self.loader_indexing_path):
            return

        df = DataModel().load(self.loader_indexing_path)
        for row in df:
            data = row.raw_data()
            key = data[0]
            if isinstance(key, list):
                key = tuple(key)
            if isinstance(key, tuple) and len(key) == 3:
                try:
                    key = CallSite(key[0], key[1], key[2])
                except (TypeError, IndexError):
                    pass
            try:
                self.item_id_to_bundle_id[key] = data[1]
                self.bundle_count = max(self.bundle_count, data[1] + 1)
            except TypeError:
                key = tuple(key)
                self.item_id_to_bundle_id[key] = data[1]
                self.bundle_count = max(self.bundle_count, data[1] + 1)

class BitVectorManagerLoader(MethodLevelAnalysisResultLoader):
    def unflatten_item_dataframe_when_loading(self, _id, flattened_item):
        manager = BitVectorManager()
        counter = 0
        id_to_bit_pos = {}
        bit_pos_to_id = {}
        for row in flattened_item:
            counter += 1
            bit_id = None
            if row.state_id:
                bit_id = StateDefNode(index = int(row.index), state_id = int(row.state_id), stmt_id = int(row.stmt_id))
            elif row.symbol_id:
                bit_id = SymbolDefNode(index = int(row.index), symbol_id = int(row.symbol_id), stmt_id = int(row.stmt_id))
            if not bit_id:
                continue
            bit_pos_to_id[int(row.bit_pos)] = bit_id
            id_to_bit_pos[bit_id] = int(row.bit_pos)
        manager.counter = counter
        manager.id_to_bit_pos = id_to_bit_pos
        manager.bit_pos_to_id = bit_pos_to_id
        return manager

    def flatten_item_when_saving(self, method_id, bit_vector_manager: BitVectorManager):
        return bit_vector_manager.to_dict(method_id)

class StmtStatusLoader(MethodLevelAnalysisResultLoader):
    def unflatten_item_dataframe_when_loading(self, method_id, flattened_item):
        stmt_to_status = {}
        for row in flattened_item:
            in_symbol_bits_list = json.loads(row.in_symbol_bits)
            new_in_symbol_bits_list = []
            for item in in_symbol_bits_list:
                new_in_symbol_bits_list.append(
                    SymbolDefNode(index = item["index"], symbol_id = item["symbol_id"], stmt_id = item["stmt_id"])
                )

            out_symbol_bits_list = json.loads(row.out_symbol_bits)
            new_out_symbol_bits_list = []
            for item in out_symbol_bits_list:
                new_out_symbol_bits_list.append(
                    SymbolDefNode(index = item["index"], symbol_id = item["symbol_id"], stmt_id = item["stmt_id"])
                )

            in_state_bits_list = json.loads(row.in_state_bits)
            new_in_state_bits_list = []
            for item in in_state_bits_list:
                new_in_state_bits_list.append(
                    StateDefNode(index = item["index"], state_id = item["state_id"], stmt_id = item["stmt_id"])
                )

            out_state_bits_list = json.loads(row.out_state_bits)
            new_out_state_bits_list = []
            for item in out_state_bits_list:
                new_out_state_bits_list.append(
                    StateDefNode(index = item["index"], state_id = item["state_id"], stmt_id = item["stmt_id"])
                )

            stmt_to_status[row.stmt_id] = \
                StmtStatus(
                    stmt_id = int(row.stmt_id),
                    defined_symbol = int(row.defined_symbol),
                    used_symbols = json.loads(row.used_symbols),
                    implicitly_defined_symbols = json.loads(row.implicitly_defined_symbols),
                    implicitly_used_symbols = json.loads(row.implicitly_used_symbols),
                    in_symbol_bits = set(new_in_symbol_bits_list),
                    out_symbol_bits = set(new_out_symbol_bits_list),
                    defined_states = set(json.loads(row.defined_states)),
                    in_state_bits = set(new_in_state_bits_list),
                    out_state_bits = set(new_out_state_bits_list),
                    field_name = row.field,
                )
        return stmt_to_status

    def flatten_item_when_saving(self, method_id, stmt_to_status: dict[int, StmtStatus]):
        all_status = []
        for _, status in stmt_to_status.items():
            record = status.to_dict(method_id)
            all_status.append(record)
        return all_status

class SymbolStateSpaceLoader(MethodLevelAnalysisResultLoader):
    def unflatten_item_dataframe_when_loading(self, _id, flattened_item):
        symbol_state_space = SymbolStateSpace()
        for row in flattened_item:
            if row.symbol_or_state == SYMBOL_OR_STATE.SYMBOL:
                item = Symbol(
                    stmt_id = row.stmt_id,
                    symbol_id = row.symbol_id,
                    source_unit_id = row.source_unit_id,
                    name = row.name,
                    default_data_type = row.default_data_type,
                    states = set(row.states),
                    symbol_or_state = row.symbol_or_state
                )
            else:
                access_path = []
                access_path_str_list = json.loads(row.access_path)
                for access_path_point in access_path_str_list:
                    access_path.append(
                        AccessPoint(
                            kind = access_path_point['kind'],
                            key = access_path_point['key'],
                            state_id = access_path_point['state_id']
                        )
                    )
                tangping_elements = json.loads(row.tangping_elements)
                if isinstance(tangping_elements, list):
                    tangping_elements = set(tangping_elements)
                item = State(
                    stmt_id = row.stmt_id,
                    data_type = row.data_type,
                    state_type = row.state_type,
                    state_id = row.state_id,
                    value = row.value,
                    fields = json.loads(row.fields, object_hook=json_dict_value_list_to_set_hook),
                    array = json.loads(row.array, object_hook=json_dict_value_list_to_set_hook),
                    tangping_flag = row.tangping_flag,
                    tangping_elements = tangping_elements,
                    access_path = access_path,
                    symbol_or_state = row.symbol_or_state
                )
            symbol_state_space.add(item)

        return symbol_state_space

    def flatten_item_when_saving(self, _id, symbol_state_space: SymbolStateSpace):
        return symbol_state_space.to_dict(_id)

# TODO: convert to memory
class CalleeParameterMapping(MethodLevelAnalysisResultLoader):
    def unflatten_item_dataframe_when_loading(self, _id, flattened_item):
        parameter_mapping_list = []
        for row in flattened_item:
            arg_access_path = []
            access_path_str_list = row.arg_access_path
            for access_path_point_str in access_path_str_list:
                if util.is_available(access_path_point_str):
                    access_path_point = ast.literal_eval(access_path_point_str)
                    arg_access_path.append(
                        AccessPoint(
                            kind = access_path_point['kind'],
                            key = access_path_point['key'],
                            state_id = access_path_point['state_id']
                        )
                    )

            parameter_access_point_str = row.parameter_access_path
            parameter_access_path = AccessPoint()
            if util.is_available(parameter_access_point_str):
                parameter_access_point = ast.literal_eval(parameter_access_point_str)
                parameter_access_path = AccessPoint(
                    kind = parameter_access_point['kind'],
                    key = parameter_access_point['key'],
                    state_id = parameter_access_point['state_id']
                )

            parameter_mapping_list.append(
                ParameterMapping(
                    arg_index_in_space = row.arg_index_in_space,
                    arg_state_id = row.arg_state_id,
                    arg_source_symbol_id = row.arg_source_symbol_id,
                    parameter_symbol_id = row.parameter_symbol_id,
                    arg_access_path = arg_access_path,
                    parameter_type = row.parameter_type,
                    parameter_access_path = parameter_access_path,
                    is_default_value = row.is_default_value,
                )
            )
        return parameter_mapping_list

    def flatten_item_when_saving(self, _id, parameter_mapping_list: list[ParameterMapping]):
        all_parameter_mapping = []
        for parameter_mapping in parameter_mapping_list:
            record = parameter_mapping.to_dict(_id)
            all_parameter_mapping.append(record)
        return all_parameter_mapping

class MethodDefUseSummaryLoader:
    def __init__(self, path):
        self.method_summary_records = {}
        self.path = path

    def get_copy(self, method_id):
        if method_id not in self.method_summary_records:
            return MethodDefUseSummary()
        return self.method_summary_records[method_id].copy()
    
    def get(self, method_id):
        return self.method_summary_records[method_id].get(method_id)

    def save(self, method_id, basic_method_summary: MethodDefUseSummary):
        self.method_summary_records[method_id] = basic_method_summary

    def restore(self):
        # read file and convert to self.all_method_def_use
        df = DataModel().load(self.path)
        for row in df:
            self.method_summary_records[row.method_id] = MethodDefUseSummary(
                row.method_id,
                row.parameter_symbol_ids,
                row.local_symbol_ids,
                row.defined_external_symbol_ids,
                row.used_external_symbol_ids,
                row.return_symbol_ids,
                row.this_symbol_id
            )

    def export(self):
        if len(self.method_summary_records) == 0:
            return

        results = []
        for method_id in sorted(self.method_summary_records.keys()):
            summary = self.method_summary_records[method_id]
            results.append(summary.to_dict())
        DataModel(results).save(self.path)

class MethodSummaryLoader:
    def __init__(self, path):
        self.method_summary_records = {}
        self.path = path

    def get(self, _id):
        return self.method_summary_records.get(_id)

    def save(self, _id, method_summary):
        self.method_summary_records[_id] = method_summary

    def convert_list_to_dict(self, l, method_summary=None):
        if l is None:
            return {}
        if len(l) == 0:
            return {}

        results = {}
        for item in l:
            key = item[0]
            raw_index = item[1]
            new_index = item[2]
            if len(item) > 3:
                default_value_symbol_id = item[3]
            else:
                default_value_symbol_id = -1

            if key not in results:
                results[key] = set()
            results[key].add(raw_index)

            if method_summary is not None:
                if new_index != -1 and new_index != raw_index:
                    method_summary.raw_to_new_index[raw_index] = new_index
                if default_value_symbol_id != -1:
                    method_summary.index_to_default_value[raw_index] = default_value_symbol_id

        return results

    def restore(self):
        # read file and convert to self.all_method_def_use
        df = DataModel().load(self.path)
        for row in df:
            if row.caller_id:
                method_instance = MethodSummaryInstance(
                    key = CallSite(row.caller_id, row.call_stmt_id, row.method_id),
                    parameter_symbols = {},
                    defined_external_symbols = {},
                    used_external_symbols = {},
                    return_symbols = {},
                    key_dynamic_content = {},
                    dynamic_call_stmts = row.dynamic_call_stmts,
                    this_symbols = {}
                )
                method_instance.parameter_symbols = self.convert_list_to_dict(row.parameter_symbols, method_instance)
                method_instance.defined_external_symbols = self.convert_list_to_dict(row.defined_external_symbols, method_instance)
                method_instance.used_external_symbols = self.convert_list_to_dict(row.used_external_symbol_ids, method_instance)
                method_instance.return_symbols = self.convert_list_to_dict(row.return_symbols, method_instance)
                method_instance.key_dynamic_content = self.convert_list_to_dict(row.key_dynamic_content, method_instance)
                method_instance.this_symbols = self.convert_list_to_dict(row.this_symbols, method_instance)
                self.method_summary_records[(row.caller_id, row.call_stmt_id, row.method_id)] = method_instance
            else:
                method_summary = MethodSummaryTemplate(
                    key = row.method_id,
                    parameter_symbols = {},
                    defined_external_symbols = {},
                    used_external_symbols = {},
                    return_symbols = {},
                    key_dynamic_content = {},
                    dynamic_call_stmts = row.dynamic_call_stmts,
                    this_symbols = {}
                )
                method_summary.parameter_symbols = self.convert_list_to_dict(row.parameter_symbols, method_summary)
                method_summary.defined_external_symbols = self.convert_list_to_dict(row.defined_external_symbols, method_summary)
                method_summary.used_external_symbols = self.convert_list_to_dict(row.used_external_symbol_ids, method_summary)
                method_summary.return_symbols = self.convert_list_to_dict(row.return_symbols, method_summary)
                method_summary.key_dynamic_content = self.convert_list_to_dict(row.key_dynamic_content, method_summary)
                method_summary.this_symbols = self.convert_list_to_dict(row.this_symbols, method_summary)
                self.method_summary_records[row.method_id] = method_summary

    def export(self):
        if len(self.method_summary_records) == 0:
            return

        results = []
        for method_id in sorted(self.method_summary_records.keys()):
            summary = self.method_summary_records[method_id]
            results.append(summary.to_dict())
        DataModel(results).save(self.path)

class MethodInternalCalleesLoader:
    def __init__(self, path):
        self.path = path
        self.method_internal_callees_records = {}

    def get(self, method_id):
        return self.method_internal_callees_records.get(method_id)

    def save(self, method_id, method_internal_callees):
        self.method_internal_callees_records[method_id] = method_internal_callees

    def restore(self):
        # read file and convert to self.all_method_def_use
        df = DataModel().load(self.path)
        for row in df:
            callee = MethodInternalCallee(
                row.method_id,
                row.callee_type,
                row.stmt_id,
                row.callee_symbol_id,
                row.callee_symbol_index
            )
            if callee.method_id not in self.method_internal_callees_records:
                self.method_internal_callees_records[callee.method_id] = set()
            self.method_internal_callees_records[callee.method_id].add(callee)

    def export(self):
        if len(self.method_internal_callees_records) == 0:
            return

        results = []
        for callee_set in self.method_internal_callees_records.values():
            for callee in callee_set:
                results.append(callee.to_dict())
        DataModel(results).save(self.path)


class CallGraphLoader:
    def __init__(self, path):
        self.path = path
        self.call_graph = None

    def save(self, basic_call_graph: CallGraph):
        self.call_graph = basic_call_graph

    def get(self):
        return self.call_graph

    def restore(self):
        df = DataModel().load(self.path)
        self.call_graph = CallGraph()
        for row in df:
            self.call_graph.add_edge(row.source_method_id, row.target_method_id, row.stmt_id)

    def export(self):
        if util.is_empty(self.call_graph):
            return

        results = []
        for edge in self.call_graph.graph.edges(data='weight'):
            results.append({
                "source_method_id": edge[0],
                "target_method_id": edge[1],
                "stmt_id": edge[2]
            })
        DataModel(results).save(self.path)

class CallPathLoader:
    def __init__(self, file_path):
        self.path = file_path
        self.all_paths = set()

    def save(self, all_paths: set):
        self.all_paths = all_paths

    def get_all(self):
        return self.all_paths

    def restore(self):
        df = DataModel().load(self.path)
        for row in df:
            path_tuple = row.call_path
            callsite_list = []
            if util.is_available(path_tuple):
                for item in path_tuple:
                    callsite_list.append(CallSite(item[0], item[1], item[2]))

            path = CallPath(tuple(callsite_list))
            self.all_paths.add(path)

    def export(self):
        if len(self.all_paths) == 0:
            return

        dict_list = []
        for index, path in enumerate(self.all_paths):
            callsite_list = []
            for callsite in path:
                callsite_list.append(callsite.to_tuple())
            dict_list.append({
                "index": index,
                "call_path": tuple(callsite_list)
            })

        DataModel(dict_list).save(self.path)

    def get_callers_by_method_id(self, method_id, entry_point = -1):
        caller = set()
        for path in self.all_paths:
            if entry_point > 0 and path[0].caller_id != entry_point:
                continue
            for call_site in path:
                if call_site.callee_id == method_id and call_site.callee_id != 0:
                    caller.add(call_site.caller_id)
        return caller

    def get_callees_by_method_id(self, method_id, entry_point = -1):
        callee = set()
        for path in self.all_paths:
            if entry_point > 0 and path[0].caller_id != entry_point:
                continue
            for call_site in path:
                if call_site.caller_id == method_id and call_site.callee_id != 0:
                    callee.add(call_site.callee_id)
        return callee

    def get_call_path_between_two_methods(self, src_method, dst_method):
        """if des_method is None, return all call_path from src to end"""
        call_paths_between_two_methods = []
        for path in self.all_paths:
            current_path = []
            found_src = False
            for call_site in path:
                if call_site.callee_id == src_method:
                    current_path.append(call_site)
                    found_src = True
                elif found_src:
                    current_path.append(call_site)
                    if call_site.callee_id == dst_method:
                        call_paths_between_two_methods.append(current_path)
                        break
                    elif not dst_method and call_site == path[-1]:
                        call_paths_between_two_methods.append(current_path)
                        break
        return call_paths_between_two_methods

    def get_call_path_by_entry_point(self, entry_point):
        call_paths_between_two_methods = []
        for path in self.all_paths:
            call_path = []
            if 0 < entry_point != path[0].caller_id:
                continue
            call_paths_between_two_methods.append(path)
        return call_paths_between_two_methods


    def get_lowest_common_ancestor(self, node1, node2, entry_point):
        """
        寻找两个节点的最近公共祖先 (LCA)
        :param edges: 列表，格式为 [(src, weight, dst), ...]
        :param node1: 目标节点1
        :param node2: 目标节点2
        :return: 公共祖先节点 (如果不存在则返回 None)
        """

        # 1. 构建 {子节点: 父节点}  mapping字典
        # 假设边是有向的: src -> dst (父 -> 子)
        call_path = None
        for path in self.all_paths:
            if path[0].caller_id == entry_point:
                call_path = path
        if not call_path:
            return None
        parent_map = {}

        # 用来记录所有出现过的节点，防止查询不存在的节点
        all_nodes = set()

        for call_site in call_path:
            parent_map[call_site.callee_id] = call_site.caller_id
            all_nodes.add(call_site.caller_id)
            all_nodes.add(call_site.callee_id)
        # 如果输入的节点不在树中，直接返回 None
        if node1 not in all_nodes or node2 not in all_nodes:
            return None

        # 2. 记录 node1 到根节点的路径上的所有节点
        ancestors_of_n1 = set()
        curr = node1
        while curr is not None:
            ancestors_of_n1.add(curr)
            # 获取当前节点的父节点，如果已经是根节点(在map中不存在)，则get返回None
            curr = parent_map.get(curr)

        # 3. 从 node2 开始向上遍历，找到第一个出现在 ancestors_of_n1 中的节点
        curr = node2
        while curr is not None:
            if curr in ancestors_of_n1:
                return curr  # 找到了最近公共祖先
            curr = parent_map.get(curr)

        return None  # 没有公共祖先（比如是两棵不连通的树）

class UniqueSymbolIDAssignerLoader:
    def __init__(self, path):
        self.path = path
        self.negative_symbol_id = config.BUILTIN_SYMBOL_START_ID
        self.max_gir_id = config.DEFAULT_MAX_GIR_ID
        self.positive_symbol_id = self.max_gir_id + config.POSITIVE_GIR_INTERVAL

    def save_max_gir_id(self, max_gir_id):
        self.max_gir_id = max_gir_id
        # 计算基础值（原逻辑）
        base_value = self.max_gir_id + config.POSITIVE_GIR_INTERVAL
        # 向上取整到 POSITIVE_GIR_INTERVAL 的整数倍（抹掉后面几位）
        self.positive_symbol_id = (base_value + config.POSITIVE_GIR_INTERVAL - 1) // config.POSITIVE_GIR_INTERVAL * config.POSITIVE_GIR_INTERVAL

    def get_max_gir_id(self):
        return self.max_gir_id

    def is_greater_than_max_gir_id(self, symbol_id):
        return symbol_id > self.max_gir_id

    def assign_new_unique_negative_id(self):
        self.negative_symbol_id -= 1
        return self.negative_symbol_id

    def assign_new_unique_positive_id(self):
        self.positive_symbol_id += 1
        return self.positive_symbol_id

    def restore(self):
        df = DataModel().load(self.path)
        for row in df:
            self.negative_symbol_id = row.negative_symbol_id
            self.positive_symbol_id = row.positive_symbol_id
            self.max_gir_id = row.max_gir_id
            break

    def export(self):
        results = [{
            "negative_symbol_id": self.negative_symbol_id,
            "positive_symbol_id": self.positive_symbol_id,
            "max_gir_id": self.max_gir_id
        }]
        DataModel(results).save(self.path)

class ImportGraphLoader:
    def __init__(self, path):
        self.path = path
        self.import_graph = None
        self.import_graph_nodes = []
        self.import_deps = None
        self.symbol_id_to_import_node = {}
        self.import_graph_nodes_save_path = self.path + "_nodes"

        dir_path = os.path.dirname(self.path)
        new_save_path = os.path.join(dir_path, "import_deps")
        self.import_deps_save_path = new_save_path

        self.EdgeNodePair = namedtuple("EdgeNodePair", ["edge", "node"])

    def save(self, import_graph):
        self.import_graph = import_graph

    def get(self):
        return self.import_graph

    def save_nodes(self, symbol_id_to_symbol_node):
        # 定义排序键函数，根据节点的 unit_id 和 symbol_id 进行排序
        def sort_key(node_key):
            node = symbol_id_to_symbol_node[node_key]
            return node.unit_id, node.symbol_id

        result = []
        for node_key in sorted(symbol_id_to_symbol_node, key=sort_key):
            result.append(symbol_id_to_symbol_node[node_key])

        # 对图节点的键按照排序规则进行排序
        self.import_graph_nodes = result
        self.symbol_id_to_import_node = symbol_id_to_symbol_node

    def get_nodes(self):
        return self.import_graph_nodes

    def save_deps(self, import_deps):
        self.import_deps = import_deps

    def get_deps(self):
        return self.import_deps

    def get_successor_nodes_from_ids(self, successor_ids):
        result = []
        if isinstance(successor_ids, int):
            successor_ids = [successor_ids]
        for each_succ in successor_ids:
            import_node = self.symbol_id_to_import_node.get(each_succ)
            if import_node:
                result.append(import_node)
        return result

    def get_internal_successor_nodes(self, node_id):
        successor_ids = util.graph_successors_with_weight(
            self.import_graph, node_id, IMPORT_GRAPH_EDGE_KIND.INTERNAL_SYMBOL
        )
        return self.get_successor_nodes_from_ids(successor_ids)

    def get_external_successor_nodes(self, node_id):
        successor_ids = util.graph_successors_with_weight(
            self.import_graph, node_id, IMPORT_GRAPH_EDGE_KIND.EXTERNAL_SYMBOL
        )
        return self.get_successor_nodes_from_ids(successor_ids)

    def get_edges_and_nodes_with_edge_attrs(self, node_id, attr_dict: dict):
        """attr可以是：real_name, weight(edge_kind), site(import_stmt_id), symbol_type(该Node type)"""
        edge_node_list = util.graph_successors_with_edge_attrs(self.import_graph, node_id, attr_dict)
        return [self.EdgeNodePair(edge, self.get_successor_nodes_from_ids(node_index)) for edge, node_index in edge_node_list]

    def get_import_node_with_name(self, unit_id, import_name):
        """在unit中给定import_name，找到被import的节点，没有则返回None"""        
        result = None
        edge_node_list = self.get_edges_and_nodes_with_edge_attrs(unit_id, {"real_name":import_name})
        if util.is_available(edge_node_list):
            result = edge_node_list[0].node[0]    
        return result

    def restore(self):
        df = DataModel().load(self.path)
        self.import_graph = nx.DiGraph()
        for row in df:
            self.import_graph.add_edge(row.parent_node, row.child_node, weight=row.edge_type)

        self.import_graph_nodes = DataModel().load(self.import_graph_nodes_save_path)
        for each_node in self.import_graph_nodes:
            self.symbol_id_to_import_node[each_node.symbol_id] = each_node

        df = DataModel().load(self.import_deps_save_path)
        self.import_deps = nx.DiGraph()
        for row in df:
            self.import_deps.add_edge(row.unit_id, row.imported_unit_id)

    def export(self):
        if util.is_empty(self.import_graph):
            return

        # 初始化一个空列表，用于存储图中边的信息
        results = []
        # 遍历图中的每一条边
        for edge in self.import_graph.edges(data=True):
            # 为每条边创建一个字典，记录边的起始节点和结束节点
            edge_info = {
                "parent_node": edge[0],
                "child_node": edge[1],
                "edge_type": edge[2].get('weight', None)
            }
            # 将边的信息添加到结果列表中
            results.append(edge_info)

        DataModel(results).save(self.path)

        # 初始化一个列表，用于存储图中节点的信息
        node_info_list = []

        # 遍历排序后的节点键，将节点信息转换为字典并添加到列表中
        for each_node in self.import_graph_nodes:
            node_info_list.append(each_node.to_dict())

        # 使用 DataModel 保存节点信息到文件
        DataModel(node_info_list).save(self.import_graph_nodes_save_path)

        # 初始化一个空列表，用于存储图中边的信息
        results = []
        # 遍历图中的每一条边
        for edge in self.import_deps.edges:
            # 为每条边创建一个字典，记录边的起始节点和结束节点
            edge_info = {
                "unit_id": edge[0],
                "imported_unit_id": edge[1]
            }
            # 将边的信息添加到结果列表中
            results.append(edge_info)

        # 使用 DataModel 保存边信息到文件
        DataModel(results).save(self.import_deps_save_path)

class TypeGraphLoader:
    def __init__(self, path):
        self.path = path
        self.type_graph = None

    def save(self, type_graph):
        self.type_graph = type_graph

    def get(self):
        return self.type_graph

    def restore(self):
        df = DataModel().load(self.path)
        self.type_graph = BasicGraph()
        for row in df:
            self.type_graph.add_edge(row.type_id, row.parent_type_id, row.inheritance)

    def export(self):
        if util.is_empty(self.type_graph):
            return

        results = []
        for edge in self.type_graph.graph.edges(data='weight'):
            results.append({
                "type_id": edge[0],
                "parent_type_id": edge[1],
                "name": edge[2].name,
                "parent_pos": edge[2].parent_pos,
                "parent_name": edge[2].parent_name
            })
        DataModel(results).save(self.path)

class MethodSymbolToDefinedLoader(MethodLevelAnalysisResultLoader):
    # @profile
    def unflatten_item_dataframe_when_loading(self, method_id, flattened_item):
        defined_symbols = {}
        for row in flattened_item:
            if row.symbol_id not in defined_symbols:
                defined_symbols[row.symbol_id] = set()

            defined = row.defined
            for each_defined in defined:
                if isinstance(each_defined, (tuple, numpy.ndarray)):
                    defined_symbols[row.symbol_id].add(
                        SymbolDefNode(index = int(each_defined[0]), symbol_id = int(row.symbol_id), stmt_id = int(each_defined[1]))
                    )

                else:
                    defined_symbols[row.symbol_id].add(each_defined)

        return defined_symbols

    def flatten_item_when_saving(self, method_id, defined_symbols):
        all_defined = []
        for symbol_id, defined_set in defined_symbols.items():
            defined = []
            for each_defined in defined_set:
                if isinstance(each_defined, SymbolDefNode):
                    defined.append((each_defined.index, each_defined.stmt_id))

                else:
                    defined.append(each_defined)

            all_defined.append({
                "method_id": method_id,
                "symbol_id": symbol_id,
                "defined": defined
            })
        return all_defined

class MethodStateToDefinedLoader(MethodLevelAnalysisResultLoader):
    def unflatten_item_dataframe_when_loading(self, method_id, flattened_item):
        defined_states = {}
        for row in flattened_item:
            if row.state_id not in defined_states:
                defined_states[row.state_id] = set()

            for each_defined in row.defined:
                if isinstance(each_defined, tuple):
                    defined_states[row.state_id].add(
                        StateDefNode(index = int(each_defined[0]), state_id = int(row.state_id), stmt_id = int(each_defined[1])))
        return defined_states

    def flatten_item_when_saving(self, method_id, defined_states):
        all_defined = []
        for state_id, defined_set in defined_states.items():
            defined = []
            for each_defined in defined_set:
                if isinstance(each_defined, StateDefNode):
                    defined.append((each_defined.index, each_defined.stmt_id))

                else:
                    defined.append(each_defined)

            all_defined.append({
                "method_id": method_id,
                "state_id": state_id,
                "defined": defined
            })
        return all_defined

class MethodSymbolToUsedLoader(MethodLevelAnalysisResultLoader):
    def unflatten_item_dataframe_when_loading(self, method_id, flattened_item):
        stmt_to_use = {}
        for row in flattened_item:
            stmt_to_use[row.symbol_id] = set(row.used)
        return stmt_to_use

    def flatten_item_when_saving(self, method_id, used_symbols):
        all_used = []
        for symbol_id, used in used_symbols.items():
            all_used.append({
                "method_id": method_id,
                "symbol_id": symbol_id,
                "used": list(used)
            })
        return all_used

class GroupedMethodsLoader:
    def __init__(self, path):
        self.path = path
        self.grouped_methods = None

    def save(self, grouped_methods):
        self.grouped_methods = grouped_methods

    def get(self):
        return self.grouped_methods

    def export(self):
        if util.is_empty(self.grouped_methods):
            return
        DataModel([self.grouped_methods.to_dict()]).save(self.path)

    def restore(self):
        df = DataModel().load(self.path)
        if len(df) == 0:
            return
        data = df.access(0)
        self.grouped_methods = SimplyGroupedMethodTypes(
            data.no_callees,
            data.only_direct_callees,
            data.mixed_direct_callees,
            data.only_dynamic_callees,
            data.containing_dynamic_callees,
            data.containing_error_callees
        )

class SymbolGraphLoader(MethodLevelAnalysisResultLoader):
    def unflatten_item_dataframe_when_loading(self, _id, item_df):
        method_id = _id
        symbol_graph = SymbolGraph(method_id)
        for row in item_df:
            if util.is_available(row.defined_symbol_stmt_id):
                key = SymbolDefNode(
                    index = int(row.defined_symbol_index),
                    symbol_id = int(row.defined_symbol_id),
                    stmt_id = int(row.defined_symbol_stmt_id)
                )
                symbol_graph.add_edge(row.stmt_id, key, row.edge_type)
            else:
                key = SymbolDefNode(
                    index = int(row.used_symbol_index),
                    symbol_id = int(row.used_symbol_id),
                    stmt_id = int(row.used_symbol_stmt_id)
                )
                symbol_graph.add_edge(key, row.stmt_id, row.edge_type)
        return symbol_graph.graph

    def flatten_item_when_saving(self, _id, symbol_graph: nx.DiGraph):
        method_id = _id
        edges = []
        old_edges = symbol_graph.edges(data='weight', default = 0)
        for e in old_edges:
            src_node = e[0]
            dst_node = e[1]
            edge_type = 0 if util.is_empty(e[2]) else e[2]
            if isinstance(src_node, (int, numpy.int64)):
                # defined node
                edges.append({
                    "method_id": method_id,
                    "stmt_id": int(src_node),
                    "defined_symbol_stmt_id": int(dst_node.stmt_id),
                    "defined_symbol_index": int(dst_node.index),
                    "defined_symbol_id": int(dst_node.symbol_id),
                    "edge_type": edge_type
                })
            else:
                # used node
                edges.append({
                    "method_id": method_id,
                    "used_symbol_stmt_id": int(src_node.stmt_id),
                    "used_symbol_index": int(src_node.index),
                    "used_symbol_id": int(src_node.symbol_id),
                    "stmt_id": int(dst_node),
                    "edge_type": edge_type
                })
        return edges

class StateFlowGraphLoader(MethodLevelAnalysisResultLoader):
    def unflatten_item_dataframe_when_loading(self, method_id, item_df):
        symbol_graph = StateFlowGraph(method_id)
        for row in item_df:
            if not row or not row.source_node or not row.dest_node:
                continue
            symbol_graph.add_edge(
                SFGNode().from_tuple(row.source_node),
                SFGNode().from_tuple(row.dest_node),
                SFGEdge().from_tuple(row.edge)
            )
        return symbol_graph.graph

    def flatten_item_when_saving(self, method_id, state_flow_graph: nx.DiGraph):
        edges = []
        all_edges = state_flow_graph.edges(data='weight', default=None)
        for src_node, dst_node, edge in all_edges:
            edges.append({
                "method_id": method_id,
                "source_node": src_node.to_tuple(),
                "edge": edge.to_tuple(),
                "dest_node": dst_node.to_tuple(),
            })
        return edges

############################################################

class Loader:
    # This is our file system manager
    def __init__(self, options):
        self.options = options
        self.frontend_path = os.path.join(options.workspace, config.FRONTEND_DIR)
        self.semantic_p1_path = os.path.join(options.workspace, config.SEMANTIC_P1_DIR)
        self.semantic_p2_path = os.path.join(options.workspace, config.SEMANTIC_P2_DIR)
        self.semantic_p3_path = os.path.join(options.workspace, config.SEMANTIC_P3_DIR)

        self.stmt_gir_cache = util.LRUCache(capacity = config.MAX_STMT_CACHE_CAPACITY)

        self._module_symbols_loader: ModuleSymbolsLoader = ModuleSymbolsLoader(
            options,
            os.path.join(self.frontend_path, config.MODULE_SYMBOLS_PATH),
        )

        self._gir_loader = UnitGIRLoader(
            options,
            # schema.gir_schema,
            [],
            os.path.join(self.frontend_path, config.GIR_BUNDLE_PATH),
            config.GIR_CACHE_CAPACITY,
            config.BUNDLE_CACHE_CAPACITY
        )

        self._unique_symbol_id_assigner_loader = UniqueSymbolIDAssignerLoader(
            os.path.join(self.frontend_path, config.UNIQUE_SYMBOL_IDS_PATH),
        )

        self._external_symbol_id_collection_loader = ExternalSymbolIDCollectionLoader(
            os.path.join(self.semantic_p1_path, config.EXTERNAL_SYMBOL_ID_COLLECTION_PATH)
        )

        self._cfg_loader: CFGLoader = CFGLoader(
            options,
            schema.control_flow_graph_schema,
            os.path.join(self.semantic_p1_path, config.CFG_BUNDLE_PATH),
            config.LRU_CACHE_CAPACITY,
            config.BUNDLE_CACHE_CAPACITY
        )

        self._scope_hierarchy_loader = ScopeHierarchyLoader(
            options,
            [],
            os.path.join(self.semantic_p1_path, config.SCOPE_HIERARCHY_BUNDLE_PATH),
            config.LRU_CACHE_CAPACITY,
            config.BUNDLE_CACHE_CAPACITY
        )

        self._unit_id_to_export_symbols_loader = UnitIDToExportSymbolsLoader(
            options,
            [],
            os.path.join(self.semantic_p1_path, config.UNIT_EXPORT_PATH),
            config.LRU_CACHE_CAPACITY,
            config.BUNDLE_CACHE_CAPACITY
        )

        self._class_id_to_methods_loader = ClassIDToMethodsLoader(
            os.path.join(self.semantic_p1_path, config.CLASS_METHODS_PATH),
        )

        self._call_stmt_id_to_call_format_info_loader = CallStmtIDToCallFormatInfoLoader(
            os.path.join(self.semantic_p1_path, config.CALL_STMT_ID_TO_CALL_FORMAT_INFO_PATH)
        )

        self._method_id_to_method_decl_format_loader = MethodIDToMethodDeclFormatLoader(
            os.path.join(self.semantic_p1_path, config.METHOD_ID_TO_METHOD_DECL_FORMAT_PATH)
        )

        self._unit_id_to_stmt_id_loader = UnitIDToStmtIDLoader(
            os.path.join(self.semantic_p1_path, config.UNIT_ID_TO_STMT_ID_PATH)
        )

        self._unit_id_to_method_id_loader = UnitIDToMethodIDLoader(
            os.path.join(self.semantic_p1_path, config.UNIT_ID_TO_METHOD_ID_PATH)
        )

        self._unit_id_to_class_id_loader = UnitIDToClassIDLoader(
            os.path.join(self.semantic_p1_path, config.UNIT_ID_TO_CLASS_ID_PATH)
        )

        self._class_id_to_stmt_id_loader = ClassIDToStmtIDLoader(
            os.path.join(self.semantic_p1_path, config.CLASS_ID_TO_STMT_ID_PATH)
        )

        self._method_id_to_stmt_id_loader = MethodIDToStmtIDLoader(
            os.path.join(self.semantic_p1_path, config.METHOD_ID_TO_STMT_ID_PATH)
        )

        self._unit_id_to_namespace_id_loader = UnitIDToNamespaceIDLoader(
            os.path.join(self.semantic_p1_path, config.UNIT_ID_TO_NAMESPACE_ID_PATH)
        )

        self._unit_id_to_variable_id_loader = UnitIDToVariableIDLoader(
            os.path.join(self.semantic_p1_path, config.UNIT_ID_TO_VARIABLE_ID_PATH)
        )

        self._unit_id_to_import_stmt_id_loader = UnitIDToImportStmtIDLoader(
            os.path.join(self.semantic_p1_path, config.UNIT_ID_TO_IMPORT_STMT_ID_PATH)
        )

        self._method_id_to_parameter_id_loader = MethodIDToParameterIDLoader(
            os.path.join(self.semantic_p1_path, config.METHOD_ID_TO_PARAMETER_ID_PATH)
        )

        self._class_id_to_method_id_loader = ClassIDToMethodIDLoader(
            os.path.join(self.semantic_p1_path, config.CLASS_ID_TO_METHOD_ID_PATH)
        )

        self._class_id_to_field_id_loader = ClassIDToFieldIDLoader(
            os.path.join(self.semantic_p1_path, config.CLASS_ID_TO_FIELD_ID_PATH)
        )

        self._class_id_to_class_name_loader = ClassIdToNameLoader(
            os.path.join(self.semantic_p1_path, config.CLASS_ID_TO_CLASS_NAME_PATH)
        )

        self._method_id_to_method_name_loader = MethodIDToMethodNameLoader(
            os.path.join(self.semantic_p1_path, config.METHOD_ID_TO_METHOD_NAME_PATH)
        )

        self._symbol_name_to_scope_ids_loader = SymbolNameToScopeIDsLoader(
            options,
            [],
            os.path.join(self.semantic_p1_path, config.SYMBOL_NAME_TO_SCOPE_IDS_PATH),
            config.LRU_CACHE_CAPACITY,
            config.BUNDLE_CACHE_CAPACITY
        )

        self._symbol_name_to_decl_ids_loader = SymbolNameToDeclIDsLoader(
            options,
            [],
            os.path.join(self.semantic_p1_path, config.SYMBOL_NAME_TO_DECL_IDS_PATH),
            config.LRU_CACHE_CAPACITY,
            config.BUNDLE_CACHE_CAPACITY
        )

        self._scope_id_to_symbol_info_loader = ScopeIDToSymbolInfoLoader(
            options,
            [],
            os.path.join(self.semantic_p1_path, config.SCOPE_ID_TO_SYMBOL_INFO_PATH),
            config.LRU_CACHE_CAPACITY,
            config.BUNDLE_CACHE_CAPACITY
        )

        self._scope_id_to_available_scope_ids_loader = ScopeIDToAvailableScopeIDsLoader(
            options,
            [],
            os.path.join(self.semantic_p1_path, config.SCOPE_ID_TO_AVAILABLE_SCOPE_IDS_PATH),
            config.LRU_CACHE_CAPACITY,
            config.BUNDLE_CACHE_CAPACITY
        )

        # self._call_stmt_id_to_info = ScopeIDToAvailableScopeIDsLoader(
        #     options,
        #     [],
        #     os.path.join(self.semantic_path_p1, config.CALL_STMT_ID_TO_INFO_PATH),
        #     config.LRU_CACHE_CAPACITY,
        #     config.BUNDLE_CACHE_CAPACITY
        # )

        self._unit_symbol_decl_summary_loader = UnitSymbolDeclSummaryLoader(
            self._symbol_name_to_scope_ids_loader,
            self._scope_id_to_symbol_info_loader,
            self._scope_id_to_available_scope_ids_loader
        )

        self._entry_points_loader = EntryPointsLoader(
            os.path.join(self.semantic_p1_path, config.ENTRY_POINTS_PATH)
        )

        self._import_graph_loader = ImportGraphLoader(
            os.path.join(self.semantic_p1_path, config.IMPORT_GRAPH_PATH),
        )

        self._type_graph_loader = TypeGraphLoader(
            os.path.join(self.semantic_p1_path, config.TYPE_GRAPH_PATH),
        )

        self._symbol_bit_vector_manager_p1_loader = BitVectorManagerLoader(
            options,
            # schema.bit_vector_manager_schema,
            [],
            os.path.join(self.semantic_p1_path, config.SYMBOL_BIT_VECTOR_MANAGER_BUNDLE_PATH_P1),
            config.LRU_CACHE_CAPACITY,
            config.BUNDLE_CACHE_CAPACITY
        )

        self._symbol_bit_vector_manager_p2_loader = BitVectorManagerLoader(
            options,
            # schema.bit_vector_manager_schema,
            [],
            os.path.join(self.semantic_p2_path, config.SYMBOL_BIT_VECTOR_MANAGER_BUNDLE_PATH_P2),
            config.LRU_CACHE_CAPACITY,
            config.BUNDLE_CACHE_CAPACITY
        )

        self._class_id_to_members_loader = ClassIDToMembersLoader(
            options,
            [],
            os.path.join(self.semantic_p2_path, config.CLASS_ID_TO_MEMBERS_PATH),
            config.LRU_CACHE_CAPACITY,
            config.BUNDLE_CACHE_CAPACITY
        )

        self._stmt_id_to_scope_id_loader = StmtIDToScopeIDLoader(
            os.path.join(self.semantic_p1_path, config.STMT_ID_TO_SCOPE_ID_PATH)
        )

        self._symbol_bit_vector_manager_p3_loader = BitVectorManagerLoader(
            options,
            # schema.bit_vector_manager_schema,
            [],
            os.path.join(self.semantic_p3_path, config.SYMBOL_BIT_VECTOR_MANAGER_BUNDLE_PATH_P3),
            config.MIN_CACHE_CAPACITY,
            config.BUNDLE_CACHE_CAPACITY
        )

        self._state_bit_vector_manager_p2_loader = BitVectorManagerLoader(
            options,
            # schema.bit_vector_manager_schema,
            [],
            os.path.join(self.semantic_p2_path, config.STATE_BIT_VECTOR_MANAGER_BUNDLE_PATH_P2),
            config.LRU_CACHE_CAPACITY,
            config.BUNDLE_CACHE_CAPACITY
        )

        self._state_bit_vector_manager_p3_loader = BitVectorManagerLoader(
            options,
            # schema.bit_vector_manager_schema,
            [],
            os.path.join(self.semantic_p3_path, config.STATE_BIT_VECTOR_MANAGER_BUNDLE_PATH_P3),
            config.MIN_CACHE_CAPACITY,
            config.BUNDLE_CACHE_CAPACITY
        )

        self._stmt_status_p1_loader = StmtStatusLoader(
            options,
            # schema.stmt_status_schema,
            [],
            os.path.join(self.semantic_p1_path, config.STMT_STATUS_BUNDLE_PATH_P1),
            config.LRU_CACHE_CAPACITY,
            config.BUNDLE_CACHE_CAPACITY
        )

        self._stmt_status_p2_loader = StmtStatusLoader(
            options,
            # schema.stmt_status_schema,
            [],
            os.path.join(self.semantic_p2_path, config.STMT_STATUS_BUNDLE_PATH_P2),
            config.LRU_CACHE_CAPACITY,
            config.BUNDLE_CACHE_CAPACITY
        )

        self._stmt_status_p3_loader = StmtStatusLoader(
            options,
            # schema.stmt_status_schema,
            [],
            os.path.join(self.semantic_p3_path, config.STMT_STATUS_BUNDLE_PATH_P3),
            config.MIN_CACHE_CAPACITY,
            config.BUNDLE_CACHE_CAPACITY
        )

        self._symbol_state_space_p1_loader = SymbolStateSpaceLoader(
            options,
            # schema.symbol_state_space_schema,
            [],
            os.path.join(self.semantic_p1_path, config.SYMBOL_STATE_SPACE_BUNDLE_PATH_P1),
            config.LRU_CACHE_CAPACITY,
            config.BUNDLE_CACHE_CAPACITY
        )

        self._symbol_state_space_p2_loader = SymbolStateSpaceLoader(
            options,
            # schema.symbol_state_space_schema,
            [],
            os.path.join(self.semantic_p2_path, config.SYMBOL_STATE_SPACE_BUNDLE_PATH_P2),
            config.LRU_CACHE_CAPACITY,
            config.BUNDLE_CACHE_CAPACITY
        )

        self._symbol_state_space_summary_p2_loader = SymbolStateSpaceLoader(
            options,
            # schema.symbol_state_space_schema,
            [],
            os.path.join(self.semantic_p2_path, config.SYMBOL_STATE_SPACE_SUMMARY_BUNDLE_PATH_P2),
            config.LRU_CACHE_CAPACITY,
            config.BUNDLE_CACHE_CAPACITY
        )

        self._symbol_state_space_p3_loader = SymbolStateSpaceLoader(
            options,
            # schema.symbol_state_space_schema,
            [],
            os.path.join(self.semantic_p3_path, config.SYMBOL_STATE_SPACE_BUNDLE_PATH_P3),
            config.MIN_CACHE_CAPACITY,
            config.BUNDLE_CACHE_CAPACITY
        )

        self._symbol_state_space_summary_p3_loader = SymbolStateSpaceLoader(
            options,
            # schema.symbol_state_space_schema,
            [],
            os.path.join(self.semantic_p3_path, config.SYMBOL_STATE_SPACE_SUMMARY_BUNDLE_PATH_P3),
            config.MIN_CACHE_CAPACITY,
            config.BUNDLE_CACHE_CAPACITY
        )

        self._method_internal_callees_loader = MethodInternalCalleesLoader(
            os.path.join(self.semantic_p1_path, config.METHOD_INTERNAL_CALLEES_PATH),
        )

        self._method_def_use_summary_loader = MethodDefUseSummaryLoader(
            os.path.join(self.semantic_p1_path, config.METHOD_DEF_USE_SUMMARY_PATH),
        )

        self._method_summary_template_loader = MethodSummaryLoader(
            os.path.join(self.semantic_p2_path, config.METHOD_SUMMARY_TEMPLATE_PATH),
        )

        self._method_summary_template_instance = MethodSummaryLoader(
            os.path.join(self.semantic_p3_path, config.METHOD_SUMMARY_INSTANCE_PATH),
        )

        self._classified_method_call_loader = CallGraphLoader(
            os.path.join(self.semantic_p1_path, config.CALL_GRAPH_BUNDLE_PATH_P1),
        )

        self._prelim_call_graph_loader = CallGraphLoader(
            os.path.join(self.semantic_p2_path, config.STATIC_CALL_GRAPH_BUNDLE_PATH_P2),
        )

        self._global_call_path_loader = CallPathLoader(
            os.path.join(self.semantic_p3_path, config.GLOBAL_CALL_PATH_BUNDLE_PATH),
        )

        self._defined_symbols_p1_loader = MethodSymbolToDefinedLoader(
            options,
            [],
            os.path.join(self.semantic_p1_path, config.DEFINED_SYMBOLS_PATH),
            config.LRU_CACHE_CAPACITY,
            config.BUNDLE_CACHE_CAPACITY
        )

        self._defined_symbols_p2_loader = MethodSymbolToDefinedLoader(
            options,
            [],
            os.path.join(self.semantic_p2_path, config.DEFINED_SYMBOLS_PATH_P2),
            config.LRU_CACHE_CAPACITY,
            config.BUNDLE_CACHE_CAPACITY
        )

        self._defined_symbols_p3_loader = MethodSymbolToDefinedLoader(
            options,
            [],
            os.path.join(self.semantic_p3_path, config.DEFINED_SYMBOLS_PATH_P3),
            config.MIN_CACHE_CAPACITY,
            config.BUNDLE_CACHE_CAPACITY
        )

        self._defined_states_p1_loader = MethodStateToDefinedLoader(
            options,
            [],
            os.path.join(self.semantic_p1_path, config.DEFINED_STATES_PATH_P1),
            config.LRU_CACHE_CAPACITY,
            config.BUNDLE_CACHE_CAPACITY
        )

        self._defined_states_p2_loader = MethodStateToDefinedLoader(
            options,
            [],
            os.path.join(self.semantic_p2_path, config.DEFINED_STATES_PATH_P2),
            config.LRU_CACHE_CAPACITY,
            config.BUNDLE_CACHE_CAPACITY
        )

        self._used_symbols_loader = MethodSymbolToUsedLoader(
            options,
            [],
            os.path.join(self.semantic_p1_path, config.USED_SYMBOLS_PATH),
            config.LRU_CACHE_CAPACITY,
            config.BUNDLE_CACHE_CAPACITY
        )

        self._grouped_methods_loader: GroupedMethodsLoader = GroupedMethodsLoader(
            os.path.join(self.semantic_p1_path, config.GROUPED_METHODS_PATH)
        )

        self._symbol_graph_p2_loader: SymbolGraphLoader = SymbolGraphLoader(
            options,
            schema.symbol_graph_schema_p2,
            os.path.join(self.semantic_p2_path, config.SYMBOL_GRAPH_BUNDLE_PATH_P2),
            config.LRU_CACHE_CAPACITY,
            config.BUNDLE_CACHE_CAPACITY
        )

        self._symbol_graph_p3_loader: SymbolGraphLoader = SymbolGraphLoader(
            options,
            schema.symbol_graph_schema_p2,
            os.path.join(self.semantic_p3_path, config.SYMBOL_GRAPH_BUNDLE_PATH_P3),
            config.LRU_CACHE_CAPACITY,
            config.BUNDLE_CACHE_CAPACITY
        )

        self._state_flow_graph_p2_loader: StateFlowGraphLoader = StateFlowGraphLoader(
            options,
            schema.state_flow_graph_schema_p2,
            os.path.join(self.semantic_p2_path, config.SFG_BUNDLE_PATH_P2),
            config.LRU_CACHE_CAPACITY,
            config.BUNDLE_CACHE_CAPACITY
        )

        self._state_flow_graph_p3_loader: StateFlowGraphLoader = StateFlowGraphLoader(
            options,
            schema.state_flow_graph_schema_p2,
            os.path.join(self.semantic_p3_path, config.SFG_BUNDLE_PATH_P3),
            config.MIN_CACHE_CAPACITY,
            config.BUNDLE_CACHE_CAPACITY
        )

        self._callee_parameter_mapping_p2_loader: CalleeParameterMapping = CalleeParameterMapping(
            options,
            [],
            os.path.join(self.semantic_p2_path, config.CALLEE_PARAMETER_MAPPING_BUNDLE_PATH_P2),
            config.LRU_CACHE_CAPACITY,
            config.BUNDLE_CACHE_CAPACITY
        )

        self._callee_parameter_mapping_p3_loader: CalleeParameterMapping = CalleeParameterMapping(
            options,
            [],
            os.path.join(self.semantic_p2_path, config.CALLEE_PARAMETER_MAPPING_BUNDLE_PATH_P3),
            config.LRU_CACHE_CAPACITY,
            config.BUNDLE_CACHE_CAPACITY
        )

        self.method_header_cache = util.LRUCache(config.METHOD_HEADER_CACHE_CAPABILITY)
        self.method_body_cache = util.LRUCache(config.METHOD_BODY_CACHE_CAPABILITY)
        self.stmt_scope_cache = util.LRUCache(config.STMT_SCOPE_CACHE_CAPABILITY)

        self._all_loaders = self.init_loading()

    def init_loading(self):
        results = []
        loader_list = list(self.__dict__.keys())
        avoidings = ["_all_loaders"]
        for loader in loader_list:
            if loader not in avoidings:
                if loader.startswith("_") and loader.endswith("_loader"):
                    results.append(getattr(self, loader))
        return results

    def get_method_header(self, method_id):
        if method_id <= 0:
            return (None, None)

        if self.method_header_cache.contain(method_id):
            return self.method_header_cache.get(method_id)

        unit_id = self._unit_id_to_method_id_loader.convert_many_to_one(method_id)
        unit_gir = self._gir_loader.get_item_by_id(unit_id)
        if util.is_empty(unit_gir):
            return (None, None)
        method_decl_stmt = unit_gir.query_index_column_value_first("stmt_id", method_id)
        method_parameters = unit_gir.read_block(method_decl_stmt.parameters)
        result = (method_decl_stmt, method_parameters)
        self.method_header_cache.put(method_id, result)
        return result

    def _load_method_body_by_header(self, method_id, method_decl_stmt):
        if util.is_empty(method_decl_stmt):
            return None

        if self.method_body_cache.contain(method_id):
            self.method_body_cache.get(method_id)

        unit_id = self.convert_method_id_to_unit_id(method_id)
        unit_gir = self._gir_loader.get_item_by_id(unit_id)
        method_body = unit_gir.read_block(method_decl_stmt.body)
        self.method_body_cache.put(method_id, method_body)
        return method_body

    def get_method_body(self, method_id):
        method_decl_stmt, _ = self.get_method_header(method_id)
        return self._load_method_body_by_header(method_id, method_decl_stmt)

    def get_splitted_method_gir(self, method_id):
        method_decl_stmt, method_parameters = self.get_method_header(method_id)
        method_body = self._load_method_body_by_header(method_id, method_decl_stmt)
        return (method_decl_stmt, method_parameters, method_body)

    def _get_whole_method_gir(self, method_id):
        if method_id <= 0:
            return None

        unit_id = self._unit_id_to_method_id_loader.convert_many_to_one(method_id)
        unit_gir = self._gir_loader.get_item_by_id(unit_id)
        if util.is_empty(unit_gir):
            return None
        method_decl_stmt = unit_gir.query_index_column_value_first("stmt_id", method_id)
        max_id = unit_gir.boundary_of_multi_blocks([method_decl_stmt.parameters, method_decl_stmt.body])
        if max_id <= 0:
            return None
        method_whole_gir = unit_gir.slice(method_decl_stmt.get_index(), max_id + 1)
        return method_whole_gir

    def _clone_method_gir(self, unit_id, method_id, method_gir, new_name):
        unit_gir = self._gir_loader.get_item_by_id(unit_id)
        unit_gir_to_dict = unit_gir.convert_to_dict_list()
        start_stmt_id = self.get_max_gir_id()
        interval = start_stmt_id - method_id

        new_method_gir = []
        for stmt in method_gir:
            stmt_to_dict = stmt.copy().to_dict()
            for column in GIR_COLUMNS_TO_BE_ADDED:
                if column in stmt_to_dict:
                    if isinstance(stmt_to_dict[column], (int, float)) and (stmt_to_dict[column] > 0):
                        stmt_to_dict[column] += interval
            new_method_gir.append(stmt_to_dict)

        self._gir_loader.remove_unit_id(unit_id)
        new_method_gir[0]["name"] = new_name
        unit_gir_to_dict.extend(new_method_gir)

        self.save_max_gir_id(start_stmt_id + len(new_method_gir))
        self._gir_loader.save(unit_id, unit_gir_to_dict)

        return start_stmt_id

    def clone_method_in_strict_mode(self, method_id, new_name):
        unit_id = self.convert_method_id_to_unit_id(method_id)
        method_gir = self._get_whole_method_gir(method_id)
        if len(method_gir) == 0:
            return -1
        new_method_id = self._clone_method_gir(unit_id, method_id, method_gir, new_name)
        self.add_method_id_to_unit_id(new_method_id, unit_id)
        #self._clone_method_symbol_state_space_p1(method_id, stmt_ids, new_method_id)
        return new_method_id

    def get_stmt_gir(self, stmt_id):
        if stmt_id <= 0:
            return None

        if self.stmt_gir_cache.contain(stmt_id):
            return self.stmt_gir_cache.get(stmt_id)

        unit_id = self.convert_stmt_id_to_unit_id(stmt_id)
        unit_gir = self._gir_loader.get_item_by_id(unit_id)
        stmt_gir = unit_gir.query_index_column_value_first("stmt_id", stmt_id)
        self.stmt_gir_cache.put(stmt_id, stmt_gir)
        return stmt_gir

    def export(self):
        for loader in self._all_loaders:
            loader.export()
            if hasattr(loader, 'export_indexing'):
                loader.export_indexing()

    def restore(self):
        for loader in self._all_loaders:
            if hasattr(loader, 'restore_indexing'):
                #util.debug(loader.__class__.__name__ + " is restoring index")
                try:
                    loader.restore_indexing()
                except (FileNotFoundError, TypeError, Exception) as e:
                    # Ensure one loader failure doesn't block others
                    if not isinstance(e, FileNotFoundError):
                        util.warn(f"Failed to restore indexing for {loader.__class__.__name__}: {e}")
                    pass
            if hasattr(loader, 'restore'):
                #util.debug(loader.__class__.__name__ + " is restoring")
                try:
                    loader.restore()
                except (FileNotFoundError, Exception) as e:
                    if not isinstance(e, FileNotFoundError):
                        util.warn(f"Failed to restore {loader.__class__.__name__}: {e}")
                    pass

    ############################################################
    # The following is used to forwarding calls; This may be better for autocomplete in editor
    # For save_xxx(), its parameters is usually <_id, content> at the most cases
    # For load_xxx(), its parameter is usually <_id>
    # For export_xxx(), it does not have a parameter
    ############################################################
    def get_module_symbol_table(self):
        return self._module_symbols_loader.get_module_symbol_table()
    def save_module_symbols(self, module_symbol_results):
        return self._module_symbols_loader.save(module_symbol_results)
    def get_all_module_ids(self):
        return self._module_symbols_loader.get_all_module_ids()
    def get_all_unit_info(self):
        return self._module_symbols_loader.get_all_unit_info()
    def get_all_unit_ids(self):
        return self._module_symbols_loader.get_all_unit_ids()
    def convert_module_id_to_module_info(self, module_id):
        return self._module_symbols_loader.convert_module_id_to_module_info(module_id)
    # def convert_unit_id_to_unit_info(self, unit_id):
    #     return self._module_symbols_loader.convert_unit_id_to_unit_info(unit_id)
    def convert_unit_id_to_unit_path(self, unit_id):
        return self._module_symbols_loader.convert_unit_id_to_unit_path(unit_id)
    def convert_unit_path_to_unit_id(self, unit_path):
        return self._module_symbols_loader.convert_unit_path_to_unit_id(unit_path)

    def is_module_id(self, module_id):
        return self._module_symbols_loader.is_module_id(module_id)
    def is_unit_id(self, unit_id):
        return self._module_symbols_loader.is_unit_id(unit_id)
    def is_module_dir_id(self, module_dir_id):
        return self._module_symbols_loader.is_module_dir_id(module_dir_id)
    def convert_unit_id_to_lang_name(self, unit_id):
        return self._module_symbols_loader.convert_unit_id_to_unit_lang_name(unit_id)
    def convert_module_id_to_child_ids(self, module_id):
        return self._module_symbols_loader.convert_module_id_to_child_ids(module_id)

    def get_unit_gir(self, unit_id):
        return self._gir_loader.get_item_by_id(unit_id)
    def save_unit_gir(self, unit_id, unit_gir):
        self._gir_loader.save(unit_id, unit_gir)
    def export_gir(self):
        return self._gir_loader.export()

    def get_unit_scope_hierarchy(self, unit_id) -> DataModel:
        return self._scope_hierarchy_loader.get_item_by_id(unit_id)
    def save_unit_scope_hierarchy(self, unit_id, scope_hierarchy):
        return self._scope_hierarchy_loader.save(unit_id, scope_hierarchy)
    def get_all_scope_hierarchy(self):
        return self._scope_hierarchy_loader.get_all()
    def export_scope_hierarchy(self):
        return self._scope_hierarchy_loader.export()

    def get_unit_export_symbols(self, unit_id) -> DataModel:
        return self._unit_id_to_export_symbols_loader.get_item_by_id(unit_id)
    def save_unit_export_symbols(self, unit_id, export_symbols):
        return self._unit_id_to_export_symbols_loader.save(unit_id, export_symbols)

    def get_methods_in_class(self, class_id):
        return self._class_id_to_methods_loader.convert_one_to_many(class_id)
    def save_methods_in_class(self, class_id, methods):
        return self._class_id_to_methods_loader.save(class_id, methods)

    def convert_stmt_id_to_call_stmt_format(self, stmt_id):
        return self._call_stmt_id_to_call_format_info_loader.get(stmt_id)
    def save_stmt_id_to_call_stmt_format(self, stmt_id, call_format_info):
        return self._call_stmt_id_to_call_format_info_loader.save(stmt_id, call_format_info)
    def get_map_call_stmt_id_to_call_format_info(self):
        return self._call_stmt_id_to_call_format_info_loader.get_map_call_stmt_id_to_call_format_info()

    def convert_method_id_to_method_decl_format(self, method_id):
        return self._method_id_to_method_decl_format_loader.get(method_id)
    def save_method_id_to_method_decl_format(self, method_id, method_decl_format):
        return self._method_id_to_method_decl_format_loader.save(method_id, method_decl_format)

    def convert_unit_id_to_stmt_ids(self, unit_id):
        return self._unit_id_to_stmt_id_loader.convert_one_to_many(unit_id)
    def save_unit_id_to_stmt_ids(self, unit_id, stmt_ids):
        return self._unit_id_to_stmt_id_loader.save(unit_id, stmt_ids)
    def convert_stmt_id_to_unit_id(self, stmt_id):
        return self._unit_id_to_stmt_id_loader.get(stmt_id)
    def get_all_stmt_ids(self):
        return self._unit_id_to_stmt_id_loader.get_all_stmt_ids()

    def save_method_external_symbol_id_collection(self, method_id, external_symbol_id_collection):
        self._external_symbol_id_collection_loader.save_external_symbol_id_collection(method_id, external_symbol_id_collection)
    def get_method_external_symbol_id_collection(self, method_id):
        return self._external_symbol_id_collection_loader.get_external_symbol_id_collection(method_id)

    def convert_unit_id_to_variable_ids(self, unit_id):
        return self._unit_id_to_variable_id_loader.convert_one_to_many(unit_id)
    def save_unit_id_to_variable_ids(self, unit_id, variable_ids):
        return self._unit_id_to_variable_id_loader.save(unit_id, variable_ids)
    def convert_variable_id_to_unit_id(self, variable_id):
        return self._unit_id_to_variable_id_loader.convert_many_to_one(variable_id)
    def get_all_variable_ids(self):
        return self._unit_id_to_variable_id_loader.get_all_items_in_many()
    def is_variable_decl(self, variable_id):
        return self._unit_id_to_variable_id_loader.is_variable_decl(variable_id)

    def convert_unit_id_to_import_stmt_ids(self, unit_id):
        return self._unit_id_to_import_stmt_id_loader.convert_one_to_many(unit_id)
    def save_unit_id_to_import_stmt_ids(self, unit_id, import_stmt_ids):
        return self._unit_id_to_import_stmt_id_loader.save(unit_id, import_stmt_ids)
    def convert_import_stmt_id_to_unit_id(self, import_stmt_id):
        return self._unit_id_to_import_stmt_id_loader.convert_many_to_one(import_stmt_id)
    def get_all_import_stmt_ids(self):
        return self._unit_id_to_import_stmt_id_loader.get_all_items_in_many()
    def is_import_stmt(self, import_stmt_id):
        return self._unit_id_to_import_stmt_id_loader.is_import_stmt(import_stmt_id)

    def convert_method_id_to_parameter_ids(self, method_id):
        return self._method_id_to_parameter_id_loader.convert_one_to_many(method_id)
    def convert_parameter_id_to_method_id(self, parameter_id):
        return self._method_id_to_parameter_id_loader.convert_many_to_one(parameter_id)
    def save_method_id_to_parameter_ids(self, method_id, parameter_ids):
        return self._method_id_to_parameter_id_loader.save(method_id, parameter_ids)
    def is_parameter_decl(self, parameter_id):
        return self._method_id_to_parameter_id_loader.is_parameter_decl(parameter_id)
    def is_parameter_decl_of_method(self, method_id, parameter_id):
        return self._method_id_to_parameter_id_loader.is_parameter_decl_of_method(method_id, parameter_id)

    def convert_class_id_to_method_ids(self, class_id):
        return self._class_id_to_method_id_loader.convert_one_to_many(class_id)
    def save_class_id_to_method_ids(self, class_id, method_ids):
        return self._class_id_to_method_id_loader.save(class_id, method_ids)
    def convert_method_id_to_class_id(self, method_id):
        return self._class_id_to_method_id_loader.convert_many_to_one(method_id)
    def is_method_decl_of_class(self, class_id, method_id):
        return self._class_id_to_method_id_loader.is_method_decl_of_class(class_id, method_id)

    def save_class_id_to_members(self, class_id, class_members):
        return self._class_id_to_members_loader.save(class_id, class_members)
    def save_all_class_id_to_members(self, class_id_to_members):
        return self._class_id_to_members_loader.save_all(class_id_to_members)
    def convert_class_id_to_members(self, class_id, create_if_not_exists = False):
        class_members: DataModel = self._class_id_to_members_loader.get_item_by_id(class_id)
        nil_members = {}
        if util.is_empty(class_members):
            if create_if_not_exists:
                self.save_class_id_to_members(class_id, nil_members)
            return nil_members

        # class_members_df = class_members.get_data()
        if util.is_available(class_members):
            return class_members
        return nil_members

    def get_map_class_id_to_members(self):
        return self._class_id_to_members_loader.get_all()

    def convert_class_id_to_field_ids(self, class_id):
        return self._class_id_to_field_id_loader.convert_one_to_many(class_id)
    def save_class_id_to_field_ids(self, class_id, field_ids):
        return self._class_id_to_field_id_loader.save(class_id, field_ids)
    def convert_field_id_to_class_id(self, field_id):
        return self._class_id_to_field_id_loader.convert_many_to_one(field_id)
    def is_field_decl(self, field_id):
        return self._class_id_to_field_id_loader.is_field_decl(field_id)
    def is_field_decl_of_class(self, field_id, class_id):
        return self._class_id_to_field_id_loader.is_field_decl_of_class(field_id, class_id)

    def convert_unit_id_to_method_ids(self, unit_id):
        return self._unit_id_to_method_id_loader.convert_one_to_many(unit_id)
    def save_unit_id_to_method_ids(self, unit_id, method_ids):
        return self._unit_id_to_method_id_loader.save(unit_id, method_ids)
    def convert_method_id_to_unit_id(self, method_id):
        return self._unit_id_to_method_id_loader.convert_many_to_one(method_id)
    def add_method_id_to_unit_id(self, method_id, unit_id):
        return self._unit_id_to_method_id_loader.add_method_id_to_unit_id(method_id, unit_id)
    def get_all_method_ids(self):
        return self._unit_id_to_method_id_loader.get_all_items_in_many()
    def is_method_decl(self, method_id):
        return self._unit_id_to_method_id_loader.is_method_decl(method_id)

    def convert_unit_id_to_class_ids(self, unit_id):
        return self._unit_id_to_class_id_loader.convert_one_to_many(unit_id)
    def save_unit_id_to_class_ids(self, unit_id, class_ids):
        return self._unit_id_to_class_id_loader.save(unit_id, class_ids)
    def convert_class_id_to_unit_id(self, class_id):
        return self._unit_id_to_class_id_loader.convert_many_to_one(class_id)
    def get_all_class_ids(self):
        return self._unit_id_to_class_id_loader.get_all_items_in_many()
    def is_class_decl(self, class_id):
        return self._unit_id_to_class_id_loader.is_class_decl(class_id)
    
    def save_class_id_to_stmt_ids(self, class_id, stmt_ids):
        return self._class_id_to_stmt_id_loader.save(class_id, stmt_ids)
    def convert_class_id_to_stmt_ids(self, class_id):
        return self._class_id_to_stmt_id_loader.convert_one_to_many(class_id)
    def convert_stmt_id_to_class_id(self, stmt_id):
        return self._class_id_to_stmt_id_loader.convert_many_to_one(stmt_id)
    def save_method_id_to_stmt_ids(self, method_id, stmt_ids):
        return self._method_id_to_stmt_id_loader.save(method_id, stmt_ids)
    def convert_method_id_to_stmt_ids(self, method_id):
        return self._method_id_to_stmt_id_loader.convert_one_to_many(method_id)
    def convert_stmt_id_to_method_id(self, stmt_id):
        return self._method_id_to_stmt_id_loader.convert_many_to_one(stmt_id)

    def convert_unit_id_to_namespace_ids(self, unit_id):
        return self._unit_id_to_namespace_id_loader.convert_one_to_many(unit_id)
    def save_unit_id_to_namespace_ids(self, unit_id, namespace_ids):
        return self._unit_id_to_namespace_id_loader.save(unit_id, namespace_ids)
    def convert_namespace_id_to_unit_id(self, namespace_id):
        return self._unit_id_to_namespace_id_loader.convert_many_to_one(namespace_id)
    def get_all_namespace_ids(self):
        return self._unit_id_to_namespace_id_loader.get_all_items_in_many()
    def is_namespace_decl(self, namespace_id):
        return self._unit_id_to_namespace_id_loader.is_namespace_decl(namespace_id)

    def convert_class_id_to_class_name(self, class_id):
        return self._class_id_to_class_name_loader.convert_many_to_one(class_id)
    def convert_class_name_to_class_ids(self, class_name):
        return self._class_id_to_class_name_loader.convert_one_to_many(class_name)
    def save_class_id_to_class_name(self, class_id, class_name):
        return self._class_id_to_class_name_loader.save(class_name, class_id)

    def convert_method_id_to_method_name(self, method_id):
        return self._method_id_to_method_name_loader.convert_many_to_one(method_id)
    def convert_method_name_to_method_ids(self, method_name):
        return self._method_id_to_method_name_loader.convert_one_to_many(method_name)
    def save_method_id_to_method_name(self, method_id, method_name):
        return self._method_id_to_method_name_loader.save(method_name, method_id)

    def save_unit_symbol_decl_summary(self, unit_id, summary):
        return self._unit_symbol_decl_summary_loader.save(unit_id, summary)
    def get_unit_symbol_decl_summary(self, unit_id) -> UnitSymbolDeclSummary:
        return self._unit_symbol_decl_summary_loader.get(unit_id)

    def save_max_gir_id(self, max_gir_id):
        return self._unique_symbol_id_assigner_loader.save_max_gir_id(max_gir_id)
    def get_max_gir_id(self):
        return self._unique_symbol_id_assigner_loader.get_max_gir_id()
    def is_greater_than_max_gir_id(self, symbol_id):
        return self._unique_symbol_id_assigner_loader.is_greater_than_max_gir_id(symbol_id)
    def assign_new_unique_positive_id(self):
        return self._unique_symbol_id_assigner_loader.assign_new_unique_positive_id()
    def assign_new_unique_negative_id(self):
        return self._unique_symbol_id_assigner_loader.assign_new_unique_negative_id()

    def save_stmt_id_to_scope_id(self, stmt_id_to_scope_id_cache):
        return self._stmt_id_to_scope_id_loader.save(stmt_id_to_scope_id_cache)

    def _convert_id_to_scope(self, scope_id):
        """返回指定id对应的scope"""
        if scope_id <= 0:
            return None
        if self.stmt_scope_cache.contain(scope_id):
            return self.stmt_scope_cache.get(scope_id)
        unit_id = self.convert_stmt_id_to_unit_id(scope_id)
        if unit_id < 0: return None # 可能的，比如import的fake节点的symbol_id是虚构的
        scope_data = self.get_unit_scope_hierarchy(unit_id)
        stmt_scope = scope_data.query_index_column_value_first("stmt_id", scope_id)
        self.stmt_scope_cache.put(scope_id, stmt_scope)
        return stmt_scope

    def convert_stmt_id_to_scope_id(self, stmt_id):
        scope_id = self._stmt_id_to_scope_id_loader.get(stmt_id)
        if scope_id == -1:
            # 可能自己就是scope
            self_scope = self._convert_id_to_scope(stmt_id)
            if self_scope:
                scope_id = self_scope.scope_id
        return scope_id

    def save_unit_symbol_name_to_decl_ids(self, unit_id, symbol_name_to_decl_ids):
        return self._symbol_name_to_decl_ids_loader.save(unit_id, symbol_name_to_decl_ids)
    def get_unit_symbol_name_to_decl_ids(self, unit_id):
        return self._symbol_name_to_decl_ids_loader.get_item_by_id(unit_id)

    # def save_symbol_name_to_scope_ids(self, *args):
    #     return self._symbol_name_to_scope_ids_loader.save(*args)
    # def get_symbol_name_to_scope_ids(self, *args):
    #     return self._symbol_name_to_scope_ids_loader.get(*args)
    #
    # def save_scope_id_to_symbol_info(self, *args):
    #     return self._scope_id_to_symbol_info_loader.save(*args)
    # def get_scope_id_to_symbol_info(self, *args):
    #     return self._scope_id_to_symbol_info_loader.get(*args)
    #
    # def save_scope_id_to_available_scope_ids(self, *args):
    #     return self._scope_id_to_available_scope_ids_loader.save(*args)
    # def get_scope_id_to_available_scope_ids(self, *args):
    #     return self._scope_id_to_available_scope_ids_loader.get(*args)

    def save_entry_points(self, entry_points):
        return self._entry_points_loader.save(entry_points)
    def get_entry_points(self):
        return self._entry_points_loader.get_entry_points()
    def export_entry_points(self):
        return self._entry_points_loader.export()

    def get_method_cfg(self, method_id):
        return self._cfg_loader.get_item_by_id(method_id)
    def save_method_cfg(self, method_id, cfg):
        return self._cfg_loader.save(method_id, cfg)

    def save_symbol_bit_vector_p1(self, method_id, bit_vector):
        return self._symbol_bit_vector_manager_p1_loader.save(method_id, bit_vector)
    def get_symbol_bit_vector_p1(self, method_id):
        return self._symbol_bit_vector_manager_p1_loader.get_item_by_id(method_id)

    def save_symbol_bit_vector_p2(self, method_id, bit_vector):
        return self._symbol_bit_vector_manager_p2_loader.save(method_id, bit_vector)
    def get_symbol_bit_vector_p2(self, method_id):
        return self._symbol_bit_vector_manager_p2_loader.get_item_by_id(method_id)

    def save_symbol_bit_vector_p3(self, method_id, bit_vector):
        return self._symbol_bit_vector_manager_p3_loader.save(method_id, bit_vector)
    def get_symbol_bit_vector_p3(self, method_id):
        return self._symbol_bit_vector_manager_p3_loader.get_item_by_id(method_id)

    def save_state_bit_vector_p2(self, method_id, bit_vector):
        return self._state_bit_vector_manager_p2_loader.save(method_id, bit_vector)
    def get_state_bit_vector_p2(self, method_id):
        return self._state_bit_vector_manager_p2_loader.get_item_by_id(method_id)

    def save_state_bit_vector_p3(self, method_id, bit_vector):
        return self._state_bit_vector_manager_p3_loader.save(method_id, bit_vector)
    def get_state_bit_vector_p3(self, method_id):
        return self._state_bit_vector_manager_p3_loader.get_item_by_id(method_id)

    def save_stmt_status_p1(self, method_id, status):
        return self._stmt_status_p1_loader.save(method_id, status)
    def get_stmt_status_p1(self, method_id):
        return self._stmt_status_p1_loader.get_item_by_id(method_id)

    def save_stmt_status_p2(self, method_id, status):
        return self._stmt_status_p2_loader.save(method_id, status)
    def get_stmt_status_p2(self, method_id):
        return self._stmt_status_p2_loader.get_item_by_id(method_id)

    def save_stmt_status_p3(self, context_id, status):
        return self._stmt_status_p3_loader.save(context_id, status)
    def get_stmt_status_p3(self, context_id):
        return self._stmt_status_p3_loader.get_item_by_id(context_id)

    def save_symbol_state_space_p1(self, method_id, state_space):
        return self._symbol_state_space_p1_loader.save(method_id, state_space)
    def get_symbol_state_space_p1(self, method_id):
        return self._symbol_state_space_p1_loader.get_item_by_id(method_id)
    def contain_symbol_state_space_p1(self, method_id):
        return self._symbol_state_space_p1_loader.contain(method_id)

    def save_symbol_state_space_p2(self, method_id, state_space):
        return self._symbol_state_space_p2_loader.save(method_id, state_space)
    def get_symbol_state_space_p2(self, method_id):
        return self._symbol_state_space_p2_loader.get_item_by_id(method_id)

    def save_symbol_state_space_summary_p2(self, method_id, summary):
        return self._symbol_state_space_summary_p2_loader.save(method_id, summary)
    def get_symbol_state_space_summary_p2(self, method_id):
        return self._symbol_state_space_summary_p2_loader.get_item_by_id(method_id)

    def save_symbol_state_space_p3(self, method_id, state_space):
        return self._symbol_state_space_p3_loader.save(method_id, state_space)
    def get_symbol_state_space_p3(self, method_id):
        return self._symbol_state_space_p3_loader.get_item_by_id(method_id)

    def save_symbol_state_space_summary_p3(self, context_id, summary):
        return self._symbol_state_space_summary_p3_loader.save(context_id, summary)
    def get_symbol_state_space_summary_p3(self, context_id):
        return self._symbol_state_space_summary_p3_loader.get_item_by_id(context_id)

    def save_method_internal_callees(self, method_id, callees):
        return self._method_internal_callees_loader.save(method_id, callees)
    def get_method_internal_callees(self, method_id):
        return self._method_internal_callees_loader.get(method_id)

    def save_grouped_methods(self, grouped_methods):
        return self._grouped_methods_loader.save(grouped_methods)
    def get_grouped_methods(self):
        return self._grouped_methods_loader.get()

    def save_import_graph(self, graph):
        return self._import_graph_loader.save(graph)
    def get_import_graph(self):
        return self._import_graph_loader.get()
    def save_import_graph_nodes(self, nodes):
        return self._import_graph_loader.save_nodes(nodes)
    def get_import_graph_nodes(self):
        return self._import_graph_loader.get_nodes()
    def save_import_deps(self, deps):
        return self._import_graph_loader.save_deps(deps)
    def get_import_deps(self):
        return self._import_graph_loader.get_deps()
    def get_internal_successor_nodes_in_import_graph(self, node_id):
        return self._import_graph_loader.get_internal_successor_nodes(node_id)
    def get_external_successor_nodes_in_import_graph(self, node_id):
        return self._import_graph_loader.get_external_successor_nodes(node_id)
    def get_edges_and_nodes_with_edge_attrs_in_import_graph(self, node_id, attr_dict):
        return self._import_graph_loader.get_edges_and_nodes_with_edge_attrs(node_id, attr_dict)
    def get_import_node_with_name(self, unit_id, import_name):
        return self._import_graph_loader.get_import_node_with_name(unit_id, import_name)

    def save_type_graph(self, graph):
        return self._type_graph_loader.save(graph)
    def get_type_graph(self):
        return self._type_graph_loader.get()

    def save_classified_method_call(self, graph):
        return self._classified_method_call_loader.save(graph)
    def get_classified_method_call(self):
        return self._classified_method_call_loader.get()

    def save_call_graph_p2(self, graph):
        return self._prelim_call_graph_loader.save(graph)
    def get_call_graph_p2(self):
        return self._prelim_call_graph_loader.get()

    def save_call_paths_p3(self, paths):
        return self._global_call_path_loader.save(paths)
    def get_call_paths_p3(self):
        return self._global_call_path_loader.get_all()

    def get_caller_ids_by_id_in_p2(self, method_id):
        call_graph = self.get_call_graph_p2().graph
        return set(util.graph_predecessors(call_graph, method_id))

    def get_caller_names_by_name_in_p2(self, method_name):
        method_ids = self.convert_method_name_to_method_ids(method_name)
        caller_ids = set()
        caller_names = set()
        for method_id in method_ids:
            caller_ids = caller_ids | self.get_caller_ids_by_id_in_p2(method_id)
        for caller_id in caller_ids:
            caller_names.add(self.convert_method_id_to_method_name(caller_id))
        return caller_names

    def get_callee_ids_by_id_in_p2(self, method_id):
        call_graph = self.get_call_graph_p2().graph
        return set(util.graph_successors(call_graph, method_id))

    def get_callee_names_by_name_in_p2(self, method_name):
        method_ids = self.convert_method_name_to_method_ids(method_name)
        callee_ids = set()
        callee_names = set()
        for method_id in method_ids:
            callee_ids = callee_ids | self.get_callee_ids_by_id_in_p2(method_id)
        for caller_id in callee_ids:
            callee_names.add(self.convert_method_id_to_method_name(caller_id))
        return callee_names

    def get_caller_ids_by_id_in_p3(self, method_id, entry_point_id = -1):
        return self._global_call_path_loader.get_callers_by_method_id(method_id, entry_point_id)

    def get_caller_names_by_name_in_p3(self, method_name, entry_point_id = -1):
        method_ids = self.convert_method_name_to_method_ids(method_name)
        caller_ids = set()
        caller_names = set()
        for method_id in method_ids:
            callers = self.get_caller_ids_by_id_in_p3(method_id, entry_point_id)
            caller_ids = caller_ids | callers

        for caller_id in caller_ids:
            caller_names.add(self.convert_method_id_to_method_name(caller_id))

        return caller_names

    def get_callee_ids_by_id_in_p3(self, method_id, entry_point_id = -1):
        return self._global_call_path_loader.get_callees_by_method_id(method_id, entry_point_id)

    def get_callee_names_by_name_in_p3(self, method_name, entry_point_id = -1):
        method_ids = self.convert_method_name_to_method_ids(method_name)
        callee_ids = set()
        callee_names = set()
        for method_id in method_ids:
            callees = self.get_callee_ids_by_id_in_p3(method_id, entry_point_id)
            callee_ids = callee_ids | callees

        for callee_id in callee_ids:
            callee_names.add(self.convert_method_id_to_method_name(callee_id))

        return callee_names

    def get_lowest_common_ancestor_in_call_path_p3(self, method_id1, method_id2, entry_point_id):
        return self._global_call_path_loader.get_lowest_common_ancestor(method_id1, method_id2, entry_point_id)

    # gl: 给一个函数来查询函数调用路径吧
    # 输入是两个函数，还是两个函数列表啊，感觉列表更合理一点
    def get_call_path_between_two_methods_in_p3(self, src_method, dst_method = None):
        return self._global_call_path_loader.get_call_path_between_two_methods(src_method, dst_method)

    def get_call_path_by_entry_point(self, entry_point):
        return self._global_call_path_loader.get_call_path_by_entry_point(entry_point)

    def get_call_path_in_name_by_entry_point(self, entry_point):
        call_path = self._global_call_path_loader.get_call_path_by_entry_point(entry_point)
        all_path = []
        for path in call_path:
            path_in_name = []
            for call_site in path:
                caller_name = self.convert_method_id_to_method_name(call_site.caller_id)
                callee_name = self.convert_method_id_to_method_name(call_site.callee_id)
                if len(path_in_name) == 0 or path_in_name[-1] != caller_name:
                    path_in_name.append(caller_name)
                if len(path_in_name) == 0 or path_in_name[-1] != callee_name:
                    path_in_name.append(callee_name)

            all_path.append(path_in_name)
        return all_path
    # gl: 试了一下还是叫 get_callers/callees 更好
    # 就是参数有点复杂
    # 写的时候，根据条件分流到不同的函数吧
    def get_callers(self, method, phase="p3", match_by="name", entry_point_id=-1):
        if phase not in ("p2", "p3", "all"):
            raise ValueError("phase must be p2, p3, or all")
        if match_by not in ("name", "id"):
            raise ValueError("match must be name or id")

        if match_by == "name":
            if phase == "p2":
                return self.get_caller_names_by_name_in_p2(method)
            elif phase == "p3":
                return self.get_caller_names_by_name_in_p3(method, entry_point_id)
            else:
                result_in_p2 = self.get_caller_names_by_name_in_p2(method)
                result_in_p3 = self.get_caller_names_by_name_in_p3(method, entry_point_id)
                return result_in_p2 | result_in_p3
        else:
            if phase == "p2":
                return self.get_caller_ids_by_id_in_p2(method)
            elif phase == "p3":
                return self.get_caller_ids_by_id_in_p3(method, entry_point_id)
            else:
                result_in_p2 = self.get_caller_ids_by_id_in_p2(method)
                result_in_p3 = self.get_caller_ids_by_id_in_p3(method, entry_point_id)
                return result_in_p2 | result_in_p3

    def get_callees(self, method, phase="p3", match="name", entry_point_id=-1):
        if phase not in ("p2", "p3", "all"):
            raise ValueError("phase must be p2 or p3")
        if match not in ("name", "id"):
            raise ValueError("match must be name or id")

        if match == "name":
            if phase == "p2":
                return self.get_callee_names_by_name_in_p2(method)
            elif phase == "p3":
                return self.get_callee_names_by_name_in_p3(method, entry_point_id)
            else:
                result_in_p2 = self.get_callee_names_by_name_in_p2(method)
                result_in_p3 = self.get_callee_names_by_name_in_p3(method, entry_point_id)
                return result_in_p2 | result_in_p3
        else:
            if phase == "p2":
                return self.get_callee_ids_by_id_in_p2(method)
            elif phase == "p3":
                return self.get_callee_ids_by_id_in_p3(method, entry_point_id)
            else:
                result_in_p2 = self.get_callee_ids_by_id_in_p2(method)
                result_in_p3 = self.get_callee_ids_by_id_in_p3(method, entry_point_id)
                return result_in_p2 | result_in_p3

    def get_method_defined_symbols_p1(self, method_id):
        return self._defined_symbols_p1_loader.get_item_by_id(method_id)
    def get_method_defined_symbols_raw_p1(self, method_id):
        return self._defined_symbols_p1_loader.get_raw_item_by_id(method_id)
    def save_method_defined_symbols_p1(self, method_id, symbols):
        return self._defined_symbols_p1_loader.save(method_id, symbols)

    def get_method_defined_symbols_p2(self, method_id):
        return self._defined_symbols_p2_loader.get_item_by_id(method_id)
    def save_method_defined_symbols_p2(self, method_id, symbols):
        return self._defined_symbols_p2_loader.save(method_id, symbols)

    def get_method_defined_symbols_p3(self, context_id):
        return self._defined_symbols_p3_loader.get_item_by_id(context_id)
    def save_method_defined_symbols_p3(self, context_id, symbols):
        return self._defined_symbols_p3_loader.save(context_id, symbols)

    def get_method_defined_states_p1(self, method_id):
        return self._defined_states_p1_loader.get_item_by_id(method_id)
    def save_method_defined_states_p1(self, method_id, states):
        return self._defined_states_p1_loader.save(method_id, states)

    def get_method_defined_states_p2(self, method_id):
        return self._defined_states_p2_loader.get_item_by_id(method_id)
    def save_method_defined_states_p2(self, method_id, states):
        return self._defined_states_p2_loader.save(method_id, states)

    def get_method_used_symbols(self, method_id):
        return self._used_symbols_loader.get_item_by_id(method_id)
    def save_method_used_symbols(self, method_id, symbols):
        return self._used_symbols_loader.save(method_id, symbols)

    def get_method_symbol_graph_p2(self, method_id):
        return self._symbol_graph_p2_loader.get_item_by_id(method_id)
    def save_method_symbol_graph_p2(self, method_id, graph):
        return self._symbol_graph_p2_loader.save(method_id, graph)
    def save_method_symbol_graph_p3(self, method_id, graph):
        return self._symbol_graph_p3_loader.save(method_id, graph)

    def save_method_sfg(self, method_id, graph):
        return self._state_flow_graph_p2_loader.save(method_id, graph)
    def get_method_sfg(self, method_id):
        return self._state_flow_graph_p2_loader.get_item_by_id(method_id)
    def get_global_sfg_by_entry_point(self, method_id):
        return self._state_flow_graph_p3_loader.get_item_by_id(method_id)
    def save_global_sfg_by_entry_point(self, method_id, graph: StateFlowGraph):
        return self._state_flow_graph_p3_loader.save(method_id, graph.graph)

    def get_method_def_use_summary(self, method_id):
        return self._method_def_use_summary_loader.get_copy(method_id)
    def save_method_def_use_summary(self, method_id, summary):
        return self._method_def_use_summary_loader.save(method_id, summary)

    def get_method_summary_template(self, method_id):
        return self._method_summary_template_loader.get(method_id)
    def save_method_summary_template(self, method_id, template):
        return self._method_summary_template_loader.save(method_id, template)

    def get_method_summary_instance(self, context_id):
        return self._method_summary_template_instance.get(context_id)
    def save_method_summary_instance(self, context_id, instance):
        return self._method_summary_template_instance.save(context_id, instance)

    def get_parameter_mapping_p2(self, call_site):
        return self._callee_parameter_mapping_p2_loader.get_item_by_id(call_site)
    def save_parameter_mapping_p2(self, call_site, mapping):
        return self._callee_parameter_mapping_p2_loader.save(call_site, mapping)

    def get_parameter_mapping_p3(self, call_site):
        return self._callee_parameter_mapping_p3_loader.get_item_by_id(call_site)
    def save_parameter_mapping_p3(self, call_site, mapping):
        return self._callee_parameter_mapping_p3_loader.save(call_site, mapping)

    def get_class_method_name_by_method_id(self, method_id):
        method_name = self.convert_method_id_to_method_name(method_id)
        class_id = self.convert_method_id_to_class_id(method_id)
        class_name = self.convert_class_id_to_class_name(class_id)
        if class_name:
            return f"{class_name}.{method_name}"
        else:
            return method_name

    def _get_source_code_from_start_to_end(self, lines, start, end):
        """获取给定行数区间的source_code"""
        start_line = int(start) if not util.isna(start) else 0
        end_line = int(end) + 1 if not util.isna(end) else -1

        if start_line > 0 and end_line < len(lines):
            stmt_source_code = lines[start_line: end_line]
        else:
            stmt_source_code = lines[start_line:]
        return stmt_source_code

    def get_unit_source_code_by_stmt_id(self, stmt_id):
        """给定一个stmt_id，获取其所在unit的源代码"""
        unit_id = self.convert_stmt_id_to_unit_id(stmt_id)
        if unit_id == -1:
            return []

        unit_info = self.convert_module_id_to_module_info(unit_id)
        if not unit_info or not getattr(unit_info, "original_path", None):
            return []

        unit_path = unit_info.original_path
        try:
            with open(unit_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
            return [line.rstrip("\n") for line in lines]
        except Exception as e:
            # 可选：只在 debug 时输出，避免污染正常输出
            util.debug(f"get_unit_source_code_by_stmt_id failed: stmt_id={stmt_id}, unit_id={unit_id}, path={unit_path}, err={e}")
            return []

    def get_stmt_source_code_with_comment(self, stmt_id):
        """
            获取stmt的source_code(包含注释)
            对于method_decl语句，会获得整个方法体的源代码
        """
        if stmt_id < 0:
            return []
        unit_source_code = self.get_unit_source_code_by_stmt_id(stmt_id)
        stmt = self.get_stmt_gir(stmt_id)
        if stmt.operation == 'method_decl':
            start = stmt.start_row
            if stmt.start_row <= 0:
                start = 0
            return self._get_source_code_from_start_to_end(unit_source_code, start = start, end = stmt.end_row)
        return self._get_source_code_from_start_to_end(unit_source_code, start = stmt.start_row, end = stmt.end_row)

    def get_method_decl_source_code(self, method_id):
        """
            给定method_id，获取method_decl源代码(仅函数声明部分)
        """
        method_decl_stmt = self.get_stmt_gir(method_id)
        parameters_decl_id = None
        if util.is_available(method_decl_stmt.parameters):
            parameters_decl_id = int(method_decl_stmt.parameters) + 1 # +1才是第一个parameter_decl的位置，不+1是block_start
        unit_source_code = self.get_unit_source_code_by_stmt_id(method_id)
        if util.is_available(parameters_decl_id):
            parameters_decl = self.get_stmt_gir(parameters_decl_id)
            return self._get_source_code_from_start_to_end(unit_source_code, parameters_decl.start_row, parameters_decl.end_row)
        else:
            method_decl_line_id = int(method_decl_stmt.start_row)
            return unit_source_code[method_decl_line_id]

    def get_stmt_parent_method_source_code(self, stmt_id):
        # python文件行号从一开始，tree-sitter从0开始
        unit_id = self.convert_stmt_id_to_unit_id(stmt_id)
        unit_gir = self.get_unit_gir(unit_id)
        stmt_id_to_stmt = {}
        for row in unit_gir:
            stmt_id_to_stmt[row.stmt_id] = row

        current_stmt = stmt_id_to_stmt.get(stmt_id)
        while current_stmt and current_stmt.operation != 'method_decl':
            parent_stmt_id = current_stmt.parent_stmt_id
            current_stmt = stmt_id_to_stmt.get(parent_stmt_id)

        unit_info = self.convert_module_id_to_module_info(unit_id)
        lang_name = unit_info.lang
        unit_path = unit_info.original_path

        with open(unit_path, 'r') as f:
            lines = f.readlines()
        lines = [line.rstrip() for line in lines]

        if current_stmt.name == "%unit_init" or current_stmt.name == "%class_sinit":
            block_start_stmt_id = current_stmt.stmt_id + 1
            stmts = []
            for id, stmt in stmt_id_to_stmt.items():
                if stmt.parent_stmt_id == block_start_stmt_id:
                    stmts.append(stmt)
            code_with_comment = []
            for stmt in stmts:
                code_with_comment.extend(self._get_source_code_from_start_to_end(lines, stmt.start_row, stmt.end_row))
            return code_with_comment

        method_start_line = 0
        method_end_line = -1
        if current_stmt:
            method_start_line = int(current_stmt.start_row)
            method_end_line = int(current_stmt.end_row) + 1
        method_start_line = method_start_line - 1
        if method_start_line > 0:
            method_start_line = util.determine_comment_line(lang_name, method_start_line, lines)
        else:
            method_start_line = 0
        if method_start_line > int(current_stmt.decorators):
            method_start_line = int(current_stmt.decorators)
        code_with_comment = []
        if method_end_line > 0 and method_end_line < len(lines):
            code_with_comment = lines[method_start_line: method_end_line]
        else:
            code_with_comment = lines[method_start_line:]
        return code_with_comment

    def print_context_info_for_debug(self, stmt_id, method_id):
        unit_id = self.convert_stmt_id_to_unit_id(stmt_id)
        unit_path = self.convert_unit_id_to_unit_path(unit_id)
        method_name = self.convert_method_id_to_method_name(method_id)
        class_id = self.convert_method_id_to_class_id(method_id)
        class_name = self.convert_class_id_to_class_name(class_id)
        if util.is_empty(class_name):
            class_name = "None"

        context = {
            'unit_path': unit_path,
            'class_name': class_name,
            'method_name': method_name,
        }
        pprint.pprint(context, indent=2, width=80)

    def get_method_of_class_with_name(self, class_name:str, method_name:str) -> set[int]:
        """
            给定method_name和class_name。如果class中有同名方法，返回method_id
            ** of_class，指必须是定义在该class中的方法，不包含继承方法
        """
        res = set()

        class_ids = self.convert_class_name_to_class_ids(class_name)
        for class_id in class_ids:
            method_ids_of_class = self.convert_class_id_to_method_ids(class_id)
            for method_id in method_ids_of_class:
                curr_method_name = self.convert_method_id_to_method_name(method_id)
                if curr_method_name == method_name:
                    res.add(method_id)
        return res

    def get_target_paths_to_be_analyzed(self):
        """返回扫描的根路径"""
        return getattr(self.options, "in_path", "")

    def get_workspace_path(self):
        workspace_root = getattr(self.options, "workspace", "")
        return workspace_root + "/src" if workspace_root != "" else ""

    def convert_unit_name_to_method_ids(self, unit_name):
        method_ids = set()
        module_symbol_table = self.get_module_symbol_table()

        for module_symbol in module_symbol_table:
            if self.is_unit_id(module_symbol.unit_id) and module_symbol.unit_path.endwith(unit_name)  :
                method_ids = method_ids | self.convert_unit_id_to_method_ids(module_symbol.unit_id)

        return method_ids

    # def load_call_path_with_method_name(self, start_method_name, end_method_name, start_method_class = None, end_method_class = None, start_method_unit = None, end_method_unit = None):
    #
    #     start_method_ids = self.convert_method_name_to_method_ids(start_method_name)
    #     end_method_ids = self.convert_method_name_to_method_ids(end_method_name)
    #
    #     if start_method_class:
    #         start_method_class_ids = self.convert_class_name_to_class_ids(start_method_class)
    #         for class_id in start_method_class_ids:
    #             methods_in_class = self.convert_class_id_to_method_ids(class_id)
    #             start_method_ids = start_method_ids & methods_in_class
    #
    #     if end_method_class:
    #         end_method_class_ids = self.convert_class_name_to_class_ids(end_method_class)
    #         for class_id in end_method_class_ids:
    #             methods_in_class = self.convert_class_id_to_method_ids(class_id)
    #             end_method_ids = end_method_ids & methods_in_class
    #
    #     if start_method_unit:
    #         unit_method_ids = self.convert_unit_name_to_method_ids(start_method_unit)
    #         start_method_ids = start_method_ids & unit_method_ids
    #
    #     if end_method_unit:
    #         unit_method_ids = self.convert_unit_name_to_method_ids(end_method_unit)
    #         end_method_ids = end_method_ids & unit_method_ids
    #
    #     call_paths = self.load_call_paths_p3()
    #     all_paths = set()
    #     for call_path in call_paths:
    #         index = 0
    #         path = call_path.path
    #         if len(path) < 2:
    #             continue
    #         start_index = -1
    #         while index <= len(path):
    #             if path[index] in start_method_ids:
    #                 start_index = index
    #                 break
    #             index = index + 2
    #         if start_index == -1:
    #             continue
    #
    #         end_index = -1
    #             # 检查起始函数之后的所有函数
    #
    #         while index > start_index:
    #             if path[index] in end_method_ids:
    #                 end_index = index
    #             index = index - 2
    #
    #         if end_index == -1:
    #             continue
    #
    #         # while index < len(methods):

    def get_parent_class_by_class_name(self, class_name):
        type_graph = self.get_type_graph().graph
        class_relevant_info = []
        for u, v, wt in type_graph.edges(data="weight"):
            if wt.name == class_name:
                if wt.parent_name.startswith("%vv"):
                    # TODO 还原这里的%vv的AccessPath
                    pass
                class_relevant_info.append(TypeNode(
                    name = class_name,
                    class_stmt_id = u,
                    parent_id = v,
                    parent_name = wt.parent_name,
                    parent_index = wt.parent_pos
                ))
        return class_relevant_info

    def get_son_class_by_class_name(self, class_name):
        type_graph = self.get_type_graph().graph
        class_relevant_info = []
        for u, v, wt in type_graph.edges(data="weight"):
            if class_name in wt.parent_name:
                class_relevant_info.append(TypeNode(
                    name=wt.name,
                    class_stmt_id=u,
                    parent_id=v,
                    parent_name=class_name,
                    parent_index=wt.parent_pos
                ))
        return class_relevant_info

    def get_yaml_info(self, unit_path: str, line_num: int):
        unit_id = self.convert_unit_path_to_unit_id(unit_path)
        if unit_id == -1:
            return -1

        unit_gir = self._gir_loader.get_item_by_id(unit_id)
        if unit_gir is None:
            return -1

        for stmt in unit_gir:
            start_row = stmt.start_row + 1
            if math.isnan(start_row):
                continue
            if start_row == line_num:
                return self.convert_stmt_id_to_method_id(stmt.stmt_id)
        return -1


    def get_rule_method(self, rule):
        method_ids = set()
        module_symbol_table = self.get_module_symbol_table()

        if not rule.line_num :
            return -1
        if not rule.unit_path and not rule.unit_name:
            return -1
        if rule.unit_path:
            for module_symbol in module_symbol_table:
                if module_symbol.original_path == rule.unit_path:
                    unit_id = module_symbol.unit_id
                    method_ids = self.convert_unit_id_to_method_ids(unit_id)
        elif rule.unit_name:
            for module_symbol in module_symbol_table:
                if isinstance(module_symbol.original_path, float) and math.isnan(module_symbol.original_path):
                    continue
                if not os.path.isfile(module_symbol.original_path):
                    continue
                if os.path.basename(module_symbol.original_path) == rule.unit_name:
                    unit_id = module_symbol.unit_id
                    method_ids.update(self.convert_unit_id_to_method_ids(unit_id))
        for method_id in method_ids:
            method_stmt = self.get_stmt_gir(method_id)
            start_row = method_stmt.start_row + 1
            end_row = method_stmt.end_row + 1
            if math.isnan(start_row):
                continue
            if int(start_row) <= rule.line_num <= int(end_row):
                return method_id
        return -1

    def get_call_path_from_sources_to_sinks(self, source_rules, sink_rules):
        call_paths = []
        for source in source_rules:
            source_method_id = self.get_rule_method(source)
            for sink in sink_rules:
                sink_method_id = self.get_rule_method(sink)
                result = self.get_call_path_between_two_methods_in_p3(source_method_id, sink_method_id)
                if len(result) > 0:
                    call_paths.append(self.get_call_path_between_two_methods_in_p3(source_method_id, sink_method_id))

        return call_paths
    
    def _is_stmt_source_or_sink(self, stmt, unit_path, rules):
        gir_str = readable_gir.get_gir_str(stmt)
        for rule in rules:
            if rule.line_num:
                if util.is_empty(stmt.start_row):
                    continue
                if rule.line_num < stmt.start_row + 1 or stmt.end_row + 1 < rule.line_num:
                    continue
            
            # 快速检查：符号名是否在字符串中
            if rule.symbol_name in gir_str:
                # 如果在，再进行精确的单词边界匹配
                pattern = r'\b' + re.escape(rule.symbol_name) + r'\b'
                if re.search(pattern, gir_str):
                    return True
        return False
        
    def _filter_rules_by_unit_path(self, unit_path, rules):
        new_rules = []
        for each_rule in rules:
            if each_rule.unit_path:
                if each_rule.unit_path in unit_path:
                    new_rules.append(each_rule)
            else:
                new_rules.append(each_rule)
        return new_rules

    def get_source_sink_stmt_ids_by_rules(self):
        rule_manager = RuleManager()
        source_stmt_ids = set()
        sink_stmt_ids = set()

        for unit_info in self.get_all_unit_info():
            unit_id = unit_info.module_id
            unit_gir = self.get_unit_gir(unit_id)
            unit_path = unit_info.original_path

            source_rules = self._filter_rules_by_unit_path(unit_path, rule_manager.all_sources_from_code)
            sink_rules = self._filter_rules_by_unit_path(unit_path, rule_manager.all_sinks_from_code)
            if not unit_gir:
                continue
            for stmt in unit_gir:
                if self._is_stmt_source_or_sink(stmt, unit_path, source_rules):
                    source_stmt_ids.add(stmt.stmt_id)
                if self._is_stmt_source_or_sink(stmt, unit_path, sink_rules):
                    sink_stmt_ids.add(stmt.stmt_id)

        return source_stmt_ids, sink_stmt_ids

