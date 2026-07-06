#!/usr/bin/env python3

import os
import ast
import yaml
import dataclasses,pprint
import lian.util.data_model as dm

from lian.util import util
from lian.config import config
from lian.util.loader import Loader
from lian.config.constants import (LIAN_SYMBOL_KIND)

@dataclasses.dataclass
class EntryPointRule:
    lang: str = ""
    unit_id: int = -1
    unit_path: str = ""
    unit_name: str = ""
    method_id: int = -1
    method_list: list[str] = dataclasses.field(default_factory=list)
    attrs: list[str] = dataclasses.field(default_factory=list)
    args: str = ""
    return_type: str = ""

    def __post_init__(self):
        self.check_availablility()
    
    def check_availablility(self):
        self.is_lang_available = util.is_available(self.lang)
        self.is_unit_name_available = util.is_available(self.unit_name)
        self.is_unit_path_available = util.is_available(self.unit_path)
        self.is_method_list_available = util.is_available(self.method_list)
        self.is_attrs_available = util.is_available(self.attrs)
        self.is_args_available = util.is_available(self.args)
        self.is_return_type_available = util.is_available(self.return_type)

class EntryPointGenerator:
    def __init__(self, options, event_manager, loader) -> None:
        self.options = options
        self.event_manager = event_manager
        self.loader:Loader = loader
        self.entry_point_rules = []
        self.entry_point_results = set()
        self._load_settings()

    def _parse_config_file(self, file_path):
        # 判断是否可以打开
        if not os.path.isfile(file_path):
            util.error("Failed to open entry point file: " + file_path)
            return

        data = None
        with open(file_path, "r") as f:
            data = yaml.safe_load(f)
            if data is None:
                util.error("Failed to load entry point file: " + file_path)
                return

        for line in data:
            try:
                self.entry_point_rules.append(
                    EntryPointRule(
                        **line
                    )
                )
            except Exception as e:
                util.error_and_quit(f"Failed to parse entry point file ({file_path}), error: {e}")

    def _load_settings(self):
        for root, dirs, files in os.walk(self.options.default_settings):
            for file_name in files:
                processing_flag, _ = util.check_file_processing_flag_and_extract_lang(file_name, config.ENTRY_POINTS_FILE)
                if not processing_flag:
                    continue

                self._parse_config_file(os.path.join(root, file_name))

    def filter_rule_by_unit_info(self, unit_info):
        unit_name = os.path.basename(unit_info.unit_path)
        candidate_rules = []

        for rule in self.entry_point_rules:
            # 按语言过滤
            if rule.is_lang_available and rule.lang != unit_info.lang:
                continue

            # 按 unit_id 过滤（精确匹配）
            if rule.unit_id >= 0 and rule.unit_id != unit_info.module_id:
                continue

            # 按 unit_name 过滤（子串包含）
            if rule.is_unit_name_available and rule.unit_name not in unit_name:
                continue

            # 按 unit_path 过滤（子串包含）
            if rule.is_unit_path_available and rule.unit_path not in unit_info.unit_path:
                continue

            # 通过 unit 级别过滤，加入候选
            candidate_rules.append(rule)

        return candidate_rules
    
    def check_rules(self, unit_info, unit_scope, candidate_rules):
        all_method_scopes = unit_scope.query_index_column_value("scope_kind", LIAN_SYMBOL_KIND.METHOD_KIND)
        for scope in all_method_scopes:
            name = scope.name if util.is_available(scope.name) else ""
            attrs = scope.attrs if util.is_available(scope.attrs) else ""
            args = ""  # 当前未从 scope 获取 args，可后续扩展
            return_type = ""  # 同上

            matched = False
            for rule in candidate_rules:
                # 跳过已由 unit_id/unit_name/unit_path/lang 排除的规则（已在上一步处理）

                # 检查 method_id（精确匹配）
                if rule.method_id >= 0:
                    if rule.method_id == scope.stmt_id:
                        matched = True
                        break
                    else:
                        continue  # 此规则不匹配当前 method

                # 检查 method_list（名称列表）
                if rule.is_method_list_available and name not in rule.method_list:
                    continue

                # 检查 attrs（全包含）
                if rule.is_attrs_available:
                    if not attrs or not all(attr in attrs for attr in rule.attrs):
                        continue

                # 检查 args（当前未实现，保留逻辑）
                if rule.is_args_available and rule.args != args:
                    continue

                # 检查 return_type（当前未实现，保留逻辑）
                if rule.is_return_type_available and rule.return_type != return_type:
                    continue

                # 所有条件通过
                matched = True
                break

            if matched:
                self.entry_point_results.add(scope.stmt_id)
                
    def collect_entry_points_from_unit_scope(self, unit_info, unit_scope):
        # Step 1: 预筛选与当前 unit_info 匹配的规则
        candidate_rules = self.filter_rule_by_unit_info(unit_info)
        # 如果没有候选规则，直接跳过
        if not candidate_rules:
            return
        # Step 2: 遍历方法，仅用候选规则判断
        self.check_rules(unit_info, unit_scope, candidate_rules)

        # Step 3: 导出结果
        self.loader.save_entry_points(self.entry_point_results)

    def collect_fallback_c_entry_points(self, c_like_unit_scopes):
        if not c_like_unit_scopes or self.entry_point_results:
            return

        for unit_info, unit_scope in c_like_unit_scopes:
            all_method_scopes = unit_scope.query_index_column_value("scope_kind", LIAN_SYMBOL_KIND.METHOD_KIND)
            for scope in all_method_scopes:
                attrs = scope.attrs if util.is_available(scope.attrs) else ""
                if attrs and "static" in str(attrs):
                    continue
                self.entry_point_results.add(scope.stmt_id)

        if self.entry_point_results:
            self.loader.save_entry_points(self.entry_point_results)

