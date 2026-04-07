#!/usr/bin/env python3

import os
import pprint
import re
import sys
import yaml
import dataclasses
import lian.events.event_return as er
from lian.events.handler_template import EventData
from lian.config import config
from lian.config.constants import (
    LIAN_SYMBOL_KIND,
    RULE_KIND,
    CONFIG_ITEM_Kind,
    ACCESS_POINT_KIND
)
from lian.externs.extern_rule import Rule
from lian.externs.modeling import js_api
from lian.common_structs import AccessPoint, InterruptionData, State, Symbol
from lian.util import util


@dataclasses.dataclass
class ConfigurationItem:
    kind: int = CONFIG_ITEM_Kind.ARG
    arg_pos: int = -1

class ExternSystem:
    def __init__(self, options, loader, resolver):
        self.options = options
        self.resolver = resolver
        self.loader = loader
        self.rule_id = config.RULE_START_ID
        self.lang_to_externs = {}
        self.method_name_to_externs = {}

    def check_externs(self, path):
        pass

    def validate_rule(self, rule):
        if not isinstance(rule, Rule):
            return False

        if len(rule.method_name) == 0:
            return False

        if rule.kind == RULE_KIND.RULE:
            if len(rule.src) == 0 and len(rule.dst) == 0 and rule.unset is False:
                return False
        elif rule.kind == RULE_KIND.CODE:
            if rule.mock_id in (0, -1):
                return False
        elif rule.kind == RULE_KIND.MODEL:
            if util.is_empty(rule.model_method):
                return False

        return True

    def install_rule(self, rule):
        if not self.validate_rule(rule):
            return

        rule.rule_id = self.rule_id
        self.rule_id += 1

        if rule.lang not in self.lang_to_externs:
            self.lang_to_externs[rule.lang] = {}

        method_name_to_externs = self.lang_to_externs[rule.lang]
        if rule.method_name not in method_name_to_externs:
            method_name_to_externs[rule.method_name] = []

        method_name_to_externs[rule.method_name].append(rule)

    def install_mock_code_file(self, unit_info, unit_scope):
        if not unit_info.original_path.startswith(config.EXTERNS_MOCK_CODE_DIR):
            return

        method_decls = unit_scope.query_index_column_value(
            "scope_kind", LIAN_SYMBOL_KIND.METHOD_KIND
        )

        for each_method in method_decls:
            class_name = ""
            method_name = each_method.name
            if config.MOCK_METHOD_NAME_SEPARATOR in each_method.name:
                class_name, method_name = self.split_name_to_class_and_method_name(each_method.name, config.MOCK_METHOD_NAME_SEPARATOR)

            a_rule = Rule(
                kind = RULE_KIND.CODE,
                lang = unit_info.lang,
                class_name = class_name,
                method_name = method_name,
                mock_path = unit_info.unit_path,
                mock_id = each_method.stmt_id
            )
            self.install_rule(a_rule)

    def scan_rule_path(self, target_path, configuration_files):
        for root, dirs, files in os.walk(target_path):
            for file in files:
                file_path = os.path.join(root, file)
                if os.path.isdir(file_path):
                    self.scan_rule_path(file_path, configuration_files)
                elif os.path.isfile(file_path):
                    if file_path.endswith(".yaml"):
                        configuration_files.append(file_path)

    def safe_read_configuration_element(self, rule, element, default = []):
        if rule:
            if element in rule:
                content = rule[element]
                if content:
                    return content
        return default

    def validate_configuration_data(self, data):
        if not isinstance(data, dict):
            return False

        if "lang" not in data or "rules" not in data:
            return False

        if util.is_empty(data["lang"]) or util.is_empty(data["rules"]):
            return False

        return True

    def validate_configuration_rule(self, each_rule):
        if each_rule:
            if "name" not in each_rule or "dst" not in each_rule:
                return False

    def split_name_to_class_and_method_name(self, name, separator = "."):
        splitted_name = name.split(separator)
        if len(splitted_name) == 0:
            return ("", "")

        if len(splitted_name) == 1:
            return ("", splitted_name[0])

        return (".".join(splitted_name[:-1]), splitted_name[-1])

    def extract_argument_number(self, content):
       pattern = r'%arg(\d+)'
       match = re.match(pattern, content)
       if match:
           return int(match.group(1))
       return None

    def parse_configuration_src_and_dst_item(self, items):
        results = []
        if not items:
            return []

        for index, each_item in enumerate(items):
            splitted_names = each_item.split(".")
            for each_split in splitted_names:
                if each_split.startswith("%return"):
                    results.append(ConfigurationItem(kind=CONFIG_ITEM_Kind.RETURN))
                elif each_split.startswith("%arg"):
                    pos = self.extract_argument_number(each_split)
                    if util.is_available(pos):
                        results.append(ConfigurationItem(kind=CONFIG_ITEM_Kind.ARG, arg_pos=index))
                elif each_split.startswith("%this"):
                    results.append(ConfigurationItem(kind=CONFIG_ITEM_Kind.THIS))
        return results

    def parse_configuration_rule(self, configuration_file):
        results = []
        data = None
        with open(configuration_file, 'r') as file:
            data = yaml.safe_load(file)

        if self.validate_configuration_data(data) is False:
            return results

        lang = data["lang"]
        rules = data["rules"]
        for each_rule in rules:
            name = self.safe_read_configuration_element(each_rule, "name", default="")
            src = self.safe_read_configuration_element(each_rule, "src")
            dst = self.safe_read_configuration_element(each_rule, "dst")
            if len(name) == 0 or len(dst) == 0:
                continue

            class_name, method_name = self.split_name_to_class_and_method_name(name)
            if len(method_name) == 0:
                continue

            src_results = self.parse_configuration_src_and_dst_item(src)
            dst_results = self.parse_configuration_src_and_dst_item(dst)

            a_rule = Rule(
                kind = RULE_KIND.RULE,
                lang = lang,
                class_name= class_name,
                method_name = method_name,
                src = src_results,
                dst = dst_results
            )
            results.append(a_rule)

        return results

    def install_configuration_rules(self):
        configuration_files = []
        self.scan_rule_path(config.EXTERN_RULES_DIR, configuration_files)
        if len(configuration_files) == 0:
            return

        for each_rule_file in configuration_files:
            rules = self.parse_configuration_rule(each_rule_file)
            for each_rule in rules:
                self.install_rule(each_rule)

    def install_model_methods(self):
        all_model_methods = self.register_model_methods()
        for each_rule in all_model_methods:
            self.install_rule(each_rule)

    def display_all_installed_rules(self):
        if self.options.debug:
            pprint.pprint(self.lang_to_externs)

    def copy_src_state_indexes(self, frame, state_analysis, status, stmt_id, src_state_indexes):
        new_src_states = set()
        for state_index in src_state_indexes:
            new_state_index = state_analysis.create_copy_of_state_and_add_space(
                status, stmt_id, state_index, overwritten_flag = True
            )
            new_state = frame.symbol_state_space[new_state_index]
            new_state.access_path.append(AccessPoint(
                kind = ACCESS_POINT_KIND.BUILTIN_METHOD,
                state_id=new_state.state_id,
            ))
            new_src_states.add(new_state_index)
        return new_state_index

    def exec_configuration_rule(self, rule, data):
        stmt_id = data.stmt_id
        status = data.status
        frame = data.frame
        state_analysis = data.state_analysis

        all_arg_state_indexes = []
        arg_symbol_indexes = []
        if len(status.used_symbols) > 1:
            arg_symbol_indexes = status.used_symbols[1:]

        for symbol_index in arg_symbol_indexes:
            state_indexes = data.state_analysis.read_used_states(symbol_index, data.in_states)
            all_arg_state_indexes.append(state_indexes)

        defined_symbol = data.defined_symbol

        src_state_indexes = set()
        for each_src_item in rule.src_state_indexes:
            if each_src_item.kind == CONFIG_ITEM_Kind.ARG:
                if each_src_item.arg_pos < len(all_arg_state_indexes):
                    current_states = all_arg_state_indexes[each_src_item.arg_pos]
                    src_state_indexes.update(current_states)
            elif each_src_item.kind == CONFIG_ITEM_Kind.RETURN:
                src_state_indexes.update(defined_symbol.states)
            elif each_src_item.kind == CONFIG_ITEM_Kind.THIS:
                pass

        for each_dst_item in rule.dst_results:
            if each_dst_item.kind == CONFIG_ITEM_Kind.ARG:
                if each_dst_item.arg_pos + 1 < len(status.used_symbols):
                    arg_symbol = status.used_symbols[each_dst_item.arg_pos + 1]
                    if isinstance(arg_symbol, Symbol):
                        pass
                    arg_symbol.states = self.copy_src_state_indexes(frame, state_analysis, status, stmt_id, src_state_indexes)
            elif each_dst_item.kind == CONFIG_ITEM_Kind.RETURN:
                defined_symbol.states = src_state_indexes
            elif each_dst_item.kind == CONFIG_ITEM_Kind.THIS:
                pass

    def exec_mock_code(self, rule, data):
        in_data = data.in_data
        args = in_data.args
        data.out_data = in_data.state_analysis.compute_target_method_states(
            in_data.stmt_id, in_data.stmt, in_data.status, in_data.in_states, {rule.mock_id}, in_data.defined_symbol, args
        )

    def exec_model_method(self, rule, data):
        return rule.model_method(data)

    def is_method_analyzed(self, data, method_id):
        return method_id in data.in_data.state_analysis.analyzed_method_list

    def are_methods_in_rules_prepared(self, rules, data, unanalyzed_method_ids):
        for each_rule in rules:
            if each_rule.kind == RULE_KIND.CODE:
                if not self.is_method_analyzed(data, each_rule.mock_id):
                    unanalyzed_method_ids.add(each_rule.mock_id)
                    return False
        return True

    def find_and_apply_rules(self, rules, data):
        for each_rule in rules:
            if each_rule.kind == RULE_KIND.CODE:
                self.exec_mock_code(each_rule, data)
            elif each_rule.kind == RULE_KIND.RULE:
                self.exec_configuration_rule(each_rule, data)
            elif each_rule.kind == RULE_KIND.MODEL:
                self.exec_model_method(each_rule, data)

    def init(self):
        self.install_model_methods()
        self.install_configuration_rules()

    def find_proper_rules(self, data):
        in_data = data.in_data
        frame = in_data.frame
        unsolved_callee_states = in_data.unsolved_callee_states

        method_names = []
        for unsolved_state_index in unsolved_callee_states:
            unsolved_state = frame.symbol_state_space[unsolved_state_index]
            if not isinstance(unsolved_state, State):
                continue

            access_path = unsolved_state.access_path
            if len(access_path) > 0:
                last_point_name = access_path[-1].key
                if type(last_point_name) == str and not last_point_name.startswith("%"):
                    method_names.append(last_point_name)

        if len(method_names) == 0:
            return []

        all_rules = []
        for lang in (data.lang, config.ANY_LANG):
            if lang in self.lang_to_externs:
                method_name_to_externs = self.lang_to_externs[lang]
                for each_name in method_names:
                    if each_name in method_name_to_externs:
                        all_rules.extend(method_name_to_externs[each_name])

        return all_rules

    def handle(self, data: EventData):
        all_rules = self.find_proper_rules(data)
        if len(all_rules) == 0:
            return

        in_data = data.in_data
        frame = in_data.frame
        unanalyzed_method_ids = set()
        if self.are_methods_in_rules_prepared(all_rules, data, unanalyzed_method_ids):
            self.find_and_apply_rules(all_rules, data)

        if len(unanalyzed_method_ids) != 0:
            flag = in_data.p2result_flag
            flag.interruption_flag = True,
            flag.interruption_data = InterruptionData(
                caller_id = frame.method_id,
                call_stmt_id = in_data.stmt_id,
                callee_ids = unanalyzed_method_ids
            )
            return er.EventHandlerReturnKind.INTERRUPTION_CALL

        return er.EventHandlerReturnKind.SUCCESS

    def register_model_methods(self):
        # 不要写死，用options配置
        all_modelings = dict()
        if hasattr(self.options, "extern_path") and self.options.extern_path:
            # all_modelings["abc"] = []
            # sys.path.append(self.options.extern_path)  # 添加绝对路径
            # from externs.modeling import abc_modeling
            # method_name_to_model = abc_modeling.METHOD_NAME_TO_MODEL
            # for key, value in method_name_to_model.items():
            #     all_modelings["abc"].append(Rule(method_name=key, model_method=value))
            pass
        else:
            all_modelings[config.ANY_LANG] = []

            all_modelings["python"] = []

            all_modelings["java"] = []

            all_modelings["csharp"] = []

            all_modelings["llvm"] = []

            all_modelings["abc"] = []

            all_modelings["php"] = []

            all_modelings["typescript"] = []

            all_modelings["arkts"] = []

            all_modelings["javascript"] = [
                Rule(method_name="call", model_method=js_api.js_call),
                Rule(method_name="then", model_method=js_api.js_then),
            ]

        results = []
        for lang in all_modelings:
            for each_rule in all_modelings[lang]:
                each_rule.kind = RULE_KIND.MODEL
                each_rule.lang = lang
                results.append(each_rule)

        return results

