#!/usr/bin/env python3

# "lian/src/lian/externs/extern_rule.py"

# add source tag
# - interface: add_tag(tag, value)
# - .yaml config

import dataclasses
import os

import yaml
from lian.config import config
from lian.util import util

class Source:
    def __init__(self, name, tag, value):
        self.name = name
        self.tag = tag
        self.value = value


@dataclasses.dataclass
class Rule:
    """
    rule_id                 : id of rule
    rule_type               : code or rule

    lang                    : language
    name                    : name of class_name.method_name
    args                    : arguments of args

    A rule:
        how to write a rule of src/dst?
            - %this         : access this
            - %arg[0-9]+    : access argument
            - %return       : access return value
            - .             : access internal field
        should unset the taint?
            - unset         : unset the taint
    """
    rule_id: int = -1

    kind: int = -1
    lang: str = config.ANY_LANG
    name: str = ""
    operation: str = ""
    receiver: str = ""
    field: list = dataclasses.field(default_factory=list)
    target: str = ""
    args: list = dataclasses.field(default_factory=list)
    tag: list = dataclasses.field(default_factory=list)
    src: list = dataclasses.field(default_factory=list)
    dst: list = dataclasses.field(default_factory=list)
    attr: str = ""
    unset: bool = False
    unit_path: str = ""
    unit_name: str = ""
    line_num: str = ""
    key: str = ""
    vuln_type: str = ""
    # mock_path: str          = ""
    # mock_id: int            = -1

    # model_method: object    = None

    # def __repr__(self):
    #     return f"Rule(rule_id={self.rule_id}, kind={self.kind}, lang={self.lang}, class_name={self.class_name}, method_name={self.method_name}, args={self.args}, src={self.src}, dst={self.dst}, unset={self.unset}, mock_path={self.mock_path}, mock_id={self.mock_id}, model_method={self.model_method})"

    def to_dict(self):
        return {
            "rule_id": self.rule_id,
            "kind": self.kind,
            "lang": self.lang,
            "name": self.name,
            "operation": self.operation,
            "receiver": self.receiver,
            "field": self.field,
            "args": self.args,
            "tag": self.tag,
            "src": self.src,
            "dst": self.dst,
            "unset": self.unset,
            "unit_path": self.unit_path,
            "unit_name": self.unit_name,
            "line_num": self.line_num,
            "key": self.key,
        }

@dataclasses.dataclass
class SourceCodeRule:
    unit_path: str = ""
    line_num: str = ""
    symbol_name: str = ""
    kind: int = -1
    lang: str = config.ANY_LANG


class RuleManager:
    def __init__(self, default_settings = None):
        self.all_sources = []
        self.all_sinks = []
        self.all_propagations = []
        self.all_sources_from_code = []
        self.all_sinks_from_code = []
        self.taint_source = config.TAINT_SOURCE
        self.taint_sink = config.TAINT_SINK
        self.taint_prop = config.TAINT_PROPAGATION
        self.taint_source_from_code = config.TAINT_SOURCE_FROM_CODE
        self.taint_sink_from_code = config.TAINT_SINK_FROM_CODE
        self.default_settings = default_settings
        if default_settings:
            self.taint_source = os.path.join(default_settings, "source.yaml")
            self.taint_sink = os.path.join(default_settings, "sink.yaml")
            self.taint_prop = os.path.join(default_settings, "propagation.yaml")

        self.init()

    def init(self):
        if self.default_settings:
            with open(self.taint_source, 'r') as file:
                data = yaml.safe_load(file)
                rule_kind = "source"
                for rule_group in data:
                    lang = rule_group["lang"]
                    rules = rule_group["rules"]
                    for rule in rules:
                        new_rule = Rule(
                            kind=rule_kind,
                            lang=lang,
                            name=rule.get("name", None),
                            operation=rule.get("operation", None),
                            receiver=rule.get("receiver", None),
                            field=rule.get("field", []),
                            target=rule.get("target", None),
                            args=rule.get("args", None),
                            tag=rule.get("tag", None),
                            src=rule.get("src", None),
                            dst=rule.get("dst", None),
                            attr=rule.get("attr", None),
                            unit_path=rule.get("unit_path", None),
                            unit_name=rule.get("unit_name", None),
                            line_num=rule.get("line_num", None),
                            key=rule.get("key", None),
                            unset=rule.get("unset", None)
                        )
                        self.all_sources.append(new_rule)

            with open(self.taint_sink, 'r') as file:
                data = yaml.safe_load(file)
                rule_kind = "sink"
                for rule_group in data:
                    lang = rule_group["lang"]
                    rules = rule_group["rules"]
                    for rule in rules:
                        new_rule = Rule(
                            kind=rule_kind,
                            lang=lang,
                            name=rule.get("name", None),
                            operation=rule.get("operation", None),
                            receiver=rule.get("receiver", None),
                            field=rule.get("field", []),
                            target=rule.get("target", None),
                            args=rule.get("args", None),
                            tag=rule.get("tag", None),
                            src=rule.get("src", None),
                            dst=rule.get("dst", None),
                            unit_path=rule.get("unit_path", None),
                            unit_name=rule.get("unit_name", None),
                            line_num=rule.get("line_num", None),
                            key=rule.get("key", None),
                            unset=rule.get("unset", None),
                            vuln_type=rule.get("vuln_type", None),
                        )
                        self.all_sinks.append(new_rule)

            with open(self.taint_prop, 'r') as file:
                data = yaml.safe_load(file)
                rule_kind = "prop"
                for rule_group in data:
                    lang = rule_group["lang"]
                    rules = rule_group["rules"]
                    for rule in rules:
                        new_rule = Rule(
                            kind=rule_kind,
                            lang=lang,
                            name=rule.get("name", None),
                            operation=rule.get("operation", None),
                            receiver=rule.get("receiver", None),
                            field=rule.get("field", []),
                            target=rule.get("target", None),
                            args=rule.get("args", None),
                            tag=rule.get("tag", None),
                            src=rule.get("src", None),
                            dst=rule.get("dst", None),
                            unit_path=rule.get("unit_path", None),
                            unit_name=rule.get("unit_name", None),
                            line_num=rule.get("line_num", None),
                            unset=rule.get("unset", None)
                        )
                        self.all_propagations.append(new_rule)

        with open(self.taint_source_from_code, 'r') as file:
            data = yaml.safe_load(file)
            rule_kind = "source"
            for rule_group in data:
                lang = rule_group["lang"]
                rules = rule_group["rules"]
                for rule in rules:
                    new_rule = SourceCodeRule(
                        kind=rule_kind,
                        lang=lang,
                        unit_path=rule.get("unit_path", None),
                        line_num=rule.get("line_num", None),
                        symbol_name=rule.get("symbol_name", None),
                    )
                    self.all_sources_from_code.append(new_rule)

        with open(self.taint_sink_from_code, 'r') as file:
            data = yaml.safe_load(file)
            rule_kind = "sink"
            for rule_group in data:
                lang = rule_group["lang"]
                rules = rule_group["rules"]
                for rule in rules:
                    new_rule = SourceCodeRule(
                        kind=rule_kind,
                        lang=lang,
                        unit_path=rule.get("unit_path", None),
                        line_num=rule.get("line_num", None),
                        symbol_name=rule.get("symbol_name", None),
                    )
                    self.all_sinks_from_code.append(new_rule)

    def add_rule(self, rule_type, rule):
        pass

    def delete_rule(self, rule_type, rule):
        pass
