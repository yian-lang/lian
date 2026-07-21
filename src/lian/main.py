#!/usr/bin/env python3
import os
import sys
############################################################
# Initliaze the configuration
############################################################
# Support empty
import builtins
import types

try:
    builtins.profile
except AttributeError:
    def profile(func):
        return func
    builtins.profile = profile
# Disable copy
import pandas as pd
pd.options.mode.copy_on_write = False

# Init path - 添加 lian 模块的父目录
sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

############################################################
# Essential content
############################################################
from lian import (
    preparation,
    args_parser
)

from lian.config import constants, config
from lian.events.event_manager import EventManager
from lian.config import config, constants, lang_config
from lian.util import util
from lian.util.loader import Loader
from lian.lang.lang_analysis import LangAnalysis
from lian.basics.basic_analysis import P1BasicSemanticAnalysis
from lian.core.prelim_semantics import P2PrelimSemanticAnalysis
from lian.core.global_semantics import P3GlobalSemanticAnalysis
from lian.core.resolver import Resolver
from lian.incremental.unit_level_incremental_checker import UnitLevelIncrementalChecker
from lian.externs.extern_system import ExternSystem
from lian.taint.taint_analysis import TaintAnalysis

class Lian:
    def __init__(self):
        self.args_parser = args_parser.ArgsParser()
        self.options: types.SimpleNamespace = self.args_parser.obtain_default_options()

        self.event_manager: EventManager = None
        self.loader: Loader = None
        self.extern_system: ExternSystem = None
        self.resolver: Resolver = None
        self.problem_monitor = None
        self.lang_table = lang_config.LANG_TABLE
        self.command_handler = {
            "lang"           :     self.lang_cmd,
            "semantic"       :     self.semantic_cmd,
            "taint"          :     self.taint_analysis,
            "run"            :     self.run_all,
        }

        self.set_workspace_dir_flag = False

    def parse_cmds(self, **custom_options):
        self.options = self.args_parser.init().parse_cmds()

        if self.options.quiet:
            self.options.debug = False

        if not hasattr(self.options, "default_settings") or len(self.options.default_settings) == 0:
            self.options.default_settings = config.DEFAULT_SETTINGS
        if not hasattr(self.options, "addition_settings") or len(self.options.addition_settings) == 0:
            self.options.addition_settings = ""

        if util.is_available(custom_options):
            if isinstance(self.options, dict):
                for key, value in custom_options.items():
                    if key in self.options:
                        self.options[key] = value
            else:
                for key, value in custom_options.items():
                    if hasattr(self.options, key):
                        setattr(self.options, key, value)

        config.COMPLETE_SFG_DUMP_FLAG = self.options.complete_graph
        
        return self

    def set_workspace_dir(self, default_workspace_dir = config.DEFAULT_WORKSPACE):
        self.set_workspace_dir_flag = True
        if default_workspace_dir not in self.options.workspace:
            self.options.workspace = os.path.join(self.options.workspace, default_workspace_dir)
        self.options.default_workspace_dir = default_workspace_dir
        return self

    def update_lang_config(self):
        lang_config.update_lang_extensions(self.lang_table, self.options.lang)

        file_extensions = []
        for lang in self.options.lang:
            file_extensions.extend(lang_config.LANG_EXTENSIONS.get(lang, []))
        self.options.lang_extensions = file_extensions

    def init_submodules(self, other_init = None):
        # Analyze options
        config.DEBUG_FLAG = self.options.debug
        if self.options.debug:
            util.debug(self.options)

        if not self.set_workspace_dir_flag:
            self.set_workspace_dir()

        # update lang config & options.lang_extensions
        self.update_lang_config()

        self.event_manager = EventManager(self.options)
        self.loader = Loader(self.options)
        self.resolver = Resolver(self.options, self.event_manager, self.loader)
        self.extern_system = ExternSystem(self.options, self.loader, self.resolver)
        self.event_manager.register_extern_system(self.extern_system)

        # prepare folders and unit info tables
        preparation.run(self.options, self.loader)
        if self.options.incremental:
            UnitLevelIncrementalChecker.init(self.options, self.event_manager, self.loader)
        if not self.options.nomock:
            self.extern_system.init()

        if util.is_available(other_init):
            other_init(self)

        return self

    def add_lang(self,lang, extension, so_path, parser):
        self.lang_table.append(
            lang_config.LangConfig(
                name = lang, extension = extension, so_path = so_path, parser = parser
            )
        )

    def dispatch_command(self):
        handler = self.command_handler.get(self.options.sub_command)
        if not handler:
            util.error_and_quit(f"Failed to find command \"{self.options.sub_command}\"")
        return handler()

    def lang_analysis(self):
        LangAnalysis(self).run()
        self.loader.export()
        return self

    def semantic_analysis(self):
        P1BasicSemanticAnalysis(self).run()
        if self.options.basic_semantics:
            self.loader.export()
            return self
        analyzed_method_list = []
        if self.options.enable_p2:
            analyzed_method_list = P2PrelimSemanticAnalysis(self).run().analyzed_method_list
        P3GlobalSemanticAnalysis(self, analyzed_method_list).run()
        self.loader.export()
        return self

    def taint_analysis(self):
        taint_analysis = TaintAnalysis(self, self.options).run()
        return taint_analysis

    def lang_cmd(self):
        self.lang_analysis()
        return self

    def semantic_cmd(self):
        self.lang_analysis()
        self.semantic_analysis()
        return self

    def run_all(self):
        self.lang_analysis()
        self.semantic_analysis()
        if not self.options.basic_semantics:
            self.taint_analysis()
        return self

    # def run_all(self):
    #     self.semantic_analysis()
    #     self.taint_analysis()
    #     return self

    def run(self):
        self.parse_cmds().init_submodules()

        if not self.options.quiet:
            print("Start analysis...")

        self.dispatch_command()

        if not self.options.quiet:
            print("\nThe analysis is done. Please check the output folder: " + os.path.abspath(self.options.workspace))

        return self

def main():
    Lian().run()

if __name__ == "__main__":
    main()
