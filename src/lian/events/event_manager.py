#!/usr/bin/env python3

import os,sys
import inspect
import importlib
import dataclasses
import pprint

from lian.util import util
from lian.config import config
from lian.config.constants import (
    EVENT_KIND,
)
import lian.events.event_return as er
from lian.events.handler_template import EventData
from lian.events.event_registers import DefaultEventHandlerManager

class EventManager:
    def __init__(self, options):
        """
        the format of these hangles:
        {
            lang1: <hanglers>,
            lang2: <handlers>,
            ....
            "%"(ANY_LANG): <handlers>
        }
        """
        self.options = options
        self.optional_event_handler_paths = options.event_handlers
        self.mock_source_code_handlers = []
        self.source_code_handlers = []
        self.gir_list_handlers = []
        self.flattened_gir_list_handlers = []
        self.gir_data_model_handlers = []
        self.def_use_handlers = []
        self.state_flow_handlers = []
        self.method_summary_handlers = []
        self.entry_point_handlers = []
        self.taint_analysis_handlers = []
        self.p2state_field_read_before_handlers = []
        self.p2state_field_read_after_handlers = []
        self.p2state_call_stmt_before_handlers = []
        self.p2state_field_write_after_handlers = []
        self.p2state_generate_external_states_handlers = []
        self.p2state_new_object_before_handlers = []
        self.p2state_new_object_after_handlers = []
        self.p2state_builtin_function_before_handlers = []
        self.p2state_extern_callee_handlers = []

        self.event_handlers = {
            EVENT_KIND.MOCK_SOURCE_CODE_READY                        : self.mock_source_code_handlers,
            EVENT_KIND.ORIGINAL_SOURCE_CODE_READY                    : self.source_code_handlers,
            EVENT_KIND.UNFLATTENED_GIR_LIST_GENERATED                : self.gir_list_handlers,
            EVENT_KIND.GIR_LIST_GENERATED                            : self.flattened_gir_list_handlers,
            EVENT_KIND.GIR_DATA_MODEL_GENERATED                      : self.gir_data_model_handlers,

            EVENT_KIND.P2STATE_FIELD_READ_BEFORE                     : self.p2state_field_read_before_handlers,
            EVENT_KIND.P2STATE_FIELD_READ_AFTER                      : self.p2state_field_read_after_handlers,
            EVENT_KIND.P2STATE_CALL_STMT_BEFORE                     : self.p2state_call_stmt_before_handlers,
            EVENT_KIND.P2STATE_GENERATE_EXTERNAL_STATES              : self.p2state_generate_external_states_handlers,
            EVENT_KIND.P2STATE_NEW_OBJECT_BEFORE                     : self.p2state_new_object_before_handlers,
            EVENT_KIND.P2STATE_NEW_OBJECT_AFTER                      : self.p2state_new_object_after_handlers,
            EVENT_KIND.P2STATE_BUILTIN_FUNCTION_BEFORE               : self.p2state_builtin_function_before_handlers,
            EVENT_KIND.P2STATE_EXTERN_CALLEE                         : self.p2state_extern_callee_handlers,
            EVENT_KIND.P2STATE_FIELD_WRITE_AFTER                     : self.p2state_field_write_after_handlers,
        }

        self.register_default_event_handlers()
        self.register_optional_event_handlers()

        # if self.options.debug:
        #     self.list_installed_handlers()

    # Execute plugins in registration order.
    # def add_handler(self, handler_list, func, langs):
    #     # default_list = handler_list.get(config.ANY_LANG, [])
    #     handler_list.append()

    #     for each_lang in langs:
    #         if each_lang not in handler_list:
    #             # handler_list[each_lang] = default_list.copy()
    #             handler_list[each_lang] = []
    #         if each_lang == config.ANY_LANG:
    #             for key in handler_list:
    #                 handler_list[key].append(func)
    #         else:
    #             handler_list[each_lang].append(func)

    def add_handler(self, handler_list:list, func, langs):
        handler_list.append((langs, func))

    def notify(self, data:EventData):
        event_return = er.config_event_unprocessed()
        all_handlers = self.event_handlers.get(data.event, None)
        data.out_data = data.in_data

        if all_handlers is None:
            return event_return

        for langs, handler in all_handlers:
            if data.lang in langs or config.ANY_LANG in langs:
                if self.options.debug:
                    util.debug("Handling the event: ", EVENT_KIND[data.event], " with the handler: ", handler)
                current_return = handler(data)
                event_return = er.sync_event_return(current_return, event_return)
                if er.should_block_other_event_handlers(event_return):
                    return event_return
                if er.is_event_successfully_processed(current_return):
                    data.in_data = data.out_data

        # if data.lang in all_handlers:
        #     for handler in all_handlers[data.lang]:
        #         if self.options.debug:
        #             util.debug("Handling the event: ", EventKind[data.event], " with the handler: ", handler)

        #         current_return = handler(data)
        #         event_return = er.sync_event_return(current_return, event_return)
        #         if er.should_block_other_event_handlers(event_return):
        #             return event_return
        #         if er.is_event_successfully_processed(current_return):
        #             data.in_data = data.out_data

        # for handler in all_handlers.get(config.ANY_LANG, []):
        #     if self.options.debug:
        #         util.debug("Handling the event: ", EventKind[data.event], " with the handler: ", handler)

        #     current_return = handler(data)

        #     event_return = er.sync_event_return(current_return, event_return)
        #     if er.should_block_other_event_handlers(event_return):
        #         return event_return
        #     if er.is_event_successfully_processed(current_return):
        #         data.in_data = data.out_data

        return event_return

    def register_default_event_handlers(self):
        DefaultEventHandlerManager(self).enable()

    def register_extern_system(self, extern_system):
        if extern_system:
            self.register(
                event = EVENT_KIND.P2STATE_EXTERN_CALLEE,
                handler = extern_system.handle,
                langs = [config.ANY_LANG]
            )

    # def register_problem_monitor(self, problem_monitor:ProblemMonitor):
    #     if problem_monitor:
    #         self.register(
    #             event = EVENT_KIND.P2STATE_EXTERN_CALLEE,
    #             handler = problem_monitor.method_call_handler,
    #             langs = [config.ANY_LANG]
    #         )

    def register_optional_event_handlers(self):
        def get_concrete_classes(module):
            classes = inspect.getmembers(module, inspect.isclass)

            for class_name, class_type in classes:
                if (not inspect.isabstract(class_type)
                    and len(class_type.__bases__) == 1
                    and class_type.__bases__[0] != object
                ):
                    # concrete_classes.append((class_name, class_type))
                    return class_type

            return None

        def create_instance_from_path(app_path):
            module_name = "tmp_module"
            spec = importlib.util.spec_from_file_location(module_name, app_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            concrete_class = get_concrete_classes(module)
            if concrete_class:
                concrete_class(self)

        for path in self.optional_event_handler_paths:
            create_instance_from_path(path)

    def register(self, event, handler, langs = config.ANY_LANG):
        if event not in self.event_handlers:
            util.warn(f"Unknown event: {event}")
            return

        if isinstance(langs, str):
            langs = [langs]
        elif isinstance(langs, set):
            langs = list(langs)

        self.add_handler(self.event_handlers[event], handler, langs)

    def register_list(self, handler_list):
        for element in handler_list:
            self.register(element.event, element.handler, element.langs)

    def list_installed_handlers(self):
        for event in self.event_handlers:
            util.debug(f"Event: {EVENT_KIND[event]}, handlers: {str(self.event_handlers[event])}")
