#!/usr/bin/env python3

import dataclasses
import os
from lian.common_structs import AccessPoint, State, ComputeFrame
from lian.core.stmt_states import StmtStates
from lian.events.handler_template import EventData
from lian.config.constants import (
    EVENT_KIND,
    LIAN_INTERNAL,
    STATE_TYPE_KIND,
    LIAN_SYMBOL_KIND,
    ACCESS_POINT_KIND
)
import lian.events.event_return as er
from lian.util import util
from lian.util.loader import Loader
from lian.config import type_table
import pprint

LANG_INIT_SCRIPT_NAME = {
    "python" : "__init__.py",
    "javascript" : "index.js"
}

def get_lang_init_script_name(lang):
    return LANG_INIT_SCRIPT_NAME.get(lang, "")

LANG_CONSTRUCTORS = {
    # "python"            : ["__new__", "__init__", "__post_init__"],
    "python"            : ["__init__", "__post_init__"],
    "javascript"        : ["constructor"],
    "php"               : ["__construct"],
}

def get_lang_constructor_method_names(lang):
    return LANG_CONSTRUCTORS.get(lang, [])

def init_imported_unit(data: EventData):
    # TODO: need to port the following code as a plugin
    in_data = data.in_data
    lang = data.lang
    unit_id = in_data.unit_id
    frame:ComputeFrame = in_data.frame
    if unit_id in frame.inited_unit_list:
        return

    frame.inited_unit_list.add(unit_id)

    if frame.loader.is_module_dir_id(unit_id):
        # try import __init__.py or index.js
        init_file_name = get_lang_init_script_name(lang)
        if init_file_name:
            module_dir_path = frame.loader.convert_unit_id_to_unit_path(unit_id)
            init_file_path = os.path.join(module_dir_path, init_file_name)
            init_file_id = frame.loader.convert_unit_path_to_unit_id(init_file_path)
            if init_file_id:
                frame.init_imported_unit(init_file_id, lang)
        return

    elif frame.loader.is_unit_id(unit_id):
        # If importing a module/file, initialize all imported units according to its import_graph first, then recursively initialize.
        import_graph = frame.loader.load_import_graph()
        if import_graph.graph.has_node(unit_id):
            children_imports = util.graph_successors(import_graph.graph, unit_id)
            for kid_import in children_imports:
                frame.init_imported_unit(kid_import, lang)

        unit_scope = frame.loader.load_unit_scope_hierarchy(unit_id)
        scope_item = unit_scope.slow_query(
            (unit_scope.scope_kind == LIAN_SYMBOL_KIND.METHOD_KIND) &
            (unit_scope.name == LIAN_INTERNAL.UNIT_INIT)
        )
        frame.analyze_method(scope_item.stmt_id)

# before_new_object
def init_new_object(data: EventData):
    in_data = data.in_data
    frame: ComputeFrame = in_data.frame
    status = in_data.status
    defined_symbol = in_data.defined_symbol
    stmt_id = in_data.stmt_id
    state_analysis:StmtStates = in_data.state_analysis
    type_state_to_new_index = in_data.type_state_to_new_index
    type_state_to_callee_methods = in_data.type_state_to_callee_methods
    loader:Loader = frame.loader
    app_return = er.config_event_unprocessed()

    for each_type_state_index in in_data.type_states:
        type_name = ""
        each_type_state = frame.symbol_state_space[each_type_state_index]
        methods_in_class = []
        if not isinstance(each_type_state, State):
            continue

        callee_method_list = []
        if loader.is_method_decl(each_type_state.value):
            callee_method_list.append(each_type_state.value)
            type_name = loader.convert_method_id_to_method_name(each_type_state.value)

        elif loader.is_class_decl(each_type_state.value) or each_type_state.data_type == LIAN_INTERNAL.THIS:
            methods_in_class = loader.get_methods_in_class(each_type_state.value)
            type_name = loader.convert_class_id_to_class_name(each_type_state.value)
            if each_type_state.data_type == LIAN_INTERNAL.THIS:
                method_id = loader.convert_stmt_id_to_method_id(stmt_id)
                class_id = loader.convert_method_id_to_class_id(method_id)
                if frame.this_class_ids and len(frame.this_class_ids) > 0:
                    class_id = frame.this_class_ids[0]
                methods_in_class = loader.get_methods_in_class(class_id)
                type_name = loader.convert_class_id_to_class_name(class_id)
            if methods_in_class:
                for each_method in methods_in_class:
                    if each_method.name == LIAN_INTERNAL.CLASS_INIT:
                        callee_method_list.append(each_method.stmt_id)

                constructor_names = get_lang_constructor_method_names(data.lang)
                if constructor_names:
                    for each_constructor_name in constructor_names:
                        for each_method in methods_in_class:
                            if each_method.name == each_constructor_name:
                                callee_method_list.append(each_method.stmt_id)
                                break
                else:
                    # Find the methods whose names are the same as the class name
                    for each_method in methods_in_class:
                        if each_method.name == type_name:
                            callee_method_list.append(each_method.stmt_id)

        new_object_state_index = state_analysis.create_state_and_add_space(
            stmt_id = stmt_id, status = status, source_symbol_id = defined_symbol.symbol_id,
            data_type = type_name, value = each_type_state.value, source_state_id=stmt_id,
            access_path= [AccessPoint(key = type_name, kind = ACCESS_POINT_KIND.NEW_OBJECT)]
        )

        # Populate method names into new_object_state fields
        new_object_state = frame.symbol_state_space[new_object_state_index]
        if methods_in_class:
            member_methods = {}
            for each_method in methods_in_class:
                each_method_name = each_method.name
                each_method_id = each_method.stmt_id
                new_member_method_state_index = state_analysis.create_state_and_add_space(
                    stmt_id = stmt_id,
                    status = status,
                    source_symbol_id = each_method_id,
                    source_state_id = new_object_state.source_state_id,
                    data_type = LIAN_INTERNAL.METHOD_DECL,
                    value = each_method_id,
                    access_path = state_analysis.copy_and_extend_access_path(
                        new_object_state.access_path,
                        AccessPoint(
                            kind = ACCESS_POINT_KIND.FIELD_NAME,
                            key = each_method_name
                        )
                    )
                )
                state_analysis.update_access_path_state_id(new_member_method_state_index)
                util.add_to_dict_with_default_set(member_methods, each_method_name, new_member_method_state_index)
            new_object_state.fields = member_methods

        state_analysis.update_access_path_state_id(new_object_state_index)
        type_state_to_new_index[each_type_state_index] = new_object_state_index
        # Initialization method called upon creating an instance of this type
        type_state_to_callee_methods[each_type_state_index] = callee_method_list
        defined_symbol.states.add(new_object_state_index) # Provide the old state; later uses will locate the updated state constructed via state_id
    app_return = er.config_continue_event_processing(app_return)
    return app_return

# after_new_object
def apply_constructor_summary(data: EventData):
    in_data = data.in_data
    frame: ComputeFrame = in_data.frame
    status = in_data.status
    defined_symbol = in_data.defined_symbol
    stmt_id = in_data.stmt_id
    stmt = in_data.stmt
    in_states = in_data.in_states
    state_analysis:StmtStates = in_data.state_analysis
    type_state_to_new_index = in_data.type_state_to_new_index
    type_state_to_callee_methods = in_data.type_state_to_callee_methods
    callee_method_list = []
    app_return = er.config_event_unprocessed()
    args = in_data.args

    for each_type_state_index in type_state_to_new_index:
        # Retrieve the previously created new_instance_state
        new_object_state_index = type_state_to_new_index[each_type_state_index]

        if each_type_state_index in type_state_to_callee_methods:
            # call Initialization method called upon creating an instance of this type
            callee_method_list = type_state_to_callee_methods[each_type_state_index]
        if callee_method_list:
            p2result_flag = state_analysis.compute_target_method_states(
                stmt_id, stmt, status, in_states,
                callee_method_list, defined_symbol, args,
                {new_object_state_index}, new_object_flag = True
            )
            if p2result_flag.interruption_flag:
                in_data.p2result_flag.interruption_flag = p2result_flag.interruption_flag
                in_data.p2result_flag.interruption_data = p2result_flag.interruption_data
                app_return = er.config_block_event_requester(app_return)
                return app_return

    app_return = er.config_continue_event_processing(app_return)
    return app_return

