#!/usr/bin/env python3

import dataclasses
import pprint
from lian.common_structs import State
from lian.events.handler_template import EventData
import lian.events.event_return as er
from lian.config.constants import (
    EVENT_KIND,
    LIAN_INTERNAL,
    STATE_TYPE_KIND,
    JS_PROTOTYPE
)
from lian.common_structs import (
    State
)
from lian.util import util

def bind_method_call(data: EventData):
    test = data.in_data

def field_read_prototype(data: EventData):
    in_data = data.in_data
    stmt_id = in_data.stmt_id
    status = in_data.status
    field_name = status.field_name
    receiver_states = in_data.receiver_states
    frame = in_data.frame
    resolver = in_data.resolver
    target_set = set()

    if field_name == JS_PROTOTYPE.PROTOTYPE:
        for receiver_state_index in receiver_states:
            receiver_state = frame.symbol_state_space[receiver_state_index]
            if JS_PROTOTYPE.PROTOTYPE in receiver_state.fields:
                target_set.update(receiver_state.fields[JS_PROTOTYPE.PROTOTYPE])

    else:
        for receiver_state_index in receiver_states:
            receiver_state = frame.symbol_state_space[receiver_state_index]
            if not isinstance(receiver_state, State):
                continue

            if field_name in receiver_state.fields:
                index_set = receiver_state.fields.get(field_name, set())
                target_set.update(index_set)

            elif JS_PROTOTYPE.PROTO in receiver_state.fields:
                available_state_defs = frame.state_bit_vector_manager.explain(status.in_state_bits)
                proto_index_set = receiver_state.fields[JS_PROTOTYPE.PROTO]
                newest_proto_index_set = resolver.collect_newest_states_by_state_indexes(frame, stmt_id, proto_index_set, available_state_defs)
                for each_proto_index in newest_proto_index_set:
                    proto_state = frame.symbol_state_space[each_proto_index]
                    if not isinstance(proto_state, State):
                        continue

                    if proto_state and field_name in proto_state.fields:
                        target_set.update(proto_state.fields[field_name])
                        break
                    else:
                        if JS_PROTOTYPE.PROTO in proto_state.fields:
                            proto_index_set = proto_state.fields[JS_PROTOTYPE.PROTO]
                        else:
                            break

    if target_set:
        for target_index in target_set:
            in_data.defined_states.add(target_index)
        return er.EventHandlerReturnKind.STOP_REQUESTERS
    return er.EventHandlerReturnKind.UNPROCESSED

def method_decl_prototype(data: EventData):
    in_data = data.in_data
    stmt_id = in_data.stmt_id
    symbol_id = in_data.symbol_id
    frame = in_data.frame
    index = in_data.external_state_index
    index_set = {index}

    app_return = er.config_event_unprocessed()
    if frame.loader.is_method_decl(symbol_id) or frame.loader.is_class_decl(symbol_id):
        prototype_state = State(
            stmt_id = stmt_id,
            source_symbol_id = symbol_id,
            data_type = LIAN_INTERNAL.PROTOTYPE,
            fields = {JS_PROTOTYPE.CONSTRUCTOR: index_set}
        )
        prototype_index = frame.symbol_state_space.add(prototype_state)
        method_state = frame.symbol_state_space[index]
        if isinstance(method_state, State):
            method_state.fields = {JS_PROTOTYPE.PROTOTYPE: {prototype_index}}

        data.out_data = data.in_data
        app_return = er.config_continue_event_processing(app_return)

    return app_return


def new_object_proto(data: EventData):
    in_data = data.in_data
    frame = in_data.frame
    app_return = er.config_event_unprocessed()
    defined_states = in_data.defined_states
    type_states = in_data.type_states
    for defined_state_index in defined_states:
        defined_state = frame.symbol_state_space[defined_state_index]
        for type_state_index in type_states:
            type_state = frame.symbol_state_space[type_state_index]

            if type_state.value == defined_state.value:
                if JS_PROTOTYPE.PROTOTYPE in type_state.fields:
                    prototype = type_state.fields[JS_PROTOTYPE.PROTOTYPE]
                    if not isinstance(prototype, State):
                        continue

                    defined_state.fields = {JS_PROTOTYPE.PROTO: prototype}
                    app_return = er.config_continue_event_processing(app_return)
    data.out_data = data.in_data
    return app_return

