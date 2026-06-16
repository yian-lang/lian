#!/usr/bin/env python3

import copy
from lian.events.handler_template import EventData

from lian.common_structs import (
    Argument,
    MethodCallArguments,
    State,
    Symbol
)
from lian.config.constants import LIAN_INTERNAL

def abc_then(data: EventData):
    in_data = data.in_data
    stmt_id = in_data.stmt_id
    stmt = in_data.stmt
    status = in_data.status.copy()
    in_states = in_data.in_states
    defined_symbol = in_data.defined_symbol
    resolver = in_data.resolver
    frame = in_data.frame
    state_analysis = in_data.state_analysis
    args = in_data.args

    this_symbol_index = status.used_symbols.pop(0)
    name_symbol: Symbol = frame.symbol_state_space[this_symbol_index]
    this_states = state_analysis.read_used_states(this_symbol_index, in_states)

    real_method_ids = set()
    unsolved_callee_states = in_data.unsolved_callee_states
    arg_set = set()

    def add_callback_arg_state(state_index):
        if state_index < 0:
            return
        state = frame.symbol_state_space[state_index]
        if not isinstance(state, State):
            return
        arg_set.add(
            Argument(
                state_id = state.state_id,
                call_stmt_id = stmt_id,
                position = 0,
                source_symbol_id = state.source_symbol_id,
                access_path = state.access_path,
                index_in_space = state_index
            )
        )

    for callee_state_index in unsolved_callee_states:
        callee_state = frame.symbol_state_space[callee_state_index]
        if not isinstance(callee_state, State):
            continue
        access_path = callee_state.access_path
        if len(access_path) < 2:
            continue
        receiver_path = access_path[-2]
        receiver_state_id = receiver_path.state_id
        receiver_state_indexs = resolver.collect_newest_states_by_state_ids(frame, status, {receiver_state_id})

        for receiver_state_index in receiver_state_indexs:
            add_callback_arg_state(receiver_state_index)

    for callee_state_index in unsolved_callee_states:
        add_callback_arg_state(callee_state_index)
    real_positional_args = [arg_set]
    real_args = MethodCallArguments(real_positional_args, [])

    positional_args = args.positional_args
    for arg_set in positional_args:
        for arg in arg_set:
            arg_state = frame.symbol_state_space[arg.index_in_space]
            if hasattr(arg_state, 'data_type') and arg_state.data_type == LIAN_INTERNAL.METHOD_DECL:
                real_method_ids.add(arg_state.value)
    if real_method_ids:
        data.out_data = state_analysis.compute_target_method_states(
            stmt_id, stmt, status, in_states, real_method_ids, defined_symbol, real_args, this_states
        )

def abc_on(data: EventData):
    in_data = data.in_data
    stmt_id = in_data.stmt_id
    stmt = in_data.stmt
    status = in_data.status.copy()
    in_states = in_data.in_states
    defined_symbol = in_data.defined_symbol
    resolver = in_data.resolver
    frame = in_data.frame
    state_analysis = in_data.state_analysis
    args = in_data.args

    this_symbol_index = status.used_symbols.pop(0)
    name_symbol: Symbol = frame.symbol_state_space[this_symbol_index]
    this_states = state_analysis.read_used_states(this_symbol_index, in_states)

    real_method_ids = set()
    unsolved_callee_states = in_data.unsolved_callee_states
    arg_set = set()
    for callee_state_index in unsolved_callee_states:
        if callee_state_index < 0:
            continue
        callee_state = frame.symbol_state_space[callee_state_index]
        if isinstance(callee_state, State):
            arg_set.add(
                Argument(
                    state_id = callee_state.state_id,
                    call_stmt_id = stmt_id,
                    position = callee_state,
                    source_symbol_id = callee_state.source_symbol_id,
                    access_path = callee_state.access_path,
                    index_in_space = callee_state_index
                )
            )
    real_positional_args = [arg_set]
    real_args = MethodCallArguments(real_positional_args, [])

    positional_args = args.positional_args
    for arg_set in positional_args:
        for arg in arg_set:
            arg_state = frame.symbol_state_space[arg.index_in_space]
            if hasattr(arg_state, 'data_type') and arg_state.data_type == LIAN_INTERNAL.METHOD_DECL:
                real_method_ids.add(arg_state.value)
    data.out_data = state_analysis.compute_target_method_states(
        stmt_id, stmt, status, in_states, real_method_ids, defined_symbol, real_args, this_states
    )

def _collect_callback_method_ids(args, frame):
    real_method_ids = set()
    for arg_set in args.positional_args:
        for arg in arg_set:
            arg_state = frame.symbol_state_space[arg.index_in_space]
            if hasattr(arg_state, 'data_type') and arg_state.data_type == LIAN_INTERNAL.METHOD_DECL:
                real_method_ids.add(arg_state.value)
    return real_method_ids


def _argument_from_state_index(frame, stmt_id, state_index, position):
    if state_index < 0:
        return None
    state = frame.symbol_state_space[state_index]
    if not isinstance(state, State):
        return None
    return Argument(
        state_id = state.state_id,
        call_stmt_id = stmt_id,
        position = position,
        source_symbol_id = state.source_symbol_id,
        access_path = state.access_path,
        index_in_space = state_index
    )


def _collect_unsolved_callee_state_args(frame, stmt_id, unsolved_callee_states, position):
    arg_set = set()
    for callee_state_index in unsolved_callee_states:
        arg = _argument_from_state_index(frame, stmt_id, callee_state_index, position)
        if arg is not None:
            arg_set.add(arg)
    return arg_set


def _call_callback_with_args(data: EventData, real_positional_args):
    in_data = data.in_data
    stmt_id = in_data.stmt_id
    stmt = in_data.stmt
    status = in_data.status.copy()
    in_states = in_data.in_states
    defined_symbol = in_data.defined_symbol
    resolver = in_data.resolver
    frame = in_data.frame
    state_analysis = in_data.state_analysis
    args = in_data.args

    this_symbol_index = status.used_symbols.pop(0)
    name_symbol: Symbol = frame.symbol_state_space[this_symbol_index]
    this_states = state_analysis.read_used_states(this_symbol_index, in_states)

    real_args = MethodCallArguments(real_positional_args, [])
    real_method_ids = _collect_callback_method_ids(args, frame)

    if real_method_ids:
        data.out_data = state_analysis.compute_target_method_states(
            stmt_id, stmt, status, in_states, real_method_ids, defined_symbol, real_args, this_states
        )


def abc_onGetPhoneNumber(data: EventData):
    in_data = data.in_data
    stmt_id = in_data.stmt_id
    frame = in_data.frame
    data_arg_set = _collect_unsolved_callee_state_args(
        frame, stmt_id, in_data.unsolved_callee_states, position = 1
    )
    _call_callback_with_args(data, [set(), data_arg_set])


def abc_getCalendar(data: EventData):
    in_data = data.in_data
    stmt_id = in_data.stmt_id
    frame = in_data.frame
    data_arg_set = _collect_unsolved_callee_state_args(
        frame, stmt_id, in_data.unsolved_callee_states, position = 1
    )
    # CalendarManager.getCalendar(callback) passes data as the callback's
    # second positional parameter: callback(err, data).
    _call_callback_with_args(data, [set(), data_arg_set])


def abc_bind(data: EventData):
    in_data = data.in_data
    stmt_id = in_data.stmt_id
    stmt = in_data.stmt
    status = in_data.status.copy()
    in_states = in_data.in_states
    defined_symbol = in_data.defined_symbol
    resolver = in_data.resolver
    frame = in_data.frame
    state_analysis = in_data.state_analysis
    args = in_data.args

    this_symbol_index = status.used_symbols.pop(0)
    name_symbol: Symbol = frame.symbol_state_space[this_symbol_index]
    this_states = state_analysis.read_used_states(this_symbol_index, in_states)

    available_state_defs = frame.state_bit_vector_manager.explain(status.in_state_bits)
    real_method_ids = set()
    unsolved_callee_states = in_data.unsolved_callee_states
    arg_set = set()
    for callee_state_index in unsolved_callee_states:
        callee_state = frame.symbol_state_space[callee_state_index]
        access_path = callee_state.access_path
        if len(access_path) < 2:
            continue
        receiver_path = access_path[-2]
        receiver_state_id = receiver_path.state_id
        receiver_state_indexs = resolver.collect_newest_states_by_state_ids(frame, status, {receiver_state_id})

        for receiver_state_index in receiver_state_indexs:
            if receiver_state_index < 0:
                continue
            receiver_state = frame.symbol_state_space[receiver_state_index]

            if isinstance(receiver_state, State) and hasattr(receiver_state, 'data_type') and receiver_state.data_type == LIAN_INTERNAL.METHOD_DECL:
                real_method_ids.add(receiver_state.value)

    real_positional_args = [set(), set(), set(), set(), set(), set(), set()]
    real_args = MethodCallArguments(real_positional_args, [])



    data.out_data = state_analysis.compute_target_method_states(
        stmt_id, stmt, status, in_states, real_method_ids, defined_symbol, real_args, this_states
    )

def abc_forEachUpdateFunction(data: EventData):
    in_data = data.in_data
    stmt_id = in_data.stmt_id
    stmt = in_data.stmt
    status = in_data.status.copy()
    in_states = in_data.in_states
    defined_symbol = in_data.defined_symbol
    resolver = in_data.resolver
    frame = in_data.frame
    state_analysis = in_data.state_analysis
    args = in_data.args

    this_symbol_index = status.used_symbols.pop(0)
    name_symbol: Symbol = frame.symbol_state_space[this_symbol_index]
    this_states = state_analysis.read_used_states(this_symbol_index, in_states)

    real_method_ids = set()
    unsolved_callee_states = in_data.unsolved_callee_states
    arg_set = set()
    # for callee_state_index in unsolved_callee_states:
    #     if callee_state_index < 0:
    #         continue
    #     callee_state = frame.symbol_state_space[callee_state_index]
    #     if isinstance(callee_state, State):
    #         arg_set.add(
    #             Argument(
    #                 state_id = callee_state.state_id,
    #                 call_stmt_id = stmt_id,
    #                 position = callee_state,
    #                 source_symbol_id = callee_state.source_symbol_id,
    #                 access_path = callee_state.access_path,
    #                 index_in_space = callee_state_index
    #             )
    #         )


    positional_args = args.positional_args[1]
    # if len(positional_args) > 0:
    #     taint_arg = positional_args[0] // set()
    #     real_positional_args = [taint_arg]
    real_args = MethodCallArguments([positional_args], [])

    real_positional_args = [arg_set]

    for arg_set in args.positional_args:
        for arg in arg_set:
            arg_state = frame.symbol_state_space[arg.index_in_space]
            if hasattr(arg_state, 'data_type') and arg_state.data_type == LIAN_INTERNAL.METHOD_DECL:
                real_method_ids.add(arg_state.value)
    data.out_data = state_analysis.compute_target_method_states(
        stmt_id, stmt, status, in_states, real_method_ids, defined_symbol, real_args, this_states
    )


def abc_router_back(data: EventData):
    in_data = data.in_data
    stmt_id = in_data.stmt_id
    stmt = in_data.stmt
    status = in_data.status.copy()
    in_states = in_data.in_states
    defined_symbol = in_data.defined_symbol
    resolver = in_data.resolver
    frame = in_data.frame
    state_analysis = in_data.state_analysis
    args = in_data.args
    loader = in_data.loader
    this_symbol_index = status.used_symbols.pop(0)
    name_symbol: Symbol = frame.symbol_state_space[this_symbol_index]
    this_states = state_analysis.read_used_states(this_symbol_index, in_states)

    real_method_ids = set()
    unsolved_callee_states = in_data.unsolved_callee_states
    arg_set = set()

    positional_args = args.positional_args
    if len(positional_args) == 0:
        return
    arg0 = list(positional_args[0])[0]
    arg0_index = arg0.index_in_space
    arg0_state = frame.symbol_state_space[arg0_index]

    url_states_set = arg0_state.fields["url"]
    target_method_ids = set()

    for url_index in url_states_set:
        url_state = frame.symbol_state_space[url_index]
        if not isinstance(url_state, State):
            continue
        url_value = url_state.value
        path_list = url_value.split("/")
        target_name = path_list[-1]
        method_ids = loader.convert_method_name_to_method_ids(target_name)
        target_method_ids.update(method_ids)


    real_args = MethodCallArguments([], [])
    data.out_data = state_analysis.compute_target_method_states(
        stmt_id, stmt, status, in_states, target_method_ids, defined_symbol, real_args, this_states
    )

def abc_initialRender(data: EventData):
    in_data = data.in_data
    stmt_id = in_data.stmt_id
    stmt = in_data.stmt
    status = in_data.status.copy()
    in_states = in_data.in_states
    defined_symbol = in_data.defined_symbol
    resolver = in_data.resolver
    frame = in_data.frame
    state_analysis = in_data.state_analysis
    args = in_data.args
    loader = in_data.loader
    this_symbol_index = status.used_symbols.pop(0)
    name_symbol: Symbol = frame.symbol_state_space[this_symbol_index]
    this_states = state_analysis.read_used_states(this_symbol_index, in_states)

    real_method_ids = set()
    unsolved_callee_states = in_data.unsolved_callee_states
    arg_set = set()

    positional_args = args.positional_args
    target_method_ids = set()

    current_class_id = loader.convert_method_id_to_class_id(frame.method_id)
    methods_in_class = copy.deepcopy(loader.get_methods_in_class(current_class_id))

    method_ids = loader.convert_method_name_to_method_ids("initialRender")
    target_method_ids.update(method_ids)


    real_args = MethodCallArguments([], [])
    data.out_data = state_analysis.compute_target_method_states(
        stmt_id, stmt, status, in_states, target_method_ids, defined_symbol, real_args, this_states
    )

METHOD_NAME_TO_MODEL = {
    "then": abc_then,
    "on": abc_on,
    "setTimeout": abc_on,
    "onGetPhoneNumber": abc_onGetPhoneNumber,
    "observeComponentCreation2": abc_then,
    "create": abc_then,
    "onClick" :abc_then,
    "onChange": abc_then,
    "bind": abc_bind,
    "forEachUpdateFunction": abc_forEachUpdateFunction,
    "back": abc_router_back,
    "getCalendar": abc_getCalendar,
}
