#!/usr/bin/env python3

from lian.events.handler_template import EventData

from lian.common_structs import (
    Argument,
    MethodCallArguments,
    State,
    Symbol
)
from lian.config.constants import LIAN_INTERNAL

def js_call(data: EventData):
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
    for callee_state in unsolved_callee_states:
        parent_id = resolver.obtain_parent_states(stmt_id, frame, status, callee_state)
        if not parent_id:
            continue
        state_analysis.unset_key_state_flag(name_symbol.symbol_id, callee_state, stmt_id)
        real_method_ids.update(parent_id)

    callee_method_ids = set()
    for each_state_index in real_method_ids:
        each_state = frame.symbol_state_space[each_state_index]
        if not isinstance(each_state, State):
            continue

        if state_analysis.is_state_a_method_decl(each_state):
            if each_state.value:
                callee_method_ids.add(int(each_state.value))

    return state_analysis.compute_target_method_states(
        stmt_id, stmt, status, in_states, callee_method_ids, defined_symbol, args, this_states
    )



def js_then(data: EventData):
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

    this_symbol_index = status.used_symbols[0]
    name_symbol: Symbol = frame.symbol_state_space[this_symbol_index]
    this_states = state_analysis.read_used_states(this_symbol_index, in_states)

    available_state_defs = frame.state_bit_vector_manager.explain(status.in_state_bits)
    real_method_ids = set()
    unsolved_callee_states = in_data.unsolved_callee_states
    arg_set = set()
    for callee_state_index in unsolved_callee_states:
        callee_state = frame.symbol_state_space[callee_state_index]
        access_path = callee_state.access_path
        receiver_path = access_path[-2]
        receiver_state_id = receiver_path.state_id
        receiver_state_indexs = resolver.collect_newest_states_by_state_ids(frame, available_state_defs, {receiver_state_id})

        for receiver_state_index in receiver_state_indexs:
            if receiver_state_index < 0:
                continue
            receiver_state = frame.symbol_state_space[receiver_state_index]
            if isinstance(receiver_state, State):
                arg_set.add(
                    Argument(
                        state_id = receiver_state.state_id,
                        call_stmt_id = stmt_id,
                        position = receiver_state,
                        source_symbol_id = receiver_state.source_symbol_id,
                        access_path = receiver_state.access_path,
                        index_in_space = receiver_state_index
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

METHOD_NAME_TO_MODEL = {'then':js_then, 'call':js_call}
