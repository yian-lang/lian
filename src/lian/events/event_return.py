#!/usr/bin/env python3

from lian.util import util

EventHandlerReturnKind = util.SimpleEnum({
    "UNPROCESSED"                       : 0, #Unprocessed by any handler
    "SUCCESS"                           : 1, #Continue processing
    "STOP_OTHER_EVENT_HANDLERS"         : 2, #Stop other handlers from processing
    "STOP_REQUESTERS"                   : 4, #不允许触发该event的业务代码Continue processing
    "INTERRUPTION_CALL"                 : 8, #Interrupt and call corresponding functions
})

def is_event_successfully_processed(event_return):
    return event_return != EventHandlerReturnKind.UNPROCESSED

def is_event_unprocessed(event_return):
    return event_return == EventHandlerReturnKind.UNPROCESSED

def should_block_other_event_handlers(event_return):
    return event_return & EventHandlerReturnKind.STOP_OTHER_EVENT_HANDLERS

def should_block_event_requester(event_return):
    return event_return & EventHandlerReturnKind.STOP_REQUESTERS

def should_interrupt_call(event_return):
    return event_return & EventHandlerReturnKind.INTERRUPTION_CALL

def sync_event_return(local_event_return, global_event_return):
    if local_event_return is None:
        return global_event_return
    if is_event_successfully_processed(local_event_return):
        global_event_return |= EventHandlerReturnKind.SUCCESS
    if should_block_other_event_handlers(local_event_return):
        global_event_return |= EventHandlerReturnKind.STOP_OTHER_EVENT_HANDLERS
    if should_block_event_requester(local_event_return):
        global_event_return |= EventHandlerReturnKind.STOP_REQUESTERS
    if should_interrupt_call(local_event_return):
        global_event_return |= EventHandlerReturnKind.INTERRUPTION_CALL
    return global_event_return

def config_event_unprocessed():
    return EventHandlerReturnKind.UNPROCESSED

def config_continue_event_processing(event_return):
    event_return |= EventHandlerReturnKind.SUCCESS
    return event_return

def config_block_other_event_handlers(event_return):
    event_return |= EventHandlerReturnKind.STOP_OTHER_EVENT_HANDLERS
    return event_return

def config_block_event_requester(event_return):
    event_return |= EventHandlerReturnKind.STOP_REQUESTERS
    return event_return

def config_interrupt_call(event_return):
    event_return |= EventHandlerReturnKind.INTERRUPTION_CALL
    return event_return
