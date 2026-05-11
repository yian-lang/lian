#!/usr/bin/env python3

from lian.util import util

CLASS_DECL_OPERATION = {
    "class_decl",
    "record_decl",
    "interface_decl",
    "enum_decl",
    "struct_decl",
    "trait_decl",
    "union_decl",
    "implement_decl",
    "type_alias_decl"
}

NAMESPACE_DECL_OPERATION = {
    "namespace_decl",
    "module_decl",
}

IMPORT_OPERATION = {
    "import_stmt",
    "from_import_stmt",
    "from_export_stmt"
}

METHOD_DECL_OPERATION = {
    "method_decl",
    "method_header"
}

FOR_STMT_OPERATION = {
    "for_stmt",
    "forin_stmt"
}
WITH_STMT_OPERATION = {
    "with_stmt",
}

VARIABLE_DECL_OPERATION = {
    "variable_decl",
    #"type_alias_decl"
}

CASE_AS_OPERATION = {
    "case_stmt"
}

PARAMETER_DECL_OPERATION = {
    "parameter_decl"
}

BLOCK_OPERATION = {
    "for_stmt",
    "forin_stmt",
}

CALL_OPERATION = {
    "call_stmt"
}

EXPORT_STMT_OPERATION = {
    "export_stmt",
    "from_export_stmt"
}

RETURN_STMT_OPERATION = {
    "return_stmt"
}

SUMMARY_GENERAL_SYMBOL_ID = util.SimpleEnum({
    "RETURN_SYMBOL_ID"              : -28,
})

LOOP_OPERATIONS = set([
    "for_stmt",
    "forin_stmt",
    "for_value_stmt",
    "while_stmt",
    "dowhile_stmt"
])

CONFIG_ITEM_Kind = util.SimpleEnum({
    "ARG"                           : 0,
    "RETURN"                        : 1,
    "THIS"                          : 2,
})

LANG_KIND = util.SimpleEnum({
    "C"                             : 0,
    "CPP"                           : 1,
    "CSHARP"                        : 2,
    "RUST"                          : 3,
    "GO"                            : 4,
    "JAVA"                          : 5,
    "JAVASCRIPT"                    : 6,
    "TYPESCRIPT"                    : 7,
    "KOTLIN"                        : 8,
    "SCALA"                         : 9,
    "LLVM"                          : 10,
    "PYTHON"                        : 11,
    "RUBY"                          : 12,
    "SMALI"                         : 13,
    "SWIFT"                         : 14,
    "PHP"                           : 15,
    "CODEQL"                        : 16,
    "QL"                            : 17,
    "ABC"                           : 18,
})

LIAN_SYMBOL_KIND = util.SimpleEnum({
    'MODULE_SYMBOL'                 : 0,
    'UNIT_SYMBOL'                   : 1,
    "PACKAGE_STMT"                  : 2,
    "IMPORT_STMT"                   : 3,
    "INCLUDE_STMT"                  : 4,
    "VARIABLE_DECL"                 : 5,
    "PARAMETER_DECL"                : 6,
    "CALL_STMT"                     : 7,
    "EXPORT_STMT"                   : 8,
    "BLOCK_KIND"                    : 9,
    "METHOD_KIND"                   : 10,
    "CLASS_KIND"                    : 11,
    "NAMESPACE_KIND"                : 12,
    "UNIT_KIND"                     : 13,
    "BUILTIN_KIND"                  : 14,
    "FOR_KIND"                      : 15,
    "WITH_KIND"                     : 16,
    "UNKNOWN_KIND"                  : 17,
})

IMPORT_GRAPH_EDGE_KIND = util.SimpleEnum({
    "INTERNAL_SYMBOL"               : 0,
    "EXTERNAL_SYMBOL"               : 1,
    "UNSOLVED_SYMBOL"               : 2,
})


METHOD_SUMMARY_SYMBOL_KIND = util.SimpleEnum({
    'PARARMETER_SYMBOL'             : 1,
    'DEFINED_EXTERNAL_SYMBOL'       : 2,
    'USED_EXTERNAL_SYMBOL'          : 3,
    'RETRUN_SYMBOL'                 : 4,
    'DYNAMIC_CALL'                  : 5,
    'DIRECT_CALL'                   : 6
})


CONTROL_FLOW_KIND = util.SimpleEnum({
    "EMPTY"                         : 0,
    "IF_TRUE"                       : 1,
    "IF_FALSE"                      : 2,
    "FOR_CONDITION"                 : 3,
    "LOOP_TRUE"                     : 4,
    "LOOP_FALSE"                    : 5,
    "LOOP_BACK"                     : 6,
    "BREAK"                         : 7,
    "CONTINUE"                      : 8,
    "RETURN"                        : 9,
    "CATCH_TRUE"                    : 10,
    "CATCH_FALSE"                   : 11,
    "CATCH_FINALLY"                 : 12,
    "PARAMETER_UNINIT"              : 13,
    "PARAMETER_INIT"                : 14,
    "EXIT"                          : 15,
    "YIELD"                         : 16,
})

SYMBOL_DEPENDENCY_GRAPH_EDGE_KIND = util.SimpleEnum({
    "REGULAR"                       : 0,
    "EXPLICITLY_DEFINED"            : 1,
    "EXPLICITLY_USED"               : 2,
    "IMPLICITLY_DEFINED"            : 3,
    "IMPLICITLY_USED"               : 4
})

STATE_TYPE_KIND = util.SimpleEnum({
    "EMPTY"                         : 0,
    "REGULAR"                       : 1,
    "UNSOLVED"                      : 2,
    "UNINIT"                        : 3,
    "ANYTHING"                      : 4,
})

EXTERNAL_KEY_STATE_TYPE = util.SimpleEnum({
    "CALL"                          : 0,
    "ADDR"                          : 1,
    "ARRAY"                         : 2,
    "FIELD"                         : 3,
    "EMPTY"                         : 4,
})

BUILTIN_OR_CUSTOM_DATA_TYPE = util.SimpleEnum({
    "BUILTIN"                       : 0,
    "CUSTOM"                        : 1,
})

# ANALYSIS_PHASE_NAME = util.SimpleEnum({
#     "ScopeHierarchy"            : "scope_hierarchy",
#     "TypeHierarchy"             : "type_hierarchy",
#     "ControlFlowGraph"          : "control_flow",
#     "SymbolFlowGraph"           : "symbol_flow",
#     "StateFlowGraph"            : "state_flow",
#     "MethodSummary"             : "method_summary",
#     "AbstractCompute"           : "abstract_compute",
#     "CallGraph"                 : "call_graph",
#     "PrelimSemantics"           : "prelim_semantics",
#     "GlobalSemantics"          : "global_semantics",
# })

ANALYSIS_PHASE_ID = util.SimpleEnum({
    "NO_PHASE"                      : 1,
    "PRELIM_SEMANTICS"              : 2,
    "GLOBAL_SEMANTICS"              : 3,
})

BASIC_CALL_GRAPH_NODE_KIND = util.SimpleEnum({
    "DYNAMIC_METHOD"                : -1,
    "ERROR_METHOD"                  : -2,
})


DATA_TYPE_CORRELATION_KIND = util.SimpleEnum({
    "alias"                         : 0,
    "inherit"                       : 1,
})

SYMBOL_OR_STATE = util.SimpleEnum({
    "SYMBOL"                        : 0,
    "STATE"                         : 1,
    "EXTERNAL_KEY_STATE"            : 2,
    "UNKNOWN"                       : 3,
})

SFG_EDGE_KIND = util.SimpleEnum({
    "REGULAR"                       : 0,
    "SYMBOL_IS_DEFINED"             : 1,
    "SYMBOL_IS_USED"                : 2,
    "SYMBOL_FLOW"                   : 3,
    "INDIRECT_SYMBOL_FLOW"          : 4,
    "SYMBOL_STATE"                  : 5,
    "INDIRECT_SYMBOL_STATE"         : 6,
    "STATE_INCLUSION"               : 7,
    "INDIRECT_STATE_INCLUSION"      : 8,
    "CALL_RETURN"                   : 9,
    "STATE_COPY"                    : 10,
    "STATE_IS_USED"                 : 11,
})

SFG_NODE_KIND = util.SimpleEnum({
    "REGULAR"                       : 0,
    "STMT"                          : 1,
    "SYMBOL"                        : 2,
    "STATE"                         : 3,
})

ACCESS_POINT_KIND = util.SimpleEnum({
    "TOP_LEVEL"                     : 0,
    "ADDR_OF"                       : 1,
    "MEM_READ"                      : 2,
    "FORIN_ELEMENT"                 : 3,
    "ELEMENT_OF"                    : 4,
    "NEW_OBJECT"                    : 5,
    "BINARY_ASSIGN"                 : 8,
    "FIELD_NAME"                    : 9,
    "FIELD_ELEMENT"                 : 10,
    "ARRAY_INDEX"                   : 11,
    "ARRAY_ELEMENT"                 : 12,
    "CALL_RETURN"                   : 13,
    "EXTERNAL"                      : 14,
    "REQUIRED_MODULE"               : 15,
    "BUILTIN_METHOD"                : 18,
    "NAMESPACE"                     : 19,
})

RULE_KIND = util.SimpleEnum({
    "RULE"                          : 0,
    "CODE"                          : 1,
    "MODEL"                         : 2,
})

CONDITION_FLAG = util.SimpleEnum({
    "NO_PATH"                       : 0,  # 00
    "TRUE_PATH"                     : 1,  # 01
    "FALSE_PATH"                    : 2,  # 10
    "ANY_PATH"                      : 3,  # 11
})

LOADER_QUERY_ENTRY = util.SimpleEnum({
    'control_flow_graph'            : 1,
    'symbol_dependency_graph'       : 2,
    'stmt_status'                   : 3,
    'symbols_states_space'          : 4,
    'method_summary'                : 5,
    'gir'                           : 6,
    'scope_space'                   : 7,
})

CALLEE_TYPE = util.SimpleEnum({
    "DIRECT_CALLEE"                 : 0,
    "DYNAMIC_CALLEE"                : 1,
    "ERROR_CALLEE"                  : 2,
})

EXPORT_NODE_TYPE = util.SimpleEnum({
    "MODULE_UNIT"                   : 0,
    "MODULE_DIR"                    : 1,
    "REGULAR_SYMBOL"                : 2,
    "UNKNOWN_IMPORT"                : 3,
})

LIAN_INTERNAL = util.SimpleEnum({
    # Constants
    "TRUE"                          : "true",
    "FALSE"                         : "false",
    "NULL"                          : "null",
    "UNDEFINED"                     : "undefined",

    "I8"                            : "i8",
    "I16"                           : "i16",
    "I32"                           : "i32",
    "I64"                           : "i64",
    "U8"                            : "u8",
    "U16"                           : "u16",
    "U32"                           : "u32",
    "U64"                           : "u64",
    "F32"                           : "f32",
    "F64"                           : "f64",
    "F128"                          : "f128",

    # Data Types
    "BOOL"                          : "%bool",
    "INT"                           : "%int",
    "FLOAT"                         : "%float",
    "POINTER"                       : "%pointer",
    "STRING"                        : "%string",
    "ARRAY"                         : "%array",
    "TUPLE"                         : "%tuple",
    "RECORD"                        : "%record",
    "OBJECT"                        : "%object",
    "REQUIRED_MODULE"               : "%require",

    # Prefixes
    "VARIABLE_DECL_PREF"            : "%vv",
    "DEFAULT_VALUE_PREF"            : "%dvv",
    "METHOD_DECL_PREF"              : "%mm",
    "CLASS_DECL_PREF"               : "%cc",

    # Builtin Keywords
    "THIS"                          : "%this",
    "SELF"                          : "%this",
    "PARENT"                        : "%parent",
    "SUPER"                         : "%parent",
    "CLASS"                         : "%class",

    # Data Types
    "PARAMETER_DECL"                : "%parameter_decl",
    "METHOD_DECL"                   : "%method_decl",
    "GENERATOR_DECL"                : "%generator_decl",
    "VARIABLE_DECL"                 : "%variable_decl",
    "CLASS_DECL"                    : "%class_decl",
    "UNIT"                          : "%unit",
    "DIR"                           : "%dir",

    # Builtin Methods
    "UNIT_INIT"                     : "%unit_init",
    "CLASS_INIT"                    : "%class_init",
    "CLASS_STATIC_INIT"             : "%class_sinit",

    # Builtin Parameters and Args Types
    "PACKED_POSITIONAL_PARAMETER"   : "%packed_pos_pmt",
    "PACKED_NAMED_PARAMETER"        : "%packed_named_pmt",
    "POSITIONAL_ONLY_PARAMETER"     : "%pos_pmt",
    "KEYWORLD_ONLY_PARAMETER"       : "%keyword_pmt",
    "PACKED_POSTIONAL_ARGUMENT"     : "%pos_arg",
    "PACKED_NAMED_ARGUMENT"         : "%named_arg",

    #Prototype
    "PROTOTYPE"                     : "%prototype",
    "PROTO"                         : "%__proto__",

    "CASE_AS"                       : "%case_as",

    # Root_Scope_id
    "ROOT_SCOPE"                    : 0
})

ABC_INTERNAL = util.SimpleEnum({
    "TRUE"                          : "true",
    "FALSE"                         : "false",
    "NULL"                          : "null",
    "UNDEFINED"                     : "undefined",
    "HOLE"                          : "hole",
    "THIS"                          : "%this",
    "ANONYMOUS"                     : "%mm",
})

JS_PROTOTYPE = util.SimpleEnum({
    "PROTOTYPE"                     : "prototype",
    "PROTO"                         : "__proto__",
    "CONSTRUCTOR"                   : "constructor",
})

TAG_KEYWORD = util.SimpleEnum({
    "RETURN"                        : r"\%return",
    "ARG0"                          : r"\%arg0",
    "ARG1"                          : r"\%arg1",
    "ARG2"                          : r"\%arg2",
    "ARG3"                          : r"\%arg3",
    "ARG4"                          : r"\%arg4",
    "TARGET"                        : r"\%target",
    "RECEIVER"                      : r"\%receiver",
    "FIELD"                         : r"\%field",
    "THIS"                          : r"\%this",
    "ANYNAME"                       : r"\%anyname",
})

SENSITIVE_OPERATIONS = set([
    "call_stmt",
    "array_read",
    "field_read",
    "forin_stmt"
])

GIR_COLUMNS_TO_BE_ADDED = set([
    "fields",
    "methods",
    "nested",
    "static_init",
    "init",
    "parameters",
    "parameters_end",
    "parameters_start",
    "parent_stmt_id",
    "stmt_id",
    "body",
    "then_body",
    "else_body",
    "condition_prebody",
    "update_body",
    "init_body",
    "catch_body",
    "final_body",
    "original_stmt"
])

EventKind = util.SimpleEnum({
    "TAINT_BEFORE"                                  : 0,
    "SINK_BEFORE"                                   : 1,
    "PROP_BEFORE"                                   : 2,
    "PROP_AFTER"                                    : 3,
    "PROP_FOREACH_ITEM"                             : 4,
    "CALL_BEFORE"                                   : 5,
})

EVENT_KIND = util.SimpleEnum({
    "NONE"                                          : 0,
    "MOCK_SOURCE_CODE_READY"                        : 1,
    "ORIGINAL_SOURCE_CODE_READY"                    : 2,
    "UNFLATTENED_GIR_LIST_GENERATED"                : 3,
    "GIR_LIST_GENERATED"                            : 4,
    "GIR_DATA_MODEL_GENERATED"                      : 5,
    "ENTRY_POINT_ANALYSIS_BEFORE"                   : 6,
    "ENTRY_POINT_ANALYSIS_AFTER"                    : 7,
    "UNIT_KIND_HIERARCHY_GENERATED"                 : 8,
    "CONTROL_FLOW_GRAPH_GENERATED"                  : 9,
    "P1STMT_DEF_USE_ANALYSIS_BEFORE"                : 20,
    "P1STMT_DEF_USE_ANALYSIS_AFTER"                 : 21,
    "P1METHOD_DEF_USE_SUMMARY_GENERATED"            : 22,
    "P2STATE_FIELD_READ_BEFORE"                     : 40,
    "P2STATE_FIELD_READ_AFTER"                      : 41,
    "P2STATE_GENERATE_EXTERNAL_STATES"              : 42,
    "P2STATE_NEW_OBJECT_BEFORE"                     : 43,
    "P2STATE_BUILTIN_FUNCTION_BEFORE"               : 44,
    "P2STATE_NEW_OBJECT_AFTER"                      : 45,
    "P2STATE_EXTERN_CALLEE"                         : 46,
    "P2STATE_FIELD_WRITE_AFTER"                     : 47,
    "P2STATE_CALL_STMT_BEFORE"                      : 48,
    "P2STATE_CALL_STMT_AFTER"                       : 49,
})
