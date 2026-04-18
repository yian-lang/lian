
import os

EMPTY                                                        = 0
START_INDEX                                                  = 100
DEBUG_FLAG                                                   = False
STRING_MAX_LEN                                               = 2000000
MAX_PRIORITY                                                 = 100
MIN_ID_INTERVAL                                              = 10
BUILTIN_OBJECT_SYMBOL_ID                                     = -101
BUILTIN_SYMBOL_START_ID                                      = -120        

RULE_START_ID                                                = 10
MAX_ROWS                                                     = 40 * 10000
MAX_BENCHMARK_FILES                                          = 1000
MAX_ANALYSIS_ROUND_FOR_PRELIM_ANALYSIS                       = 1
MAX_ANALYSIS_ROUND_FOR_GLOBAL_ANALYSIS                       = 1
MAX_ANALYSIS_ROUND_FOR_CALL_SITE                             = 1

FIRST_ROUND                                                  = 0
SECOND_ROUND                                                 = 1

ANY_LANG                                                     = "%"

DEFAULT_WORKSPACE                                            = "lian_workspace"
MODULE_SYMBOLS_FILE                                          = "module_symbols"
SOURCE_CODE_DIR                                              = "src"
EXTERNS_DIR                                                  = "externs"
BACKUP_DIR                                                   = "bak"
FRONTEND_DIR                                                 = "frontend"
SEMANTIC_P1_DIR                                              = "semantic_p1"
SEMANTIC_P2_DIR                                              = "semantic_p2"
SEMANTIC_P3_DIR                                              = "semantic_p3"
TAINT_OUTPUT_DIR                                             = "taint"

ROOT_DIR                                                     = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__)))))

LANG_SO_DIR                                                  = os.path.join(ROOT_DIR, "lib")

SRC_LIAN_DIR                                                 = os.path.join(ROOT_DIR, "src/lian")
EXTERNS_MOCK_CODE_DIR                                        = os.path.join(SRC_LIAN_DIR, "externs/mock")
EXTERN_RULES_DIR                                             = os.path.join(SRC_LIAN_DIR, "externs/rules")
EXTERN_MODEL_CODE_DIR                                        = os.path.join(SRC_LIAN_DIR, "externs/modeling")
MOCK_METHOD_NAME_SEPARATOR                                   = "_1_"

DEFAULT_SETTINGS                                             = os.path.join(ROOT_DIR, "default_settings")
DEFAULT_SETTINGS_PATH                                        = os.path.join(ROOT_DIR, DEFAULT_SETTINGS)

BUNDLE_CACHE_CAPACITY                                        = 2
LRU_CACHE_CAPACITY                                           = 20
MIN_CACHE_CAPACITY                                           = 1
MEDIUM_CACHE_CAPACITY                                        = 4

IMPLICIT_ROOT_SCOPES_CACHE_CAPACITY                          = 10
IMPORT_GRAPH_NODE_CACHE_CAPACITY                             = 10

GIR_CACHE_CAPACITY                                           = 1000
METHOD_HEADER_CACHE_CAPABILITY                               = 100
METHOD_BODY_CACHE_CAPABILITY                                 = 10
STMT_SCOPE_CACHE_CAPABILITY                                  = 1000
MAX_STMT_CACHE_CAPACITY                                      = 1000

UNSOLVED_SYMBOL_NAME                                         = "%%%%unsolved_symbols"
POSITIVE_GIR_INTERVAL                                        = 10000
DEFAULT_MAX_GIR_ID                                           = 100000000

MAX_TYPE_CAST_SOURCE_STATES                                  = 4
MAX_ARRAY_ELEMENT_STATES                                     = 4

MAX_METHOD_CALL_COUNT                                        = 30

COMPLETE_SFG_DUMP_FLAG                                       = False

TAINT_SOURCE                                                 = os.path.join(DEFAULT_SETTINGS, "source.yaml")
TAINT_SINK                                                   = os.path.join(DEFAULT_SETTINGS, "sink.yaml")
TAINT_PROPAGATION                                            = os.path.join(DEFAULT_SETTINGS, "propagation.yaml")
TAINT_SOURCE_FROM_CODE                                       = os.path.join(DEFAULT_SETTINGS, "source_from_code.yaml")
TAINT_SINK_FROM_CODE                                         = os.path.join(DEFAULT_SETTINGS, "sink_from_code.yaml")

NO_TAINT                                                     = 0
MAX_STMT_TAINT_ANALYSIS_COUNT                                = 3
ANY_LANG                                                     = "%"


ENTRY_POINTS_FILE                                            = "entry.yaml"
PROPAGATION_FILE                                             = "propagation.yaml"
SOURCE_FILE                                                  = "source.yaml"
SINK_FILE                                                    = "sink.yaml"
INDIRECT_CALL_FILE                                           = "icall.yaml"

MODULE_SYMBOLS_PATH                                          = "module_symbols"
LOADER_INDEXING_PATH                                         = "indexing"
GIR_BUNDLE_PATH                                              = "gir"
CFG_BUNDLE_PATH                                              = "cfg"
SCOPE_HIERARCHY_BUNDLE_PATH                                  = "scope_hierarchy"
METHOD_INTERNAL_CALLEES_PATH                                 = "method_internal_callees"
SYMBOL_NAME_TO_SCOPE_IDS_PATH                                = "symbol_name_to_scope_ids"
SYMBOL_NAME_TO_DECL_IDS_PATH                                 = "symbol_name_to_decl_ids"
SCOPE_ID_TO_SYMBOL_INFO_PATH                                 = "scope_to_symbol_info"
SCOPE_ID_TO_AVAILABLE_SCOPE_IDS_PATH                         = "scope_to_available_scope_ids"

EXTERNAL_SYMBOL_ID_COLLECTION_PATH                           = "external_symbol_id_collection"
UNIQUE_SYMBOL_IDS_PATH                                       = "unique_symbol_ids"

CALL_STMT_ID_TO_INFO_PATH                                    = "call_stmt_id_to_info"
CALL_STMT_ID_TO_CALL_FORMAT_INFO_PATH                        = "call_stmt_format"
METHOD_ID_TO_METHOD_DECL_FORMAT_PATH                         = "method_decl_format"

UNIT_ID_TO_STMT_ID_PATH                                      = "unit_to_stmt_id"
UNIT_ID_TO_METHOD_ID_PATH                                    = "unit_to_method_id"
UNIT_ID_TO_CLASS_ID_PATH                                     = "unit_to_class_id"
UNIT_ID_TO_NAMESPACE_ID_PATH                                 = "unit_to_namespace_id"
UNIT_ID_TO_VARIABLE_ID_PATH                                  = "unit_to_variable_id"
UNIT_ID_TO_IMPORT_STMT_ID_PATH                               = "unit_to_import_stmt"
CLASS_ID_TO_STMT_ID_PATH                                     = "class_to_stmt_id"
METHOD_ID_TO_STMT_ID_PATH                                    = "method_to_stmt_id"
METHOD_ID_TO_PARAMETER_ID_PATH                               = "method_to_parameter_id"
CLASS_ID_TO_METHOD_ID_PATH                                   = "class_to_method_id"
CLASS_ID_TO_FIELD_ID_PATH                                    = "class_to_field_id"
CLASS_ID_TO_MEMBERS_PATH                                     = "class_to_method_id"
CLASS_METHODS_PATH                                           = "class_methods"
CLASS_ID_TO_CLASS_NAME_PATH                                  = "class_id_to_name"
METHOD_ID_TO_METHOD_NAME_PATH                                = "method_id_to_name"
STMT_ID_TO_SCOPE_ID_PATH                                     = "stmt_id_to_scope_id"

CALL_GRAPH_BUNDLE_PATH_P1                                    = "call_graph_p1"
STATIC_CALL_GRAPH_BUNDLE_PATH_P2                             = "call_graph_p2"
GLOBAL_CALL_PATH_BUNDLE_PATH                                 = "call_paths_p3"

ENTRY_POINTS_PATH                                            = "entry_points"
SYMBOL_BIT_VECTOR_MANAGER_BUNDLE_PATH_P1                     = "symbol_bit_vector_p1"
SYMBOL_BIT_VECTOR_MANAGER_BUNDLE_PATH_P2                     = "symbol_bit_vector_p2"
SYMBOL_BIT_VECTOR_MANAGER_BUNDLE_PATH_P3                     = "symbol_bit_vector_p3"
STATE_BIT_VECTOR_MANAGER_BUNDLE_PATH_P1                      = "state_bit_vector_p1"
STATE_BIT_VECTOR_MANAGER_BUNDLE_PATH_P2                      = "state_bit_vector_p2"
STATE_BIT_VECTOR_MANAGER_BUNDLE_PATH_P3                      = "state_bit_vector_p3"
STMT_STATUS_BUNDLE_PATH_P1                                   = "stmt_status_p1"
STMT_STATUS_BUNDLE_PATH_P2                                   = "stmt_status_p2"
STMT_STATUS_BUNDLE_PATH_P3                                   = "stmt_status_p3"
SYMBOL_STATE_SPACE_BUNDLE_PATH_P1                            = "s2space_p1"
SYMBOL_STATE_SPACE_BUNDLE_PATH_P2                            = "s2space_p2"
SYMBOL_STATE_SPACE_BUNDLE_PATH_P3                            = "s2space_p3"
SYMBOL_STATE_SPACE_SUMMARY_BUNDLE_PATH_P2                    = "space_summary_p2"
SYMBOL_STATE_SPACE_SUMMARY_BUNDLE_PATH_P3                    = "space_summary_p3"
DEFINED_SYMBOLS_PATH                                         = "defined_symbols_p1"
DEFINED_SYMBOLS_PATH_P2                                      = "defined_symbols_p2"
DEFINED_SYMBOLS_PATH_P3                                      = "defined_symbols_p3"
DEFINED_STATES_PATH_P1                                       = "defined_states_p1"
DEFINED_STATES_PATH_P2                                       = "defined_states_p2"
USED_SYMBOLS_PATH                                            = "used_symbols"
GROUPED_METHODS_PATH                                         = "grouped_methods"

UNIT_EXPORT_PATH                                             = "unit_export_symbols"
IMPORT_GRAPH_PATH                                            = "import_graph"

TYPE_GRAPH_PATH                                              = "type_graph"

SYMBOL_GRAPH_BUNDLE_PATH_P2                                  = "symbol_graph"
SYMBOL_GRAPH_BUNDLE_PATH_P3                                  = "symbol_graph_p3"
SFG_BUNDLE_PATH_P2                                           = "state_flow_graph_p2"
SFG_BUNDLE_PATH_P3                                           = "state_flow_graph_p3"
STATE_FLOW_GRAPH_P2_DIR                                      = "state_flow_p2_dot"
STATE_FLOW_GRAPH_P3_DIR                                      = "state_flow_p3_dot"

CALLEE_PARAMETER_MAPPING_BUNDLE_PATH_P2                      = "callee_parameter_mapping_p2"
CALLEE_PARAMETER_MAPPING_BUNDLE_PATH_P3                      = "callee_parameter_mapping_p3"

METHOD_DEF_USE_SUMMARY_PATH                                  = "method_def_use_summary"
METHOD_SUMMARY_TEMPLATE_PATH                                 = "method_summary_template"
METHOD_SUMMARY_INSTANCE_PATH                                 = "method_summary_instance"

TAINT_FILE_NAME                                              = "taint_path.yaml"

