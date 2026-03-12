#!/usr/bin/env python3

import pprint
from lian.config import config
from lian.common_structs import (
    AccessPoint,
    SimpleWorkList,
    SourceSymbolScopeInfo,
    Symbol,
    UnitSymbolDeclSummary,
    ComputeFrame,
    ComputeFrameStack,
    State,
    ParameterMapping,
    SymbolDefNode,
    StateDefNode,
    SymbolStateSpace,
    MetaComputeFrame,
    DeferedIndexUpdate,
    CallSite
)
from lian.config.constants import (
    EXPORT_NODE_TYPE,
    LIAN_SYMBOL_KIND,
    LIAN_SYMBOL_KIND,
    LIAN_INTERNAL,
    IMPORT_OPERATION,
    ACCESS_POINT_KIND,
    CLASS_DECL_OPERATION,
    STATE_TYPE_KIND,
    IMPORT_GRAPH_EDGE_KIND,
    ANALYSIS_PHASE_ID,
)
from lian.util.loader import Loader
from lian.util import util
from lian.util.decorators import static_vars

class Resolver:
    def __init__(self, options, event_manager, loader):
        self.options = options
        self.loader:Loader = loader
        self.event_manager = event_manager
        self.file_path_to_unit_ids = {}

        # Please note that the variable decls in class scope should not be included
        self.unit_id_to_variable_dec_summary = {}
        self.variable_id_to_scope = {}

        self.implicit_root_scopes_cache = util.LRUCache(config.IMPLICIT_ROOT_SCOPES_CACHE_CAPACITY)

    def find_unit_id_by_path(self, path):
        if path in self.file_path_to_unit_ids:
            return self.file_path_to_unit_ids[path]

        # TODO: given a path, find it and return its unit id
        unit_ids = []

        self.file_path_to_unit_ids[path] = unit_ids
        return unit_ids

    def resolve_class_name_to_ids(self, unit_id, scope_id, class_name):

        result = []

        summary: UnitSymbolDeclSummary = self.loader.get_unit_symbol_decl_summary(unit_id)
        if util.is_empty(summary):
            return result

        if class_name not in summary.symbol_name_to_scope_ids:
            # print(f"scope里没有class_name {class_name}")
            return result

        scope_ids = summary.symbol_name_to_scope_ids[class_name]
        available_scope_ids = summary.scope_id_to_available_scope_ids.get(scope_id, set([0]))
        target_scope_ids = available_scope_ids & scope_ids
        # print("=" * 60)
        # print(scope_ids, available_scope_ids, summary, stmt_id)
        if len(target_scope_ids) == 0:
            return result

        for scope_id in target_scope_ids:
            symbol_id = summary.scope_id_to_symbol_info[scope_id][class_name]
            if not self.loader.is_import_stmt(symbol_id):
                # if it is a class decl, found it
                if self.loader.is_class_decl(symbol_id):
                    result.append(symbol_id)
                continue

            # if it is an import stmt, check the target unit's import information
            export_edge_node_list = self.loader.get_edges_and_nodes_with_edge_attrs_in_import_graph(
                unit_id, {"weight": IMPORT_GRAPH_EDGE_KIND.INTERNAL_SYMBOL, "site" : symbol_id}
            )
            for edge_node_pair in export_edge_node_list:
                import_symbol_id = edge_node_pair.node.symbol_id
                if self.loader.is_class_decl(import_symbol_id):
                    result.append(import_symbol_id)

            # export_symbols = self.loader.load_unit_export_symbols(unit_id)
            # if export_symbols:
            #     import_info = export_symbols.query_index_column_value("import_stmt", symbol_id)
            #     for each_import in import_info:
            #         if self.loader.is_class_decl(each_import.symbol_id):
            #             result.append(each_import.symbol_id)
            import_node = self.loader.get_import_node_with_name(unit_id, class_name)
            if import_node and import_node.symbol_id > 0 and import_node.symbol_type != LIAN_SYMBOL_KIND.UNKNOWN_KIND:
                imported_unit_id = import_node.unit_id
                if imported_unit_id != -1 and imported_unit_id != unit_id:
                    result.append(import_node.symbol_id)

        return result

    def organize_return_value(self, unit_id, scope_id, symbol_name, summary, default_return):
        # 找到scope中该symbol_name的decl_stmt_id
        symbol_id = summary.scope_id_to_symbol_info[scope_id][symbol_name]
        if not self.loader.is_import_stmt(symbol_id):
            return SourceSymbolScopeInfo(unit_id, symbol_id, scope_id)

        # since this is an import stmt, we need to read import information to find the real symbol_id
        import_node = self.loader.get_import_node_with_name(unit_id, symbol_name)
        if util.is_empty(import_node):
            return default_return
        if import_node.symbol_id > 0 and import_node.symbol_type != LIAN_SYMBOL_KIND.UNKNOWN_KIND:
            imported_unit_id = import_node.unit_id
            if imported_unit_id != -1 and imported_unit_id != unit_id:
                # 明确解析出了导入的symbol来源是什么
                return SourceSymbolScopeInfo(
                    imported_unit_id,
                    import_node.symbol_id,
                    self.loader.convert_stmt_id_to_scope_id(import_node.symbol_id),
                    symbol_id
                )
        # 否则，返回import语句
        return SourceSymbolScopeInfo(-1, symbol_id, scope_id)

    def resolve_implicit_root_scopes(self, unit_id):
        if self.implicit_root_scopes_cache.contain(unit_id):
            return self.implicit_root_scopes_cache.get(unit_id)

        unit_scope_space_dm = self.loader.get_unit_scope_hierarchy(unit_id)
        query_implicit_root_scope_condition =(
            (unit_scope_space_dm.get_data()["scope_id"] == 0) &
            (unit_scope_space_dm.get_data()["scope_kind"] == LIAN_SYMBOL_KIND.BLOCK_KIND)
        )
        implicit_root_scopes = set(unit_scope_space_dm.slow_query(
            condition_or_index = query_implicit_root_scope_condition,
            column_name = "stmt_id"
        ).tolist())

        self.implicit_root_scopes_cache.put(unit_id, implicit_root_scopes)
        return implicit_root_scopes

    def resolve_symbol_source_decl(self, unit_id, stmt_id, symbol_name:str, source_symbol_must_be_global = False):
        # if symbol_name == LIAN_INTERNAL.THIS:
        #     return SourceSymbolScopeInfo(unit_id, config.BUILTIN_THIS_SYMBOL_ID, -1)
        # default return value
        default_return = SourceSymbolScopeInfo(unit_id, -1, -1)
        if util.is_empty(symbol_name):
            return default_return

        unit_symbol_decl_summary: UnitSymbolDeclSummary = self.loader.get_unit_symbol_decl_summary(unit_id)

        if source_symbol_must_be_global:
            global_scope_id = 0
            if symbol_name in unit_symbol_decl_summary.symbol_name_to_scope_ids:
                symbol_decl_scopes = unit_symbol_decl_summary.symbol_name_to_scope_ids[symbol_name]
                if global_scope_id in symbol_decl_scopes:
                    return self.organize_return_value(unit_id, global_scope_id, symbol_name, unit_symbol_decl_summary, default_return)
        else:
            # 获取当前语句所在scope_id
            current_scope = self.loader.convert_stmt_id_to_scope_id(stmt_id)
            # if stmt.parent_stmt_id in unit_symbol_decl_summary.scope_id_to_available_scope_ids:
            #     scope_id = stmt.parent_stmt_id
            if current_scope == -1:
                return default_return

            if symbol_name in unit_symbol_decl_summary.symbol_name_to_scope_ids:
                # symbol声明所在的scopes
                symbol_decl_scope_ids = unit_symbol_decl_summary.symbol_name_to_scope_ids[symbol_name]
                # 当前scope可见的scopes
                available_scope_ids = unit_symbol_decl_summary.scope_id_to_available_scope_ids.get(current_scope, set())
                implicit_root_scope_ids = self.resolve_implicit_root_scopes(unit_id)
                # 可用的、声明symbol的scopes
                target_scope_ids = (implicit_root_scope_ids | available_scope_ids) & symbol_decl_scope_ids
                if len(target_scope_ids) != 0:
                    # scope_id越大越近，我们要找最近的decl
                    # sorted_scopes_list = sorted(target_scope_ids, reverse=True)
                    # nearest_scope_id = sorted_scopes_list[0]
                    nearest_scope_id = max(target_scope_ids)
                    return self.organize_return_value(unit_id, nearest_scope_id, symbol_name, unit_symbol_decl_summary, default_return)
        return default_return

    def collect_newest_states_by_state_indexes(
        self, frame: ComputeFrame, stmt_id, state_index_set: set, available_state_defs, old_index_ceiling: int = -1
    ):
        newest_remaining = set()
        state_index_set_copy = set()
        status = frame.stmt_id_to_status[stmt_id]
        for index in state_index_set:
            if old_index_ceiling > 0:
                if index < old_index_ceiling:
                    state_index_set_copy.add(index)
                else:
                    newest_remaining.add(index)
            else:
                state_index_set_copy.add(index)

        # print(f"newest_remaining: {newest_remaining}")
        state_index_to_id = {}
        for index in state_index_set_copy:
            state_index_to_id[index] = frame.symbol_state_space.convert_state_index_to_state_id(index)

        # print("@collect_newest_states_by_state_indexes")
        # print("state_index_set_copy: ", state_index_set_copy)
        # print("state_index_set: ", state_index_set)

        result = set()
        # if frame.method_id == 20:
        #     print(f"available_state_defs: {available_state_defs}")
        #     print("frame.defined_states[12]",frame.defined_states[12])
        for state_index in state_index_to_id:
            state_id = state_index_to_id[state_index]
            if state_id in frame.defined_states:
                state_defs = available_state_defs & frame.defined_states[state_id]
                if state_defs:
                    for each_def in state_defs:
                        if each_def.index != -1:
                            result.add(each_def.index)
                else:
                    result.add(state_index)

            # 如果不在frame.defined_states中，就返回自身
            else:
                result.add(state_index)
        # print(f"result: {result}")

        return result | newest_remaining

    def collect_newest_states_by_state_ids(
        self, frame: ComputeFrame, status, state_id_set
    ):
        index_set = set()
        available_state_defs = frame.state_bit_vector_manager.explain(status.in_state_bits)
        def collect_single_state_id(state_id):
            reachable_state_defs: set[StateDefNode] = set()
            if state_id in frame.defined_states:
                reachable_state_defs = available_state_defs & frame.defined_states[state_id]

            for each_reachable_state_def in reachable_state_defs:
                if each_reachable_state_def.index != -1:
                    index_set.add(each_reachable_state_def.index)

        if isinstance(state_id_set, set):
            for state_id in state_id_set:
                collect_single_state_id(state_id)

        elif isinstance(state_id_set, int):
            collect_single_state_id(state_id_set)

        return index_set

    def obtain_parent_states(self, stmt_id, frame, status, base_state_index):
        parent_state_id = self.obtain_parent_state_id(frame, status, base_state_index)
        parent_state_id = int(parent_state_id)
        if parent_state_id <= 0:
            return set()

        available_state_defs = frame.state_bit_vector_manager.explain(status.in_state_bits)
        # for defined_state_index in status.defined_states:
        #     defined_state: State = frame.symbol_state_space[defined_state_index]
        #     if not isinstance(defined_state, State):
        #         continue

        #     state_id = defined_state.state_id
        #     bit_id = StateDefNode(index=defined_state_index, state_id=state_id, stmt_id=stmt_id)
        #     available_state_defs.add(bit_id)
        #     if bit_id not in frame.all_state_defs:
        #         frame.all_state_defs.add(bit_id)
        #         util.add_to_dict_with_default_set(frame.defined_states, state_id, bit_id)
        #         frame.state_bit_vector_manager.add_bit_id(bit_id)

        newest_states = self.collect_newest_states_by_state_ids(frame, status, {parent_state_id})
        return newest_states

    def obtain_parent_state_id(self, frame, status, base_state_index):
        base_state = frame.symbol_state_space[base_state_index]
        if not isinstance(base_state, State):
            return -1

        status.state_bits = status.in_state_bits
        access_path = base_state.access_path
        if access_path is None or len(access_path) < 2:
            return -1

        parent_state_id = access_path[-2].state_id
        return parent_state_id

    def get_this_state(self, caller_frame: ComputeFrame, new_indexes: set):
        # print("进入get_this_state")
        call_stmt_id = caller_frame.stmt_worklist.peek()
        stmt = self.loader.get_stmt_gir(call_stmt_id)
        if stmt.operation != "call_stmt":
            return

        # 取出call_name_symbol的states
        call_stmt_status = caller_frame.stmt_id_to_status[call_stmt_id]
        call_name_symbol_index = call_stmt_status.used_symbols[0]
        call_name_symbol = caller_frame.symbol_state_space[call_name_symbol_index]
        if not isinstance(call_name_symbol, Symbol):
            return
        call_name_state_index_set = call_name_symbol.states

        # 获取call_name_states的parent_states，也就是this的states
        for each_state_index in call_name_state_index_set:
            new_indexes.update(
                self.obtain_parent_states(call_stmt_id, caller_frame, call_stmt_status, each_state_index)
            )

        # new_space = current_space.extract_related_elements_to_new_space(this_state_set)
        # for source_state_index in this_state_set:
        #     new_index = util.map_index_to_new_index(
        #         source_state_index, new_space.old_index_to_new_index
        #     )
        #     new_indexes.add(new_index)

        # return new_space

    def infer_arg_from_parameter(self, caller_frame: ComputeFrame, callee_frame: ComputeFrame, state_symbol_id, arg_access_path: list, source_states: set):
        # 可能只找到arg的symbol id,也可能直接找到source state
        call_stmt_id = caller_frame.stmt_worklist.peek()
        current_space = caller_frame.symbol_state_space
        source_states.clear()
        # print(f"{callee_id, caller_id, call_stmt_id} load_parameter_mapping")
        parameter_mapping_list: list[ParameterMapping] = self.loader.get_parameter_mapping_p2(callee_frame.call_site)
        # print("parameter_mapping_list")
        # pprint.pprint(parameter_mapping_list)
        if not parameter_mapping_list:
            return state_symbol_id

        arg_fields = {}
        arg_array = []
        for each_mapping in parameter_mapping_list:
            # print(f"each_mapping: {each_mapping}")
            if each_mapping.parameter_symbol_id != state_symbol_id:
                continue

            if each_mapping.is_default_value:
                default_value_symbol_id = each_mapping.arg_state_id
                return default_value_symbol_id

            arg_source_symbol_id = each_mapping.arg_source_symbol_id
            # 实参不是symbol
            if arg_source_symbol_id == -1 and each_mapping.arg_index_in_space != -1:
                parameter_type = each_mapping.parameter_type
                if parameter_type == LIAN_INTERNAL.PACKED_POSITIONAL_PARAMETER:
                    parameter_access_path = each_mapping.parameter_access_path
                    index = parameter_access_path.key
                    util.add_to_list_with_default_set(arg_array, index, each_mapping.arg_index_in_space)

                elif parameter_type == LIAN_INTERNAL.PACKED_NAMED_PARAMETER:
                    parameter_access_path = each_mapping.parameter_access_path
                    key = parameter_access_path.key
                    util.add_to_dict_with_default_set(arg_fields, key, each_mapping.arg_index_in_space)

                else:
                    source_states.add(each_mapping.arg_index_in_space)
                continue

            # print(f"arg_source_symbol_id: {arg_source_symbol_id}")
            if arg_source_symbol_id not in caller_frame.defined_symbols:
                return arg_source_symbol_id

            if each_mapping.parameter_type in (
                LIAN_INTERNAL.PACKED_POSITIONAL_PARAMETER, LIAN_INTERNAL.PACKED_NAMED_PARAMETER
            ):
                parameter_access_path = each_mapping.parameter_access_path
                # print(f"parameter_access_path: {parameter_access_path}")
                for access_point in arg_access_path:
                    if (
                        access_point.kind in (ACCESS_POINT_KIND.FIELD_ELEMENT, ACCESS_POINT_KIND.ARRAY_ELEMENT) and
                        access_point.key == parameter_access_path.key and
                        access_point.kind == parameter_access_path.kind
                    ):
                        # print(f"remove access_point: {access_point}")
                        arg_access_path.remove(access_point)
                        break
                # if parameter_access_path != arg_access_path[0]:
                #     continue

            # current_frame = caller_frame
            # state_symbol_id = arg_source_symbol_id
            #arg_access_path = each_mapping.arg_access_path + arg_access_path
            return arg_source_symbol_id

        if arg_fields or arg_array:
            item = State(
                stmt_id = call_stmt_id,
                value = "",
                source_symbol_id = state_symbol_id,
                fields = arg_fields,
                array = arg_array
            )
            index = current_space.add(item)
            source_states.add(index)

        # if source_states:
        #     new_indexes = set()
        #     new_space = current_space.extract_related_elements_to_new_space(source_states)
        #     for source_state_index in source_states:
        #         new_index = util.map_index_to_new_index(
        #             source_state_index, new_space.old_index_to_new_index
        #         )
        #         new_indexes.add(new_index)
        #     source_states.clear()
        #     source_states.update(new_indexes)
        #     return (state_symbol_id, new_space)

        return state_symbol_id

    def get_latest_source_state_indexes(self, current_frame: ComputeFrame, state_symbol_id):
        # if self.options.debug:
        #     print(f"get_latest_source_state_indexes: method_id {current_frame.method_id}, state_symbol_id: {state_symbol_id}")
        current_space = current_frame.symbol_state_space
        current_stmt_id = current_frame.stmt_worklist.peek()
        current_status = current_frame.stmt_id_to_status[current_stmt_id]

        available_symbol_defs: set = current_frame.symbol_bit_vector_manager.explain(current_status.in_symbol_bits)
        reachable_symbol_defs: set = available_symbol_defs & current_frame.defined_symbols[state_symbol_id]
        available_state_defs = current_frame.state_bit_vector_manager.explain(current_status.in_state_bits)
        # print(f"available_symbol_defs: {available_symbol_defs}")
        # print(f"reachable_symbol_defs: {reachable_symbol_defs}")
        # print(f"available_state_defs: {available_state_defs}")
        source_state_indexes = set()

        if len(reachable_symbol_defs) == 0:
            return set()

        for each_def in reachable_symbol_defs:
            def_symbol = current_space[each_def.index]
            if not isinstance(def_symbol, Symbol):
                continue

            state_index_set = set()
            for source_state_index in def_symbol.states:
                source_state = current_space[source_state_index]
                # if (source_state and isinstance(source_state, State) and source_state.state_type != StateTypeKind.ANYTHING):
                if source_state and isinstance(source_state, State):
                    # source_state_indexes.add(source_state_index)
                    state_index_set.add(source_state_index)
            each_symbol_newest_states = self.collect_newest_states_by_state_indexes(current_frame, current_stmt_id, state_index_set, available_state_defs)
            source_state_indexes.update(each_symbol_newest_states)

        if not source_state_indexes:
            return set()

        state_index_old_to_new = {} # TODO：2024.11.14 是否可以优化，从而不用再新创一个state？
        latest_source_state_indexes = self.retrieve_latest_states(current_frame, current_stmt_id, current_space, source_state_indexes, available_state_defs, state_index_old_to_new) # 拿source_state的最新状态
        # print(f"\nlatest_source_state_indexes in get_latest_source_state_indexes: {latest_source_state_indexes}")
        return latest_source_state_indexes

    # def get_sub_space(self, current_frame, current_space:SymbolStateSpace, latest_source_state_indexes, new_indexes):
    #     if not isinstance(current_frame, ComputeFrame):
    #         return None

    #     if not current_space:
    #         return None

    #     new_space = current_space.extract_related_elements_to_new_space(latest_source_state_indexes)
    #     for source_state_index in latest_source_state_indexes:
    #         new_index = util.map_index_to_new_index(
    #             source_state_index, new_space.old_index_to_new_index
    #         )
    #         new_indexes.add(new_index)

    #     # print(f"new_space in get_sub_space: {new_space}")
    #     # print(f"new_indexes in get_sub_space: {new_indexes}\n")

    #     return new_space

    def retrieve_latest_states(self, frame, stmt_id, symbol_state_space, state_indexes, available_defined_states, state_index_old_to_new):
        return_indexes = set()
        for state_index in state_indexes:
            if state_index in state_index_old_to_new: # 一个下标只处理一次
                return_indexes.update(state_index_old_to_new[state_index])
                continue

            # 找到当前state的最新别名
            newest_state_index_set =  self.collect_newest_states_by_state_indexes(frame, stmt_id, {state_index}, available_defined_states)
            for newest_state_index in newest_state_index_set:
                if newest_state_index in state_index_old_to_new:
                    state_index_old_to_new[state_index] = state_index_old_to_new[newest_state_index]
                    return_indexes.update(state_index_old_to_new[newest_state_index])
                    continue

                newest_state: State = symbol_state_space[newest_state_index]
                if not (newest_state and isinstance(newest_state, State)):
                    continue

                # 其是否有小弟
                if newest_state.fields or newest_state.array or newest_state.tangping_elements:
                    created_state = newest_state.copy(stmt_id)  # 只有该state有小弟时，才需要创建一个新的state并修改。
                    return_index = symbol_state_space.add(created_state)
                    util.add_to_dict_with_default_set(state_index_old_to_new, state_index, return_index)
                    util.add_to_dict_with_default_set(state_index_old_to_new, newest_state_index, return_index)
                    return_indexes.add(return_index)

                    # 递归处理小弟
                    for field_name, field_indexes in created_state.fields.items():
                        new_indexes = self.retrieve_latest_states(frame, stmt_id, symbol_state_space, field_indexes, available_defined_states, state_index_old_to_new)
                        created_state.fields[field_name] = new_indexes

                    new_array = []
                    for array_indexes in created_state.array:
                        latest_array_indexes = self.retrieve_latest_states(frame, stmt_id, symbol_state_space, array_indexes, available_defined_states, state_index_old_to_new)
                        new_array.append(latest_array_indexes)
                        created_state.array = new_array

                    created_state.tangping_elements = self.retrieve_latest_states(frame, stmt_id, symbol_state_space, created_state.tangping_elements, available_defined_states, state_index_old_to_new)

                else:
                    util.add_to_dict_with_default_set(state_index_old_to_new, state_index, newest_state_index)
                    util.add_to_dict_with_default_set(state_index_old_to_new, newest_state_index, newest_state_index)
                    return_indexes.add(newest_state_index)

        return return_indexes

    def get_state_from_path(self, current_space, arg_access_path: list[AccessPoint], source_state_indexes):
        if not arg_access_path:
            return source_state_indexes.copy()

        # print("get_state_from_path方法")
        # print(f"source_state_indexes: {source_state_indexes}")
        # print(f"arg_access_path: {arg_access_path}")

        new_source_states = source_state_indexes.copy()
        for one_point in arg_access_path:
            tmp_indexes = set()
            for source_state_index in new_source_states:
                source = current_space[source_state_index]
                if not source:
                    continue

                tmp_states: set[State] = set()
                if isinstance(source, Symbol):
                    for state_index in source.states:
                        if state_index == -1:
                            continue
                        tmp_state = current_space[state_index]
                        if isinstance(tmp_state, Symbol):
                            continue
                        tmp_states.add(tmp_state)

                    # tmp_states = set([current_space[s] for s in source.states])
                else:
                    tmp_states = {source}

                point_kind = one_point.kind
                #if point_kind in (AccessPointKind.FIELD_NAME, AccessPointKind.FIELD_ELEMENT):
                if point_kind == ACCESS_POINT_KIND.FIELD_ELEMENT:
                    key = one_point.key
                    for tmp_state in tmp_states:
                        fields = tmp_state.fields
                        if key in fields:
                            tmp_indexes.update(fields[key])

                #elif point_kind in (AccessPointKind.ARRAY_INDEX, AccessPointKind.ARRAY_ELEMENT):
                elif point_kind == ACCESS_POINT_KIND.ARRAY_ELEMENT:
                    index = one_point.key
                    for tmp_state in tmp_states:
                        array = tmp_state.array
                        if 0 <= index < len(array):
                            tmp_indexes.update(array[index])

                else:
                    tmp_indexes.add(source_state_index)

            final_indexes = set()
            for tmp_index in tmp_indexes:
                tmp_content = current_space[tmp_index]
                if isinstance(tmp_content, Symbol):
                    final_indexes.update(tmp_content.states)
                else:
                    final_indexes.add(tmp_index)

            new_source_states = final_indexes.copy()

        return new_source_states

    def resolve_symbol_states(self, state: State, frame_stack: ComputeFrameStack, frame: ComputeFrame, stmt_id, stmt, status):
        # -traverse the frame stack;
        # -For each frame, check the bit vector of its last stmt;
        # -find the corresponding states based on the bit vector

        source_symbol_id = state.source_symbol_id
        # if self.options.debug:
        #     print(f"\n\n进入resolve_symbol_states\nresolve_symbol_states@ state_symbol_id: {state_symbol_id} \nresolving_state: {state}\n")
        access_path = state.access_path.copy()
        data_type = state.data_type
        current_space = None
        new_indexes = set()
        return_indexes = set()
        source_state_indexes = set()
        current_frame = None

        for current_frame_index in range(len(frame_stack) - 1, 1, -1):
            current_frame: ComputeFrame = frame_stack[current_frame_index]
            if current_frame.is_meta_frame:
                break

            # if self.options.debug:
                # print(f"--current method id: {current_frame.method_id} state_symbol_id: {state_symbol_id} access_path: {access_path}")
            if len(current_frame.stmt_worklist) == 0:
                continue

            if data_type == LIAN_INTERNAL.THIS or source_symbol_id == frame.method_def_use_summary.this_symbol_id:
                # if self.options.debug:
                #     print("resolve_symbol_states 在找this")
                caller_frame = frame_stack[current_frame_index - 1]
                if caller_frame.is_meta_frame:
                    break
                # if not isinstance(caller_frame, ComputeFrame):
                #     break
                #current_space = self.get_this_state(caller_frame, source_state_indexes)

                self.get_this_state(caller_frame, source_state_indexes)
                # print(f"source_state_indexes before get_state_from_path: {source_state_indexes}")

            else:
                if self.loader.is_method_decl(source_symbol_id):
                    # if self.options.debug:
                    #     print(f"state_source_symbol_id {state_symbol_id} is method_decl")
                    new_state = State(
                        stmt_id = stmt_id,
                        source_symbol_id = source_symbol_id,
                        data_type = LIAN_INTERNAL.METHOD_DECL,
                        state_type = STATE_TYPE_KIND.REGULAR,
                        value = source_symbol_id,
                    )
                    return {current_space.add(new_state)}

                elif self.loader.is_class_decl(source_symbol_id):
                    # if self.options.debug:
                    #     print(f"state_source_symbol_id {state_symbol_id} is class_decl")
                    new_state = State(
                        stmt_id = stmt_id,
                        source_symbol_id = source_symbol_id,
                        data_type = LIAN_INTERNAL.CLASS_DECL,
                        state_type = STATE_TYPE_KIND.REGULAR,
                        value = source_symbol_id
                    )
                    return {current_space.add(new_state)}

                if source_symbol_id not in current_frame.defined_symbols:
                    # if self.options.debug:
                    #     print("state_symbol_id not in current_frame.defined_symbols")
                    continue

                if self.loader.is_parameter_decl_of_method(source_symbol_id, current_frame.method_id):
                    caller_frame = frame_stack[current_frame_index - 1]
                    if caller_frame.is_meta_frame:
                        continue
                    # print("From Parameter Decl")
                    # 根据parameter找到对应的arg，并更新所在frame以及state_symbol_id。
                    #(inferred_symbol_id, source_states_related_space) = self.infer_arg_from_parameter(caller_frame, current_frame, source_symbol_id, access_path, source_state_indexes)
                    inferred_symbol_id = self.infer_arg_from_parameter(caller_frame, current_frame, source_symbol_id, access_path, source_state_indexes)
                    if source_state_indexes:
                        #current_space = source_states_related_space
                        break
                    source_symbol_id = inferred_symbol_id
                    continue

                # 获取source state所在的子space以及其在子space中的index
                # latest_source_state_indexes = self.get_latest_source_state_indexes(current_frame, source_symbol_id)
                # current_space = self.get_sub_space(current_frame, current_space, latest_source_state_indexes, source_state_indexes)

        if current_frame.is_meta_frame:
            return return_indexes

        # if self.options.debug:
        #     print(f"\nsource_state_indexes before get_state_from_path: {source_state_indexes}")
        #     print(f"current_space:{current_space}")
        #     print(f"access_path: {access_path}")
        # 根据source state的access_path找到目标state
        accessed_states = self.get_state_from_path(current_space, access_path, source_state_indexes)
        # if self.options.debug:
        #     print(f"source_state_indexes after get_state_from_path: {accessed_states}")
        if not accessed_states:
            return return_indexes

        # if source_state_indexes:
        #     states_need_to_be_extracted = accessed_states | source_state_indexes
        # else:
        #     states_need_to_be_extracted = accessed_states.copy()

        # new_space = current_space.extract_related_elements_to_new_space(accessed_states)
        # # new_space = current_space.extract_related_elements_to_new_space(states_need_to_be_extracted)
        # for tmp_index in accessed_states:
        #     new_index = util.map_index_to_new_index(
        #         tmp_index, new_space.old_index_to_new_index
        #     )
        #     new_indexes.add(new_index)

        # if new_space:
        #     new_space_copy = new_space.copy()
        #     if new_indexes:
        #         frame.symbol_state_space.append_space_copy(new_space_copy)
        #         for each_index in new_indexes:
        #             return_indexes.add(new_space_copy.old_index_to_new_index[each_index])
        # print(f"source_state_indexes before get_state_from_path: {source_state_indexes}")
        # print(f"current_space:{current_space}")
        return return_indexes


    def resolve_anything_in_summary_generation(
            self, state_index, caller_frame: ComputeFrame, stmt_id, callee_id = -1, deferred_index_updates = None,
            set_to_update = None, parameter_symbol_id = -1
            ):
        '''
        在apply_summary时，若callee的state_summary中，有将要关联的state是anything(external或parameter)，则通过该方法找到concrete_state，并更新set_to_update
        '''
        state = caller_frame.symbol_state_space[state_index]
        state_symbol_id = state.source_symbol_id
        access_path = state.access_path.copy()
        data_type = state.data_type
        caller_symbol_state_space = caller_frame.symbol_state_space
        current_space = None
        new_space = None
        new_indexes = set()
        source_state_indexes = set()

        if self.loader.is_class_decl(state_symbol_id) or self.loader.is_method_decl(state_symbol_id):
            return

        if data_type == LIAN_INTERNAL.THIS or state_symbol_id == caller_frame.method_def_use_summary.this_symbol_id:
            pass

        # 若anything的source是callee参数。
        if self.loader.is_parameter_decl_of_method(state_symbol_id, callee_id):
            if util.is_empty(set_to_update) or deferred_index_updates is None:
                return
            # 收集初始的arg_indexes
            arg_state_indexes = set()
            call_site = CallSite(caller_frame.method_id, stmt_id, callee_id)
            if caller_frame.stmt_state_analysis.analysis_phase_id == ANALYSIS_PHASE_ID.PRELIM_SEMANTICS:
                parameter_mapping_list = self.loader.get_parameter_mapping_p2(call_site)
            else:
                parameter_mapping_list = self.loader.get_parameter_mapping_p3(call_site)
            if util.is_empty(parameter_mapping_list):
                return
            for each_mapping in parameter_mapping_list:
                if each_mapping.parameter_symbol_id == state_symbol_id:
                    arg_state_indexes.add(each_mapping.arg_index_in_space)
            deferred_index_update = DeferedIndexUpdate(
                state_index = state_index, state_symbol_id = state_symbol_id, stmt_id = stmt_id,
                arg_state_indexes = arg_state_indexes, access_path = access_path, set_to_update = set_to_update
                )
            deferred_index_updates.add(deferred_index_update) # 延迟更新。会通过update_deferred_index方法更新

            if state_symbol_id != parameter_symbol_id:
                set_to_update.discard(state_index)
                return
            else:
                # anything_state的src_symbol是parameter自身。说明是a.f=%v1或a.f=a.*的形式
                concrete_state_index = self.resolve_anything_with_same_src_symbol_in_summary_generation(
                    state_index, caller_frame, stmt_id, callee_id, parameter_symbol_id,
                    deferred_index_updates, set_to_update, arg_state_indexes
                )
                if concrete_state_index and concrete_state_index != state_index:
                    set_to_update.add(concrete_state_index)
                    set_to_update.discard(state_index)
                return

        if state_symbol_id in caller_frame.defined_symbols:
            source_state_indexes = self.get_latest_source_state_indexes(caller_frame, state_symbol_id)

        accessed_states = self.get_state_from_path(caller_symbol_state_space, access_path, source_state_indexes)
        if accessed_states:
            set_to_update.discard(state_index)
            set_to_update.update(accessed_states)
            return

    @static_vars(processing_list = set, result_cache = dict)
    def resolve_anything_with_same_src_symbol_in_summary_generation(
        self, state_index, caller_frame: ComputeFrame, stmt_id, callee_id, parameter_symbol_id = -1,
        deferred_index_updates = None, set_to_update = None, arg_state_indexes = None
        ):
        state = caller_frame.symbol_state_space[state_index]
        access_path = state.access_path
        # print(f"\nresolve_anything_with_same_src_symbol_in_summary_generation state_index {state_index} id_set_to_update {id(set_to_update)} path {access_path}\nbegin========= ")

        state_identifier = id(access_path)
        # 循环依赖或没有fields或a.f=a
        if state_identifier in self.resolve_anything_with_same_src_symbol_in_summary_generation.processing_list\
            or not state.fields \
            or len(access_path) == 1:
            # print(set_to_update)
            set_to_update.discard(state_index)
            # if self.options.debug:
            #     if not state.fields:
            #         print("进入的state没有fields(a.f=a.g) 延迟更新")
            #     elif len(access_path) == 1:
            #         print("出现a.f=a，延迟更新")
            #     else:
            #         print("出现循环依赖 延迟更新 ")
            if util.is_available(set_to_update):
                deferred_index_update = DeferedIndexUpdate(
                    state_index = state_index, state_symbol_id = parameter_symbol_id, stmt_id = stmt_id,
                    arg_state_indexes = arg_state_indexes, access_path = access_path, set_to_update = set_to_update
                    )
                # print(f"rs 添加延迟更新 {deferred_index_update}")
                deferred_index_updates.add(deferred_index_update)
            return None
        self.resolve_anything_with_same_src_symbol_in_summary_generation.processing_list.add(state_identifier)

        created_state = state.copy(stmt_id)
        change_flag = False

        for field_name, field_indexes in state.fields.items():
            for field_index in field_indexes:
                field_state = caller_frame.symbol_state_space[field_index]
                if field_state.state_type != STATE_TYPE_KIND.ANYTHING: # field_state.g=1
                    # print(f"遍历该state的fields：field_name为<{field_name}>,state不是anything")
                    continue
                elif field_state.source_symbol_id != parameter_symbol_id: # field_state.g=external
                    # print(f"遍历该state的fields：field_name为<{field_name}>的anything_state的source不是自己")
                    self.resolve_anything_in_summary_generation(
                        field_index, caller_frame, stmt_id, callee_id, deferred_index_updates,
                        created_state.fields[field_name], parameter_symbol_id
                    )
                    change_flag = True
                else: # v1.g=v2 或 field_state.g=a.*
                    # print(f"遍历该state的fields：field_name为<{field_name}>的anything_state的source还是自己，递归")
                    set_to_update.discard(state_index)
                    created_state.fields[field_name].discard(field_index)
                    new_state_index = self.resolve_anything_with_same_src_symbol_in_summary_generation(
                        field_index, caller_frame, stmt_id, callee_id, parameter_symbol_id,
                        deferred_index_updates, created_state.fields[field_name], arg_state_indexes
                        )
                    change_flag = True
                    if new_state_index:
                        created_state.fields[field_name].add(new_state_index)

        if change_flag:
            created_state.state_type =  STATE_TYPE_KIND.REGULAR
            return_index = caller_frame.symbol_state_space.add(created_state)
            util.add_to_dict_with_default_set(
                self.resolve_anything_with_same_src_symbol_in_summary_generation.result_cache,
                state_index,
                return_index
                )
            self.resolve_anything_with_same_src_symbol_in_summary_generation.processing_list.discard(state_identifier)
            # print("有变化，返回",return_index)
            return return_index
        else:
            # print("没变化 进来的什么就返回什么",state_index)
            util.add_to_dict_with_default_set(
                self.resolve_anything_with_same_src_symbol_in_summary_generation.result_cache,
                state_index,
                state_index
                )
            self.resolve_anything_with_same_src_symbol_in_summary_generation.processing_list.discard(state_identifier)
            return state_index


    def update_deferred_index(self, old_to_new_index, deferred_index_updates, current_space):
        for deferred_index_update in deferred_index_updates:
            deferred_index_update:DeferedIndexUpdate
            old_arg_indexes = deferred_index_update.arg_state_indexes
            access_path = deferred_index_update.access_path
            set_to_update = deferred_index_update.set_to_update
            # 从被callee_summary更新完的arg_states中找
            updated_arg_indexes = {old_to_new_index.get(old_arg_index, old_arg_index) for old_arg_index in old_arg_indexes}
            concrete_states = self.get_state_from_path(current_space, access_path, updated_arg_indexes)
            set_to_update.update(concrete_states)

    def are_states_identical(self, state_index1, state_index2, space1: SymbolStateSpace, space2: SymbolStateSpace):
        def are_child_identical(child_index1, child_index2):
            state1 = space1[child_index1]
            state2 = space2[child_index2]
            if not(state1 and isinstance(state1, State) and state2 and isinstance(state2, State)):
                return False

            is_identical = True
            if state1.array and state2.array:
                if len(state1.array) != len(state2.array):
                    return False
                else:
                    for child_group1, child_group2 in zip(state1.array, state2.array):
                        if len(child_group1) != len(child_group2):
                            return False
                        else:
                            for child1, child2 in zip(sorted(list(child_group1)), sorted(list(child_group2))):
                                is_identical &= are_child_identical(child1, child2)
                                if not is_identical:
                                    return False

            elif state1.fields and state2.fields:
                if len(state1.fields) != len(state2.fields):
                    return False
                else:
                    for child_key1, child_key2 in zip(sorted(state1.fields), sorted(state2.fields)):
                        child_group1 = sorted(list(state1.fields[child_key1]))
                        child_group2 = sorted(list(state2.fields[child_key2]))
                        if len(child_group1) != len(child_group2):
                            return False
                        else:
                            for child1, child2 in zip(child_group1, child_group2):
                                is_identical &= are_child_identical(child1, child2)
                                if not is_identical:
                                    return False

            else:
                return state1.value == state2.value
        return are_child_identical(state_index1, state_index2)

    def resolve_symbol_name_to_def_stmt_in_method(
        self, frame:ComputeFrame, unit_id, stmt_id, symbol_name, ignore_field_read_def = True
    ) -> dict[str,set[int]]:

        def find_symbol_def_above_stmt(_stmt_id, _symbol_ids):
            result = set()
            status = frame.stmt_id_to_status[_stmt_id]

            available_defs: list[SymbolDefNode] = frame.symbol_bit_vector_manager.explain(status.in_symbol_bits)
            for symbol_def_node in available_defs:
                if symbol_def_node.symbol_id not in _symbol_ids:
                    continue

                if ignore_field_read_def:
                    def_stmt = self.loader.get_stmt_gir(symbol_def_node.stmt_id)
                    if def_stmt.operation != "field_read":
                        result.add(symbol_def_node.stmt_id)
                    else:
                        # 仍是field_read，递归继续找它的上一层定义
                        result.update(find_symbol_def_above_stmt(def_stmt.stmt_id, _symbol_ids))
                else:
                    result.add(symbol_def_node.stmt_id)
            return result

        NEAREST = "nearest_def_stmt_ids"
        ALL = "all_def_stmt_ids"

        # 收集symbol_name对应的symbol_ids
        symbol_ids = set()
        # insight: symbol_id就是该symbol的decl_stmt_id
        symbol_decl_stmt_ids = self.loader.get_unit_symbol_name_to_decl_ids(unit_id).get(symbol_name, set()) & frame.stmt_id_to_status.keys()
        symbol_ids.update(symbol_decl_stmt_ids)
        # import等语句(见def-use阶段)会修改defined_symbol的symbol_id，需要采集到修改后的symbol_id
        for decl_stmt_id in symbol_decl_stmt_ids:
            decl_stmt = self.loader.get_stmt_gir(decl_stmt_id)
            if decl_stmt.operation in IMPORT_OPERATION:
                decl_stmt_status = frame.stmt_id_to_status[decl_stmt_id]
                new_symbol_id = frame.symbol_state_space[decl_stmt_status.defined_symbol].symbol_id
                symbol_ids.add(new_symbol_id)

        def_stmt_ids = {NEAREST:set(), ALL:set()}

        # 当前方法中最近的对该symbol_name的def
        def_stmt_ids[NEAREST].update(find_symbol_def_above_stmt(stmt_id, symbol_ids))

        # 当前方法中所有该symbol_name的def
        for symbol_id in symbol_ids:
            frame_symbol_to_def:set[SymbolDefNode] = frame.defined_symbols.get(symbol_id, set())
            all_def_stmt_ids_of_symbol_id = {def_node.stmt_id for def_node in frame_symbol_to_def}
            def_stmt_ids[ALL].update(all_def_stmt_ids_of_symbol_id)
        return def_stmt_ids

    def find_symbol_global_def_in_unit(self, unit_id, symbol_name)->dict:
        unit_symbol_decl_summary: UnitSymbolDeclSummary = self.loader.get_unit_symbol_decl_summary(unit_id)
        global_defs = {
            LIAN_SYMBOL_KIND.CLASS_KIND  : set(),
            LIAN_SYMBOL_KIND.METHOD_KIND : set(),
            LIAN_SYMBOL_KIND.IMPORT_STMT : set()
        }
        if unit_symbol_decl_summary.scope_id_to_symbol_info is None: return global_defs
        root_scope_symbol_info = unit_symbol_decl_summary.scope_id_to_symbol_info.get(LIAN_INTERNAL.ROOT_SCOPE, {})
        # TODO：加上implicit_root_scope(比如if name=="main"下的scope定义)
        if symbol_name not in root_scope_symbol_info: return global_defs  # 只要定义在顶层scope中的
        symbol_row_id = root_scope_symbol_info[symbol_name]
        unit_class_ids: list[int] = self.loader.convert_unit_id_to_class_ids(unit_id)
        unit_methods_ids: list[int] = self.loader.convert_unit_id_to_method_ids(unit_id)
        unit_import_stmt_ids: list[int] = self.loader.convert_unit_id_to_import_stmt_ids(unit_id)
        if symbol_row_id in unit_class_ids:
            global_defs[LIAN_SYMBOL_KIND.CLASS_KIND].add(symbol_row_id)
        if symbol_row_id in unit_methods_ids:
            global_defs[LIAN_SYMBOL_KIND.METHOD_KIND].add(symbol_row_id)
        if symbol_row_id in unit_import_stmt_ids:
            global_defs[LIAN_SYMBOL_KIND.IMPORT_STMT].add(symbol_row_id)
        return global_defs

    def get_file_symbol_import_by_name(self, unit_id, symbol_name: str) -> list[str]:
        import_stmts = []
        # 获取当前文件中该symbol_name的import信息
        edge_node_list = self.loader.get_edges_and_nodes_with_edge_attrs_in_import_graph(unit_id, {"real_name": symbol_name})
        for edge_node_pair in edge_node_list:
            import_stmt_id = edge_node_pair.edge.get("site")
            if import_stmt_id != -1:
                import_stmt = self.loader.get_stmt_gir(import_stmt_id)
                import_stmts.append(import_stmt)
        return import_stmts

    def get_previous_call_site(self, frame:ComputeFrame, index:int):
        call_stack:ComputeFrameStack = frame.frame_stack
        if not isinstance(call_stack,ComputeFrameStack):
            return None
        previous_frame_index = index + 1

        if len(call_stack) > previous_frame_index:
            previous_frame:ComputeFrame = call_stack[-previous_frame_index]
            if not isinstance(previous_frame, ComputeFrame):
                return None
            caller_method_id = previous_frame.call_site.caller_id
            call_stmt_id = previous_frame.call_site.call_stmt_id
            callee_method_id = previous_frame.call_site.callee_id
            if caller_method_id == call_stmt_id == -1:
                return None
            caller_method_decl = self.loader.get_method_decl_source_code(caller_method_id)
            caller_method_unit_id = self.loader.convert_method_id_to_unit_id(caller_method_id)
            caller_method_unit_path = self.loader.convert_unit_id_to_unit_path(caller_method_unit_id)
            caller_method_unit_path = caller_method_unit_path if caller_method_unit_path else ""
            caller_method_class_id = self.loader.convert_method_id_to_class_id(caller_method_id)
            caller_method_class_name = self.loader.convert_class_id_to_class_name(caller_method_class_id)
            call_stmt_src_code = self.loader.get_stmt_source_code_with_comment(call_stmt_id)
            callee_method_decl = self.loader.get_method_decl_source_code(callee_method_id)
            caller_frame = None
            if len(call_stack) > previous_frame_index + 1:
                caller_frame:ComputeFrame = call_stack[-(previous_frame_index + 1)]
                if not isinstance(caller_frame, ComputeFrame):
                    caller_frame = None

            return {
                "caller_method_decl"      :  caller_method_decl,
                "caller_method_id"        :  caller_method_id,
                "caller_method_unit_id"   :  caller_method_unit_id,
                "caller_method_unit_path" :  caller_method_unit_path,
                "caller_method_class_id"  :  caller_method_class_id,
                "caller_method_class_name":  caller_method_class_name,
                "call_stmt_source_code"   :  call_stmt_src_code,
                "call_stmt_id"            :  call_stmt_id,
                "callee_method_decl"      :  callee_method_decl,
                "callee_method_id"        :  callee_method_id,
                "caller_frame"            :  caller_frame
            }

    def recover_callee_name(self, stmt, status, s2space):
        if stmt.operation == "object_call_stmt":
            if stmt.receiver_object and not stmt.receiver_object.startswith("%vv"):
                return stmt.receiver_object + '.' + stmt.field
            else:
                return stmt.field
        def access_path_formatter(state_access_path):
            key_list = []

            for item in state_access_path:
                key = item.key
                key = key if isinstance(key, str) else str(key)
                # 处理非空且不以%vv开头的key
                if key and not key.startswith("%vv"):
                    key_list.append(key)
                # 处理以%vv开头且kind为13(call)的情况，添加()后缀
                elif key.startswith("%vv") and item.kind == 13 and key_list:
                    key_list[-1] = key_list[-1] + "()"

            return '.'.join(key_list)

        if not status.used_symbols:
            return "None"

        name_index = status.used_symbols[0]
        name_symbol = s2space[name_index]

        if name_symbol.name.startswith("%vv"):
            access_path = "None"

            for index in name_symbol.states:
                name_state = s2space[index]

                if isinstance(name_state, State) and len(name_state.access_path) > 0:
                    access_path = access_path_formatter(name_state.access_path)
                    break

            return access_path
        
        return name_symbol.name

    def get_class_method(self, class_id):
        methods_in_class = self.loader.get_methods_in_class(class_id)
        class_id_to_methods = {}
        for method in methods_in_class:
            method_class_id = method.class_id
            class_name = self.loader.convert_class_id_to_class_name(method_class_id)
            class_tuple = (method_class_id, class_name)
            if class_tuple not in class_id_to_methods:
                class_id_to_methods[class_tuple] = [method]
            else:
                class_id_to_methods[class_tuple].append(method)

        return class_id_to_methods
