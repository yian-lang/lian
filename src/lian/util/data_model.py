#!/usr/bin/env python3

import numpy as np
import pandas as pd

from lian.config import config
from lian.util import util

class DataModel:
    def __init__(self, data = None, columns = None, reset_index = False, is_copy = False):
        self._data = None
        self._reset_index = reset_index
        self._schema = {}

        self._need_refresh_rows = True
        self._rows = None
        self._column_indexer = {}

        if data is None:
            return

        if isinstance(data, pd.DataFrame):
            if is_copy:
                self._data = data.copy(deep=False)
            else:
                self._data = data

        elif isinstance(data, DataModel):
            self._data = data._data
            self._rows = data._rows
            self._column_indexer = data._column_indexer

        else:
            if columns is not None and len(columns) != 0:
                if isinstance(columns, dict):
                    self._data = pd.DataFrame(data, columns = columns.keys())
                    # self.set_columns(columns)
                else:
                    self._data = pd.DataFrame(data, columns = columns)
            else:
                self._data = pd.DataFrame(data)

        if self._data is not None:
            self.refresh_schema()
            if reset_index:
                self.reset_index()

    def clone(self):
        return DataModel(self._data, is_copy=True)

    def set_refresh_flag(self):
        self._need_refresh_rows = True
        if self._data is not None:
            self.refresh_schema()

    def __getitem__(self, item):
        # treat item as a column name if item is string
        if isinstance(item, str):
            return self.access_column(item)
        # item is a row index if item is a integer or a list
        return self.access(item)

    def __getattr__(self, column_name):
        return self.access_column(column_name)

    def __iter__(self):
        self.refresh_rows()
        index = self._data.index

        counter = 0
        for row in self._rows:
            yield Row(row, self._schema, index[counter])
            counter += 1

    def __len__(self):
        return len(self._data)

    def __repr__(self):
        self.refresh_rows()

        row_str = []
        for row in self._rows:
            row_str.append("  " + str(list(row)).replace("None,", "").replace("nan,", ""))
        result = "\n".join(row_str)
        return f'DataModel(length={len(self._data)}, _schema={str(self._schema.keys())},\n _rows = [\n{result}\n])'

    def is_empty(self):
        if self._data is None:
            return True
        return len(self._data) == 0

    def is_available(self):
        return not self.is_empty()

    def refresh_schema(self):
        self._schema = util.list_to_dict_with_index(self._data.columns)

    def refresh_rows(self):
        if not self._need_refresh_rows:
            return
        self._need_refresh_rows = False

        # refresh the row content
        self._rows = self._data.values
        # reset indexer
        self._column_indexer = {}

    def get_rows(self):
        self.refresh_rows()
        return self._rows

    def set_columns(self, columns):
        self._data.columns = columns

    def unique_values_of_column(self, column):
        s = set(self._data[column])
        s.discard(None)
        s.discard(np.nan)
        s.discard(float("nan"))
        return s

    def load(self, path):
        self._data = pd.read_feather(path)
        self.set_refresh_flag()
        return self

    def save(self, path):
        try:
            self.reset_index()._data.to_feather(path)
            return self
        except Exception as e:
            print(e)

    def access(self, row_index, column_name = ""):
        if len(column_name) != 0:
            return self._data.loc[row_index, column_name]

        self.refresh_rows()
        if isinstance(row_index, (int, np.int64)):
            if row_index >= 0 and row_index < len(self._rows):
                return Row(self._rows[row_index], self._schema, self._data.index[row_index])
            return None

        if isinstance(row_index, (list, set)):
            results = []
            for item in row_index:
                results.append(self.access(item))
            return results

        return None

    def access_column(self, column_name):
        # pos = self._schema.get(column_name, -1)
        # if pos == -1:
        #     return None

        # data = None
        # if self._rows is not None:
        #     data = self._rows[:, pos]
        # else:
        #     data = self._data.values[:, pos]

        data = self._data[column_name].values
        column = Column(self._data[column_name])
        column._parent_data_model = self
        column._column_name = column_name
        column._column_data = data
        return column

    def slice(self, start_index, end_index):
        result = DataModel(self._data.iloc[start_index: end_index], columns = self._schema.keys())
        return result

    def append_data_model(self, extra_data):
        target_to_be_merged = extra_data
        if isinstance(extra_data, DataModel):
            target_to_be_merged = extra_data._data
        self._data = pd.concat([self._data, target_to_be_merged], ignore_index=True, copy = False)
        self.set_refresh_flag()

    def modify_row(self, row_index, new_row):
        self._data.iloc[row_index] = new_row
        self.set_refresh_flag()

    def modify_column(self, column_name, value):
        self._data[column_name] = value
        self.set_refresh_flag()

    def rename_column(self, columns):
        self._data.rename(columns=columns, inplace=True, copy = False)
        self.set_refresh_flag()

    def modify_element(self, row_index, column_name, value):
        self._data.loc[row_index, column_name] = value
        self.set_refresh_flag()

    def slow_query(self, condition_or_index, column_name = "", reset_index:bool = True):
        if isinstance(condition_or_index, set):
            condition_or_index = list(condition_or_index)

        if len(column_name) != 0:
            return self._data.loc[condition_or_index, column_name]

        df = self._data.loc[condition_or_index]
        return DataModel(df, columns = self._schema, reset_index = reset_index)
    
    def _convert_bool_list_to_index_list(self, bool_list):
        return np.where(bool_list)[0]

    def slow_query_first(self, mask):
        self.refresh_rows()
        index = None
        if isinstance(mask, (int, np.int64)):
            index = mask
        else:
            if not isinstance(mask, set):
                mask = self._convert_bool_list_to_index_list(mask)
            if len(mask) == 0:
                return None
            index = sorted(mask)[0]
        row = self._rows[index]
        return Row(row, self._schema, index)
    
    def query_index_column_value_indices(self, column_name, value) -> list:
        if util.isna(value):
            return []
        
        if column_name not in self._schema:
            util.error_and_quit(f"Failed to find column \"{column_name}\"")
        
        if column_name not in self._column_indexer:
            self._indexing_column(column_name)

        return sorted(self._column_indexer[column_name].get(value, set()))

    def query_index_column_value(self, column_name, value) -> "DataModel":  
        index_list = self.query_index_column_value_indices(column_name, value)
        if len(index_list) == 0:
            return []
        df = self._data.iloc[index_list]
        return DataModel(df, columns = self._schema) 

    def query_index_column_value_first(self, column_name, value) -> "Row":
        #self.refresh_rows()
        index_list = self.query_index_column_value_indices(column_name, value)
        if len(index_list) == 0:
            return None
        pos = index_list[0]  # 这就是位置！
        row_data = self._data.iloc[pos].values
        return Row(row_data, self._schema, index_list[0])

    def fillna(self, value):
        self._data.fillna(value, inplace = True)

    def reset_index(self, move_index_to_column = False, directly_modify_current_dataframe = True):
        new_data = self._data.reset_index(
            drop=(not move_index_to_column),
            inplace = directly_modify_current_dataframe
        )
        if not directly_modify_current_dataframe:
            self._data = new_data
        return self

    def _indexing_column(self, column_name, column_data = None):
        if column_data is None:
            column_data = self._data[column_name]

        if column_name not in self._column_indexer:
            self._column_indexer[column_name] = {}

        target = self._column_indexer[column_name]
        # for idx_label, value in zip(self._data.index, column_data):
        for idx_label, value in enumerate(column_data):
            if util.isna(value):
                continue
            if value not in target:
                target[value] = []
            target[value].append(idx_label)

    def search_block_start_end_indics(self, block_id):
        if util.isna(block_id):
            return None
        
        indices = self.query_index_column_value_indices("stmt_id", block_id)
        
        return sorted(indices)

    def read_block(self, block_id, reset_index = False):
        block_start_end = self.search_block_start_end_indics(block_id)
        if block_start_end is None:
            return []
        if len(block_start_end) != 2:
            util.error_and_quit(f"Failed to find block \"{block_id}\"")
            return []

        block = self.slice(block_start_end[0] + 1, block_start_end[1])
        if reset_index:
            block.reset_index()
        return block

    def read_block_with_block_stmts(self, block_id, reset_index = False):
        block_start_end = self.search_block_start_end_indics(block_id)
        if block_start_end is None:
            return []
        if len(block_start_end) < 2:
            return []

        block = self.slice(block_start_end[0], block_start_end[1] + 1)
        if reset_index:
            block.reset_index()
        return block

    def boundary_of_multi_blocks(self, multi_block_ids):
        ids = [-1]
        for block_id in multi_block_ids:
            if not util.isna(block_id):
                block_start_end = self.search_block_start_end_indics(block_id)
                if block_start_end is not None:
                    ids.extend(block_start_end)
        return max(ids)

    def display(self):
        self.refresh_schema()
        self.refresh_rows()
        if config.DEBUG_FLAG:
            util.debug(self._rows)

    def convert_to_dict_list(self):
        df = self._data
        records = df.to_dict(orient="records")
        cleaned_records = []
        for row in records:
            cleaned_row = {}
            for key, value in row.items():
                if pd.notnull(value):
                    cleaned_row[key] = value
            cleaned_records.append(cleaned_row)
        return cleaned_records

    def get_schema(self):
        return self._data.columns

    def get_data(self):
        return self._data

    def remove_rows(self, column_name, value):
        self._data = self._data[self._data[column_name] != value]
        self.set_refresh_flag()

class Row:
    def __init__(self, row, schema, index):
        object.__setattr__(self, "_row", row)
        object.__setattr__(self, "_schema", schema)
        object.__setattr__(self, "_index", index)

    def __copy__(self):
        new_row = self._row
        new_schema = self._schema
        new_index = self._index
        return Row(new_row, new_schema, new_index)

    def __getattr__(self, item):
        pos = self._schema.get(item, -1)
        if pos != -1:
            return self._row[pos]
        if item == "copy":
            return self.__copy__
        if item == "clone":
            return self.__copy__
        #util.error(f"Failed to obtain key <{item}> from the dataframe row{self._row}")
        return None
    
    def get_whole_str(self):
        results = {}
        for schema_name, pos in self._schema.items():
            if pos != -1:
                results[schema_name] = self._row[pos]
        return str(results)

    def to_dict(self):
        result = {}
        for key, pos in self._schema.items():
            result[key] = self._row[pos]
        return result

    def __setattr__(self, name, value):
        if name.startswith("_"):
            object.__setattr__(self, name, value)
        else:
            if name in self._schema:
                pos = self._schema[name]
                self._row[pos] = value
            else:
                self._row.append(value)
                self._schema[name] = len(self._row) - 1
                #raise AttributeError(f"Unable to set properties '{name}'")

    def add_new_column(self, column_name, column_data):
        if column_name in self._schema:
            pos = self._schema[column_name]
            self._row[pos] = column_data
        else:
            self._row = np.append(self._row, column_data)
            self._schema[column_name] = len(self._row) - 1

    def __repr__(self):
        return f"Row({self._row})"

    def get_index(self):
        return self._index

    def __len__(self):
        return len(self._row)

    def raw_data(self):
        return self._row

    def __contains__(self, item):
        return item in self._schema

    def __iter__(self):
        return iter(self._row)

    def __eq__(self, other: object) -> bool:
        """定义两个Row实例的相等性：所有核心属性完全一致才视为相等"""
        if not isinstance(other, Row):
            return False  # 非Row实例直接不相等
        if self._index != other._index:
            return False
        if self._schema != other._schema:
            return False
        if isinstance(self._row, np.ndarray) and isinstance(other._row, np.ndarray):
            if not np.array_equal(self._row, other._row):
                return False
        else:
            if self._row != other._row:
                return False
        return True

    def __hash__(self) -> int:
        schema_tuple = tuple(sorted(self._schema.items()))
        if isinstance(self._row, np.ndarray):
            row_tuple = tuple(self._row.tolist())
        else:
            row_tuple = tuple(self._row)
        return hash((self._index, schema_tuple, row_tuple))

class Column(pd.Series):
    def __repr__(self):
        return f"Column(name:{self._column_name}, data:{self._column_data})"

    # def __len__(self):
    #     return len(self._column_data)

    def is_empty(self):
        return len(self) == 0

    def is_available(self):
        return not self.is_empty()

    def isin(self, target_list: list):
        return np.isin(self, target_list)

    def bundle_search(self, value):
        # use it as eq() when the line number exceeds 100,000 lines
        target = self._parent_data_model._column_indexer
        if self._column_name not in target:
            self._parent_data_model._indexing_column(
                self._column_name, self._column_data
            )

        return target[self._column_name].get(value, set())

