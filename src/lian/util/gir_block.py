from dataclasses import dataclass
from lian.util import util

@dataclass(frozen=True)
class _BlockFrame:
    block_id: int
    start_index: int

class BlockRange:
    """
    半开区间 (start, end)
    可见 stmt 满足 start < index < end
    """
    def __init__(self, start: int, end: int):
        if start >= end:
            raise ValueError("invalid block range")
        self.start = start
        self.end = end

    def contains_index(self, index: int) -> bool:
        return self.start < index < self.end

    def contains_range(self, other: "BlockRange") -> bool:
        # 使用严格不等式：
        # 子 block 必须完全嵌套在父区间内部，
        # block_start/block_end 本身不属于内部可见 stmt。
        return self.start < other.start and other.end < self.end

    def size(self) -> int:
        return max(0, self.end - self.start - 1)

    def iter_indices(self):
        for i in range(self.start + 1, self.end):
            yield i

    def __repr__(self):
        return f"BlockRange({self.start}, {self.end})"
    
    def get_real_start_index(self):
        return self.start + 1
    
    def get_end_index(self):
        return self.end


class GIRBlockViewer:
    def __init__(self, unit_gir=None, parent=None, scope_range: BlockRange = None):
        # --------------------------
        # 子 block 视图构造
        # --------------------------
        if parent is not None:
            self._stmt_collection = parent._stmt_collection
            self._stmt_id_to_index = parent._stmt_id_to_index
            self._index_to_stmt_id = parent._index_to_stmt_id
            self._block_id_to_range = parent._block_id_to_range
            self._operation_to_indices = parent._operation_to_indices
            self._range = scope_range
            return

        self._stmt_collection = []
        self._stmt_id_to_index = {}
        self._index_to_stmt_id = {}
        self._block_id_to_range = {}
        self._operation_to_indices = {}
        self._range = BlockRange(-1, 0)

        if util.is_empty(unit_gir):
            return None
        
        if isinstance(unit_gir, GIRBlockViewer):
            self._stmt_collection = unit_gir._stmt_collection
            self._stmt_id_to_index = unit_gir._stmt_id_to_index
            self._index_to_stmt_id = unit_gir._index_to_stmt_id
            self._block_id_to_range = unit_gir._block_id_to_range
            self._operation_to_indices = unit_gir._operation_to_indices
            self._range = unit_gir._range
            return
        
        index = -1
        block_stack = []

        for stmt in unit_gir:
            stmt_id = stmt.stmt_id
            op = stmt.operation

            # --------------------------
            # duplicate 检测（允许 block_start/block_end 成对）
            # --------------------------

            index += 1
            self._index_to_stmt_id[index] = stmt_id
            self._stmt_collection.append(stmt)

            if stmt_id not in self._stmt_id_to_index:
                self._stmt_id_to_index[stmt_id] = index
            else:
                existing_index = self._stmt_id_to_index[stmt_id]
                existing_stmt = self._stmt_collection[existing_index]
                # 仅允许：
                #   已存在 block_start
                #   当前为 block_end
                if not (
                    existing_stmt.operation == "block_start"
                    and op == "block_end"
                ):
                    raise RuntimeError("duplicate stmt_id detected")

            # operation 索引
            if op not in self._operation_to_indices:
                self._operation_to_indices[op] = []
            self._operation_to_indices[op].append(index)

            # --------------------------
            # block 几何处理
            # --------------------------
            if op == "block_start":
                block_stack.append(_BlockFrame(stmt_id, index))

            elif op == "block_end":
                if not block_stack:
                    print(unit_gir)
                    raise RuntimeError("block_end without block_start")

                top_block = block_stack.pop()
                if top_block.block_id != stmt_id:
                    raise RuntimeError("block nesting mismatch")

                self._block_id_to_range[stmt_id] = BlockRange(
                    top_block.start_index,
                    index
                )

        if block_stack:
            print(unit_gir)
            raise RuntimeError("unclosed block detected")

        # 根范围
        self._range = BlockRange(-1, len(self._stmt_collection))

    def __len__(self):
        return self._range.size()

    def __getitem__(self, index):
        if isinstance(index, slice):
            return list(self)[index]

        real_len = len(self)

        if index < 0:
            index += real_len

        if index < 0 or index >= real_len:
            raise IndexError

        real_index = self._range.start + 1 + index
        return self._stmt_collection[real_index]
    
    def __iter__(self):
        """
        按当前可见范围的真实 index 顺序迭代。
        """
        for i in self._range.iter_indices():
            yield self._stmt_collection[i]

    def __contains__(self, stmt):
        """
        判断 stmt 是否属于当前可见范围。
        """

        if util.is_empty(stmt):
            return False

        stmt_id = stmt.stmt_id
        index = self._stmt_id_to_index.get(stmt_id)
        if index is None:
            return False

        # 必须 index 在当前 scope 内
        if not self._range.contains_index(index):
            return False

        # 防止不同对象但 id 相同
        return self._stmt_collection[index] is stmt
    
    def __repr__(self):
        """
        打印当前 viewer 可见范围内的所有指令。
        按真实 index 顺序展开。
        """

        lines = []

        header = (
            f"<GIRBlockViewer "
            f"range={self._range} "
            f"size={len(self)}>"
        )

        lines.append(header)

        for i in self._range.iter_indices():
            stmt = self._stmt_collection[i]
            lines.append(f"  [{i}] {stmt!r}")

        lines.append("</GIRBlockViewer>")

        return "\n".join(lines)
    
    def get_range(self) -> BlockRange:
        return self._range
    
    def contains_index_pos(self, index_pos):
        return self._range.contains_index(index_pos)

    def contains_stmt_id(self, stmt_id):
        if stmt_id not in self._stmt_id_to_index:            
            return False
        index = self._stmt_id_to_index[stmt_id]
        return self._range.contains_index(index)
    
    def get_all_stmt_ids(self):
        result = set()
        for i in self._range.iter_indices():
            result.add(self._index_to_stmt_id[i])
        return sorted(result)

    def read_block(self, block_id):
        if util.is_empty(block_id):
            return None
        
        target_range = self._block_id_to_range.get(block_id)
        if target_range is None:
            return None

        # 基于几何包含做访问控制
        if not self._range.contains_range(target_range):
            return None

        return GIRBlockViewer(
            parent=self,
            scope_range=target_range
        )
    
    def get_block_stmt_ids(self, block_id):
        if util.is_empty(block_id):
            return []
        
        target_range = self._block_id_to_range.get(block_id)
        if target_range is None:
            return []
        
        # 收集target_range内所有指令stmt ids
        results = []
        for index in target_range.iter_indices():
            if index in self._index_to_stmt_id:
                results.append(self._index_to_stmt_id[index])
        return results

    def get_stmt_by_id(self, stmt_id):
        idx = self._stmt_id_to_index.get(stmt_id)
        if idx is None:
            return None

        if not self._range.contains_index(idx):
            return None

        return self._stmt_collection[idx]
    
    def get_stmt_by_pos(self, index):
        if not self._range.contains_index(index):
            return None
        return self._stmt_collection[index]

    def query_operation(self, operation):
        """
        基于预建索引的 operation 查询。
        返回结果保持 IR 原始顺序。
        """
        result = []
        for i in self._operation_to_indices.get(operation, []):
            if self._range.contains_index(i):
                result.append(self._stmt_collection[i])

        return result

    def query_field(self, field, value):
        """
        线性扫描字段查询。
        不做任何隐藏索引优化。
        """
        result = []

        for stmt in self:
            if hasattr(stmt, field):
                if getattr(stmt, field) == value:
                    result.append(stmt)

        return result
    
    def append_other(self, other: "GIRBlockViewer"):
        """
        将两个 viewer 当前可见范围按真实 index 顺序拼接，
        返回一个全新的 GIRBlockViewer。

        不共享索引结构，完全重新扫描构造。
        """

        combined = []

        # 1. 按真实 index 顺序添加 self
        for i in self._range.iter_indices():
            combined.append(self._stmt_collection[i])

        # 2. 按真实 index 顺序添加 other
        for i in other._range.iter_indices():
            combined.append(other._stmt_collection[i])

        # 3. 重新扫描构造
        self.__init__(unit_gir=combined)

        return self

    def boundary_of_multi_blocks(self, multi_block_ids):
        """
        给定多个 block_id，
        返回这些 block 对应的最大真实 index。
        不做可见性和几何检查。

        若没有任何有效 block，返回 -1。
        """
        max_index = -1
        for block_id in multi_block_ids:
            block_range = self._block_id_to_range.get(block_id)
            if block_range is None:
                continue

            if block_range.end > max_index:
                max_index = block_range.end

        return max_index
