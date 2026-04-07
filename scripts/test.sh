#!/bin/bash

# ===================== 配置区（可根据需要修改） =====================
# 默认日志保存目录（会自动创建）
LOG_BASE_DIR="./command_logs"
# ===================================================================

# 检查参数是否正确
if [ $# -ne 1 ]; then
    echo "用法: $0 <目标目录>"
    echo "示例: $0 /home/corgi/test_dir"
    exit 1
fi

# 目标目录（用户传入的参数）
TARGET_DIR="$1"

# 检查目标目录是否存在
if [ ! -d "$TARGET_DIR" ]; then
    echo "错误: 目录 $TARGET_DIR 不存在！"
    exit 1
fi

# 创建日志根目录
mkdir -p "$LOG_BASE_DIR"
if [ $? -ne 0 ]; then
    echo "错误: 无法创建日志目录 $LOG_BASE_DIR"
    exit 1
fi

# 遍历目标目录下的所有一级项（目录 + 文件）
# 使用 * 而非 */，表示匹配所有一级子项
for ITEM in "$TARGET_DIR"/*; do
    # 获取项的完整路径（去重/标准化）
    ITEM_PATH=$(realpath "$ITEM")
    # 获取项的名称（用于日志命名）
    ITEM_NAME=$(basename "$ITEM_PATH")

    # 跳过不存在的项（防御性判断）
    if [ ! -e "$ITEM_PATH" ]; then
        echo "跳过不存在的项: $ITEM_PATH"
        continue
    fi

    # 为每个项创建单独的日志文件（带时间戳）
    TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
    LOG_FILE="$LOG_BASE_DIR/${ITEM_NAME}_${TIMESTAMP}.log"

    echo "========================================"
    # 区分显示是目录还是文件
    if [ -d "$ITEM_PATH" ]; then
        echo "开始处理子目录: $ITEM_NAME"
    else
        echo "开始处理文件: $ITEM_NAME"
    fi
    echo "目标路径: $ITEM_PATH"
    echo "日志将保存到: $LOG_FILE"
    echo "========================================"

    # 执行核心命令：最后一个参数替换为当前项（目录/文件）的路径
    python -m kernprof -o /tmp/line_profiler.lprof -lvr -u 1e-3 -z \
    /home/corgi/workspace/lian/src/lian/main.py run -l javascript -f --nomock \
    --graph --benchmark -w /tmp/lian_workspacee \
    "$ITEM_PATH" \
    > "$LOG_FILE" 2>&1

    # 检查命令执行结果
    if [ $? -eq 0 ]; then
        echo -e "✅ $(if [ -d "$ITEM_PATH" ]; then echo "子目录"; else echo "文件"; fi) $ITEM_NAME 处理完成（成功）"
        echo "执行结果: 查看日志 $LOG_FILE"
    else
        echo -e "❌ $(if [ -d "$ITEM_PATH" ]; then echo "子目录"; else echo "文件"; fi) $ITEM_NAME 处理失败（错误）"
        echo "错误详情: 查看日志 $LOG_FILE"
    fi
    echo -e "\n"
done

echo "========================================"
echo "📊 所有项（目录+文件）处理完成！"
echo "所有日志已保存到: $LOG_BASE_DIR"
echo "========================================"
