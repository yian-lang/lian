import os
import streamlit as st
import subprocess
import pandas as pd
from pathlib import Path
import collections
import base64
from dataclasses import dataclass

# --- 基础配置 ---
REGULAR_CMD ="python"
BENCHMARK_CMD = "time python -m kernprof -o /tmp/line_profiler.lprof -lvr -u 1e-3 -z"
BASE_DIR = Path(__file__).parent.absolute()
LOGO_PICTURE_PATH = "../docs/cn/img/logo.png"
# 假设 logo 存在，如果没有可以注释掉
LOGO_PATH = BASE_DIR / LOGO_PICTURE_PATH if (BASE_DIR / LOGO_PICTURE_PATH).exists() else None
LIAN_PATH = os.path.join(os.path.dirname(BASE_DIR), "src/lian/main.py")
DEFAULT_WORKSPACE = "/tmp/lian_workspace"

# 支持的语言列表
SUPPORTED_LANGUAGES = [
    "abc", "python", "java", "javascript", "typescript", "php", "c", "go", "llvm", "csharp (dev)", "ruby (dev)", "smali (dev)",
]

# 分析类型选项
ANALYSIS_COMMANDS = {
    "run": "污点分析 Taint analysis",
    "semantic": "语义分析 Semantic analysis",
    "lang": "生成 GIR generation",
}

IGNORED_EXTENSIONS = [".log", ".indexing"]
TXT_EXTENSIONS = [".txt", ".dot"]
IGNORED_DIRS = ["externs", "src"]

SORTED_DIRS = [
    "frontend",
    "semantic_p1",
    "semantic_p2",
    "semantic_p3"
]

# 定义日志展示行数限制（防止浏览器卡死）
MAX_DISPLAY_LINES = 40
UPDATE_FREQ = 10
DATAFRAME_HEIGHT = 600
FOOTER_HEIGHT = 64
MIN_FOOTER_HEIGHT = 20
MAX_FOOTER_HEIGHT = 200


@dataclass
class ReturnStatus:
    status: str
    message: str

class Render:
    def __init__(self) -> None:
        self.workspace = DEFAULT_WORKSPACE
        self.in_path = ""

    def is_ignored_file(self, path):
        for ext in IGNORED_EXTENSIONS:
            if path.endswith(ext):
                return True
        return False

    def is_ignored_dir(self, path):
        for dir_name in IGNORED_DIRS:
            if f"/{dir_name}/" in path or path.endswith(f"/{dir_name}") or path.startswith(f"{dir_name}/") or path == dir_name:
                return True
        return False

    def config_layout(self, page_title="莲花代码分析 Lian Code Analyzer"):
        st.set_page_config(
            layout="wide",
            page_title=page_title,
            page_icon=LOGO_PATH,
            initial_sidebar_state="expanded"
        )

    def config_css(self):
        st.markdown("""
        <style>
            .stTabs [data-baseweb="tab-list"] {
                flex-wrap: wrap;
                row-gap: 0px;
            }

            div[role="radiogroup"] {
                flex-wrap: wrap;
            }

            pre code {
                white-space: pre-wrap !important;
                word-break: break-all !important;
            }
        </style>
        """, unsafe_allow_html=True)

    def config_title(self):
        if LOGO_PATH:
            with open(LOGO_PATH, "rb") as f:
                img_bytes = f.read()
            img_b64 = base64.b64encode(img_bytes).decode()
            header_html = f"""
            <div style=\"display:flex;align-items:center;gap:12px;margin-bottom:1rem;\">
                <img src=\"data:image/png;base64,{img_b64}\" style=\"height:36px;\" />
                <h1 style=\"margin:0;\">莲花代码分析 LIAN Code Analyzer</h1>
            </div>
            """
            st.markdown(header_html, unsafe_allow_html=True)
        else:
            st.title("莲花代码分析 LIAN Code Analyzer")

    def build_sidebar(self):
        from_btn_flag = False
        with st.sidebar:
            col1, col2, col3 = st.columns(3)
            with col1:
                st.header("配置 Config")

            # Disable widgets if analysis is running
            is_running = st.session_state.get("is_running", False)

            self.sub_command = st.radio(
                "选择分析命令 Select analysis command",
                options=list(ANALYSIS_COMMANDS.keys()),
                format_func=lambda x: ANALYSIS_COMMANDS[x],
                disabled=is_running
            )

            self.lang = st.multiselect(
                "语言 Language (-l)",
                options=SUPPORTED_LANGUAGES,
                default=[],
                key="lang_sidebar",
                disabled=is_running
            )

            in_path_input = st.text_input(
                "待分析路径 Input path (-in_path)",
                value=self.in_path,
                help="要分析的代码路径，可以是文件或目录 path to code (file or directory)",
                width="stretch",
                disabled=is_running
            )
            in_path_input = in_path_input.strip()
            if in_path_input.startswith("~"):
                in_path_input = os.path.expanduser(in_path_input)
            if in_path_input != self.in_path:
                self.in_path = in_path_input

            empty_line = True
            if os.path.sep in self.in_path:
                short_path_str = self.in_path
                if self.in_path.endswith(os.path.sep):
                    short_path_str = os.path.basename(self.in_path[:-1]) + "/"
                else:
                    short_path_str = os.path.basename(self.in_path)

                if short_path_str:
                    st.markdown(
                        f"<div style='color: silver; margin: 0; line-height: 0; '>"
                        f"&nbsp&nbsp..{short_path_str}"
                        f"</div>",
                        unsafe_allow_html=True
                    )
                    empty_line = False

            if empty_line:
                st.markdown(
                    f"<div style='color: lightgray; margin: 0; line-height: 0; '>"
                    f""
                    f"</div>",
                    unsafe_allow_html=True
                )

            st.header("其他配置 other settings")
            self.workspace = st.text_input(
                "工作空间路径 Workspace path (-w) ",
                value=self.workspace,
                disabled=is_running
            )

            self.reset_tabs = st.checkbox(
                "重置结果视图 Reset result view",
                value=False,
                disabled=is_running
            )
            self.enable_p2 = st.checkbox(
                "启用第二阶段自下而上分析 Enable P2 preliminary bottom-up analysis (--enable-p2)",
                value=False,
                disabled=is_running
            )
            self.force = st.checkbox(
                "强制模式 Force mode (-f) ",
                value=False,
                disabled=is_running
            )
            self.debug = st.checkbox(
                "调试模式 Debug mode (-d)",
                value=False,
                disabled=is_running
            )
            self.output_graph = st.checkbox(
                "输出SFG图 Output SFG graph (--graph)",
                value=False,
                disabled=is_running
            )
            self.complete_graph = st.checkbox(
                "输出完整SFG图 Output full SFG (--complete-graph)",
                value=False,
                disabled=is_running
            )

            self.print_stmts = st.checkbox(
                "打印语句 Print unflattened GIR statements (-p)",
                value=False,
                disabled=is_running
            )
            self.incremental = st.checkbox(
                "增量分析 Incremental analysis (-inc)",
                value=False,
                disabled=is_running
            )
            self.nomock = st.checkbox(
                "禁用外部假文件 Disable extern mock files (--nomock)",
                value=True,
                disabled=is_running
            )

            self.event_handlers = st.text_input(
                "事件处理器 Event handlers (-e)",
                value="",
                disabled=is_running
            )
            self.default_settings = st.text_input(
                "默认设置 Default settings (--default-settings)",
                value="",
                disabled=is_running
            )
            self.additional_settings = st.text_input(
                "额外设置 Additional settings (--additional-settings)",
                value="",
                disabled=is_running
            )
            self.benchmark= st.checkbox(
                "测试模式 benchmark (--benchmark) : only for test",
                value=False,
                disabled=is_running
            )
            st.markdown("查看[项目源代码Gitee](https://gitee.com/fdu-ssr/lian)")
            st.markdown("本项目由[复旦大学系统安全与可靠性研究组](https://gitee.com/fdu-ssr/)开发和维护")

            st.markdown(" Check out the [source code on GitHub](https://github.com/yang-guangliang/lian)")
            st.markdown(" Developed and maintained by [Fudan University SSR Group](https://yang-guangliang.github.io/)")

            with col2:
                # Show "运行" button when no analysis is running
                if st.button("运行 Run", type="primary", width='stretch', disabled=is_running):
                    cmd_list = self.build_command()
                    st.session_state.last_cmd = cmd_list
                    st.session_state.is_running = True  # Mark analysis as running
                    from_btn_flag = True
                    st.rerun()

            with col3:
                # Show "停止" button when analysis is running
                if st.button("停止 Stop", type="secondary", width='stretch', disabled=not is_running):
                    # Terminate the running process
                    if "process" in st.session_state:
                        st.session_state.process.terminate()
                    st.session_state.is_running = False  # Reset running state
                    from_btn_flag = False
                    st.rerun()

            return from_btn_flag

    def build_command(self):
        cmd = []
        if self.benchmark:
            cmd.extend(BENCHMARK_CMD.split())
        else:
            cmd.append(REGULAR_CMD)
        
        cmd.extend([LIAN_PATH, self.sub_command])

        if self.lang:
            cmd.extend(["-l", ",".join(self.lang)])

        # 参数映射
        flags = [
            ("-f", self.force),
            ("--enable-p2", self.enable_p2),
            ("-d", self.debug),
            ("-p", self.print_stmts),
            #("--android", self.android_mode),
            #("--strict-parse-mode", self.strict_parse),
            ("-inc", self.incremental),
            ("--nomock", self.nomock),
            ("--graph", self.output_graph),
            ("--complete-graph", self.complete_graph),
            ("--benchmark", self.benchmark),
        ]
        for flag, condition in flags:
            if condition:
                cmd.append(flag)

        # 始终传递工作空间路径 (-w)，避免依赖后端默认值
        if self.workspace:
            cmd.extend(["-w", self.workspace])

        options = [
            ("-e", self.event_handlers, ""),
            ("--default-settings", self.default_settings, ""),
            ("--additional-settings", self.additional_settings, ""),
        ]
        for flag, condition, default in options:
            if condition and condition != default:
                cmd.extend([flag, condition])

        cmd.append(self.in_path)

        return cmd

    def display_running_result(self, result_status: ReturnStatus, component=st):
        if result_status is None:
            return

        if result_status.status == "success":
            component.success(result_status.message)
        else:
            component.error(result_status.message)

    def create_log_container_with_result(self, from_btn_flag: bool = False):
        """执行命令并返回日志内容和状态，用于保存到 session_state"""
        if not st.session_state.get("is_running", False):
            if not from_btn_flag:
                self.display_running_result(st.session_state.get("result_status", None))

                if "full_log" in st.session_state:
                    st.subheader("执行日志 Execution log")
                    log_lines = st.session_state.full_log.splitlines()
                    recent_lines = log_lines[-MAX_DISPLAY_LINES:] if len(log_lines) > MAX_DISPLAY_LINES else log_lines
                    with st.expander(f"⚙️ 日志记录 (显示最近 {MAX_DISPLAY_LINES} 行) Log records", expanded=st.session_state.expander_open):
                        st.code("\n".join(recent_lines), language="bash")

                        # Add a "Download Log" button for the full log
                        if len(log_lines) > MAX_DISPLAY_LINES:
                            st.download_button(
                                label="下载完整日志 Download full log",
                                data=st.session_state.full_log.encode('utf-8'),
                                file_name="full_log.txt",
                                mime="text/plain"
                            )
            return

        st.subheader("执行日志 Execution log")

        status_box = st.empty()
        status_box.info("准备开始分析 Preparing analysis ...")

        full_log_content = []
        log_buffer = collections.deque(maxlen=MAX_DISPLAY_LINES)
        line_counter = 0
        result_status = None

        expander_entered = False
        expander_str = f"⚙️ 日志记录 (显示最近 {MAX_DISPLAY_LINES} 行) Log records"
        with st.expander(expander_str, expanded=st.session_state.expander_open):
            expander_entered = True
            log_placeholder = st.empty()

            try:
                status_box.info("🚀 正在启动 Launching LIAN analysis ...")

                # Store the subprocess in session state for termination
                process = subprocess.Popen(
                    st.session_state.last_cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                    encoding='utf-8',
                )
                st.session_state.process = process  # Save process reference

                while True:
                    line = process.stdout.readline()
                    if not line and process.poll() is not None:
                        break

                    if line:
                        line = line.rstrip()
                        if "<Workspace directory> :" in line:
                            workspace_dir = line.split(":")[1].strip()
                            self.workspace = workspace_dir

                        full_log_content.append(line)
                        log_buffer.append(line)

                        if "######" in line:
                            status_box.info(line)

                        line_counter += 1
                        if line_counter % UPDATE_FREQ == 0:
                            log_placeholder.code("\n".join(log_buffer), language="bash")

                log_placeholder.code("\n".join(log_buffer), language="bash")

                return_code = process.wait()

                if return_code == 0:
                    result_status = ReturnStatus("success", "✅ 分析完成 Analysis completed!")
                else:
                    result_status = ReturnStatus("error", f"❌ 分析异常终止 Analysis failed (Exit Code: {return_code})")
            except Exception as e:
                result_status = ReturnStatus("error", f"❌ 执行错误 Execution error: {str(e)}")

            # Save the full log content to session state
            st.session_state.full_log = "\n".join(full_log_content)

        # Reset the running state
        st.session_state.expander_open = expander_entered
        st.session_state.is_running = False
        st.session_state.result_status = result_status
        st.rerun()

    def read_dataframe(self, file_path: Path):
        return pd.read_feather(file_path)

    def render_dataframe_with_search(self, df, key_suffix):
        """渲染带有高级检索功能的 DataFrame"""
        # --- DataFrame 高级检索功能 ---
        with st.expander("🔍 数据检索与过滤 Data search & filter", expanded=False):
            col1, col2 = st.columns([1, 2])
            with col1:
                search_cols = st.multiselect(
                    "限制检索列 (留空则检索所有列) Columns to search (empty = all)",
                    options=df.columns.tolist(),
                    default=[],
                    key=f"cols_{key_suffix}"
                )
            with col2:
                search_term = st.text_input(
                    "输入检索内容 (支持部分匹配) Search term (partial match supported)",
                    key=f"search_{key_suffix}"
                )

        # 执行过滤逻辑
        if search_term:
            target_cols = search_cols if search_cols else df.columns

            # 构建查询条件
            mask = pd.DataFrame(False, index=df.index, columns=target_cols)
            for col in target_cols:
                mask[col] = df[col].astype(str).str.contains(search_term, case=False, na=False)

            final_mask = mask.any(axis=1)
            filtered_df = df[final_mask]

            st.info(f"检索到 {len(filtered_df)} / {len(df)} 行数据 (Found {len(filtered_df)} / {len(df)} rows)")
            st.dataframe(filtered_df, width='stretch', height=DATAFRAME_HEIGHT)
        else:
            st.dataframe(df, width='stretch', height=DATAFRAME_HEIGHT)

    def display_as_text(self, file_path: Path):
        """显示文本文件内容"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            st.code(content, language="text")
        except Exception as e:
            st.error(f"无法读取文件 Failed to read file: {e}")

    def render_results(self):
        st.subheader("分析结果可视化 Analysis results visualization")

        # 检查并处理工作空间路径
        workspace_path = Path(self.workspace)

        if not workspace_path.exists():
            st.info(f"等待分析完成... 工作空间 `{self.workspace}` 尚未找到 (Workspace `{self.workspace}` not found).")

            self.build_footer()
            return

        search_query = st.text_input(
            "🔍 在结果中过滤文件或目录 Filter files/dirs in results",
            key="results_search_box"
        ).lower()

        # 查找所有文件
        result_dirs_map = collections.defaultdict(list) # {dir_path: [file_paths]}

        for root, _, files in os.walk(self.workspace):
            current_root = Path(root)
            current_root_str = str(current_root)

            # 过滤工作空间中的 src 根目录和所有 externs 相关目录
            if self.is_ignored_dir(current_root_str):
                continue

            for file in files:
                # 扩展名过滤
                if self.is_ignored_file(file):
                    continue

                file_path = current_root / file

                # 检查是否匹配搜索关键词
                if not search_query or search_query in file.lower() or search_query in current_root.name.lower():
                    result_dirs_map[current_root].append(file_path)

        if not result_dirs_map:
            if search_query:
                 st.warning(f"在工作空间中未找到与关键词 '{search_query}' 匹配的文件 (No files matched keyword '{search_query}' in workspace).")
            else:
                 st.warning("工作空间中未发现任何文件 (No files found in workspace).")

            self.build_footer()
            return

        # 1. 目录层设计 (Tabs)
        sorted_dirs = sorted(
            list(result_dirs_map.keys()),
            key=lambda d: (
                # Priority order for specific directories
                SORTED_DIRS.index(d.name)
                if d.name in SORTED_DIRS
                else float('inf'),  # Other directories go after
                d.name  # Secondary sort by name
            )
        )

        tabs_map = {}
        tab_name = ""
        for d in sorted_dirs:
            relative_path = d.relative_to(workspace_path)
            tab_name = str(relative_path) if str(relative_path) != '.' else workspace_path.name

            if tab_name in tabs_map:
                 tab_name = f"{d.parent.name}/{d.name}"

            tabs_map[tab_name] = d


        tab_names_list = list(tabs_map.keys())

        if "selected_tab" not in st.session_state or st.session_state.selected_tab not in tab_names_list:
            st.session_state.selected_tab = tab_names_list[0]

        selected_tab = st.radio(
            "目录 Directory",
            options=tab_names_list,
            index=tab_names_list.index(st.session_state.selected_tab),
            horizontal=True,
            key="tab_selection"
        )
        st.session_state.selected_tab = selected_tab

        # 2. 文件层设计：下拉选择 + 内容展示
        dir_path = tabs_map[selected_tab]
        files_with_names = {f.name: f for f in result_dirs_map[dir_path]}
        file_names = sorted(list(files_with_names.keys()))

        if len(file_names) == 0:
            self.build_footer()
            return

        # 文件选择组件
        selected_file = st.selectbox(
            f"选择文件 ({len(file_names)} 个文件) (Select {len(file_names)} files)",
            options=["请选择文件 Please select a file..."] + file_names,
            key="file_select",
            index=1 if len(file_names) == 1 else 0
        )

        file_path_str = files_with_names.get(selected_file, None)
        if not file_path_str:
            self.build_footer()
            return

        file_path = Path(file_path_str)

        st.markdown(f"**文件路径** (File path) : `{file_path}` ")
        self.config_layout(page_title=f"{file_path.name}")

        with st.spinner(f"正在加载 Loading {file_path.name} ({file_path.suffix.upper()})..."):
            if file_path.suffix.lower() in TXT_EXTENSIONS:
                self.display_as_text(file_path)
            else:
                try:
                    df = self.read_dataframe(file_path)
                    self.render_dataframe_with_search(df, f"{tab_name}_{file_path.name}")
                except Exception as e:
                    #st.warning("尝试作为文本显示...")
                    self.display_as_text(file_path)

    def build_footer(self, space_height=FOOTER_HEIGHT):
        st.markdown(f"""
        <div style="min-height: {space_height}vh;"></div>
        """, unsafe_allow_html=True)

    def reset_all_result_tabs(self):
        if "file_select" in st.session_state:
            st.session_state["file_select"] = None

# --- 主界面逻辑 ---
def main():
    render = Render()
    render.config_css()
    render.config_layout()
    render.config_title()
    from_btn_flag = render.build_sidebar()

    if "expander_open" not in st.session_state:
        st.session_state.expander_open = False

    if render.reset_tabs:
        render.reset_all_result_tabs()
        render.reset_tabs = False

    if "last_cmd" in st.session_state:
        st.code(" ".join(st.session_state.last_cmd), language="bash")

    # 执行并保存日志
    render.create_log_container_with_result(from_btn_flag)
    render.render_results()
    render.build_footer(MIN_FOOTER_HEIGHT)

if __name__ == "__main__":
    main()
