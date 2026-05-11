from dataclasses import dataclass
import os
from lian.config.config import LANG_SO_DIR
from lian.lang import (
    abc_parser,
    c_parser,
    csharp_parser,
    go_parser,
    java_parser,
    javascript_parser,
    python_parser,
    ruby_parser,
    php_parser,
    llvm_parser,
    smali_parser,
    typescript_parser,
)
import platform
from lian.util import util

@dataclass
class LangConfig:
    name     : str
    parser   : object
    extension: list     = None
    so_path  : str      = ""


LANG_TABLE = [
    LangConfig(name = "abc", extension = [".txt"], parser = abc_parser.Parser),
    LangConfig(name = "c", extension = [".c", ".h", ".i",], parser = c_parser.Parser),
    LangConfig(name = "csharp", extension = [".cs"], parser = csharp_parser.Parser),
    LangConfig(name = "go", extension = [".go"], parser = go_parser.Parser),
    LangConfig(name = "java", extension = [".java"], parser = java_parser.Parser),
    LangConfig(name = "javascript", extension = [".js"], parser = javascript_parser.Parser),
    LangConfig(name = "python", extension = [".py"], parser = python_parser.Parser),
    LangConfig(name = "php", extension = [".php"], parser = php_parser.Parser),
    LangConfig(name = "ruby", extension = [".rb"], parser = ruby_parser.Parser),
    LangConfig(name = "smali", extension = [".smali"], parser = smali_parser.Parser),
    LangConfig(name = "typescript", extension = [".ts", ".tsx"], parser = typescript_parser.Parser),
    LangConfig(name = "llvm", extension = [".ll"], parser = llvm_parser.Parser),
]

def get_platform_key() -> str:
    system = platform.system().lower()
    machine = platform.machine().lower()

    # ---------- Linux ----------
    if system == "linux":
        if machine in ("x86_64", "amd64"):
            return "linux_x86_64"
        if machine in ("i386", "i686"):
            return "linux_x86_32"
        # if machine in ("aarch64", "arm64"):
        #     return "linux_arm64"
        # if machine in ("armv7l", "armv6l"):
        #     return "linux_arm32"

    # ---------- Windows ----------
    if system == "windows":
        if machine in ("x86_64", "amd64"):
            return "windows_x86_64"
        if machine in ("x86", "i386", "i686"):
            return "windows_x86_32"

    # ---------- macOS ----------
    if system == "darwin":
        if machine == "x86_64":
            return "darwin_x86_64"
        if machine == "arm64":
            return "darwin_arm64"

    # ---------- Fallback ----------
    return "generic"

# 为每种语言设置正确的so文件路径
for lang in LANG_TABLE:
    # 使用当前系统检测到的目录，如果不存在则回退到默认目录
    lang.so_path = os.path.join(LANG_SO_DIR, get_platform_key(), f"{lang.name}.so")
    # 如果so文件不存在，就报错
    # if not os.path.exists(lang.so_path):
    #     util.error_and_quit(f"Failed to initialize the AST parser find so file \"{lang.so_path}\"")

LANG_EXTENSIONS = {}
EXTENSIONS_LANG = {}
def update_lang_extensions(lang_table, lang_list):
    global LANG_EXTENSIONS
    global EXTENSIONS_LANG

    for line in lang_table:
        LANG_EXTENSIONS[line.name] = line.extension

    # Adjust the attribution of .h files
    if "c" in lang_list:
        if ".h" in LANG_EXTENSIONS.get("cpp", []):
            LANG_EXTENSIONS["cpp"].remove(".h")
    elif "cpp" in lang_list:
        if ".h" in LANG_EXTENSIONS.get("c", []):
            LANG_EXTENSIONS["c"].remove(".h")

    for lang, exts in LANG_EXTENSIONS.items():
        for each_ext in exts:
            if each_ext not in EXTENSIONS_LANG:
                EXTENSIONS_LANG[each_ext] = lang
