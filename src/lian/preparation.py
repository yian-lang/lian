#!/usr/bin/env python3

import os
import sys
import re
import shutil
import tempfile
import subprocess
import hashlib
from lian.util import util
from lian.config import constants, config, lang_config
import lian.util.data_model as dm

SymbolKind = constants.LIAN_SYMBOL_KIND
LANG_EXTENSIONS = lang_config.LANG_EXTENSIONS
EXTENSIONS_LANG = lang_config.EXTENSIONS_LANG

class WorkspaceBuilder:
    def __init__(self, options):
        self.dst_file_to_src_file = {}
        self.options = options
        self.clang_installed = False
        self.c_like_extensions = LANG_EXTENSIONS.get('c', []) + LANG_EXTENSIONS.get('cpp', [])
        self.required_subdirs = [
            config.SOURCE_CODE_DIR, config.EXTERNS_DIR, config.FRONTEND_DIR,
            config.SEMANTIC_P1_DIR, config.SEMANTIC_P2_DIR, config.SEMANTIC_P3_DIR,
            config.STATE_FLOW_GRAPH_P2_DIR, config.STATE_FLOW_GRAPH_P3_DIR,
            config.TAINT_OUTPUT_DIR,
        ]
        self.header_keywords = [
            "stdio.h", "stdlib.h", "string.h", "math.h", "ctype.h", "time.h",
            "assert.h", "errno.h", "limits.h", "locale.h", "setjmp.h", "signal.h",
            "stdarg.h", "stddef.h", "stdint.h", "stdio_ext.h", "float.h", "iso646.h",
            "wchar.h", "wctype.h", "fenv.h", "inttypes.h", "complex.h", "tgmath.h",
            "stdalign.h", "stdatomic.h", "stdnoreturn.h", "threads.h", "uchar.h",
            "iostream", "iomanip", "fstream", "sstream", "cmath", "cstdlib", "cstdio",
            "cstring", "cctype", "cwchar", "climits", "cfloat", "cstdarg", "cstdbool",
            "csignal", "cerrno", "ciso646", "cwctype", "csetjmp", "ctime", "cassert",
            "cfenv", "cstdalign", "cstdint", "cinttypes", "clocale", "ccomplex",
            "cuchar", "stdexcept", "string", "vector", "deque", "list", "set", "map",
            "unordered_map", "unordered_set", "stack", "queue", "algorithm", "iterator",
            "numeric", "utility", "memory", "functional", "bitset", "locale", "stdexcept",
            "cassert", "mutex", "thread", "future", "condition_variable", "chrono",
            "random", "ratio", "complex", "tuple", "array", "new", "type_traits",
            "typeinfo", "initializer_list", "scoped_allocator", "system_error", "iosfwd",
            "ios", "istream", "ostream", "limits", "exception", "functional", "locale",
            "codecvt", "cstddef", "cstdint", "compare", "coroutine", "iterator",
            "memory_resource", "version", "concepts", "ranges", "span", "stop_token",
            "syncstream", "any", "optional", "variant"
        ]

    def cleanup_directory(self, path):
        if not os.path.exists(path):
            return
        for filename in os.listdir(path):
            file_path = os.path.join(path, filename)
            try:
                if os.path.isfile(file_path) or os.path.islink(file_path):
                    os.unlink(file_path)
                elif os.path.isdir(file_path):
                    shutil.rmtree(file_path)
            except Exception as e:
                util.error_and_quit(f"Failed to delete {file_path}. Reason: {e}")

    def prepare_directory(self, path):
        if not self.options.quiet:
            print(f"The workspace directory : {path}")

        if not os.path.exists(path):
            os.makedirs(path)
            if not self.options.quiet:
                print(f"Directory created at: {path}")
            return

    def manage_directory(self):
        path = os.path.abspath(self.options.workspace)


        if not self.options.force:
            if not self.options.incremental:
                util.error_and_quit(f"The target directory already exists. Use --force/-f to overwrite.")
        else:
            if not self.options.quiet:
                util.warn(f"With the force mode flag, the workspace is being rewritten")

            self.prepare_directory(path)

            for filename in os.listdir(path):
                file_path = os.path.join(path, filename)
                try:
                    if os.path.isfile(file_path) or os.path.islink(file_path):
                        os.unlink(file_path)
                    elif os.path.isdir(file_path):
                        shutil.rmtree(file_path)
                except Exception as e:
                    util.error_and_quit(f"Failed to delete {file_path}. Reason: {e}")

    def obtain_file_extension(self, file_path):
        return os.path.splitext(file_path)[1].lower()

    def preprocess_c_like_file(self, file_path):
        # check if the file exists
        if not os.path.isfile(file_path):
            util.error(f"Error: The file does not exist or the path is invalid: {file_path}")
            return

        extension = self.obtain_file_extension(file_path)
        if extension not in self.c_like_extensions:
            return

        file_path_name = os.path.splitext(file_path)[0]
        new_file_path = f"{file_path_name}_processed{extension}"

        # Create a new file to store the modified content
        with open(new_file_path, 'w') as new_file:
            with open(file_path, 'r') as f:
                for line in f:
                    # skip the #include <
                    if re.match(r'^\s*#include\s*<', line):
                        continue
                    # skip the keywords
                    if any(re.search(fr'\b{keyword}\b', line) for keyword in self.header_keywords):
                        continue

                    new_file.write(line)

        # Prepare the include headers if provided
        include_flags = []
        if self.options.included_headers:
            include_flags.append('-I')
            include_flags.append(self.options.included_headers)

        # Depending on the language type, choose the right Clang command
        try:
            if extension in LANG_EXTENSIONS.get('c', []) :
                preprocessed_file = f"{file_path_name}.i"
                subprocess.run(['clang', '-P', '-E', new_file_path, '-o', preprocessed_file] + include_flags, check=True)
            elif extension in LANG_EXTENSIONS.get('cpp', []):
                preprocessed_file = f"{file_path_name}.ii"
                subprocess.run(['clang++', '-P', '-E', new_file_path, '-o', preprocessed_file] + include_flags, check=True)
        except subprocess.CalledProcessError:
            return

    def rescan_c_like_files(self, target_path):
        if os.path.isdir(target_path):
            for root, dirs, files in os.walk(target_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    if os.path.isdir(file_path):
                        self.rescan_c_like_files(file_path)
                    elif os.path.isfile(file_path):
                        self.preprocess_c_like_file(file_path)

        elif os.path.isfile(target_path):
            self.preprocess_c_like_file(target_path)

    def change_c_like_files(self, src_dir_path):
        if "c" in self.options.lang or "cpp" in self.options.lang:
            if self.options.enable_header_preprocess:
                if not self.clang_installed:
                    self.clang_installed = shutil.which('clang') is not None and shutil.which('clang++') is not None
                if self.clang_installed:
                    self.rescan_c_like_files(src_dir_path)

                    LANG_EXTENSIONS["c"] = [".i"]
                    LANG_EXTENSIONS["cpp"] = [".ii"]

    def copytree_with_extension(self, src, dst_path):
        if os.path.islink(src):
            return

        # Check if the source is a directory
        if os.path.isdir(src):
            # Walk through the source directory
            for root, dirs, files in os.walk(src):
                # Construct the destination path, maintaining the folder structure
                rel_path = os.path.relpath(root, src)
                new_dst_path = os.path.join(dst_path, rel_path)

                # Create directories in the destination path
                os.makedirs(new_dst_path, exist_ok=True)

                # Recursively call the function for each file with the specified extension
                for file in files:
                    src_file = os.path.join(root, file)
                    self.copytree_with_extension(src_file, new_dst_path)

        # If the source is a file
        elif os.path.isfile(src):
            ext = os.path.splitext(src)[1].lower()
            if ext in self.options.lang_extensions:
                dst_file = os.path.realpath(os.path.join(dst_path, os.path.basename(src)))
                src_file = os.path.realpath(src)
                if not self.options.strict_parse_mode:
                    shutil.copy2(src_file, dst_file)
                self.dst_file_to_src_file[dst_file] = src_file

    def backup_workspace(self):
        workspace_path = self.options.workspace
        if not os.path.exists(workspace_path):
            return
        bak_subdir = os.path.join(workspace_path, config.BACKUP_DIR)

        self.cleanup_directory(bak_subdir)
        os.makedirs(bak_subdir, exist_ok = True)
        for subdir in self.required_subdirs:
            subdir_path = os.path.join(workspace_path, subdir)
            if not os.path.exists(subdir_path):
                continue
            subdir_bak_path = os.path.join(bak_subdir, subdir)
            shutil.copytree(subdir_path, subdir_bak_path)
        module_symbol_path = os.path.join(workspace_path, config.MODULE_SYMBOLS_PATH)
        module_symbol_bak_path = os.path.join(bak_subdir, config.MODULE_SYMBOLS_PATH)
        if os.path.exists(module_symbol_path):
            shutil.copy2(module_symbol_path, module_symbol_bak_path)

    def run(self):
        workspace_path = self.options.workspace
        self.manage_directory()

        # backup the previous workspace. the backup should be empty if forced mode is used.
        if self.options.incremental:
            util.debug("Running under incremental mode, backing up previous workspace")
            self.backup_workspace()
        # util.error_and_quit("Q")
        #build the sub-directories
        for subdir in self.required_subdirs:
            subdir_path = os.path.join(workspace_path, subdir)
            os.makedirs(subdir_path, exist_ok=True)

        src_dir_path = os.path.join(workspace_path, config.SOURCE_CODE_DIR)
        for path in self.options.in_path:
            real_path = os.path.realpath(path)
            if config.DEFAULT_WORKSPACE in real_path:
                continue
            if os.path.isdir(path):
                path_name = os.path.basename(path)
                self.copytree_with_extension(path, os.path.join(src_dir_path, path_name))
            else:
                self.copytree_with_extension(path, src_dir_path)
            #self.copytree_with_extension(path, src_dir_path)

        self.change_c_like_files(src_dir_path)

        if not self.options.nomock:
            externs_dir_path = os.path.join(workspace_path, config.EXTERNS_DIR)
            self.copytree_with_extension(config.EXTERNS_MOCK_CODE_DIR, externs_dir_path)

        return self.dst_file_to_src_file

class ModuleSymbolsBuilder:
    def __init__(self, options, loader, dst_file_to_src_file = {}):
        self.global_module_id = config.START_INDEX
        self.module_symbol_results = []
        self.options = options
        self.loader = loader
        self.file_counter = 0
        self.dst_file_to_src_file = dst_file_to_src_file

        self.target_src_path = os.path.join(self.options.workspace, config.SOURCE_CODE_DIR)

    def generate_module_id(self):
        result = self.global_module_id
        self.global_module_id += 1
        return result

    def file_hash(self, file_path):
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    def scan_modules_by_scanning_workspace_dir(self, module_path, prefix_path,  parent_module_id = 0, is_extern = False):
        if util.is_empty(module_path):
            return

        # Only scan current directory, _not_ recursively
        for entry in os.scandir(module_path):
            # scan all folders and build the module-level symbols
            if entry.is_dir():
                module_id = self.generate_module_id()
                self.module_symbol_results.append({
                    "module_id": module_id,
                    "symbol_name": entry.name,
                    "unit_path": entry.path,
                    "parent_module_id": parent_module_id,
                    "symbol_type": SymbolKind.MODULE_SYMBOL,
                    "is_extern": is_extern
                })
                self.scan_modules_by_scanning_workspace_dir(entry.path, prefix_path, module_id, is_extern)

            # scan each .gl file, and extract the unit-level symbols
            elif entry.is_file():
                self.file_counter += 1
                unit_id = self.generate_module_id()
                unit_name, unit_ext = os.path.splitext(entry.name)

                exported_name = entry.path.replace(prefix_path, "")
                exported_name = os.path.splitext(exported_name)[0]
                exported_name = exported_name.replace(os.path.sep, ".")

                unit_hash = self.file_hash(entry.path)

                self.module_symbol_results.append({
                    "module_id": unit_id,
                    "unit_id": unit_id,
                    "symbol_name": unit_name,
                    "unit_ext": unit_ext,
                    "lang": EXTENSIONS_LANG.get(unit_ext, "unknown"),
                    "parent_module_id": parent_module_id,
                    "symbol_type": SymbolKind.UNIT_SYMBOL,
                    "unit_path": entry.path,
                    "original_path": self.dst_file_to_src_file.get(entry.path, ""),
                    "is_extern": is_extern,
                    "exported_name": exported_name,
                    "hash": unit_hash
                })

    def scan_modules_by_scanning_module_symbol_table(self):
        self.file_path_to_id = {}
        for dst_file in self.dst_file_to_src_file:
            remaining_path = dst_file.replace(self.target_src_path + "/", "")
            path_list = remaining_path.split(os.sep)
            counter = 0
            while counter < len(path_list):
                parent_path = os.path.join(self.target_src_path, os.sep.join(path_list[:counter]))
                parent_module_id = self.file_path_to_id.get(parent_path, 0)
                real_path = os.path.join(parent_path, path_list[counter])
                if real_path in self.file_path_to_id:
                    counter += 1
                    continue

                module_id = self.generate_module_id()
                self.file_path_to_id[real_path] = module_id

                if counter != len(path_list) - 1:
                    # this is directory
                    self.module_symbol_results.append({
                        "module_id": module_id,
                        "symbol_name": path_list[counter],
                        "unit_path": real_path,
                        "parent_module_id": parent_module_id,
                        "symbol_type": SymbolKind.MODULE_SYMBOL,
                        "is_extern": False
                    })
                else:
                    # this is unit file
                    self.file_counter += 1
                    unit_id = module_id
                    unit_name, unit_ext = os.path.splitext(path_list[counter])

                    exported_name = path_list[:-1]
                    exported_name.append(unit_name)
                    exported_name = ".".join(exported_name)

                    self.module_symbol_results.append({
                        "module_id": unit_id,
                        "unit_id": unit_id,
                        "symbol_name": unit_name,
                        "unit_ext": unit_ext,
                        "lang": EXTENSIONS_LANG.get(unit_ext, "unknown"),
                        "parent_module_id": parent_module_id,
                        "symbol_type": SymbolKind.UNIT_SYMBOL,
                        "unit_path": dst_file,
                        "original_path": self.dst_file_to_src_file.get(dst_file, ""),
                        "is_extern": False,
                        "exported_name": exported_name,
                    })

                counter += 1

    def run(self):
        if self.options.strict_parse_mode:
            self.scan_modules_by_scanning_module_symbol_table()
            if len(self.module_symbol_results) == 0:
                util.error_and_quit("No target file found.")
            self.loader.save_module_symbols(self.module_symbol_results)
            return

        target_path = os.path.join(self.options.workspace, config.SOURCE_CODE_DIR + "/")
        self.scan_modules_by_scanning_workspace_dir(module_path = target_path, prefix_path = target_path)
        if len(self.module_symbol_results) == 0:
            util.error_and_quit("No target file found.")
        target_path = os.path.join(self.options.workspace, config.EXTERNS_DIR + "/")
        self.scan_modules_by_scanning_workspace_dir(module_path = target_path, prefix_path = target_path, is_extern = True)
        self.loader.save_module_symbols(self.module_symbol_results)

def run(options, loader):
    dst_file_to_src_file = WorkspaceBuilder(options).run()
    ModuleSymbolsBuilder(options, loader, dst_file_to_src_file).run()
    loader.export()
