#!/usr/bin/env python3

from ctypes import c_void_p, cdll
import os,sys
import subprocess
import tempfile
import unittest
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import pandas as pd
import networkx as nx
import tree_sitter
from pyarrow.lib import ArrowInvalid

import tests.run.init_test as init_test

from lian.config import lang_config
from lian import common_structs as common_structure
from lian.lang import c_parser
from lian.taint.taint_analysis import TaintAnalysis

class TestSearchGraph(unittest.TestCase):
    def setUp(self):
        graph = nx.MultiDiGraph()
        graph.add_edge(11, 1)
        graph.add_edge(12, 1)
        graph.add_edge(1, 2)
        graph.add_edge(21, 2)
        graph.add_edge(22, 2)
        graph.add_edge(211, 21)
        graph.add_edge(212, 21)
        graph.add_edge(2, 3)

        # 3 -> 2 -> 21 -> 211
        #              -> 212
        #        -> 22
        #        -> 1  -> 11
        #              -> 12

        self.result = {
            1: False,
            11: [11],
            12: [12],
            2: False,
            21: False,
            211: True,
            212: True,
            22: None,
            3: None,
        }

        self.graph = graph

    def test_backward_search(self):
        result = self.result
        class Test:
            def test(self, node):
                nonlocal result
                return result.get(node)

        search = common_structure.BasicGraph()
        search.graph = self.graph
        self.assertEqual(search.backward_search(3, Test().test), {11, 12, 211, 212})

    def test_pre_process_graph(self):
        pass


class TestCParserArrayDataType(unittest.TestCase):
    def parse_c_gir(self, code: str):
        lang = next(item for item in lang_config.LANG_TABLE if item.name == "c")
        lib = cdll.LoadLibrary(lang.so_path)
        lang_fn = getattr(lib, "tree_sitter_c")
        lang_fn.restype = c_void_p

        language = tree_sitter.Language(lang_fn())
        parser = tree_sitter.Parser(language)
        tree = parser.parse(code.encode("utf8"))

        options = type("Options", (), {
            "debug": False,
            "print_stmts": False,
            "strict_parse_mode": False,
        })()
        unit_info = type("UnitInfo", (), {"original_path": "array_decl_test.c"})()
        statements = []
        c_parser.Parser(options, unit_info).parse_gir(tree.root_node, statements)
        return statements

    def test_array_declaration_data_type_keeps_declared_size(self):
        statements = self.parse_c_gir(
            "int arr[3];\n"
            "int matrix[2][4];\n"
            "int *ptrs[5];\n"
        )

        decls = [stmt["variable_decl"] for stmt in statements if "variable_decl" in stmt]
        self.assertEqual(decls[0]["data_type"], "int[3]")
        self.assertEqual(decls[1]["data_type"], "int[2][4]")
        self.assertEqual(decls[2]["data_type"], "int*[5]")

    def test_multidimensional_array_initializer_stays_array(self):
        statements = self.parse_c_gir(
            "int matrix[2][3] = {{1, 2, 3}, {4, 5, 6}};\n"
        )

        operations = [
            next(iter(stmt.keys()))
            for stmt in statements
            if isinstance(stmt, dict) and stmt
        ]
        new_arrays = [stmt["new_array"] for stmt in statements if "new_array" in stmt]
        empty_type_structs = [
            stmt["new_struct"]
            for stmt in statements
            if "new_struct" in stmt and not stmt["new_struct"].get("data_type")
        ]

        self.assertGreaterEqual(len(new_arrays), 3)
        self.assertNotIn("new_struct", operations)
        self.assertEqual(empty_type_structs, [])

    def test_struct_initializer_with_array_field_stays_struct(self):
        statements = self.parse_c_gir(
            "struct Buffer { int data[4]; int *cursor; };\n"
            "struct Buffer buf = {{3, 1, 4, 1}, 0};\n"
        )

        struct_news = [stmt["new_struct"] for stmt in statements if "new_struct" in stmt]
        self.assertTrue(
            any(stmt.get("data_type") == "Buffer" for stmt in struct_news),
            msg=f"new_struct statements: {struct_news}",
        )

    def test_anonymous_struct_array_initializer_keeps_element_type(self):
        statements = self.parse_c_gir(
            'static struct { const char *s; int c; } keys[] = {{"x", 1}, {0, 0}};\n'
        )

        struct_news = [stmt["new_struct"] for stmt in statements if "new_struct" in stmt]
        empty_type_structs = [stmt for stmt in struct_news if not stmt.get("data_type")]

        self.assertEqual(empty_type_structs, [])
        self.assertGreaterEqual(len(struct_news), 2)
        self.assertTrue(
            all(stmt.get("data_type", "").startswith("%vv") for stmt in struct_news),
            msg=f"new_struct statements: {struct_news}",
        )


class TestCP2AddrOf(unittest.TestCase):
    def test_addr_of_parameter_does_not_crash_in_p2(self):
        with tempfile.TemporaryDirectory(prefix="lian_c_p2_addr_of_") as tmp_dir:
            tmp_path = Path(tmp_dir)
            project_dir = tmp_path / "project"
            workspace_dir = tmp_path / "workspace"
            project_dir.mkdir()
            (project_dir / "addr_of.c").write_text(
                "void callee(int *p) {}\n"
                "void f(int n) { callee(&n); }\n",
                encoding="utf8",
            )

            env = os.environ.copy()
            src_path = str(Path(__file__).resolve().parents[2] / "src")
            env["PYTHONPATH"] = (
                src_path
                if not env.get("PYTHONPATH")
                else src_path + os.pathsep + env["PYTHONPATH"]
            )

            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "lian.main",
                    "run",
                    str(project_dir),
                    "-l",
                    "c",
                    "-w",
                    str(workspace_dir),
                    "-f",
                    "--enable-p2",
                    "-q",
                ],
                cwd=Path(__file__).resolve().parents[2],
                env=env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=60,
            )

            self.assertEqual(
                result.returncode,
                0,
                msg=f"stdout:\n{result.stdout}\n\nstderr:\n{result.stderr}",
            )

    def test_yank_anonymous_struct_array_does_not_crash_in_p2(self):
        with tempfile.TemporaryDirectory(prefix="lian_c_p2_yank_") as tmp_dir:
            workspace_dir = Path(tmp_dir) / "workspace"
            repo_root = Path(__file__).resolve().parents[2]

            env = os.environ.copy()
            src_path = str(repo_root / "src")
            env["PYTHONPATH"] = (
                src_path
                if not env.get("PYTHONPATH")
                else src_path + os.pathsep + env["PYTHONPATH"]
            )

            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "lian.main",
                    "run",
                    str(repo_root / "tests" / "wy_bug" / "yank.c"),
                    "-l",
                    "c",
                    "-w",
                    str(workspace_dir),
                    "-f",
                    "--enable-p2",
                    "-q",
                ],
                cwd=repo_root,
                env=env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=60,
            )

            self.assertEqual(
                result.returncode,
                0,
                msg=f"stdout:\n{result.stdout}\n\nstderr:\n{result.stderr}",
            )

    def test_struct_field_write_does_not_crash_in_p2(self):
        with tempfile.TemporaryDirectory(prefix="lian_c_p2_mem_write_") as tmp_dir:
            tmp_path = Path(tmp_dir)
            project_dir = tmp_path / "project"
            workspace_dir = tmp_path / "workspace"
            project_dir.mkdir()
            (project_dir / "mem_write.c").write_text(
                "typedef struct Node {\n"
                "    struct Node *next;\n"
                "} Node;\n"
                "\n"
                "void link(Node *p, Node *q) {\n"
                "    p->next = q;\n"
                "}\n",
                encoding="utf8",
            )

            env = os.environ.copy()
            src_path = str(Path(__file__).resolve().parents[2] / "src")
            env["PYTHONPATH"] = (
                src_path
                if not env.get("PYTHONPATH")
                else src_path + os.pathsep + env["PYTHONPATH"]
            )

            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "lian.main",
                    "run",
                    str(project_dir),
                    "-l",
                    "c",
                    "-w",
                    str(workspace_dir),
                    "-f",
                    "--enable-p2",
                    "-q",
                ],
                cwd=Path(__file__).resolve().parents[2],
                env=env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=60,
            )

            self.assertEqual(
                result.returncode,
                0,
                msg=f"stdout:\n{result.stdout}\n\nstderr:\n{result.stderr}",
            )


class TestTaintUnreadableSFG(unittest.TestCase):
    def _make_analysis(self, loader):
        lian = SimpleNamespace(loader=loader)
        options = SimpleNamespace(
            default_settings=str(Path(__file__).resolve().parents[2] / "default_settings"),
            quiet=False,
        )
        return TaintAnalysis(lian, options)

    def test_run_skips_unreadable_entry_point_and_continues(self):
        loader = SimpleNamespace(
            get_all_method_ids=lambda: [101, 202, 303],
            get_global_sfg_by_entry_point=lambda method_id: (
                (_ for _ in ()).throw(ArrowInvalid("File is too small"))
                if method_id == 202 else
                f"sfg-{method_id}"
            ),
        )
        analysis = self._make_analysis(loader)
        processed = []

        def fake_update_sfg(sfg):
            analysis.sfg = sfg

        analysis._update_sfg = fake_update_sfg
        analysis.find_sources = lambda: processed.append(("sources", analysis.current_entry_point)) or []
        analysis.find_sinks = lambda: processed.append(("sinks", analysis.current_entry_point)) or []
        analysis.find_flows = lambda sources, sinks: processed.append(("flows", analysis.current_entry_point)) or []

        with patch("builtins.print") as mock_print:
            result = analysis.run()

        self.assertIs(result, analysis)
        self.assertEqual(
            processed,
            [
                ("sources", 101), ("sinks", 101), ("flows", 101),
                ("sources", 303), ("sinks", 303), ("flows", 303),
            ],
        )
        printed = "\n".join(" ".join(str(arg) for arg in call.args) for call in mock_print.call_args_list)
        self.assertIn("Skip taint entry point 202", printed)
        self.assertIn("Skipped 1 entry points due to unreadable SFG bundles.", printed)

    def test_run_preserves_normal_taint_flow_path(self):
        loader = SimpleNamespace(
            get_all_method_ids=lambda: [11, 22],
            get_global_sfg_by_entry_point=lambda method_id: f"sfg-{method_id}",
        )
        analysis = self._make_analysis(loader)
        processed = []

        def fake_update_sfg(sfg):
            analysis.sfg = sfg

        analysis._update_sfg = fake_update_sfg
        analysis.find_sources = lambda: processed.append(("sources", analysis.current_entry_point)) or ["source"]
        analysis.find_sinks = lambda: processed.append(("sinks", analysis.current_entry_point)) or ["sink"]
        analysis.find_flows = lambda sources, sinks: processed.append(("flows", analysis.current_entry_point)) or []

        with patch("builtins.print") as mock_print:
            result = analysis.run()

        self.assertIs(result, analysis)
        self.assertEqual(
            processed,
            [
                ("sources", 11), ("sinks", 11), ("flows", 11),
                ("sources", 22), ("sinks", 22), ("flows", 22),
            ],
        )
        printed = "\n".join(" ".join(str(arg) for arg in call.args) for call in mock_print.call_args_list)
        self.assertNotIn("Skip taint entry point", printed)
        self.assertNotIn("Skipped 1 entry points", printed)



if __name__ == '__main__':
    unittest.main()
