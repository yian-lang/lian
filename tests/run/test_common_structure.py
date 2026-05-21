#!/usr/bin/env python3

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
from pyarrow.lib import ArrowInvalid

import tests.run.init_test as init_test

from lian import common_structs as common_structure
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
