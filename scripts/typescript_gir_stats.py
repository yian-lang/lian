#!/usr/bin/env python3

import argparse
import builtins
import json
import os
import sys
from collections import Counter
from pathlib import Path
from types import SimpleNamespace

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.append(str(REPO_ROOT / "src"))

try:
    builtins.profile
except AttributeError:
    def profile(func):
        return func
    builtins.profile = profile

from lian.config import lang_config
from lian.config.constants import EVENT_KIND
from lian.events.event_manager import EventManager
from lian.events.handler_template import EventData
from lian.lang.lang_analysis import GIRParser, GIRProcessing


DEFAULT_EXCLUDE_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".next",
    ".turbo",
    "coverage",
    "node_modules",
    "extension-node-modules",
}


def build_options():
    return SimpleNamespace(
        debug=False,
        print_stmts=False,
        strict_parse_mode=False,
        quiet=True,
        event_handlers=[],
    )


def discover_typescript_files(paths, exclude_dirs, include_dts):
    discovered = []
    seen = set()

    for raw_path in paths:
        path = Path(raw_path).resolve()
        if not path.exists():
            raise FileNotFoundError(f"Path does not exist: {path}")

        if path.is_file():
            if is_typescript_file(path, include_dts):
                resolved = str(path)
                if resolved not in seen:
                    seen.add(resolved)
                    discovered.append(path)
            continue

        for root, dirs, files in os.walk(path):
            dirs[:] = sorted(d for d in dirs if d not in exclude_dirs)
            for filename in sorted(files):
                candidate = Path(root) / filename
                if not is_typescript_file(candidate, include_dts):
                    continue
                resolved = str(candidate.resolve())
                if resolved in seen:
                    continue
                seen.add(resolved)
                discovered.append(candidate.resolve())

    return sorted(discovered)


def is_typescript_file(path, include_dts):
    suffixes = path.suffixes
    if suffixes[-2:] == [".d", ".ts"] and not include_dts:
        return False
    return path.suffix in {".ts", ".tsx"}


def count_source_lines(code):
    lines = code.splitlines()
    total_lines = len(lines)
    non_empty_lines = sum(1 for line in lines if line.strip())
    return total_lines, non_empty_lines


def collect_operation_counts(flattened_nodes):
    counts = Counter()
    for node in flattened_nodes:
        if not isinstance(node, dict):
            continue
        operation = node.get("operation")
        if not operation:
            continue
        counts[operation] += 1
    return counts


def format_ratio(value):
    return f"{value:.4f}"


def print_operation_summary(operation_counts):
    print("Flattened GIR node counts:")
    for operation, count in sorted(operation_counts.items(), key=lambda item: (-item[1], item[0])):
        print(f"  {operation:<24} {count}")


def print_top_files(file_stats, top_n, ratio_base_label):
    print()
    print(f"Top {min(top_n, len(file_stats))} files by flattened GIR/source-line ratio ({ratio_base_label} lines):")
    if not file_stats:
        print("  <no files>")
        return

    header = (
        f"{'#':>2}  {'ratio':>9}  {'gir':>7}  "
        f"{'lines':>7}  {'all':>7}  file"
    )
    print(header)
    for index, stat in enumerate(file_stats[:top_n], start=1):
        print(
            f"{index:>2}  "
            f"{format_ratio(stat['ratio']):>9}  "
            f"{stat['flattened_gir_count']:>7}  "
            f"{stat['ratio_base_lines']:>7}  "
            f"{stat['total_lines']:>7}  "
            f"{stat['path']}"
        )


def flatten_typescript_gir(parser, lang_name, gir_statements):
    event = EventData(lang_name, EVENT_KIND.UNFLATTENED_GIR_LIST_GENERATED, gir_statements)
    parser.event_manager.notify(event)

    _, flattened_nodes = GIRProcessing(0).flatten(event.out_data)
    if not flattened_nodes:
        return []

    event = EventData(lang_name, EVENT_KIND.GIR_LIST_GENERATED, flattened_nodes)
    parser.event_manager.notify(event)
    return event.out_data


def create_report(files, parser, ratio_base, lang_table):
    aggregate_operation_counts = Counter()
    file_stats = []
    failures = []
    lang_name = "typescript"

    for file_path in files:
        try:
            code = file_path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            failures.append({"path": str(file_path), "error": "Failed to decode file as UTF-8"})
            continue
        except OSError as exc:
            failures.append({"path": str(file_path), "error": str(exc)})
            continue

        total_lines, non_empty_lines = count_source_lines(code)

        try:
            gir_statements = parser.parse(
                SimpleNamespace(original_path=str(file_path)),
                str(file_path),
                lang_name,
                lang_table,
            )
        except SystemExit as exc:
            failures.append({"path": str(file_path), "error": f"Parser aborted with code {exc.code}"})
            continue
        except Exception as exc:
            failures.append({"path": str(file_path), "error": str(exc)})
            continue

        if not gir_statements:
            flattened_nodes = []
        else:
            try:
                flattened_nodes = flatten_typescript_gir(parser, lang_name, gir_statements)
            except SystemExit as exc:
                failures.append({"path": str(file_path), "error": f"Flatten aborted with code {exc.code}"})
                continue
            except Exception as exc:
                failures.append({"path": str(file_path), "error": str(exc)})
                continue

        if not flattened_nodes:
            operation_counts = Counter()
        else:
            operation_counts = collect_operation_counts(flattened_nodes)

        flattened_gir_count = len(flattened_nodes)
        aggregate_operation_counts.update(operation_counts)

        ratio_base_lines = non_empty_lines if ratio_base == "non-empty" else total_lines
        ratio = flattened_gir_count / ratio_base_lines if ratio_base_lines else 0.0
        file_stats.append(
            {
                "path": str(file_path),
                "flattened_gir_count": flattened_gir_count,
                "gir_count": flattened_gir_count,
                "total_lines": total_lines,
                "non_empty_lines": non_empty_lines,
                "ratio_base_lines": ratio_base_lines,
                "ratio": ratio,
                "operation_counts": dict(sorted(operation_counts.items())),
            }
        )

    file_stats.sort(key=lambda item: (-item["ratio"], -item["flattened_gir_count"], item["path"]))
    return {
        "files_analyzed": len(file_stats),
        "files_failed": len(failures),
        "total_flattened_gir_count": sum(aggregate_operation_counts.values()),
        "total_gir_count": sum(aggregate_operation_counts.values()),
        "operation_counts": dict(sorted(aggregate_operation_counts.items(), key=lambda item: (-item[1], item[0]))),
        "top_files": file_stats,
        "failures": failures,
    }


def parse_args():
    parser = argparse.ArgumentParser(
        description="Collect GIR statistics for the TypeScript parser."
    )
    parser.add_argument("paths", nargs="+", help="TypeScript file or directory to analyze")
    parser.add_argument(
        "--top",
        type=int,
        default=10,
        help="Number of files to show in the ratio ranking (default: 10)",
    )
    parser.add_argument(
        "--ratio-base",
        choices=["non-empty", "total"],
        default="non-empty",
        help="Use non-empty or total source lines as the ratio denominator (default: non-empty)",
    )
    parser.add_argument(
        "--include-dts",
        action="store_true",
        help="Include .d.ts files in the analysis",
    )
    parser.add_argument(
        "--exclude-dir",
        action="append",
        default=[],
        help="Directory name to exclude during recursive traversal; can be repeated",
    )
    parser.add_argument(
        "--json-out",
        type=str,
        help="Optional path to write the full report as JSON",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    exclude_dirs = DEFAULT_EXCLUDE_DIRS | set(args.exclude_dir)
    files = discover_typescript_files(args.paths, exclude_dirs, args.include_dts)
    if not files:
        print("No TypeScript files found.")
        return 1

    options = build_options()
    event_manager = EventManager(options)
    gir_parser = GIRParser(options, event_manager, loader=None, output_path="")
    lang_table = [lang for lang in lang_config.LANG_TABLE if lang.name == "typescript"]
    report = create_report(files, gir_parser, args.ratio_base, lang_table)

    print(f"Analyzed files: {report['files_analyzed']}")
    print(f"Failed files:   {report['files_failed']}")
    print(f"Total flattened GIR: {report['total_flattened_gir_count']}")
    print_operation_summary(report["operation_counts"])
    print_top_files(report["top_files"], args.top, args.ratio_base)

    if report["failures"]:
        print()
        print("Failures:")
        for failure in report["failures"]:
            print(f"  {failure['path']}: {failure['error']}")

    if args.json_out:
        output_path = Path(args.json_out).resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        print()
        print(f"JSON report written to: {output_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
