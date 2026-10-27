#!/usr/bin/env python3
"""Render the dated, evidence-linked status snapshot using only Python's stdlib."""

import argparse
from collections import Counter
import datetime
from html import escape
import json
import math
from pathlib import Path
import re
import subprocess
import sys
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "docs/status.json"
SVG = ROOT / "docs/assets/status.svg"
REPORT = ROOT / "docs/PROGRESS.md"
PASS = "#2e9645"
PENDING = "#35404c"
TEXT = "#eff5fb"
MUTED = "#aab8c8"


def junit_names(path):
    cases = list(ET.parse(path).getroot().iter("testcase"))
    if not cases:
        raise ValueError(f"No test cases in {path}")
    if any(case.find("failure") is not None or case.find("error") is not None
           or case.find("skipped") is not None
           or case.get("status", "run") not in ("run", "passed") for case in cases):
        raise ValueError("Record only a complete passing run; failed/skipped tests found")
    names = [case.attrib["name"] for case in cases]
    if len(names) != len(set(names)):
        raise ValueError("Duplicate test names in JUnit")
    return names


def test_group(name):
    if name.startswith("macho-run-"):
        return "CLI fixtures"
    if "dynarmic" in name:
        return "Translated execution"
    return "Core contracts"


def validate(data):
    datetime.date.fromisoformat(data["verified_date"])
    if not re.fullmatch(r"[0-9a-f]{40}", data["source_revision"]):
        raise ValueError("source_revision must be a full commit SHA")
    names = data["tests"]
    if not names or len(names) != len(set(names)):
        raise ValueError("Record a passing JUnit snapshot with unique test names first")
    if sum(test_group(name) == "Core contracts" for name in names) != data["core_test_count"]:
        raise ValueError("Core count does not match the full JIT test inventory")
    ids = set()
    for group in data["groups"]:
        for item in [group, *group["checks"]]:
            if item["id"] in ids:
                raise ValueError(f"Duplicate identifier: {item['id']}")
            ids.add(item["id"])
        for check in group["checks"]:
            if check["status"] not in ("verified", "pending"):
                raise ValueError(f"Unknown status: {check['id']}")
            if check["status"] == "verified":
                if not check.get("tests") or not set(check["tests"]) <= set(names):
                    raise ValueError(f"Missing passing test evidence: {check['id']}")
                source = (ROOT / check["source"]).resolve()
                if not source.is_relative_to(ROOT) or not source.is_file():
                    raise ValueError(f"Missing or out-of-repo source: {check['id']}")


def summary(data):
    checks = [check for group in data["groups"] for check in group["checks"]]
    done = sum(check["status"] == "verified" for check in checks)
    return done, len(checks), 100 * done / len(checks)


def text(x, y, value, size=14, fill=TEXT, weight=400, extra=""):
    return (f'<text x="{x:.2f}" y="{y:.2f}" font-size="{size}" '
            f'fill="{fill}" font-weight="{weight}" {extra}>{escape(str(value))}</text>')


def rect(x, y, width, height, fill):
    return (f'<rect x="{x:.2f}" y="{y:.2f}" width="{width:.2f}" '
            f'height="{height:.2f}" fill="{fill}"/>')


def tile_group(x, y, width, height, label, cells):
    """One labeled region, one individually identified tile per real item."""
    pieces = [rect(x, y, width, height, "#16212b")]
    passed = sum(cell["verified"] for cell in cells)
    pieces.append(text(x + 8, y + 20, label, 14, weight=600))
    pieces.append(text(x + width - 8, y + 20, f"{passed}/{len(cells)}", 12,
                       MUTED, extra='text-anchor="end"'))
    inner_w, inner_h = width - 8, height - 32
    def grid_score(columns):
        rows = math.ceil(len(cells) / columns)
        aspect = (inner_w / columns) / (inner_h / rows)
        empty = (columns * rows - len(cells)) / len(cells)
        return abs(math.log(aspect)) + 3 * empty

    columns = min(range(1, len(cells) + 1), key=grid_score)
    rows = math.ceil(len(cells) / columns)
    cell_w, cell_h = inner_w / columns, inner_h / rows
    for index, cell in enumerate(cells):
        cx = x + 4 + index % columns * cell_w
        cy = y + 28 + index // columns * cell_h
        pieces.append(f'<g id="{escape(cell["id"])}"><title>{escape(cell["detail"])}</title>')
        pieces.append(rect(cx + 1, cy + 1, cell_w - 2, cell_h - 2,
                           PASS if cell["verified"] else PENDING))
        pieces.append(text(cx + cell_w / 2, cy + cell_h / 2 + 4,
                           cell["label"], 12, "#07140b" if cell["verified"] else TEXT,
                           weight=600, extra='text-anchor="middle"'))
        pieces.append('</g>')
    return "\n".join(pieces)


def render_svg(data):
    done, total, pct = summary(data)
    count = len(data["tests"])
    description = (f"{done} of {total} curated capability checks verified in bounded fixtures "
                   f"({pct:.1f} percent). {count} of {count} registered JIT-enabled CTest "
                   "suites passed. This is not an overall macOS compatibility percentage.")
    pieces = [
        '<svg xmlns="http://www.w3.org/2000/svg" width="1100" height="656" '
        'viewBox="0 0 1100 656" role="img" aria-labelledby="title description">',
        '<title id="title">mac-os-arm status</title>',
        f'<desc id="description">{escape(description)}</desc>',
        '<g font-family="-apple-system, BlinkMacSystemFont, Segoe UI, sans-serif">',
        rect(0, 0, 1100, 656, "#0c1118"),
        text(28, 44, "mac-os-arm", 28, weight=650),
        text(197, 44, "/ Status", 28, MUTED),
        text(1072, 40, f"VERIFIED  {data['verified_date']}", 12, MUTED,
             extra='text-anchor="end" letter-spacing="1.2"'),
        text(28, 70, "ARM64 / ARM64e userspace runtime  |  through phase 82", 14, MUTED),
        rect(28, 86, 1044, 1, "#2b3643"),
        rect(28, 104, 164, 30, "#35404c"),
        text(40, 124, "Capability checklist", 14, weight=600),
        rect(192, 104, 76, 30, "#b78914"),
        text(230, 124, f"{pct:.1f}%", 14, "#10150b", weight=650, extra='text-anchor="middle"'),
        rect(280, 104, 106, 30, "#35404c"),
        text(292, 124, "Test suites", 14, weight=600),
        rect(386, 104, 82, 30, PASS),
        text(427, 124, "100.0%", 14, "#07140b", weight=650, extra='text-anchor="middle"'),
        text(1072, 124, "EXPERIMENTAL / FIXTURE-BASED EVIDENCE", 12, MUTED,
             extra='text-anchor="end" letter-spacing="0.6"'),
        text(28, 171, "Scoped capabilities", 18, weight=600),
        text(28, 194, f"{done} / {total} verified in fixtures  |  {total - done} pending", 14, MUTED),
        text(568, 171, "Verification suites", 18, weight=600),
        text(568, 194, f"{count} / {count} passed  |  full JIT-enabled test inventory", 14, MUTED),
    ]
    # A slice-and-dice treemap: each region's area follows its checklist count.
    y = 208.0
    for offset in range(0, len(data["groups"]), 2):
        row = data["groups"][offset:offset + 2]
        weight = sum(len(group["checks"]) for group in row)
        height = 340 * weight / total
        x = 28.0
        for group in row:
            width = 504 * len(group["checks"]) / weight
            cells = [{"id": f"check-{check['id']}", "label": check["id"],
                      "verified": check["status"] == "verified",
                      "detail": f"{check['id']}: {check['label']} [{check['status']}]"}
                     for check in group["checks"]]
            pieces.append(tile_group(x, y, width - 3, height - 3, group["short"], cells))
            x += width
        y += height
    groups = [("Core contracts", "Core contracts"),
              ("Translated execution", "JIT")]
    counts = Counter(test_group(name) for name in data["tests"])
    top_count = sum(counts[key] for key, _ in groups)
    top_height = 340 * top_count / count
    x = 568.0
    for key, label in groups:
        width = 504 * counts[key] / top_count
        cells = [{"id": f"suite-{index + 1}", "label": f"{index + 1:02d}",
                  "verified": True, "detail": f"PASS: {name}"}
                 for index, name in enumerate(data["tests"]) if test_group(name) == key]
        pieces.append(tile_group(x, 208, width - 3, top_height - 3, label, cells))
        x += width
    cells = [{"id": f"suite-{index + 1}", "label": f"{index + 1:02d}",
              "verified": True, "detail": f"PASS: {name}"}
             for index, name in enumerate(data["tests"]) if test_group(name) == "CLI fixtures"]
    pieces.append(tile_group(568, 208 + top_height, 501, 340 - top_height - 3,
                             "CLI fixtures", cells))
    pieces.extend([
        rect(28, 572, 12, 12, PASS),
        text(48, 583, "Verified fixture / model", 13, MUTED),
        rect(246, 572, 12, 12, PENDING),
        text(266, 583, "Pending demonstration", 13, MUTED),
        text(568, 583, "One tile = one listed check or one registered CTest suite", 13, MUTED),
        text(28, 615, "Checklist coverage, not overall macOS compatibility. Stock apps and graphics remain undemonstrated.", 14),
        text(28, 639, f"Source {data['source_revision'][:7]}  |  {data['core_test_count']} core suites; {count} with JIT  |  Evidence and definitions: docs/PROGRESS.md", 12, MUTED),
        '</g></svg>',
    ])
    return "\n".join(pieces) + "\n"


def render_report(data):
    done, total, pct = summary(data)
    count = len(data["tests"])
    lines = [
        "# Progress and evidence", "",
        "<!-- Generated by tools/render_status.py from docs/status.json. Edit the data, then regenerate. -->", "",
        "![mac-os-arm capability and verification status](assets/status.svg)", "",
        f"Snapshot: **{data['verified_date']}**, runtime source "
        f"[`{data['source_revision'][:7]}`](https://github.com/kallmek3nny/mac-os-arm/commit/{data['source_revision']}). "
        f"Local verification: {data['platform']}. The status-only change does not alter runtime source.", "",
        f"**{done}/{total} scoped capability checks ({pct:.1f}%)** have fixture/model evidence; "
        f"**{total - done} remain pending**. **{count}/{count} registered CTest suites passed** in the full "
        f"JIT-enabled build, which includes the {data['core_test_count']} core suites. The separate core build "
        f"also passed {data['core_test_count']}/{data['core_test_count']}.", "",
        "## What the percentage means", "",
        "The denominator is the explicit, curated checklist below. Every check has equal weight. "
        "Green means the narrowly worded behavior is implemented and exercised by the linked fixture/model tests. "
        "It does not mark a subsystem complete. Gray means the observable demonstration has not been recorded.", "",
        "**This is not a percentage of macOS, Apple APIs, ARM instructions, engineering effort, or real-app compatibility.** "
        "There is no complete inventory for those. Checks differ in difficulty, may share a test suite, and may be revised "
        "as the roadmap changes. A suite may contain many assertions; each suite is counted once on the right-hand map. "
        "The graphics work in the separate mac-os repository does not count toward this runtime.", "",
        "This snapshot adds a progress inventory; its pending entries are explicit future acceptance targets, not a claim "
        "that a complete macOS compatibility plan exists. See [runtime status and limitations](STATUS.md) for context.", "",
        f"The [source revision's GitHub CI]({data['ci_url']}) passed Ubuntu/macOS core jobs and the then-filtered Linux JIT job. "
        "The workflow now runs the entire JIT-enabled CTest inventory, including CLI fixtures. "
        "The green test map records the dated full local run above; it is not a live GitHub CI badge.", "",
        "## Capability checklist", "",
    ]
    for group in data["groups"]:
        verified = sum(check["status"] == "verified" for check in group["checks"])
        lines.extend([f"### {group['label']} ({verified}/{len(group['checks'])})", "",
                      "| ID | Scoped acceptance check | Evidence |", "| --- | --- | --- |"])
        for check in group["checks"]:
            if check["status"] == "verified":
                evidence = f"[Source / fixture](../{check['source']}); " + ", ".join(
                    f"`{name}`" for name in check["tests"])
                state = "Verified"
            else:
                evidence = "Pending; no passing demonstration recorded"
                state = "Pending"
            lines.append(f"| {check['id']} | **{state}**: {check['label']} | {evidence} |")
        lines.append("")
    lines.extend(["## Passing test inventory", "",
                  "IDs match the numbered tiles in the verification map.", "",
                  "| Tile | Registered CTest suite | Group | Result |", "| --- | --- | --- | --- |"])
    for index, name in enumerate(data["tests"], 1):
        lines.append(f"| {index:02d} | `{name}` | {test_group(name)} | Pass |")
    lines.extend(["", "## Updating the snapshot", "",
                  "Edit the explicit capability checks in [status.json](status.json), preserving their IDs. "
                  "Add source and passing test evidence before marking a check verified. "
                  "Do not infer broad support from a syscall name or from a passing synthetic fixture.", "",
                  "After building both configurations, record complete fresh runs:", "", "```sh",
                  "ctest --test-dir build -C Release --output-on-failure --timeout 30 --output-junit core-results.xml",
                  "ctest --test-dir build-jit -C Release --output-on-failure --timeout 30 --output-junit jit-results.xml",
                  "python tools/render_status.py --record-junit build-jit/jit-results.xml --core-junit build/core-results.xml --ctest-build build-jit --date YYYY-MM-DD --source-ref SOURCE_SHA",
                  "python tools/render_status.py --check --ctest-build build-jit", "```", "",
                  "`SOURCE_SHA` is the tested runtime commit. Recording rejects failed, skipped, missing, or mismatched suites. "
                  "The generator requires Python 3.10 or newer, uses only its standard library, and deterministically produces "
                  "[the SVG](assets/status.svg) and this report. CI checks generated files and the registered test inventory. "
                  "Source links document the manual capability assessment; passing a suite alone cannot certify a new capability.", ""])
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Reject stale generated files without writing")
    parser.add_argument("--ctest-build", type=Path, help="Compare snapshot names with a configured CTest build")
    parser.add_argument("--record-junit", type=Path, help="Record a complete passing JIT-enabled run")
    parser.add_argument("--core-junit", type=Path, help="Separate complete passing core run")
    parser.add_argument("--date", help="Verification date in YYYY-MM-DD")
    parser.add_argument("--source-ref", help="Tested runtime source commit or ref")
    args = parser.parse_args()
    data = json.loads(DATA.read_text(encoding="utf-8"))
    if args.record_junit:
        if args.check or not all((args.core_junit, args.ctest_build, args.date, args.source_ref)):
            parser.error("Recording requires --core-junit, --ctest-build, --date and --source-ref, without --check")
        data["tests"] = junit_names(args.record_junit)
        core = junit_names(args.core_junit)
        if set(core) != {name for name in data["tests"] if test_group(name) == "Core contracts"}:
            raise ValueError("Core run does not match the core subset of the JIT-enabled run")
        data["core_test_count"] = len(core)
        data["verified_date"] = args.date
        data["source_revision"] = subprocess.check_output(
            ["git", "rev-parse", "--verify", args.source_ref + "^{commit}"], cwd=ROOT, text=True).strip()
    validate(data)
    if args.ctest_build:
        manifest = json.loads(subprocess.check_output(
            ["ctest", "--test-dir", str(args.ctest_build), "--show-only=json-v1"], text=True))
        current = {item["name"] for item in manifest["tests"]}
        recorded = set(data["tests"])
        if current != recorded:
            raise ValueError(f"CTest inventory changed: added={sorted(current-recorded)}, removed={sorted(recorded-current)}")
    outputs = {SVG: render_svg(data), REPORT: render_report(data)}
    if args.check:
        stale = [str(path.relative_to(ROOT)) for path, value in outputs.items()
                 if not path.is_file() or path.read_text(encoding="utf-8") != value]
        if stale:
            raise ValueError("Regenerate stale status outputs: " + ", ".join(stale))
        print("Status SVG, report, evidence paths and test inventory are consistent")
    else:
        if args.record_junit:
            DATA.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
        for path, value in outputs.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(value, encoding="utf-8", newline="\n")
        print(f"Rendered {SVG.relative_to(ROOT)} and {REPORT.relative_to(ROOT)}")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, subprocess.CalledProcessError, ET.ParseError) as error:
        sys.exit(str(error))
