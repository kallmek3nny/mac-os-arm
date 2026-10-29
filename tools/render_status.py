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
PASS = "#65dfad"
PENDING = "#91a1b8"
TEXT = "#edf3fc"
MUTED = "#9eafc6"


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


def rect(x, y, width, height, fill, radius=0, stroke="none"):
    return (f'<rect x="{x:.2f}" y="{y:.2f}" width="{width:.2f}" '
            f'height="{height:.2f}" rx="{radius}" fill="{fill}" stroke="{stroke}"/>')


def tile_group(x, y, width, height, label, cells, columns):
    """Keep headings and individual evidence tiles readable in a consistent card."""
    pieces = [rect(x, y, width, height, "#101b2a", 12, "#243249")]
    passed = sum(cell["verified"] for cell in cells)
    pieces.append(text(x + 14, y + 29, label, 17, weight=600))
    complete = passed == len(cells)
    pieces.append(rect(x + width - 66, y + 12, 52, 24,
                       "#16352f" if complete else "#1d2a3e", 6))
    pieces.append(text(x + width - 40, y + 29, f"{passed}/{len(cells)}", 13,
                       PASS if complete else MUTED, weight=600, extra='text-anchor="middle"'))
    rows = math.ceil(len(cells) / columns)
    gap = 6
    cell_w = (width - 28 - gap * (columns - 1)) / columns
    cell_h = (height - 62 - gap * (rows - 1)) / rows
    for index, cell in enumerate(cells):
        cx = x + 14 + index % columns * (cell_w + gap)
        cy = y + 48 + index // columns * (cell_h + gap)
        pieces.append(f'<g id="{escape(cell["id"])}"><title>{escape(cell["detail"])}</title>')
        pieces.append(rect(cx, cy, cell_w, cell_h,
                           "#153b32" if cell["verified"] else "#1a273a", 5,
                           "#2b6853" if cell["verified"] else "#35445c"))
        pieces.append(text(cx + cell_w / 2, cy + cell_h / 2 + 5,
                           cell["label"], 14, PASS if cell["verified"] else PENDING,
                           weight=600, extra='text-anchor="middle" font-family="Consolas, monospace"'))
        pieces.append('</g>')
    return "\n".join(pieces)


def render_svg(data):
    done, total, pct = summary(data)
    count = len(data["tests"])
    description = (f"{done} of {total} curated capability checks verified in bounded fixtures "
                   f"({pct:.1f} percent). {count} of {count} registered JIT-enabled CTest "
                   "suites passed. This is not an overall macOS compatibility percentage.")
    counts = Counter(test_group(name) for name in data["tests"])
    pieces = [
        '<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="1112" '
        'viewBox="0 0 1200 1112" role="img" aria-labelledby="title description">',
        '<title id="title">mac-os-arm status</title>',
        f'<desc id="description">{escape(description)}</desc>',
        '<defs><linearGradient id="background" x2="0.8" y2="1">'
        '<stop stop-color="#111e31"/><stop offset="1" stop-color="#0b121e"/>'
        '</linearGradient></defs>',
        '<g font-family="-apple-system, BlinkMacSystemFont, Segoe UI, sans-serif">',
        rect(0.5, 0.5, 1199, 1111, "url(#background)", 20, "#29374d"),
        text(44, 40, "RUNTIME / PROJECT STATUS", 12, MUTED, weight=600,
             extra='letter-spacing="2"'),
        rect(44, 63, 48, 48, "#17382f", 12, "#2b6853"),
        text(68, 94, ">_", 22, PASS, weight=600,
             extra='text-anchor="middle" font-family="Consolas, monospace"'),
        text(110, 98, "mac-os-arm", 38, weight=700, extra='letter-spacing="-1"'),
        rect(920, 24, 236, 30, "#302b23", 15, "#514435"),
        text(1038, 44, "EXPERIMENTAL RUNTIME", 12, "#e6be7b", weight=600,
             extra='text-anchor="middle" letter-spacing="0.8"'),
        text(1156, 97, f"VERIFIED  {data['verified_date']}", 13, MUTED,
             extra='text-anchor="end" letter-spacing="1.2"'),
        text(44, 138, "ARM64 / ARM64e userspace runtime for x86_64 hosts", 17, MUTED),
        rect(44, 166, 544, 156, "#10252a", 14, "#275044"),
        text(68, 196, "CAPABILITY CHECKLIST", 13, PASS, weight=600, extra='letter-spacing="1.2"'),
        text(564, 196, f"{total - done} PENDING", 12, MUTED, extra='text-anchor="end"'),
        text(68, 274, f"{pct:g}%", 64, weight=700, extra='letter-spacing="-2"'),
        text(246, 235, f"{done} of {total} checks verified", 21, weight=600),
        text(246, 262, "Bounded fixture / model evidence", 15, MUTED),
        rect(68, 299, 496, 7, "#263b43", 3.5),
        rect(68, 299, 496 * done / total, 7, PASS, 3.5),
        rect(612, 166, 544, 156, "#142135", 14, "#2b3f5b"),
        text(636, 196, "TEST SUITES", 13, "#9bbcff", weight=600, extra='letter-spacing="1.2"'),
        text(1132, 196, "FULL JIT BUILD", 12, MUTED, extra='text-anchor="end"'),
        text(636, 274, f"{count}/{count}", 60, weight=700, extra='letter-spacing="-2"'),
        text(840, 235, "All suites passed", 21, weight=600),
        text(840, 262, f"{counts['Core contracts']} core / {counts['Translated execution']} JIT / {counts['CLI fixtures']} CLI", 15, MUTED),
        rect(636, 299, 496, 7, PASS, 3.5),
        text(44, 368, "Capability map", 23, weight=600),
        text(44, 392, f"{total} explicit checks, grouped by subsystem", 15, MUTED),
        text(660, 368, "Verification suites", 23, weight=600),
        text(660, 392, "One numbered tile per registered CTest suite", 15, MUTED),
    ]
    # Equal-size cards keep pending application and graphics checks visible too.
    for index, group in enumerate(data["groups"]):
        cells = [{"id": f"check-{check['id']}", "label": check["id"],
                  "verified": check["status"] == "verified",
                  "detail": f"{check['id']}: {check['label']} [{check['status']}]"}
                 for check in group["checks"]]
        columns = len(cells) if len(cells) <= 6 else math.ceil(len(cells) / 2)
        pieces.append(tile_group(44 + index % 2 * 304, 412 + index // 2 * 128,
                                 288, 114, group["short"], cells, columns))
    for key, label, y, height, columns in [
        ("Core contracts", "Core contracts", 412, 182, 7),
        ("Translated execution", "Translated execution / JIT", 608, 114, 5),
        ("CLI fixtures", "CLI fixtures", 736, 174, 8),
    ]:
        cells = [{"id": f"suite-{index + 1}", "label": f"{index + 1:02d}",
                  "verified": True, "detail": f"PASS: {name}"}
                 for index, name in enumerate(data["tests"]) if test_group(name) == key]
        pieces.append(tile_group(660, y, 496, height, label, cells, columns))
    pieces.extend([
        rect(44, 940, 12, 12, PASS, 3),
        text(66, 952, "Verified fixture / model", 15, MUTED),
        rect(314, 940, 12, 12, PENDING, 3),
        text(336, 952, "Pending demonstration", 15, MUTED),
        text(1156, 952, "Tile IDs match the linked evidence report", 14, MUTED,
             extra='text-anchor="end"'),
        rect(44, 976, 1112, 76, "#172130", 10, "#303e51"),
        text(64, 1005, "Stock apps and graphics remain undemonstrated.", 17, weight=600),
        text(64, 1031, "Percentages refer to the curated checklist; overall macOS compatibility remains unmeasured.", 15, MUTED),
        text(44, 1085, f"TESTED SOURCE  {data['source_revision'][:7]}", 12, MUTED,
             extra='letter-spacing="1"'),
        text(1156, 1085, "Definitions and evidence: docs/PROGRESS.md", 13, MUTED,
             extra='text-anchor="end"'),
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
        "It does not mark a subsystem complete. Slate means the observable demonstration has not been recorded. "
        "Each capability has one tile; card area does not represent its scope or engineering effort.", "",
        "**This is not a percentage of macOS, Apple APIs, ARM instructions, engineering effort, or real-app compatibility.** "
        "The separately collected Apple SDK/XNU reference inventory is not this checklist's denominator. "
        "Checks differ in difficulty, may share a test suite, and may be revised "
        "as the roadmap changes. A suite may contain many assertions; each suite is counted once on the right-hand map. "
        "The graphics work in the separate mac-os repository does not count toward this runtime.", "",
        "This snapshot adds a progress inventory; its pending entries are explicit future acceptance targets, not a claim "
        "that a complete macOS compatibility plan exists. See [runtime status and limitations](STATUS.md) for context.", "",
        f"The [tested runtime revision's GitHub CI]({data['ci_url']}) covers Ubuntu/macOS core jobs and the complete Linux JIT job, "
        "including CLI fixtures. "
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
