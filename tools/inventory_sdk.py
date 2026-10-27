#!/usr/bin/env python3
"""Enumerate real ARM64/ARM64e macOS SDK interfaces with a fixed SDK major."""
import argparse
from collections import Counter
import gzip
import hashlib
import json
from pathlib import Path
import re
import subprocess
import yaml


class TbdLoader(getattr(yaml, "CBaseLoader", yaml.BaseLoader)):
    pass


TbdLoader.add_constructor("!tapi-tbd", lambda loader, node: loader.construct_mapping(node))
TARGETS = {"arm64-macos", "arm64e-macos"}
SYMBOL_KEYS = {"symbols", "weak-symbols", "thread-local-symbols", "objc-classes", "objc-eh-types", "objc-ivars"}


def command(*args):
    return subprocess.check_output(args, text=True).strip()


def source_record(path, sdk):
    return {"path": str(path.relative_to(sdk)), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def selected(block):
    return bool(TARGETS.intersection(block.get("targets", [])))


def expanded(key, name):
    if key == "objc-classes":
        return ["_OBJC_CLASS_$_" + name, "_OBJC_METACLASS_$_" + name]
    if key == "objc-eh-types":
        return ["_OBJC_EHTYPE_$_" + name]
    if key == "objc-ivars":
        return ["_OBJC_IVAR_$_" + name]
    return [name]


def tapi_yaml(content):
    """LLVM TAPI permits empty flow-list items which strict YAML rejects."""
    result, quote, depth, previous, index = [], None, 0, "", 0
    while index < len(content):
        char = content[index]
        if quote:
            result.append(char)
            if quote == '"' and char == "\\" and index + 1 < len(content):
                index += 1
                result.append(content[index])
            elif char == quote:
                if quote == "'" and index + 1 < len(content) and content[index + 1] == "'":
                    index += 1
                    result.append(content[index])
                else:
                    quote = None
                    previous = "scalar"
        elif char in "\"'":
            quote = char
            result.append(char)
        elif char == "," and depth and previous in {"[", ","}:
            pass
        else:
            result.append(char)
            if char == "[":
                depth += 1
            elif char == "]":
                depth -= 1
            if not char.isspace():
                previous = char
        index += 1
    return "".join(result)


def collect_libraries(sdk):
    libraries = {}
    files = sorted({path.resolve() for path in sdk.rglob("*.tbd") if path.is_file()})
    key_counts = Counter()
    for path in files:
        try:
            documents = list(yaml.load_all(tapi_yaml(path.read_text()), Loader=TbdLoader))
        except yaml.YAMLError as error:
            raise ValueError(f"Cannot parse complete SDK inventory: {path}: {error}") from error
        for doc in documents:
            if not isinstance(doc, dict) or str(doc.get("tbd-version")) != "4":
                raise ValueError(f"Audit new TBD format before counting: {path}")
            if not selected(doc):
                continue
            lib = libraries.setdefault(doc["install-name"], {"symbols": set(), "sources": [], "reexported_libraries": set()})
            lib["sources"].append(source_record(path, sdk))
            for block in doc.get("exports", []):
                if not selected(block):
                    continue
                unexpected = set(block) - SYMBOL_KEYS - {"targets"}
                if unexpected:
                    raise ValueError(f"Uncounted export keys {unexpected}: {path}")
                for key in SYMBOL_KEYS:
                    values = block.get(key, [])
                    key_counts[key] += len(values)
                    for name in values:
                        lib["symbols"].update(symbol for symbol in expanded(key, name)
                                              if not symbol.startswith(("$ld$", "_$ld$")))
            for block in doc.get("reexported-libraries", []):
                if selected(block):
                    lib["reexported_libraries"].update(block.get("libraries", []))
    records, full = [], []
    for install_name, lib in sorted(libraries.items()):
        symbols = sorted(lib["symbols"])
        digest = hashlib.sha256(("\n".join(symbols) + "\n").encode()).hexdigest()
        records.append({"install_name": install_name, "defined_symbols": len(symbols), "symbols_sha256": digest,
                        "sources": lib["sources"], "reexported_libraries": sorted(lib["reexported_libraries"])})
        full.append({"install_name": install_name, "symbols": symbols})
    return records, full, len(files), dict(key_counts)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--sdk", type=Path)
    parser.add_argument("--sdk-major", type=int, default=27)
    args = parser.parse_args()
    sdk = (args.sdk or Path(command("xcrun", "--sdk", "macosx", "--show-sdk-path"))).resolve()
    settings = json.loads((sdk / "SDKSettings.json").read_text())
    version = settings["Version"]
    if int(version.split(".")[0]) != args.sdk_major:
        raise ValueError(f"Expected macOS {args.sdk_major} SDK, found {version}")
    print(json.dumps({"sdk_version": version, "xcode": command("xcodebuild", "-version"),
                      "host": command("sw_vers")}), flush=True)
    records, full, file_count, key_counts = collect_libraries(sdk)
    result = {"schema": 1, "sdk_version": version, "sdk_settings": settings,
              "host": command("sw_vers"), "host_architecture": command("uname", "-m"),
              "xcode": command("xcodebuild", "-version"), "targets": sorted(TARGETS),
              "tbd_files_scanned": file_count, "libraries": records,
              "total_defined_symbols": sum(row["defined_symbols"] for row in records),
              "raw_export_key_counts": dict(key_counts)}
    mig = {}
    headers = list((sdk / "usr/include").rglob("*.h"))
    for path in headers:
        content = path.read_text(errors="replace").replace("\\\n", " ")
        for match in re.finditer(r"#define\s+subsystem_to_name_map_(\w+)([^\n]*)", content):
            for name, number in re.findall(r'\{\s*"(\w+)"\s*,\s*(\d+)\s*\}', match.group(2)):
                ident = f"{match.group(1)}:{number}"
                entry = {"subsystem": match.group(1), "name": name, "number": int(number), "source": str(path.relative_to(sdk))}
                if ident in mig and mig[ident]["name"] != name:
                    raise ValueError(f"Conflicting MIG names for {ident}")
                mig[ident] = entry
    result["mig_routines"] = [mig[key] for key in sorted(mig)]
    facts = {}
    for relative, pattern in [
        ("usr/include/sys/syscall.h", r"^#\s*define\s+(SYS_\w+)\s+([^\n/]+)"),
        ("usr/include/mach-o/loader.h", r"^#\s*define\s+(LC_\w+)\s+([^\n/]+)"),
        ("usr/include/mach-o/fixup-chains.h", r"^\s*(DYLD_CHAINED_PTR_\w+)\s*=\s*(\d+)"),
    ]:
        path = sdk / relative
        content = path.read_text()
        facts[relative] = {**source_record(path, sdk), "definitions": [
            {"name": match.group(1), "value": match.group(2).strip(), "line": content.count("\n", 0, match.start()) + 1}
            for match in re.finditer(pattern, content, re.M)]}
    result["definitions"] = facts
    result["trap_headers"] = []
    for path in headers:
        if path.name in {"mach_traps.h", "mach_syscalls.h", "syscall_sw.h"}:
            stripped = re.sub(r"/\*.*?\*/", "", path.read_text(), flags=re.S)
            candidates = re.findall(r"\b([A-Za-z_]\w*)\s*\([^;{}]*\)\s*;", stripped)
            result["trap_headers"].append({**source_record(path, sdk), "declaration_candidates": candidates,
                "kernel_trap_lines": [line.strip() for line in stripped.splitlines() if "kernel_trap(" in line]})
    args.output.parent.mkdir(parents=True, exist_ok=True)
    full_bytes = (json.dumps(full, separators=(",", ":")) + "\n").encode()
    compressed = gzip.compress(full_bytes, mtime=0)
    args.output.with_name("sdk-symbols.json.gz").write_bytes(compressed)
    result["symbol_manifest"] = {"file": "sdk-symbols.json.gz", "sha256": hashlib.sha256(compressed).hexdigest(),
                                 "uncompressed_sha256": hashlib.sha256(full_bytes).hexdigest()}
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"sdk_version": version, "xcode": result["xcode"], "tbd_files": file_count,
                      "libraries": len(records), "defined_symbols": result["total_defined_symbols"],
                      "mig_routines": len(mig), "definitions": {key: len(value["definitions"]) for key, value in facts.items()},
                      "trap_headers": result["trap_headers"], "symbol_manifest": result["symbol_manifest"]}, indent=2))


if __name__ == "__main__":
    main()
