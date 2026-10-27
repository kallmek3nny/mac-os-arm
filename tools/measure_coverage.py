"""Match runtime paths against externally enumerated API and format identities."""
import argparse
import ast
import gzip
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]


def code(path):
    value = (ROOT / path).read_text(encoding="utf-8")
    return re.sub(r"/\*.*?\*/|//[^\n]*", lambda m: "\n" * m.group().count("\n"), value, flags=re.S)


def integer(expression, names=None):
    expression = re.sub(r"\b(0[xX][0-9a-fA-F]+|\d+)(?:ULL|UL|LL|U|L)\b", r"\1", expression.strip())
    def resolve(node):
        if isinstance(node, ast.Constant) and isinstance(node.value, int):
            return node.value
        if isinstance(node, ast.Name) and names and node.id in names:
            return names[node.id]
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
            return resolve(node.left) | resolve(node.right)
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
            return -resolve(node.operand)
        raise ValueError(f"Audit unsupported integer expression: {expression}")
    return resolve(ast.parse(expression, mode="eval").body)


def constants(path, prefix):
    result = {}
    for name, expression in re.findall(r"constexpr\s+std::\w+\s+(" + prefix + r"\w+)\s*=\s*([^;]+);", code(path)):
        result[name] = integer(expression, result)
    return result


def function_body(source, name):
    match = re.search(r"\b" + re.escape(name) + r"\s*\([^)]*\)\s*(?:noexcept\s*)?\{", source)
    if not match:
        raise ValueError(f"Missing reviewed implementation boundary: {name}")
    depth, start = 1, match.end()
    for index in range(start, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start:index]
    raise ValueError(f"Unbalanced implementation boundary: {name}")


def metric(ident, label, entries, mapped, rejected=None, source=None):
    rejected = rejected or set()
    rows = []
    for entry in entries:
        state = "modeled" if entry["id"] in mapped else "missing"
        if entry["id"] in rejected:
            state = "rejection only"
        rows.append({**entry, "status": state})
    return {"id": ident, "label": label, "mapped": sum(row["status"] == "modeled" for row in rows),
            "total": len(rows), "entries": rows, "source": source}


def from_defines(reference, path, prefix, excluded):
    names, by_id = {}, {}
    for row in reference["definitions"][path]["definitions"]:
        if row["name"] in excluded or row["name"].startswith(prefix + "START_"):
            continue
        value = integer(row["value"], names)
        names[row["name"]] = value
        if row["name"] == "LC_REQ_DYLD":
            continue
        entry = by_id.setdefault(value, {"id": value, "name": row["name"], "aliases": [], "line": row["line"]})
        if row["name"] != entry["name"]:
            entry["aliases"].append(row["name"])
    return list(by_id.values())


def measure(reference):
    syscall_source = code("src/darwin_syscall.cpp")
    syscall_constants = constants("include/macosarm/darwin_syscall.hpp", "kDarwinSys")
    dispatch = set(re.findall(r"case (kDarwinSys\w+)\s*:", syscall_source))
    mapped_syscalls = {syscall_constants[name] for name in dispatch}
    # Rejection preflight is not a working API implementation.
    register = function_body(syscall_source, "dispatch_bsdthread_register_preflight")
    create = re.search(r"case kDarwinSysBsdthreadCreate:(.*?)case kDarwinSysThreadSelfid:", syscall_source, re.S)
    if "return reject(kDarwinErrnoEnosys);" not in register or "set_success(" in register or not create or "set_success(" in create.group(1):
        raise ValueError("Re-audit pthread creation/registration before changing coverage classification")
    rejected = {syscall_constants["kDarwinSysBsdthreadCreate"], syscall_constants["kDarwinSysBsdthreadRegister"]}
    syscalls = from_defines(reference, "usr/include/sys/syscall.h", "SYS_", {"SYS_MAXSYSCALL", "SYS_invalid"})
    unknown = mapped_syscalls - {row["id"] for row in syscalls}
    if unknown:
        raise ValueError(f"Runtime syscalls missing from the SDK reference: {sorted(unknown)}")
    result = [metric("bsd", "BSD syscall numbers", syscalls, mapped_syscalls, rejected, "src/darwin_syscall.cpp")]
    mig = [{"id": f"{row['subsystem']}:{row['number']}", "name": row["name"],
            "number": row["number"], "source": row["source"]} for row in reference["mig_routines"]]
    host = [row["id"] for row in mig if row["name"] == "host_info" and row["number"] == 200]
    if len(host) != 1 or "kHostInfoMessageId = 200U" not in code("src/mach_trap.cpp"):
        raise ValueError("Re-audit the host_info MIG mapping against the SDK")
    result.append(metric("mig", "MIG message routines", mig, set(host), source="src/mach_trap.cpp"))
    commands = from_defines(reference, "usr/include/mach-o/loader.h", "LC_", set())
    local = constants("include/macosarm/macho.hpp", "kLc")
    referenced = set(re.findall(r"\bkLc\w+\b", code("src/macho.cpp"))) - {"kLcReqDyld"}
    command_ids = {local[name] for name in referenced}
    result.append(metric("loader", "Mach-O load commands", commands, command_ids, source="src/macho.cpp"))
    formats = from_defines(reference, "usr/include/mach-o/fixup-chains.h", "DYLD_CHAINED_PTR_", set())
    enum = re.search(r"enum class ChainedPointerFormat[^\{]*\{(.*?)\};", code("include/macosarm/dyld_fixups.hpp"), re.S).group(1)
    enum_ids = {name: int(number) for name, number in re.findall(r"(\w+)\s*=\s*(\d+)", enum)}
    implemented = set()
    for file, functions in [("src/dyld_fixup_apply.cpp", ["is_generic_format", "is_arm64e_format"]),
                            ("src/dyld_fixup_pauth.cpp", ["supported_format"])]:
        for name in functions:
            implemented.update(re.findall(r"ChainedPointerFormat::(\w+)", function_body(code(file), name)))
    result.append(metric("fixups", "Chained pointer formats", formats, {enum_ids[name] for name in implemented},
                         source="src/dyld_fixup_apply.cpp"))
    if any(not item["total"] for item in result):
        raise ValueError("An external API inventory is empty; do not display an invented ceiling")
    return result


REFERENCE_KEYS = {"schema", "sdk_version", "xcode", "libraries", "total_defined_symbols", "mig_routines", "definitions"}


def validate_reference(reference):
    missing = REFERENCE_KEYS - set(reference) if isinstance(reference, dict) else REFERENCE_KEYS
    if missing or reference["schema"] != 1:
        raise ValueError("Expected a schema 1 sdk-inventory.json from tools/inventory_sdk.py; "
                         f"missing fields: {sorted(missing)}")
    if not str(reference["sdk_version"]).startswith("27."):
        raise ValueError("The project target requires a macOS 27 reference")
    total = sum(library["defined_symbols"] for library in reference["libraries"])
    if not total or total != reference["total_defined_symbols"]:
        raise ValueError("SDK symbol totals do not match the complete per-library inventory")
    names = [library["install_name"] for library in reference["libraries"]]
    if len(names) != len(set(names)):
        raise ValueError("SDK install-name aliases have not been deduplicated")
    for library in reference["libraries"]:
        if not re.fullmatch(r"[a-f0-9]{64}", library["symbols_sha256"]):
            raise ValueError("Missing canonical symbol-set fingerprint")
    return measure(reference)


def verify_symbol_manifest(reference, folder):
    """Recompute every per-library fingerprint from the archived symbol names."""
    manifest = reference.get("symbol_manifest")
    name = manifest.get("file") if isinstance(manifest, dict) else None
    if not isinstance(name, str) or not name or Path(name).name != name:
        raise ValueError("The reference does not name a local symbol archive")
    compressed = (Path(folder) / name).read_bytes()
    if hashlib.sha256(compressed).hexdigest() != manifest.get("sha256"):
        raise ValueError("Symbol archive does not match its recorded SHA-256")
    raw = gzip.decompress(compressed)
    if hashlib.sha256(raw).hexdigest() != manifest.get("uncompressed_sha256"):
        raise ValueError("Decompressed symbol archive does not match its recorded SHA-256")
    archived = {}
    for entry in json.loads(raw):
        library, symbols = entry["install_name"], entry["symbols"]
        if (library in archived or not all(isinstance(symbol, str) for symbol in symbols)
                or symbols != sorted(set(symbols))):
            raise ValueError(f"Per-library symbols are duplicated or unsorted: {library}")
        archived[library] = symbols
    expected = {library["install_name"]: library for library in reference["libraries"]}
    if set(archived) != set(expected):
        raise ValueError("Per-library symbol archive does not list exactly the inventoried libraries")
    for library, symbols in archived.items():
        digest = hashlib.sha256(("\n".join(symbols) + "\n").encode()).hexdigest()
        if digest != expected[library]["symbols_sha256"] or len(symbols) != expected[library]["defined_symbols"]:
            raise ValueError(f"Per-library symbol fingerprint does not match the archive: {library}")
    return sum(len(symbols) for symbols in archived.values())


def report(reference):
    metrics = validate_reference(reference)
    return {"schema": 1, "sdk_version": reference["sdk_version"], "xcode": reference["xcode"],
            "reference_defined_symbols": reference["total_defined_symbols"], "metrics": metrics}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", type=Path, required=True,
                        help="sdk-inventory.json produced by tools/inventory_sdk.py on a macOS 27 runner")
    parser.add_argument("--output", type=Path, help="Write the classified coverage report as JSON")
    args = parser.parse_args()
    content = args.reference.read_bytes()
    reference = json.loads(content)
    result = report(reference)
    result["reference_sha256"] = hashlib.sha256(content).hexdigest()
    result["verified_archive_symbols"] = verify_symbol_manifest(reference, args.reference.parent)
    for item in result["metrics"]:
        print(f"{item['label']}: {item['mapped']}/{item['total']} reference identities have a modeled runtime path")
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8", newline="\n")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError) as error:
        sys.exit(str(error))
