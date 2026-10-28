"""Coverage regressions: identities come from the SDK reference, never from runtime names."""
import gzip
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import measure_coverage as coverage


def digest(symbols):
    return hashlib.sha256(("\n".join(symbols) + "\n").encode()).hexdigest()


def rows(*pairs):
    return [{"name": name, "value": value, "line": line} for line, (name, value) in enumerate(pairs, 1)]


def reference():
    runtime = coverage.constants("include/macosarm/darwin_syscall.hpp", "kDarwinSys")
    syscalls = [("SYS_" + name, str(value)) for name, value in sorted(runtime.items(), key=lambda item: item[1])]
    syscalls += [("SYS_unmodeled_fixture", "9999"), ("SYS_alias_fixture", "9999"), ("SYS_MAXSYSCALL", "10000")]
    return {
        "schema": 1, "sdk_version": "27.0", "xcode": "Xcode 27.0",
        "libraries": [{"install_name": "/usr/lib/libFixture.dylib", "defined_symbols": 2,
                       "symbols_sha256": digest(["_a", "_b"])}],
        "total_defined_symbols": 2,
        "mig_routines": [
            {"subsystem": "mach_host", "name": "host_info", "number": 200, "source": "usr/include/mach/mach_host.h"},
            {"subsystem": "clock", "name": "clock_get_time", "number": 1000, "source": "usr/include/mach/clock.h"}],
        "definitions": {
            "usr/include/sys/syscall.h": {"definitions": rows(*syscalls)},
            "usr/include/mach-o/loader.h": {"definitions": rows(
                ("LC_REQ_DYLD", "0x80000000"), ("LC_SYMTAB", "0x2"), ("LC_SYMSEG", "0x3"), ("LC_SEGMENT_64", "0x19"),
                ("LC_MAIN", "(0x28|LC_REQ_DYLD)"))},
            "usr/include/mach-o/fixup-chains.h": {"definitions": rows(
                ("DYLD_CHAINED_PTR_ARM64E", "1"), ("DYLD_CHAINED_PTR_64", "2"), ("DYLD_CHAINED_PTR_32", "3"),
                ("DYLD_CHAINED_PTR_64_OFFSET", "6"), ("DYLD_CHAINED_PTR_START_NONE", "0xFFFF"))}},
    }


class MeasureCoverageTests(unittest.TestCase):
    def test_runtime_paths_are_classified_against_reference_identities(self):
        metrics = {item["id"]: item for item in coverage.validate_reference(reference())}
        status = {key: {row["name"]: row["status"] for row in item["entries"]} for key, item in metrics.items()}
        self.assertEqual(status["bsd"]["SYS_kDarwinSysBsdthreadCreate"], "rejection only")
        self.assertEqual(status["bsd"]["SYS_kDarwinSysBsdthreadRegister"], "rejection only")
        self.assertEqual(status["bsd"]["SYS_unmodeled_fixture"], "missing")
        self.assertNotIn("SYS_MAXSYSCALL", status["bsd"])
        self.assertEqual(metrics["bsd"]["mapped"], metrics["bsd"]["total"] - 3)
        alias = next(row for row in metrics["bsd"]["entries"] if row["id"] == 9999)
        self.assertEqual(alias["aliases"], ["SYS_alias_fixture"])
        self.assertEqual(status["loader"], {"LC_SYMTAB": "modeled", "LC_SYMSEG": "missing",
                                            "LC_SEGMENT_64": "modeled", "LC_MAIN": "modeled"})
        self.assertEqual(status["fixups"], {"DYLD_CHAINED_PTR_ARM64E": "modeled", "DYLD_CHAINED_PTR_64": "modeled",
                                            "DYLD_CHAINED_PTR_32": "missing", "DYLD_CHAINED_PTR_64_OFFSET": "modeled"})
        self.assertEqual(status["mig"], {"host_info": "modeled", "clock_get_time": "missing"})

    def test_incomplete_or_foreign_references_are_rejected(self):
        def duplicate(ref):
            ref["libraries"].append(dict(ref["libraries"][0]))
            ref["total_defined_symbols"] = 4
        cases = [
            (lambda ref: ref.update(sdk_version="26.4"), "macOS 27"),
            (lambda ref: ref.update(total_defined_symbols=3), "totals"),
            (duplicate, "deduplicated"),
            (lambda ref: ref["libraries"][0].update(symbols_sha256="absent"), "fingerprint"),
            (lambda ref: ref["definitions"]["usr/include/sys/syscall.h"]["definitions"].pop(0), "Runtime syscalls"),
            (lambda ref: ref["mig_routines"].pop(0), "host_info"),
            (lambda ref: ref["definitions"]["usr/include/mach-o/fixup-chains.h"].update(definitions=[]), "empty"),
        ]
        for change, message in cases:
            ref = reference()
            change(ref)
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                coverage.validate_reference(ref)
        with self.assertRaisesRegex(ValueError, "sdk-inventory"):
            coverage.validate_reference({"architecture": "arm64", "sdks": []})

    def test_symbol_manifest_fingerprints_are_verified(self):
        ref = reference()
        raw = (json.dumps([{"install_name": "/usr/lib/libFixture.dylib", "symbols": ["_a", "_b"]}],
                          separators=(",", ":")) + "\n").encode()
        compressed = gzip.compress(raw, mtime=0)
        ref["symbol_manifest"] = {"file": "sdk-symbols.json.gz", "sha256": hashlib.sha256(compressed).hexdigest(),
                                  "uncompressed_sha256": hashlib.sha256(raw).hexdigest()}
        with tempfile.TemporaryDirectory() as folder:
            archive = Path(folder) / "sdk-symbols.json.gz"
            archive.write_bytes(compressed)
            self.assertEqual(coverage.verify_symbol_manifest(ref, Path(folder)), 2)
            ref["libraries"][0]["symbols_sha256"] = digest(["_a"])
            with self.assertRaisesRegex(ValueError, "Per-library"):
                coverage.verify_symbol_manifest(ref, Path(folder))
            archive.write_bytes(gzip.compress(b"[]\n", mtime=0))
            with self.assertRaisesRegex(ValueError, "archive"):
                coverage.verify_symbol_manifest(ref, Path(folder))

    def test_report_records_reference_provenance_and_every_metric(self):
        result = coverage.report(reference())
        self.assertEqual((result["schema"], result["sdk_version"], result["xcode"]), (1, "27.0", "Xcode 27.0"))
        self.assertEqual([item["id"] for item in result["metrics"]], ["bsd", "mig", "loader", "fixups"])


if __name__ == "__main__":
    unittest.main()
