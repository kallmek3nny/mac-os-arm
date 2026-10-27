"""Reference-counting regressions: architecture, aliases, symbols and malformed TBDs."""
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from inventory_sdk import collect_libraries, tapi_yaml, TbdLoader
import yaml


class SdkInventoryTests(unittest.TestCase):
    def test_tapi_empty_items_preserve_quoted_symbol_contents_and_names(self):
        data = yaml.load(tapi_yaml("--- !tapi-tbd\nclients: [ first,, second,, ]\n"
                                  "symbols: [ 'comma,,symbol', true, 'escaped''quote' ]\n"), Loader=TbdLoader)
        self.assertEqual(data["clients"], ["first", "second"])
        self.assertEqual(data["symbols"], ["comma,,symbol", "true", "escaped'quote"])

    def test_arm_slices_aliases_and_objc_expand_into_one_named_export_set(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "first.tbd").write_text("""--- !tapi-tbd
tbd-version: 4
targets: [ arm64-macos, arm64e-macos, x86_64-macos, arm64-ios-macabi ]
install-name: /usr/lib/libFixture.dylib
exports:
  - targets: [ arm64-macos, arm64e-macos ]
    symbols: [ _shared, '$ld$hide$os1.0$_directive' ]
    objc-classes: [ Fixture ]
    objc-eh-types: [ Fixture ]
    objc-ivars: [ Fixture.value ]
  - targets: [ x86_64-macos ]
    symbols: [ _intel_only ]
  - targets: [ arm64-ios-macabi ]
    symbols: [ _catalyst_only ]
reexported-libraries:
  - targets: [ arm64-macos ]
    libraries: [ /usr/lib/libOther.dylib ]
...
""")
            (root / "second.tbd").write_text("""--- !tapi-tbd
tbd-version: 4
targets: [ arm64-macos ]
install-name: /usr/lib/libFixture.dylib
exports:
  - targets: [ arm64-macos ]
    weak-symbols: [ _shared, _weak ]
    thread-local-symbols: [ _tls ]
...
""")
            records, full, count, _ = collect_libraries(root)
            self.assertEqual(count, 2)
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["defined_symbols"], 7)
            self.assertEqual(set(full[0]["symbols"]), {
                "_shared", "_weak", "_tls", "_OBJC_CLASS_$_Fixture", "_OBJC_METACLASS_$_Fixture",
                "_OBJC_EHTYPE_$_Fixture", "_OBJC_IVAR_$_Fixture.value"})

    def test_new_formats_and_unknown_export_fields_fail_instead_of_undercounting(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            stub = root / "bad.tbd"
            stub.write_text("--- !tapi-tbd\ntbd-version: 5\n")
            with self.assertRaisesRegex(ValueError, "Audit new TBD"):
                collect_libraries(root)
            stub.write_text("--- !tapi-tbd\ntbd-version: 4\ntargets: [ arm64-macos ]\n"
                            "install-name: /fixture\nexports:\n  - targets: [ arm64-macos ]\n"
                            "    future-symbol-field: [ _new ]\n")
            with self.assertRaisesRegex(ValueError, "Uncounted export keys"):
                collect_libraries(root)

    def test_symlinked_sdk_roots_record_paths_relative_to_the_resolved_root(self):
        """macOS reaches temporary and SDK folders through links such as /var -> /private/var."""
        with tempfile.TemporaryDirectory() as folder:
            real = Path(folder) / "real"
            (real / "usr/lib").mkdir(parents=True)
            (real / "usr/lib/libLinked.tbd").write_text(
                "--- !tapi-tbd\ntbd-version: 4\ntargets: [ arm64-macos ]\n"
                "install-name: /usr/lib/libLinked.dylib\nexports:\n"
                "  - targets: [ arm64-macos ]\n    symbols: [ _linked ]\n...\n")
            link = Path(folder) / "link"
            try:
                link.symlink_to(real, target_is_directory=True)
            except (OSError, NotImplementedError) as error:
                self.skipTest(f"directory symlinks are unavailable: {error}")
            records, full, count, _ = collect_libraries(link)
            self.assertEqual(count, 1)
            self.assertEqual(records[0]["sources"][0]["path"], str(Path("usr/lib/libLinked.tbd")))
            self.assertEqual(full, [{"install_name": "/usr/lib/libLinked.dylib", "symbols": ["_linked"]}])


if __name__ == "__main__":
    unittest.main()
