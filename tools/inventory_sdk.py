#!/usr/bin/env python3
"""Discover installed Apple SDKs before selecting a versioned ABI reference."""
import argparse
from collections import Counter
import json
from pathlib import Path
import subprocess


def command(*args):
    return subprocess.check_output(args, text=True).strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    default = Path(command("xcrun", "--sdk", "macosx", "--show-sdk-path")).resolve()
    sdks = {default}
    sdks.update(path.resolve() for path in Path("/Applications").glob(
        "Xcode*.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX*.sdk"))
    result = {"host": command("sw_vers"), "architecture": command("uname", "-m"),
              "xcode": command("xcodebuild", "-version"), "default_sdk": str(default), "sdks": []}
    for sdk in sorted(sdks):
        settings = json.loads((sdk / "SDKSettings.json").read_text())
        files = sorted({path.resolve() for path in sdk.rglob("*.tbd") if path.is_file()})
        versions = Counter()
        samples = {}
        for path in files:
            content = path.read_text()
            first = content.lstrip().splitlines()[0]
            version = "json" if first.startswith("{") else first
            versions[version] += 1
            samples.setdefault(version, {"path": str(path.relative_to(sdk)), "prefix": content[:7000]})
        result["sdks"].append({"path": str(sdk), "settings": settings,
                               "tbd_files": len(files), "formats": dict(versions), "samples": samples})
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"xcode": result["xcode"], "host": result["host"],
                      "sdks": [{"path": sdk["path"], "version": sdk["settings"].get("Version"),
                                "tbd_files": sdk["tbd_files"], "formats": sdk["formats"]}
                               for sdk in result["sdks"]]}, indent=2))


if __name__ == "__main__":
    main()
