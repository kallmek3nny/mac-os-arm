# mac-os-arm

Experimental ARM64-to-x86_64 macOS userspace rehosting work for post-Intel macOS software.

This repository is intentionally separate from `kallmek3nny/mac-os`. The GPU/driver project can evolve independently; this repository owns the ARM64 Mach-O loader, translation runtime, Darwin/Mach bridge, and later architecture-neutral graphics handoff.

## Current state

The implementation has progressed through Phase 46. It includes ARM64 Mach-O parsing/loading, protected guest memory with cross-fragment access, dyld dependency graphs and supported chained fixups, initializer execution, process startup, selected Darwin syscalls, modeled Mach messages, and an optional Dynarmic ARM64 JIT.

This is an experimental userspace runtime, not a macOS kernel or a general application runner. Tests exercise bounded fixtures; they do not establish stock libSystem, Foundation, AppKit, or arbitrary application compatibility. Thread creation is unavailable. Pointer authentication uses an emulator-defined software policy, not Apple hardware PAC.

See [the architecture and handoff](docs/STATUS.md) for code ownership, limitations, verification evidence, and the recommended next milestone.

## build

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release --parallel 2
ctest --test-dir build -C Release --output-on-failure --timeout 30
```

Requires CMake 3.20+ and a C++20 compiler. The default build does not enable or fetch Dynarmic.

The only non-test executable is `macho-inspect <arm64-mach-o>` (under `build/`, or `build/Release/` with a multi-configuration generator). It prints metadata; it does not execute the file. Library callers execute images through `run_macho_session` in `include/macosarm/session.hpp`, supplying a backend and host services.

## Optional JIT build

Linux x86_64 is the JIT CI configuration. Install Boost development headers (Ubuntu: `sudo apt-get install libboost-dev`), then:

```sh
cmake -S . -B build-jit -DCMAKE_BUILD_TYPE=Release -DMACOSARM_ENABLE_DYNARMIC=ON
cmake --build build-jit --config Release --parallel 2
ctest --test-dir build-jit -C Release --output-on-failure --timeout 30
```

CMake fetches Dynarmic and its submodules at the commit pinned in `CMakeLists.txt`, requiring network access. Core CI runs on Linux and macOS; a separate Linux job exercises translated fixtures. A passing core build alone does not validate JIT execution.
