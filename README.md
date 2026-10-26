# mac-os-arm

Experimental ARM64/ARM64e macOS userspace rehosting and translation research for x86_64 macOS hosts. This project is separate from [`kallmek3nny/mac-os`](https://github.com/kallmek3nny/mac-os), which handles GPU/driver research.

## current state (through phase 82)

The runtime contains an ARM64 Mach-O loader and memory model, dyld dependency/symbol/fixup machinery, a model of selected Darwin BSD syscalls and Mach traps, thread-startup and guest TLS scaffolding, and optional Dynarmic ARM64 execution. Recent work adds executable-memory JIT invalidation, synthetic BSD process credentials, a small `macho-run` CLI, guest stdin read support, and non-canceling read/write syscall aliases. Phases 62–82 additionally cover selected time, entropy, descriptor lifecycle, stat, ioctl, vectored/positional I/O, resource-limit, duplication and sync syscalls, with bounded guest execution tests.

This is **not** general macOS 27 application compatibility. The project verifies constrained ARM64 test programs and selected runtime contracts; it has **not** demonstrated unmodified stock libSystem, Objective-C/Foundation/AppKit, graphical applications, or full host-kernel and dyld shared-cache integration. Software pointer-authentication modeling is not Apple hardware PAC.

See [runtime status and limitations](docs/STATUS.md) for the implementation map and next compatibility gaps.

## core build

Requires CMake 3.20+ and a C++20 compiler.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release --parallel 2
ctest --test-dir build -C Release --output-on-failure --timeout 30
```

The default build does not fetch or enable Dynarmic. `macho-inspect` parses and prints ARM64 Mach-O metadata; it does not execute guest code.

## optional dynarmic build and runner

The JIT is exercised by Linux x86_64 CI. It requires Boost headers (Ubuntu package: `libboost-dev`). Dynarmic is fetched at the commit pinned in `CMakeLists.txt`.

```sh
cmake -S . -B build-jit -DCMAKE_BUILD_TYPE=Release -DMACOSARM_ENABLE_DYNARMIC=ON
cmake --build build-jit --config Release --parallel 2
ctest --test-dir build-jit -C Release --output-on-failure --timeout 30
```

A JIT-enabled build also produces `macho-run`, a bounded command-line runner for **supported raw ARM64 Mach-O images**:

```sh
./build-jit/macho-run --budget 200000 ./guest-image.arm64 argument1
```

The CLI exposes limited guest stdin/stdout/stderr and exit semantics. Existing end-to-end tests cover purpose-built hello, argument-count, and stdin-echo fixtures. A successful fixture is **not** evidence of arbitrary macOS app execution.

## direction

Extend the real guest execution path, Darwin/libSystem/pthread behavior, shared-cache/dyld loading, Objective-C runtime, Foundation/AppKit and eventually graphics. Keep strict compiler warnings and CI coverage across Ubuntu, macOS, and the Dynarmic JIT.
