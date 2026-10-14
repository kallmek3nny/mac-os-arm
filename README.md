# mac-os-arm

Experimental ARM64-to-x86_64 macOS userspace rehosting work for post-Intel macOS software.

This repository is intentionally separate from `kallmek3nny/mac-os`. The GPU/driver project can evolve independently; this repository owns the ARM64 Mach-O loader, translation runtime, Darwin/Mach bridge, and later architecture-neutral graphics handoff.

## current milestone

Phase 0 is deliberately small and testable:

- strict little-endian 64-bit Mach-O parsing
- ARM64 CPU validation
- `LC_SEGMENT_64` extraction with bounds checks
- `LC_MAIN` extraction with bounds checks
- a `macho-inspect` utility
- Linux/macOS CI with command-level and job-level timeouts

No ARM instructions are executed yet.

## build

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel 2
ctest --test-dir build --output-on-failure --timeout 30
```

## roadmap

1. Mach-O loader and guest address-space model
2. ARM64 execution backend integration
3. Darwin syscall and Mach trap bridge
4. dyld/libSystem support
5. ARM64e/PAC model
6. Objective-C/Foundation/AppKit bring-up
7. architecture-neutral GPU bridge into the separate `mac-os` hardware work
