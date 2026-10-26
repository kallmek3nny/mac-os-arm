# runtime architecture and compatibility status

This handoff covers the implementation through phase 82. This is an experimental ARM64 userspace translation runtime, **not** a complete macOS 27 virtual machine, dyld, kernel or Rosetta replacement.

## execution path

| subsystem | entry points | current scope |
| --- | --- | --- |
| mach-o | `src/macho.cpp`, `src/image_loader.cpp` | bounded ARM64 Mach-O parsing and segment loading |
| guest memory | `src/address_space.cpp` | guest mappings, permissions, splits, guarded stacks and cross-fragment reads/writes |
| dyld | `src/dyld_*.cpp`, `include/macosarm/dyld_*.hpp` | dependency plans, symbols, selected chained fixups, initializers and startup state |
| cpu | `src/dynarmic_backend.cpp`, `include/macosarm/execution.hpp` | optional translated ARM64 execution, memory callbacks and code invalidation |
| process | `src/session.cpp`, `src/process.cpp` | session bootstrap, instruction budgeting, BSD syscall and Mach trap dispatch |
| darwin bridge | `src/darwin_syscall.cpp`, `src/mach_trap.cpp` | selected synthetic or host-delegated BSD services and modeled Mach messages |
| cli | `src/macho_run.cpp` | run raw supported ARM64 Mach-O fixtures with guest arguments and limited stdio |

## demonstrated capabilities

- CPU-backed execution exists in optional Dynarmic tests, including ARM64 guest instructions and bounded raw Mach-O fixtures.
- A `macho-run` tool accepts raw ARM64 Mach-O images. Fixture tests validate stdout, return codes, argument handling and stdin echo/EOF.
- The BSD bridge includes limited read/write, `read_nocancel`/`write_nocancel`, time and entropy, close/dup/dup2, fstat64, ioctl terminal and descriptor flags, vectored/positional I/O, fcntl flags and fd duplication, resource limits and file sync, process identity/credentials (some values deliberately synthetic), guest-memory mmap/mprotect/munmap and thread-related bootstrap paths.
- Guest thread contexts, worker TLS/errno isolation and code-generation invalidation have explicit tests. This is not equivalent to native Darwin pthread support.
- Both core and JIT configurations have CI suites. The Dynarmic suites execute real translated fixture code rather than merely mocking a CPU.

## still missing or constrained

- No evidence of arbitrary unmodified macOS applications launching, or stock macOS 27 libSystem, dyld shared-cache, Foundation, AppKit, Objective-C or WindowServer compatibility.
- Darwin BSD calls and Mach IPC are partial models. Guest Mach messages do not imply integration with host macOS services. Most unknown calls remain unsupported.
- Memory mappings and dyld relocation/export formats are intentionally limited; writable/executable mapping policy and real-world library bootstrap need further work.
- The software pointer-authentication policy is not hardware PAC or a guarantee of compatibility with Apple ARM64e security semantics.
- Running a CLI fixture is an important milestone but does not demonstrate a real application dependency closure.

## next concrete milestones

1. Run a self-contained, independently compiled ARM64 Mach-O through `macho-run` and record unsupported calls without loosening execution budgets or memory checks.
2. Expand concrete libSystem/pthread functionality required by that program with source-grounded ABI layout and translated regression tests.
3. Bring up selected real shared-cache/dyld/Objective-C paths, then Foundation/AppKit, before claiming graphical application execution.

Never confuse the separate `kallmek3nny/mac-os` GPU-driver project with ARM64 userspace translation work in this repository.
