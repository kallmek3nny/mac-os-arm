# Runtime architecture and handoff

Baseline inspected: `677af5c7a3816ead56901774bf3dab5441146afd` (Phase 46, PR #52). These are inspected implementation boundaries, not a claim of complete application compatibility.

## Execution path and ownership

| Layer | Start reading here | Responsibility |
| --- | --- | --- |
| Session | `src/session.cpp`, `include/macosarm/session.hpp` | Compose loading, startup state, optional dyld bootstrap, and execution. |
| File format | `src/macho.cpp`, `src/image_loader.cpp` | Validate Mach-O and materialize guest segments. |
| Memory | `src/address_space.cpp` | Guest mappings, rights, splitting/protection, and cross-fragment access. |
| Dynamic linking | `src/dyld_*.cpp`, `include/macosarm/dyld_*.hpp` | Dependencies, symbols, fixups, and initializers. Substantial implementations also live inline in headers. |
| CPU | `include/macosarm/execution.hpp`, `src/dynarmic_backend.cpp` | CPU state, backend contract, translated execution, memory callbacks. |
| Process loop | `src/process.cpp` | Enforce budgets; dispatch supervisor calls to BSD or Mach handlers. |
| Darwin services | `src/darwin_syscall.cpp`, `src/mach_trap.cpp` | Selected syscalls and modeled Mach state/messages. |
| Pointer authentication | `src/pointer_auth.cpp`, `include/macosarm/pointer_auth.hpp` | Emulator-defined signing/authentication policy. |

Start with `tests/test_session_dynarmic.cpp` for translated session integration. Test `.inc` files are included by parent translation units, not independent CTest executables. Preserve their registration when reorganizing tests.

## Implemented versus missing

- BSD dispatch supports exit, host-delegated write, modeled process/thread identity, bounded anonymous mmap, mprotect, and munmap. Unknown syscalls return ENOSYS.
- mmap implements restricted private anonymous non-executable memory. File backing, shared mappings, fixed replacement, and MAP_JIT are unsupported.
- Main-thread bootstrap data exists, but valid `bsdthread_register` calls return ENOSYS; `bsdthread_create` rejects the unregistered process. This is not multithreading support.
- Mach messages use a guest context. Tests do not demonstrate communication with real macOS services or WindowServer.
- dyld symbol resolution explicitly rejects thread-local, stub-and-resolver, and function-variant exports. Some chained-fixup formats/page-start cases are unsupported.
- PAC uses an emulator-defined signature and low-48-bit pointer policy, without Apple hardware compatibility/security claims.
- `macho-inspect` is the only product executable. Execution is available through library APIs and tests, without a general application-launch CLI.
- This inspection did not establish stock libSystem/dyld shared-cache support, Objective-C/Foundation/AppKit compatibility, graphics integration, or a real application launch.

## Verification baseline

[CI for the inspected commit](https://github.com/kallmek3nny/mac-os-arm/actions/runs/39177740874) reports success for Linux core, macOS core, and Linux Dynarmic jobs. No open PRs were returned during inspection on October 18, 2026.

Core tests validate host-side contracts; JIT tests execute translated fixture programs. Neither proves an unmodified macOS application runs. The JIT CI job uses a test-name filter; the README command runs the full JIT-enabled suite.

The documentation/build cleanup was also configured and built locally on Windows with Ninja and GNU C++ 16.1.0: all 21 core CTest suites passed. Reconfiguring after consolidating the warning settings required no recompilation. The JIT was not built locally; its evidence above is the baseline GitHub CI run.

## Recommended next milestone

Run one reproducible external ARM64 Mach-O program through a small CLI using the existing session API. Restrict it to supported syscalls first, with known stdout, exit status, an instruction budget, and explicit failures. Include reproducible fixture source/build instructions and an end-to-end test. This supplies a user-visible acceptance target before more isolated compatibility phases.

Then choose one specific dynamically linked program with an authorized dependency set and record its first unsupported operation. Implement the required missing behavior with regression coverage. More rejection-path tests alone do not establish libSystem or pthread support.

## Maintenance priorities

1. Keep the README synchronized with observable capabilities rather than phase numbers alone.
2. Preserve session, process, backend, and service boundaries. Avoid broad renaming while establishing a runnable milestone.
3. Move inline dyld implementations into source files only one subsystem at a time, validating both core and JIT suites.
4. Keep generated builds out of Git and keep Dynarmic pinned.
