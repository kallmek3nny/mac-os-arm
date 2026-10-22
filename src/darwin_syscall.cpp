#include "macosarm/darwin_syscall.hpp"
#include "macosarm/mach_trap.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>

namespace macosarm {
namespace {

constexpr std::size_t kIoChunkSize = 64 * 1024;

void set_success(CpuState& state, std::uint64_t value) noexcept {
    state.x[0] = value;
    state.pstate &= ~kA64PstateCarry;
}

void set_error(CpuState& state, std::uint32_t error) noexcept {
    state.x[0] = error;
    state.pstate |= kA64PstateCarry;
}

[[nodiscard]] SyscallDispatchResult dispatch_write(
    CpuState& state,
    GuestAddressSpace& address_space,
    DarwinHostServices& host,
    std::uint64_t syscall_number) {

    const auto fd = static_cast<std::int32_t>(static_cast<std::uint32_t>(state.x[0]));
    std::uint64_t guest_address = state.x[1];
    std::uint64_t remaining = state.x[2];
    std::uint64_t total_written = 0;
    std::array<std::byte, kIoChunkSize> chunk{};

    while (remaining != 0) {
        const auto requested = static_cast<std::size_t>(
            std::min<std::uint64_t>(remaining, chunk.size()));
        const auto read_result = address_space.read(
            guest_address,
            std::span<std::byte>(chunk.data(), requested));
        if (!read_result) {
            if (total_written == 0) {
                set_error(state, kDarwinErrnoEfault);
            } else {
                set_success(state, total_written);
            }
            return {SyscallDispatchError::none, SyscallAction::resume, syscall_number, 0};
        }

        const HostWriteResult host_result = host.write(
            fd,
            std::span<const std::byte>(chunk.data(), requested));
        if (!host_result) {
            if (total_written == 0) {
                set_error(state, host_result.error);
            } else {
                set_success(state, total_written);
            }
            return {SyscallDispatchError::none, SyscallAction::resume, syscall_number, 0};
        }
        if (host_result.bytes_written > requested) {
            return {
                SyscallDispatchError::host_contract_violation,
                SyscallAction::resume,
                syscall_number,
                0,
            };
        }

        total_written += host_result.bytes_written;
        if (host_result.bytes_written != requested) {
            set_success(state, total_written);
            return {SyscallDispatchError::none, SyscallAction::resume, syscall_number, 0};
        }

        if (guest_address > std::numeric_limits<std::uint64_t>::max() - requested) {
            set_success(state, total_written);
            return {SyscallDispatchError::none, SyscallAction::resume, syscall_number, 0};
        }
        guest_address += requested;
        remaining -= requested;
    }

    set_success(state, total_written);
    return {SyscallDispatchError::none, SyscallAction::resume, syscall_number, 0};
}

// XNU bsd/kern/sys_generic.c: read_nocancel resolves the descriptor (EBADF)
// before dofileread rejects nbyte > INT_MAX (EINVAL) or copyout faults
// (EFAULT). A read may legally return fewer bytes than requested, so issue
// exactly one bounded host read and never block again to fill the buffer.
// The destination is probed first, so host input is never consumed and then
// dropped because the guest buffer cannot receive it.
[[nodiscard]] SyscallDispatchResult dispatch_read(
    CpuState& state,
    GuestAddressSpace& address_space,
    DarwinHostServices& host,
    std::uint64_t syscall_number) {

    const auto finish = [&]() {
        return SyscallDispatchResult{
            SyscallDispatchError::none, SyscallAction::resume, syscall_number, 0};
    };
    const auto contract_violation = [&]() {
        return SyscallDispatchResult{
            SyscallDispatchError::host_contract_violation,
            SyscallAction::resume, syscall_number, 0};
    };

    const auto fd = static_cast<std::int32_t>(static_cast<std::uint32_t>(state.x[0]));
    const std::uint64_t guest_address = state.x[1];
    const std::uint64_t nbyte = state.x[2];

    // A zero-length host read validates the descriptor without consuming
    // input; a bad descriptor wins over any later argument error.
    const auto check_descriptor =
        [&](std::uint32_t fallback_error) -> SyscallDispatchResult {
        const HostReadResult probe = host.read(fd, std::span<std::byte>{});
        if (probe.bytes_read != 0U) {
            return contract_violation();
        }
        if (!probe) {
            set_error(state, probe.error);
        } else if (fallback_error != 0U) {
            set_error(state, fallback_error);
        } else {
            set_success(state, 0U);
        }
        return finish();
    };

    if (nbyte == 0U) {
        return check_descriptor(0U);
    }
    if (nbyte > static_cast<std::uint64_t>(std::numeric_limits<std::int32_t>::max())) {
        return check_descriptor(kDarwinErrnoEinval);
    }
    const auto requested = static_cast<std::size_t>(
        std::min<std::uint64_t>(nbyte, kIoChunkSize));
    if (!address_space.probe_write(guest_address, requested)) {
        return check_descriptor(kDarwinErrnoEfault);
    }

    std::array<std::byte, kIoChunkSize> chunk{};
    const HostReadResult host_result = host.read(
        fd, std::span<std::byte>(chunk.data(), requested));
    if (!host_result) {
        set_error(state, host_result.error);
        return finish();
    }
    if (host_result.bytes_read > requested) {
        return contract_violation();
    }
    const auto received = static_cast<std::size_t>(host_result.bytes_read);
    if (received != 0U &&
        !address_space.write(guest_address,
                             std::span<const std::byte>(chunk.data(), received))) {
        set_error(state, kDarwinErrnoEfault);
        return finish();
    }
    set_success(state, host_result.bytes_read);
    return finish();
}

// The narrow anonymous mmap contract used by guest malloc and libsystem.
// XNU bsd/kern/kern_mman.c uses mach_vm_map_kernel for MAP_ANON and
// treats non-fixed addr as a start hint. We currently have neither vnode
// pagers nor atomic MAP_FIXED replacement, MAP_JIT entitlements, shared VM,
// or executable-memory code-signing. Those requests remain unsupported.
[[nodiscard]] SyscallDispatchResult dispatch_mmap(
    CpuState& state,
    GuestAddressSpace& address_space,
    std::uint64_t syscall_number) {

    const auto reject = [&](std::uint32_t error) {
        set_error(state, error);
        return SyscallDispatchResult{
            SyscallDispatchError::none, SyscallAction::resume, syscall_number, 0};
    };

    constexpr std::uint64_t page_size = GuestAddressSpace::kPageSize;
    constexpr std::uint64_t allocation_base = 0x2000000000ULL;
    constexpr std::uint64_t max_allocation_size = 256ULL * 1024ULL * 1024ULL;
    constexpr std::size_t max_mappings = 4096;
    constexpr std::uint32_t prot_mask = 7U;
    constexpr std::uint32_t valid_flags =
        kDarwinMapPrivate | kDarwinMapFixed | kDarwinMapJit |
        kDarwinMapAnonymous | kDarwinMapUnix03 | 1U; // MAP_SHARED

    const std::uint64_t length = state.x[1];
    const std::uint32_t prot = static_cast<std::uint32_t>(state.x[2]);
    const std::uint32_t flags = static_cast<std::uint32_t>(state.x[3]);
    const std::int32_t fd = static_cast<std::int32_t>(
        static_cast<std::uint32_t>(state.x[4]));
    const std::uint64_t position = state.x[5];

    if (length == 0 || (flags & ~valid_flags) != 0 ||
        (prot & ~prot_mask) != 0) {
        return reject(kDarwinErrnoEinval);
    }
    if (length > std::numeric_limits<std::uint64_t>::max() - (page_size - 1U)) {
        return reject(kDarwinErrnoEinval);
    }
    const std::uint64_t rounded_size =
        (length + page_size - 1U) & ~(page_size - 1U);
    if (rounded_size > max_allocation_size) {
        return reject(kDarwinErrnoEnomem);
    }

    // Only private, anonymous, non-fixed, non-JIT read/write regions
    // have an implemented backing and protection contract.
    if ((flags & ~kDarwinMapUnix03) !=
            (kDarwinMapPrivate | kDarwinMapAnonymous) ||
        (prot & 4U) != 0U || fd != -1 || position != 0U) {
        return reject(kDarwinErrnoEnosys);
    }
    const auto mappings = address_space.mappings();
    if (mappings.size() >= max_mappings) {
        return reject(kDarwinErrnoEnomem);
    }

    // Scan a finite snapshot of existing mappings to find a full hole.
    // Preserve caller-owned images and PAGEZERO without touching host VM.
    const auto free_region = [&](std::uint64_t start) -> std::optional<std::uint64_t> {
        std::uint64_t candidate = start;
        for (const Mapping& mapped : mappings) {
            const std::uint64_t end = mapped.base + mapped.size;
            if (end <= candidate) {
                continue;
            }
            if (mapped.base > candidate &&
                mapped.base - candidate >= rounded_size) {
                return candidate;
            }
            candidate = end;
            if (candidate > std::numeric_limits<std::uint64_t>::max() - rounded_size) {
                return std::nullopt;
            }
        }
        if (candidate > std::numeric_limits<std::uint64_t>::max() - rounded_size) {
            return std::nullopt;
        }
        return candidate;
    };

    const std::uint64_t hint = state.x[0];
    const std::uint64_t start =
        hint == 0U ||
        hint > std::numeric_limits<std::uint64_t>::max() - (page_size - 1U)
            ? allocation_base
            : (hint + page_size - 1U) & ~(page_size - 1U);
    auto address = free_region(start);
    if (!address.has_value() && start != allocation_base) {
        address = free_region(allocation_base);
    }
    if (!address.has_value()) {
        return reject(kDarwinErrnoEnomem);
    }

    Protection protection = Protection::none;
    if ((prot & 1U) != 0U) {
        protection = protection | Protection::read;
    }
    if ((prot & 2U) != 0U) {
        protection = protection | Protection::write;
    }
    if (!address_space.map(*address, rounded_size, protection,
                           Protection::read | Protection::write)) {
        return reject(kDarwinErrnoEnomem);
    }

    set_success(state, *address);
    return {SyscallDispatchError::none, SyscallAction::resume, syscall_number, 0};
}

[[nodiscard]] SyscallDispatchResult dispatch_mprotect(
    CpuState& state,
    GuestAddressSpace& address_space,
    std::uint64_t syscall_number) {

    // XNU bsd/kern/kern_mman.c: mprotect_sanitize checks alignment and
    // rounded range; mach_vm_protect returns ENOMEM for unmapped gaps and
    // EACCES when requested permissions exceed maximum map protections.
    const auto reject = [&](std::uint32_t error) {
        set_error(state, error);
        return SyscallDispatchResult{
            SyscallDispatchError::none, SyscallAction::resume, syscall_number, 0};
    };
    constexpr std::uint64_t page_size = GuestAddressSpace::kPageSize;
    const std::uint64_t address = state.x[0];
    const std::uint64_t length = state.x[1];
    // XNU's BSD protection sanitizer masks unknown bits.
    const std::uint32_t bits = static_cast<std::uint32_t>(state.x[2]) & 7U;
    if ((address % page_size) != 0U ||
        length > std::numeric_limits<std::uint64_t>::max() - (page_size - 1U)) {
        return reject(kDarwinErrnoEinval);
    }
    if (length == 0) {
        // XNU explicitly allows SIZE_ZERO_FALLTHROUGH.
        set_success(state, 0);
        return {SyscallDispatchError::none, SyscallAction::resume, syscall_number, 0};
    }
    const std::uint64_t rounded_size =
        (length + page_size - 1U) & ~(page_size - 1U);
    if (rounded_size > std::numeric_limits<std::uint64_t>::max() - address) {
        return reject(kDarwinErrnoEinval);
    }

    Protection protection = Protection::none;
    if ((bits & 1U) != 0U) {
        protection = protection | Protection::read;
    }
    if ((bits & 2U) != 0U) {
        protection = protection | Protection::write;
    }
    if ((bits & 4U) != 0U) {
        protection = protection | Protection::execute;
    }

    const VmResult result = address_space.protect_range(
        address, rounded_size, protection);
    if (!result) {
        return reject(result.error == VmError::unmapped ? kDarwinErrnoEnomem :
                      result.error == VmError::protection ? kDarwinErrnoEacces :
                      kDarwinErrnoEinval);
    }
    set_success(state, 0);
    return {SyscallDispatchError::none, SyscallAction::resume, syscall_number, 0};
}

[[nodiscard]] SyscallDispatchResult dispatch_munmap(
    CpuState& state,
    GuestAddressSpace& address_space,
    std::uint64_t syscall_number) {

    // XNU bsd/kern/kern_mman.c: munmap validates page alignment, nonzero
    // length and arithmetic range before calling mach_vm_deallocate().
    // mach_vm_deallocate rounds the length to the task's page size.
    const std::uint64_t base = state.x[0];
    const std::uint64_t size = state.x[1];
    constexpr std::uint64_t page_size = GuestAddressSpace::kPageSize;
    const std::uint64_t remainder = size % page_size;

    if ((base % page_size) != 0 || size == 0 ||
        size > std::numeric_limits<std::uint64_t>::max() - base) {
        set_error(state, kDarwinErrnoEinval);
        return {SyscallDispatchError::none, SyscallAction::resume, syscall_number, 0};
    }

    const std::uint64_t padding = remainder == 0 ? 0 : page_size - remainder;
    if (size > std::numeric_limits<std::uint64_t>::max() - padding) {
        set_error(state, kDarwinErrnoEinval);
        return {SyscallDispatchError::none, SyscallAction::resume, syscall_number, 0};
    }
    const std::uint64_t rounded_size = size + padding;
    if (rounded_size > std::numeric_limits<std::uint64_t>::max() - base ||
        !address_space.unmap_range(base, rounded_size)) {
        set_error(state, kDarwinErrnoEinval);
    } else {
        set_success(state, 0);
    }
    return {SyscallDispatchError::none, SyscallAction::resume, syscall_number, 0};
}

// Apple libpthread/kern/kern_internal.h: fixed, packed 56-byte record.
// Extract little-endian input fields after the copyin and size-version check.
[[nodiscard]] std::uint64_t pthread_record_u64(
    const std::array<std::byte, 56>& bytes, std::size_t offset) noexcept {
    std::uint64_t value = 0;
    for (std::size_t i = 0; i < 8U; ++i) {
        value |= static_cast<std::uint64_t>(
            std::to_integer<unsigned char>(bytes[offset + i])) << (i * 8U);
    }
    return value;
}

[[nodiscard]] std::uint32_t pthread_record_u32(
    const std::array<std::byte, 56>& bytes, std::size_t offset) noexcept {
    std::uint32_t value = 0;
    for (std::size_t i = 0; i < 4U; ++i) {
        value |= static_cast<std::uint32_t>(
            std::to_integer<unsigned char>(bytes[offset + i])) << (i * 8U);
    }
    return value;
}

// Preflight *never* commits registration or edits guest bytes. A valid
// request still returns ENOSYS instead of pretending support for pthread
// creation, registration copyout, workqueue scheduling, or QoS policies.
[[nodiscard]] SyscallDispatchResult dispatch_bsdthread_register_preflight(
    CpuState& state,
    GuestAddressSpace& address_space,
    const MachContext& context,
    std::uint64_t syscall_number) {
    const auto reject = [&](std::uint32_t error) {
        set_error(state, error);
        return SyscallDispatchResult{
            SyscallDispatchError::none, SyscallAction::resume, syscall_number, 0};
    };
    const auto pthread_size = static_cast<std::int32_t>(
        static_cast<std::uint32_t>(state.x[2]));
    if (pthread_size < 0 || pthread_size > 64 * 1024) {
        return reject(kDarwinErrnoEinval);
    }
    PthreadRegistrationPreflight candidate{};
    candidate.threadstart = state.x[0];
    candidate.wqthread = state.x[1];
    candidate.pthread_size = static_cast<std::uint32_t>(pthread_size);
    const std::uint64_t data_address = state.x[3];
    const std::uint64_t data_size = state.x[4];
    if (data_address != 0U) {
        if (data_size < sizeof(std::uint64_t)) {
            return reject(kDarwinErrnoEinval);
        }
        std::array<std::byte, 56> record{};
        const std::size_t copied = static_cast<std::size_t>(
            std::min<std::uint64_t>(data_size, record.size()));
        if (!address_space.read(data_address, std::span<std::byte>(record).first(copied))) {
            return reject(kDarwinErrnoEfault);
        }
        if (pthread_record_u64(record, 0U) != data_size) {
            return reject(kDarwinErrnoEinval);
        }
        candidate.record_size = data_size;
        candidate.record_address = data_address;
        candidate.copyout_size = static_cast<std::uint32_t>(copied);
        candidate.dispatch_queue_offset = pthread_record_u64(record, 8U);
        candidate.tsd_offset = pthread_record_u32(record, 24U);
        candidate.return_to_kernel_offset = pthread_record_u32(record, 28U);
        candidate.mach_thread_self_offset = pthread_record_u32(record, 32U);
        candidate.joinable_offset_bits = pthread_record_u32(record, 48U);
        candidate.wq_quantum_expiry_offset = pthread_record_u32(record, 52U);
        candidate.copyout_writable =
            static_cast<bool>(address_space.probe_write(data_address, copied));
    } else {
        candidate.dispatch_queue_offset = state.x[5];
    }
    // Match libpthread's source-observed per-process offsets. Values outside
    // the pthread structure's 64-bit TSD slot are ignored, not accepted.
    constexpr std::uint32_t slot_size = sizeof(std::uint64_t);
    std::uint32_t maximum_offset = 0U;
    if (candidate.pthread_size >= slot_size &&
        candidate.tsd_offset <= candidate.pthread_size - slot_size) {
        maximum_offset = candidate.pthread_size - candidate.tsd_offset - slot_size;
    } else {
        candidate.tsd_offset = 0U;
    }
    if (candidate.dispatch_queue_offset > maximum_offset) {
        candidate.dispatch_queue_offset = 0U;
    }
    if (candidate.return_to_kernel_offset > maximum_offset) {
        candidate.return_to_kernel_offset = 0U;
    }
    if (candidate.mach_thread_self_offset > maximum_offset) {
        candidate.mach_thread_self_offset = 0U;
    }
    if (candidate.wq_quantum_expiry_offset > maximum_offset) {
        candidate.wq_quantum_expiry_offset = 0U;
    }
    // ARM64 bsdthread_create eventually jumps through the registered
    // libpthread startup veneers. Observe whether both targets are aligned
    // and executable in the guest VM, without changing XNU's register-time
    // error ordering or claiming that their instructions are valid.
    // In particular, never dereference a guest entrypoint as host memory.
    const auto executable_entry = [&](std::uint64_t address) {
        if (address == 0U || (address & 3U) != 0U) {
            return false;
        }
        std::array<std::byte, 4> instruction{};
        return static_cast<bool>(address_space.fetch_code(address, instruction));
    };
    candidate.threadstart_executable = executable_entry(candidate.threadstart);
    candidate.wqthread_executable = executable_entry(candidate.wqthread);

    context.observe_pthread_registration_preflight(candidate);
    return reject(kDarwinErrnoEnosys);
}

} // namespace

SyscallDispatchResult dispatch_darwin_syscall(
    CpuState& state,
    GuestAddressSpace& address_space,
    const ExecutionResult& execution,
    DarwinHostServices& host,
    const MachContext& context,
    const MachThreadIdentity* current_thread) {

    if (execution.reason != StopReason::supervisor_call) {
        return {SyscallDispatchError::not_supervisor_call, SyscallAction::resume, 0, 0};
    }
    if (execution.supervisor_call != kDarwinSvcImmediate) {
        return {SyscallDispatchError::unsupported_svc, SyscallAction::resume, 0, 0};
    }

    const std::uint64_t syscall_number = state.x[16];
    switch (syscall_number) {
    case kDarwinSysExit:
        return {
            SyscallDispatchError::none,
            SyscallAction::exit_process,
            syscall_number,
            static_cast<std::int32_t>(static_cast<std::uint32_t>(state.x[0])),
        };
    case kDarwinSysRead:
        return dispatch_read(state, address_space, host, syscall_number);
    case kDarwinSysWrite:
        return dispatch_write(state, address_space, host, syscall_number);
    case kDarwinSysMmap:
        return dispatch_mmap(state, address_space, syscall_number);
    case kDarwinSysMprotect:
        return dispatch_mprotect(state, address_space, syscall_number);
    case kDarwinSysMunmap:
        return dispatch_munmap(state, address_space, syscall_number);
    case kDarwinSysGetpid:
        // XNU bsd/kern/syscalls.master: BSD #20, int getpid(void).
        // Process identity belongs to the shared context, never to the host.
        set_success(state, context.process_id());
        return {SyscallDispatchError::none, SyscallAction::resume, syscall_number, 0};
    case kDarwinSysGetppid:
        // XNU syscalls.master #39: int getppid(void). A translated process is
        // reported as a child of launchd, never of the host parent process.
        set_success(state, kDarwinSyntheticParentProcessId);
        return {SyscallDispatchError::none, SyscallAction::resume, syscall_number, 0};
    case kDarwinSysGetuid:
    case kDarwinSysGeteuid:
        // XNU syscalls.master #24 getuid / #25 geteuid: both always succeed.
        // Real and effective ids are the same synthetic non-root login user;
        // host credentials are never consulted or exposed.
        set_success(state, kDarwinSyntheticUserId);
        return {SyscallDispatchError::none, SyscallAction::resume, syscall_number, 0};
    case kDarwinSysGetgid:
    case kDarwinSysGetegid:
        // XNU syscalls.master #47 getgid / #43 getegid: synthetic "staff".
        set_success(state, kDarwinSyntheticGroupId);
        return {SyscallDispatchError::none, SyscallAction::resume, syscall_number, 0};
    case kDarwinSysIssetugid:
        // XNU syscalls.master #327: int issetugid(void). The synthetic
        // credentials never change and no image is launched set-id, so the
        // process is not tainted; libSystem may then honor environment vars.
        set_success(state, 0U);
        return {SyscallDispatchError::none, SyscallAction::resume, syscall_number, 0};
    case kDarwinSysBsdthreadRegister:
        return dispatch_bsdthread_register_preflight(
            state, address_space, context, syscall_number);
    case kDarwinSysBsdthreadTerminate:
        // XNU syscalls.master #361: (stackaddr, freesize, port, sema_or_ulock).
        // A registered pthread can also request stack deallocation, Mach
        // right release and semaphore signaling. We cannot perform those
        // kernel lifetime operations yet, so never acknowledge such a call.
        // For manually constructed, resource-free guest execution contexts
        // only, terminate the caller without killing sibling contexts.
        if (current_thread == nullptr || state.x[0] != 0 ||
            state.x[1] != 0 || state.x[2] != 0 || state.x[3] != 0) {
            set_error(state, kDarwinErrnoEnosys);
            return {SyscallDispatchError::none, SyscallAction::resume, syscall_number, 0};
        }
        return {SyscallDispatchError::none, SyscallAction::exit_thread, syscall_number, 0};
    case kDarwinSysBsdthreadCreate:
        // libpthread/kern/kern_support.c: _bsdthread_create rejects a
        // process before allocating a thread when proc_get_register(p) == 0.
        // Our bsdthread_register cannot succeed yet; remain unregistered and
        // reject creation with XNU's EINVAL, without claiming thread support.
        // A validated preflight is not a successful registration.
        set_error(state, context.pthread_registered()
                             ? kDarwinErrnoEnosys : kDarwinErrnoEinval);
        return {SyscallDispatchError::none, SyscallAction::resume, syscall_number, 0};
    case kDarwinSysThreadSelfid:
        // _thread_selfid reports a 64-bit thread ID, not the Mach port name.
        // The current thread is the process main thread in the legacy path.
        set_success(state, current_thread != nullptr
                               ? current_thread->thread_id : context.thread_id());
        return {SyscallDispatchError::none, SyscallAction::resume, syscall_number, 0};
    default:
        set_error(state, kDarwinErrnoEnosys);
        return {SyscallDispatchError::none, SyscallAction::resume, syscall_number, 0};
    }
}

SyscallDispatchResult dispatch_darwin_syscall(
    CpuState& state,
    GuestAddressSpace& address_space,
    const ExecutionResult& execution,
    DarwinHostServices& host,
    const MachContext& context) {
    return dispatch_darwin_syscall(state, address_space, execution, host, context, nullptr);
}

SyscallDispatchResult dispatch_darwin_syscall(
    CpuState& state,
    GuestAddressSpace& address_space,
    const ExecutionResult& execution,
    DarwinHostServices& host) {
    MachContext context;
    return dispatch_darwin_syscall(state, address_space, execution, host, context);
}

std::string_view syscall_dispatch_error_name(SyscallDispatchError error) noexcept {
    switch (error) {
    case SyscallDispatchError::none: return "none";
    case SyscallDispatchError::not_supervisor_call: return "not_supervisor_call";
    case SyscallDispatchError::unsupported_svc: return "unsupported_svc";
    case SyscallDispatchError::host_contract_violation: return "host_contract_violation";
    }
    return "unknown";
}

} // namespace macosarm
