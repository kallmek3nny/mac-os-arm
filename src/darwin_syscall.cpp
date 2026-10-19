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

// Model only XNU's early registration rejection paths. Successful pthread
// registration requires thread, workqueue and QoS behavior we do not provide;
// valid calls remain ENOSYS instead of advertising fake kernel capabilities.
[[nodiscard]] SyscallDispatchResult dispatch_bsdthread_register_preflight(
    CpuState& state,
    GuestAddressSpace& address_space,
    std::uint64_t syscall_number) {

    const auto reject = [&](std::uint32_t error) {
        set_error(state, error);
        return SyscallDispatchResult{
            SyscallDispatchError::none, SyscallAction::resume, syscall_number, 0};
    };

    // XNU's register shim passes uint32_t flags to its signed pthread size.
    const auto pthread_size = static_cast<std::int32_t>(
        static_cast<std::uint32_t>(state.x[2]));
    if (pthread_size < 0 || pthread_size > 64 * 1024) {
        return reject(kDarwinErrnoEinval);
    }

    const std::uint64_t data_address = state.x[3];
    const std::uint64_t data_size = state.x[4];
    if (data_address != 0) {
        constexpr std::size_t kRegistrationSize = 56;
        constexpr std::size_t kVersionSize = sizeof(std::uint64_t);
        if (data_size < kVersionSize) {
            return reject(kDarwinErrnoEinval);
        }

        // libpthread/kern/kern_internal.h uses a packed 56-byte record;
        // _bsdthread_register copyins min(sizeof(record), supplied_size).
        std::array<std::byte, kRegistrationSize> record{};
        const auto copy_size = static_cast<std::size_t>(
            std::min<std::uint64_t>(data_size, record.size()));
        if (!address_space.read(data_address, std::span<std::byte>(record).first(copy_size))) {
            return reject(kDarwinErrnoEfault);
        }
        std::uint64_t version = 0;
        for (std::size_t i = 0; i < kVersionSize; ++i) {
            version |= static_cast<std::uint64_t>(
                std::to_integer<unsigned char>(record[i])) << (8U * i);
        }
        if (version != data_size) {
            return reject(kDarwinErrnoEinval);
        }
    }

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
    case kDarwinSysBsdthreadRegister:
        return dispatch_bsdthread_register_preflight(state, address_space, syscall_number);
    case kDarwinSysBsdthreadCreate:
        // libpthread/kern/kern_support.c: _bsdthread_create rejects a
        // process before allocating a thread when proc_get_register(p) == 0.
        // Our bsdthread_register cannot succeed yet; remain unregistered and
        // reject creation with XNU's EINVAL, without claiming thread support.
        set_error(state, kDarwinErrnoEinval);
        return {SyscallDispatchError::none, SyscallAction::resume, syscall_number, 0};
    case kDarwinSysThreadSelfid:
        // _thread_selfid reports a 64-bit thread ID, not the Mach port name.
        // The rehost currently models exactly one main thread per context.
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
