#include "macosarm/darwin_syscall.hpp"
#include "macosarm/mach_trap.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>

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
    const MachContext& context) {

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
    case kDarwinSysGetpid:
        // XNU bsd/kern/syscalls.master: BSD #20, int getpid(void).
        // Process identity belongs to the shared context, never to the host.
        set_success(state, context.process_id());
        return {SyscallDispatchError::none, SyscallAction::resume, syscall_number, 0};
    case kDarwinSysBsdthreadRegister:
        return dispatch_bsdthread_register_preflight(state, address_space, syscall_number);
    case kDarwinSysThreadSelfid:
        // _thread_selfid reports a 64-bit thread ID, not the Mach port name.
        // The rehost currently models exactly one main thread per context.
        set_success(state, context.thread_id());
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
