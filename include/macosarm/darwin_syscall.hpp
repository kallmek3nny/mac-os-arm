#pragma once

#include "macosarm/address_space.hpp"
#include "macosarm/execution.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace macosarm {

constexpr std::uint32_t kDarwinSvcImmediate = 0x80;
constexpr std::uint64_t kDarwinSysExit = 1;
constexpr std::uint64_t kDarwinSysWrite = 4;
constexpr std::uint32_t kDarwinErrnoEintr = 4;
constexpr std::uint32_t kDarwinErrnoEio = 5;
constexpr std::uint32_t kDarwinErrnoEbadf = 9;
constexpr std::uint32_t kDarwinErrnoEacces = 13;
constexpr std::uint32_t kDarwinErrnoEfault = 14;
constexpr std::uint32_t kDarwinErrnoEinval = 22;
constexpr std::uint32_t kDarwinErrnoEfbig = 27;
constexpr std::uint32_t kDarwinErrnoEnospc = 28;
constexpr std::uint32_t kDarwinErrnoEpipe = 32;
constexpr std::uint32_t kDarwinErrnoEnosys = 78;
constexpr std::uint32_t kA64PstateCarry = 1u << 29;

struct HostWriteResult {
    std::uint64_t bytes_written{};
    std::uint32_t error{};

    [[nodiscard]] explicit operator bool() const noexcept {
        return error == 0;
    }
};

class DarwinHostServices {
public:
    virtual ~DarwinHostServices() = default;

    [[nodiscard]] virtual HostWriteResult write(
        std::int32_t fd,
        std::span<const std::byte> bytes) = 0;
};

enum class SyscallAction {
    resume,
    exit_process,
};

enum class SyscallDispatchError {
    none,
    not_supervisor_call,
    unsupported_svc,
    host_contract_violation,
};

struct SyscallDispatchResult {
    SyscallDispatchError error{SyscallDispatchError::none};
    SyscallAction action{SyscallAction::resume};
    std::uint64_t syscall_number{};
    std::int32_t exit_status{};

    [[nodiscard]] explicit operator bool() const noexcept {
        return error == SyscallDispatchError::none;
    }
};

[[nodiscard]] SyscallDispatchResult dispatch_darwin_syscall(
    CpuState& state,
    GuestAddressSpace& address_space,
    const ExecutionResult& execution,
    DarwinHostServices& host);

[[nodiscard]] std::string_view syscall_dispatch_error_name(SyscallDispatchError error) noexcept;

} // namespace macosarm
