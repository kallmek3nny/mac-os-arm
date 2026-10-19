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
constexpr std::uint64_t kDarwinSysGetpid = 20;
constexpr std::uint64_t kDarwinSysMunmap = 73;
constexpr std::uint64_t kDarwinSysMprotect = 74;
constexpr std::uint64_t kDarwinSysMmap = 197;
constexpr std::uint64_t kDarwinSysBsdthreadCreate = 360;
constexpr std::uint64_t kDarwinSysBsdthreadRegister = 366;
constexpr std::uint64_t kDarwinSysThreadSelfid = 372;
constexpr std::uint32_t kDarwinErrnoEio = 5;
constexpr std::uint32_t kDarwinErrnoEnomem = 12;
constexpr std::uint32_t kDarwinErrnoEacces = 13;
constexpr std::uint32_t kDarwinErrnoEinval = 22;
constexpr std::uint32_t kDarwinErrnoEfault = 14;
constexpr std::uint32_t kDarwinErrnoEnosys = 78;
constexpr std::uint32_t kA64PstateCarry = 1u << 29;

// XNU bsd/sys/mman.h, kept separate from host OS mmap flags.
constexpr std::uint32_t kDarwinMapPrivate = 0x0002;
constexpr std::uint32_t kDarwinMapFixed = 0x0010;
constexpr std::uint32_t kDarwinMapJit = 0x0800;
constexpr std::uint32_t kDarwinMapAnonymous = 0x1000;
constexpr std::uint32_t kDarwinMapUnix03 = 0x40000;

class MachContext;
struct MachThreadIdentity;

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

// Process execution passes its shared Mach context, keeping BSD thread IDs
// consistent across translated initializers, main, and Mach traps.
[[nodiscard]] SyscallDispatchResult dispatch_darwin_syscall(
    CpuState& state,
    GuestAddressSpace& address_space,
    const ExecutionResult& execution,
    DarwinHostServices& host,
    const MachContext& context);

[[nodiscard]] SyscallDispatchResult dispatch_darwin_syscall(
    CpuState& state,
    GuestAddressSpace& address_space,
    const ExecutionResult& execution,
    DarwinHostServices& host,
    const MachContext& context,
    const MachThreadIdentity* current_thread);

[[nodiscard]] std::string_view syscall_dispatch_error_name(SyscallDispatchError error) noexcept;

} // namespace macosarm
