#pragma once

#include "macosarm/address_space.hpp"
#include "macosarm/execution.hpp"

#include <cstdint>
#include <optional>
#include <string_view>

namespace macosarm {

constexpr std::int64_t kMachTrapVmAllocate = -10;
constexpr std::int64_t kMachTrapVmDeallocate = -12;
constexpr std::int64_t kMachTrapVmProtect = -14;
constexpr std::int64_t kMachTrapVmMap = -15;
constexpr std::int64_t kMachTrapReplyPort = -26;
constexpr std::int64_t kMachTrapThreadSelf = -27;
constexpr std::int64_t kMachTrapTaskSelf = -28;
constexpr std::int64_t kMachTrapHostSelf = -29;
constexpr std::int64_t kMachTrapMessage = -31;

constexpr std::uint32_t kMachKernSuccess = 0;
constexpr std::uint32_t kMachKernInvalidAddress = 1;
constexpr std::uint32_t kMachKernProtectionFailure = 2;
constexpr std::uint32_t kMachKernNoSpace = 3;
constexpr std::uint32_t kMachKernInvalidArgument = 4;

constexpr std::uint64_t kMachVmFlagsAnywhere = 0x1;
constexpr std::uint32_t kMachVmProtRead = 0x1;
constexpr std::uint32_t kMachVmProtWrite = 0x2;
constexpr std::uint32_t kMachVmProtExecute = 0x4;
constexpr std::uint32_t kMachVmProtMask =
    kMachVmProtRead | kMachVmProtWrite | kMachVmProtExecute;

class MachContext {
public:
    static constexpr std::uint32_t kDefaultTaskSelfPort = 0x101;
    static constexpr std::uint32_t kDefaultThreadSelfPort = 0x102;
    static constexpr std::uint32_t kDefaultHostSelfPort = 0x103;
    static constexpr std::uint32_t kFirstReplyPort = 0x2000;
    static constexpr std::uint64_t kVmAnywhereBase = 0x1000000000ULL;

    [[nodiscard]] std::uint32_t task_self_port() const noexcept { return task_self_port_; }
    [[nodiscard]] std::uint32_t thread_self_port() const noexcept { return thread_self_port_; }
    [[nodiscard]] std::uint32_t host_self_port() const noexcept { return host_self_port_; }
    [[nodiscard]] std::optional<std::uint32_t> allocate_reply_port() noexcept;

private:
    std::uint32_t task_self_port_{kDefaultTaskSelfPort};
    std::uint32_t thread_self_port_{kDefaultThreadSelfPort};
    std::uint32_t host_self_port_{kDefaultHostSelfPort};
    std::uint32_t next_reply_port_{kFirstReplyPort};
};

enum class MachTrapDispatchError {
    none,
    not_supervisor_call,
    unsupported_svc,
    not_mach_trap,
    unsupported_trap,
    port_namespace_exhausted,
};

struct MachTrapDispatchResult {
    MachTrapDispatchError error{MachTrapDispatchError::none};
    std::int64_t trap_number{};
    std::uint32_t returned_port{};

    [[nodiscard]] explicit operator bool() const noexcept {
        return error == MachTrapDispatchError::none;
    }
};

[[nodiscard]] std::int64_t decode_darwin_trap_number(const CpuState& state) noexcept;

[[nodiscard]] MachTrapDispatchResult dispatch_mach_trap(
    CpuState& state,
    GuestAddressSpace& address_space,
    const ExecutionResult& execution,
    MachContext& context);

[[nodiscard]] std::string_view mach_trap_dispatch_error_name(MachTrapDispatchError error) noexcept;

} // namespace macosarm
