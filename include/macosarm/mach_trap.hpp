#pragma once

#include "macosarm/address_space.hpp"
#include "macosarm/execution.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <optional>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace macosarm {

constexpr std::int64_t kMachTrapVmAllocate = -10;
constexpr std::int64_t kMachTrapVmDeallocate = -12;
constexpr std::int64_t kMachTrapVmProtect = -14;
constexpr std::int64_t kMachTrapVmMap = -15;
constexpr std::int64_t kMachTrapPortDeallocate = -18;
constexpr std::int64_t kMachTrapPortConstruct = -24;
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
constexpr std::uint32_t kMachKernResourceShortage = 6;
constexpr std::uint32_t kMachKernInvalidName = 15;

constexpr std::uint64_t kMachVmFlagsAnywhere = 0x1;
constexpr std::uint32_t kMachVmProtRead = 0x1;
constexpr std::uint32_t kMachVmProtWrite = 0x2;
constexpr std::uint32_t kMachVmProtExecute = 0x4;
constexpr std::uint32_t kMachVmProtMask =
    kMachVmProtRead | kMachVmProtWrite | kMachVmProtExecute;

constexpr std::uint32_t kMachPortOptionsReplyPort = 0x1000;
constexpr std::size_t kMachPortOptionsSize = 24;

constexpr std::uint32_t kMachMsgSuccess = 0;
constexpr std::uint32_t kMachSendInvalidData = 0x10000002;
constexpr std::uint32_t kMachSendInvalidDest = 0x10000003;
constexpr std::uint32_t kMachSendInvalidVoucher = 0x10000005;
constexpr std::uint32_t kMachSendMsgTooSmall = 0x10000008;
constexpr std::uint32_t kMachSendInvalidReply = 0x10000009;
constexpr std::uint32_t kMachSendInvalidNotify = 0x1000000b;
constexpr std::uint32_t kMachSendNoBuffer = 0x1000000d;
constexpr std::uint32_t kMachSendTooLarge = 0x1000000e;
constexpr std::uint32_t kMachSendInvalidType = 0x1000000f;
constexpr std::uint32_t kMachSendInvalidHeader = 0x10000010;
constexpr std::uint32_t kMachRcvInvalidName = 0x10004002;
constexpr std::uint32_t kMachRcvTimedOut = 0x10004003;
constexpr std::uint32_t kMachRcvTooLarge = 0x10004004;
constexpr std::uint32_t kMachRcvInvalidData = 0x10004008;

constexpr std::uint32_t kMachSendMsg = 0x00000001;
constexpr std::uint32_t kMachRcvMsg = 0x00000002;
constexpr std::uint32_t kMachSendTimeout = 0x00000010;
constexpr std::uint32_t kMachRcvTimeout = 0x00000100;
constexpr std::uint32_t kMachMsgSimpleSupportedOptions =
    kMachSendMsg | kMachRcvMsg | kMachSendTimeout | kMachRcvTimeout;
constexpr std::uint32_t kMachMsgBitsRemoteMask = 0x0000001f;
constexpr std::uint32_t kMachMsgBitsLocalMask = 0x00001f00;
constexpr std::uint32_t kMachMsgBitsComplex = 0x80000000U;
constexpr std::size_t kMachMsgHeaderSize = 24;
constexpr std::size_t kMachMsgMaxInlineSize = 1024 * 1024;
constexpr std::size_t kMachMsgMaxQueueDepth = 64;

// Per-context identity for a translated guest thread, not a host pthread.
struct MachThreadIdentity {
    std::uint64_t thread_id{};
    std::uint32_t thread_self_port{};
};

class MachContext {
public:
    // Synthetic POSIX pid namespace: one stable pid per translated process
    // context, not the host pid or a promise of fork/exec support.
    static constexpr std::uint32_t kFirstSyntheticProcessId = 0x10000;
    static constexpr std::uint32_t kDefaultTaskSelfPort = 0x101;
    static constexpr std::uint32_t kDefaultThreadSelfPort = 0x102;
    // Single translated main-thread identity, scoped to a MachContext.
    // This is a userspace rehosting value, not an Apple kernel thread ID.
    static constexpr std::uint64_t kSyntheticMainThreadId = 0x100000001ULL;
    static constexpr std::uint32_t kFirstWorkerThreadPort = 0x10000;
    static constexpr std::size_t kMaxGuestThreads = 64;
    static constexpr std::uint32_t kDefaultHostSelfPort = 0x103;
    static constexpr std::uint32_t kFirstReplyPort = 0x2000;
    static constexpr std::size_t kMaxReplyPorts = 4096;
    static constexpr std::uint64_t kVmAnywhereBase = 0x1000000000ULL;

    MachContext();

    [[nodiscard]] std::uint32_t process_id() const noexcept { return process_id_; }
    [[nodiscard]] std::uint32_t task_self_port() const noexcept { return task_self_port_; }
    [[nodiscard]] std::uint32_t thread_self_port() const noexcept { return thread_self_port_; }
    [[nodiscard]] std::uint64_t thread_id() const noexcept { return thread_id_; }
    [[nodiscard]] std::uint32_t host_self_port() const noexcept { return host_self_port_; }
    [[nodiscard]] MachThreadIdentity main_thread_identity() const noexcept {
        return {thread_id_, thread_self_port_};
    }
    [[nodiscard]] std::optional<MachThreadIdentity> allocate_worker_thread_identity() noexcept;
    // Retire the exact live worker identity. Thread IDs and Mach port names
    // never recycle: stale guest handles must not resolve to a later worker.
    [[nodiscard]] bool retire_worker_thread_identity(MachThreadIdentity identity) noexcept;
    [[nodiscard]] bool is_active_worker_thread_identity(
        MachThreadIdentity identity) const noexcept;
    [[nodiscard]] bool acquire_host_self_send_right() noexcept;
    [[nodiscard]] bool has_host_self_send_right() const noexcept {
        return host_self_send_refs_ != 0;
    }
    [[nodiscard]] bool release_host_self_send_right() noexcept;
    [[nodiscard]] std::optional<std::uint32_t> allocate_reply_port();
    [[nodiscard]] bool rollback_reply_port_allocation(std::uint32_t port) noexcept;
    [[nodiscard]] bool is_receive_port(std::uint32_t port) const noexcept;
    [[nodiscard]] bool enqueue_message(std::uint32_t port, std::vector<std::byte> message);
    [[nodiscard]] const std::vector<std::byte>* peek_message(std::uint32_t port) const noexcept;
    [[nodiscard]] bool pop_message(std::uint32_t port) noexcept;
    [[nodiscard]] std::size_t queued_message_count(std::uint32_t port) const noexcept;

private:
    std::uint32_t process_id_{};
    std::uint32_t task_self_port_{kDefaultTaskSelfPort};
    std::uint32_t thread_self_port_{kDefaultThreadSelfPort};
    std::uint64_t thread_id_{kSyntheticMainThreadId};
    std::uint32_t host_self_port_{kDefaultHostSelfPort};
    std::uint32_t host_self_send_refs_{0};
    std::uint32_t next_reply_port_{kFirstReplyPort};
    // Bound *simultaneously* active workers, not lifetime thread creations.
    // The monotonic serial is intentionally separate from reclaimed slots.
    std::uint64_t next_worker_serial_{};
    std::array<std::optional<MachThreadIdentity>, kMaxGuestThreads - 1U>
        active_worker_threads_{};
    std::unordered_map<std::uint32_t, std::deque<std::vector<std::byte>>> receive_queues_;
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

[[nodiscard]] MachTrapDispatchResult dispatch_mach_trap(
    CpuState& state,
    GuestAddressSpace& address_space,
    const ExecutionResult& execution,
    MachContext& context,
    const MachThreadIdentity* current_thread);

[[nodiscard]] std::string_view mach_trap_dispatch_error_name(MachTrapDispatchError error) noexcept;

} // namespace macosarm
