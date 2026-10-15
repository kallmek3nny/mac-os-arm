#include "macosarm/mach_trap.hpp"

#include "macosarm/darwin_syscall.hpp"

#include <bit>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>

namespace {

int failures = 0;

void expect(bool condition, const std::string& label) {
    if (!condition) {
        std::cerr << "FAIL: " << label << '\n';
        ++failures;
    }
}

macosarm::ExecutionResult svc(std::uint32_t immediate = macosarm::kDarwinSvcImmediate) {
    return {
        macosarm::StopReason::supervisor_call,
        1,
        immediate,
        macosarm::VmError::none,
    };
}

void set_trap(macosarm::CpuState& state, std::int64_t trap_number) {
    state.x[16] = std::bit_cast<std::uint64_t>(trap_number);
}

} // namespace

int main() {
    macosarm::GuestAddressSpace vm;
    macosarm::MachContext context;
    macosarm::CpuState state{};

    set_trap(state, macosarm::kMachTrapTaskSelf);
    auto result = macosarm::dispatch_mach_trap(state, vm, svc(), context);
    expect(static_cast<bool>(result), "task_self trap succeeds");
    expect(state.x[0] == macosarm::MachContext::kDefaultTaskSelfPort,
           "task_self returns stable synthetic task port");
    expect(result.returned_port == state.x[0], "task_self result reports returned port");

    state.x[0] = 0;
    result = macosarm::dispatch_mach_trap(state, vm, svc(), context);
    expect(static_cast<bool>(result), "repeated task_self succeeds");
    expect(state.x[0] == macosarm::MachContext::kDefaultTaskSelfPort,
           "repeated task_self preserves port identity");

    set_trap(state, macosarm::kMachTrapThreadSelf);
    result = macosarm::dispatch_mach_trap(state, vm, svc(), context);
    expect(static_cast<bool>(result), "thread_self trap succeeds");
    expect(state.x[0] == macosarm::MachContext::kDefaultThreadSelfPort,
           "thread_self returns synthetic thread port");

    set_trap(state, macosarm::kMachTrapHostSelf);
    result = macosarm::dispatch_mach_trap(state, vm, svc(), context);
    expect(static_cast<bool>(result), "host_self trap succeeds");
    expect(state.x[0] == macosarm::MachContext::kDefaultHostSelfPort,
           "host_self returns synthetic host port");

    set_trap(state, macosarm::kMachTrapReplyPort);
    const auto first_reply = macosarm::dispatch_mach_trap(state, vm, svc(), context);
    const std::uint64_t first_port = state.x[0];
    const auto second_reply = macosarm::dispatch_mach_trap(state, vm, svc(), context);
    const std::uint64_t second_port = state.x[0];
    expect(static_cast<bool>(first_reply) && static_cast<bool>(second_reply),
           "reply-port allocation succeeds repeatedly");
    expect(first_port == macosarm::MachContext::kFirstReplyPort,
           "first reply port starts at deterministic namespace base");
    expect(second_port == first_port + 1, "reply ports are unique and monotonic");

    set_trap(state, macosarm::kMachTrapMessage);
    result = macosarm::dispatch_mach_trap(state, vm, svc(), context);
    expect(result.error == macosarm::MachTrapDispatchError::unsupported_trap,
           "unimplemented negative Mach trap is rejected explicitly");
    expect(result.trap_number == macosarm::kMachTrapMessage,
           "unsupported Mach trap preserves signed trap number");

    state.x[16] = macosarm::kDarwinSysWrite;
    result = macosarm::dispatch_mach_trap(state, vm, svc(), context);
    expect(result.error == macosarm::MachTrapDispatchError::not_mach_trap,
           "nonnegative BSD syscall is not misrouted as Mach");

    set_trap(state, macosarm::kMachTrapTaskSelf);
    result = macosarm::dispatch_mach_trap(state, vm, svc(0x42), context);
    expect(result.error == macosarm::MachTrapDispatchError::unsupported_svc,
           "wrong SVC immediate is rejected");

    macosarm::ExecutionResult non_svc{};
    non_svc.reason = macosarm::StopReason::instruction_budget;
    result = macosarm::dispatch_mach_trap(state, vm, non_svc, context);
    expect(result.error == macosarm::MachTrapDispatchError::not_supervisor_call,
           "non-SVC backend stop is rejected");

    expect(macosarm::decode_darwin_trap_number(state) == macosarm::kMachTrapTaskSelf,
           "x16 decoding preserves negative Mach trap sign");

    if (failures != 0) {
        std::cerr << failures << " test(s) failed\n";
        return EXIT_FAILURE;
    }

    std::cout << "Mach trap dispatch tests passed\n";
    return EXIT_SUCCESS;
}
