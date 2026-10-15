#include "macosarm/mach_trap.hpp"

#include "macosarm/darwin_syscall.hpp"

#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <span>
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

void write_u64(macosarm::GuestAddressSpace& vm, std::uint64_t address, std::uint64_t value) {
    std::array<std::byte, 8> bytes{};
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        bytes[i] = static_cast<std::byte>((value >> (i * 8)) & 0xffU);
    }
    expect(static_cast<bool>(vm.write(address, bytes)), "test writes guest u64");
}

std::uint64_t read_u64(const macosarm::GuestAddressSpace& vm, std::uint64_t address) {
    std::array<std::byte, 8> bytes{};
    expect(static_cast<bool>(vm.read(address, bytes)), "test reads guest u64");
    std::uint64_t value = 0;
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        value |= static_cast<std::uint64_t>(std::to_integer<unsigned char>(bytes[i])) << (i * 8);
    }
    return value;
}

bool has_mapping(
    const macosarm::GuestAddressSpace& vm,
    std::uint64_t base,
    std::uint64_t size,
    macosarm::Protection protection) {
    for (const auto& mapping : vm.mappings()) {
        if (mapping.base == base && mapping.size == size && mapping.protection == protection) {
            return true;
        }
    }
    return false;
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

    constexpr std::uint64_t control_base = 0x300000000ULL;
    expect(static_cast<bool>(vm.map(
               control_base,
               macosarm::GuestAddressSpace::kPageSize,
               macosarm::Protection::read | macosarm::Protection::write)),
           "Mach VM control page maps");

    state.x[0] = context.task_self_port();
    state.x[1] = control_base;
    state.x[2] = macosarm::GuestAddressSpace::kPageSize + 1;
    state.x[3] = macosarm::kMachVmFlagsAnywhere;
    set_trap(state, macosarm::kMachTrapVmAllocate);
    result = macosarm::dispatch_mach_trap(state, vm, svc(), context);
    expect(static_cast<bool>(result), "mach_vm_allocate dispatch succeeds");
    expect(state.x[0] == macosarm::kMachKernSuccess, "mach_vm_allocate returns KERN_SUCCESS");

    const std::uint64_t allocated = read_u64(vm, control_base);
    constexpr std::uint64_t rounded_two_pages = macosarm::GuestAddressSpace::kPageSize * 2;
    expect(allocated == macosarm::MachContext::kVmAnywhereBase,
           "VM_FLAGS_ANYWHERE starts at deterministic high guest base");
    expect(has_mapping(
               vm,
               allocated,
               rounded_two_pages,
               macosarm::Protection::read | macosarm::Protection::write),
           "mach_vm_allocate rounds size to 16K pages and creates RW mapping");

    state.x[0] = context.task_self_port();
    state.x[1] = allocated;
    state.x[2] = macosarm::GuestAddressSpace::kPageSize + 1;
    state.x[3] = 0;
    state.x[4] = macosarm::kMachVmProtRead;
    set_trap(state, macosarm::kMachTrapVmProtect);
    result = macosarm::dispatch_mach_trap(state, vm, svc(), context);
    expect(static_cast<bool>(result), "mach_vm_protect dispatch succeeds");
    expect(state.x[0] == macosarm::kMachKernSuccess, "mach_vm_protect returns KERN_SUCCESS");
    expect(has_mapping(vm, allocated, rounded_two_pages, macosarm::Protection::read),
           "mach_vm_protect updates guest mapping protection");

    const std::array<std::byte, 1> byte{std::byte{0x5a}};
    expect(vm.write(allocated, byte).error == macosarm::VmError::protection,
           "Mach-protected read-only mapping rejects guest writes");

    state.x[0] = context.task_self_port();
    state.x[1] = allocated;
    state.x[2] = macosarm::GuestAddressSpace::kPageSize + 1;
    set_trap(state, macosarm::kMachTrapVmDeallocate);
    result = macosarm::dispatch_mach_trap(state, vm, svc(), context);
    expect(static_cast<bool>(result), "mach_vm_deallocate dispatch succeeds");
    expect(state.x[0] == macosarm::kMachKernSuccess, "mach_vm_deallocate returns KERN_SUCCESS");
    std::array<std::byte, 1> output{};
    expect(vm.read(allocated, output).error == macosarm::VmError::unmapped,
           "mach_vm_deallocate removes the mapping");

    const std::size_t mappings_before_bad_copyout = vm.mappings().size();
    state.x[0] = context.task_self_port();
    state.x[1] = 0xdead00000000ULL;
    state.x[2] = macosarm::GuestAddressSpace::kPageSize;
    state.x[3] = macosarm::kMachVmFlagsAnywhere;
    set_trap(state, macosarm::kMachTrapVmAllocate);
    result = macosarm::dispatch_mach_trap(state, vm, svc(), context);
    expect(static_cast<bool>(result), "bad allocation copyout is a guest-visible Mach failure");
    expect(state.x[0] == macosarm::kMachKernInvalidAddress,
           "bad allocation output pointer returns KERN_INVALID_ADDRESS");
    expect(vm.mappings().size() == mappings_before_bad_copyout,
           "failed allocation copyout rolls back newly created guest mapping");

    constexpr std::uint64_t fixed_base = macosarm::MachContext::kVmAnywhereBase + 0x100000ULL;
    write_u64(vm, control_base, fixed_base);
    state.x[0] = context.task_self_port();
    state.x[1] = control_base;
    state.x[2] = macosarm::GuestAddressSpace::kPageSize;
    state.x[3] = 0;
    set_trap(state, macosarm::kMachTrapVmAllocate);
    result = macosarm::dispatch_mach_trap(state, vm, svc(), context);
    expect(static_cast<bool>(result) && state.x[0] == macosarm::kMachKernSuccess,
           "fixed mach_vm_allocate succeeds at requested address");
    expect(read_u64(vm, control_base) == fixed_base,
           "fixed mach_vm_allocate preserves requested address");

    state.x[0] = context.task_self_port();
    state.x[1] = fixed_base;
    state.x[2] = macosarm::GuestAddressSpace::kPageSize;
    set_trap(state, macosarm::kMachTrapVmDeallocate);
    result = macosarm::dispatch_mach_trap(state, vm, svc(), context);
    expect(static_cast<bool>(result) && state.x[0] == macosarm::kMachKernSuccess,
           "fixed allocation can be deallocated");

    state.x[0] = 0x9999;
    state.x[1] = control_base;
    state.x[2] = macosarm::GuestAddressSpace::kPageSize;
    state.x[3] = macosarm::kMachVmFlagsAnywhere;
    set_trap(state, macosarm::kMachTrapVmAllocate);
    result = macosarm::dispatch_mach_trap(state, vm, svc(), context);
    expect(static_cast<bool>(result), "invalid task target remains a handled Mach trap");
    expect(state.x[0] == macosarm::kMachKernInvalidArgument,
           "invalid task target returns KERN_INVALID_ARGUMENT");

    set_trap(state, macosarm::kMachTrapVmMap);
    result = macosarm::dispatch_mach_trap(state, vm, svc(), context);
    expect(result.error == macosarm::MachTrapDispatchError::unsupported_trap,
           "mach_vm_map remains explicitly unsupported until object semantics exist");

    constexpr std::int64_t unknown_mach_trap = -999;
    set_trap(state, unknown_mach_trap);
    result = macosarm::dispatch_mach_trap(state, vm, svc(), context);
    expect(result.error == macosarm::MachTrapDispatchError::unsupported_trap,
           "unknown negative Mach trap is rejected explicitly");
    expect(result.trap_number == unknown_mach_trap,
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
