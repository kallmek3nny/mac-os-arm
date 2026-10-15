#include "macosarm/dyld_initializer_execution.hpp"

#include <array>
#include <vector>

namespace {

class InitializerTestHost final : public macosarm::DarwinHostServices {
public:
    [[nodiscard]] macosarm::HostWriteResult write(
        std::int32_t,
        std::span<const std::byte> bytes) override {
        return {bytes.size(), 0};
    }
};

struct InitializerEntrySnapshot {
    std::uint64_t pc{};
    std::uint64_t lr{};
    std::array<std::uint64_t, 5> args{};
};

class ReturningInitializerBackend final : public macosarm::ExecutionBackend {
public:
    [[nodiscard]] macosarm::ExecutionResult run(
        macosarm::CpuState& state,
        macosarm::GuestAddressSpace&,
        std::uint64_t instruction_budget) override {
        ++calls;
        if (instruction_budget != 1) {
            return {macosarm::StopReason::backend_error, 0, 0, macosarm::VmError::none};
        }
        entries.push_back({
            state.pc,
            state.x[30],
            {state.x[0], state.x[1], state.x[2], state.x[3], state.x[4]},
        });
        state.pc = state.x[30];
        return {macosarm::StopReason::instruction_budget, 1, 0, macosarm::VmError::none};
    }

    std::size_t calls{};
    std::vector<InitializerEntrySnapshot> entries;
};

class LoopInitializerBackend final : public macosarm::ExecutionBackend {
public:
    [[nodiscard]] macosarm::ExecutionResult run(
        macosarm::CpuState& state,
        macosarm::GuestAddressSpace&,
        std::uint64_t) override {
        ++calls;
        state.pc += 4;
        return {macosarm::StopReason::instruction_budget, 1, 0, macosarm::VmError::none};
    }
    std::size_t calls{};
};

class SyscallThenReturnBackend final : public macosarm::ExecutionBackend {
public:
    [[nodiscard]] macosarm::ExecutionResult run(
        macosarm::CpuState& state,
        macosarm::GuestAddressSpace&,
        std::uint64_t) override {
        if (step++ == 0) {
            state.x[16] = 999;
            state.pc += 4;
            return {
                macosarm::StopReason::supervisor_call,
                1,
                macosarm::kDarwinSvcImmediate,
                macosarm::VmError::none,
            };
        }
        saw_enosys = state.x[0] == macosarm::kDarwinErrnoEnosys &&
                     (state.pstate & macosarm::kA64PstateCarry) != 0;
        state.pc = state.x[30];
        return {macosarm::StopReason::instruction_budget, 1, 0, macosarm::VmError::none};
    }

    std::size_t step{};
    bool saw_enosys{};
};

class MachThenReturnBackend final : public macosarm::ExecutionBackend {
public:
    [[nodiscard]] macosarm::ExecutionResult run(
        macosarm::CpuState& state,
        macosarm::GuestAddressSpace&,
        std::uint64_t) override {
        if (step++ == 0) {
            state.x[16] = static_cast<std::uint64_t>(macosarm::kMachTrapTaskSelf);
            state.pc += 4;
            return {
                macosarm::StopReason::supervisor_call,
                1,
                macosarm::kDarwinSvcImmediate,
                macosarm::VmError::none,
            };
        }
        saw_task_port = state.x[0] == macosarm::MachContext::kDefaultTaskSelfPort;
        state.pc = state.x[30];
        return {macosarm::StopReason::instruction_budget, 1, 0, macosarm::VmError::none};
    }

    std::size_t step{};
    bool saw_task_port{};
};

class ExitInitializerBackend final : public macosarm::ExecutionBackend {
public:
    [[nodiscard]] macosarm::ExecutionResult run(
        macosarm::CpuState& state,
        macosarm::GuestAddressSpace&,
        std::uint64_t) override {
        state.x[16] = macosarm::kDarwinSysExit;
        state.x[0] = 23;
        state.pc += 4;
        return {
            macosarm::StopReason::supervisor_call,
            1,
            macosarm::kDarwinSvcImmediate,
            macosarm::VmError::none,
        };
    }
};

class SyscallErrorBackend final : public macosarm::ExecutionBackend {
public:
    [[nodiscard]] macosarm::ExecutionResult run(
        macosarm::CpuState& state,
        macosarm::GuestAddressSpace&,
        std::uint64_t) override {
        state.x[16] = 999;
        state.pc += 4;
        return {macosarm::StopReason::supervisor_call, 1, 0, macosarm::VmError::none};
    }
};

class MachErrorBackend final : public macosarm::ExecutionBackend {
public:
    [[nodiscard]] macosarm::ExecutionResult run(
        macosarm::CpuState& state,
        macosarm::GuestAddressSpace&,
        std::uint64_t) override {
        state.x[16] = static_cast<std::uint64_t>(static_cast<std::int64_t>(-999));
        state.pc += 4;
        return {
            macosarm::StopReason::supervisor_call,
            1,
            macosarm::kDarwinSvcImmediate,
            macosarm::VmError::none,
        };
    }
};

class ExceptionOnSecondCallBackend final : public macosarm::ExecutionBackend {
public:
    [[nodiscard]] macosarm::ExecutionResult run(
        macosarm::CpuState& state,
        macosarm::GuestAddressSpace&,
        std::uint64_t) override {
        if (calls++ == 0) {
            state.pc = state.x[30];
            return {macosarm::StopReason::instruction_budget, 1, 0, macosarm::VmError::none};
        }
        return {macosarm::StopReason::exception, 1, 0, macosarm::VmError::none};
    }
    std::size_t calls{};
};

class MemoryFaultInitializerBackend final : public macosarm::ExecutionBackend {
public:
    [[nodiscard]] macosarm::ExecutionResult run(
        macosarm::CpuState&,
        macosarm::GuestAddressSpace&,
        std::uint64_t) override {
        return {macosarm::StopReason::memory_fault, 0, 0, macosarm::VmError::unmapped};
    }
};

class ContractViolationInitializerBackend final : public macosarm::ExecutionBackend {
public:
    [[nodiscard]] macosarm::ExecutionResult run(
        macosarm::CpuState&,
        macosarm::GuestAddressSpace&,
        std::uint64_t) override {
        return {macosarm::StopReason::instruction_budget, 2, 0, macosarm::VmError::none};
    }
};

macosarm::dyld::InitializerPlan execution_plan(
    std::initializer_list<std::uint64_t> addresses) {
    macosarm::dyld::InitializerPlan plan;
    std::size_t image_index = 0;
    for (std::uint64_t address : addresses) {
        plan.image_order.push_back(image_index);
        plan.calls.push_back({
            image_index,
            macosarm::dyld::InitializerKind::mod_init_func,
            address,
            0,
            0,
        });
        ++image_index;
    }
    return plan;
}

macosarm::dyld::LoadedImageGraph execution_graph(std::size_t image_count) {
    macosarm::dyld::LoadedImageGraph graph;
    graph.images.resize(image_count);
    return graph;
}

bool execution_load_nop(macosarm::GuestAddressSpace& vm, std::uint64_t address) {
    constexpr std::array<std::byte, 4> nop{
        std::byte{0x1f}, std::byte{0x20}, std::byte{0x03}, std::byte{0xd5}};
    return static_cast<bool>(vm.load_bytes(address, nop));
}

} // namespace

int dyld_initializer_execution_main() {
    using macosarm::CpuState;
    using macosarm::GuestAddressSpace;
    using macosarm::Protection;
    using macosarm::SyscallDispatchError;
    using macosarm::VmError;
    using macosarm::dyld::InitializerExecutionConfig;
    using macosarm::dyld::InitializerExecutionError;

    constexpr std::uint64_t code = 0x740000000ULL;
    GuestAddressSpace vm;
    expect(static_cast<bool>(vm.map(
               code,
               GuestAddressSpace::kPageSize,
               Protection::read | Protection::execute)),
           "initializer executor maps code page");
    for (std::uint64_t offset : {0x100ULL, 0x200ULL, 0x300ULL, 0x400ULL}) {
        expect(execution_load_nop(vm, code + offset),
               "initializer executor loads target instruction");
    }

    InitializerTestHost host;

    {
        auto graph = execution_graph(2);
        const auto plan = execution_plan({code + 0x100, code + 0x200});
        CpuState state{};
        state.sp = 0x750000000ULL;
        ReturningInitializerBackend backend;
        InitializerExecutionConfig config;
        config.context = {7, 0x1110, 0x2220, 0x3330, 0x4440};

        const auto result = macosarm::dyld::execute_initializers(
            graph, plan, state, vm, backend, host, config);
        expect(static_cast<bool>(result), "bounded initializer executor returns success");
        expect(result.instructions_executed == 2, "initializer executor counts translated instructions");
        expect(result.initialized_images == std::vector<bool>({true, true}),
               "initializer ledger commits each fully completed image");
        expect(backend.entries.size() == 2, "backend sees both initializer calls exactly once");
        if (backend.entries.size() == 2) {
            expect(backend.entries[0].pc == code + 0x100 &&
                       backend.entries[1].pc == code + 0x200,
                   "initializer call order follows frozen plan");
            expect(backend.entries[0].lr == config.return_sentinel &&
                       backend.entries[1].lr == config.return_sentinel,
                   "each initializer receives unmapped return sentinel in LR");
            const std::array<std::uint64_t, 5> expected_args{
                7, 0x1110, 0x2220, 0x3330, 0x4440};
            expect(backend.entries[0].args == expected_args &&
                       backend.entries[1].args == expected_args,
                   "initializer ABI context is loaded into x0 through x4 for every call");
        }
    }

    {
        auto graph = execution_graph(1);
        const auto plan = execution_plan({code + 0x100});
        CpuState state{};
        SyscallThenReturnBackend backend;
        const auto result = macosarm::dyld::execute_initializers(
            graph, plan, state, vm, backend, host);
        expect(static_cast<bool>(result), "initializer can resume after Darwin syscall dispatch");
        expect(backend.saw_enosys, "unsupported positive Darwin syscall resumes with ENOSYS ABI result");
        expect(result.instructions_executed == 2, "syscall and return both count toward initializer budget");
    }

    {
        auto graph = execution_graph(1);
        const auto plan = execution_plan({code + 0x100});
        CpuState state{};
        MachThenReturnBackend backend;
        const auto result = macosarm::dyld::execute_initializers(
            graph, plan, state, vm, backend, host);
        expect(static_cast<bool>(result), "initializer can resume after Mach trap dispatch");
        expect(backend.saw_task_port, "Mach task-self trap result is visible to translated initializer");
    }

    {
        auto graph = execution_graph(1);
        const auto plan = execution_plan({code + 0x100});
        CpuState state{};
        ExitInitializerBackend backend;
        const auto result = macosarm::dyld::execute_initializers(
            graph, plan, state, vm, backend, host);
        expect(result.error == InitializerExecutionError::initializer_requested_exit,
               "exit syscall during initializer is an explicit bootstrap failure");
        expect(result.exit_status == 23, "initializer exit status is preserved");
        expect(result.initialized_images == std::vector<bool>({false}),
               "image is not committed initialized when initializer requests exit");
    }

    {
        auto graph = execution_graph(1);
        const auto plan = execution_plan({code + 0x100});
        CpuState state{};
        SyscallErrorBackend backend;
        const auto result = macosarm::dyld::execute_initializers(
            graph, plan, state, vm, backend, host);
        expect(result.error == InitializerExecutionError::syscall_error,
               "bad SVC immediate is surfaced as initializer syscall error");
        expect(result.syscall_error == SyscallDispatchError::unsupported_svc,
               "initializer syscall dispatch detail is preserved");
    }

    {
        auto graph = execution_graph(1);
        const auto plan = execution_plan({code + 0x100});
        CpuState state{};
        MachErrorBackend backend;
        const auto result = macosarm::dyld::execute_initializers(
            graph, plan, state, vm, backend, host);
        expect(result.error == InitializerExecutionError::mach_trap_error,
               "unsupported Mach trap is surfaced during initializer execution");
        expect(result.mach_trap_error == macosarm::MachTrapDispatchError::unsupported_trap,
               "initializer Mach trap error detail is preserved");
    }

    {
        auto graph = execution_graph(2);
        const auto plan = execution_plan({code + 0x100, code + 0x200});
        CpuState state{};
        ExceptionOnSecondCallBackend backend;
        const auto result = macosarm::dyld::execute_initializers(
            graph, plan, state, vm, backend, host);
        expect(result.error == InitializerExecutionError::exception,
               "translated exception aborts initializer execution");
        expect(result.failed_image_index == 1 && result.failed_call_index == 1,
               "initializer exception identifies exact image and call");
        expect(result.initialized_images == std::vector<bool>({true, false}),
               "ledger preserves prior completed image but does not commit failing image");
    }

    {
        auto graph = execution_graph(1);
        const auto plan = execution_plan({code + 0x100});
        CpuState state{};
        LoopInitializerBackend backend;
        InitializerExecutionConfig config;
        config.instructions_per_initializer = 2;
        config.total_instruction_budget = 10;
        const auto result = macosarm::dyld::execute_initializers(
            graph, plan, state, vm, backend, host, config);
        expect(result.error == InitializerExecutionError::initializer_instruction_budget,
               "per-initializer execution budget is hard bounded");
        expect(result.instructions_executed == 2 && backend.calls == 2,
               "per-initializer budget stops before a third backend step");
    }

    {
        auto graph = execution_graph(1);
        const auto plan = execution_plan({code + 0x100});
        CpuState state{};
        LoopInitializerBackend backend;
        InitializerExecutionConfig config;
        config.instructions_per_initializer = 10;
        config.total_instruction_budget = 2;
        const auto result = macosarm::dyld::execute_initializers(
            graph, plan, state, vm, backend, host, config);
        expect(result.error == InitializerExecutionError::total_instruction_budget,
               "total initializer execution budget is hard bounded");
        expect(result.instructions_executed == 2 && backend.calls == 2,
               "total initializer budget stops before a third backend step");
    }

    {
        auto graph = execution_graph(1);
        const auto plan = execution_plan({code + 0x100});
        CpuState state{};
        MemoryFaultInitializerBackend backend;
        const auto result = macosarm::dyld::execute_initializers(
            graph, plan, state, vm, backend, host);
        expect(result.error == InitializerExecutionError::memory_fault,
               "initializer backend memory fault is explicit");
        expect(result.vm_error == VmError::unmapped,
               "initializer memory fault preserves VM detail");
    }

    {
        auto graph = execution_graph(1);
        const auto plan = execution_plan({code + 0x100});
        CpuState state{};
        ContractViolationInitializerBackend backend;
        const auto result = macosarm::dyld::execute_initializers(
            graph, plan, state, vm, backend, host);
        expect(result.error == InitializerExecutionError::backend_contract_violation,
               "backend cannot claim more than one instruction from one-step initializer runner");
    }

    {
        auto graph = execution_graph(1);
        auto plan = execution_plan({code + 0x100});
        plan.image_order = {0, 0};
        CpuState state{};
        ReturningInitializerBackend backend;
        const auto result = macosarm::dyld::execute_initializers(
            graph, plan, state, vm, backend, host);
        expect(result.error == InitializerExecutionError::invalid_plan,
               "malformed duplicate image order is rejected before execution");
        expect(backend.calls == 0, "invalid initializer plan has no guest side effects");
    }

    {
        auto graph = execution_graph(1);
        const auto plan = execution_plan({code + 0x100});
        CpuState state{};
        ReturningInitializerBackend backend;
        InitializerExecutionConfig config;
        config.return_sentinel = code + 0x800;
        const auto result = macosarm::dyld::execute_initializers(
            graph, plan, state, vm, backend, host, config);
        expect(result.error == InitializerExecutionError::return_sentinel_mapped,
               "return sentinel must not alias any guest mapping");
        expect(backend.calls == 0, "mapped return sentinel is rejected before execution");
    }

    {
        auto graph = execution_graph(1);
        const auto plan = execution_plan({code + 0x100});
        CpuState state{};
        ReturningInitializerBackend backend;
        InitializerExecutionConfig config;
        config.return_sentinel = 3;
        const auto result = macosarm::dyld::execute_initializers(
            graph, plan, state, vm, backend, host, config);
        expect(result.error == InitializerExecutionError::invalid_config,
               "unaligned return sentinel is rejected before execution");
    }

    {
        auto graph = execution_graph(1);
        macosarm::dyld::InitializerPlan plan;
        plan.image_order = {0};
        plan.calls.push_back({0, macosarm::dyld::InitializerKind::mod_init_func,
                              0x760000000ULL, 0, 0});
        CpuState state{};
        ReturningInitializerBackend backend;
        const auto result = macosarm::dyld::execute_initializers(
            graph, plan, state, vm, backend, host);
        expect(result.error == InitializerExecutionError::target_not_executable,
               "initializer target is revalidated immediately before execution");
        expect(result.vm_error == VmError::unmapped,
               "initializer target validation preserves fetch VM error");
    }

    expect(macosarm::dyld::initializer_execution_error_name(
               InitializerExecutionError::initializer_requested_exit) ==
               "initializer_requested_exit",
           "initializer execution error has stable name");

    if (failures != 0) {
        std::cerr << failures << " dyld initializer execution test(s) failed\n";
        return EXIT_FAILURE;
    }

    std::cout << "dyld initializer execution tests passed\n";
    return EXIT_SUCCESS;
}
