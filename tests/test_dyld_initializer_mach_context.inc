namespace {

class ReplyPortInitializerBackend final : public macosarm::ExecutionBackend {
public:
    [[nodiscard]] macosarm::ExecutionResult run(
        macosarm::CpuState& state,
        macosarm::GuestAddressSpace&,
        std::uint64_t instruction_budget) override {
        if (instruction_budget != 1) {
            return {macosarm::StopReason::backend_error, 0, 0, macosarm::VmError::none};
        }
        if (step++ == 0) {
            state.x[16] = static_cast<std::uint64_t>(macosarm::kMachTrapReplyPort);
            state.pc += 4;
            return {
                macosarm::StopReason::supervisor_call,
                1,
                macosarm::kDarwinSvcImmediate,
                macosarm::VmError::none,
            };
        }
        returned_port = state.x[0];
        state.pc = state.x[30];
        return {macosarm::StopReason::instruction_budget, 1, 0, macosarm::VmError::none};
    }

    std::size_t step{};
    std::uint64_t returned_port{};
};

} // namespace

int dyld_initializer_mach_context_main() {
    using macosarm::CpuState;
    using macosarm::GuestAddressSpace;
    using macosarm::MachContext;
    using macosarm::Protection;
    using macosarm::dyld::InitializerExecutionConfig;

    constexpr std::uint64_t code = 0x748000000ULL;
    GuestAddressSpace vm;
    expect(static_cast<bool>(vm.map(
               code,
               GuestAddressSpace::kPageSize,
               Protection::read | Protection::execute)),
           "caller-owned Mach-context fixture maps code page");
    expect(execution_load_nop(vm, code + 0x100),
           "caller-owned Mach-context fixture loads initializer target");

    const auto graph = execution_graph(1);
    const auto plan = execution_plan({code + 0x100});
    InitializerTestHost host;
    MachContext mach_context;
    InitializerExecutionConfig config;
    config.mach_context = &mach_context;

    CpuState first_state{};
    ReplyPortInitializerBackend first_backend;
    const auto first = macosarm::dyld::execute_initializers(
        graph,
        plan,
        first_state,
        vm,
        first_backend,
        host,
        config);
    expect(static_cast<bool>(first) &&
               first_backend.returned_port == MachContext::kFirstReplyPort,
           "initializer uses caller-owned Mach namespace for first reply port");

    CpuState second_state{};
    ReplyPortInitializerBackend second_backend;
    const auto second = macosarm::dyld::execute_initializers(
        graph,
        plan,
        second_state,
        vm,
        second_backend,
        host,
        config);
    expect(static_cast<bool>(second) &&
               second_backend.returned_port == MachContext::kFirstReplyPort + 1U,
           "caller-owned Mach namespace persists across initializer executions");

    if (failures != 0) {
        std::cerr << failures << " caller-owned initializer Mach-context test(s) failed\n";
        return EXIT_FAILURE;
    }
    std::cout << "caller-owned initializer Mach-context tests passed\n";
    return EXIT_SUCCESS;
}
