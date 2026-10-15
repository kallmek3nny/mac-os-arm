#include "macosarm/dyld_process_startup.hpp"

#include <array>
#include <string_view>

int process_startup_initializer_context_main() {
    using macosarm::CpuState;
    using macosarm::GuestAddressSpace;
    using macosarm::ProcessStartupConfig;
    using macosarm::Protection;
    using macosarm::dyld::InitializerExecutionConfig;

    constexpr std::uint64_t code = 0x7a0000000ULL;
    constexpr std::uint64_t stack = 0x7b0000000ULL;
    constexpr std::uint64_t program_vars = 0x12345000ULL;

    GuestAddressSpace vm;
    expect(static_cast<bool>(vm.map(
               code,
               GuestAddressSpace::kPageSize,
               Protection::read | Protection::execute)),
           "startup initializer bridge maps code page");
    expect(static_cast<bool>(vm.map(
               stack,
               GuestAddressSpace::kPageSize,
               Protection::read | Protection::write)),
           "startup initializer bridge maps stack page");
    expect(execution_load_nop(vm, code + 0x100),
           "startup initializer bridge loads initializer target");

    const std::array<std::string_view, 2> arguments{"demo", "arg"};
    const std::array<std::string_view, 1> environment{"MODE=test"};
    const std::array<std::string_view, 1> apple{"executable_path=demo"};
    ProcessStartupConfig startup_config;
    startup_config.arguments = std::span<const std::string_view>(arguments);
    startup_config.environment = std::span<const std::string_view>(environment);
    startup_config.apple = std::span<const std::string_view>(apple);
    const auto startup = macosarm::build_process_startup(
        vm,
        stack,
        GuestAddressSpace::kPageSize,
        startup_config);
    expect(static_cast<bool>(startup),
           "startup initializer bridge materializes process stack");

    const auto graph = execution_graph(1);
    const auto plan = execution_plan({code + 0x100});
    CpuState state{};
    state.sp = startup.layout.stack_pointer;
    ReturningInitializerBackend backend;
    InitializerTestHost host;
    InitializerExecutionConfig config;
    config.instructions_per_initializer = 1;
    config.total_instruction_budget = 1;
    config.context = macosarm::dyld::initializer_context_from_process_startup(
        startup.layout,
        program_vars);

    const auto result = macosarm::dyld::execute_initializers(
        graph,
        plan,
        state,
        vm,
        backend,
        host,
        config);
    expect(static_cast<bool>(result) && backend.entries.size() == 1,
           "startup initializer bridge executes one translated initializer");
    if (backend.entries.size() == 1) {
        const std::array<std::uint64_t, 5> expected{
            startup.layout.argc,
            startup.layout.argv,
            startup.layout.envp,
            startup.layout.apple,
            program_vars,
        };
        expect(backend.entries.front().args == expected,
               "process startup argc/argv/envp/apple flow into initializer x0-x3 unchanged");
    }

    if (failures != 0) {
        std::cerr << failures << " process startup initializer bridge test(s) failed\n";
        return EXIT_FAILURE;
    }
    std::cout << "process startup initializer bridge tests passed\n";
    return EXIT_SUCCESS;
}
