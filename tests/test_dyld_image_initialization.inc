#include "macosarm/dyld_image_initialization.hpp"

int dyld_image_initialization_main() {
    using macosarm::CpuState;
    using macosarm::GuestAddressSpace;
    using macosarm::Protection;
    using macosarm::dyld::ImageInitializationError;
    using macosarm::dyld::InitializerExecutionError;
    using macosarm::dyld::InitializerPlanError;
    using macosarm::dyld::LoadedImageGraph;

    constexpr std::uint64_t code = 0x770000000ULL;
    GuestAddressSpace vm;
    expect(static_cast<bool>(vm.map(
               code,
               GuestAddressSpace::kPageSize,
               Protection::read | Protection::execute)),
           "image initialization integration maps code page");
    expect(execution_load_nop(vm, code + 0x100),
           "image initialization integration loads root initializer target");
    expect(execution_load_nop(vm, code + 0x200),
           "image initialization integration loads dependency initializer target");

    InitializerTestHost host;

    {
        LoadedImageGraph graph;
        graph.images.resize(2);
        graph.images[0].dependencies.push_back(plan_edge(1));
        graph.images[0].initializers.routines = {code + 0x100, 0, true};
        graph.images[1].initializers.routines = {code + 0x200, 0, true};

        CpuState state{};
        ReturningInitializerBackend backend;
        const auto result = macosarm::dyld::initialize_image_graph(
            graph, state, vm, backend, host);

        expect(static_cast<bool>(result), "high-level image initialization succeeds");
        expect(result.planning.plan.image_order == std::vector<std::size_t>({1, 0}),
               "high-level image initialization plans dependency before dependent");
        expect(result.execution.initialized_images == std::vector<bool>({true, true}),
               "high-level image initialization commits complete ledger");
        expect(backend.entries.size() == 2 &&
                   backend.entries[0].pc == code + 0x200 &&
                   backend.entries[1].pc == code + 0x100,
               "high-level image initialization executes frozen dependency order");
    }

    {
        LoadedImageGraph graph;
        graph.images.resize(1);
        graph.images[0].initializers.routines = {0x780000000ULL, 0, true};

        CpuState state{};
        ReturningInitializerBackend backend;
        const auto result = macosarm::dyld::initialize_image_graph(
            graph, state, vm, backend, host);

        expect(result.error == ImageInitializationError::planning_failure,
               "planning failure stops high-level image initialization before guest execution");
        expect(result.planning.error == InitializerPlanError::target_not_executable,
               "high-level image initialization preserves planning detail");
        expect(backend.calls == 0,
               "planning failure produces no initializer guest side effects");
    }

    {
        LoadedImageGraph graph;
        graph.images.resize(2);
        graph.images[0].initializers.routines = {code + 0x100, 0, true};
        graph.images[1].initializers.routines = {code + 0x200, 0, true};

        CpuState state{};
        ExceptionOnSecondCallBackend backend;
        const auto result = macosarm::dyld::initialize_image_graph(
            graph, state, vm, backend, host);

        expect(result.error == ImageInitializationError::execution_failure,
               "guest initializer failure is distinguished from planning failure");
        expect(result.execution.error == InitializerExecutionError::exception,
               "high-level image initialization preserves execution failure detail");
        expect(result.execution.initialized_images == std::vector<bool>({true, false}),
               "high-level image initialization exposes partial committed ledger");
    }

    expect(macosarm::dyld::image_initialization_error_name(
               ImageInitializationError::planning_failure) == "planning_failure",
           "image initialization error has stable name");

    if (failures != 0) {
        std::cerr << failures << " dyld high-level image initialization test(s) failed\n";
        return EXIT_FAILURE;
    }

    std::cout << "dyld high-level image initialization tests passed\n";
    return EXIT_SUCCESS;
}
