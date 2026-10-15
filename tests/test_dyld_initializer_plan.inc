#include "macosarm/dyld_initializers.hpp"

#include <array>

namespace {

macosarm::dyld::GraphDependency plan_edge(
    std::size_t target,
    macosarm::macho::DylibLoadKind kind = macosarm::macho::DylibLoadKind::normal) {
    macosarm::dyld::GraphDependency edge;
    edge.dependency.kind = kind;
    edge.state = macosarm::dyld::GraphDependencyState::loaded;
    edge.image_index = target;
    return edge;
}

bool plan_load_instruction(macosarm::GuestAddressSpace& vm, std::uint64_t address) {
    constexpr std::array<std::byte, 4> nop{
        std::byte{0x1f}, std::byte{0x20}, std::byte{0x03}, std::byte{0xd5}};
    return static_cast<bool>(vm.load_bytes(address, nop));
}

bool plan_store_u64(macosarm::GuestAddressSpace& vm, std::uint64_t address, std::uint64_t value) {
    std::array<std::byte, 8> bytes{};
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        bytes[index] = static_cast<std::byte>((value >> (index * 8U)) & 0xffU);
    }
    return static_cast<bool>(vm.write(address, bytes));
}

macosarm::macho::InitializerPointerSection plan_section(
    std::uint64_t address,
    std::uint64_t size) {
    macosarm::macho::InitializerPointerSection section;
    section.segment_name = "__DATA_CONST";
    section.section_name = "__mod_init_func";
    section.address = address;
    section.size = size;
    return section;
}

} // namespace

int dyld_initializer_plan_main() {
    using macosarm::GuestAddressSpace;
    using macosarm::Protection;
    using macosarm::VmError;
    using macosarm::dyld::InitializerKind;
    using macosarm::dyld::InitializerPlanConfig;
    using macosarm::dyld::InitializerPlanError;
    using macosarm::dyld::LoadedImageGraph;

    constexpr std::uint64_t code_root = 0x710000000ULL;
    constexpr std::uint64_t code_a = 0x710004000ULL;
    constexpr std::uint64_t code_up = 0x710008000ULL;
    constexpr std::uint64_t code_b = 0x71000c000ULL;
    constexpr std::uint64_t data = 0x720000000ULL;

    GuestAddressSpace vm;
    expect(static_cast<bool>(vm.map(code_root, GuestAddressSpace::kPageSize,
                                    Protection::read | Protection::execute)),
           "initializer planner maps root code page");
    expect(static_cast<bool>(vm.map(code_a, GuestAddressSpace::kPageSize,
                                    Protection::read | Protection::execute)),
           "initializer planner maps A code page");
    expect(static_cast<bool>(vm.map(code_up, GuestAddressSpace::kPageSize,
                                    Protection::read | Protection::execute)),
           "initializer planner maps upward code page");
    expect(static_cast<bool>(vm.map(code_b, GuestAddressSpace::kPageSize,
                                    Protection::read | Protection::execute)),
           "initializer planner maps B code page");
    expect(static_cast<bool>(vm.map(data, GuestAddressSpace::kPageSize,
                                    Protection::read | Protection::write)),
           "initializer planner maps pointer data page");

    const std::array<std::uint64_t, 7> executable_targets{
        code_root + 0x100,
        code_root + 0x200,
        code_a + 0x100,
        code_a + 0x200,
        code_a + 0x300,
        code_up + 0x100,
        code_b + 0x100,
    };
    for (std::uint64_t target : executable_targets) {
        expect(plan_load_instruction(vm, target), "initializer planner loads executable target");
    }
    expect(plan_store_u64(vm, data + 0x100, code_root + 0x200),
           "initializer planner stores root mod-init pointer");
    expect(plan_store_u64(vm, data + 0x200, code_a + 0x200),
           "initializer planner stores first A mod-init pointer");
    expect(plan_store_u64(vm, data + 0x208, code_a + 0x300),
           "initializer planner stores second A mod-init pointer");

    LoadedImageGraph graph;
    graph.images.resize(4);
    graph.images[0].path = "/app/root";
    graph.images[1].path = "/lib/A";
    graph.images[2].path = "/lib/Up";
    graph.images[3].path = "/lib/B";

    graph.images[0].dependencies.push_back(plan_edge(1));
    graph.images[0].dependencies.push_back(
        plan_edge(2, macosarm::macho::DylibLoadKind::upward));
    graph.images[1].dependencies.push_back(plan_edge(3));
    graph.images[3].dependencies.push_back(plan_edge(1));

    graph.images[0].initializers.routines = {code_root + 0x100, 0, true};
    graph.images[0].initializers.pointer_sections.push_back(plan_section(data + 0x100, 8));
    graph.images[1].initializers.routines = {code_a + 0x100, 0, true};
    graph.images[1].initializers.pointer_sections.push_back(plan_section(data + 0x200, 16));
    graph.images[2].initializers.routines = {code_up + 0x100, 0, true};
    graph.images[3].initializers.routines = {code_b + 0x100, 0, true};

    {
        const auto result = macosarm::dyld::plan_initializers(graph, vm);
        expect(static_cast<bool>(result), "initializer plan succeeds for cyclic graph");
        expect(result.plan.image_order == std::vector<std::size_t>({3, 1, 0, 2}),
               "initializer image order is dependency-first with upward image deferred");
        expect(result.plan.calls.size() == 7,
               "initializer plan records every routines and mod-init call exactly once");
        if (result.plan.calls.size() == 7) {
            expect(result.plan.calls[0].image_index == 3 &&
                       result.plan.calls[0].kind == InitializerKind::routines64 &&
                       result.plan.calls[0].address == code_b + 0x100,
                   "deep dependency initializer runs first");
            expect(result.plan.calls[1].image_index == 1 &&
                       result.plan.calls[1].kind == InitializerKind::routines64,
                   "LC_ROUTINES_64 precedes module initializers within image");
            expect(result.plan.calls[2].image_index == 1 &&
                       result.plan.calls[2].kind == InitializerKind::mod_init_func &&
                       result.plan.calls[2].entry_index == 0 &&
                       result.plan.calls[2].address == code_a + 0x200,
                   "first mod-init pointer follows legacy routines initializer");
            expect(result.plan.calls[3].image_index == 1 &&
                       result.plan.calls[3].entry_index == 1 &&
                       result.plan.calls[3].address == code_a + 0x300,
                   "mod-init pointer order is preserved");
            expect(result.plan.calls[4].image_index == 0 &&
                       result.plan.calls[5].image_index == 0,
                   "root initializers follow ordinary dependencies");
            expect(result.plan.calls[6].image_index == 2 &&
                       result.plan.calls[6].address == code_up + 0x100,
                   "upward-linked initializer is deferred until normal chain completes");
        }
    }

    {
        InitializerPlanConfig config;
        config.max_initializers = 3;
        const auto result = macosarm::dyld::plan_initializers(graph, vm, config);
        expect(result.error == InitializerPlanError::initializer_limit,
               "initializer count is bounded explicitly");
        expect(result.plan.calls.empty() && result.plan.image_order.empty(),
               "failed initializer planning does not leak a partial plan");
    }

    {
        LoadedImageGraph bad;
        bad.images.resize(1);
        bad.images[0].dependencies.push_back(plan_edge(99));
        const auto result = macosarm::dyld::plan_initializers(bad, vm);
        expect(result.error == InitializerPlanError::invalid_dependency_index,
               "invalid loaded dependency index is rejected");
        expect(result.failed_image_index == 0,
               "invalid dependency reports the image containing the bad edge");
    }

    {
        LoadedImageGraph bad;
        bad.images.resize(1);
        bad.images[0].initializers.pointer_sections.push_back(plan_section(data + 0x300, 8));
        expect(plan_store_u64(vm, data + 0x300, 0), "zero initializer pointer is stored for rejection test");
        const auto result = macosarm::dyld::plan_initializers(bad, vm);
        expect(result.error == InitializerPlanError::null_initializer,
               "null mod-init pointer is rejected explicitly");
        expect(result.failed_section_index == 0 && result.failed_entry_index == 0,
               "null pointer error identifies section entry");
    }

    {
        LoadedImageGraph bad;
        bad.images.resize(1);
        bad.images[0].initializers.pointer_sections.push_back(plan_section(data + 0x320, 8));
        expect(plan_store_u64(vm, data + 0x320, data + 0x380),
               "non-executable initializer pointer is stored for rejection test");
        const auto result = macosarm::dyld::plan_initializers(bad, vm);
        expect(result.error == InitializerPlanError::target_not_executable,
               "initializer target without execute permission is rejected");
        expect(result.vm_error == VmError::protection,
               "target execute-permission failure is preserved");
    }

    {
        LoadedImageGraph bad;
        bad.images.resize(1);
        bad.images[0].initializers.pointer_sections.push_back(plan_section(0x730000000ULL, 8));
        const auto result = macosarm::dyld::plan_initializers(bad, vm);
        expect(result.error == InitializerPlanError::pointer_read_failure,
               "unmapped mod-init pointer section is rejected");
        expect(result.vm_error == VmError::unmapped,
               "pointer read VM failure is preserved");
    }

    {
        LoadedImageGraph empty;
        const auto result = macosarm::dyld::plan_initializers(empty, vm);
        expect(result.error == InitializerPlanError::empty_graph,
               "empty graph cannot produce an initializer plan");
    }

    expect(macosarm::dyld::initializer_kind_name(InitializerKind::mod_init_func) == "mod_init_func",
           "initializer kind has stable name");
    expect(macosarm::dyld::initializer_plan_error_name(
               InitializerPlanError::target_not_executable) == "target_not_executable",
           "initializer plan error has stable name");

    if (failures != 0) {
        std::cerr << failures << " dyld initializer planning test(s) failed\n";
        return EXIT_FAILURE;
    }

    std::cout << "dyld initializer planning tests passed\n";
    return EXIT_SUCCESS;
}
