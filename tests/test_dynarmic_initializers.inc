#include "macosarm/dyld_initializer_execution.hpp"

namespace {

class DynarmicInitializerHost final : public macosarm::DarwinHostServices {
public:
    [[nodiscard]] macosarm::HostWriteResult write(
        std::int32_t,
        std::span<const std::byte> bytes) override {
        return {bytes.size(), 0};
    }
};

void dyninit_put_instruction(
    std::array<std::byte, macosarm::GuestAddressSpace::kPageSize>& page,
    std::size_t offset,
    std::uint32_t instruction) {
    for (std::size_t i = 0; i < 4; ++i) {
        page.at(offset + i) = static_cast<std::byte>((instruction >> (i * 8U)) & 0xffU);
    }
}

} // namespace

int dynarmic_initializer_main() {
    using macosarm::CpuState;
    using macosarm::DynarmicBackend;
    using macosarm::GuestAddressSpace;
    using macosarm::Protection;
    using macosarm::dyld::InitializerExecutionConfig;
    using macosarm::dyld::InitializerExecutionError;
    using macosarm::dyld::InitializerKind;
    using macosarm::dyld::InitializerPlan;
    using macosarm::dyld::LoadedImageGraph;

    constexpr std::uint64_t code_base = 0x180000000ULL;
    constexpr std::uint64_t stack_pointer = 0x700000000ULL;
    constexpr std::uint32_t paciasp = 0xd503233fU;
    constexpr std::uint32_t mov_x0_42 = 0xd2800540U;
    constexpr std::uint32_t autiasp = 0xd50323bfU;
    constexpr std::uint32_t ret = 0xd65f03c0U;

    GuestAddressSpace vm;
    if (!vm.map(
            code_base,
            GuestAddressSpace::kPageSize,
            Protection::read | Protection::execute)) {
        std::cerr << "FAIL: Dynarmic initializer code page maps\n";
        return EXIT_FAILURE;
    }

    std::array<std::byte, GuestAddressSpace::kPageSize> page{};
    dyninit_put_instruction(page, 0, paciasp);
    dyninit_put_instruction(page, 4, mov_x0_42);
    dyninit_put_instruction(page, 8, autiasp);
    dyninit_put_instruction(page, 12, ret);
    if (!vm.load_bytes(code_base, page)) {
        std::cerr << "FAIL: Dynarmic initializer program loads\n";
        return EXIT_FAILURE;
    }

    LoadedImageGraph graph;
    graph.images.resize(1);
    InitializerPlan plan;
    plan.image_order = {0};
    plan.calls.push_back({0, InitializerKind::mod_init_func, code_base, 0, 0});
    DynarmicInitializerHost host;

    {
        CpuState state{};
        state.sp = stack_pointer;
        DynarmicBackend backend(pauth_test_keys());
        InitializerExecutionConfig config;
        config.instructions_per_initializer = 16;
        config.total_instruction_budget = 16;
        config.context.argc = 7;

        const auto result = macosarm::dyld::execute_initializers(
            graph, plan, state, vm, backend, host, config);
        if (!result) {
            std::cerr << "FAIL: real Dynarmic PAUTH initializer executes: "
                      << macosarm::dyld::initializer_execution_error_name(result.error) << '\n';
            return EXIT_FAILURE;
        }
        if (result.instructions_executed != 4) {
            std::cerr << "FAIL: real Dynarmic initializer executes exactly four instructions\n";
            return EXIT_FAILURE;
        }
        if (result.initialized_images != std::vector<bool>({true})) {
            std::cerr << "FAIL: real Dynarmic initializer commits image ledger\n";
            return EXIT_FAILURE;
        }
        if (state.x[0] != 42) {
            std::cerr << "FAIL: translated initializer body mutates x0 through real Dynarmic\n";
            return EXIT_FAILURE;
        }
        if (state.pc != config.return_sentinel || state.x[30] != config.return_sentinel) {
            std::cerr << "FAIL: AUTIASP restores raw initializer return sentinel before RET\n";
            return EXIT_FAILURE;
        }
    }

    {
        CpuState state{};
        state.sp = stack_pointer;
        DynarmicBackend backend;
        const auto result = macosarm::dyld::execute_initializers(
            graph, plan, state, vm, backend, host);
        if (result.error != InitializerExecutionError::exception) {
            std::cerr << "FAIL: PAUTH initializer without explicit key policy traps\n";
            return EXIT_FAILURE;
        }
        if (result.initialized_images != std::vector<bool>({false})) {
            std::cerr << "FAIL: failed PAUTH initializer does not commit image ledger\n";
            return EXIT_FAILURE;
        }
    }

    std::cout << "Dynarmic image initializer tests passed\n";
    return EXIT_SUCCESS;
}
