#include "macosarm/dyld_authenticated_initialization.hpp"

namespace {

class DynarmicAuthenticatedInitializerHost final : public macosarm::DarwinHostServices {
public:
    [[nodiscard]] macosarm::HostWriteResult write(
        std::int32_t,
        std::span<const std::byte> bytes) override {
        return {bytes.size(), 0};
    }
};

void dynauth_put_instruction(
    std::array<std::byte, macosarm::GuestAddressSpace::kPageSize>& page,
    std::size_t offset,
    std::uint32_t instruction) {
    for (std::size_t index = 0; index < 4; ++index) {
        page.at(offset + index) =
            static_cast<std::byte>((instruction >> (index * 8U)) & 0xffU);
    }
}

bool dynauth_store_u64(
    macosarm::GuestAddressSpace& address_space,
    std::uint64_t address,
    std::uint64_t value) {
    std::array<std::byte, sizeof(std::uint64_t)> bytes{};
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        bytes[index] = static_cast<std::byte>((value >> (index * 8U)) & 0xffU);
    }
    return static_cast<bool>(address_space.write(address, bytes));
}

} // namespace

int dynarmic_authenticated_initializer_main() {
    using macosarm::CpuState;
    using macosarm::DynarmicBackend;
    using macosarm::GuestAddressSpace;
    using macosarm::PointerAuthKey;
    using macosarm::PointerAuthenticator;
    using macosarm::Protection;
    using macosarm::dyld::AuthenticatedFixupSlot;
    using macosarm::dyld::AuthenticatedInitializerPlanConfig;
    using macosarm::dyld::InitializerExecutionConfig;
    using macosarm::dyld::LoadedImageGraph;

    constexpr std::uint64_t code_base = 0x181000000ULL;
    constexpr std::uint64_t data_base = 0x182000000ULL;
    constexpr std::uint64_t initializer_slot = data_base + 0x100;
    constexpr std::uint64_t stack_pointer = 0x700000000ULL;
    constexpr std::uint16_t diversity = 0x4567;
    constexpr std::uint32_t paciasp = 0xd503233fU;
    constexpr std::uint32_t mov_x0_42 = 0xd2800540U;
    constexpr std::uint32_t autiasp = 0xd50323bfU;
    constexpr std::uint32_t ret = 0xd65f03c0U;

    GuestAddressSpace address_space;
    if (!address_space.map(
            code_base,
            GuestAddressSpace::kPageSize,
            Protection::read | Protection::execute)) {
        std::cerr << "FAIL: authenticated Dynarmic initializer code page maps\n";
        return EXIT_FAILURE;
    }
    if (!address_space.map(
            data_base,
            GuestAddressSpace::kPageSize,
            Protection::read | Protection::write)) {
        std::cerr << "FAIL: authenticated Dynarmic initializer pointer page maps\n";
        return EXIT_FAILURE;
    }

    std::array<std::byte, GuestAddressSpace::kPageSize> page{};
    dynauth_put_instruction(page, 0, paciasp);
    dynauth_put_instruction(page, 4, mov_x0_42);
    dynauth_put_instruction(page, 8, autiasp);
    dynauth_put_instruction(page, 12, ret);
    if (!address_space.load_bytes(code_base, page)) {
        std::cerr << "FAIL: authenticated Dynarmic initializer program loads\n";
        return EXIT_FAILURE;
    }

    const PointerAuthenticator authenticator(pauth_test_keys());
    const auto signed_initializer = authenticator.sign(
        code_base,
        PointerAuthKey::instruction_b,
        PointerAuthenticator::blend_discriminator(initializer_slot, diversity));
    if (!signed_initializer) {
        std::cerr << "FAIL: authenticated Dynarmic initializer pointer signs\n";
        return EXIT_FAILURE;
    }
    if (!dynauth_store_u64(
            address_space,
            initializer_slot,
            signed_initializer.pointer)) {
        std::cerr << "FAIL: authenticated Dynarmic initializer pointer stores\n";
        return EXIT_FAILURE;
    }

    LoadedImageGraph graph;
    graph.images.resize(1);
    macosarm::macho::InitializerPointerSection section;
    section.segment_name = "__DATA_CONST";
    section.section_name = "__mod_init_func";
    section.address = initializer_slot;
    section.size = sizeof(std::uint64_t);
    graph.images[0].initializers.pointer_sections.push_back(section);

    const std::vector<AuthenticatedFixupSlot> authenticated_slots{{
        initializer_slot,
        PointerAuthKey::instruction_b,
        diversity,
        true,
    }};
    AuthenticatedInitializerPlanConfig plan_config;
    plan_config.pointer_auth = &authenticator;
    plan_config.authenticated_slots = std::span<const AuthenticatedFixupSlot>(
        authenticated_slots.data(),
        authenticated_slots.size());

    CpuState state{};
    state.sp = stack_pointer;
    DynarmicBackend backend(pauth_test_keys());
    DynarmicAuthenticatedInitializerHost host;
    InitializerExecutionConfig execution_config;
    execution_config.instructions_per_initializer = 16;
    execution_config.total_instruction_budget = 16;

    const auto result = macosarm::dyld::initialize_image_graph_with_pointer_auth(
        graph,
        state,
        address_space,
        backend,
        host,
        plan_config,
        execution_config);
    if (!result) {
        std::cerr << "FAIL: signed initializer slot executes through real Dynarmic: "
                  << macosarm::dyld::authenticated_image_initialization_error_name(result.error)
                  << '\n';
        return EXIT_FAILURE;
    }
    if (result.planning.plan.calls.size() != 1 ||
        result.planning.plan.calls.front().address != code_base) {
        std::cerr << "FAIL: signed initializer slot authenticates to raw Dynarmic target\n";
        return EXIT_FAILURE;
    }
    if (result.execution.instructions_executed != 4) {
        std::cerr << "FAIL: authenticated Dynarmic initializer executes four instructions\n";
        return EXIT_FAILURE;
    }
    if (result.execution.initialized_images != std::vector<bool>({true})) {
        std::cerr << "FAIL: authenticated Dynarmic initializer commits image ledger\n";
        return EXIT_FAILURE;
    }
    if (state.x[0] != 42) {
        std::cerr << "FAIL: authenticated Dynarmic initializer body mutates x0\n";
        return EXIT_FAILURE;
    }
    if (state.pc != execution_config.return_sentinel ||
        state.x[30] != execution_config.return_sentinel) {
        std::cerr << "FAIL: authenticated Dynarmic initializer AUTIASP restores return sentinel\n";
        return EXIT_FAILURE;
    }

    std::cout << "authenticated Dynarmic initializer tests passed\n";
    return EXIT_SUCCESS;
}
