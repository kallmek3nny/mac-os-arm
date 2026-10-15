#include "macosarm/dyld_authenticated_initialization.hpp"

namespace {

macosarm::PointerAuthKeySet authinit_keys() {
    macosarm::PointerAuthKeySet keys{};
    keys.values[0] = {0x0123456789abcdefULL, 0xfedcba9876543210ULL};
    keys.values[1] = {0x1111222233334444ULL, 0x5555666677778888ULL};
    keys.values[2] = {0x89abcdef01234567ULL, 0x76543210fedcba98ULL};
    keys.values[3] = {0x0f1e2d3c4b5a6978ULL, 0x8877665544332211ULL};
    return keys;
}

bool authinit_store_u64(
    macosarm::GuestAddressSpace& vm,
    std::uint64_t address,
    std::uint64_t value) {
    std::array<std::byte, sizeof(std::uint64_t)> bytes{};
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        bytes[index] = static_cast<std::byte>((value >> (index * 8U)) & 0xffU);
    }
    return static_cast<bool>(vm.write(address, bytes));
}

bool authinit_load_nop(macosarm::GuestAddressSpace& vm, std::uint64_t address) {
    constexpr std::array<std::byte, 4> nop{
        std::byte{0x1f}, std::byte{0x20}, std::byte{0x03}, std::byte{0xd5}};
    return static_cast<bool>(vm.load_bytes(address, nop));
}

macosarm::macho::InitializerPointerSection authinit_section(std::uint64_t address) {
    macosarm::macho::InitializerPointerSection section;
    section.segment_name = "__DATA_CONST";
    section.section_name = "__mod_init_func";
    section.address = address;
    section.size = sizeof(std::uint64_t);
    return section;
}

macosarm::dyld::AuthenticatedInitializerPlanConfig authinit_config(
    const macosarm::PointerAuthenticator* authenticator,
    const std::vector<macosarm::dyld::AuthenticatedFixupSlot>& slots) {
    macosarm::dyld::AuthenticatedInitializerPlanConfig config;
    config.pointer_auth = authenticator;
    config.authenticated_slots = std::span<const macosarm::dyld::AuthenticatedFixupSlot>(slots);
    return config;
}

} // namespace

int dyld_authenticated_initialization_main() {
    using macosarm::CpuState;
    using macosarm::GuestAddressSpace;
    using macosarm::PointerAuthError;
    using macosarm::PointerAuthKey;
    using macosarm::PointerAuthenticator;
    using macosarm::Protection;
    using macosarm::dyld::AuthenticatedFixupSlot;
    using macosarm::dyld::AuthenticatedImageInitializationError;
    using macosarm::dyld::AuthenticatedInitializerPlanError;
    using macosarm::dyld::LoadedImageGraph;

    constexpr std::uint64_t code = 0x790000000ULL;
    constexpr std::uint64_t data = 0x791000000ULL;
    constexpr std::uint64_t target = code + 0x100;
    constexpr std::uint64_t dependency_target = code + 0x200;
    constexpr std::uint64_t root_target = code + 0x300;
    constexpr std::uint64_t slot = data + 0x100;
    constexpr std::uint16_t diversity = 0x2468;

    GuestAddressSpace vm;
    expect(static_cast<bool>(vm.map(
               code,
               GuestAddressSpace::kPageSize,
               Protection::read | Protection::execute)),
           "authenticated initializer planner maps executable page");
    expect(static_cast<bool>(vm.map(
               data,
               GuestAddressSpace::kPageSize,
               Protection::read | Protection::write)),
           "authenticated initializer planner maps pointer page");
    expect(authinit_load_nop(vm, target),
           "authenticated initializer planner loads target instruction");
    expect(authinit_load_nop(vm, dependency_target),
           "authenticated initializer planner loads dependency target");
    expect(authinit_load_nop(vm, root_target),
           "authenticated initializer planner loads root target");

    const PointerAuthenticator authenticator(authinit_keys());
    const std::uint64_t discriminator =
        PointerAuthenticator::blend_discriminator(slot, diversity);
    const auto signed_target = authenticator.sign(
        target,
        PointerAuthKey::instruction_b,
        discriminator);
    expect(static_cast<bool>(signed_target),
           "authenticated initializer target signs for test setup");

    LoadedImageGraph graph;
    graph.images.resize(1);
    graph.images[0].initializers.pointer_sections.push_back(authinit_section(slot));

    const std::vector<AuthenticatedFixupSlot> slots{{
        slot,
        PointerAuthKey::instruction_b,
        diversity,
        true,
    }};

    {
        expect(authinit_store_u64(vm, slot, signed_target.pointer),
               "authenticated initializer stores signed pointer");
        const auto result = macosarm::dyld::plan_initializers_with_pointer_auth(
            graph,
            vm,
            authinit_config(&authenticator, slots));
        expect(static_cast<bool>(result),
               "authenticated initializer pointer resolves with correct policy");
        expect(result.plan.calls.size() == 1 &&
                   result.plan.calls.front().address == target,
               "authenticated initializer plan records recovered raw target");
    }

    {
        expect(authinit_store_u64(vm, slot, signed_target.pointer),
               "wrong-key test restores signed initializer pointer");
        std::vector<AuthenticatedFixupSlot> wrong = slots;
        wrong.front().key = PointerAuthKey::instruction_a;
        const auto result = macosarm::dyld::plan_initializers_with_pointer_auth(
            graph,
            vm,
            authinit_config(&authenticator, wrong));
        expect(result.error == AuthenticatedInitializerPlanError::pointer_auth_failure &&
                   result.pointer_auth_error == PointerAuthError::invalid_signature,
               "wrong authenticated initializer key fails explicitly");
    }

    {
        expect(authinit_store_u64(vm, slot, signed_target.pointer),
               "wrong-diversity test restores signed initializer pointer");
        std::vector<AuthenticatedFixupSlot> wrong = slots;
        ++wrong.front().diversity;
        const auto result = macosarm::dyld::plan_initializers_with_pointer_auth(
            graph,
            vm,
            authinit_config(&authenticator, wrong));
        expect(result.error == AuthenticatedInitializerPlanError::pointer_auth_failure &&
                   result.pointer_auth_error == PointerAuthError::invalid_signature,
               "wrong authenticated initializer diversity fails explicitly");
    }

    {
        const auto wrong_storage_signature = authenticator.sign(
            target,
            PointerAuthKey::instruction_b,
            PointerAuthenticator::blend_discriminator(slot + 8, diversity));
        expect(static_cast<bool>(wrong_storage_signature) &&
                   authinit_store_u64(vm, slot, wrong_storage_signature.pointer),
               "wrong-storage test stores mismatched address-diverse signature");
        const auto result = macosarm::dyld::plan_initializers_with_pointer_auth(
            graph,
            vm,
            authinit_config(&authenticator, slots));
        expect(result.error == AuthenticatedInitializerPlanError::pointer_auth_failure &&
                   result.failed_storage_address == slot,
               "wrong address-diversity storage address fails explicitly");
    }

    {
        expect(authinit_store_u64(vm, slot, signed_target.pointer),
               "missing-policy test restores signed initializer pointer");
        const auto result = macosarm::dyld::plan_initializers_with_pointer_auth(
            graph,
            vm,
            authinit_config(nullptr, slots));
        expect(result.error == AuthenticatedInitializerPlanError::pointer_auth_required,
               "authenticated initializer requires explicit pointer-auth policy");
    }

    {
        expect(authinit_store_u64(
                   vm,
                   slot,
                   signed_target.pointer ^ (std::uint64_t{1} << 48)),
               "tamper test stores modified signed initializer pointer");
        const auto result = macosarm::dyld::plan_initializers_with_pointer_auth(
            graph,
            vm,
            authinit_config(&authenticator, slots));
        expect(result.error == AuthenticatedInitializerPlanError::pointer_auth_failure &&
                   result.pointer_auth_error == PointerAuthError::invalid_signature,
               "tampered authenticated initializer pointer fails explicitly");
    }

    {
        expect(authinit_store_u64(vm, slot, target),
               "unauthenticated compatibility test stores raw pointer");
        const auto legacy = macosarm::dyld::plan_initializers(graph, vm);
        const auto authenticated = macosarm::dyld::plan_initializers_with_pointer_auth(
            graph,
            vm);
        expect(static_cast<bool>(legacy) && static_cast<bool>(authenticated),
               "unauthenticated initializer behavior remains accepted");
        expect(legacy.plan.image_order == authenticated.plan.image_order &&
                   legacy.plan.calls.size() == authenticated.plan.calls.size() &&
                   !authenticated.plan.calls.empty() &&
                   legacy.plan.calls.front().address == authenticated.plan.calls.front().address,
               "unauthenticated initializer planning remains unchanged");
    }

    {
        const auto misaligned = authenticator.sign(
            target + 2,
            PointerAuthKey::instruction_b,
            discriminator);
        expect(static_cast<bool>(misaligned) && authinit_store_u64(vm, slot, misaligned.pointer),
               "misalignment test stores validly signed unaligned target");
        const auto result = macosarm::dyld::plan_initializers_with_pointer_auth(
            graph,
            vm,
            authinit_config(&authenticator, slots));
        expect(result.error == AuthenticatedInitializerPlanError::target_misaligned,
               "authenticated initializer validates recovered target alignment");
    }

    {
        expect(authinit_store_u64(vm, slot, signed_target.pointer),
               "malformed metadata test restores signed pointer");
        std::vector<AuthenticatedFixupSlot> malformed{slots.front(), slots.front()};
        const auto result = macosarm::dyld::plan_initializers_with_pointer_auth(
            graph,
            vm,
            authinit_config(&authenticator, malformed));
        expect(result.error == AuthenticatedInitializerPlanError::malformed_authenticated_slot &&
                   result.plan.calls.empty() && result.plan.image_order.empty(),
               "duplicate retained authenticated-slot metadata fails closed");
    }

    {
        LoadedImageGraph ordered;
        ordered.images.resize(2);
        ordered.images[0].dependencies.push_back(plan_edge(1));
        ordered.images[0].initializers.routines = {root_target, 0, true};
        ordered.images[1].initializers.routines = {dependency_target, 0, true};
        const auto legacy = macosarm::dyld::plan_initializers(ordered, vm);
        const auto authenticated = macosarm::dyld::plan_initializers_with_pointer_auth(
            ordered,
            vm);
        expect(static_cast<bool>(legacy) && static_cast<bool>(authenticated) &&
                   authenticated.plan.image_order == std::vector<std::size_t>({1, 0}) &&
                   legacy.plan.image_order == authenticated.plan.image_order &&
                   authenticated.plan.calls.size() == 2 &&
                   authenticated.plan.calls[0].address == dependency_target &&
                   authenticated.plan.calls[1].address == root_target,
               "authenticated planner preserves phase23 dependency and initializer ordering");
    }

    {
        expect(authinit_store_u64(
                   vm,
                   slot,
                   authenticator.sign(
                       root_target,
                       PointerAuthKey::instruction_b,
                       discriminator).pointer),
               "ledger test stores authenticated root initializer pointer");
        LoadedImageGraph ledger_graph;
        ledger_graph.images.resize(2);
        ledger_graph.images[0].dependencies.push_back(plan_edge(1));
        ledger_graph.images[0].initializers.pointer_sections.push_back(authinit_section(slot));
        ledger_graph.images[1].initializers.routines = {dependency_target, 0, true};

        CpuState state{};
        ExceptionOnSecondCallBackend backend;
        InitializerTestHost host;
        const auto result = macosarm::dyld::initialize_image_graph_with_pointer_auth(
            ledger_graph,
            state,
            vm,
            backend,
            host,
            authinit_config(&authenticator, slots));
        expect(result.error == AuthenticatedImageInitializationError::execution_failure,
               "authenticated high-level initialization preserves execution failure");
        expect(result.execution.initialized_images == std::vector<bool>({false, true}),
               "failed current image stays uninitialized while completed dependency remains committed");
    }

    expect(macosarm::dyld::authenticated_initializer_plan_error_name(
               AuthenticatedInitializerPlanError::pointer_auth_failure) == "pointer_auth_failure",
           "authenticated initializer planning errors have stable names");

    if (failures != 0) {
        std::cerr << failures << " authenticated initializer test(s) failed\n";
        return EXIT_FAILURE;
    }

    std::cout << "authenticated initializer tests passed\n";
    return EXIT_SUCCESS;
}
