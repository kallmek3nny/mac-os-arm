#include "macosarm/dyld_graph_bootstrap.hpp"

namespace {

constexpr std::size_t kBootstrapOldSegmentSize = 72U;
constexpr std::size_t kBootstrapSectionSize = 80U;
constexpr std::size_t kBootstrapSegmentSize =
    kBootstrapOldSegmentSize + kBootstrapSectionSize;

std::vector<std::byte> bootstrap_add_initializer_pointer_section(
    std::vector<std::byte> bytes,
    std::uint64_t vm_address,
    std::uint32_t slot_offset) {
    const std::uint32_t command_bytes = graphfix_read_u32(bytes, 20);
    const std::size_t segment = 32U;
    const std::size_t old_segment_end = segment + kBootstrapOldSegmentSize;
    const std::size_t commands_end = 32U + static_cast<std::size_t>(command_bytes);
    if (commands_end + kBootstrapSectionSize > 0x200U ||
        old_segment_end > commands_end) {
        std::abort();
    }

    std::move_backward(
        bytes.begin() + static_cast<std::ptrdiff_t>(old_segment_end),
        bytes.begin() + static_cast<std::ptrdiff_t>(commands_end),
        bytes.begin() + static_cast<std::ptrdiff_t>(commands_end + kBootstrapSectionSize));
    std::fill(
        bytes.begin() + static_cast<std::ptrdiff_t>(old_segment_end),
        bytes.begin() + static_cast<std::ptrdiff_t>(old_segment_end + kBootstrapSectionSize),
        std::byte{0});

    put_u32(bytes, segment + 4, static_cast<std::uint32_t>(kBootstrapSegmentSize));
    put_u32(bytes, segment + 56, 7U);
    put_u32(bytes, segment + 60, 7U);
    put_u32(bytes, segment + 64, 1U);

    const std::size_t section = old_segment_end;
    put_string(bytes, section, "__mod_init_func");
    put_string(bytes, section + 16, "__TEXT");
    put_u64(bytes, section + 32, vm_address + slot_offset);
    put_u64(bytes, section + 40, sizeof(std::uint64_t));
    put_u32(bytes, section + 48, slot_offset);
    put_u32(bytes, section + 52, 3U);
    put_u32(bytes, section + 64, macosarm::macho::kSModInitFuncPointers);

    put_u32(
        bytes,
        20,
        command_bytes + static_cast<std::uint32_t>(kBootstrapSectionSize));
    return bytes;
}

struct BootstrapAuthRootFixture {
    static constexpr std::uint64_t base = 0x780000000ULL;
    static constexpr std::uint32_t slot_offset = 0x200U;
    static constexpr std::uint32_t target_offset = 0x300U;
    static constexpr std::uint16_t diversity = 0x6a5bU;
    static constexpr macosarm::PointerAuthKey key = macosarm::PointerAuthKey::data_b;

    BootstrapAuthRootFixture() {
        auto payload = graphwide_payload(
            macosarm::dyld::ChainedPointerFormat::arm64e_userland);
        graphwide_put_u16(payload, 28U + 8U + 22U, slot_offset);
        bytes = bootstrap_add_initializer_pointer_section(
            graphfix_dylib("/usr/lib/bootstrap-root.dylib", base, payload),
            base,
            slot_offset);
        put_u32(
            bytes,
            8,
            static_cast<std::uint32_t>(macosarm::macho::kCpuSubtypeArm64e));
        raw_pointer = graphwide_auth_rebase(
            target_offset,
            diversity,
            key,
            true);
        put_u64(bytes, slot_offset, raw_pointer);
        bytes.at(target_offset) = std::byte{0x1f};
        bytes.at(target_offset + 1U) = std::byte{0x20};
        bytes.at(target_offset + 2U) = std::byte{0x03};
        bytes.at(target_offset + 3U) = std::byte{0xd5};

        auto parsed = macosarm::macho::parse(bytes);
        expect(static_cast<bool>(parsed), "authenticated bootstrap root Mach-O parses");
        if (parsed) {
            image = std::move(parsed.image);
        }
        expect(static_cast<bool>(vm.map(
                   base,
                   0x4000,
                   macosarm::Protection::read |
                       macosarm::Protection::write |
                       macosarm::Protection::execute)),
               "authenticated bootstrap root maps supplied image");
        expect(static_cast<bool>(vm.load_bytes(base, bytes)),
               "authenticated bootstrap root loads supplied image bytes");
    }

    std::vector<std::byte> bytes;
    macosarm::macho::Image image;
    macosarm::LoadedImage mapping{base, base + target_offset, 1};
    macosarm::GuestAddressSpace vm;
    std::uint64_t raw_pointer{};
};

macosarm::ProcessStartupLayout bootstrap_build_startup(
    macosarm::GuestAddressSpace& vm,
    std::uint64_t stack_base,
    std::span<const std::string_view> arguments,
    std::span<const std::string_view> environment,
    std::span<const std::string_view> apple) {
    expect(static_cast<bool>(vm.map(
               stack_base,
               0x4000,
               macosarm::Protection::read | macosarm::Protection::write)),
           "graph bootstrap maps process startup stack");
    macosarm::ProcessStartupConfig config;
    config.arguments = arguments;
    config.environment = environment;
    config.apple = apple;
    const auto startup = macosarm::build_process_startup(vm, stack_base, 0x4000, config);
    expect(static_cast<bool>(startup), "graph bootstrap materializes process startup ABI");
    return startup.layout;
}

} // namespace

int dyld_graph_bootstrap_main() {
    using macosarm::CpuState;
    using macosarm::MachContext;
    using macosarm::PointerAuthenticator;
    using macosarm::dyld::ImageGraphBootstrapConfig;
    using macosarm::dyld::ImageGraphBootstrapError;
    using macosarm::dyld::LoadedImageGraphFixupsError;

    constexpr std::string_view executable =
        "/Applications/Bootstrap.app/Contents/MacOS/Bootstrap";

    {
        BootstrapAuthRootFixture fixture;
        InitializerTestHost host;
        ReturningInitializerBackend backend;
        CpuState state{};
        macosarm::dyld::ImageLookup lookup;
        const auto result = macosarm::dyld::bootstrap_image_graph(
            fixture.image,
            fixture.bytes,
            fixture.mapping,
            "/usr/lib/bootstrap-root.dylib",
            executable,
            fixture.vm,
            lookup,
            {},
            state,
            backend,
            host);
        expect(result.error == ImageGraphBootstrapError::fixup_failure &&
                   result.fixups.error == LoadedImageGraphFixupsError::pointer_auth_required,
               "high-level bootstrap refuses authenticated fixups without explicit PAUTH policy");
        expect(backend.calls == 0,
               "high-level bootstrap does not execute initializers after fixup failure");
        expect(graphwide_read_u64(
                   fixture.vm,
                   BootstrapAuthRootFixture::base + BootstrapAuthRootFixture::slot_offset) ==
                   fixture.raw_pointer,
               "missing bootstrap PAUTH policy leaves authenticated raw slot untouched");
    }

    {
        BootstrapAuthRootFixture fixture;
        constexpr std::uint64_t stack_base = 0x781000000ULL;
        const std::array<std::string_view, 3> arguments{
            "bootstrap-root", "alpha", "beta"};
        const std::array<std::string_view, 1> environment{"MODE=test"};
        const std::array<std::string_view, 1> apple{"executable_path=/usr/lib/bootstrap-root.dylib"};
        const auto startup = bootstrap_build_startup(
            fixture.vm,
            stack_base,
            arguments,
            environment,
            apple);

        const PointerAuthenticator authenticator(graphwide_keys());
        MachContext mach_context;
        ImageGraphBootstrapConfig config;
        config.fixups.max_total_fixups = 1;
        config.fixups.pointer_auth = &authenticator;
        config.max_initializers = 1;
        config.max_authenticated_slots = 1;
        config.program_vars = 0x123456789ULL;
        config.execution.context = {99, 98, 97, 96, 95};
        config.execution.mach_context = &mach_context;

        InitializerTestHost host;
        ReturningInitializerBackend backend;
        CpuState state{};
        macosarm::dyld::ImageLookup lookup;
        const auto result = macosarm::dyld::bootstrap_image_graph(
            fixture.image,
            fixture.bytes,
            fixture.mapping,
            "/usr/lib/bootstrap-root.dylib",
            executable,
            fixture.vm,
            lookup,
            startup,
            state,
            backend,
            host,
            config);

        expect(static_cast<bool>(result) &&
                   result.loading.graph.images.size() == 1 &&
                   result.fixups.fixups_processed == 1 &&
                   result.fixups.authenticated_slots.size() == 1,
               "high-level bootstrap joins graph loading and authenticated retained fixups");
        expect(static_cast<bool>(result.initialization) &&
                   result.initialization.planning.plan.calls.size() == 1 &&
                   result.initialization.execution.initialized_images ==
                       std::vector<bool>({true}),
               "high-level bootstrap joins authenticated planning and initializer execution");
        if (result.fixups.authenticated_slots.size() == 1) {
            const auto& slot = result.fixups.authenticated_slots.front();
            expect(slot.storage_address ==
                       BootstrapAuthRootFixture::base + BootstrapAuthRootFixture::slot_offset &&
                       slot.key == BootstrapAuthRootFixture::key &&
                       slot.diversity == BootstrapAuthRootFixture::diversity &&
                       slot.address_diversity,
                   "bootstrap preserves exact authenticated fixup policy into planning");
        }
        if (result.initialization.planning.plan.calls.size() == 1) {
            expect(result.initialization.planning.plan.calls.front().address ==
                       BootstrapAuthRootFixture::base + BootstrapAuthRootFixture::target_offset,
                   "bootstrap planner authenticates retained initializer slot to raw target");
        }
        expect(backend.entries.size() == 1,
               "bootstrap executes authenticated initializer exactly once");
        if (backend.entries.size() == 1) {
            const std::array<std::uint64_t, 5> expected_args{
                startup.argc,
                startup.argv,
                startup.envp,
                startup.apple,
                config.program_vars,
            };
            expect(backend.entries.front().args == expected_args,
                   "bootstrap overrides stale execution context with process startup ABI values");
        }
    }

    {
        constexpr std::uint64_t dependency_base = 0x782000000ULL;
        constexpr std::uint64_t stack_base = 0x783000000ULL;
        MemoryLookup store;
        store.files.emplace(
            "/usr/lib/libBootstrapInit.dylib",
            graph_init_add_routines(
                make_dylib("/usr/lib/libBootstrapInit.dylib", dependency_base),
                dependency_base + 0x180,
                0x44));
        auto root = root_image({dependency("/usr/lib/libBootstrapInit.dylib")});
        macosarm::GuestAddressSpace vm;
        const std::array<std::string_view, 2> arguments{"Bootstrap", "dependency"};
        const std::array<std::string_view, 0> environment{};
        const std::array<std::string_view, 0> apple{};
        const auto startup = bootstrap_build_startup(
            vm,
            stack_base,
            arguments,
            environment,
            apple);
        const auto lookup = store.callback();
        InitializerTestHost host;
        ReturningInitializerBackend backend;
        CpuState state{};
        ImageGraphBootstrapConfig config;
        config.program_vars = 0x7788;

        const auto result = macosarm::dyld::bootstrap_image_graph(
            root,
            {},
            macosarm::LoadedImage{0x100000000ULL, 0, 0},
            executable,
            executable,
            vm,
            lookup,
            startup,
            state,
            backend,
            host,
            config);
        expect(static_cast<bool>(result) && result.loading.graph.images.size() == 2,
               "high-level bootstrap loads dependency graph before initialization");
        expect(result.fixups.fixups_processed == 0 &&
                   result.fixups.authenticated_slots.empty(),
               "high-level bootstrap keeps no-fixup dependency graph unchanged");
        expect(result.initialization.planning.plan.calls.size() == 1 &&
                   result.initialization.planning.plan.calls.front().address ==
                       dependency_base + 0x180,
               "high-level bootstrap plans dependency initializer from retained metadata");
        expect(backend.entries.size() == 1,
               "high-level bootstrap executes dependency initializer exactly once");
        if (backend.entries.size() == 1) {
            const std::array<std::uint64_t, 5> expected_args{
                startup.argc,
                startup.argv,
                startup.envp,
                startup.apple,
                config.program_vars,
            };
            expect(backend.entries.front().args == expected_args,
                   "dependency initializer receives startup-derived ABI through high-level bootstrap");
        }
    }

    expect(macosarm::dyld::image_graph_bootstrap_error_name(
               ImageGraphBootstrapError::initializer_execution_failure) ==
               "initializer_execution_failure",
           "graph bootstrap errors have stable names");

    if (failures != 0) {
        std::cerr << failures << " high-level graph bootstrap test(s) failed\n";
        return EXIT_FAILURE;
    }
    std::cout << "high-level graph bootstrap tests passed\n";
    return EXIT_SUCCESS;
}
