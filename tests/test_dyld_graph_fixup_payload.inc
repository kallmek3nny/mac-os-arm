#include "macosarm/dyld_fixup_payload.hpp"

namespace {

std::uint32_t graphfix_read_u32(
    const std::vector<std::byte>& bytes,
    std::size_t offset) {
    std::uint32_t value = 0;
    for (std::size_t index = 0; index < 4; ++index) {
        value |= static_cast<std::uint32_t>(
                     std::to_integer<unsigned char>(bytes.at(offset + index)))
                 << (index * 8U);
    }
    return value;
}

std::vector<std::byte> graphfix_dylib(
    std::string_view install_name,
    std::uint64_t vm_address,
    const std::vector<std::byte>& payload,
    std::uint32_t declared_offset = 0x3000,
    std::uint32_t declared_size = 0) {
    std::vector<std::byte> file = make_dylib(install_name, vm_address);
    const std::uint32_t command_count = graphfix_read_u32(file, 16);
    const std::uint32_t command_bytes = graphfix_read_u32(file, 20);
    const std::size_t command = 32U + static_cast<std::size_t>(command_bytes);
    if (command + 16U > 0x3000U) {
        std::abort();
    }

    put_u32(file, command, macosarm::macho::kLcDyldChainedFixups);
    put_u32(file, command + 4, 16);
    put_u32(file, command + 8, declared_offset);
    const std::uint32_t payload_size = declared_size == 0
        ? static_cast<std::uint32_t>(payload.size())
        : declared_size;
    put_u32(file, command + 12, payload_size);
    put_u32(file, 16, command_count + 1);
    put_u32(file, 20, command_bytes + 16);

    if (!payload.empty() &&
        static_cast<std::size_t>(declared_offset) <= file.size() &&
        payload.size() <= file.size() - static_cast<std::size_t>(declared_offset)) {
        std::copy(
            payload.begin(),
            payload.end(),
            file.begin() + static_cast<std::ptrdiff_t>(declared_offset));
    }
    return file;
}

} // namespace

int dyld_graph_fixup_payload_main() {
    using macosarm::GuestAddressSpace;
    using macosarm::LoadedImage;
    using macosarm::dyld::ChainedFixupPayloadError;
    using macosarm::dyld::DependencyGraphConfig;
    using macosarm::dyld::DependencyGraphError;

    const LoadedImage root_mapping{0x100000000ULL, 0x100000200ULL, 2};
    constexpr std::string_view executable =
        "/Applications/Test.app/Contents/MacOS/Test";
    const std::vector<std::byte> no_root_bytes;

    {
        const std::vector<std::byte> payload{
            std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44},
            std::byte{0x55}, std::byte{0x66}, std::byte{0x77}, std::byte{0x88}};
        MemoryLookup store;
        store.files.emplace(
            "/usr/lib/libFix.dylib",
            graphfix_dylib("/usr/lib/libFix.dylib", 0x510000000ULL, payload));
        GuestAddressSpace vm;
        const auto result = macosarm::dyld::load_dependency_graph(
            root_image({dependency("/usr/lib/libFix.dylib")}),
            no_root_bytes,
            root_mapping,
            executable,
            executable,
            vm,
            store.callback());
        expect(static_cast<bool>(result) && result.graph.images.size() == 2,
               "dependency graph accepts retained chained-fixup payload");
        if (result.graph.images.size() == 2) {
            expect(result.graph.images[1].chained_fixups_payload == payload,
                   "dependency graph retains exact chained-fixup payload bytes");
        }
    }

    {
        const std::vector<std::byte> payload{
            std::byte{0xaa}, std::byte{0xbb}, std::byte{0xcc}, std::byte{0xdd}};
        const std::vector<std::byte> root_bytes =
            graphfix_dylib("/usr/lib/root.dylib", 0x520000000ULL, payload);
        const auto parsed = macosarm::macho::parse(root_bytes);
        expect(static_cast<bool>(parsed), "root fixup-payload fixture parses");
        GuestAddressSpace vm;
        const auto result = macosarm::dyld::load_dependency_graph(
            parsed.image,
            root_bytes,
            LoadedImage{0x520000000ULL, 0, 1},
            "/usr/lib/root.dylib",
            executable,
            vm,
            {});
        expect(static_cast<bool>(result) && result.graph.images.size() == 1,
               "root graph retains chained-fixup payload");
        if (result.graph.images.size() == 1) {
            expect(result.graph.images[0].chained_fixups_payload == payload,
                   "root image preserves exact chained-fixup payload bytes");
        }
    }

    {
        MemoryLookup store;
        store.files.emplace(
            "/usr/lib/libPlain.dylib",
            make_dylib("/usr/lib/libPlain.dylib", 0x530000000ULL));
        GuestAddressSpace vm;
        const auto result = macosarm::dyld::load_dependency_graph(
            root_image({dependency("/usr/lib/libPlain.dylib")}),
            no_root_bytes,
            root_mapping,
            executable,
            executable,
            vm,
            store.callback());
        expect(static_cast<bool>(result) && result.graph.images.size() == 2 &&
                   result.graph.images[1].chained_fixups_payload.empty(),
               "images without LC_DYLD_CHAINED_FIXUPS retain no synthetic payload");
    }

    {
        MemoryLookup store;
        store.files.emplace(
            "/usr/lib/libBroken.dylib",
            graphfix_dylib(
                "/usr/lib/libBroken.dylib",
                0x540000000ULL,
                {},
                0x3ff0,
                0x40));
        GuestAddressSpace vm;
        const auto result = macosarm::dyld::load_dependency_graph(
            root_image({dependency("/usr/lib/libBroken.dylib")}),
            no_root_bytes,
            root_mapping,
            executable,
            executable,
            vm,
            store.callback());
        expect(result.error == DependencyGraphError::fixups_payload_failure &&
                   result.fixups_payload_error == ChainedFixupPayloadError::range_out_of_bounds,
               "out-of-file chained-fixup payload fails graph construction explicitly");
        expect(result.graph.images.empty(),
               "fixup-payload graph failure clears partially built graph");
        expect(vm.mappings().empty(),
               "fixup-payload graph failure leaves no dependency mappings behind");
    }

    {
        const std::vector<std::byte> payload(32, std::byte{0x5a});
        MemoryLookup store;
        store.files.emplace(
            "/usr/lib/libBounded.dylib",
            graphfix_dylib("/usr/lib/libBounded.dylib", 0x550000000ULL, payload));
        GuestAddressSpace vm;
        DependencyGraphConfig config;
        config.max_chained_fixup_payload_bytes = 8;
        const auto result = macosarm::dyld::load_dependency_graph(
            root_image({dependency("/usr/lib/libBounded.dylib")}),
            no_root_bytes,
            root_mapping,
            executable,
            executable,
            vm,
            store.callback(),
            config);
        expect(result.error == DependencyGraphError::fixups_payload_failure &&
                   result.fixups_payload_error == ChainedFixupPayloadError::payload_limit,
               "retained chained-fixup payload size is hard bounded");
        expect(vm.mappings().empty(),
               "payload-limit failure occurs before mapping dependency image");
    }

    expect(macosarm::dyld::chained_fixup_payload_error_name(
               ChainedFixupPayloadError::range_out_of_bounds) == "range_out_of_bounds",
           "chained-fixup payload errors have stable names");
    expect(macosarm::dyld::dependency_graph_error_name(
               DependencyGraphError::fixups_payload_failure) == "fixups_payload_failure",
           "dependency graph exposes chained-fixup payload failures");

    if (failures != 0) {
        std::cerr << failures << " graph fixup-payload test(s) failed\n";
        return EXIT_FAILURE;
    }
    std::cout << "dependency graph fixup-payload tests passed\n";
    return EXIT_SUCCESS;
}
