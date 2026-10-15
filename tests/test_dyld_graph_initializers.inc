#include "macosarm/macho_initializers.hpp"

namespace {

std::uint32_t graph_init_read_u32(const std::vector<std::byte>& bytes, std::size_t offset) {
    std::uint32_t value = 0;
    for (std::size_t index = 0; index < 4; ++index) {
        value |= static_cast<std::uint32_t>(std::to_integer<unsigned char>(bytes.at(offset + index)))
                 << (index * 8U);
    }
    return value;
}

std::vector<std::byte> graph_init_add_routines(
    std::vector<std::byte> bytes,
    std::uint64_t address,
    std::uint64_t module,
    std::uint32_t command_size = 72U) {
    const std::uint32_t command_count = graph_init_read_u32(bytes, 16);
    const std::uint32_t commands_size = graph_init_read_u32(bytes, 20);
    const std::size_t command = 32U + static_cast<std::size_t>(commands_size);
    if (command + command_size > bytes.size()) {
        std::abort();
    }

    put_u32(bytes, command, macosarm::macho::kLcRoutines64);
    put_u32(bytes, command + 4, command_size);
    if (command_size >= 16U) {
        put_u64(bytes, command + 8, address);
    }
    if (command_size >= 24U) {
        put_u64(bytes, command + 16, module);
    }
    put_u32(bytes, 16, command_count + 1U);
    put_u32(bytes, 20, commands_size + command_size);
    return bytes;
}

} // namespace

int dyld_graph_initializers_main() {
    using macosarm::GuestAddressSpace;
    using macosarm::LoadedImage;
    using macosarm::dyld::DependencyGraphError;
    using macosarm::macho::InitializerMetadataError;

    constexpr std::string_view kExecutable = "/Applications/Test.app/Contents/MacOS/Test";
    const LoadedImage root_mapping{0x100000000ULL, 0x100000200ULL, 2};
    const std::vector<std::byte> no_root_bytes;

    {
        MemoryLookup store;
        store.files.emplace(
            "/libs/libInit.dylib",
            graph_init_add_routines(
                make_dylib("/libs/libInit.dylib", 0x610000000ULL),
                0x610000180ULL,
                0x44ULL));
        const auto root = root_image({dependency("/libs/libInit.dylib")});
        GuestAddressSpace vm;
        const auto lookup = store.callback();
        const auto result = macosarm::dyld::load_dependency_graph(
            root,
            no_root_bytes,
            root_mapping,
            kExecutable,
            kExecutable,
            vm,
            lookup);

        expect(static_cast<bool>(result), "graph accepts dependency initializer metadata");
        expect(result.graph.images.size() == 2, "initializer graph keeps root and child");
        expect(result.graph.images[0].initializers.pointer_sections.empty() &&
                   !result.graph.images[0].initializers.routines.present,
               "empty root byte span preserves legacy pre-parsed-root behavior");
        expect(result.graph.images[1].initializers.routines.present,
               "dependency LC_ROUTINES_64 metadata is retained in graph");
        expect(result.graph.images[1].initializers.routines.address == 0x610000180ULL,
               "dependency initializer address is retained");
        expect(result.graph.images[1].initializers.routines.module == 0x44ULL,
               "dependency initializer module is retained");
    }

    {
        MemoryLookup store;
        store.files.emplace(
            "/libs/libBadInit.dylib",
            graph_init_add_routines(
                make_dylib("/libs/libBadInit.dylib", 0x620000000ULL),
                0x620000180ULL,
                0,
                16U));
        const auto root = root_image({dependency("/libs/libBadInit.dylib")});
        GuestAddressSpace vm;
        const auto lookup = store.callback();
        const auto result = macosarm::dyld::load_dependency_graph(
            root,
            no_root_bytes,
            root_mapping,
            kExecutable,
            kExecutable,
            vm,
            lookup);

        expect(result.error == DependencyGraphError::initializer_metadata_failure,
               "malformed dependency initializer metadata fails graph explicitly");
        expect(result.initializer_error == InitializerMetadataError::malformed_routines,
               "graph preserves initializer metadata error detail");
        expect(result.failed_image_index == 0 && result.failed_dependency_index == 0,
               "graph reports dependency edge that supplied malformed initializer metadata");
        expect(result.graph.images.empty(), "initializer metadata failure returns no partial graph");
        expect(vm.mappings().empty(), "initializer metadata failure occurs before dependency mapping");
    }

    {
        const auto root_bytes = graph_init_add_routines(
            make_dylib("/libs/root-metadata.dylib", 0x630000000ULL),
            0x6300001c0ULL,
            0x55ULL);
        const auto root = root_image({});
        GuestAddressSpace vm;
        MemoryLookup store;
        const auto lookup = store.callback();
        const auto result = macosarm::dyld::load_dependency_graph(
            root,
            root_bytes,
            root_mapping,
            kExecutable,
            kExecutable,
            vm,
            lookup);

        expect(static_cast<bool>(result), "root initializer metadata scans when root bytes are supplied");
        expect(result.graph.images.size() == 1 && result.graph.images[0].initializers.routines.present,
               "root LC_ROUTINES_64 metadata is retained");
        expect(result.graph.images[0].initializers.routines.address == 0x6300001c0ULL,
               "root initializer address is preserved");
    }

    expect(macosarm::dyld::dependency_graph_error_name(
               DependencyGraphError::initializer_metadata_failure) ==
               "initializer_metadata_failure",
           "initializer graph failure has stable error name");

    if (failures != 0) {
        std::cerr << failures << " dyld initializer graph test(s) failed\n";
        return EXIT_FAILURE;
    }

    std::cout << "dyld initializer graph tests passed\n";
    return EXIT_SUCCESS;
}
