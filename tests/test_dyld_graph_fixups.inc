#include "macosarm/dyld_graph_fixups.hpp"

namespace {

void graphwide_put_u16(
    std::vector<std::byte>& bytes,
    std::size_t offset,
    std::uint16_t value) {
    bytes.at(offset) = static_cast<std::byte>(value & 0xffU);
    bytes.at(offset + 1) = static_cast<std::byte>((value >> 8U) & 0xffU);
}

void graphwide_put_u32(
    std::vector<std::byte>& bytes,
    std::size_t offset,
    std::uint32_t value) {
    for (std::size_t index = 0; index < 4; ++index) {
        bytes.at(offset + index) =
            static_cast<std::byte>((value >> (index * 8U)) & 0xffU);
    }
}

void graphwide_put_u64(
    std::vector<std::byte>& bytes,
    std::size_t offset,
    std::uint64_t value) {
    for (std::size_t index = 0; index < 8; ++index) {
        bytes.at(offset + index) =
            static_cast<std::byte>((value >> (index * 8U)) & 0xffU);
    }
}

std::vector<std::byte> graphwide_payload(
    macosarm::dyld::ChainedPointerFormat format,
    bool import_foo = false) {
    constexpr std::size_t header_size = 28;
    constexpr std::size_t starts_size = 8;
    constexpr std::size_t segment_size = 24;
    constexpr std::size_t imports_offset = header_size + starts_size + segment_size;
    const std::size_t symbols_offset = imports_offset + (import_foo ? 4U : 0U);
    const std::size_t payload_size = symbols_offset + (import_foo ? 5U : 0U);
    std::vector<std::byte> bytes(payload_size, std::byte{0});

    graphwide_put_u32(bytes, 0, 0);
    graphwide_put_u32(bytes, 4, static_cast<std::uint32_t>(header_size));
    graphwide_put_u32(bytes, 8, static_cast<std::uint32_t>(imports_offset));
    graphwide_put_u32(bytes, 12, static_cast<std::uint32_t>(symbols_offset));
    graphwide_put_u32(bytes, 16, import_foo ? 1U : 0U);
    graphwide_put_u32(bytes, 20, macosarm::dyld::kChainedImport);
    graphwide_put_u32(bytes, 24, 0);

    graphwide_put_u32(bytes, header_size, 1);
    graphwide_put_u32(bytes, header_size + 4, static_cast<std::uint32_t>(starts_size));

    const std::size_t segment = header_size + starts_size;
    graphwide_put_u32(bytes, segment, static_cast<std::uint32_t>(segment_size));
    graphwide_put_u16(bytes, segment + 4, 0x4000);
    graphwide_put_u16(bytes, segment + 6, static_cast<std::uint16_t>(format));
    graphwide_put_u64(bytes, segment + 8, 0);
    graphwide_put_u32(bytes, segment + 16, 0);
    graphwide_put_u16(bytes, segment + 20, 1);
    graphwide_put_u16(bytes, segment + 22, 0x20);

    if (import_foo) {
        graphwide_put_u32(bytes, imports_offset, 1U);
        bytes.at(symbols_offset) = std::byte{'_'};
        bytes.at(symbols_offset + 1) = std::byte{'f'};
        bytes.at(symbols_offset + 2) = std::byte{'o'};
        bytes.at(symbols_offset + 3) = std::byte{'o'};
        bytes.at(symbols_offset + 4) = std::byte{0};
    }
    return bytes;
}

std::uint64_t graphwide_generic_rebase(std::uint64_t target) {
    const std::uint64_t low36 = target & ((std::uint64_t{1} << 36) - 1);
    const std::uint64_t high8 = (target >> 56) & 0xffU;
    return low36 | (high8 << 36);
}

std::uint64_t graphwide_generic_bind(std::uint32_t ordinal) {
    return (static_cast<std::uint64_t>(ordinal) & 0xffffffU) |
           (std::uint64_t{1} << 63);
}

std::uint64_t graphwide_auth_rebase(
    std::uint32_t target_offset,
    std::uint16_t diversity,
    macosarm::PointerAuthKey key,
    bool address_diversity) {
    return static_cast<std::uint64_t>(target_offset) |
           (static_cast<std::uint64_t>(diversity) << 32) |
           (static_cast<std::uint64_t>(address_diversity ? 1U : 0U) << 48) |
           ((static_cast<std::uint64_t>(key) & 0x3U) << 49) |
           (std::uint64_t{1} << 63);
}

std::uint64_t graphwide_arm64e_rebase(std::uint64_t target) {
    const std::uint64_t low43 = target & ((std::uint64_t{1} << 43) - 1);
    const std::uint64_t high8 = (target >> 56) & 0xffU;
    return low43 | (high8 << 43);
}

bool graphwide_store_u64(
    macosarm::GuestAddressSpace& address_space,
    std::uint64_t address,
    std::uint64_t value) {
    std::array<std::byte, 8> bytes{};
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        bytes[index] = static_cast<std::byte>((value >> (index * 8U)) & 0xffU);
    }
    return static_cast<bool>(address_space.write(address, bytes));
}

std::uint64_t graphwide_read_u64(
    const macosarm::GuestAddressSpace& address_space,
    std::uint64_t address) {
    std::array<std::byte, 8> bytes{};
    expect(static_cast<bool>(address_space.read(address, bytes)),
           "graph-wide fixup fixture pointer reads");
    std::uint64_t value = 0;
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        value |= static_cast<std::uint64_t>(std::to_integer<unsigned char>(bytes[index]))
                 << (index * 8U);
    }
    return value;
}

macosarm::PointerAuthKeySet graphwide_keys() {
    macosarm::PointerAuthKeySet keys{};
    keys.values[0] = {0x0123456789abcdefULL, 0xfedcba9876543210ULL};
    keys.values[1] = {0x1111222233334444ULL, 0x5555666677778888ULL};
    keys.values[2] = {0x1020304050607080ULL, 0x90a0b0c0d0e0f000ULL};
    keys.values[3] = {0x0f1e2d3c4b5a6978ULL, 0x8796a5b4c3d2e1f0ULL};
    return keys;
}

struct GraphwideFixture {
    static constexpr std::uint64_t root_base = 0x560000000ULL;
    static constexpr std::uint64_t dependency_base = 0x561000000ULL;

    GraphwideFixture() {
        expect(static_cast<bool>(address_space.map(
                   root_base,
                   0x4000,
                   macosarm::Protection::read | macosarm::Protection::write)),
               "graph-wide fixup fixture maps root");
        expect(static_cast<bool>(address_space.map(
                   dependency_base,
                   0x4000,
                   macosarm::Protection::read | macosarm::Protection::write)),
               "graph-wide fixup fixture maps dependency");

        macosarm::dyld::GraphImage root;
        root.path = "/root";
        root.mapping.preferred_load_address = root_base;
        root.image.segments.push_back({
            "__DATA", root_base, 0x4000, 0, 0, 3, 3});

        macosarm::dyld::GraphImage dependency;
        dependency.path = "/libA.dylib";
        dependency.mapping.preferred_load_address = dependency_base;
        dependency.image.segments.push_back({
            "__DATA", dependency_base, 0x4000, 0, 0, 3, 3});
        macosarm::dyld::ExportSymbol symbol;
        symbol.name = "_foo";
        symbol.kind = macosarm::dyld::ExportKind::regular;
        symbol.value = 0x180;
        dependency.exports.push_back(std::move(symbol));

        macosarm::dyld::GraphDependency edge;
        edge.dependency.path = "/libA.dylib";
        edge.dependency.kind = macosarm::macho::DylibLoadKind::normal;
        edge.state = macosarm::dyld::GraphDependencyState::loaded;
        edge.resolved_path = "/libA.dylib";
        edge.image_index = 1;
        root.dependencies.push_back(std::move(edge));

        graph.images.push_back(std::move(root));
        graph.images.push_back(std::move(dependency));
    }

    macosarm::GuestAddressSpace address_space;
    macosarm::dyld::LoadedImageGraph graph;
};

} // namespace

int dyld_graph_fixups_main() {
    using macosarm::PointerAuthError;
    using macosarm::PointerAuthKey;
    using macosarm::PointerAuthenticator;
    using macosarm::dyld::ChainedFixupsApplyError;
    using macosarm::dyld::ChainedFixupsError;
    using macosarm::dyld::ChainedPointerFormat;
    using macosarm::dyld::GraphFixupScanError;
    using macosarm::dyld::LoadedImageGraphFixupsConfig;
    using macosarm::dyld::LoadedImageGraphFixupsError;

    {
        GraphwideFixture fixture;
        fixture.graph.images[0].chained_fixups_payload =
            graphwide_payload(ChainedPointerFormat::generic64, true);
        fixture.graph.images[1].chained_fixups_payload =
            graphwide_payload(ChainedPointerFormat::generic64_offset);
        const std::uint64_t root_raw = graphwide_generic_bind(0);
        const std::uint64_t dependency_raw = graphwide_generic_rebase(0x500);
        expect(graphwide_store_u64(
                   fixture.address_space,
                   GraphwideFixture::root_base + 0x20,
                   root_raw),
               "graph-wide bind fixture stores root chain");
        expect(graphwide_store_u64(
                   fixture.address_space,
                   GraphwideFixture::dependency_base + 0x20,
                   dependency_raw),
               "graph-wide rebase fixture stores dependency chain");

        const auto result = macosarm::dyld::apply_loaded_image_graph_fixups(
            fixture.graph,
            fixture.address_space);
        expect(static_cast<bool>(result) && result.fixups_processed == 2,
               "graph-wide fixups apply both retained image payloads");
        expect(graphwide_read_u64(
                   fixture.address_space,
                   GraphwideFixture::root_base + 0x20) ==
                   GraphwideFixture::dependency_base + 0x180,
               "graph-wide bind resolves through loaded dependency graph");
        expect(graphwide_read_u64(
                   fixture.address_space,
                   GraphwideFixture::dependency_base + 0x20) ==
                   GraphwideFixture::dependency_base + 0x500,
               "graph-wide generic64-offset rebase uses each image base");
        expect(result.authenticated_slots.empty(),
               "generic graph fixups publish no fake authenticated slots");
    }

    {
        GraphwideFixture fixture;
        fixture.graph.images[0].chained_fixups_payload =
            graphwide_payload(ChainedPointerFormat::generic64_offset);
        fixture.graph.images[1].chained_fixups_payload =
            graphwide_payload(ChainedPointerFormat::generic64);
        const std::uint64_t root_raw = graphwide_generic_rebase(0x700);
        const std::uint64_t dependency_raw =
            graphwide_generic_rebase(GraphwideFixture::dependency_base + 0x800) |
            (std::uint64_t{1} << 44);
        expect(graphwide_store_u64(
                   fixture.address_space,
                   GraphwideFixture::root_base + 0x20,
                   root_raw) &&
                   graphwide_store_u64(
                       fixture.address_space,
                       GraphwideFixture::dependency_base + 0x20,
                       dependency_raw),
               "graph-wide rollback fixture stores both raw chains");

        const auto result = macosarm::dyld::apply_loaded_image_graph_fixups(
            fixture.graph,
            fixture.address_space);
        expect(result.error == LoadedImageGraphFixupsError::generic_apply_failure &&
                   result.failed_image_index == 1 &&
                   result.generic_error == ChainedFixupsApplyError::pointer_reserved_bits,
               "later-image apply failure is surfaced with exact underlying error");
        expect(result.rolled_back,
               "later-image apply failure reports graph-wide rollback");
        expect(graphwide_read_u64(
                   fixture.address_space,
                   GraphwideFixture::root_base + 0x20) == root_raw &&
                   graphwide_read_u64(
                       fixture.address_space,
                       GraphwideFixture::dependency_base + 0x20) == dependency_raw,
               "later-image failure restores earlier committed graph fixups");
    }

    {
        GraphwideFixture fixture;
        fixture.graph.images[0].chained_fixups_payload =
            graphwide_payload(ChainedPointerFormat::generic64_offset);
        fixture.graph.images[1].chained_fixups_payload.assign(27, std::byte{0});
        const std::uint64_t root_raw = graphwide_generic_rebase(0x600);
        expect(graphwide_store_u64(
                   fixture.address_space,
                   GraphwideFixture::root_base + 0x20,
                   root_raw),
               "graph metadata preflight fixture stores root chain");
        const auto result = macosarm::dyld::apply_loaded_image_graph_fixups(
            fixture.graph,
            fixture.address_space);
        expect(result.error == LoadedImageGraphFixupsError::metadata_parse_failure &&
                   result.failed_image_index == 1 &&
                   result.metadata_error == ChainedFixupsError::header_too_small,
               "malformed retained payload fails before graph mutation");
        expect(graphwide_read_u64(
                   fixture.address_space,
                   GraphwideFixture::root_base + 0x20) == root_raw,
               "metadata preflight failure leaves earlier image raw chain untouched");
    }

    {
        GraphwideFixture fixture;
        fixture.graph.images[0].chained_fixups_payload =
            graphwide_payload(ChainedPointerFormat::generic64_offset);
        fixture.graph.images[1].chained_fixups_payload =
            graphwide_payload(ChainedPointerFormat::generic64_offset);
        const std::uint64_t root_raw = graphwide_generic_rebase(0x610);
        const std::uint64_t dependency_raw = graphwide_generic_rebase(0x620);
        expect(graphwide_store_u64(
                   fixture.address_space,
                   GraphwideFixture::root_base + 0x20,
                   root_raw) &&
                   graphwide_store_u64(
                       fixture.address_space,
                       GraphwideFixture::dependency_base + 0x20,
                       dependency_raw),
               "graph fixup-limit fixture stores both chains");
        LoadedImageGraphFixupsConfig config;
        config.max_total_fixups = 1;
        const auto result = macosarm::dyld::apply_loaded_image_graph_fixups(
            fixture.graph,
            fixture.address_space,
            config);
        expect(result.error == LoadedImageGraphFixupsError::scan_failure &&
                   result.scan_error == GraphFixupScanError::fixup_limit &&
                   result.failed_image_index == 1,
               "graph-wide fixup limit is enforced during mutation-free preflight");
        expect(graphwide_read_u64(
                   fixture.address_space,
                   GraphwideFixture::root_base + 0x20) == root_raw &&
                   graphwide_read_u64(
                       fixture.address_space,
                       GraphwideFixture::dependency_base + 0x20) == dependency_raw,
               "global fixup-limit failure leaves all raw chains untouched");
    }

    {
        GraphwideFixture fixture;
        fixture.graph.images.resize(1);
        fixture.graph.images[0].dependencies.clear();
        fixture.graph.images[0].chained_fixups_payload =
            graphwide_payload(ChainedPointerFormat::arm64e_userland);
        constexpr std::uint16_t diversity = 0x55aa;
        const std::uint64_t storage = GraphwideFixture::root_base + 0x20;
        const std::uint64_t raw = graphwide_auth_rebase(
            0x900,
            diversity,
            PointerAuthKey::data_b,
            true);
        expect(graphwide_store_u64(fixture.address_space, storage, raw),
               "authenticated graph fixture stores raw ARM64e chain");

        const auto missing = macosarm::dyld::apply_loaded_image_graph_fixups(
            fixture.graph,
            fixture.address_space);
        expect(missing.error == LoadedImageGraphFixupsError::pointer_auth_required &&
                   missing.failed_image_index == 0,
               "authenticated graph fixups require explicit pointer-auth policy before writes");
        expect(graphwide_read_u64(fixture.address_space, storage) == raw,
               "missing graph pointer-auth policy leaves raw authenticated chain untouched");

        const PointerAuthenticator authenticator(graphwide_keys());
        LoadedImageGraphFixupsConfig config;
        config.pointer_auth = &authenticator;
        const auto applied = macosarm::dyld::apply_loaded_image_graph_fixups(
            fixture.graph,
            fixture.address_space,
            config);
        expect(static_cast<bool>(applied) &&
                   applied.authenticated_slots.size() == 1 &&
                   applied.pointer_auth_error == PointerAuthError::none,
               "authenticated graph fixup applies without pointer-auth errors and publishes one retained slot policy");
        if (applied.authenticated_slots.size() == 1) {
            const auto& slot = applied.authenticated_slots.front();
            expect(slot.storage_address == storage &&
                       slot.key == PointerAuthKey::data_b &&
                       slot.diversity == diversity &&
                       slot.address_diversity,
                   "graph fixup preserves exact authenticated key/diversity policy");
            const auto recovered = authenticator.authenticate(
                graphwide_read_u64(fixture.address_space, storage),
                slot.key,
                PointerAuthenticator::blend_discriminator(
                    slot.storage_address,
                    slot.diversity));
            expect(static_cast<bool>(recovered) &&
                       recovered.pointer == GraphwideFixture::root_base + 0x900,
                   "graph ARM64e fixup writes a software-PAC pointer authenticating to raw target");
        }
    }

    {
        GraphwideFixture fixture;
        fixture.graph.images.resize(1);
        fixture.graph.images[0].dependencies.clear();
        fixture.graph.images[0].chained_fixups_payload =
            graphwide_payload(ChainedPointerFormat::arm64e_userland);
        const std::uint64_t storage = GraphwideFixture::root_base + 0x20;
        const std::uint64_t raw = graphwide_arm64e_rebase(0xa00);
        expect(graphwide_store_u64(fixture.address_space, storage, raw),
               "unauthenticated ARM64e graph fixture stores raw chain");
        const auto result = macosarm::dyld::apply_loaded_image_graph_fixups(
            fixture.graph,
            fixture.address_space);
        expect(static_cast<bool>(result) && result.authenticated_slots.empty(),
               "unauthenticated ARM64e graph fixups do not require fake pointer-auth policy");
        expect(graphwide_read_u64(fixture.address_space, storage) ==
                   GraphwideFixture::root_base + 0xa00,
               "unauthenticated ARM64e graph rebase preserves existing semantics");
    }

    expect(macosarm::dyld::graph_fixup_scan_error_name(
               GraphFixupScanError::fixup_limit) == "fixup_limit",
           "graph fixup scan errors have stable names");
    expect(macosarm::dyld::loaded_image_graph_fixups_error_name(
               LoadedImageGraphFixupsError::rollback_failure) == "rollback_failure",
           "graph fixup application errors have stable names");

    if (failures != 0) {
        std::cerr << failures << " graph-wide fixup test(s) failed\n";
        return EXIT_FAILURE;
    }
    std::cout << "graph-wide retained fixup tests passed\n";
    return EXIT_SUCCESS;
}
