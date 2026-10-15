#include "macosarm/dyld_fixups.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>
#include <utility>

namespace {

int failures = 0;

void expect(bool condition, const std::string& label) {
    if (!condition) {
        std::cerr << "FAIL: " << label << '\n';
        ++failures;
    }
}

std::array<std::byte, 8> bytes_for(std::uint64_t value) {
    std::array<std::byte, 8> bytes{};
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        bytes[index] = static_cast<std::byte>((value >> (index * 8U)) & 0xffU);
    }
    return bytes;
}

std::uint64_t value_from(const std::array<std::byte, 8>& bytes) {
    std::uint64_t value = 0;
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        value |= static_cast<std::uint64_t>(std::to_integer<unsigned char>(bytes[index]))
                 << (index * 8U);
    }
    return value;
}

void load_u64(
    macosarm::GuestAddressSpace& address_space,
    std::uint64_t address,
    std::uint64_t value) {
    const auto bytes = bytes_for(value);
    expect(static_cast<bool>(address_space.load_bytes(address, bytes)), "fixture pointer loads");
}

std::uint64_t read_u64(
    const macosarm::GuestAddressSpace& address_space,
    std::uint64_t address) {
    std::array<std::byte, 8> bytes{};
    expect(static_cast<bool>(address_space.read(address, bytes)), "fixture pointer reads");
    return value_from(bytes);
}

std::uint64_t arm64e_rebase(
    std::uint64_t target,
    std::uint16_t next = 0,
    bool authenticated = false) {
    const std::uint64_t low43 = target & ((std::uint64_t{1} << 43) - 1);
    const std::uint64_t high8 = (target >> 56) & 0xffU;
    return low43 |
           (high8 << 43) |
           ((static_cast<std::uint64_t>(next) & 0x7ffU) << 51) |
           (authenticated ? (std::uint64_t{1} << 63) : 0);
}

std::uint64_t encoded_addend19(std::int32_t addend) {
    return static_cast<std::uint64_t>(static_cast<std::int64_t>(addend)) &
           ((std::uint64_t{1} << 19) - 1);
}

std::uint64_t arm64e_bind16(
    std::uint32_t ordinal,
    std::int32_t addend = 0,
    std::uint16_t next = 0,
    std::uint16_t zero = 0,
    bool authenticated = false) {
    return (static_cast<std::uint64_t>(ordinal) & 0xffffU) |
           (static_cast<std::uint64_t>(zero) << 16) |
           (encoded_addend19(addend) << 32) |
           ((static_cast<std::uint64_t>(next) & 0x7ffU) << 51) |
           (std::uint64_t{1} << 62) |
           (authenticated ? (std::uint64_t{1} << 63) : 0);
}

std::uint64_t arm64e_bind24(
    std::uint32_t ordinal,
    std::int32_t addend = 0,
    std::uint16_t next = 0,
    std::uint8_t zero = 0,
    bool authenticated = false) {
    return (static_cast<std::uint64_t>(ordinal) & 0xffffffU) |
           (static_cast<std::uint64_t>(zero) << 24) |
           (encoded_addend19(addend) << 32) |
           ((static_cast<std::uint64_t>(next) & 0x7ffU) << 51) |
           (std::uint64_t{1} << 62) |
           (authenticated ? (std::uint64_t{1} << 63) : 0);
}

macosarm::dyld::ExportSymbol export_symbol(
    std::string name,
    macosarm::dyld::ExportKind kind,
    std::uint64_t value) {
    macosarm::dyld::ExportSymbol result;
    result.name = std::move(name);
    result.kind = kind;
    result.value = value;
    return result;
}

struct Fixture {
    static constexpr std::uint64_t kRootBase = 0x100000000ULL;
    static constexpr std::uint64_t kDependencyBase = 0x200000000ULL;

    explicit Fixture(std::uint64_t root_segment_size = 0x8000) {
        expect(
            static_cast<bool>(address_space.map(
                kRootBase,
                0x8000,
                macosarm::Protection::read | macosarm::Protection::write)),
            "fixture root mapping created");

        macosarm::dyld::GraphImage root;
        root.path = "/root";
        root.mapping.preferred_load_address = kRootBase;
        root.image.segments.push_back(
            macosarm::macho::Segment{
                "__DATA",
                kRootBase,
                root_segment_size,
                0,
                0,
                3,
                3});

        macosarm::dyld::GraphImage dependency;
        dependency.path = "/libA.dylib";
        dependency.mapping.preferred_load_address = kDependencyBase;
        dependency.image.segments.push_back(
            macosarm::macho::Segment{
                "__TEXT",
                kDependencyBase,
                0x4000,
                0,
                0,
                5,
                5});
        dependency.exports.push_back(
            export_symbol("_foo", macosarm::dyld::ExportKind::regular, 0x180));

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

macosarm::dyld::ChainedFixupsMetadata metadata(
    macosarm::dyld::ChainedPointerFormat format,
    std::size_t page_count = 1) {
    macosarm::dyld::ChainedFixupsMetadata result;
    result.segments.resize(1);
    auto& segment = result.segments[0];
    segment.present = true;
    segment.page_size = 0x4000;
    segment.pointer_format = format;
    segment.segment_offset = 0;
    segment.pages.resize(page_count);
    return result;
}

} // namespace

int main() {
    using macosarm::dyld::ChainedFixupsApplyConfig;
    using macosarm::dyld::ChainedFixupsApplyError;
    using macosarm::dyld::ChainedImportEntry;
    using macosarm::dyld::ChainedPointerFormat;

    {
        Fixture fixture;
        auto fixups = metadata(ChainedPointerFormat::arm64e);
        fixups.segments[0].pages[0].offsets.push_back(0x20);
        const std::uint64_t target = Fixture::kRootBase + 0x1234;
        load_u64(fixture.address_space, Fixture::kRootBase + 0x20, arm64e_rebase(target));

        const auto result = macosarm::dyld::apply_chained_fixups(
            fixture.graph, 0, fixups, fixture.address_space);
        expect(static_cast<bool>(result), "arm64e vmaddr rebase applies");
        expect(
            read_u64(fixture.address_space, Fixture::kRootBase + 0x20) == target,
            "arm64e vmaddr rebase restores target");
    }

    {
        Fixture fixture;
        auto fixups = metadata(ChainedPointerFormat::arm64e_userland);
        fixups.segments[0].pages[0].offsets.push_back(0x28);
        load_u64(fixture.address_space, Fixture::kRootBase + 0x28, arm64e_rebase(0x3456));

        const auto result = macosarm::dyld::apply_chained_fixups(
            fixture.graph, 0, fixups, fixture.address_space);
        expect(static_cast<bool>(result), "arm64e userland offset rebase applies");
        expect(
            read_u64(fixture.address_space, Fixture::kRootBase + 0x28) ==
                Fixture::kRootBase + 0x3456,
            "arm64e userland rebase adds image base");
    }

    {
        Fixture fixture;
        auto fixups = metadata(ChainedPointerFormat::arm64e_userland);
        fixups.imports.push_back(ChainedImportEntry{1, false, "_foo", -5});
        fixups.segments[0].pages[0].offsets.push_back(0x30);
        load_u64(fixture.address_space, Fixture::kRootBase + 0x30, arm64e_bind16(0, 7));

        const auto result = macosarm::dyld::apply_chained_fixups(
            fixture.graph, 0, fixups, fixture.address_space);
        expect(static_cast<bool>(result), "arm64e positive pointer addend applies");
        expect(
            read_u64(fixture.address_space, Fixture::kRootBase + 0x30) ==
                Fixture::kDependencyBase + 0x182,
            "arm64e import and positive pointer addends combine");
    }

    {
        Fixture fixture;
        auto fixups = metadata(ChainedPointerFormat::arm64e_userland);
        fixups.imports.push_back(ChainedImportEntry{1, false, "_foo", 9});
        fixups.segments[0].pages[0].offsets.push_back(0x38);
        load_u64(fixture.address_space, Fixture::kRootBase + 0x38, arm64e_bind16(0, -7));

        const auto result = macosarm::dyld::apply_chained_fixups(
            fixture.graph, 0, fixups, fixture.address_space);
        expect(static_cast<bool>(result), "arm64e negative pointer addend applies");
        expect(
            read_u64(fixture.address_space, Fixture::kRootBase + 0x38) ==
                Fixture::kDependencyBase + 0x182,
            "arm64e signed pointer addend sign-extends");
    }

    {
        Fixture fixture;
        auto fixups = metadata(ChainedPointerFormat::arm64e_userland24);
        fixups.imports.resize(0x10001);
        fixups.imports[0x10000] = ChainedImportEntry{1, false, "_foo", 0};
        fixups.segments[0].pages[0].offsets.push_back(0x40);
        load_u64(
            fixture.address_space,
            Fixture::kRootBase + 0x40,
            arm64e_bind24(0x10000));

        const auto result = macosarm::dyld::apply_chained_fixups(
            fixture.graph, 0, fixups, fixture.address_space);
        expect(static_cast<bool>(result), "arm64e userland24 accepts 24-bit ordinal");
        expect(
            read_u64(fixture.address_space, Fixture::kRootBase + 0x40) ==
                Fixture::kDependencyBase + 0x180,
            "arm64e userland24 resolves ordinal above 16-bit range");
    }

    {
        Fixture fixture;
        auto fixups = metadata(ChainedPointerFormat::arm64e);
        fixups.imports.push_back(ChainedImportEntry{1, false, "_foo", 0});
        fixups.segments[0].pages[0].offsets.push_back(0x48);
        const std::uint64_t raw = arm64e_bind16(0, 0, 0, 1);
        load_u64(fixture.address_space, Fixture::kRootBase + 0x48, raw);

        const auto result = macosarm::dyld::apply_chained_fixups(
            fixture.graph, 0, fixups, fixture.address_space);
        expect(
            result.error == ChainedFixupsApplyError::pointer_reserved_bits,
            "classic arm64e bind rejects nonzero 16-bit zero field");
        expect(
            read_u64(fixture.address_space, Fixture::kRootBase + 0x48) == raw,
            "malformed arm64e bind does not mutate memory");
    }

    {
        Fixture fixture;
        auto fixups = metadata(ChainedPointerFormat::arm64e_userland24);
        fixups.imports.push_back(ChainedImportEntry{1, true, "_missing", 33});
        fixups.segments[0].pages[0].offsets.push_back(0x50);
        load_u64(fixture.address_space, Fixture::kRootBase + 0x50, arm64e_bind24(0, -4));

        const auto result = macosarm::dyld::apply_chained_fixups(
            fixture.graph, 0, fixups, fixture.address_space);
        expect(static_cast<bool>(result), "arm64e weak missing bind applies");
        expect(
            read_u64(fixture.address_space, Fixture::kRootBase + 0x50) == 0,
            "arm64e weak missing bind writes null and ignores addends");
    }

    {
        Fixture fixture;
        auto fixups = metadata(ChainedPointerFormat::arm64e_userland);
        fixups.imports.push_back(ChainedImportEntry{1, false, "_foo", 0});
        fixups.segments[0].pages[0].offsets.push_back(0x58);
        const std::uint64_t raw = arm64e_bind16(4);
        load_u64(fixture.address_space, Fixture::kRootBase + 0x58, raw);

        const auto result = macosarm::dyld::apply_chained_fixups(
            fixture.graph, 0, fixups, fixture.address_space);
        expect(
            result.error == ChainedFixupsApplyError::bind_ordinal_out_of_range,
            "arm64e invalid bind ordinal rejected");
        expect(
            read_u64(fixture.address_space, Fixture::kRootBase + 0x58) == raw,
            "arm64e invalid ordinal does not mutate memory");
    }

    {
        Fixture fixture;
        auto fixups = metadata(ChainedPointerFormat::arm64e_userland);
        fixups.segments[0].pages[0].offsets.push_back(0x60);
        const std::uint64_t first_target = Fixture::kRootBase + 0x700;
        const std::uint64_t second_target = Fixture::kRootBase + 0x900;
        load_u64(
            fixture.address_space,
            Fixture::kRootBase + 0x60,
            arm64e_rebase(0x700, 1));
        load_u64(
            fixture.address_space,
            Fixture::kRootBase + 0x68,
            arm64e_rebase(0x900));

        const auto result = macosarm::dyld::apply_chained_fixups(
            fixture.graph, 0, fixups, fixture.address_space);
        expect(static_cast<bool>(result), "arm64e chain walks 8-byte stride");
        expect(result.fixups_processed == 2, "arm64e chain processes both entries");
        expect(
            read_u64(fixture.address_space, Fixture::kRootBase + 0x60) == first_target,
            "arm64e first chained rebase applied");
        expect(
            read_u64(fixture.address_space, Fixture::kRootBase + 0x68) == second_target,
            "arm64e next=1 advances eight bytes");
    }

    {
        Fixture fixture;
        auto fixups = metadata(ChainedPointerFormat::arm64e_userland);
        fixups.segments[0].pages[0].offsets.push_back(0x3ff8);
        const std::uint64_t raw = arm64e_rebase(0x100, 1);
        load_u64(fixture.address_space, Fixture::kRootBase + 0x3ff8, raw);

        const auto result = macosarm::dyld::apply_chained_fixups(
            fixture.graph, 0, fixups, fixture.address_space);
        expect(
            result.error == ChainedFixupsApplyError::chain_next_out_of_page,
            "arm64e chain cannot escape page");
        expect(
            read_u64(fixture.address_space, Fixture::kRootBase + 0x3ff8) == raw,
            "page escape is rejected before mutation");
    }

    {
        Fixture fixture(0x1008);
        auto fixups = metadata(ChainedPointerFormat::arm64e_userland);
        fixups.segments[0].pages[0].offsets.push_back(0x1000);
        const std::uint64_t raw = arm64e_rebase(0x100, 1);
        load_u64(fixture.address_space, Fixture::kRootBase + 0x1000, raw);

        const auto result = macosarm::dyld::apply_chained_fixups(
            fixture.graph, 0, fixups, fixture.address_space);
        expect(
            result.error == ChainedFixupsApplyError::chain_next_out_of_segment,
            "arm64e chain cannot escape segment");
        expect(
            read_u64(fixture.address_space, Fixture::kRootBase + 0x1000) == raw,
            "segment escape is rejected before mutation");
    }

    {
        Fixture fixture;
        auto fixups = metadata(ChainedPointerFormat::arm64e_userland);
        fixups.segments[0].pages[0].offsets.push_back(0x70);
        const std::uint64_t raw = arm64e_rebase(0x222, 0, true);
        load_u64(fixture.address_space, Fixture::kRootBase + 0x70, raw);

        const auto result = macosarm::dyld::apply_chained_fixups(
            fixture.graph, 0, fixups, fixture.address_space);
        expect(
            result.error == ChainedFixupsApplyError::authenticated_pointer_unsupported,
            "authenticated arm64e pointer is explicitly rejected");
        expect(
            macosarm::dyld::chained_fixups_apply_error_name(result.error) ==
                "authenticated_pointer_unsupported",
            "authenticated arm64e rejection has stable error name");
        expect(
            read_u64(fixture.address_space, Fixture::kRootBase + 0x70) == raw,
            "authenticated pointer rejection does not fake PAC mutation");
    }

    {
        Fixture fixture;
        auto fixups = metadata(ChainedPointerFormat::arm64e_userland);
        fixups.segments[0].pages[0].offsets.push_back(0x78);
        const std::uint64_t first_raw = arm64e_rebase(0x800, 1);
        const std::uint64_t auth_raw = arm64e_rebase(0x900, 0, true);
        load_u64(fixture.address_space, Fixture::kRootBase + 0x78, first_raw);
        load_u64(fixture.address_space, Fixture::kRootBase + 0x80, auth_raw);

        const auto result = macosarm::dyld::apply_chained_fixups(
            fixture.graph, 0, fixups, fixture.address_space);
        expect(
            result.error == ChainedFixupsApplyError::authenticated_pointer_unsupported,
            "mixed chain stops on authenticated pointer");
        expect(result.rolled_back, "mixed arm64e chain rolls back prior unauth fixup");
        expect(
            read_u64(fixture.address_space, Fixture::kRootBase + 0x78) == first_raw,
            "rollback restores earlier arm64e pointer exactly");
        expect(
            read_u64(fixture.address_space, Fixture::kRootBase + 0x80) == auth_raw,
            "failing authenticated pointer remains untouched");
    }

    {
        Fixture fixture;
        auto fixups = metadata(ChainedPointerFormat::arm64e_userland, 2);
        fixups.segments[0].pages[0].offsets.push_back(0x88);
        fixups.segments[0].pages[1].offsets.push_back(0x90);
        load_u64(fixture.address_space, Fixture::kRootBase + 0x88, arm64e_rebase(0x111));
        load_u64(
            fixture.address_space,
            Fixture::kRootBase + 0x4000 + 0x90,
            arm64e_rebase(0x222));

        const auto result = macosarm::dyld::apply_chained_fixups(
            fixture.graph, 0, fixups, fixture.address_space);
        expect(static_cast<bool>(result), "arm64e multiple pages apply");
        expect(result.fixups_processed == 2, "arm64e multiple pages count fixups");
        expect(
            read_u64(fixture.address_space, Fixture::kRootBase + 0x88) ==
                Fixture::kRootBase + 0x111,
            "arm64e first page rebase applied");
        expect(
            read_u64(fixture.address_space, Fixture::kRootBase + 0x4000 + 0x90) ==
                Fixture::kRootBase + 0x222,
            "arm64e second page rebase applied");
    }

    {
        Fixture fixture;
        auto fixups = metadata(ChainedPointerFormat::arm64e_userland);
        fixups.segments[0].pages[0].offsets.push_back(0xa0);
        const std::uint64_t first_raw = arm64e_rebase(0x400, 1);
        const std::uint64_t second_raw = arm64e_rebase(0x500);
        load_u64(fixture.address_space, Fixture::kRootBase + 0xa0, first_raw);
        load_u64(fixture.address_space, Fixture::kRootBase + 0xa8, second_raw);

        ChainedFixupsApplyConfig config;
        config.max_fixups = 1;
        const auto result = macosarm::dyld::apply_chained_fixups(
            fixture.graph, 0, fixups, fixture.address_space, config);
        expect(
            result.error == ChainedFixupsApplyError::fixup_limit,
            "arm64e deterministic fixup limit enforced");
        expect(result.rolled_back, "arm64e fixup-limit failure rolls back");
        expect(
            read_u64(fixture.address_space, Fixture::kRootBase + 0xa0) == first_raw,
            "fixup-limit rollback restores first pointer");
        expect(
            read_u64(fixture.address_space, Fixture::kRootBase + 0xa8) == second_raw,
            "fixup-limit failure leaves second pointer untouched");
    }

    if (failures != 0) {
        std::cerr << failures << " arm64e chained-fixup test(s) failed\n";
        return EXIT_FAILURE;
    }

    std::cout << "arm64e chained-fixup tests passed\n";
    return EXIT_SUCCESS;
}
