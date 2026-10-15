#include "macosarm/dyld_fixups.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <limits>
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

std::uint64_t rebase64(std::uint64_t target, std::uint16_t next = 0) {
    const std::uint64_t low36 = target & ((std::uint64_t{1} << 36) - 1);
    const std::uint64_t high8 = (target >> 56) & 0xffU;
    return low36 | (high8 << 36) | (static_cast<std::uint64_t>(next) << 51);
}

std::uint64_t bind64(
    std::uint32_t ordinal,
    std::uint8_t addend = 0,
    std::uint16_t next = 0) {
    return (static_cast<std::uint64_t>(ordinal) & 0xffffffU) |
           (static_cast<std::uint64_t>(addend) << 24) |
           (static_cast<std::uint64_t>(next) << 51) |
           (std::uint64_t{1} << 63);
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

    explicit Fixture(
        std::uint64_t root_segment_size = 0x8000,
        macosarm::Protection protection =
            macosarm::Protection::read | macosarm::Protection::write) {
        expect(
            static_cast<bool>(address_space.map(kRootBase, 0x8000, protection)),
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
        auto fixups = metadata(ChainedPointerFormat::generic64);
        fixups.segments[0].pages[0].offsets.push_back(0x20);
        const std::uint64_t target = Fixture::kRootBase + 0x1234;
        load_u64(fixture.address_space, Fixture::kRootBase + 0x20, rebase64(target));

        const auto result = macosarm::dyld::apply_chained_fixups(
            fixture.graph, 0, fixups, fixture.address_space);
        expect(static_cast<bool>(result), "generic64 rebase applies");
        expect(
            read_u64(fixture.address_space, Fixture::kRootBase + 0x20) == target,
            "generic64 rebase restores vm address");
    }

    {
        Fixture fixture;
        auto fixups = metadata(ChainedPointerFormat::generic64_offset);
        fixups.segments[0].pages[0].offsets.push_back(0x28);
        load_u64(fixture.address_space, Fixture::kRootBase + 0x28, rebase64(0x3456));

        const auto result = macosarm::dyld::apply_chained_fixups(
            fixture.graph, 0, fixups, fixture.address_space);
        expect(static_cast<bool>(result), "generic64 offset rebase applies");
        expect(
            read_u64(fixture.address_space, Fixture::kRootBase + 0x28) ==
                Fixture::kRootBase + 0x3456,
            "generic64 offset rebase adds image base");
    }

    {
        Fixture fixture;
        auto fixups = metadata(ChainedPointerFormat::generic64);
        fixups.imports.push_back(ChainedImportEntry{1, false, "_foo", 0});
        fixups.segments[0].pages[0].offsets.push_back(0x30);
        load_u64(fixture.address_space, Fixture::kRootBase + 0x30, bind64(0));

        const auto result = macosarm::dyld::apply_chained_fixups(
            fixture.graph, 0, fixups, fixture.address_space);
        expect(static_cast<bool>(result), "cross-image bind applies");
        expect(
            read_u64(fixture.address_space, Fixture::kRootBase + 0x30) ==
                Fixture::kDependencyBase + 0x180,
            "bind resolves through one-based dependency ordinal");
    }

    {
        Fixture fixture;
        auto fixups = metadata(ChainedPointerFormat::generic64);
        fixups.imports.push_back(ChainedImportEntry{1, false, "_foo", -5});
        fixups.segments[0].pages[0].offsets.push_back(0x38);
        load_u64(fixture.address_space, Fixture::kRootBase + 0x38, bind64(0, 7));

        const auto result = macosarm::dyld::apply_chained_fixups(
            fixture.graph, 0, fixups, fixture.address_space);
        expect(static_cast<bool>(result), "bind addends apply");
        expect(
            read_u64(fixture.address_space, Fixture::kRootBase + 0x38) ==
                Fixture::kDependencyBase + 0x182,
            "import and pointer addends combine without truncation");
    }

    {
        Fixture fixture;
        auto fixups = metadata(ChainedPointerFormat::generic64);
        fixups.imports.push_back(ChainedImportEntry{1, true, "_missing", 99});
        fixups.segments[0].pages[0].offsets.push_back(0x40);
        load_u64(fixture.address_space, Fixture::kRootBase + 0x40, bind64(0, 17));

        const auto result = macosarm::dyld::apply_chained_fixups(
            fixture.graph, 0, fixups, fixture.address_space);
        expect(static_cast<bool>(result), "weak missing bind applies");
        expect(
            read_u64(fixture.address_space, Fixture::kRootBase + 0x40) == 0,
            "weak missing bind writes null and ignores addends");
    }

    {
        Fixture fixture;
        auto fixups = metadata(ChainedPointerFormat::generic64);
        fixups.imports.push_back(ChainedImportEntry{1, false, "_foo", 0});
        fixups.segments[0].pages[0].offsets.push_back(0x48);
        const std::uint64_t raw = bind64(4);
        load_u64(fixture.address_space, Fixture::kRootBase + 0x48, raw);

        const auto result = macosarm::dyld::apply_chained_fixups(
            fixture.graph, 0, fixups, fixture.address_space);
        expect(
            result.error == ChainedFixupsApplyError::bind_ordinal_out_of_range,
            "invalid bind ordinal rejected");
        expect(
            read_u64(fixture.address_space, Fixture::kRootBase + 0x48) == raw,
            "invalid bind ordinal does not mutate memory");
    }

    {
        Fixture fixture;
        auto fixups = metadata(ChainedPointerFormat::generic64);
        fixups.imports.push_back(ChainedImportEntry{2, false, "_foo", 0});
        fixups.segments[0].pages[0].offsets.push_back(0x50);
        load_u64(fixture.address_space, Fixture::kRootBase + 0x50, bind64(0));

        const auto result = macosarm::dyld::apply_chained_fixups(
            fixture.graph, 0, fixups, fixture.address_space);
        expect(
            result.error == ChainedFixupsApplyError::library_ordinal_out_of_range,
            "invalid dependency ordinal rejected");
    }

    {
        Fixture fixture;
        auto fixups = metadata(ChainedPointerFormat::arm64e_userland);
        fixups.segments[0].pages[0].offsets.push_back(0x58);
        const std::uint64_t raw = std::uint64_t{1} << 63;
        load_u64(fixture.address_space, Fixture::kRootBase + 0x58, raw);

        const auto result = macosarm::dyld::apply_chained_fixups(
            fixture.graph, 0, fixups, fixture.address_space);
        expect(
            result.error == ChainedFixupsApplyError::authenticated_pointer_unsupported,
            "authenticated arm64e pointer rejected instead of faking PAC");
        expect(
            read_u64(fixture.address_space, Fixture::kRootBase + 0x58) == raw,
            "authenticated arm64e rejection leaves memory untouched");
    }

    {
        Fixture fixture;
        auto fixups = metadata(ChainedPointerFormat::generic64);
        fixups.segments[0].pages[0].offsets.push_back(0x60);
        const std::uint64_t raw = rebase64(0x1234) | (std::uint64_t{1} << 44);
        load_u64(fixture.address_space, Fixture::kRootBase + 0x60, raw);

        const auto result = macosarm::dyld::apply_chained_fixups(
            fixture.graph, 0, fixups, fixture.address_space);
        expect(
            result.error == ChainedFixupsApplyError::pointer_reserved_bits,
            "generic64 reserved bits rejected");
    }

    {
        Fixture fixture;
        auto fixups = metadata(ChainedPointerFormat::generic64);
        fixups.segments[0].pages[0].offsets.push_back(0x3ff8);
        const std::uint64_t raw = rebase64(0x1234, 1);
        load_u64(fixture.address_space, Fixture::kRootBase + 0x3ff8, raw);

        const auto result = macosarm::dyld::apply_chained_fixups(
            fixture.graph, 0, fixups, fixture.address_space);
        expect(
            result.error == ChainedFixupsApplyError::chain_next_out_of_page,
            "chain next delta cannot leave its page");
        expect(
            read_u64(fixture.address_space, Fixture::kRootBase + 0x3ff8) == raw,
            "bad next delta is detected before current pointer write");
    }

    {
        Fixture fixture(0x2000);
        auto fixups = metadata(ChainedPointerFormat::generic64);
        fixups.segments[0].pages[0].offsets.push_back(0x1ff8);
        load_u64(
            fixture.address_space,
            Fixture::kRootBase + 0x1ff8,
            rebase64(0x1234, 1));

        const auto result = macosarm::dyld::apply_chained_fixups(
            fixture.graph, 0, fixups, fixture.address_space);
        expect(
            result.error == ChainedFixupsApplyError::chain_next_out_of_segment,
            "chain next delta cannot leave Mach-O segment");
    }

    {
        Fixture fixture;
        fixture.graph.images[1].exports.push_back(
            export_symbol(
                "_huge",
                macosarm::dyld::ExportKind::absolute,
                std::numeric_limits<std::uint64_t>::max() - 1));
        auto fixups = metadata(ChainedPointerFormat::generic64);
        fixups.imports.push_back(ChainedImportEntry{1, false, "_huge", 0});
        fixups.segments[0].pages[0].offsets.push_back(0x68);
        load_u64(fixture.address_space, Fixture::kRootBase + 0x68, bind64(0, 4));

        const auto result = macosarm::dyld::apply_chained_fixups(
            fixture.graph, 0, fixups, fixture.address_space);
        expect(
            result.error == ChainedFixupsApplyError::addend_overflow,
            "bind addend overflow rejected");
    }

    {
        Fixture fixture;
        auto fixups = metadata(ChainedPointerFormat::generic64);
        fixups.segments[0].pages[0].offsets.push_back(0x20);
        const std::uint64_t first = rebase64(Fixture::kRootBase + 0x500, 4);
        const std::uint64_t second = bind64(0);
        load_u64(fixture.address_space, Fixture::kRootBase + 0x20, first);
        load_u64(fixture.address_space, Fixture::kRootBase + 0x30, second);

        const auto result = macosarm::dyld::apply_chained_fixups(
            fixture.graph, 0, fixups, fixture.address_space);
        expect(
            result.error == ChainedFixupsApplyError::bind_ordinal_out_of_range &&
                result.rolled_back &&
                result.fixups_processed == 1,
            "later chain failure rolls back earlier applied fixup");
        expect(
            read_u64(fixture.address_space, Fixture::kRootBase + 0x20) == first &&
                read_u64(fixture.address_space, Fixture::kRootBase + 0x30) == second,
            "rollback restores exact raw chain words");
    }

    {
        Fixture fixture;
        auto fixups = metadata(ChainedPointerFormat::generic64, 2);
        fixups.segments[0].pages[0].offsets.push_back(0x20);
        fixups.segments[0].pages[1].offsets.push_back(0x28);
        load_u64(
            fixture.address_space,
            Fixture::kRootBase + 0x20,
            rebase64(Fixture::kRootBase + 0x700));
        load_u64(
            fixture.address_space,
            Fixture::kRootBase + 0x4000 + 0x28,
            rebase64(Fixture::kRootBase + 0x800));

        const auto result = macosarm::dyld::apply_chained_fixups(
            fixture.graph, 0, fixups, fixture.address_space);
        expect(static_cast<bool>(result) && result.fixups_processed == 2,
               "multiple chained-fixup pages apply");
        expect(
            read_u64(fixture.address_space, Fixture::kRootBase + 0x20) ==
                    Fixture::kRootBase + 0x700 &&
                read_u64(fixture.address_space, Fixture::kRootBase + 0x4000 + 0x28) ==
                    Fixture::kRootBase + 0x800,
            "multiple pages receive independent rebases");
    }

    {
        Fixture fixture;
        auto fixups = metadata(ChainedPointerFormat::generic64, 2);
        fixups.segments[0].pages[0].offsets.push_back(0x20);
        fixups.segments[0].pages[1].offsets.push_back(0x20);
        const std::uint64_t first = rebase64(Fixture::kRootBase + 0x900);
        const std::uint64_t second = rebase64(Fixture::kRootBase + 0xa00);
        load_u64(fixture.address_space, Fixture::kRootBase + 0x20, first);
        load_u64(fixture.address_space, Fixture::kRootBase + 0x4000 + 0x20, second);

        ChainedFixupsApplyConfig config;
        config.max_fixups = 1;
        const auto result = macosarm::dyld::apply_chained_fixups(
            fixture.graph, 0, fixups, fixture.address_space, config);
        expect(
            result.error == ChainedFixupsApplyError::fixup_limit &&
                result.rolled_back,
            "fixup abuse limit rolls back prior pages");
        expect(
            read_u64(fixture.address_space, Fixture::kRootBase + 0x20) == first &&
                read_u64(fixture.address_space, Fixture::kRootBase + 0x4000 + 0x20) == second,
            "fixup-limit rollback restores all prior writes");
    }

    {
        Fixture fixture(0x8000, macosarm::Protection::read);
        auto fixups = metadata(ChainedPointerFormat::generic64);
        fixups.segments[0].pages[0].offsets.push_back(0x20);
        const std::uint64_t raw = rebase64(Fixture::kRootBase + 0xb00);
        load_u64(fixture.address_space, Fixture::kRootBase + 0x20, raw);

        const auto result = macosarm::dyld::apply_chained_fixups(
            fixture.graph, 0, fixups, fixture.address_space);
        expect(
            result.error == ChainedFixupsApplyError::write_failure &&
                result.vm_error == macosarm::VmError::protection,
            "fixups cannot write into read-only mappings");
        expect(
            read_u64(fixture.address_space, Fixture::kRootBase + 0x20) == raw,
            "write-protection failure leaves raw pointer intact");
    }

    {
        Fixture fixture;
        auto fixups = metadata(ChainedPointerFormat::generic64);
        fixups.segments[0].segment_offset = 0x100;
        const auto result = macosarm::dyld::apply_chained_fixups(
            fixture.graph, 0, fixups, fixture.address_space);
        expect(
            result.error == ChainedFixupsApplyError::segment_offset_mismatch,
            "metadata segment offset must match selected Mach-O segment");
    }

    {
        Fixture fixture;
        auto fixups = metadata(ChainedPointerFormat::generic64);
        fixups.segments[0].pages[0].offsets = {0x20, 0x40};
        const auto result = macosarm::dyld::apply_chained_fixups(
            fixture.graph, 0, fixups, fixture.address_space);
        expect(
            result.error == ChainedFixupsApplyError::multiple_page_starts_unsupported,
            "generic64 multi-start pages rejected explicitly");
    }

    expect(
        macosarm::dyld::chained_fixups_apply_error_name(
            ChainedFixupsApplyError::rollback_failure) == "rollback_failure",
        "apply errors have stable names");

    if (failures != 0) {
        std::cerr << failures << " test(s) failed\n";
        return EXIT_FAILURE;
    }
    std::cout << "dyld generic chained-fixup apply tests passed\n";
    return EXIT_SUCCESS;
}
