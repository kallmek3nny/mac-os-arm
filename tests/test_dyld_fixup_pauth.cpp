#include "macosarm/dyld_fixup_pauth.hpp"

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

macosarm::PointerAuthKeySet test_keys() {
    macosarm::PointerAuthKeySet keys;
    keys.values[0] = {0x0123456789abcdefULL, 0xfedcba9876543210ULL};
    keys.values[1] = {0x1111222233334444ULL, 0x5555666677778888ULL};
    keys.values[2] = {0x1020304050607080ULL, 0x90a0b0c0d0e0f000ULL};
    keys.values[3] = {0x0f1e2d3c4b5a6978ULL, 0x8796a5b4c3d2e1f0ULL};
    return keys;
}

std::uint64_t auth_rebase(
    std::uint32_t target_offset,
    std::uint16_t diversity,
    macosarm::PointerAuthKey key,
    bool address_diversity,
    std::uint16_t next = 0) {
    return static_cast<std::uint64_t>(target_offset) |
           (static_cast<std::uint64_t>(diversity) << 32) |
           (static_cast<std::uint64_t>(address_diversity ? 1U : 0U) << 48) |
           ((static_cast<std::uint64_t>(key) & 0x3U) << 49) |
           ((static_cast<std::uint64_t>(next) & 0x7ffU) << 51) |
           (std::uint64_t{1} << 63);
}

std::uint64_t auth_bind16(
    std::uint16_t ordinal,
    std::uint16_t diversity,
    macosarm::PointerAuthKey key,
    bool address_diversity,
    std::uint16_t next = 0,
    std::uint16_t zero = 0) {
    return static_cast<std::uint64_t>(ordinal) |
           (static_cast<std::uint64_t>(zero) << 16) |
           (static_cast<std::uint64_t>(diversity) << 32) |
           (static_cast<std::uint64_t>(address_diversity ? 1U : 0U) << 48) |
           ((static_cast<std::uint64_t>(key) & 0x3U) << 49) |
           ((static_cast<std::uint64_t>(next) & 0x7ffU) << 51) |
           (std::uint64_t{1} << 62) |
           (std::uint64_t{1} << 63);
}

std::uint64_t auth_bind24(
    std::uint32_t ordinal,
    std::uint16_t diversity,
    macosarm::PointerAuthKey key,
    bool address_diversity,
    std::uint16_t next = 0,
    std::uint8_t zero = 0) {
    return (static_cast<std::uint64_t>(ordinal) & 0xffffffU) |
           (static_cast<std::uint64_t>(zero) << 24) |
           (static_cast<std::uint64_t>(diversity) << 32) |
           (static_cast<std::uint64_t>(address_diversity ? 1U : 0U) << 48) |
           ((static_cast<std::uint64_t>(key) & 0x3U) << 49) |
           ((static_cast<std::uint64_t>(next) & 0x7ffU) << 51) |
           (std::uint64_t{1} << 62) |
           (std::uint64_t{1} << 63);
}

std::uint64_t unauth_rebase(std::uint64_t target, std::uint16_t next = 0) {
    const std::uint64_t low43 = target & ((std::uint64_t{1} << 43) - 1);
    const std::uint64_t high8 = (target >> 56) & 0xffU;
    return low43 | (high8 << 43) |
           ((static_cast<std::uint64_t>(next) & 0x7ffU) << 51);
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

    Fixture() {
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
            macosarm::macho::Segment{"__DATA", kRootBase, 0x8000, 0, 0, 3, 3});

        macosarm::dyld::GraphImage dependency;
        dependency.path = "/libA.dylib";
        dependency.mapping.preferred_load_address = kDependencyBase;
        dependency.image.segments.push_back(
            macosarm::macho::Segment{"__TEXT", kDependencyBase, 0x4000, 0, 0, 5, 5});
        dependency.exports.push_back(
            export_symbol("_foo", macosarm::dyld::ExportKind::regular, 0x180));
        dependency.exports.push_back(
            export_symbol(
                "_huge",
                macosarm::dyld::ExportKind::absolute,
                0x0001000000000000ULL));

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
    std::size_t pages = 1) {
    macosarm::dyld::ChainedFixupsMetadata result;
    result.segments.resize(1);
    auto& segment = result.segments[0];
    segment.present = true;
    segment.page_size = 0x4000;
    segment.pointer_format = format;
    segment.segment_offset = 0;
    segment.pages.resize(pages);
    return result;
}

} // namespace

int main() {
    using macosarm::PointerAuthError;
    using macosarm::PointerAuthKey;
    using macosarm::PointerAuthenticator;
    using macosarm::dyld::Arm64eFixupsApplyConfig;
    using macosarm::dyld::Arm64eFixupsApplyError;
    using macosarm::dyld::ChainedImportEntry;
    using macosarm::dyld::ChainedPointerFormat;

    const PointerAuthenticator authenticator(test_keys());

    {
        Fixture fixture;
        auto fixups = metadata(ChainedPointerFormat::arm64e_userland);
        fixups.segments[0].pages[0].offsets.push_back(0x20);
        const std::uint64_t raw = auth_rebase(0x1234, 0x55aa, PointerAuthKey::instruction_a, false);
        load_u64(fixture.address_space, Fixture::kRootBase + 0x20, raw);

        const auto result = macosarm::dyld::apply_arm64e_chained_fixups(
            fixture.graph, 0, fixups, fixture.address_space);
        expect(
            result.error == Arm64eFixupsApplyError::pointer_auth_required,
            "authenticated fixups require explicit pointer-auth policy");
        expect(
            read_u64(fixture.address_space, Fixture::kRootBase + 0x20) == raw,
            "missing pointer-auth policy leaves raw chain untouched");
    }

    {
        Fixture fixture;
        auto fixups = metadata(ChainedPointerFormat::arm64e_userland);
        fixups.segments[0].pages[0].offsets.push_back(0x28);
        constexpr std::uint16_t diversity = 0x1234;
        load_u64(
            fixture.address_space,
            Fixture::kRootBase + 0x28,
            auth_rebase(0x3456, diversity, PointerAuthKey::instruction_a, false));

        Arm64eFixupsApplyConfig config;
        config.pointer_auth = &authenticator;
        const auto result = macosarm::dyld::apply_arm64e_chained_fixups(
            fixture.graph, 0, fixups, fixture.address_space, config);
        const auto expected = authenticator.sign(
            Fixture::kRootBase + 0x3456,
            PointerAuthKey::instruction_a,
            diversity);
        expect(static_cast<bool>(result), "authenticated arm64e rebase applies");
        expect(static_cast<bool>(expected), "expected authenticated rebase signs");
        expect(
            read_u64(fixture.address_space, Fixture::kRootBase + 0x28) == expected.pointer,
            "authenticated rebase writes software-signed target");
    }

    {
        Fixture fixture;
        auto fixups = metadata(ChainedPointerFormat::arm64e_userland);
        constexpr std::uint64_t slot = Fixture::kRootBase + 0x30;
        constexpr std::uint16_t diversity = 0xbeef;
        fixups.segments[0].pages[0].offsets.push_back(0x30);
        load_u64(
            fixture.address_space,
            slot,
            auth_rebase(0x444, diversity, PointerAuthKey::data_b, true));

        Arm64eFixupsApplyConfig config;
        config.pointer_auth = &authenticator;
        const auto result = macosarm::dyld::apply_arm64e_chained_fixups(
            fixture.graph, 0, fixups, fixture.address_space, config);
        const std::uint64_t signed_value = read_u64(fixture.address_space, slot);
        expect(static_cast<bool>(result), "address-diverse authenticated rebase applies");
        expect(
            static_cast<bool>(authenticator.authenticate(
                signed_value,
                PointerAuthKey::data_b,
                PointerAuthenticator::blend_discriminator(slot, diversity))),
            "address-diverse rebase authenticates at original storage address");
        expect(
            authenticator.authenticate(
                    signed_value,
                    PointerAuthKey::data_b,
                    PointerAuthenticator::blend_discriminator(slot + 8, diversity))
                    .error == PointerAuthError::invalid_signature,
            "address-diverse rebase fails at a different storage address");
    }

    {
        Fixture fixture;
        auto fixups = metadata(ChainedPointerFormat::arm64e_userland);
        fixups.imports.push_back(ChainedImportEntry{1, false, "_foo", 7});
        fixups.segments[0].pages[0].offsets.push_back(0x38);
        constexpr std::uint16_t diversity = 0x77;
        load_u64(
            fixture.address_space,
            Fixture::kRootBase + 0x38,
            auth_bind16(0, diversity, PointerAuthKey::data_a, false));

        Arm64eFixupsApplyConfig config;
        config.pointer_auth = &authenticator;
        const auto result = macosarm::dyld::apply_arm64e_chained_fixups(
            fixture.graph, 0, fixups, fixture.address_space, config);
        const auto expected = authenticator.sign(
            Fixture::kDependencyBase + 0x187,
            PointerAuthKey::data_a,
            diversity);
        expect(static_cast<bool>(result), "authenticated cross-image bind applies");
        expect(
            read_u64(fixture.address_space, Fixture::kRootBase + 0x38) == expected.pointer,
            "authenticated bind signs resolved symbol plus import addend");
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
            auth_bind24(0x10000, 0x99, PointerAuthKey::instruction_b, false));

        Arm64eFixupsApplyConfig config;
        config.pointer_auth = &authenticator;
        const auto result = macosarm::dyld::apply_arm64e_chained_fixups(
            fixture.graph, 0, fixups, fixture.address_space, config);
        expect(static_cast<bool>(result), "authenticated userland24 bind accepts 24-bit ordinal");
        expect(
            static_cast<bool>(authenticator.authenticate(
                read_u64(fixture.address_space, Fixture::kRootBase + 0x40),
                PointerAuthKey::instruction_b,
                0x99)),
            "authenticated userland24 bind uses requested key and diversity");
    }

    {
        Fixture fixture;
        auto fixups = metadata(ChainedPointerFormat::arm64e_userland);
        fixups.imports.push_back(ChainedImportEntry{1, true, "_missing", 99});
        fixups.segments[0].pages[0].offsets.push_back(0x48);
        load_u64(
            fixture.address_space,
            Fixture::kRootBase + 0x48,
            auth_bind16(0, 0x22, PointerAuthKey::data_a, true));

        Arm64eFixupsApplyConfig config;
        config.pointer_auth = &authenticator;
        const auto result = macosarm::dyld::apply_arm64e_chained_fixups(
            fixture.graph, 0, fixups, fixture.address_space, config);
        expect(static_cast<bool>(result), "authenticated weak missing bind applies");
        expect(
            read_u64(fixture.address_space, Fixture::kRootBase + 0x48) == 0,
            "authenticated weak missing bind remains null rather than signing zero");
    }

    {
        Fixture fixture;
        auto fixups = metadata(ChainedPointerFormat::arm64e_userland);
        fixups.imports.push_back(ChainedImportEntry{1, false, "_foo", 0});
        fixups.segments[0].pages[0].offsets.push_back(0x50);
        const std::uint64_t raw =
            auth_bind16(0, 0x11, PointerAuthKey::data_a, false, 0, 1);
        load_u64(fixture.address_space, Fixture::kRootBase + 0x50, raw);

        Arm64eFixupsApplyConfig config;
        config.pointer_auth = &authenticator;
        const auto result = macosarm::dyld::apply_arm64e_chained_fixups(
            fixture.graph, 0, fixups, fixture.address_space, config);
        expect(
            result.error == Arm64eFixupsApplyError::pointer_reserved_bits,
            "authenticated bind rejects nonzero reserved field");
        expect(
            read_u64(fixture.address_space, Fixture::kRootBase + 0x50) == raw,
            "malformed authenticated bind does not mutate memory");
    }

    {
        Fixture fixture;
        auto fixups = metadata(ChainedPointerFormat::arm64e_userland);
        fixups.imports.push_back(ChainedImportEntry{1, false, "_huge", 0});
        fixups.segments[0].pages[0].offsets.push_back(0x58);
        const std::uint64_t raw =
            auth_bind16(0, 0x44, PointerAuthKey::instruction_a, false);
        load_u64(fixture.address_space, Fixture::kRootBase + 0x58, raw);

        Arm64eFixupsApplyConfig config;
        config.pointer_auth = &authenticator;
        const auto result = macosarm::dyld::apply_arm64e_chained_fixups(
            fixture.graph, 0, fixups, fixture.address_space, config);
        expect(
            result.error == Arm64eFixupsApplyError::pointer_auth_failure &&
                result.pointer_auth_error == PointerAuthError::pointer_out_of_range,
            "authenticated bind reports software PAUTH policy failure precisely");
        expect(
            read_u64(fixture.address_space, Fixture::kRootBase + 0x58) == raw,
            "pointer-auth failure leaves current raw word untouched");
    }

    {
        Fixture fixture;
        auto fixups = metadata(ChainedPointerFormat::arm64e_userland);
        fixups.imports.push_back(ChainedImportEntry{1, false, "_foo", 0});
        fixups.segments[0].pages[0].offsets.push_back(0x60);
        const std::uint64_t first_raw =
            auth_rebase(0x700, 0x51, PointerAuthKey::data_b, true, 1);
        const std::uint64_t second_raw =
            auth_bind16(0, 0x52, PointerAuthKey::data_a, false, 0, 1);
        load_u64(fixture.address_space, Fixture::kRootBase + 0x60, first_raw);
        load_u64(fixture.address_space, Fixture::kRootBase + 0x68, second_raw);

        Arm64eFixupsApplyConfig config;
        config.pointer_auth = &authenticator;
        const auto result = macosarm::dyld::apply_arm64e_chained_fixups(
            fixture.graph, 0, fixups, fixture.address_space, config);
        expect(
            result.error == Arm64eFixupsApplyError::pointer_reserved_bits,
            "later authenticated-chain failure is surfaced");
        expect(result.rolled_back, "authenticated-chain failure rolls back prior signed write");
        expect(
            read_u64(fixture.address_space, Fixture::kRootBase + 0x60) == first_raw &&
                read_u64(fixture.address_space, Fixture::kRootBase + 0x68) == second_raw,
            "authenticated rollback restores exact raw chain words");
    }

    {
        Fixture fixture;
        auto fixups = metadata(ChainedPointerFormat::arm64e_userland);
        fixups.segments[0].pages[0].offsets.push_back(0x70);
        load_u64(fixture.address_space, Fixture::kRootBase + 0x70, unauth_rebase(0x888));

        Arm64eFixupsApplyConfig config;
        config.pointer_auth = &authenticator;
        const auto result = macosarm::dyld::apply_arm64e_chained_fixups(
            fixture.graph, 0, fixups, fixture.address_space, config);
        expect(static_cast<bool>(result), "PAUTH-aware arm64e applier preserves unauth fixups");
        expect(
            read_u64(fixture.address_space, Fixture::kRootBase + 0x70) ==
                Fixture::kRootBase + 0x888,
            "PAUTH-aware applier preserves phase-21 userland rebase semantics");
    }

    expect(
        macosarm::dyld::arm64e_fixups_apply_error_name(
            Arm64eFixupsApplyError::pointer_auth_failure) == "pointer_auth_failure",
        "authenticated-fixup errors have stable names");

    if (failures != 0) {
        std::cerr << failures << " authenticated arm64e fixup test(s) failed\n";
        return EXIT_FAILURE;
    }

    std::cout << "authenticated arm64e chained-fixup tests passed\n";
    return EXIT_SUCCESS;
}
