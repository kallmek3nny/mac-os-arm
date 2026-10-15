#include "macosarm/dyld_graph_fixups.hpp"

namespace {

constexpr std::size_t kGraphwideImportsOffset = 28U + 8U + 24U;
constexpr std::size_t kGraphwideSymbolsOffset = kGraphwideImportsOffset + 4U;

void graphwide_rewrite_import(
    std::vector<std::byte>& payload,
    bool weak_import,
    char first,
    char second,
    char third) {
    graphwide_put_u32(
        payload,
        kGraphwideImportsOffset,
        1U | (weak_import ? (1U << 8U) : 0U));
    payload.at(kGraphwideSymbolsOffset) = std::byte{'_'};
    payload.at(kGraphwideSymbolsOffset + 1U) = static_cast<std::byte>(first);
    payload.at(kGraphwideSymbolsOffset + 2U) = static_cast<std::byte>(second);
    payload.at(kGraphwideSymbolsOffset + 3U) = static_cast<std::byte>(third);
    payload.at(kGraphwideSymbolsOffset + 4U) = std::byte{0};
}

} // namespace

int dyld_graph_fixups_edgecases_main() {
    using macosarm::VmError;
    using macosarm::dyld::ChainedFixupsApplyError;
    using macosarm::dyld::ChainedPointerFormat;
    using macosarm::dyld::GraphFixupScanError;
    using macosarm::dyld::LoadedImageGraphFixupsError;
    using macosarm::dyld::LoadedImageGraphFixupsResult;

    {
        GraphwideFixture fixture;
        constexpr std::uint64_t root_value = 0x1122334455667788ULL;
        constexpr std::uint64_t dependency_value = 0x8877665544332211ULL;
        expect(graphwide_store_u64(
                   fixture.address_space,
                   GraphwideFixture::root_base + 0x20,
                   root_value) &&
                   graphwide_store_u64(
                       fixture.address_space,
                       GraphwideFixture::dependency_base + 0x20,
                       dependency_value),
               "graph no-fixup fixture stores sentinels");

        const auto result = macosarm::dyld::apply_loaded_image_graph_fixups(
            fixture.graph,
            fixture.address_space);
        expect(static_cast<bool>(result) &&
                   result.fixups_processed == 0 &&
                   !result.rolled_back &&
                   result.authenticated_slots.empty(),
               "graph with no retained chained fixups is a clean no-op");
        expect(graphwide_read_u64(
                   fixture.address_space,
                   GraphwideFixture::root_base + 0x20) == root_value &&
                   graphwide_read_u64(
                       fixture.address_space,
                       GraphwideFixture::dependency_base + 0x20) == dependency_value,
               "graph no-fixup path leaves guest memory unchanged");
    }

    {
        GraphwideFixture fixture;
        fixture.graph.images.resize(1);
        fixture.graph.images[0].dependencies.clear();
        fixture.graph.images[0].chained_fixups_payload =
            graphwide_payload(ChainedPointerFormat::generic64_kernel_cache);
        constexpr std::uint64_t raw = 0x1020304050607080ULL;
        expect(graphwide_store_u64(
                   fixture.address_space,
                   GraphwideFixture::root_base + 0x20,
                   raw),
               "unsupported-format fixture stores raw chain word");

        const auto result = macosarm::dyld::apply_loaded_image_graph_fixups(
            fixture.graph,
            fixture.address_space);
        expect(result.error == LoadedImageGraphFixupsError::scan_failure &&
                   result.scan_error == GraphFixupScanError::unsupported_pointer_format &&
                   result.failed_image_index == 0,
               "unsupported graph pointer format fails explicitly during preflight");
        expect(graphwide_read_u64(
                   fixture.address_space,
                   GraphwideFixture::root_base + 0x20) == raw,
               "unsupported graph pointer format fails before mutation");
    }

    {
        GraphwideFixture fixture;
        auto payload = graphwide_payload(ChainedPointerFormat::generic64, true);
        graphwide_rewrite_import(payload, false, 'b', 'a', 'r');
        fixture.graph.images[0].chained_fixups_payload = std::move(payload);

        const std::uint64_t first_raw =
            graphwide_generic_rebase(GraphwideFixture::root_base + 0xb00) |
            (std::uint64_t{2} << 51U);
        const std::uint64_t second_raw = graphwide_generic_bind(0);
        expect(graphwide_store_u64(
                   fixture.address_space,
                   GraphwideFixture::root_base + 0x20,
                   first_raw) &&
                   graphwide_store_u64(
                       fixture.address_space,
                       GraphwideFixture::root_base + 0x28,
                       second_raw),
               "missing-symbol graph fixture stores two-slot chain");

        const auto result = macosarm::dyld::apply_loaded_image_graph_fixups(
            fixture.graph,
            fixture.address_space);
        expect(result.error == LoadedImageGraphFixupsError::generic_apply_failure &&
                   result.failed_image_index == 0 &&
                   result.generic_error == ChainedFixupsApplyError::symbol_not_found &&
                   result.rolled_back,
               "graph symbol-resolution failure is explicit and transactional");
        expect(graphwide_read_u64(
                   fixture.address_space,
                   GraphwideFixture::root_base + 0x20) == first_raw &&
                   graphwide_read_u64(
                       fixture.address_space,
                       GraphwideFixture::root_base + 0x28) == second_raw,
               "symbol-resolution failure restores earlier writes in the same graph image");
    }

    {
        GraphwideFixture fixture;
        auto payload = graphwide_payload(ChainedPointerFormat::generic64, true);
        graphwide_rewrite_import(payload, true, 'b', 'a', 'r');
        fixture.graph.images[0].chained_fixups_payload = std::move(payload);
        const std::uint64_t raw = graphwide_generic_bind(0);
        expect(graphwide_store_u64(
                   fixture.address_space,
                   GraphwideFixture::root_base + 0x20,
                   raw),
               "weak-null graph fixture stores bind chain");

        const auto result = macosarm::dyld::apply_loaded_image_graph_fixups(
            fixture.graph,
            fixture.address_space);
        expect(static_cast<bool>(result) &&
                   result.fixups_processed == 1 &&
                   result.authenticated_slots.empty(),
               "missing weak graph bind succeeds without synthetic authentication state");
        expect(graphwide_read_u64(
                   fixture.address_space,
                   GraphwideFixture::root_base + 0x20) == 0,
               "missing weak graph bind materializes a null pointer");
    }

    {
        GraphwideFixture fixture;
        fixture.graph.images[0].chained_fixups_payload =
            graphwide_payload(ChainedPointerFormat::arm64e_userland);
        fixture.graph.images[1].chained_fixups_payload =
            graphwide_payload(ChainedPointerFormat::arm64e_userland24);
        constexpr std::uint64_t root_offset = 0xb00;
        constexpr std::uint64_t dependency_offset = 0xc00;
        expect(graphwide_store_u64(
                   fixture.address_space,
                   GraphwideFixture::root_base + 0x20,
                   graphwide_arm64e_rebase(root_offset)) &&
                   graphwide_store_u64(
                       fixture.address_space,
                       GraphwideFixture::dependency_base + 0x20,
                       graphwide_arm64e_rebase(dependency_offset)),
               "multi-image ARM64e fixture stores raw chains");

        const auto result = macosarm::dyld::apply_loaded_image_graph_fixups(
            fixture.graph,
            fixture.address_space);
        expect(static_cast<bool>(result) &&
                   result.fixups_processed == 2 &&
                   result.authenticated_slots.empty(),
               "ARM64e userland and userland24 apply coherently across graph images");
        expect(graphwide_read_u64(
                   fixture.address_space,
                   GraphwideFixture::root_base + 0x20) ==
                   GraphwideFixture::root_base + root_offset &&
                   graphwide_read_u64(
                       fixture.address_space,
                       GraphwideFixture::dependency_base + 0x20) ==
                   GraphwideFixture::dependency_base + dependency_offset,
               "multi-image ARM64e rebases use each image base independently");
    }

    {
        macosarm::GuestAddressSpace vm;
        std::vector<macosarm::dyld::graph_fixup_detail::PreparedImage> prepared(1);
        prepared[0].image_index = 7;
        constexpr std::uint64_t address = 0x12345000ULL;
        prepared[0].journal.push_back({address, 0x1122334455667788ULL});
        LoadedImageGraphFixupsResult result;
        result.authenticated_slots.push_back({
            address,
            macosarm::PointerAuthKey::data_a,
            0x1234,
            true,
        });

        const bool restored = macosarm::dyld::graph_fixup_detail::restore_prepared_images(
            prepared,
            prepared.size(),
            vm,
            result);
        expect(!restored &&
                   result.error == LoadedImageGraphFixupsError::rollback_failure &&
                   result.failed_image_index == 7 &&
                   result.address == address &&
                   result.vm_error == VmError::unmapped &&
                   result.rolled_back &&
                   result.authenticated_slots.empty(),
               "graph rollback write failure is explicit and suppresses stale authenticated-slot state");
    }

    if (failures != 0) {
        std::cerr << failures << " graph-wide fixup edge-case test(s) failed\n";
        return EXIT_FAILURE;
    }
    std::cout << "graph-wide retained fixup edge-case tests passed\n";
    return EXIT_SUCCESS;
}
