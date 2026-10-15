#include "macosarm/dyld_auth_slots.hpp"

int dyld_auth_slots_main() {
    using macosarm::PointerAuthKey;
    using macosarm::PointerAuthenticator;
    using macosarm::dyld::Arm64eFixupsApplyConfig;
    using macosarm::dyld::Arm64eFixupsApplyError;
    using macosarm::dyld::AuthenticatedFixupSlot;
    using macosarm::dyld::AuthenticatedFixupSlotScanError;
    using macosarm::dyld::ChainedImportEntry;
    using macosarm::dyld::ChainedPointerFormat;

    const PointerAuthenticator authenticator(test_keys());

    {
        Fixture fixture;
        auto fixups = metadata(ChainedPointerFormat::arm64e_userland);
        constexpr std::uint64_t slot = Fixture::kRootBase + 0x100;
        constexpr std::uint16_t diversity = 0x1357;
        fixups.segments[0].pages[0].offsets.push_back(0x100);
        load_u64(
            fixture.address_space,
            slot,
            auth_rebase(0x900, diversity, PointerAuthKey::instruction_b, true));

        Arm64eFixupsApplyConfig config;
        config.pointer_auth = &authenticator;
        const auto result = macosarm::dyld::apply_arm64e_chained_fixups_with_auth_slots(
            fixture.graph, 0, fixups, fixture.address_space, config);

        expect(static_cast<bool>(result), "authenticated-slot wrapper applies fixups");
        expect(result.fixups_scanned == 1, "authenticated-slot wrapper scans exactly one chain entry");
        expect(result.apply.fixups_processed == 1, "authenticated-slot wrapper preserves apply count");
        expect(result.authenticated_slots.size() == 1,
               "authenticated-slot wrapper retains one authenticated slot");
        if (result.authenticated_slots.size() == 1) {
            const AuthenticatedFixupSlot expected{
                slot,
                PointerAuthKey::instruction_b,
                diversity,
                true,
            };
            expect(result.authenticated_slots.front() == expected,
                   "authenticated-slot descriptor preserves storage address/key/diversity policy");
        }
        expect(static_cast<bool>(authenticator.authenticate(
                   read_u64(fixture.address_space, slot),
                   PointerAuthKey::instruction_b,
                   PointerAuthenticator::blend_discriminator(slot, diversity))),
               "retained descriptor authenticates the pointer written by the real applier");
    }

    {
        Fixture fixture;
        auto fixups = metadata(ChainedPointerFormat::arm64e_userland);
        constexpr std::uint64_t first_slot = Fixture::kRootBase + 0x120;
        constexpr std::uint64_t second_slot = first_slot + 8;
        fixups.segments[0].pages[0].offsets.push_back(0x120);
        load_u64(
            fixture.address_space,
            first_slot,
            auth_rebase(0xa00, 0x11, PointerAuthKey::data_a, false, 1));
        load_u64(
            fixture.address_space,
            second_slot,
            unauth_rebase(0xb00));

        Arm64eFixupsApplyConfig config;
        config.pointer_auth = &authenticator;
        const auto result = macosarm::dyld::apply_arm64e_chained_fixups_with_auth_slots(
            fixture.graph, 0, fixups, fixture.address_space, config);

        expect(static_cast<bool>(result), "mixed authenticated/unauthenticated chain applies");
        expect(result.fixups_scanned == 2 && result.apply.fixups_processed == 2,
               "slot scan walks the same two-entry chain as the applier");
        expect(result.authenticated_slots.size() == 1 &&
                   result.authenticated_slots.front().storage_address == first_slot,
               "slot scan records only authenticated chain words");
    }

    {
        Fixture fixture;
        auto fixups = metadata(ChainedPointerFormat::arm64e_userland);
        fixups.imports.push_back(ChainedImportEntry{1, false, "_foo", 0});
        constexpr std::uint64_t first_slot = Fixture::kRootBase + 0x140;
        constexpr std::uint64_t second_slot = first_slot + 8;
        const std::uint64_t first_raw =
            auth_rebase(0xc00, 0x22, PointerAuthKey::data_b, true, 1);
        const std::uint64_t second_raw =
            auth_bind16(0, 0x33, PointerAuthKey::instruction_a, false, 0, 1);
        fixups.segments[0].pages[0].offsets.push_back(0x140);
        load_u64(fixture.address_space, first_slot, first_raw);
        load_u64(fixture.address_space, second_slot, second_raw);

        Arm64eFixupsApplyConfig config;
        config.pointer_auth = &authenticator;
        const auto result = macosarm::dyld::apply_arm64e_chained_fixups_with_auth_slots(
            fixture.graph, 0, fixups, fixture.address_space, config);

        expect(result.scan_error == AuthenticatedFixupSlotScanError::none,
               "slot scan can complete before a semantic apply failure");
        expect(result.apply.error == Arm64eFixupsApplyError::pointer_reserved_bits,
               "wrapper preserves underlying authenticated fixup failure");
        expect(result.authenticated_slots.empty(),
               "failed/rolled-back apply never leaks authenticated slot descriptors");
        expect(result.apply.rolled_back,
               "wrapper preserves transactional rollback from underlying applier");
        expect(read_u64(fixture.address_space, first_slot) == first_raw &&
                   read_u64(fixture.address_space, second_slot) == second_raw,
               "wrapper failure restores exact raw chain words");
    }

    {
        Fixture fixture;
        auto fixups = metadata(ChainedPointerFormat::arm64e_userland);
        constexpr std::uint64_t slot = Fixture::kRootBase + 0x160;
        const std::uint64_t raw =
            auth_rebase(0xd00, 0x44, PointerAuthKey::instruction_a, false);
        fixups.segments[0].page_size = 0x2000;
        fixups.segments[0].pages[0].offsets.push_back(0x160);
        load_u64(fixture.address_space, slot, raw);

        Arm64eFixupsApplyConfig config;
        config.pointer_auth = &authenticator;
        const auto result = macosarm::dyld::apply_arm64e_chained_fixups_with_auth_slots(
            fixture.graph, 0, fixups, fixture.address_space, config);

        expect(result.scan_error == AuthenticatedFixupSlotScanError::invalid_page_size,
               "slot scanner rejects unsupported page size before applying anything");
        expect(result.authenticated_slots.empty(),
               "slot scan failure returns no partial descriptors");
        expect(read_u64(fixture.address_space, slot) == raw,
               "slot scan failure leaves guest memory untouched");
    }

    {
        Fixture fixture;
        auto fixups = metadata(ChainedPointerFormat::arm64e_userland);
        constexpr std::uint64_t slot = Fixture::kRootBase + 0x180;
        const std::uint64_t raw =
            auth_rebase(0xe00, 0x55, PointerAuthKey::instruction_a, false);
        fixups.segments[0].pages[0].offsets.push_back(0x180);
        load_u64(fixture.address_space, slot, raw);

        Arm64eFixupsApplyConfig config;
        config.pointer_auth = &authenticator;
        config.max_fixups = 0;
        const auto result = macosarm::dyld::apply_arm64e_chained_fixups_with_auth_slots(
            fixture.graph, 0, fixups, fixture.address_space, config);

        expect(result.scan_error == AuthenticatedFixupSlotScanError::fixup_limit,
               "slot scanner shares the applier's hard fixup bound");
        expect(read_u64(fixture.address_space, slot) == raw,
               "slot scan fixup-limit failure leaves raw pointer untouched");
    }

    expect(macosarm::dyld::authenticated_fixup_slot_scan_error_name(
               AuthenticatedFixupSlotScanError::duplicate_slot) == "duplicate_slot",
           "authenticated slot scan errors have stable names");

    if (failures != 0) {
        std::cerr << failures << " authenticated fixup slot test(s) failed\n";
        return EXIT_FAILURE;
    }

    std::cout << "authenticated fixup slot tests passed\n";
    return EXIT_SUCCESS;
}
