#pragma once

#include "macosarm/dyld_fixups.hpp"
#include "macosarm/pointer_auth.hpp"

#include <cstddef>
#include <cstdint>
#include <limits>
#include <string_view>

namespace macosarm::dyld {

struct Arm64eFixupsApplyConfig {
    std::size_t max_fixups{kMaxChainedFixups};
    SymbolResolutionConfig symbol_resolution{};
    const PointerAuthenticator* pointer_auth{};
};

enum class Arm64eFixupsApplyError {
    none,
    bad_image_index,
    metadata_segment_count_exceeds_image,
    invalid_page_size,
    unsupported_pointer_format,
    pointer_auth_required,
    pointer_auth_failure,
    segment_offset_overflow,
    segment_offset_mismatch,
    page_count_exceeds_segment,
    page_address_overflow,
    multiple_page_starts_unsupported,
    chain_start_out_of_page,
    chain_start_out_of_segment,
    read_failure,
    write_failure,
    pointer_reserved_bits,
    bind_ordinal_out_of_range,
    library_ordinal_out_of_range,
    dependency_unavailable,
    unsupported_special_ordinal,
    symbol_not_found,
    symbol_resolution_failure,
    addend_overflow,
    chain_next_out_of_page,
    chain_next_out_of_segment,
    fixup_limit,
    rollback_failure,
};

struct Arm64eFixupsApplyResult {
    static constexpr std::size_t kNoIndex = std::numeric_limits<std::size_t>::max();

    Arm64eFixupsApplyError error{Arm64eFixupsApplyError::none};
    VmError vm_error{VmError::none};
    SymbolResolutionError symbol_error{SymbolResolutionError::none};
    PointerAuthError pointer_auth_error{PointerAuthError::none};
    std::size_t segment_index{kNoIndex};
    std::size_t page_index{kNoIndex};
    std::size_t import_index{kNoIndex};
    std::uint64_t address{};
    std::size_t fixups_processed{};
    bool rolled_back{};

    [[nodiscard]] explicit operator bool() const noexcept {
        return error == Arm64eFixupsApplyError::none;
    }
};

// Applies ARM64e chained pointers transactionally. Unauthenticated pointers use
// the phase-21 semantics. Authenticated pointers require `pointer_auth` and are
// signed with the chain's key/diversity/address-diversity metadata. Authenticated
// rebases use the format's 32-bit runtime offset; authenticated binds use the
// resolved symbol plus import addend and intentionally have no embedded 19-bit
// pointer addend. This is functional translated-guest PAUTH, not a claim that
// the software PAC bits match Apple hardware signatures.
[[nodiscard]] Arm64eFixupsApplyResult apply_arm64e_chained_fixups(
    const LoadedImageGraph& graph,
    std::size_t image_index,
    const ChainedFixupsMetadata& metadata,
    GuestAddressSpace& address_space,
    const Arm64eFixupsApplyConfig& config = {});

[[nodiscard]] std::string_view arm64e_fixups_apply_error_name(
    Arm64eFixupsApplyError error) noexcept;

} // namespace macosarm::dyld
