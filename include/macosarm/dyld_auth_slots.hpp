#pragma once

#include "macosarm/dyld_fixup_pauth.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

namespace macosarm::dyld {

struct AuthenticatedFixupSlot {
    std::uint64_t storage_address{};
    PointerAuthKey key{PointerAuthKey::instruction_a};
    std::uint16_t diversity{};
    bool address_diversity{};

    [[nodiscard]] friend constexpr bool operator==(
        const AuthenticatedFixupSlot&,
        const AuthenticatedFixupSlot&) = default;
};

enum class AuthenticatedFixupSlotScanError {
    none,
    bad_image_index,
    metadata_segment_count_exceeds_image,
    invalid_page_size,
    unsupported_pointer_format,
    segment_offset_overflow,
    segment_offset_mismatch,
    page_count_exceeds_segment,
    page_address_overflow,
    multiple_page_starts_unsupported,
    chain_start_out_of_page,
    chain_start_out_of_segment,
    read_failure,
    chain_next_out_of_page,
    chain_next_out_of_segment,
    duplicate_slot,
    fixup_limit,
};

struct Arm64eFixupsWithAuthSlotsResult {
    static constexpr std::size_t kNoIndex = std::numeric_limits<std::size_t>::max();

    Arm64eFixupsApplyResult apply{};
    std::vector<AuthenticatedFixupSlot> authenticated_slots;
    AuthenticatedFixupSlotScanError scan_error{AuthenticatedFixupSlotScanError::none};
    VmError vm_error{VmError::none};
    std::size_t segment_index{kNoIndex};
    std::size_t page_index{kNoIndex};
    std::uint64_t address{};
    std::size_t fixups_scanned{};

    [[nodiscard]] explicit operator bool() const noexcept {
        return scan_error == AuthenticatedFixupSlotScanError::none &&
               static_cast<bool>(apply);
    }
};

namespace authenticated_fixup_slot_detail {

[[nodiscard]] inline bool add_overflows(std::uint64_t left, std::uint64_t right) noexcept {
    return right > std::numeric_limits<std::uint64_t>::max() - left;
}

[[nodiscard]] inline bool multiply_overflows(std::uint64_t left, std::uint64_t right) noexcept {
    return left != 0 && right > std::numeric_limits<std::uint64_t>::max() / left;
}

[[nodiscard]] inline bool supported_format(ChainedPointerFormat format) noexcept {
    return format == ChainedPointerFormat::arm64e ||
           format == ChainedPointerFormat::arm64e_userland ||
           format == ChainedPointerFormat::arm64e_userland24;
}

[[nodiscard]] inline std::uint64_t decode_u64(
    const std::array<std::byte, sizeof(std::uint64_t)>& bytes) noexcept {
    std::uint64_t value = 0;
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        value |= static_cast<std::uint64_t>(std::to_integer<unsigned char>(bytes[index]))
                 << (index * 8U);
    }
    return value;
}

class Scanner {
public:
    Scanner(
        const LoadedImageGraph& graph,
        std::size_t image_index,
        const ChainedFixupsMetadata& metadata,
        const GuestAddressSpace& address_space,
        std::size_t max_fixups)
        : graph_(graph),
          image_index_(image_index),
          metadata_(metadata),
          address_space_(address_space),
          max_fixups_(max_fixups) {}

    [[nodiscard]] Arm64eFixupsWithAuthSlotsResult run() {
        if (image_index_ >= graph_.images.size()) {
            return fail(AuthenticatedFixupSlotScanError::bad_image_index);
        }
        image_ = &graph_.images[image_index_];
        if (metadata_.segments.size() > image_->image.segments.size()) {
            return fail(AuthenticatedFixupSlotScanError::metadata_segment_count_exceeds_image);
        }

        for (std::size_t segment_index = 0;
             segment_index < metadata_.segments.size(); ++segment_index) {
            const ChainedSegmentStarts& starts = metadata_.segments[segment_index];
            if (!starts.present) {
                continue;
            }
            if (!scan_segment(segment_index, starts)) {
                return std::move(result_);
            }
        }
        return std::move(result_);
    }

private:
    [[nodiscard]] Arm64eFixupsWithAuthSlotsResult fail(
        AuthenticatedFixupSlotScanError error,
        std::size_t segment_index = Arm64eFixupsWithAuthSlotsResult::kNoIndex,
        std::size_t page_index = Arm64eFixupsWithAuthSlotsResult::kNoIndex,
        std::uint64_t address = 0,
        VmError vm_error = VmError::none) {
        result_.scan_error = error;
        result_.segment_index = segment_index;
        result_.page_index = page_index;
        result_.address = address;
        result_.vm_error = vm_error;
        result_.authenticated_slots.clear();
        return std::move(result_);
    }

    [[nodiscard]] bool fail_in_place(
        AuthenticatedFixupSlotScanError error,
        std::size_t segment_index,
        std::size_t page_index,
        std::uint64_t address,
        VmError vm_error = VmError::none) {
        result_.scan_error = error;
        result_.segment_index = segment_index;
        result_.page_index = page_index;
        result_.address = address;
        result_.vm_error = vm_error;
        result_.authenticated_slots.clear();
        return false;
    }

    [[nodiscard]] bool scan_segment(
        std::size_t segment_index,
        const ChainedSegmentStarts& starts) {
        if (starts.page_size != 0x1000 && starts.page_size != 0x4000) {
            return fail_in_place(
                AuthenticatedFixupSlotScanError::invalid_page_size,
                segment_index,
                Arm64eFixupsWithAuthSlotsResult::kNoIndex,
                0);
        }
        if (!supported_format(starts.pointer_format)) {
            return fail_in_place(
                AuthenticatedFixupSlotScanError::unsupported_pointer_format,
                segment_index,
                Arm64eFixupsWithAuthSlotsResult::kNoIndex,
                0);
        }

        const macho::Segment& segment = image_->image.segments[segment_index];
        const std::uint64_t image_base = image_->mapping.preferred_load_address;
        if (segment.vm_address < image_base) {
            return fail_in_place(
                AuthenticatedFixupSlotScanError::segment_offset_overflow,
                segment_index,
                Arm64eFixupsWithAuthSlotsResult::kNoIndex,
                segment.vm_address);
        }
        if (starts.segment_offset != segment.vm_address - image_base) {
            return fail_in_place(
                AuthenticatedFixupSlotScanError::segment_offset_mismatch,
                segment_index,
                Arm64eFixupsWithAuthSlotsResult::kNoIndex,
                segment.vm_address);
        }
        if (segment.vm_size == 0) {
            if (!starts.pages.empty()) {
                return fail_in_place(
                    AuthenticatedFixupSlotScanError::page_count_exceeds_segment,
                    segment_index,
                    Arm64eFixupsWithAuthSlotsResult::kNoIndex,
                    segment.vm_address);
            }
            return true;
        }

        const std::uint64_t page_size = starts.page_size;
        const std::uint64_t page_count =
            segment.vm_size / page_size + ((segment.vm_size % page_size) != 0 ? 1 : 0);
        if (starts.pages.size() > page_count) {
            return fail_in_place(
                AuthenticatedFixupSlotScanError::page_count_exceeds_segment,
                segment_index,
                Arm64eFixupsWithAuthSlotsResult::kNoIndex,
                segment.vm_address);
        }
        if (add_overflows(segment.vm_address, segment.vm_size)) {
            return fail_in_place(
                AuthenticatedFixupSlotScanError::page_address_overflow,
                segment_index,
                Arm64eFixupsWithAuthSlotsResult::kNoIndex,
                segment.vm_address);
        }

        for (std::size_t page_index = 0; page_index < starts.pages.size(); ++page_index) {
            const ChainedPageStarts& page = starts.pages[page_index];
            if (page.offsets.empty()) {
                continue;
            }
            if (page.offsets.size() != 1) {
                return fail_in_place(
                    AuthenticatedFixupSlotScanError::multiple_page_starts_unsupported,
                    segment_index,
                    page_index,
                    segment.vm_address);
            }
            if (multiply_overflows(static_cast<std::uint64_t>(page_index), page_size)) {
                return fail_in_place(
                    AuthenticatedFixupSlotScanError::page_address_overflow,
                    segment_index,
                    page_index,
                    segment.vm_address);
            }
            const std::uint64_t page_segment_offset =
                static_cast<std::uint64_t>(page_index) * page_size;
            if (add_overflows(segment.vm_address, page_segment_offset)) {
                return fail_in_place(
                    AuthenticatedFixupSlotScanError::page_address_overflow,
                    segment_index,
                    page_index,
                    segment.vm_address);
            }
            const std::uint64_t page_address = segment.vm_address + page_segment_offset;
            const std::uint64_t start = page.offsets.front();
            if (start > page_size || page_size - start < sizeof(std::uint64_t)) {
                return fail_in_place(
                    AuthenticatedFixupSlotScanError::chain_start_out_of_page,
                    segment_index,
                    page_index,
                    page_address);
            }
            if (page_segment_offset > segment.vm_size ||
                start > segment.vm_size - page_segment_offset ||
                segment.vm_size - page_segment_offset - start < sizeof(std::uint64_t)) {
                return fail_in_place(
                    AuthenticatedFixupSlotScanError::chain_start_out_of_segment,
                    segment_index,
                    page_index,
                    page_address + start);
            }
            if (!scan_chain(segment_index, page_index, starts, segment, page_address + start)) {
                return false;
            }
        }
        return true;
    }

    [[nodiscard]] bool scan_chain(
        std::size_t segment_index,
        std::size_t page_index,
        const ChainedSegmentStarts& starts,
        const macho::Segment& segment,
        std::uint64_t address) {
        const std::uint64_t page_size = starts.page_size;
        const std::uint64_t page_address =
            segment.vm_address + static_cast<std::uint64_t>(page_index) * page_size;

        while (true) {
            if (result_.fixups_scanned >= max_fixups_) {
                return fail_in_place(
                    AuthenticatedFixupSlotScanError::fixup_limit,
                    segment_index,
                    page_index,
                    address);
            }

            std::array<std::byte, sizeof(std::uint64_t)> bytes{};
            const VmResult read = address_space_.read(address, bytes);
            if (!read) {
                return fail_in_place(
                    AuthenticatedFixupSlotScanError::read_failure,
                    segment_index,
                    page_index,
                    address,
                    read.error);
            }
            const std::uint64_t raw = decode_u64(bytes);
            ++result_.fixups_scanned;

            const bool authenticated = (raw & (std::uint64_t{1} << 63)) != 0;
            if (authenticated) {
                if (!seen_slots_.insert(address).second) {
                    return fail_in_place(
                        AuthenticatedFixupSlotScanError::duplicate_slot,
                        segment_index,
                        page_index,
                        address);
                }
                result_.authenticated_slots.push_back({
                    address,
                    static_cast<PointerAuthKey>((raw >> 49) & 0x3U),
                    static_cast<std::uint16_t>((raw >> 32) & 0xffffU),
                    ((raw >> 48) & 1U) != 0,
                });
            }

            const std::uint64_t next = (raw >> 51) & 0x7ffU;
            if (next == 0) {
                return true;
            }
            const std::uint64_t delta = next * sizeof(std::uint64_t);
            const std::uint64_t offset_in_page = address - page_address;
            if (offset_in_page > page_size ||
                delta > page_size - offset_in_page ||
                page_size - offset_in_page - delta < sizeof(std::uint64_t)) {
                return fail_in_place(
                    AuthenticatedFixupSlotScanError::chain_next_out_of_page,
                    segment_index,
                    page_index,
                    address);
            }
            const std::uint64_t offset_in_segment = address - segment.vm_address;
            if (offset_in_segment > segment.vm_size ||
                delta > segment.vm_size - offset_in_segment ||
                segment.vm_size - offset_in_segment - delta < sizeof(std::uint64_t)) {
                return fail_in_place(
                    AuthenticatedFixupSlotScanError::chain_next_out_of_segment,
                    segment_index,
                    page_index,
                    address);
            }
            if (add_overflows(address, delta)) {
                return fail_in_place(
                    AuthenticatedFixupSlotScanError::page_address_overflow,
                    segment_index,
                    page_index,
                    address);
            }
            address += delta;
        }
    }

    const LoadedImageGraph& graph_;
    std::size_t image_index_{};
    const ChainedFixupsMetadata& metadata_;
    const GuestAddressSpace& address_space_;
    std::size_t max_fixups_{};
    const GraphImage* image_{};
    std::unordered_set<std::uint64_t> seen_slots_;
    Arm64eFixupsWithAuthSlotsResult result_;
};

} // namespace authenticated_fixup_slot_detail

// Captures the authenticated-slot policy from raw ARM64e chain words before
// the transactional applier overwrites them with software-PAC pointers. Slot
// metadata is returned only if the actual fixup application succeeds. A failed
// apply therefore cannot leak descriptors for memory that was rolled back.
[[nodiscard]] inline Arm64eFixupsWithAuthSlotsResult
apply_arm64e_chained_fixups_with_auth_slots(
    const LoadedImageGraph& graph,
    std::size_t image_index,
    const ChainedFixupsMetadata& metadata,
    GuestAddressSpace& address_space,
    const Arm64eFixupsApplyConfig& config = {}) {
    auto scanned = authenticated_fixup_slot_detail::Scanner(
        graph,
        image_index,
        metadata,
        address_space,
        config.max_fixups).run();
    if (scanned.scan_error != AuthenticatedFixupSlotScanError::none) {
        return scanned;
    }

    scanned.apply = apply_arm64e_chained_fixups(
        graph,
        image_index,
        metadata,
        address_space,
        config);
    if (!scanned.apply) {
        scanned.authenticated_slots.clear();
    }
    return scanned;
}

[[nodiscard]] inline std::string_view authenticated_fixup_slot_scan_error_name(
    AuthenticatedFixupSlotScanError error) noexcept {
    switch (error) {
    case AuthenticatedFixupSlotScanError::none: return "none";
    case AuthenticatedFixupSlotScanError::bad_image_index: return "bad_image_index";
    case AuthenticatedFixupSlotScanError::metadata_segment_count_exceeds_image:
        return "metadata_segment_count_exceeds_image";
    case AuthenticatedFixupSlotScanError::invalid_page_size: return "invalid_page_size";
    case AuthenticatedFixupSlotScanError::unsupported_pointer_format: return "unsupported_pointer_format";
    case AuthenticatedFixupSlotScanError::segment_offset_overflow: return "segment_offset_overflow";
    case AuthenticatedFixupSlotScanError::segment_offset_mismatch: return "segment_offset_mismatch";
    case AuthenticatedFixupSlotScanError::page_count_exceeds_segment: return "page_count_exceeds_segment";
    case AuthenticatedFixupSlotScanError::page_address_overflow: return "page_address_overflow";
    case AuthenticatedFixupSlotScanError::multiple_page_starts_unsupported:
        return "multiple_page_starts_unsupported";
    case AuthenticatedFixupSlotScanError::chain_start_out_of_page: return "chain_start_out_of_page";
    case AuthenticatedFixupSlotScanError::chain_start_out_of_segment: return "chain_start_out_of_segment";
    case AuthenticatedFixupSlotScanError::read_failure: return "read_failure";
    case AuthenticatedFixupSlotScanError::chain_next_out_of_page: return "chain_next_out_of_page";
    case AuthenticatedFixupSlotScanError::chain_next_out_of_segment: return "chain_next_out_of_segment";
    case AuthenticatedFixupSlotScanError::duplicate_slot: return "duplicate_slot";
    case AuthenticatedFixupSlotScanError::fixup_limit: return "fixup_limit";
    }
    return "unknown";
}

} // namespace macosarm::dyld
