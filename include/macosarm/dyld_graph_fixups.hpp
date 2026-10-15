#pragma once

#include "macosarm/dyld_auth_slots.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

namespace macosarm::dyld {

enum class GraphFixupScanError {
    none,
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

struct LoadedImageGraphFixupsConfig {
    std::size_t max_total_fixups{kMaxChainedFixups};
    SymbolResolutionConfig symbol_resolution{};
    const PointerAuthenticator* pointer_auth{};
};

enum class LoadedImageGraphFixupsError {
    none,
    metadata_parse_failure,
    scan_failure,
    pointer_auth_required,
    generic_apply_failure,
    arm64e_apply_failure,
    apply_mismatch,
    rollback_failure,
};

struct LoadedImageGraphFixupsResult {
    static constexpr std::size_t kNoIndex = std::numeric_limits<std::size_t>::max();

    LoadedImageGraphFixupsError error{LoadedImageGraphFixupsError::none};
    std::size_t failed_image_index{kNoIndex};
    std::size_t segment_index{kNoIndex};
    std::size_t page_index{kNoIndex};
    std::uint64_t address{};
    ChainedFixupsError metadata_error{ChainedFixupsError::none};
    GraphFixupScanError scan_error{GraphFixupScanError::none};
    ChainedFixupsApplyError generic_error{ChainedFixupsApplyError::none};
    Arm64eFixupsApplyError arm64e_error{Arm64eFixupsApplyError::none};
    SymbolResolutionError symbol_error{SymbolResolutionError::none};
    PointerAuthError pointer_auth_error{PointerAuthError::none};
    VmError vm_error{VmError::none};
    std::size_t fixups_processed{};
    bool rolled_back{};
    std::vector<AuthenticatedFixupSlot> authenticated_slots;

    [[nodiscard]] explicit operator bool() const noexcept {
        return error == LoadedImageGraphFixupsError::none;
    }
};

namespace graph_fixup_detail {

[[nodiscard]] inline bool add_overflows(std::uint64_t left, std::uint64_t right) noexcept {
    return right > std::numeric_limits<std::uint64_t>::max() - left;
}

[[nodiscard]] inline bool multiply_overflows(std::uint64_t left, std::uint64_t right) noexcept {
    return left != 0 && right > std::numeric_limits<std::uint64_t>::max() / left;
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

[[nodiscard]] inline std::array<std::byte, sizeof(std::uint64_t)> encode_u64(
    std::uint64_t value) noexcept {
    std::array<std::byte, sizeof(std::uint64_t)> bytes{};
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        bytes[index] = static_cast<std::byte>((value >> (index * 8U)) & 0xffU);
    }
    return bytes;
}

[[nodiscard]] inline bool generic_format(ChainedPointerFormat format) noexcept {
    return format == ChainedPointerFormat::generic64 ||
           format == ChainedPointerFormat::generic64_offset;
}

[[nodiscard]] inline bool arm64e_format(ChainedPointerFormat format) noexcept {
    return format == ChainedPointerFormat::arm64e ||
           format == ChainedPointerFormat::arm64e_userland ||
           format == ChainedPointerFormat::arm64e_userland24;
}

enum class PreparedKind {
    none,
    generic,
    arm64e,
};

struct JournalEntry {
    std::uint64_t address{};
    std::uint64_t original{};
};

struct PreparedImage {
    std::size_t image_index{};
    ChainedFixupsMetadata metadata;
    PreparedKind kind{PreparedKind::none};
    std::vector<JournalEntry> journal;
};

class Preflight {
public:
    Preflight(
        const LoadedImageGraph& graph,
        const GuestAddressSpace& address_space,
        const LoadedImageGraphFixupsConfig& config)
        : graph_(graph), address_space_(address_space), config_(config) {}

    [[nodiscard]] LoadedImageGraphFixupsResult run(
        std::vector<PreparedImage>& prepared) {
        prepared.reserve(graph_.images.size());
        for (std::size_t image_index = 0; image_index < graph_.images.size(); ++image_index) {
            const GraphImage& image = graph_.images[image_index];
            if (image.chained_fixups_payload.empty()) {
                continue;
            }

            ChainedFixupsResult parsed = parse_chained_fixups(
                image.chained_fixups_payload,
                image.image.segments);
            if (!parsed) {
                result_.error = LoadedImageGraphFixupsError::metadata_parse_failure;
                result_.failed_image_index = image_index;
                result_.metadata_error = parsed.error;
                result_.authenticated_slots.clear();
                prepared.clear();
                return std::move(result_);
            }

            PreparedImage candidate;
            candidate.image_index = image_index;
            candidate.metadata = std::move(parsed.metadata);
            if (!scan_image(candidate)) {
                result_.error = LoadedImageGraphFixupsError::scan_failure;
                result_.authenticated_slots.clear();
                prepared.clear();
                return std::move(result_);
            }
            prepared.push_back(std::move(candidate));
        }

        if (!result_.authenticated_slots.empty() && config_.pointer_auth == nullptr) {
            result_.error = LoadedImageGraphFixupsError::pointer_auth_required;
            result_.failed_image_index = first_authenticated_image_;
            result_.authenticated_slots.clear();
            prepared.clear();
            return std::move(result_);
        }
        return std::move(result_);
    }

private:
    [[nodiscard]] bool fail_scan(
        GraphFixupScanError error,
        std::size_t image_index,
        std::size_t segment_index,
        std::size_t page_index,
        std::uint64_t address,
        VmError vm_error = VmError::none) {
        result_.scan_error = error;
        result_.failed_image_index = image_index;
        result_.segment_index = segment_index;
        result_.page_index = page_index;
        result_.address = address;
        result_.vm_error = vm_error;
        return false;
    }

    [[nodiscard]] bool scan_image(PreparedImage& prepared) {
        const GraphImage& image = graph_.images[prepared.image_index];
        if (prepared.metadata.segments.size() > image.image.segments.size()) {
            return fail_scan(
                GraphFixupScanError::metadata_segment_count_exceeds_image,
                prepared.image_index,
                LoadedImageGraphFixupsResult::kNoIndex,
                LoadedImageGraphFixupsResult::kNoIndex,
                0);
        }

        for (std::size_t segment_index = 0;
             segment_index < prepared.metadata.segments.size(); ++segment_index) {
            const ChainedSegmentStarts& starts = prepared.metadata.segments[segment_index];
            if (!starts.present) {
                continue;
            }
            const PreparedKind segment_kind = generic_format(starts.pointer_format)
                ? PreparedKind::generic
                : (arm64e_format(starts.pointer_format)
                       ? PreparedKind::arm64e
                       : PreparedKind::none);
            if (segment_kind == PreparedKind::none) {
                return fail_scan(
                    GraphFixupScanError::unsupported_pointer_format,
                    prepared.image_index,
                    segment_index,
                    LoadedImageGraphFixupsResult::kNoIndex,
                    0);
            }
            if (prepared.kind == PreparedKind::none) {
                prepared.kind = segment_kind;
            } else if (prepared.kind != segment_kind) {
                return fail_scan(
                    GraphFixupScanError::unsupported_pointer_format,
                    prepared.image_index,
                    segment_index,
                    LoadedImageGraphFixupsResult::kNoIndex,
                    0);
            }
            if (!scan_segment(prepared, segment_index, starts)) {
                return false;
            }
        }
        return true;
    }

    [[nodiscard]] bool scan_segment(
        PreparedImage& prepared,
        std::size_t segment_index,
        const ChainedSegmentStarts& starts) {
        if (starts.page_size != 0x1000 && starts.page_size != 0x4000) {
            return fail_scan(
                GraphFixupScanError::invalid_page_size,
                prepared.image_index,
                segment_index,
                LoadedImageGraphFixupsResult::kNoIndex,
                0);
        }

        const GraphImage& image = graph_.images[prepared.image_index];
        const macho::Segment& segment = image.image.segments[segment_index];
        const std::uint64_t image_base = image.mapping.preferred_load_address;
        if (segment.vm_address < image_base) {
            return fail_scan(
                GraphFixupScanError::segment_offset_overflow,
                prepared.image_index,
                segment_index,
                LoadedImageGraphFixupsResult::kNoIndex,
                segment.vm_address);
        }
        if (starts.segment_offset != segment.vm_address - image_base) {
            return fail_scan(
                GraphFixupScanError::segment_offset_mismatch,
                prepared.image_index,
                segment_index,
                LoadedImageGraphFixupsResult::kNoIndex,
                segment.vm_address);
        }
        if (segment.vm_size == 0) {
            if (!starts.pages.empty()) {
                return fail_scan(
                    GraphFixupScanError::page_count_exceeds_segment,
                    prepared.image_index,
                    segment_index,
                    LoadedImageGraphFixupsResult::kNoIndex,
                    segment.vm_address);
            }
            return true;
        }
        if (add_overflows(segment.vm_address, segment.vm_size)) {
            return fail_scan(
                GraphFixupScanError::page_address_overflow,
                prepared.image_index,
                segment_index,
                LoadedImageGraphFixupsResult::kNoIndex,
                segment.vm_address);
        }

        const std::uint64_t page_size = starts.page_size;
        const std::uint64_t page_count =
            segment.vm_size / page_size + ((segment.vm_size % page_size) != 0 ? 1 : 0);
        if (starts.pages.size() > page_count) {
            return fail_scan(
                GraphFixupScanError::page_count_exceeds_segment,
                prepared.image_index,
                segment_index,
                LoadedImageGraphFixupsResult::kNoIndex,
                segment.vm_address);
        }

        for (std::size_t page_index = 0; page_index < starts.pages.size(); ++page_index) {
            const ChainedPageStarts& page = starts.pages[page_index];
            if (page.offsets.empty()) {
                continue;
            }
            if (page.offsets.size() != 1) {
                return fail_scan(
                    GraphFixupScanError::multiple_page_starts_unsupported,
                    prepared.image_index,
                    segment_index,
                    page_index,
                    segment.vm_address);
            }
            if (multiply_overflows(static_cast<std::uint64_t>(page_index), page_size)) {
                return fail_scan(
                    GraphFixupScanError::page_address_overflow,
                    prepared.image_index,
                    segment_index,
                    page_index,
                    segment.vm_address);
            }
            const std::uint64_t page_segment_offset =
                static_cast<std::uint64_t>(page_index) * page_size;
            if (add_overflows(segment.vm_address, page_segment_offset)) {
                return fail_scan(
                    GraphFixupScanError::page_address_overflow,
                    prepared.image_index,
                    segment_index,
                    page_index,
                    segment.vm_address);
            }
            const std::uint64_t page_address = segment.vm_address + page_segment_offset;
            const std::uint64_t start = page.offsets.front();
            if (start > page_size || page_size - start < sizeof(std::uint64_t)) {
                return fail_scan(
                    GraphFixupScanError::chain_start_out_of_page,
                    prepared.image_index,
                    segment_index,
                    page_index,
                    page_address);
            }
            if (page_segment_offset > segment.vm_size ||
                start > segment.vm_size - page_segment_offset ||
                segment.vm_size - page_segment_offset - start < sizeof(std::uint64_t)) {
                return fail_scan(
                    GraphFixupScanError::chain_start_out_of_segment,
                    prepared.image_index,
                    segment_index,
                    page_index,
                    page_address + start);
            }
            if (!scan_chain(
                    prepared,
                    segment_index,
                    page_index,
                    starts,
                    segment,
                    page_address + start)) {
                return false;
            }
        }
        return true;
    }

    [[nodiscard]] bool scan_chain(
        PreparedImage& prepared,
        std::size_t segment_index,
        std::size_t page_index,
        const ChainedSegmentStarts& starts,
        const macho::Segment& segment,
        std::uint64_t address) {
        const std::uint64_t page_size = starts.page_size;
        const std::uint64_t page_address =
            segment.vm_address + static_cast<std::uint64_t>(page_index) * page_size;
        const bool arm64e = arm64e_format(starts.pointer_format);
        const std::uint64_t next_mask = arm64e ? 0x7ffU : 0xfffU;
        const std::uint64_t stride = arm64e ? 8U : 4U;

        while (true) {
            if (result_.fixups_processed >= config_.max_total_fixups) {
                return fail_scan(
                    GraphFixupScanError::fixup_limit,
                    prepared.image_index,
                    segment_index,
                    page_index,
                    address);
            }
            if (!seen_slots_.insert(address).second) {
                return fail_scan(
                    GraphFixupScanError::duplicate_slot,
                    prepared.image_index,
                    segment_index,
                    page_index,
                    address);
            }

            std::array<std::byte, sizeof(std::uint64_t)> bytes{};
            const VmResult read = address_space_.read(address, bytes);
            if (!read) {
                return fail_scan(
                    GraphFixupScanError::read_failure,
                    prepared.image_index,
                    segment_index,
                    page_index,
                    address,
                    read.error);
            }
            const std::uint64_t raw = decode_u64(bytes);
            prepared.journal.push_back({address, raw});
            ++result_.fixups_processed;

            if (arm64e && (raw & (std::uint64_t{1} << 63)) != 0) {
                if (first_authenticated_image_ == LoadedImageGraphFixupsResult::kNoIndex) {
                    first_authenticated_image_ = prepared.image_index;
                }
                result_.authenticated_slots.push_back({
                    address,
                    static_cast<PointerAuthKey>((raw >> 49) & 0x3U),
                    static_cast<std::uint16_t>((raw >> 32) & 0xffffU),
                    ((raw >> 48) & 1U) != 0,
                });
            }

            const std::uint64_t next = (raw >> 51) & next_mask;
            if (next == 0) {
                return true;
            }
            if (multiply_overflows(next, stride)) {
                return fail_scan(
                    GraphFixupScanError::page_address_overflow,
                    prepared.image_index,
                    segment_index,
                    page_index,
                    address);
            }
            const std::uint64_t delta = next * stride;
            const std::uint64_t offset_in_page = address - page_address;
            if (offset_in_page > page_size ||
                delta > page_size - offset_in_page ||
                page_size - offset_in_page - delta < sizeof(std::uint64_t)) {
                return fail_scan(
                    GraphFixupScanError::chain_next_out_of_page,
                    prepared.image_index,
                    segment_index,
                    page_index,
                    address);
            }
            const std::uint64_t offset_in_segment = address - segment.vm_address;
            if (offset_in_segment > segment.vm_size ||
                delta > segment.vm_size - offset_in_segment ||
                segment.vm_size - offset_in_segment - delta < sizeof(std::uint64_t)) {
                return fail_scan(
                    GraphFixupScanError::chain_next_out_of_segment,
                    prepared.image_index,
                    segment_index,
                    page_index,
                    address);
            }
            if (add_overflows(address, delta)) {
                return fail_scan(
                    GraphFixupScanError::page_address_overflow,
                    prepared.image_index,
                    segment_index,
                    page_index,
                    address);
            }
            address += delta;
        }
    }

    const LoadedImageGraph& graph_;
    const GuestAddressSpace& address_space_;
    const LoadedImageGraphFixupsConfig& config_;
    std::unordered_set<std::uint64_t> seen_slots_;
    std::size_t first_authenticated_image_{LoadedImageGraphFixupsResult::kNoIndex};
    LoadedImageGraphFixupsResult result_;
};

[[nodiscard]] inline bool restore_prepared_images(
    const std::vector<PreparedImage>& prepared,
    std::size_t end_exclusive,
    GuestAddressSpace& address_space,
    LoadedImageGraphFixupsResult& result) {
    bool restored_any = false;
    for (std::size_t image_cursor = end_exclusive; image_cursor > 0; --image_cursor) {
        const PreparedImage& image = prepared[image_cursor - 1];
        for (auto journal = image.journal.rbegin(); journal != image.journal.rend(); ++journal) {
            restored_any = true;
            const auto encoded = encode_u64(journal->original);
            const VmResult restored = address_space.write(journal->address, encoded);
            if (!restored) {
                result.error = LoadedImageGraphFixupsError::rollback_failure;
                result.failed_image_index = image.image_index;
                result.address = journal->address;
                result.vm_error = restored.error;
                result.rolled_back = true;
                result.authenticated_slots.clear();
                return false;
            }
        }
    }
    result.rolled_back = result.rolled_back || restored_any;
    return true;
}

} // namespace graph_fixup_detail

// Parses and structurally preflights every retained chained-fixup payload before
// mutating guest memory. All raw chain words are journaled up front so a failure
// in a later image can restore fixups already committed by earlier images. The
// returned authenticated-slot policy is published only after the entire graph
// applies successfully.
[[nodiscard]] inline LoadedImageGraphFixupsResult apply_loaded_image_graph_fixups(
    const LoadedImageGraph& graph,
    GuestAddressSpace& address_space,
    const LoadedImageGraphFixupsConfig& config = {}) {
    std::vector<graph_fixup_detail::PreparedImage> prepared;
    LoadedImageGraphFixupsResult result =
        graph_fixup_detail::Preflight(graph, address_space, config).run(prepared);
    if (!result) {
        return result;
    }

    const std::size_t total_fixups = result.fixups_processed;
    std::size_t applied_prepared_images = 0;
    for (std::size_t prepared_index = 0;
         prepared_index < prepared.size(); ++prepared_index) {
        const graph_fixup_detail::PreparedImage& image = prepared[prepared_index];
        if (image.kind == graph_fixup_detail::PreparedKind::none || image.journal.empty()) {
            ++applied_prepared_images;
            continue;
        }

        if (image.kind == graph_fixup_detail::PreparedKind::generic) {
            ChainedFixupsApplyConfig apply_config;
            apply_config.max_fixups = image.journal.size();
            apply_config.symbol_resolution = config.symbol_resolution;
            const ChainedFixupsApplyResult applied = apply_chained_fixups(
                graph,
                image.image_index,
                image.metadata,
                address_space,
                apply_config);
            if (!applied || applied.fixups_processed != image.journal.size()) {
                result.error = !applied
                    ? LoadedImageGraphFixupsError::generic_apply_failure
                    : LoadedImageGraphFixupsError::apply_mismatch;
                result.failed_image_index = image.image_index;
                result.generic_error = applied.error;
                result.symbol_error = applied.symbol_error;
                result.vm_error = applied.vm_error;
                result.address = applied.address;
                result.rolled_back = applied.rolled_back;
                const bool include_current =
                    static_cast<bool>(applied) ||
                    applied.error == ChainedFixupsApplyError::rollback_failure;
                const std::size_t restore_count =
                    applied_prepared_images + (include_current ? 1U : 0U);
                if (!graph_fixup_detail::restore_prepared_images(
                        prepared, restore_count, address_space, result)) {
                    return result;
                }
                result.authenticated_slots.clear();
                return result;
            }
        } else {
            Arm64eFixupsApplyConfig apply_config;
            apply_config.max_fixups = image.journal.size();
            apply_config.symbol_resolution = config.symbol_resolution;
            apply_config.pointer_auth = config.pointer_auth;
            const Arm64eFixupsApplyResult applied = apply_arm64e_chained_fixups(
                graph,
                image.image_index,
                image.metadata,
                address_space,
                apply_config);
            if (!applied || applied.fixups_processed != image.journal.size()) {
                result.error = !applied
                    ? LoadedImageGraphFixupsError::arm64e_apply_failure
                    : LoadedImageGraphFixupsError::apply_mismatch;
                result.failed_image_index = image.image_index;
                result.arm64e_error = applied.error;
                result.symbol_error = applied.symbol_error;
                result.pointer_auth_error = applied.pointer_auth_error;
                result.vm_error = applied.vm_error;
                result.address = applied.address;
                result.rolled_back = applied.rolled_back;
                const bool include_current =
                    static_cast<bool>(applied) ||
                    applied.error == Arm64eFixupsApplyError::rollback_failure;
                const std::size_t restore_count =
                    applied_prepared_images + (include_current ? 1U : 0U);
                if (!graph_fixup_detail::restore_prepared_images(
                        prepared, restore_count, address_space, result)) {
                    return result;
                }
                result.authenticated_slots.clear();
                return result;
            }
        }
        ++applied_prepared_images;
    }

    result.fixups_processed = total_fixups;
    return result;
}

[[nodiscard]] inline std::string_view graph_fixup_scan_error_name(
    GraphFixupScanError error) noexcept {
    switch (error) {
    case GraphFixupScanError::none: return "none";
    case GraphFixupScanError::metadata_segment_count_exceeds_image:
        return "metadata_segment_count_exceeds_image";
    case GraphFixupScanError::invalid_page_size: return "invalid_page_size";
    case GraphFixupScanError::unsupported_pointer_format: return "unsupported_pointer_format";
    case GraphFixupScanError::segment_offset_overflow: return "segment_offset_overflow";
    case GraphFixupScanError::segment_offset_mismatch: return "segment_offset_mismatch";
    case GraphFixupScanError::page_count_exceeds_segment: return "page_count_exceeds_segment";
    case GraphFixupScanError::page_address_overflow: return "page_address_overflow";
    case GraphFixupScanError::multiple_page_starts_unsupported:
        return "multiple_page_starts_unsupported";
    case GraphFixupScanError::chain_start_out_of_page: return "chain_start_out_of_page";
    case GraphFixupScanError::chain_start_out_of_segment: return "chain_start_out_of_segment";
    case GraphFixupScanError::read_failure: return "read_failure";
    case GraphFixupScanError::chain_next_out_of_page: return "chain_next_out_of_page";
    case GraphFixupScanError::chain_next_out_of_segment: return "chain_next_out_of_segment";
    case GraphFixupScanError::duplicate_slot: return "duplicate_slot";
    case GraphFixupScanError::fixup_limit: return "fixup_limit";
    }
    return "unknown";
}

[[nodiscard]] inline std::string_view loaded_image_graph_fixups_error_name(
    LoadedImageGraphFixupsError error) noexcept {
    switch (error) {
    case LoadedImageGraphFixupsError::none: return "none";
    case LoadedImageGraphFixupsError::metadata_parse_failure: return "metadata_parse_failure";
    case LoadedImageGraphFixupsError::scan_failure: return "scan_failure";
    case LoadedImageGraphFixupsError::pointer_auth_required: return "pointer_auth_required";
    case LoadedImageGraphFixupsError::generic_apply_failure: return "generic_apply_failure";
    case LoadedImageGraphFixupsError::arm64e_apply_failure: return "arm64e_apply_failure";
    case LoadedImageGraphFixupsError::apply_mismatch: return "apply_mismatch";
    case LoadedImageGraphFixupsError::rollback_failure: return "rollback_failure";
    }
    return "unknown";
}

} // namespace macosarm::dyld
