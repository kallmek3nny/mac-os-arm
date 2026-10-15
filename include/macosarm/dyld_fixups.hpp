#pragma once

#include "macosarm/macho.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace macosarm::dyld {

constexpr std::uint32_t kChainedFixupsVersion = 0;
constexpr std::uint32_t kChainedImport = 1;
constexpr std::uint32_t kChainedImportAddend = 2;
constexpr std::uint32_t kChainedImportAddend64 = 3;

constexpr std::uint16_t kChainedPtrStartNone = 0xffff;
constexpr std::uint16_t kChainedPtrStartMulti = 0x8000;
constexpr std::uint16_t kChainedPtrStartLast = 0x8000;

constexpr std::size_t kMaxChainedImports = 1U << 20;
constexpr std::size_t kMaxChainedSegments = 4096;
constexpr std::size_t kMaxChainedSymbolLength = 4096;

enum class ChainedPointerFormat : std::uint16_t {
    arm64e = 1,
    generic64 = 2,
    generic32 = 3,
    generic32_cache = 4,
    generic32_firmware = 5,
    generic64_offset = 6,
    arm64e_kernel = 7,
    generic64_kernel_cache = 8,
    arm64e_userland = 9,
    arm64e_firmware = 10,
    x86_64_kernel_cache = 11,
    arm64e_userland24 = 12,
    arm64e_shared_cache = 13,
    arm64e_segmented = 14,
};

struct ChainedImportEntry {
    std::int32_t library_ordinal{};
    bool weak_import{};
    std::string symbol_name;
    std::int64_t addend{};
};

struct ChainedPageStarts {
    std::vector<std::uint16_t> offsets;
};

struct ChainedSegmentStarts {
    bool present{};
    std::uint16_t page_size{};
    ChainedPointerFormat pointer_format{ChainedPointerFormat::generic64};
    std::uint64_t segment_offset{};
    std::uint32_t max_valid_pointer{};
    std::vector<ChainedPageStarts> pages;
};

struct ChainedFixupsMetadata {
    std::uint32_t imports_format{};
    std::vector<ChainedImportEntry> imports;
    std::vector<ChainedSegmentStarts> segments;
};

enum class ChainedFixupsError {
    none,
    range_out_of_bounds,
    header_too_small,
    unsupported_version,
    starts_offset_out_of_bounds,
    imports_offset_out_of_bounds,
    symbols_offset_out_of_bounds,
    unsupported_imports_format,
    unsupported_symbols_format,
    imports_limit,
    imports_table_out_of_bounds,
    imports_overlap_symbols,
    import_reserved_bits,
    import_name_out_of_bounds,
    import_name_unterminated,
    import_name_too_long,
    starts_header_out_of_bounds,
    segment_limit,
    segment_count_exceeds_image,
    segment_info_offset_out_of_bounds,
    segment_info_too_small,
    segment_info_out_of_bounds,
    invalid_page_size,
    invalid_pointer_format,
    pointer_size_mismatch,
    mixed_pointer_formats,
    page_start_array_out_of_bounds,
    page_start_out_of_bounds,
    multi_start_unsupported_64,
};

struct ChainedFixupsResult {
    ChainedFixupsMetadata metadata;
    ChainedFixupsError error{ChainedFixupsError::none};
    std::size_t error_offset{};

    [[nodiscard]] explicit operator bool() const noexcept {
        return error == ChainedFixupsError::none;
    }
};

// Parse an LC_DYLD_CHAINED_FIXUPS payload without mutating guest memory.
// `image_segments` is used only for structural validation of seg_count and
// 32-bit-vs-64-bit pointer formats; phase 19 does not walk or apply chains.
[[nodiscard]] ChainedFixupsResult parse_chained_fixups(
    std::span<const std::byte> payload,
    std::span<const macho::Segment> image_segments);

// Parse the chained-fixups range recorded in a Mach-O image. An absent or
// zero-sized range is valid and yields empty metadata.
[[nodiscard]] ChainedFixupsResult parse_image_chained_fixups(
    const macho::Image& image,
    std::span<const std::byte> file_bytes);

[[nodiscard]] std::string_view chained_pointer_format_name(ChainedPointerFormat format) noexcept;
[[nodiscard]] std::string_view chained_fixups_error_name(ChainedFixupsError error) noexcept;

} // namespace macosarm::dyld
