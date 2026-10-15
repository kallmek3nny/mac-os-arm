#include "macosarm/dyld_fixups.hpp"

#include <algorithm>
#include <limits>
#include <utility>

namespace macosarm::dyld {
namespace {

constexpr std::size_t kHeaderSize = 28;
constexpr std::size_t kStartsHeaderFixedSize = 4;
constexpr std::size_t kSegmentStartsFixedSize = 22;

[[nodiscard]] std::uint16_t read_u16(std::span<const std::byte> bytes, std::size_t offset) noexcept {
    return static_cast<std::uint16_t>(
        std::to_integer<unsigned char>(bytes[offset]) |
        (static_cast<std::uint16_t>(std::to_integer<unsigned char>(bytes[offset + 1])) << 8));
}

[[nodiscard]] std::uint32_t read_u32(std::span<const std::byte> bytes, std::size_t offset) noexcept {
    std::uint32_t value = 0;
    for (unsigned index = 0; index < 4; ++index) {
        value |= static_cast<std::uint32_t>(std::to_integer<unsigned char>(bytes[offset + index]))
                 << (index * 8U);
    }
    return value;
}

[[nodiscard]] std::uint64_t read_u64(std::span<const std::byte> bytes, std::size_t offset) noexcept {
    std::uint64_t value = 0;
    for (unsigned index = 0; index < 8; ++index) {
        value |= static_cast<std::uint64_t>(std::to_integer<unsigned char>(bytes[offset + index]))
                 << (index * 8U);
    }
    return value;
}

[[nodiscard]] std::int64_t signed_u32(std::uint32_t value) noexcept {
    if (value <= static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max())) {
        return static_cast<std::int64_t>(value);
    }
    const std::uint64_t magnitude =
        static_cast<std::uint64_t>((~value) + static_cast<std::uint32_t>(1));
    if (magnitude == (std::uint64_t{1} << 31)) {
        return static_cast<std::int64_t>(std::numeric_limits<std::int32_t>::min());
    }
    return -static_cast<std::int64_t>(magnitude);
}

[[nodiscard]] std::int64_t signed_u64(std::uint64_t value) noexcept {
    if (value <= static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
        return static_cast<std::int64_t>(value);
    }
    const std::uint64_t magnitude = (~value) + std::uint64_t{1};
    if (magnitude == (std::uint64_t{1} << 63)) {
        return std::numeric_limits<std::int64_t>::min();
    }
    return -static_cast<std::int64_t>(magnitude);
}

[[nodiscard]] std::int32_t signed_ordinal8(std::uint32_t value) noexcept {
    value &= 0xffU;
    if (value > 0xf0U) {
        return static_cast<std::int32_t>(value) - 0x100;
    }
    return static_cast<std::int32_t>(value);
}

[[nodiscard]] std::int32_t signed_ordinal16(std::uint64_t value) noexcept {
    value &= 0xffffU;
    if (value > 0xfff0U) {
        return static_cast<std::int32_t>(value) - 0x10000;
    }
    return static_cast<std::int32_t>(value);
}

[[nodiscard]] bool is_known_pointer_format(std::uint16_t value) noexcept {
    return value >= static_cast<std::uint16_t>(ChainedPointerFormat::arm64e) &&
           value <= static_cast<std::uint16_t>(ChainedPointerFormat::arm64e_segmented);
}

[[nodiscard]] bool is_64_bit_pointer_format(ChainedPointerFormat format) noexcept {
    switch (format) {
    case ChainedPointerFormat::generic32:
    case ChainedPointerFormat::generic32_cache:
    case ChainedPointerFormat::generic32_firmware:
        return false;
    case ChainedPointerFormat::arm64e:
    case ChainedPointerFormat::generic64:
    case ChainedPointerFormat::generic64_offset:
    case ChainedPointerFormat::arm64e_kernel:
    case ChainedPointerFormat::generic64_kernel_cache:
    case ChainedPointerFormat::arm64e_userland:
    case ChainedPointerFormat::arm64e_firmware:
    case ChainedPointerFormat::x86_64_kernel_cache:
    case ChainedPointerFormat::arm64e_userland24:
    case ChainedPointerFormat::arm64e_shared_cache:
    case ChainedPointerFormat::arm64e_segmented:
        return true;
    }
    return false;
}

class Parser {
public:
    Parser(std::span<const std::byte> payload, std::span<const macho::Segment> image_segments)
        : payload_(payload), image_segments_(image_segments) {}

    [[nodiscard]] ChainedFixupsResult run() {
        if (payload_.size() < kHeaderSize) {
            return fail(ChainedFixupsError::header_too_small, payload_.size());
        }

        const std::uint32_t version = read_u32(payload_, 0);
        starts_offset_ = read_u32(payload_, 4);
        imports_offset_ = read_u32(payload_, 8);
        symbols_offset_ = read_u32(payload_, 12);
        imports_count_ = read_u32(payload_, 16);
        imports_format_ = read_u32(payload_, 20);
        const std::uint32_t symbols_format = read_u32(payload_, 24);

        if (version != kChainedFixupsVersion) {
            return fail(ChainedFixupsError::unsupported_version, 0);
        }
        if (starts_offset_ >= payload_.size()) {
            return fail(ChainedFixupsError::starts_offset_out_of_bounds, 4);
        }
        if (imports_offset_ > payload_.size()) {
            return fail(ChainedFixupsError::imports_offset_out_of_bounds, 8);
        }
        if (symbols_offset_ > payload_.size()) {
            return fail(ChainedFixupsError::symbols_offset_out_of_bounds, 12);
        }
        if (symbols_format != 0) {
            return fail(ChainedFixupsError::unsupported_symbols_format, 24);
        }
        if (imports_count_ > kMaxChainedImports) {
            return fail(ChainedFixupsError::imports_limit, 16);
        }

        std::size_t import_entry_size = 0;
        switch (imports_format_) {
        case kChainedImport: import_entry_size = 4; break;
        case kChainedImportAddend: import_entry_size = 8; break;
        case kChainedImportAddend64: import_entry_size = 16; break;
        default:
            return fail(ChainedFixupsError::unsupported_imports_format, 20);
        }

        if (imports_count_ != 0 &&
            import_entry_size > std::numeric_limits<std::size_t>::max() / imports_count_) {
            return fail(ChainedFixupsError::imports_table_out_of_bounds, 16);
        }
        const std::size_t imports_bytes = import_entry_size * static_cast<std::size_t>(imports_count_);
        if (imports_offset_ > payload_.size() || imports_bytes > payload_.size() - imports_offset_) {
            return fail(ChainedFixupsError::imports_table_out_of_bounds, imports_offset_);
        }
        if (imports_offset_ > symbols_offset_ || imports_bytes > symbols_offset_ - imports_offset_) {
            return fail(ChainedFixupsError::imports_overlap_symbols, imports_offset_);
        }

        result_.metadata.imports_format = imports_format_;
        if (!parse_imports(import_entry_size)) {
            return std::move(result_);
        }
        if (!parse_starts()) {
            return std::move(result_);
        }
        return std::move(result_);
    }

private:
    [[nodiscard]] ChainedFixupsResult fail(ChainedFixupsError error, std::size_t offset) {
        result_.error = error;
        result_.error_offset = offset;
        return std::move(result_);
    }

    [[nodiscard]] bool set_error(ChainedFixupsError error, std::size_t offset) {
        if (result_.error == ChainedFixupsError::none) {
            result_.error = error;
            result_.error_offset = offset;
        }
        return false;
    }

    [[nodiscard]] bool parse_symbol_name(std::uint64_t name_offset, std::string& output) {
        const std::size_t pool_size = payload_.size() - symbols_offset_;
        if (name_offset >= pool_size) {
            return set_error(ChainedFixupsError::import_name_out_of_bounds, symbols_offset_);
        }
        const std::size_t start = symbols_offset_ + static_cast<std::size_t>(name_offset);
        std::size_t cursor = start;
        while (cursor < payload_.size() && payload_[cursor] != std::byte{0}) {
            if (cursor - start >= kMaxChainedSymbolLength) {
                return set_error(ChainedFixupsError::import_name_too_long, start);
            }
            ++cursor;
        }
        if (cursor >= payload_.size()) {
            return set_error(ChainedFixupsError::import_name_unterminated, start);
        }
        output.reserve(cursor - start);
        for (std::size_t index = start; index < cursor; ++index) {
            output.push_back(static_cast<char>(std::to_integer<unsigned char>(payload_[index])));
        }
        return true;
    }

    [[nodiscard]] bool parse_imports(std::size_t import_entry_size) {
        result_.metadata.imports.reserve(imports_count_);
        for (std::size_t index = 0; index < imports_count_; ++index) {
            const std::size_t offset = imports_offset_ + index * import_entry_size;
            ChainedImportEntry entry;
            std::uint64_t name_offset = 0;

            if (imports_format_ == kChainedImport || imports_format_ == kChainedImportAddend) {
                const std::uint32_t word = read_u32(payload_, offset);
                entry.library_ordinal = signed_ordinal8(word);
                entry.weak_import = ((word >> 8) & 1U) != 0;
                name_offset = word >> 9;
                if (imports_format_ == kChainedImportAddend) {
                    entry.addend = signed_u32(read_u32(payload_, offset + 4));
                }
            } else {
                const std::uint64_t word = read_u64(payload_, offset);
                entry.library_ordinal = signed_ordinal16(word);
                entry.weak_import = ((word >> 16) & 1U) != 0;
                if (((word >> 17) & 0x7fffU) != 0) {
                    return set_error(ChainedFixupsError::import_reserved_bits, offset);
                }
                name_offset = word >> 32;
                // Apple surfaces ADDEND64 through an int64_t bind-target callback.
                // Decode two's complement explicitly instead of relying on an
                // implementation-defined unsigned-to-signed conversion.
                entry.addend = signed_u64(read_u64(payload_, offset + 8));
            }

            if (!parse_symbol_name(name_offset, entry.symbol_name)) {
                return false;
            }
            result_.metadata.imports.push_back(std::move(entry));
        }
        return true;
    }

    [[nodiscard]] bool parse_starts() {
        if (starts_offset_ > imports_offset_ ||
            kStartsHeaderFixedSize > imports_offset_ - starts_offset_) {
            return set_error(ChainedFixupsError::starts_header_out_of_bounds, starts_offset_);
        }

        const std::uint32_t segment_count = read_u32(payload_, starts_offset_);
        if (segment_count > kMaxChainedSegments) {
            return set_error(ChainedFixupsError::segment_limit, starts_offset_);
        }
        if (segment_count > image_segments_.size()) {
            return set_error(ChainedFixupsError::segment_count_exceeds_image, starts_offset_);
        }

        const std::size_t offsets_size = static_cast<std::size_t>(segment_count) * 4;
        const std::size_t starts_table_size = kStartsHeaderFixedSize + offsets_size;
        if (starts_table_size > imports_offset_ - starts_offset_) {
            return set_error(ChainedFixupsError::starts_header_out_of_bounds, starts_offset_);
        }
        const std::size_t starts_table_end = starts_offset_ + starts_table_size;

        result_.metadata.segments.resize(segment_count);
        bool have_pointer_format = false;
        ChainedPointerFormat first_pointer_format = ChainedPointerFormat::generic64;

        for (std::size_t segment_index = 0; segment_index < segment_count; ++segment_index) {
            const std::size_t offset_field = starts_offset_ + 4 + segment_index * 4;
            const std::uint32_t relative_offset = read_u32(payload_, offset_field);
            if (relative_offset == 0) {
                continue;
            }
            if (relative_offset > imports_offset_ - starts_offset_) {
                return set_error(ChainedFixupsError::segment_info_offset_out_of_bounds, offset_field);
            }
            const std::size_t segment_offset = starts_offset_ + relative_offset;
            if (segment_offset < starts_table_end || segment_offset >= imports_offset_) {
                return set_error(ChainedFixupsError::segment_info_offset_out_of_bounds, offset_field);
            }
            if (kSegmentStartsFixedSize > imports_offset_ - segment_offset) {
                return set_error(ChainedFixupsError::segment_info_too_small, segment_offset);
            }

            const std::uint32_t structure_size = read_u32(payload_, segment_offset);
            if (structure_size < kSegmentStartsFixedSize) {
                return set_error(ChainedFixupsError::segment_info_too_small, segment_offset);
            }
            if (structure_size > imports_offset_ - segment_offset) {
                return set_error(ChainedFixupsError::segment_info_out_of_bounds, segment_offset);
            }

            ChainedSegmentStarts& segment = result_.metadata.segments[segment_index];
            segment.present = true;
            segment.page_size = read_u16(payload_, segment_offset + 4);
            if (segment.page_size != 0x1000 && segment.page_size != 0x4000) {
                return set_error(ChainedFixupsError::invalid_page_size, segment_offset + 4);
            }

            const std::uint16_t raw_pointer_format = read_u16(payload_, segment_offset + 6);
            if (!is_known_pointer_format(raw_pointer_format)) {
                return set_error(ChainedFixupsError::invalid_pointer_format, segment_offset + 6);
            }
            segment.pointer_format = static_cast<ChainedPointerFormat>(raw_pointer_format);
            if (!is_64_bit_pointer_format(segment.pointer_format)) {
                return set_error(ChainedFixupsError::pointer_size_mismatch, segment_offset + 6);
            }
            if (!have_pointer_format) {
                first_pointer_format = segment.pointer_format;
                have_pointer_format = true;
            } else if (segment.pointer_format != first_pointer_format) {
                return set_error(ChainedFixupsError::mixed_pointer_formats, segment_offset + 6);
            }

            segment.segment_offset = read_u64(payload_, segment_offset + 8);
            segment.max_valid_pointer = read_u32(payload_, segment_offset + 16);
            const std::uint16_t page_count = read_u16(payload_, segment_offset + 20);

            const std::size_t page_array_bytes = static_cast<std::size_t>(page_count) * 2;
            if (page_array_bytes > structure_size - kSegmentStartsFixedSize) {
                return set_error(ChainedFixupsError::page_start_array_out_of_bounds, segment_offset + 20);
            }

            segment.pages.resize(page_count);
            for (std::size_t page_index = 0; page_index < page_count; ++page_index) {
                const std::size_t page_field = segment_offset + kSegmentStartsFixedSize + page_index * 2;
                const std::uint16_t page_start = read_u16(payload_, page_field);
                if (page_start == kChainedPtrStartNone) {
                    continue;
                }
                if ((page_start & kChainedPtrStartMulti) != 0) {
                    return set_error(ChainedFixupsError::multi_start_unsupported_64, page_field);
                }
                if (page_start > segment.page_size) {
                    return set_error(ChainedFixupsError::page_start_out_of_bounds, page_field);
                }
                segment.pages[page_index].offsets.push_back(page_start);
            }
        }
        return true;
    }

    std::span<const std::byte> payload_;
    std::span<const macho::Segment> image_segments_;
    ChainedFixupsResult result_;
    std::size_t starts_offset_{};
    std::size_t imports_offset_{};
    std::size_t symbols_offset_{};
    std::size_t imports_count_{};
    std::uint32_t imports_format_{};
};

} // namespace

ChainedFixupsResult parse_chained_fixups(
    std::span<const std::byte> payload,
    std::span<const macho::Segment> image_segments) {
    return Parser(payload, image_segments).run();
}

ChainedFixupsResult parse_image_chained_fixups(
    const macho::Image& image,
    std::span<const std::byte> file_bytes) {
    if (!image.chained_fixups.present || image.chained_fixups.size == 0) {
        return {};
    }
    const std::size_t offset = image.chained_fixups.offset;
    const std::size_t size = image.chained_fixups.size;
    if (offset > file_bytes.size() || size > file_bytes.size() - offset) {
        ChainedFixupsResult result;
        result.error = ChainedFixupsError::range_out_of_bounds;
        result.error_offset = offset;
        return result;
    }
    return parse_chained_fixups(file_bytes.subspan(offset, size), image.segments);
}

std::string_view chained_pointer_format_name(ChainedPointerFormat format) noexcept {
    switch (format) {
    case ChainedPointerFormat::arm64e: return "arm64e";
    case ChainedPointerFormat::generic64: return "64";
    case ChainedPointerFormat::generic32: return "32";
    case ChainedPointerFormat::generic32_cache: return "32_cache";
    case ChainedPointerFormat::generic32_firmware: return "32_firmware";
    case ChainedPointerFormat::generic64_offset: return "64_offset";
    case ChainedPointerFormat::arm64e_kernel: return "arm64e_kernel";
    case ChainedPointerFormat::generic64_kernel_cache: return "64_kernel_cache";
    case ChainedPointerFormat::arm64e_userland: return "arm64e_userland";
    case ChainedPointerFormat::arm64e_firmware: return "arm64e_firmware";
    case ChainedPointerFormat::x86_64_kernel_cache: return "x86_64_kernel_cache";
    case ChainedPointerFormat::arm64e_userland24: return "arm64e_userland24";
    case ChainedPointerFormat::arm64e_shared_cache: return "arm64e_shared_cache";
    case ChainedPointerFormat::arm64e_segmented: return "arm64e_segmented";
    }
    return "unknown";
}

std::string_view chained_fixups_error_name(ChainedFixupsError error) noexcept {
    switch (error) {
    case ChainedFixupsError::none: return "none";
    case ChainedFixupsError::range_out_of_bounds: return "range_out_of_bounds";
    case ChainedFixupsError::header_too_small: return "header_too_small";
    case ChainedFixupsError::unsupported_version: return "unsupported_version";
    case ChainedFixupsError::starts_offset_out_of_bounds: return "starts_offset_out_of_bounds";
    case ChainedFixupsError::imports_offset_out_of_bounds: return "imports_offset_out_of_bounds";
    case ChainedFixupsError::symbols_offset_out_of_bounds: return "symbols_offset_out_of_bounds";
    case ChainedFixupsError::unsupported_imports_format: return "unsupported_imports_format";
    case ChainedFixupsError::unsupported_symbols_format: return "unsupported_symbols_format";
    case ChainedFixupsError::imports_limit: return "imports_limit";
    case ChainedFixupsError::imports_table_out_of_bounds: return "imports_table_out_of_bounds";
    case ChainedFixupsError::imports_overlap_symbols: return "imports_overlap_symbols";
    case ChainedFixupsError::import_reserved_bits: return "import_reserved_bits";
    case ChainedFixupsError::import_name_out_of_bounds: return "import_name_out_of_bounds";
    case ChainedFixupsError::import_name_unterminated: return "import_name_unterminated";
    case ChainedFixupsError::import_name_too_long: return "import_name_too_long";
    case ChainedFixupsError::starts_header_out_of_bounds: return "starts_header_out_of_bounds";
    case ChainedFixupsError::segment_limit: return "segment_limit";
    case ChainedFixupsError::segment_count_exceeds_image: return "segment_count_exceeds_image";
    case ChainedFixupsError::segment_info_offset_out_of_bounds: return "segment_info_offset_out_of_bounds";
    case ChainedFixupsError::segment_info_too_small: return "segment_info_too_small";
    case ChainedFixupsError::segment_info_out_of_bounds: return "segment_info_out_of_bounds";
    case ChainedFixupsError::invalid_page_size: return "invalid_page_size";
    case ChainedFixupsError::invalid_pointer_format: return "invalid_pointer_format";
    case ChainedFixupsError::pointer_size_mismatch: return "pointer_size_mismatch";
    case ChainedFixupsError::mixed_pointer_formats: return "mixed_pointer_formats";
    case ChainedFixupsError::page_start_array_out_of_bounds: return "page_start_array_out_of_bounds";
    case ChainedFixupsError::page_start_out_of_bounds: return "page_start_out_of_bounds";
    case ChainedFixupsError::multi_start_unsupported_64: return "multi_start_unsupported_64";
    }
    return "unknown";
}

} // namespace macosarm::dyld
