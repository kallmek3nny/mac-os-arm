#include "macosarm/dyld_fixups.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <string>
#include <vector>

namespace {

int failures = 0;

void expect(bool condition, const std::string& label) {
    if (!condition) {
        std::cerr << "FAIL: " << label << '\n';
        ++failures;
    }
}

void put_u16(std::vector<std::byte>& bytes, std::size_t offset, std::uint16_t value) {
    bytes[offset] = static_cast<std::byte>(value & 0xffU);
    bytes[offset + 1] = static_cast<std::byte>((value >> 8) & 0xffU);
}

void put_u32(std::vector<std::byte>& bytes, std::size_t offset, std::uint32_t value) {
    for (std::size_t index = 0; index < 4; ++index) {
        bytes[offset + index] = static_cast<std::byte>((value >> (index * 8)) & 0xffU);
    }
}

void put_u64(std::vector<std::byte>& bytes, std::size_t offset, std::uint64_t value) {
    for (std::size_t index = 0; index < 8; ++index) {
        bytes[offset + index] = static_cast<std::byte>((value >> (index * 8)) & 0xffU);
    }
}

void put_string(std::vector<std::byte>& bytes, std::size_t offset, const std::string& value) {
    for (std::size_t index = 0; index < value.size(); ++index) {
        bytes[offset + index] = static_cast<std::byte>(static_cast<unsigned char>(value[index]));
    }
    bytes[offset + value.size()] = std::byte{0};
}

std::vector<macosarm::macho::Segment> two_segments() {
    return {
        {"__TEXT", 0x100000000ULL, 0x8000, 0, 0x8000, 5, 5},
        {"__LINKEDIT", 0x100008000ULL, 0x4000, 0x8000, 0x4000, 1, 1},
    };
}

struct PayloadLayout {
    std::vector<std::byte> bytes;
    std::size_t starts_offset{};
    std::size_t segment_offset{};
    std::size_t imports_offset{};
    std::size_t symbols_offset{};
};

PayloadLayout make_payload(std::uint32_t imports_format) {
    constexpr std::size_t kHeaderSize = 28;
    constexpr std::size_t kStartsSize = 12;
    constexpr std::size_t kSegmentSize = 26;

    std::size_t import_entry_size = 4;
    if (imports_format == macosarm::dyld::kChainedImportAddend) {
        import_entry_size = 8;
    } else if (imports_format == macosarm::dyld::kChainedImportAddend64) {
        import_entry_size = 16;
    }

    PayloadLayout layout;
    layout.starts_offset = kHeaderSize;
    layout.segment_offset = layout.starts_offset + kStartsSize;
    layout.imports_offset = layout.segment_offset + kSegmentSize + 2;
    layout.symbols_offset = layout.imports_offset + import_entry_size * 2;
    layout.bytes.resize(layout.symbols_offset + 11, std::byte{0});

    put_u32(layout.bytes, 0, 0);
    put_u32(layout.bytes, 4, static_cast<std::uint32_t>(layout.starts_offset));
    put_u32(layout.bytes, 8, static_cast<std::uint32_t>(layout.imports_offset));
    put_u32(layout.bytes, 12, static_cast<std::uint32_t>(layout.symbols_offset));
    put_u32(layout.bytes, 16, 2);
    put_u32(layout.bytes, 20, imports_format);
    put_u32(layout.bytes, 24, 0);

    put_u32(layout.bytes, layout.starts_offset, 2);
    put_u32(layout.bytes, layout.starts_offset + 4, 12);
    put_u32(layout.bytes, layout.starts_offset + 8, 0);

    put_u32(layout.bytes, layout.segment_offset, static_cast<std::uint32_t>(kSegmentSize));
    put_u16(layout.bytes, layout.segment_offset + 4, 0x4000);
    put_u16(
        layout.bytes,
        layout.segment_offset + 6,
        static_cast<std::uint16_t>(macosarm::dyld::ChainedPointerFormat::arm64e_userland));
    put_u64(layout.bytes, layout.segment_offset + 8, 0);
    put_u32(layout.bytes, layout.segment_offset + 16, 0);
    put_u16(layout.bytes, layout.segment_offset + 20, 2);
    put_u16(layout.bytes, layout.segment_offset + 22, 0x20);
    put_u16(layout.bytes, layout.segment_offset + 24, macosarm::dyld::kChainedPtrStartNone);

    if (imports_format == macosarm::dyld::kChainedImport) {
        put_u32(layout.bytes, layout.imports_offset, 1U | (1U << 8));
        put_u32(layout.bytes, layout.imports_offset + 4, 0xf1U | (5U << 9));
    } else if (imports_format == macosarm::dyld::kChainedImportAddend) {
        put_u32(layout.bytes, layout.imports_offset, 1U | (1U << 8));
        put_u32(layout.bytes, layout.imports_offset + 4, 7);
        put_u32(layout.bytes, layout.imports_offset + 8, 0xf1U | (5U << 9));
        put_u32(layout.bytes, layout.imports_offset + 12, 0xfffffff9U);
    } else if (imports_format == macosarm::dyld::kChainedImportAddend64) {
        put_u64(layout.bytes, layout.imports_offset, 1ULL | (1ULL << 16));
        put_u64(layout.bytes, layout.imports_offset + 8, 9);
        put_u64(layout.bytes, layout.imports_offset + 16, 0xfff1ULL | (5ULL << 32));
        put_u64(layout.bytes, layout.imports_offset + 24, 0xfffffffffffffff7ULL);
    } else {
        put_u32(layout.bytes, layout.imports_offset, 1U | (1U << 8));
        put_u32(layout.bytes, layout.imports_offset + 4, 0xf1U | (5U << 9));
    }

    put_string(layout.bytes, layout.symbols_offset, "_foo");
    put_string(layout.bytes, layout.symbols_offset + 5, "_bar");
    return layout;
}

void expect_error(
    const PayloadLayout& layout,
    macosarm::dyld::ChainedFixupsError expected,
    const std::string& label) {
    const auto segments = two_segments();
    const auto result = macosarm::dyld::parse_chained_fixups(layout.bytes, segments);
    expect(result.error == expected, label);
}

} // namespace

int main() {
    using macosarm::dyld::ChainedFixupsError;
    using macosarm::dyld::ChainedPointerFormat;

    for (const std::uint32_t format : {
             macosarm::dyld::kChainedImport,
             macosarm::dyld::kChainedImportAddend,
             macosarm::dyld::kChainedImportAddend64}) {
        const auto layout = make_payload(format);
        const auto segments = two_segments();
        const auto result = macosarm::dyld::parse_chained_fixups(layout.bytes, segments);
        expect(static_cast<bool>(result), "valid chained-fixups payload parses");
        expect(result.metadata.imports_format == format && result.metadata.imports.size() == 2,
               "import format and count preserved");
        expect(result.metadata.imports[0].library_ordinal == 1 &&
                   result.metadata.imports[0].weak_import &&
                   result.metadata.imports[0].symbol_name == "_foo",
               "positive weak import decoded");
        expect(result.metadata.imports[1].library_ordinal == -15 &&
                   !result.metadata.imports[1].weak_import &&
                   result.metadata.imports[1].symbol_name == "_bar",
               "negative special library ordinal decoded explicitly");
        if (format == macosarm::dyld::kChainedImport) {
            expect(result.metadata.imports[0].addend == 0 && result.metadata.imports[1].addend == 0,
                   "plain imports have zero addends");
        } else {
            const std::int64_t expected_first =
                format == macosarm::dyld::kChainedImportAddend ? 7 : 9;
            const std::int64_t expected_second =
                format == macosarm::dyld::kChainedImportAddend ? -7 : -9;
            expect(result.metadata.imports[0].addend == expected_first &&
                       result.metadata.imports[1].addend == expected_second,
                   "signed import addends decoded without implementation-defined casts");
        }
        expect(result.metadata.segments.size() == 2 && result.metadata.segments[0].present &&
                   !result.metadata.segments[1].present,
               "segment starts preserve absent segment entries");
        expect(result.metadata.segments[0].page_size == 0x4000 &&
                   result.metadata.segments[0].pointer_format == ChainedPointerFormat::arm64e_userland &&
                   result.metadata.segments[0].pages.size() == 2,
               "segment page metadata decoded");
        expect(result.metadata.segments[0].pages[0].offsets.size() == 1 &&
                   result.metadata.segments[0].pages[0].offsets[0] == 0x20 &&
                   result.metadata.segments[0].pages[1].offsets.empty(),
               "single page start and NONE entry decoded");
    }

    {
        macosarm::macho::Image image;
        const std::vector<std::byte> file(32, std::byte{0});
        expect(static_cast<bool>(macosarm::dyld::parse_image_chained_fixups(image, file)),
               "absent image fixups are valid and empty");
        image.chained_fixups = macosarm::macho::FileRange{0, 0, true};
        expect(static_cast<bool>(macosarm::dyld::parse_image_chained_fixups(image, file)),
               "zero-sized image fixups are valid and empty");
        image.chained_fixups = macosarm::macho::FileRange{31, 2, true};
        const auto bad = macosarm::dyld::parse_image_chained_fixups(image, file);
        expect(bad.error == ChainedFixupsError::range_out_of_bounds,
               "out-of-file chained-fixups range rejected");
    }

    {
        const std::vector<std::byte> tiny(27, std::byte{0});
        const auto segments = two_segments();
        expect(macosarm::dyld::parse_chained_fixups(tiny, segments).error ==
                   ChainedFixupsError::header_too_small,
               "truncated header rejected");
    }

    {
        auto layout = make_payload(macosarm::dyld::kChainedImport);
        put_u32(layout.bytes, 0, 1);
        expect_error(layout, ChainedFixupsError::unsupported_version, "unknown fixups version rejected");
    }
    {
        auto layout = make_payload(macosarm::dyld::kChainedImport);
        put_u32(layout.bytes, 4, static_cast<std::uint32_t>(layout.bytes.size()));
        expect_error(layout, ChainedFixupsError::starts_offset_out_of_bounds, "bad starts offset rejected");
    }
    {
        auto layout = make_payload(macosarm::dyld::kChainedImport);
        put_u32(layout.bytes, 8, static_cast<std::uint32_t>(layout.bytes.size() + 1));
        expect_error(layout, ChainedFixupsError::imports_offset_out_of_bounds, "bad imports offset rejected");
    }
    {
        auto layout = make_payload(macosarm::dyld::kChainedImport);
        put_u32(layout.bytes, 12, static_cast<std::uint32_t>(layout.bytes.size() + 1));
        expect_error(layout, ChainedFixupsError::symbols_offset_out_of_bounds, "bad symbols offset rejected");
    }
    {
        auto layout = make_payload(macosarm::dyld::kChainedImport);
        put_u32(layout.bytes, 20, 99);
        expect_error(layout, ChainedFixupsError::unsupported_imports_format, "unknown import format rejected");
    }
    {
        auto layout = make_payload(macosarm::dyld::kChainedImport);
        put_u32(layout.bytes, 24, 1);
        expect_error(layout, ChainedFixupsError::unsupported_symbols_format, "compressed symbol pool rejected explicitly");
    }
    {
        auto layout = make_payload(macosarm::dyld::kChainedImport);
        put_u32(layout.bytes, 16, static_cast<std::uint32_t>(macosarm::dyld::kMaxChainedImports + 1));
        expect_error(layout, ChainedFixupsError::imports_limit, "import-count abuse bound enforced");
    }
    {
        auto layout = make_payload(macosarm::dyld::kChainedImportAddend64);
        put_u32(layout.bytes, 12, static_cast<std::uint32_t>(layout.imports_offset + 16));
        expect_error(layout, ChainedFixupsError::imports_overlap_symbols, "imports overlapping symbol pool rejected");
    }
    {
        auto layout = make_payload(macosarm::dyld::kChainedImportAddend64);
        const std::uint64_t word = 1ULL | (1ULL << 17);
        put_u64(layout.bytes, layout.imports_offset, word);
        expect_error(layout, ChainedFixupsError::import_reserved_bits, "ADDEND64 reserved bits rejected");
    }
    {
        auto layout = make_payload(macosarm::dyld::kChainedImport);
        put_u32(layout.bytes, layout.imports_offset, 1U | (0x7fffffU << 9));
        expect_error(layout, ChainedFixupsError::import_name_out_of_bounds, "import name offset outside symbol pool rejected");
    }
    {
        auto layout = make_payload(macosarm::dyld::kChainedImport);
        put_u32(layout.bytes, layout.imports_offset, 1U | (5U << 9));
        layout.bytes.resize(layout.symbols_offset + 10);
        layout.bytes[layout.symbols_offset + 9] = std::byte{'x'};
        expect_error(layout, ChainedFixupsError::import_name_unterminated, "unterminated import name rejected");
    }
    {
        auto layout = make_payload(macosarm::dyld::kChainedImport);
        layout.bytes.resize(layout.symbols_offset + macosarm::dyld::kMaxChainedSymbolLength + 2);
        std::fill(
            layout.bytes.begin() + static_cast<std::ptrdiff_t>(layout.symbols_offset),
            layout.bytes.end() - 1,
            std::byte{'a'});
        layout.bytes.back() = std::byte{0};
        put_u32(layout.bytes, layout.imports_offset, 1U);
        expect_error(layout, ChainedFixupsError::import_name_too_long, "oversized import name rejected");
    }
    {
        auto layout = make_payload(macosarm::dyld::kChainedImport);
        put_u32(layout.bytes, layout.starts_offset, 3);
        expect_error(layout, ChainedFixupsError::segment_count_exceeds_image, "seg_count beyond Mach-O segments rejected");
    }
    {
        auto layout = make_payload(macosarm::dyld::kChainedImport);
        put_u32(layout.bytes, layout.starts_offset + 4, 4);
        expect_error(layout, ChainedFixupsError::segment_info_offset_out_of_bounds, "segment-info pointer into starts table rejected");
    }
    {
        auto layout = make_payload(macosarm::dyld::kChainedImport);
        put_u32(layout.bytes, layout.segment_offset, 20);
        expect_error(layout, ChainedFixupsError::segment_info_too_small, "undersized segment starts rejected");
    }
    {
        auto layout = make_payload(macosarm::dyld::kChainedImport);
        put_u32(layout.bytes, layout.segment_offset, 0x1000);
        expect_error(layout, ChainedFixupsError::segment_info_out_of_bounds, "segment starts crossing imports table rejected");
    }
    {
        auto layout = make_payload(macosarm::dyld::kChainedImport);
        put_u16(layout.bytes, layout.segment_offset + 4, 0x2000);
        expect_error(layout, ChainedFixupsError::invalid_page_size, "non-4K/non-16K page size rejected");
    }
    {
        auto layout = make_payload(macosarm::dyld::kChainedImport);
        put_u16(layout.bytes, layout.segment_offset + 6, 0);
        expect_error(layout, ChainedFixupsError::invalid_pointer_format, "unknown pointer format rejected");
    }
    {
        auto layout = make_payload(macosarm::dyld::kChainedImport);
        put_u16(
            layout.bytes,
            layout.segment_offset + 6,
            static_cast<std::uint16_t>(ChainedPointerFormat::generic32));
        expect_error(layout, ChainedFixupsError::pointer_size_mismatch, "32-bit pointer format rejected for ARM64 image");
    }
    {
        auto layout = make_payload(macosarm::dyld::kChainedImport);
        put_u16(layout.bytes, layout.segment_offset + 20, 3);
        expect_error(layout, ChainedFixupsError::page_start_array_out_of_bounds, "page-start array exceeding struct size rejected");
    }
    {
        auto layout = make_payload(macosarm::dyld::kChainedImport);
        put_u16(layout.bytes, layout.segment_offset + 22, 0x4001);
        expect_error(layout, ChainedFixupsError::page_start_out_of_bounds, "page start beyond page rejected");
    }
    {
        auto layout = make_payload(macosarm::dyld::kChainedImport);
        put_u16(layout.bytes, layout.segment_offset + 22, 0x8001);
        expect_error(layout, ChainedFixupsError::multi_start_unsupported_64, "64-bit multi-start page rejected");
    }

    {
        auto layout = make_payload(macosarm::dyld::kChainedImport);
        constexpr std::size_t kSecondSegmentSize = 24;
        const std::size_t old_imports_offset = layout.imports_offset;
        layout.bytes.insert(
            layout.bytes.begin() + static_cast<std::ptrdiff_t>(old_imports_offset),
            kSecondSegmentSize,
            std::byte{0});
        layout.imports_offset += kSecondSegmentSize;
        layout.symbols_offset += kSecondSegmentSize;
        put_u32(layout.bytes, 8, static_cast<std::uint32_t>(layout.imports_offset));
        put_u32(layout.bytes, 12, static_cast<std::uint32_t>(layout.symbols_offset));

        const std::size_t second_segment = old_imports_offset;
        put_u32(
            layout.bytes,
            layout.starts_offset + 8,
            static_cast<std::uint32_t>(second_segment - layout.starts_offset));
        put_u32(layout.bytes, second_segment, static_cast<std::uint32_t>(kSecondSegmentSize));
        put_u16(layout.bytes, second_segment + 4, 0x4000);
        put_u16(
            layout.bytes,
            second_segment + 6,
            static_cast<std::uint16_t>(ChainedPointerFormat::generic64));
        put_u64(layout.bytes, second_segment + 8, 0x8000);
        put_u32(layout.bytes, second_segment + 16, 0);
        put_u16(layout.bytes, second_segment + 20, 1);
        put_u16(layout.bytes, second_segment + 22, macosarm::dyld::kChainedPtrStartNone);
        expect_error(layout, ChainedFixupsError::mixed_pointer_formats, "mixed chained pointer formats rejected");
    }

    expect(macosarm::dyld::chained_pointer_format_name(ChainedPointerFormat::arm64e_userland24) ==
               "arm64e_userland24",
           "pointer formats have stable names");
    expect(macosarm::dyld::chained_fixups_error_name(ChainedFixupsError::imports_overlap_symbols) ==
               "imports_overlap_symbols",
           "chained-fixups errors have stable names");

    if (failures != 0) {
        std::cerr << failures << " test(s) failed\n";
        return EXIT_FAILURE;
    }
    std::cout << "dyld chained-fixups metadata tests passed\n";
    return EXIT_SUCCESS;
}
