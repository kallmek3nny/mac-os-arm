#include "macosarm/macho.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

namespace {

int meta_failures = 0;

void meta_expect(bool condition, const std::string& label) {
    if (!condition) {
        std::cerr << "FAIL: " << label << '\n';
        ++meta_failures;
    }
}

void meta_put_u32(std::vector<std::byte>& bytes, std::size_t offset, std::uint32_t value) {
    for (std::size_t i = 0; i < 4; ++i) {
        bytes.at(offset + i) = static_cast<std::byte>((value >> (i * 8U)) & 0xffU);
    }
}

void meta_put_u64(std::vector<std::byte>& bytes, std::size_t offset, std::uint64_t value) {
    for (std::size_t i = 0; i < 8; ++i) {
        bytes.at(offset + i) = static_cast<std::byte>((value >> (i * 8U)) & 0xffU);
    }
}

// Load-command offsets inside load_metadata_image(); linkedit payloads sit in 0x360-0x400.
constexpr std::size_t kMetaSymtab = 128;
constexpr std::size_t kMetaDysymtab = 152;
constexpr std::size_t kMetaUuid = 232;
constexpr std::size_t kMetaBuild = 256;
constexpr std::size_t kMetaSource = 288;
constexpr std::size_t kMetaSignature = 304;
constexpr std::size_t kMetaStarts = 320;
constexpr std::size_t kMetaDataInCode = 336;

void meta_command(std::vector<std::byte>& bytes, std::size_t at, std::uint32_t command, std::uint32_t size,
                  std::uint32_t first, std::uint32_t second) {
    meta_put_u32(bytes, at, command);
    meta_put_u32(bytes, at + 4, size);
    meta_put_u32(bytes, at + 8, first);
    meta_put_u32(bytes, at + 12, second);
}

std::vector<std::byte> load_metadata_image() {
    using namespace macosarm::macho;
    std::vector<std::byte> bytes(0x400, std::byte{0});
    meta_put_u32(bytes, 0, kMhMagic64);
    meta_put_u32(bytes, 4, static_cast<std::uint32_t>(kCpuTypeArm64));
    meta_put_u32(bytes, 8, static_cast<std::uint32_t>(kCpuSubtypeArm64e));
    meta_put_u32(bytes, 12, kMhExecute);
    meta_put_u32(bytes, 16, 10U);
    meta_put_u32(bytes, 20, 72U + 24U + 24U + 80U + 24U + 32U + 16U * 4U);

    meta_command(bytes, 32, kLcSegment64, 72, 0, 0);
    meta_put_u64(bytes, 32 + 24, 0x100000000ULL);
    meta_put_u64(bytes, 32 + 32, 0x400ULL);
    meta_put_u64(bytes, 32 + 48, 0x400ULL);
    meta_put_u32(bytes, 32 + 56, 5);
    meta_put_u32(bytes, 32 + 60, 5);
    meta_command(bytes, 104, kLcMain, 24, 0x300, 0);

    meta_command(bytes, kMetaSymtab, kLcSymtab, 24, 0x360, 2);
    meta_put_u32(bytes, kMetaSymtab + 16, 0x380);
    meta_put_u32(bytes, kMetaSymtab + 20, 0x20);
    meta_command(bytes, kMetaDysymtab, kLcDysymtab, 80, 0, 1);
    meta_put_u32(bytes, kMetaDysymtab + 16, 1);
    meta_put_u32(bytes, kMetaDysymtab + 20, 1);
    meta_put_u32(bytes, kMetaDysymtab + 24, 2);
    meta_put_u32(bytes, kMetaDysymtab + 56, 0x3a0);
    meta_put_u32(bytes, kMetaDysymtab + 60, 2);

    meta_put_u32(bytes, kMetaUuid, kLcUuid);
    meta_put_u32(bytes, kMetaUuid + 4, 24);
    for (std::size_t i = 0; i < 16; ++i) {
        bytes.at(kMetaUuid + 8 + i) = static_cast<std::byte>(0xa0U + i);
    }

    meta_command(bytes, kMetaBuild, kLcBuildVersion, 32, 1, 0x001b0000U);
    meta_put_u32(bytes, kMetaBuild + 16, 0x001b0100U);
    meta_put_u32(bytes, kMetaBuild + 20, 1);
    meta_put_u32(bytes, kMetaBuild + 24, 3);
    meta_put_u32(bytes, kMetaBuild + 28, 0x04d20000U);
    meta_put_u32(bytes, kMetaSource, kLcSourceVersion);
    meta_put_u32(bytes, kMetaSource + 4, 16);
    meta_put_u64(bytes, kMetaSource + 8, 0x0000010203040506ULL);

    meta_command(bytes, kMetaSignature, kLcCodeSignature, 16, 0x3c0, 0x40);
    meta_command(bytes, kMetaStarts, kLcFunctionStarts, 16, 0x3a8, 8);
    meta_command(bytes, kMetaDataInCode, kLcDataInCode, 16, 0x3b0, 8);
    return bytes;
}

} // namespace

int macho_load_metadata_main() {
    namespace m = macosarm::macho;

    {
        const auto result = m::parse(load_metadata_image());
        meta_expect(static_cast<bool>(result), "load-command metadata image parses");
        const auto& image = result.image;
        const auto& symbols = image.symbol_table;
        meta_expect(symbols.present && symbols.symbol_offset == 0x360 && symbols.symbol_count == 2 &&
                        symbols.string_offset == 0x380 && symbols.string_size == 0x20,
                    "LC_SYMTAB ranges are preserved");
        const auto& dynamic = image.dynamic_symbol_table;
        meta_expect(dynamic.present && dynamic.local_symbol_count == 1 && dynamic.external_symbol_index == 1 &&
                        dynamic.external_symbol_count == 1 && dynamic.undefined_symbol_index == 2 &&
                        dynamic.indirect_symbol_offset == 0x3a0 && dynamic.indirect_symbol_count == 2,
                    "LC_DYSYMTAB partitions and indirect table are preserved");
        bool uuid_matches = image.has_uuid;
        for (std::size_t i = 0; i < image.uuid.size(); ++i) {
            uuid_matches = uuid_matches && image.uuid[i] == static_cast<std::uint8_t>(0xa0U + i);
        }
        meta_expect(uuid_matches, "LC_UUID bytes are preserved in file order");
        meta_expect(image.build_versions.size() == 1 && image.build_versions[0].platform == 1 &&
                        image.build_versions[0].minimum_os == 0x001b0000U &&
                        image.build_versions[0].sdk == 0x001b0100U && image.build_versions[0].tools.size() == 1 &&
                        image.build_versions[0].tools[0].tool == 3 &&
                        image.build_versions[0].tools[0].version == 0x04d20000U,
                    "LC_BUILD_VERSION platform, versions and tools are preserved");
        meta_expect(image.has_source_version && image.source_version == 0x0000010203040506ULL,
                    "LC_SOURCE_VERSION is preserved");
        meta_expect(image.code_signature.present && image.code_signature.offset == 0x3c0 &&
                        image.code_signature.size == 0x40,
                    "LC_CODE_SIGNATURE range is preserved");
        meta_expect(image.function_starts.present && image.function_starts.offset == 0x3a8 &&
                        image.function_starts.size == 8,
                    "LC_FUNCTION_STARTS range is preserved");
        meta_expect(image.data_in_code.present && image.data_in_code.offset == 0x3b0 && image.data_in_code.size == 8,
                    "LC_DATA_IN_CODE range is preserved");
    }

    // Each case changes one field of the valid image, so parsing must stop at that command with its own error.
    using Bytes = std::vector<std::byte>;
    const auto expect_error = [](auto mutate, m::ErrorCode expected, const std::string& label) {
        Bytes bytes = load_metadata_image();
        mutate(bytes);
        const auto result = m::parse(bytes);
        meta_expect(!result && result.error == expected,
                    label + " (got " + std::string(m::error_name(result.error)) + ")");
    };
    expect_error([](Bytes& b) { meta_put_u32(b, kMetaSymtab + 12, 0x100); }, m::ErrorCode::malformed_symbol_table,
                 "LC_SYMTAB symbol entries past the image are rejected");
    expect_error([](Bytes& b) { meta_put_u32(b, kMetaSymtab + 20, 0x100); }, m::ErrorCode::malformed_symbol_table,
                 "LC_SYMTAB string table past the image is rejected");
    expect_error([](Bytes& b) { meta_put_u32(b, kMetaDysymtab + 60, 0x40); },
                 m::ErrorCode::malformed_dynamic_symbol_table, "LC_DYSYMTAB indirect table past the image is rejected");
    expect_error([](Bytes& b) { meta_put_u32(b, kMetaBuild + 20, 2); }, m::ErrorCode::malformed_build_version,
                 "LC_BUILD_VERSION tool table past its command is rejected");
    expect_error([](Bytes& b) { meta_put_u32(b, kMetaSignature + 12, 0x100); }, m::ErrorCode::malformed_linkedit_data,
                 "LC_CODE_SIGNATURE range past the image is rejected");
    expect_error([](Bytes& b) { meta_put_u32(b, kMetaBuild, m::kLcUuid); }, m::ErrorCode::duplicate_load_command,
                 "a second LC_UUID is rejected");
    expect_error([](Bytes& b) { meta_put_u32(b, kMetaSignature, m::kLcSourceVersion); },
                 m::ErrorCode::duplicate_load_command, "a second LC_SOURCE_VERSION is rejected");
    expect_error([](Bytes& b) { meta_put_u32(b, kMetaDataInCode, m::kLcFunctionStarts); },
                 m::ErrorCode::duplicate_load_command, "a second LC_FUNCTION_STARTS is rejected");
    // The 16-byte LC_SOURCE_VERSION slot is smaller than each fixed-size command below.
    expect_error([](Bytes& b) { meta_put_u32(b, kMetaSource, m::kLcUuid); }, m::ErrorCode::malformed_uuid,
                 "a 16-byte LC_UUID is rejected");
    expect_error([](Bytes& b) { meta_put_u32(b, kMetaSource, m::kLcSymtab); }, m::ErrorCode::malformed_symbol_table,
                 "a 16-byte LC_SYMTAB is rejected");
    expect_error([](Bytes& b) { meta_put_u32(b, kMetaSource, m::kLcDysymtab); },
                 m::ErrorCode::malformed_dynamic_symbol_table, "a 16-byte LC_DYSYMTAB is rejected");
    expect_error([](Bytes& b) { meta_put_u32(b, kMetaSource, m::kLcBuildVersion); },
                 m::ErrorCode::malformed_build_version, "a 16-byte LC_BUILD_VERSION is rejected");

    // Ranges are summed in 64 bits, so offsets and counts near UINT32_MAX cannot wrap back inside the image.
    expect_error([](Bytes& b) { meta_put_u32(b, kMetaSymtab + 8, 0xfffffff0U); }, m::ErrorCode::malformed_symbol_table,
                 "LC_SYMTAB symoff wrapping 32 bits is rejected");
    expect_error([](Bytes& b) { meta_put_u32(b, kMetaSymtab + 16, 0xfffffff0U); }, m::ErrorCode::malformed_symbol_table,
                 "LC_SYMTAB stroff wrapping 32 bits is rejected");
    expect_error([](Bytes& b) { meta_put_u32(b, kMetaDysymtab + 56, 0xfffffffcU); },
                 m::ErrorCode::malformed_dynamic_symbol_table, "LC_DYSYMTAB indirectsymoff wrapping 32 bits is rejected");
    expect_error([](Bytes& b) { meta_put_u32(b, kMetaBuild + 20, 0x20000000U); }, m::ErrorCode::malformed_build_version,
                 "LC_BUILD_VERSION ntools whose table size wraps 32 bits is rejected");
    expect_error([](Bytes& b) { meta_put_u32(b, kMetaDataInCode + 8, 0xfffffffcU); },
                 m::ErrorCode::malformed_linkedit_data, "LC_DATA_IN_CODE dataoff wrapping 32 bits is rejected");
    expect_error([](Bytes& b) { meta_put_u32(b, kMetaDataInCode + 12, 0x100); }, m::ErrorCode::malformed_linkedit_data,
                 "LC_DATA_IN_CODE range past the image is rejected");
    // cmdsize values that still cover load_command but not the command's own fixed layout.
    expect_error([](Bytes& b) { meta_put_u32(b, kMetaUuid + 4, 16); }, m::ErrorCode::malformed_uuid,
                 "LC_UUID cmdsize below uuid_command is rejected");
    expect_error([](Bytes& b) { meta_put_u32(b, kMetaSource + 4, 8); }, m::ErrorCode::malformed_source_version,
                 "LC_SOURCE_VERSION cmdsize below source_version_command is rejected");
    expect_error([](Bytes& b) { meta_put_u32(b, kMetaDataInCode + 4, 8); }, m::ErrorCode::malformed_linkedit_data,
                 "LC_DATA_IN_CODE cmdsize below linkedit_data_command is rejected");
    expect_error([](Bytes& b) { meta_put_u32(b, kMetaDysymtab, m::kLcSymtab); }, m::ErrorCode::duplicate_load_command,
                 "a second LC_SYMTAB is rejected");
    expect_error([](Bytes& b) { meta_put_u32(b, kMetaStarts, m::kLcCodeSignature); }, m::ErrorCode::duplicate_load_command,
                 "a second LC_CODE_SIGNATURE is rejected");

    // LC_DYSYMTAB partitions index the LC_SYMTAB nlist array, so they need that table and must fit inside its
    // nsyms. The valid image already ends the undefined partition exactly at nsyms; LC_SYMSEG (0x3) is skipped.
    expect_error([](Bytes& b) { meta_put_u32(b, kMetaSymtab, 0x3U); },
                 m::ErrorCode::malformed_dynamic_symbol_table, "LC_DYSYMTAB without LC_SYMTAB is rejected");
    expect_error([](Bytes& b) { meta_put_u32(b, kMetaDysymtab + 12, 3); },
                 m::ErrorCode::malformed_dynamic_symbol_table, "LC_DYSYMTAB local symbols past nsyms are rejected");
    expect_error([](Bytes& b) { meta_put_u32(b, kMetaDysymtab + 28, 1); },
                 m::ErrorCode::malformed_dynamic_symbol_table, "LC_DYSYMTAB undefined symbols past nsyms are rejected");
    expect_error([](Bytes& b) { meta_put_u32(b, kMetaDysymtab + 16, 0xffffffffU); },
                 m::ErrorCode::malformed_dynamic_symbol_table, "LC_DYSYMTAB iextdefsym wrapping 32 bits is rejected");

    // The other LC_DYSYMTAB file tables hold 8-byte table-of-contents and relocation entries, 56-byte modules and
    // 4-byte external references. Each table below starts at offset 0 and each count is the smallest past 0x400.
    expect_error([](Bytes& b) { meta_put_u32(b, kMetaDysymtab + 36, 0x81); },
                 m::ErrorCode::malformed_dynamic_symbol_table, "LC_DYSYMTAB table of contents past the image is rejected");
    expect_error([](Bytes& b) { meta_put_u32(b, kMetaDysymtab + 44, 19); },
                 m::ErrorCode::malformed_dynamic_symbol_table, "LC_DYSYMTAB module table past the image is rejected");
    expect_error([](Bytes& b) { meta_put_u32(b, kMetaDysymtab + 52, 0x101); },
                 m::ErrorCode::malformed_dynamic_symbol_table, "LC_DYSYMTAB external refs past the image are rejected");
    expect_error([](Bytes& b) { meta_put_u32(b, kMetaDysymtab + 68, 0x81); },
                 m::ErrorCode::malformed_dynamic_symbol_table, "LC_DYSYMTAB external relocs past the image are rejected");
    expect_error([](Bytes& b) { meta_put_u32(b, kMetaDysymtab + 76, 0x81); },
                 m::ErrorCode::malformed_dynamic_symbol_table, "LC_DYSYMTAB local relocs past the image are rejected");
    // 0x20000000 eight-byte entries total exactly 2^32 bytes, which a 32-bit size would wrap to 0.
    expect_error([](Bytes& b) { meta_put_u32(b, kMetaDysymtab + 36, 0x20000000U); },
                 m::ErrorCode::malformed_dynamic_symbol_table, "LC_DYSYMTAB ntoc wrapping 32 bits is rejected");
    {
        // Tables that end exactly at the end of the file are still inside it.
        Bytes bytes = load_metadata_image();
        meta_put_u32(bytes, kMetaDysymtab + 36, 0x80);
        meta_put_u32(bytes, kMetaDysymtab + 40, 0x3c8);
        meta_put_u32(bytes, kMetaDysymtab + 44, 1);
        meta_put_u32(bytes, kMetaDysymtab + 52, 0x100);
        meta_put_u32(bytes, kMetaDysymtab + 68, 0x80);
        meta_put_u32(bytes, kMetaDysymtab + 76, 0x80);
        meta_expect(static_cast<bool>(m::parse(bytes)), "LC_DYSYMTAB file tables ending at the image end parse");
    }

    {
        // Zippered images carry one LC_BUILD_VERSION per platform, so only a repeated platform is a duplicate.
        Bytes bytes = load_metadata_image();
        meta_command(bytes, kMetaUuid, m::kLcBuildVersion, 24, 6, 0x000e0000U);
        meta_put_u32(bytes, kMetaUuid + 16, 0x000e0000U);
        meta_put_u32(bytes, kMetaUuid + 20, 0);
        const auto zippered = m::parse(bytes);
        meta_expect(static_cast<bool>(zippered) && !zippered.image.has_uuid &&
                        zippered.image.build_versions.size() == 2 && zippered.image.build_versions[0].platform == 6 &&
                        zippered.image.build_versions[0].tools.empty() &&
                        zippered.image.build_versions[1].platform == 1,
                    "LC_BUILD_VERSION accepts one command per platform");
        meta_put_u32(bytes, kMetaUuid + 8, 1);
        const auto repeated = m::parse(bytes);
        meta_expect(!repeated && repeated.error == m::ErrorCode::duplicate_load_command,
                    "LC_BUILD_VERSION repeating a platform is rejected (got " +
                        std::string(m::error_name(repeated.error)) + ")");
    }

    {
        // dyld requires each section_64 to keep [addr, addr + size) inside its segment's [vmaddr, vmaddr + vmsize)
        // and rejects a size with the sign bit set. Both sections of this __TEXT segment lie inside it and __const
        // ends exactly at vmaddr + vmsize. Each case below rewrites one section's addr and size.
        constexpr std::size_t kSegment = 32;
        constexpr std::size_t kText = kSegment + 72;
        constexpr std::size_t kConst = kText + 80;
        constexpr std::uint64_t kBase = 0x100000000ULL;
        const auto put_name = [](Bytes& bytes, std::size_t at, const std::string& name) {
            for (std::size_t i = 0; i < name.size(); ++i) {
                bytes.at(at + i) = static_cast<std::byte>(name[i]);
            }
        };
        const auto section_image = [&]() {
            Bytes bytes(0x400, std::byte{0});
            meta_put_u32(bytes, 0, m::kMhMagic64);
            meta_put_u32(bytes, 4, static_cast<std::uint32_t>(m::kCpuTypeArm64));
            meta_put_u32(bytes, 8, static_cast<std::uint32_t>(m::kCpuSubtypeArm64e));
            meta_put_u32(bytes, 12, m::kMhExecute);
            meta_put_u32(bytes, 16, 2U);
            meta_put_u32(bytes, 20, 72U + 2U * 80U + 24U);

            meta_command(bytes, kSegment, m::kLcSegment64, 72U + 2U * 80U, 0, 0);
            put_name(bytes, kSegment + 8, "__TEXT");
            meta_put_u64(bytes, kSegment + 24, kBase);
            meta_put_u64(bytes, kSegment + 32, 0x400ULL);
            meta_put_u64(bytes, kSegment + 48, 0x400ULL);
            meta_put_u32(bytes, kSegment + 56, 5);
            meta_put_u32(bytes, kSegment + 60, 5);
            meta_put_u32(bytes, kSegment + 64, 2);

            put_name(bytes, kText, "__text");
            put_name(bytes, kText + 16, "__TEXT");
            meta_put_u64(bytes, kText + 32, kBase + 0x100ULL);
            meta_put_u64(bytes, kText + 40, 0x100ULL);
            meta_put_u32(bytes, kText + 48, 0x100);
            meta_put_u32(bytes, kText + 52, 2);
            meta_put_u32(bytes, kText + 64, 0x80000400U); // S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS

            put_name(bytes, kConst, "__const");
            put_name(bytes, kConst + 16, "__TEXT");
            meta_put_u64(bytes, kConst + 32, kBase + 0x300ULL);
            meta_put_u64(bytes, kConst + 40, 0x100ULL);
            meta_put_u32(bytes, kConst + 48, 0x300);
            meta_put_u32(bytes, kConst + 52, 3);

            meta_command(bytes, kConst + 80, m::kLcMain, 24, 0x180, 0);
            return bytes;
        };

        const auto valid = m::parse(section_image());
        meta_expect(static_cast<bool>(valid) && valid.image.segments.size() == 1 &&
                        valid.image.segments[0].name == "__TEXT" && valid.image.segments[0].vm_size == 0x400ULL,
                    "section_64 table inside its segment parses (got " + std::string(m::error_name(valid.error)) + ")");
        const auto expect_section = [&](std::size_t section, std::uint64_t address, std::uint64_t size, bool accepted,
                                        const std::string& label) {
            Bytes bytes = section_image();
            meta_put_u64(bytes, section + 32, address);
            meta_put_u64(bytes, section + 40, size);
            const auto result = m::parse(bytes);
            meta_expect(accepted ? static_cast<bool>(result)
                                 : !result && result.error == m::ErrorCode::malformed_segment,
                        label + " (got " + std::string(m::error_name(result.error)) + ")");
        };
        expect_section(kConst, kBase + 0x400ULL, 0, true, "an empty section_64 at its segment end parses");
        expect_section(kText, kBase - 0x10ULL, 0x20ULL, false, "a section_64 starting before its segment is rejected");
        expect_section(kConst, kBase + 0x300ULL, 0x101ULL, false,
                       "a section_64 ending one byte past its segment is rejected");
        expect_section(kConst, kBase + 0x401ULL, 0, false, "an empty section_64 past its segment end is rejected");
        expect_section(kText, kBase + 0x100ULL, 0x8000000000000000ULL, false,
                       "a section_64 size with the sign bit set is rejected");
        // Summing addr + size here wraps to 0x100, so only a subtraction-based bound rejects this range.
        expect_section(kConst, 0xffffffffffffff00ULL, 0x200ULL, false,
                       "a section_64 whose addr + size wraps 64 bits is rejected");
    }

    {
        // dyld holds __TEXT to exactly r-x and __LINKEDIT to exactly r-- once an LC_BUILD_VERSION platform opts the
        // image into those format rules. Each case names the metadata image's only segment, sets its initprot and
        // rewrites the platform, minimum OS and SDK of its LC_BUILD_VERSION. maxprot is rwx, so only initprot varies.
        constexpr std::uint32_t kR = 0x1;
        constexpr std::uint32_t kRw = 0x3;
        constexpr std::uint32_t kRx = 0x5;
        constexpr std::uint32_t kRwx = 0x7;
        constexpr std::uint32_t kMacOs = 1;
        constexpr std::uint32_t kIos = 2;
        constexpr std::uint32_t kTvOs = 3;
        constexpr std::uint32_t kWatchOs = 4;
        constexpr std::uint32_t kMacCatalyst = 6;
        constexpr std::uint32_t kVisionOs = 11;
        constexpr std::uint32_t kMacOsSdk = 0x001b0100U;
        const std::string text_error = "__TEXT segment initprot is not r-x";
        const std::string linkedit_error = "__LINKEDIT segment initprot is not r--";
        const auto protection_image = [](const std::string& name, std::uint32_t initial_protection,
                                         std::uint32_t platform, std::uint32_t sdk) {
            Bytes bytes = load_metadata_image();
            for (std::size_t i = 0; i < name.size(); ++i) {
                bytes.at(32 + 8 + i) = static_cast<std::byte>(name[i]);
            }
            meta_put_u32(bytes, 32 + 56, 0x7U);
            meta_put_u32(bytes, 32 + 60, initial_protection);
            meta_put_u32(bytes, kMetaBuild + 8, platform);
            meta_put_u32(bytes, kMetaBuild + 12, sdk);
            meta_put_u32(bytes, kMetaBuild + 16, sdk);
            return bytes;
        };
        const auto expect_protection = [](const Bytes& bytes, const std::string& error, const std::string& label) {
            const auto result = m::parse(bytes);
            const bool matched = error.empty() ? static_cast<bool>(result)
                                               : (!result && result.error == m::ErrorCode::malformed_segment &&
                                                  result.message == error);
            meta_expect(matched, label + " (got " + std::string(m::error_name(result.error)) + ")");
        };

        // macOS opts in to both rules from the 10.15 SDK, so the metadata image's macOS 27.1 SDK applies them.
        expect_protection(protection_image("__TEXT", kRx, kMacOs, kMacOsSdk), "",
                          "macOS 27 SDK __TEXT r-x parses");
        expect_protection(protection_image("__TEXT", kRwx, kMacOs, kMacOsSdk), text_error,
                          "macOS 27 SDK __TEXT rwx is rejected");
        // 0xd adds a bit past VM_PROT_EXECUTE that the invalid-bits test skips for __TEXT; the exact rule rejects it.
        expect_protection(protection_image("__TEXT", 0xdU, kMacOs, kMacOsSdk), text_error,
                          "macOS 27 SDK __TEXT r-x plus an invalid bit is rejected");
        expect_protection(protection_image("__LINKEDIT", kR, kMacOs, kMacOsSdk), "",
                          "macOS 27 SDK __LINKEDIT r-- parses");
        expect_protection(protection_image("__LINKEDIT", kRw, kMacOs, kMacOsSdk), linkedit_error,
                          "macOS 27 SDK __LINKEDIT rw- is rejected");
        expect_protection(protection_image("__LINKEDIT", 0x9U, kMacOs, kMacOsSdk), linkedit_error,
                          "macOS 27 SDK __LINKEDIT r-- plus an invalid bit is rejected");
        // Only the exact segment names are held to these protections.
        expect_protection(protection_image("__DATA", kRwx, kMacOs, kMacOsSdk), "",
                          "macOS 27 SDK __DATA rwx parses");
        expect_protection(protection_image("__TEXT_EXEC", kRwx, kMacOs, kMacOsSdk), "",
                          "macOS 27 SDK __TEXT_EXEC rwx parses");

        // Older macOS SDKs skip both rules.
        expect_protection(protection_image("__TEXT", kRwx, kMacOs, 0x000a0e00U), "",
                          "macOS 10.14 SDK __TEXT rwx parses");
        expect_protection(protection_image("__LINKEDIT", kRw, kMacOs, 0x000a0e00U), "",
                          "macOS 10.14 SDK __LINKEDIT rw- parses");
        expect_protection(protection_image("__TEXT", kRwx, kMacOs, 0x000a0f00U), text_error,
                          "macOS 10.15 SDK __TEXT rwx is rejected");
        expect_protection(protection_image("__LINKEDIT", kRw, kMacOs, 0x000a0f00U), linkedit_error,
                          "macOS 10.15 SDK __LINKEDIT rw- is rejected");
        // iOS and tvOS always hold __TEXT to r-x, and hold __LINKEDIT to r-- from the 13 SDK.
        expect_protection(protection_image("__TEXT", kRwx, kIos, 0x000c0000U), text_error,
                          "iOS 12 SDK __TEXT rwx is rejected");
        expect_protection(protection_image("__LINKEDIT", kRw, kIos, 0x000c0000U), "",
                          "iOS 12 SDK __LINKEDIT rw- parses");
        expect_protection(protection_image("__LINKEDIT", kRw, kIos, 0x000d0000U), linkedit_error,
                          "iOS 13 SDK __LINKEDIT rw- is rejected");
        expect_protection(protection_image("__TEXT", kRwx, kTvOs, 0x000c0000U), text_error,
                          "tvOS 12 SDK __TEXT rwx is rejected");
        expect_protection(protection_image("__LINKEDIT", kRw, kTvOs, 0x000c0000U), "",
                          "tvOS 12 SDK __LINKEDIT rw- parses");
        expect_protection(protection_image("__LINKEDIT", kRw, kTvOs, 0x000d0000U), linkedit_error,
                          "tvOS 13 SDK __LINKEDIT rw- is rejected");
        // watchOS always holds __TEXT to r-x, and holds __LINKEDIT to r-- from the 9 SDK.
        expect_protection(protection_image("__TEXT", kRwx, kWatchOs, 0x00080000U), text_error,
                          "watchOS 8 SDK __TEXT rwx is rejected");
        expect_protection(protection_image("__LINKEDIT", kRw, kWatchOs, 0x00080000U), "",
                          "watchOS 8 SDK __LINKEDIT rw- parses");
        expect_protection(protection_image("__LINKEDIT", kRw, kWatchOs, 0x00090000U), linkedit_error,
                          "watchOS 9 SDK __LINKEDIT rw- is rejected");
        // Any other nonzero platform applies both rules, while platform 0 carries no platform information.
        expect_protection(protection_image("__TEXT", kRwx, kVisionOs, 0x00010000U), text_error,
                          "visionOS 1 SDK __TEXT rwx is rejected");
        expect_protection(protection_image("__LINKEDIT", kRw, kVisionOs, 0x00010000U), linkedit_error,
                          "visionOS 1 SDK __LINKEDIT rw- is rejected");
        expect_protection(protection_image("__TEXT", kRwx, 0U, kMacOsSdk), "",
                          "platform 0 __TEXT rwx parses");
        expect_protection(protection_image("__LINKEDIT", kRw, 0U, kMacOsSdk), "",
                          "platform 0 __LINKEDIT rw- parses");
        {
            // Without LC_BUILD_VERSION neither rule applies. LC_SYMSEG (0x3) replaces that command and is skipped.
            Bytes text = protection_image("__TEXT", kRwx, kMacOs, kMacOsSdk);
            meta_put_u32(text, kMetaBuild, 0x3U);
            expect_protection(text, "", "__TEXT rwx without LC_BUILD_VERSION parses");
            Bytes linkedit = protection_image("__LINKEDIT", kRw, kMacOs, kMacOsSdk);
            meta_put_u32(linkedit, kMetaBuild, 0x3U);
            expect_protection(linkedit, "", "__LINKEDIT rw- without LC_BUILD_VERSION parses");
        }

        // A zippered image carries one LC_BUILD_VERSION per platform, and either one opting in applies a rule. The
        // first command replaces LC_UUID, ahead of the metadata image's own LC_BUILD_VERSION.
        const auto zippered = [&](const std::string& name, std::uint32_t initial_protection, std::uint32_t first,
                                  std::uint32_t first_sdk, std::uint32_t second, std::uint32_t second_sdk) {
            Bytes bytes = protection_image(name, initial_protection, second, second_sdk);
            meta_command(bytes, kMetaUuid, m::kLcBuildVersion, 24, first, first_sdk);
            meta_put_u32(bytes, kMetaUuid + 16, first_sdk);
            meta_put_u32(bytes, kMetaUuid + 20, 0);
            return bytes;
        };
        expect_protection(zippered("__TEXT", kRwx, kMacCatalyst, 0x000d0000U, kMacOs, 0x000a0e00U), text_error,
                          "zippered Catalyst 13 and macOS 10.14 SDKs reject __TEXT rwx");
        expect_protection(zippered("__LINKEDIT", kRw, kMacCatalyst, 0x000d0000U, kMacOs, 0x000a0e00U),
                          linkedit_error, "zippered Catalyst 13 and macOS 10.14 SDKs reject __LINKEDIT rw-");
        expect_protection(zippered("__LINKEDIT", kRw, kMacOs, kMacOsSdk, kMacCatalyst, 0x000c0000U), linkedit_error,
                          "a later Catalyst 12 SDK keeps the macOS 27 SDK __LINKEDIT rule");
        expect_protection(zippered("__TEXT", kRwx, kMacOs, 0x000a0e00U, kMacCatalyst, 0x000c0000U), text_error,
                          "zippered macOS 10.14 and Catalyst 12 SDKs reject __TEXT rwx");
        expect_protection(zippered("__LINKEDIT", kRw, kMacOs, 0x000a0e00U, kMacCatalyst, 0x000c0000U), "",
                          "zippered macOS 10.14 and Catalyst 12 SDKs accept __LINKEDIT rw-");
    }

    if (meta_failures != 0) {
        std::cerr << meta_failures << " Mach-O load-command metadata test(s) failed\n";
        return EXIT_FAILURE;
    }

    std::cout << "Mach-O load-command metadata tests passed\n";
    return EXIT_SUCCESS;
}
