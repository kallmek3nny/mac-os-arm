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

        // On ARM64 each LC_VERSION_MIN_* names its device platform and opts the image in like an LC_BUILD_VERSION
        // naming that platform. Each case skips the metadata image's LC_BUILD_VERSION as LC_SYMSEG (0x3) and writes
        // one 16-byte version_min_command (cmd, cmdsize, version, sdk) over its LC_SOURCE_VERSION.
        const auto version_min_image = [&](const std::string& name, std::uint32_t initial_protection,
                                           std::uint32_t command, std::uint32_t version, std::uint32_t sdk) {
            Bytes bytes = protection_image(name, initial_protection, kMacOs, kMacOsSdk);
            meta_put_u32(bytes, kMetaBuild, 0x3U);
            meta_command(bytes, kMetaSource, command, 16, version, sdk);
            return bytes;
        };
        {
            const auto parsed = m::parse(version_min_image("__TEXT", kRx, m::kLcVersionMinIphoneos, 0x000c0100U,
                                                           0x000d0200U));
            const auto& mins = parsed.image.version_mins;
            meta_expect(static_cast<bool>(parsed) && parsed.image.build_versions.empty() &&
                            !parsed.image.has_source_version && mins.size() == 1 &&
                            mins[0].command == m::kLcVersionMinIphoneos && mins[0].version == 0x000c0100U &&
                            mins[0].sdk == 0x000d0200U,
                        "LC_VERSION_MIN_IPHONEOS command, version and sdk are preserved (got " +
                            std::string(m::error_name(parsed.error)) + ")");

            // A second LC_VERSION_MIN_* over LC_FUNCTION_STARTS may name another platform, but dyld's
            // PlatformAndVersions::zip joins a platform only with itself or macOS with Mac Catalyst, which no
            // LC_VERSION_MIN_* names. Two of them naming distinct platforms are incompatible in either order.
            const auto expect_incompatible = [](const Bytes& bytes, const std::string& label) {
                const auto result = m::parse(bytes);
                meta_expect(!result && result.error == m::ErrorCode::incompatible_platforms,
                            label + " (got " + std::string(m::error_name(result.error)) + ")");
            };
            Bytes pair = version_min_image("__TEXT", kRx, m::kLcVersionMinIphoneos, 0x000c0000U, 0x000d0000U);
            meta_command(pair, kMetaStarts, m::kLcVersionMinMacosx, 16, 0x000a0e00U, 0U);
            expect_incompatible(pair, "LC_VERSION_MIN_IPHONEOS then LC_VERSION_MIN_MACOSX is rejected");
            Bytes reversed = version_min_image("__TEXT", kRx, m::kLcVersionMinMacosx, 0x000a0e00U, 0U);
            meta_command(reversed, kMetaStarts, m::kLcVersionMinIphoneos, 16, 0x000c0000U, 0x000d0000U);
            expect_incompatible(reversed, "LC_VERSION_MIN_MACOSX then LC_VERSION_MIN_IPHONEOS is rejected");

            // LC_BUILD_VERSION pairs follow the same rule, so Mac Catalyst fails beside any platform but macOS. The
            // platform check runs before the format rules, so __TEXT rwx, which the iOS rule also rejects, still
            // reports the incompatible pair.
            expect_incompatible(zippered("__TEXT", kRx, kIos, 0x000d0000U, kMacOs, kMacOsSdk),
                                "LC_BUILD_VERSION iOS with macOS is rejected");
            expect_incompatible(zippered("__TEXT", kRx, kTvOs, 0x000d0000U, kIos, 0x000d0000U),
                                "LC_BUILD_VERSION tvOS with iOS is rejected");
            expect_incompatible(zippered("__TEXT", kRx, kMacCatalyst, 0x000d0000U, kVisionOs, 0x00010000U),
                                "LC_BUILD_VERSION Mac Catalyst with visionOS is rejected");
            expect_incompatible(zippered("__TEXT", kRwx, kIos, 0x000d0000U, kMacOs, kMacOsSdk),
                                "an incompatible LC_BUILD_VERSION pair is reported before the __TEXT rule");

            // Repeating a platform fails earlier, while the load commands are still being parsed.
            meta_put_u32(pair, kMetaStarts, m::kLcVersionMinIphoneos);
            const auto repeated = m::parse(pair);
            meta_expect(!repeated && repeated.error == m::ErrorCode::duplicate_load_command,
                        "a second LC_VERSION_MIN_IPHONEOS is rejected (got " +
                            std::string(m::error_name(repeated.error)) + ")");

            // cmdsize 8 still covers load_command but not the version and sdk fields.
            Bytes truncated = version_min_image("__TEXT", kRx, m::kLcVersionMinWatchos, 0x00080000U, 0x00090000U);
            meta_put_u32(truncated, kMetaSource + 4, 8);
            const auto short_command = m::parse(truncated);
            meta_expect(!short_command && short_command.error == m::ErrorCode::malformed_version_min,
                        "LC_VERSION_MIN_* cmdsize below version_min_command is rejected (got " +
                            std::string(m::error_name(short_command.error)) + ")");

            // dyld requires cmdsize == sizeof(version_min_command), so a 32-byte command whose extra bytes cover the
            // next load-command slot is rejected while the parser is still on the version_min_command.
            Bytes oversized = version_min_image("__TEXT", kRx, m::kLcVersionMinWatchos, 0x00080000U, 0x00090000U);
            meta_put_u32(oversized, kMetaSource + 4, 32);
            const auto long_command = m::parse(oversized);
            meta_expect(!long_command && long_command.error == m::ErrorCode::malformed_version_min,
                        "LC_VERSION_MIN_* cmdsize above version_min_command is rejected (got " +
                            std::string(m::error_name(long_command.error)) + ")");
        }

        // An old LC_VERSION_MIN_MACOSX with sdk 0 predates that field, so its minimum OS stands in for the SDK.
        expect_protection(version_min_image("__TEXT", kRwx, m::kLcVersionMinMacosx, 0x000a0e00U, 0x000a0f00U),
                          text_error, "LC_VERSION_MIN_MACOSX 10.15 SDK __TEXT rwx is rejected");
        expect_protection(version_min_image("__LINKEDIT", kRw, m::kLcVersionMinMacosx, 0x000a0e00U, 0x000a0f00U),
                          linkedit_error, "LC_VERSION_MIN_MACOSX 10.15 SDK __LINKEDIT rw- is rejected");
        expect_protection(version_min_image("__TEXT", kRwx, m::kLcVersionMinMacosx, 0x000a0e00U, 0x000a0e00U), "",
                          "LC_VERSION_MIN_MACOSX 10.14 SDK __TEXT rwx parses");
        expect_protection(version_min_image("__TEXT", kRwx, m::kLcVersionMinMacosx, 0x000a0f00U, 0U), text_error,
                          "LC_VERSION_MIN_MACOSX 10.15 minimum OS without an SDK rejects __TEXT rwx");
        expect_protection(version_min_image("__LINKEDIT", kRw, m::kLcVersionMinMacosx, 0x000a0e00U, 0U), "",
                          "LC_VERSION_MIN_MACOSX 10.14 minimum OS without an SDK accepts __LINKEDIT rw-");
        // iOS, tvOS and watchOS keep the LC_BUILD_VERSION thresholds above.
        expect_protection(version_min_image("__TEXT", kRwx, m::kLcVersionMinIphoneos, 0x000c0000U, 0x000c0000U),
                          text_error, "LC_VERSION_MIN_IPHONEOS 12 SDK __TEXT rwx is rejected");
        expect_protection(version_min_image("__LINKEDIT", kRw, m::kLcVersionMinIphoneos, 0x000c0000U, 0x000c0000U),
                          "", "LC_VERSION_MIN_IPHONEOS 12 SDK __LINKEDIT rw- parses");
        expect_protection(version_min_image("__LINKEDIT", kRw, m::kLcVersionMinIphoneos, 0x000c0000U, 0x000d0000U),
                          linkedit_error, "LC_VERSION_MIN_IPHONEOS 13 SDK __LINKEDIT rw- is rejected");
        expect_protection(version_min_image("__TEXT", kRwx, m::kLcVersionMinTvos, 0x000c0000U, 0x000c0000U),
                          text_error, "LC_VERSION_MIN_TVOS 12 SDK __TEXT rwx is rejected");
        expect_protection(version_min_image("__LINKEDIT", kRw, m::kLcVersionMinTvos, 0x000c0000U, 0x000d0000U),
                          linkedit_error, "LC_VERSION_MIN_TVOS 13 SDK __LINKEDIT rw- is rejected");
        expect_protection(version_min_image("__TEXT", kRwx, m::kLcVersionMinWatchos, 0x00080000U, 0x00080000U),
                          text_error, "LC_VERSION_MIN_WATCHOS 8 SDK __TEXT rwx is rejected");
        expect_protection(version_min_image("__LINKEDIT", kRw, m::kLcVersionMinWatchos, 0x00080000U, 0x00080000U),
                          "", "LC_VERSION_MIN_WATCHOS 8 SDK __LINKEDIT rw- parses");
        expect_protection(version_min_image("__LINKEDIT", kRw, m::kLcVersionMinWatchos, 0x00080000U, 0x00090000U),
                          linkedit_error, "LC_VERSION_MIN_WATCHOS 9 SDK __LINKEDIT rw- is rejected");
    }

    // LC_DYLD_INFO and LC_DYLD_INFO_ONLY carry one 48-byte dyld_info_command: cmd, cmdsize and the (offset, size)
    // pairs of the rebase, bind, weak-bind and lazy-bind opcode streams and the export trie. Each layout writes it
    // over 48 bytes of existing commands, so sizeofcmds stays 320 and only ncmds changes. The streams sit in
    // 0x3c0-0x400, which the replaced LC_CODE_SIGNATURE no longer claims, and the export trie ends exactly at the
    // end of the image. The zero-size weak-bind stream keeps an offset past the image because dyld never walks an
    // empty stream.
    {
        const auto put_dyld_info = [](Bytes& b, std::size_t at, std::uint32_t command) {
            constexpr std::uint32_t streams[10] = {0x3c0, 8, 0x3c8, 0x10, 0xfffffff0U, 0, 0x3d8, 8, 0x3e0, 0x20};
            meta_put_u32(b, at, command);
            meta_put_u32(b, at + 4, 48);
            for (std::size_t i = 0; i < 10; ++i) {
                meta_put_u32(b, at + 8 + i * 4, streams[i]);
            }
        };
        // One command over LC_SOURCE_VERSION, LC_CODE_SIGNATURE and LC_FUNCTION_STARTS leaves eight load commands.
        const auto dyld_info_image = [&](std::uint32_t command) {
            Bytes b = load_metadata_image();
            meta_put_u32(b, 16, 8U);
            put_dyld_info(b, kMetaSource, command);
            return b;
        };
        const auto range_is = [](const m::FileRange& range, std::uint64_t offset, std::uint64_t size, bool present) {
            return range.offset == offset && range.size == size && range.present == present;
        };

        meta_expect(!m::parse(load_metadata_image()).image.dyld_info.present,
                    "an image without LC_DYLD_INFO reports no dyld info");
        {
            const auto parsed = m::parse(dyld_info_image(m::kLcDyldInfoOnly));
            const auto& info = parsed.image.dyld_info;
            meta_expect(static_cast<bool>(parsed) && info.present && info.command == m::kLcDyldInfoOnly &&
                            range_is(info.rebase, 0x3c0, 8, true) && range_is(info.bind, 0x3c8, 0x10, true) &&
                            range_is(info.lazy_bind, 0x3d8, 8, true) &&
                            range_is(info.export_trie, 0x3e0, 0x20, true),
                        "LC_DYLD_INFO_ONLY command and stream ranges are preserved (got " +
                            std::string(m::error_name(parsed.error)) + ")");
            meta_expect(range_is(info.weak_bind, 0xfffffff0U, 0, false),
                        "a zero-size LC_DYLD_INFO stream keeps its raw offset and is not present");
        }
        {
            const auto plain = m::parse(dyld_info_image(m::kLcDyldInfo));
            meta_expect(static_cast<bool>(plain) && plain.image.dyld_info.present &&
                            plain.image.dyld_info.command == m::kLcDyldInfo,
                        "LC_DYLD_INFO parses and stays distinct from LC_DYLD_INFO_ONLY (got " +
                            std::string(m::error_name(plain.error)) + ")");
        }

        // Each case mutates the LC_DYLD_INFO_ONLY layout and must stop with that rule's own error and message.
        const auto expect_rejected = [&](auto mutate, m::ErrorCode expected, const std::string& message,
                                         const std::string& label) {
            Bytes bytes = dyld_info_image(m::kLcDyldInfoOnly);
            mutate(bytes);
            const auto result = m::parse(bytes);
            const std::string reported(result.message);
            meta_expect(!result && result.error == expected && reported.find(message) != std::string::npos,
                        label + " (got " + std::string(m::error_name(result.error)) + ": " + reported + ")");
        };
        const auto malformed = m::ErrorCode::malformed_linkedit_data;
        const std::string size_error = "LC_DYLD_INFO cmdsize is not 48";
        const std::string range_error = "LC_DYLD_INFO stream range exceeds image size";
        const std::string both_error = "image contains both LC_DYLD_INFO_ONLY and LC_DYLD_CHAINED_FIXUPS";

        // dyld requires cmdsize == sizeof(dyld_info_command); both wrong sizes still end inside sizeofcmds.
        expect_rejected([](Bytes& b) { meta_put_u32(b, kMetaSource + 4, 40); }, malformed, size_error,
                        "LC_DYLD_INFO cmdsize below dyld_info_command is rejected");
        expect_rejected([](Bytes& b) { meta_put_u32(b, kMetaSource + 4, 56); }, malformed, size_error,
                        "LC_DYLD_INFO cmdsize above dyld_info_command is rejected");

        // The pairs follow cmd and cmdsize: rebase at +8, bind +16, weak bind +24, lazy bind +32, export trie +40.
        expect_rejected([](Bytes& b) { meta_put_u32(b, kMetaSource + 20, 0x100); }, malformed, range_error,
                        "LC_DYLD_INFO bind stream past the image is rejected");
        expect_rejected([](Bytes& b) { meta_put_u32(b, kMetaSource + 44, 0x21); }, malformed, range_error,
                        "LC_DYLD_INFO export trie one byte past the image is rejected");
        expect_rejected([](Bytes& b) { meta_put_u32(b, kMetaSource + 8, 0xfffffff8U); }, malformed, range_error,
                        "LC_DYLD_INFO rebase offset wrapping 32 bits is rejected");
        expect_rejected([](Bytes& b) { meta_put_u32(b, kMetaSource + 28, 1); }, malformed, range_error,
                        "a nonzero LC_DYLD_INFO weak-bind stream at its raw offset past the image is rejected");

        // Two commands over LC_BUILD_VERSION through LC_DATA_IN_CODE leave seven load commands.
        expect_rejected(
            [&](Bytes& b) {
                meta_put_u32(b, 16, 7U);
                put_dyld_info(b, kMetaBuild, m::kLcDyldInfo);
                put_dyld_info(b, kMetaSignature, m::kLcDyldInfoOnly);
            },
            m::ErrorCode::duplicate_load_command, "multiple LC_DYLD_INFO commands",
            "LC_DYLD_INFO then LC_DYLD_INFO_ONLY is rejected as a duplicate");

        // LC_DYLD_INFO_ONLY opcodes beside LC_DYLD_CHAINED_FIXUPS encode the fixups twice, whichever command
        // comes first and even when every opcode stream is empty. The chained-fixups payload reuses the
        // LC_DATA_IN_CODE range.
        const auto add_fixups = [](Bytes& b) {
            meta_command(b, kMetaDataInCode, m::kLcDyldChainedFixups, 16, 0x3b0, 8);
        };
        expect_rejected(add_fixups, malformed, both_error,
                        "LC_DYLD_INFO_ONLY then LC_DYLD_CHAINED_FIXUPS is rejected");
        // LC_DYLD_CHAINED_FIXUPS over LC_SOURCE_VERSION, then LC_DYLD_INFO_ONLY over the three commands after it.
        expect_rejected(
            [&](Bytes& b) {
                meta_command(b, kMetaSource, m::kLcDyldChainedFixups, 16, 0x3b0, 8);
                put_dyld_info(b, kMetaSignature, m::kLcDyldInfoOnly);
            },
            malformed, both_error, "LC_DYLD_CHAINED_FIXUPS then LC_DYLD_INFO_ONLY is rejected");
        expect_rejected(
            [&](Bytes& b) {
                add_fixups(b);
                for (std::size_t field = 12; field < 48; field += 8) {
                    meta_put_u32(b, kMetaSource + field, 0);
                }
            },
            malformed, both_error, "LC_DYLD_INFO_ONLY with only empty streams beside chained fixups is rejected");

        // dyld's check counts only LC_DYLD_INFO_ONLY, so a plain LC_DYLD_INFO may sit beside chained fixups.
        {
            Bytes legacy = dyld_info_image(m::kLcDyldInfo);
            add_fixups(legacy);
            const auto beside = m::parse(legacy);
            meta_expect(static_cast<bool>(beside) && beside.image.dyld_info.command == m::kLcDyldInfo &&
                            range_is(beside.image.chained_fixups, 0x3b0, 8, true),
                        "LC_DYLD_INFO beside LC_DYLD_CHAINED_FIXUPS parses (got " +
                            std::string(m::error_name(beside.error)) + ")");
        }
    }

    if (meta_failures != 0) {
        std::cerr << meta_failures << " Mach-O load-command metadata test(s) failed\n";
        return EXIT_FAILURE;
    }

    std::cout << "Mach-O load-command metadata tests passed\n";
    return EXIT_SUCCESS;
}
