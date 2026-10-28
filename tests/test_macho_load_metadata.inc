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

    if (meta_failures != 0) {
        std::cerr << meta_failures << " Mach-O load-command metadata test(s) failed\n";
        return EXIT_FAILURE;
    }

    std::cout << "Mach-O load-command metadata tests passed\n";
    return EXIT_SUCCESS;
}
