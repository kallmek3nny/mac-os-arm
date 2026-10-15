#include "macosarm/macho_initializers.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

namespace {

int init_failures = 0;

void init_expect(bool condition, const std::string& label) {
    if (!condition) {
        std::cerr << "FAIL: " << label << '\n';
        ++init_failures;
    }
}

void init_put_u32(std::vector<std::byte>& bytes, std::size_t offset, std::uint32_t value) {
    for (std::size_t i = 0; i < 4; ++i) {
        bytes.at(offset + i) = static_cast<std::byte>((value >> (i * 8U)) & 0xffU);
    }
}

void init_put_u64(std::vector<std::byte>& bytes, std::size_t offset, std::uint64_t value) {
    for (std::size_t i = 0; i < 8; ++i) {
        bytes.at(offset + i) = static_cast<std::byte>((value >> (i * 8U)) & 0xffU);
    }
}

void init_put_name(std::vector<std::byte>& bytes, std::size_t offset, const std::string& name) {
    for (std::size_t i = 0; i < name.size() && i < 16; ++i) {
        bytes.at(offset + i) = static_cast<std::byte>(static_cast<unsigned char>(name[i]));
    }
}

std::vector<std::byte> initializer_image() {
    constexpr std::uint32_t segment_command_size = 72U + 80U;
    constexpr std::uint32_t routines_command_size = 72U;
    constexpr std::uint32_t command_bytes = segment_command_size + routines_command_size;
    std::vector<std::byte> bytes(0x400, std::byte{0});

    init_put_u32(bytes, 0, macosarm::macho::kMhMagic64);
    init_put_u32(bytes, 4, static_cast<std::uint32_t>(macosarm::macho::kCpuTypeArm64));
    init_put_u32(bytes, 8, static_cast<std::uint32_t>(macosarm::macho::kCpuSubtypeArm64e));
    init_put_u32(bytes, 12, macosarm::macho::kMhDylib);
    init_put_u32(bytes, 16, 2);
    init_put_u32(bytes, 20, command_bytes);

    constexpr std::size_t segment = 32;
    init_put_u32(bytes, segment, macosarm::macho::kLcSegment64);
    init_put_u32(bytes, segment + 4, segment_command_size);
    init_put_name(bytes, segment + 8, "__DATA_CONST");
    init_put_u64(bytes, segment + 24, 0x100000000ULL);
    init_put_u64(bytes, segment + 32, 0x400ULL);
    init_put_u64(bytes, segment + 40, 0);
    init_put_u64(bytes, segment + 48, 0x400ULL);
    init_put_u32(bytes, segment + 56, 3);
    init_put_u32(bytes, segment + 60, 3);
    init_put_u32(bytes, segment + 64, 1);

    constexpr std::size_t section = segment + 72;
    init_put_name(bytes, section, "__mod_init_func");
    init_put_name(bytes, section + 16, "__DATA_CONST");
    init_put_u64(bytes, section + 32, 0x100000200ULL);
    init_put_u64(bytes, section + 40, 16);
    init_put_u32(bytes, section + 48, 0x200);
    init_put_u32(bytes, section + 52, 3);
    init_put_u32(bytes, section + 64, macosarm::macho::kSModInitFuncPointers);

    constexpr std::size_t routines = segment + segment_command_size;
    init_put_u32(bytes, routines, macosarm::macho::kLcRoutines64);
    init_put_u32(bytes, routines + 4, routines_command_size);
    init_put_u64(bytes, routines + 8, 0x100000180ULL);
    init_put_u64(bytes, routines + 16, 0x1234ULL);

    return bytes;
}

} // namespace

int macho_initializers_main() {
    using macosarm::macho::InitializerMetadataError;

    {
        const auto result = macosarm::macho::parse_initializer_metadata(initializer_image());
        init_expect(static_cast<bool>(result), "initializer metadata parses");
        init_expect(result.metadata.pointer_sections.size() == 1,
                    "one S_MOD_INIT_FUNC_POINTERS section is recorded");
        if (!result.metadata.pointer_sections.empty()) {
            const auto& section = result.metadata.pointer_sections.front();
            init_expect(section.segment_name == "__DATA_CONST", "initializer segment name is preserved");
            init_expect(section.section_name == "__mod_init_func", "initializer section name is preserved");
            init_expect(section.address == 0x100000200ULL, "initializer section VM address is preserved");
            init_expect(section.size == 16, "initializer section size is preserved");
            init_expect(section.file_offset == 0x200, "initializer section file offset is preserved");
            init_expect(section.pointer_count() == 2, "initializer pointer count is derived safely");
        }
        init_expect(result.metadata.routines.present, "LC_ROUTINES_64 is recorded");
        init_expect(result.metadata.routines.address == 0x100000180ULL,
                    "LC_ROUTINES_64 init address is preserved");
        init_expect(result.metadata.routines.module == 0x1234ULL,
                    "LC_ROUTINES_64 init module is preserved");
    }

    {
        std::vector<std::byte> bytes(32, std::byte{0});
        init_put_u32(bytes, 0, macosarm::macho::kMhMagic64);
        const auto result = macosarm::macho::parse_initializer_metadata(bytes);
        init_expect(static_cast<bool>(result), "image without initializer commands parses");
        init_expect(result.metadata.pointer_sections.empty(), "no synthetic initializer section is invented");
        init_expect(!result.metadata.routines.present, "no synthetic LC_ROUTINES_64 is invented");
    }

    {
        auto bytes = initializer_image();
        init_put_u64(bytes, 32 + 72 + 40, 10);
        const auto result = macosarm::macho::parse_initializer_metadata(bytes);
        init_expect(result.error == InitializerMetadataError::malformed_initializer_section,
                    "non-pointer-aligned initializer section size is rejected");
    }

    {
        auto bytes = initializer_image();
        init_put_u64(bytes, 32 + 72 + 32, 0x1000003f8ULL);
        const auto result = macosarm::macho::parse_initializer_metadata(bytes);
        init_expect(result.error == InitializerMetadataError::malformed_initializer_section,
                    "initializer section escaping segment VM range is rejected");
    }

    {
        auto bytes = initializer_image();
        init_put_u32(bytes, 32 + 72 + 48, 0x3f8);
        const auto result = macosarm::macho::parse_initializer_metadata(bytes);
        init_expect(result.error == InitializerMetadataError::malformed_initializer_section,
                    "initializer section escaping segment file range is rejected");
    }

    {
        auto bytes = initializer_image();
        init_put_u32(bytes, 32 + 4, 72);
        const auto result = macosarm::macho::parse_initializer_metadata(bytes);
        init_expect(result.error == InitializerMetadataError::malformed_segment,
                    "segment command that cannot contain its section table is rejected");
    }

    {
        auto bytes = initializer_image();
        constexpr std::size_t routines = 32 + 152;
        init_put_u32(bytes, routines + 4, 16);
        const auto result = macosarm::macho::parse_initializer_metadata(bytes);
        init_expect(result.error == InitializerMetadataError::malformed_routines,
                    "undersized LC_ROUTINES_64 is rejected");
    }

    {
        auto bytes = initializer_image();
        bytes.resize(0x500, std::byte{0});
        init_put_u32(bytes, 16, 3);
        init_put_u32(bytes, 20, 152 + 72 + 72);
        constexpr std::size_t duplicate = 32 + 152 + 72;
        init_put_u32(bytes, duplicate, macosarm::macho::kLcRoutines64);
        init_put_u32(bytes, duplicate + 4, 72);
        init_put_u64(bytes, duplicate + 8, 0x1000001c0ULL);
        const auto result = macosarm::macho::parse_initializer_metadata(bytes);
        init_expect(result.error == InitializerMetadataError::duplicate_routines,
                    "duplicate LC_ROUTINES_64 is rejected explicitly");
    }

    {
        auto bytes = initializer_image();
        init_put_u32(bytes, 20, 0xfffffff0U);
        const auto result = macosarm::macho::parse_initializer_metadata(bytes);
        init_expect(result.error == InitializerMetadataError::malformed_load_commands,
                    "oversized initializer load-command region is rejected");
    }

    {
        auto bytes = initializer_image();
        init_put_u32(bytes, 0, 0xfeedfaceU);
        const auto result = macosarm::macho::parse_initializer_metadata(bytes);
        init_expect(result.error == InitializerMetadataError::invalid_image,
                    "non-64-bit Mach-O initializer metadata is rejected");
    }

    init_expect(macosarm::macho::initializer_metadata_error_name(
                    InitializerMetadataError::malformed_initializer_section) ==
                    "malformed_initializer_section",
                "initializer metadata errors have stable names");

    if (init_failures != 0) {
        std::cerr << init_failures << " Mach-O initializer metadata test(s) failed\n";
        return EXIT_FAILURE;
    }

    std::cout << "Mach-O initializer metadata tests passed\n";
    return EXIT_SUCCESS;
}
