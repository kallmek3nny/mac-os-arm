#include "macosarm/macho.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
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

void put_u32(std::vector<std::byte>& bytes, std::size_t offset, std::uint32_t value) {
    for (std::size_t i = 0; i < 4; ++i) {
        bytes.at(offset + i) = static_cast<std::byte>((value >> (i * 8)) & 0xffU);
    }
}

void put_u64(std::vector<std::byte>& bytes, std::size_t offset, std::uint64_t value) {
    for (std::size_t i = 0; i < 8; ++i) {
        bytes.at(offset + i) = static_cast<std::byte>((value >> (i * 8)) & 0xffU);
    }
}

void put_name(std::vector<std::byte>& bytes, std::size_t offset, const std::string& name) {
    for (std::size_t i = 0; i < name.size() && i < 16; ++i) {
        bytes.at(offset + i) = static_cast<std::byte>(static_cast<unsigned char>(name[i]));
    }
}

void put_string(std::vector<std::byte>& bytes, std::size_t offset, const std::string& value) {
    for (std::size_t i = 0; i < value.size(); ++i) {
        bytes.at(offset + i) = static_cast<std::byte>(static_cast<unsigned char>(value[i]));
    }
    bytes.at(offset + value.size()) = std::byte{0};
}

std::vector<std::byte> valid_image() {
    constexpr std::uint32_t command_bytes = 72 + 24;
    std::vector<std::byte> bytes(0x200, std::byte{0});

    put_u32(bytes, 0, macosarm::macho::kMhMagic64);
    put_u32(bytes, 4, static_cast<std::uint32_t>(macosarm::macho::kCpuTypeArm64));
    put_u32(bytes, 8, static_cast<std::uint32_t>(macosarm::macho::kCpuSubtypeArm64All));
    put_u32(bytes, 12, macosarm::macho::kMhExecute);
    put_u32(bytes, 16, 2);
    put_u32(bytes, 20, command_bytes);
    put_u32(bytes, 24, 0x00200000U);
    put_u32(bytes, 28, 0);

    const std::size_t segment = 32;
    put_u32(bytes, segment, macosarm::macho::kLcSegment64);
    put_u32(bytes, segment + 4, 72);
    put_name(bytes, segment + 8, "__TEXT");
    put_u64(bytes, segment + 24, 0x100000000ULL);
    put_u64(bytes, segment + 32, 0x200ULL);
    put_u64(bytes, segment + 40, 0);
    put_u64(bytes, segment + 48, 0x200ULL);
    put_u32(bytes, segment + 56, 5);
    put_u32(bytes, segment + 60, 5);
    put_u32(bytes, segment + 64, 0);
    put_u32(bytes, segment + 68, 0);

    const std::size_t main = segment + 72;
    put_u32(bytes, main, macosarm::macho::kLcMain);
    put_u32(bytes, main + 4, 24);
    put_u64(bytes, main + 8, 0x100ULL);
    put_u64(bytes, main + 16, 0);

    return bytes;
}

std::vector<std::byte> metadata_image() {
    constexpr std::uint32_t command_bytes = 72 + 24 + 32 + 56 + 40 + 16 + 16;
    std::vector<std::byte> bytes(0x400, std::byte{0});

    put_u32(bytes, 0, macosarm::macho::kMhMagic64);
    put_u32(bytes, 4, static_cast<std::uint32_t>(macosarm::macho::kCpuTypeArm64));
    put_u32(bytes, 8, static_cast<std::uint32_t>(macosarm::macho::kCpuSubtypeArm64e));
    put_u32(bytes, 12, macosarm::macho::kMhExecute);
    put_u32(bytes, 16, 7);
    put_u32(bytes, 20, command_bytes);
    put_u32(bytes, 24, 0x00200000U);
    put_u32(bytes, 28, 0);

    constexpr std::size_t segment = 32;
    put_u32(bytes, segment, macosarm::macho::kLcSegment64);
    put_u32(bytes, segment + 4, 72);
    put_name(bytes, segment + 8, "__TEXT");
    put_u64(bytes, segment + 24, 0x100000000ULL);
    put_u64(bytes, segment + 32, 0x400ULL);
    put_u64(bytes, segment + 40, 0);
    put_u64(bytes, segment + 48, 0x400ULL);
    put_u32(bytes, segment + 56, 5);
    put_u32(bytes, segment + 60, 5);

    constexpr std::size_t main = 104;
    put_u32(bytes, main, macosarm::macho::kLcMain);
    put_u32(bytes, main + 4, 24);
    put_u64(bytes, main + 8, 0x300ULL);

    constexpr std::size_t dylinker = 128;
    put_u32(bytes, dylinker, macosarm::macho::kLcLoadDylinker);
    put_u32(bytes, dylinker + 4, 32);
    put_u32(bytes, dylinker + 8, 12);
    put_string(bytes, dylinker + 12, "/usr/lib/dyld");

    constexpr std::size_t dylib = 160;
    put_u32(bytes, dylib, macosarm::macho::kLcLoadDylib);
    put_u32(bytes, dylib + 4, 56);
    put_u32(bytes, dylib + 8, 24);
    put_u32(bytes, dylib + 12, 7);
    put_u32(bytes, dylib + 16, 0x00010002U);
    put_u32(bytes, dylib + 20, 0x00010000U);
    put_string(bytes, dylib + 24, "/usr/lib/libSystem.B.dylib");

    constexpr std::size_t rpath = 216;
    put_u32(bytes, rpath, macosarm::macho::kLcRpath);
    put_u32(bytes, rpath + 4, 40);
    put_u32(bytes, rpath + 8, 12);
    put_string(bytes, rpath + 12, "@loader_path/Frameworks");

    constexpr std::size_t exports = 256;
    put_u32(bytes, exports, macosarm::macho::kLcDyldExportsTrie);
    put_u32(bytes, exports + 4, 16);
    put_u32(bytes, exports + 8, 0x320);
    put_u32(bytes, exports + 12, 0x10);

    constexpr std::size_t fixups = 272;
    put_u32(bytes, fixups, macosarm::macho::kLcDyldChainedFixups);
    put_u32(bytes, fixups + 4, 16);
    put_u32(bytes, fixups + 8, 0x340);
    put_u32(bytes, fixups + 12, 0x20);

    return bytes;
}

} // namespace

int main() {
    {
        auto bytes = valid_image();
        const auto result = macosarm::macho::parse(bytes);
        expect(static_cast<bool>(result), "valid arm64 Mach-O parses");
        expect(result.image.segments.size() == 1, "one segment parsed");
        expect(result.image.segments[0].name == "__TEXT", "segment name parsed");
        expect(result.image.segments[0].vm_address == 0x100000000ULL, "segment vmaddr parsed");
        expect(result.image.has_entry_point, "LC_MAIN detected");
        expect(result.image.entry_file_offset == 0x100ULL, "entry file offset parsed");
    }

    {
        const auto result = macosarm::macho::parse(metadata_image());
        expect(static_cast<bool>(result), "dyld metadata image parses");
        expect(result.image.cpu_subtype == macosarm::macho::kCpuSubtypeArm64e, "arm64e subtype preserved");
        expect(result.image.has_dynamic_linker, "dynamic linker detected");
        expect(result.image.dynamic_linker == "/usr/lib/dyld", "dynamic linker path parsed");
        expect(result.image.dependencies.size() == 1, "dylib dependency parsed");
        expect(result.image.dependencies[0].path == "/usr/lib/libSystem.B.dylib", "dylib path parsed");
        expect(result.image.dependencies[0].timestamp == 7, "dylib timestamp parsed");
        expect(result.image.dependencies[0].current_version == 0x00010002U, "dylib current version parsed");
        expect(result.image.dependencies[0].compatibility_version == 0x00010000U,
               "dylib compatibility version parsed");
        expect(result.image.dependencies[0].kind == macosarm::macho::DylibLoadKind::normal,
               "dylib load kind parsed");
        expect(result.image.runpaths.size() == 1 && result.image.runpaths[0] == "@loader_path/Frameworks",
               "LC_RPATH parsed");
        expect(result.image.exports_trie.present && result.image.exports_trie.offset == 0x320 &&
                   result.image.exports_trie.size == 0x10,
               "exports trie range parsed");
        expect(result.image.chained_fixups.present && result.image.chained_fixups.offset == 0x340 &&
                   result.image.chained_fixups.size == 0x20,
               "chained fixups range parsed");
        expect(macosarm::macho::dylib_load_kind_name(result.image.dependencies[0].kind) == "normal",
               "dylib load kind has stable name");
    }

    {
        std::vector<std::byte> bytes(8, std::byte{0});
        const auto result = macosarm::macho::parse(bytes);
        expect(result.error == macosarm::macho::ErrorCode::truncated, "short header rejected");
    }

    {
        auto bytes = valid_image();
        put_u32(bytes, 0, 0xfeedfaceU);
        const auto result = macosarm::macho::parse(bytes);
        expect(result.error == macosarm::macho::ErrorCode::bad_magic, "32-bit/bad magic rejected");
    }

    {
        auto bytes = valid_image();
        put_u32(bytes, 4, 0x01000007U);
        const auto result = macosarm::macho::parse(bytes);
        expect(result.error == macosarm::macho::ErrorCode::unsupported_cpu, "x86_64 image rejected");
    }

    {
        auto bytes = valid_image();
        put_u32(bytes, 20, 0xfffffff0U);
        const auto result = macosarm::macho::parse(bytes);
        expect(result.error == macosarm::macho::ErrorCode::malformed_load_commands,
               "oversized command region rejected");
    }

    {
        auto bytes = valid_image();
        put_u32(bytes, 32 + 4, 4);
        const auto result = macosarm::macho::parse(bytes);
        expect(result.error == macosarm::macho::ErrorCode::malformed_load_commands,
               "undersized load command rejected");
    }

    {
        auto bytes = valid_image();
        put_u64(bytes, 32 + 40, 0x1f0);
        put_u64(bytes, 32 + 48, 0x40);
        const auto result = macosarm::macho::parse(bytes);
        expect(result.error == macosarm::macho::ErrorCode::malformed_segment, "segment past EOF rejected");
    }

    {
        auto bytes = valid_image();
        put_u32(bytes, 32 + 64, 1);
        const auto result = macosarm::macho::parse(bytes);
        expect(result.error == macosarm::macho::ErrorCode::malformed_segment, "section table overflow rejected");
    }

    {
        auto bytes = valid_image();
        put_u64(bytes, 32 + 72 + 8, 0x400);
        const auto result = macosarm::macho::parse(bytes);
        expect(result.error == macosarm::macho::ErrorCode::malformed_load_commands,
               "entrypoint past EOF rejected");
    }

    {
        auto bytes = metadata_image();
        put_u32(bytes, 128 + 8, 32);
        const auto result = macosarm::macho::parse(bytes);
        expect(result.error == macosarm::macho::ErrorCode::malformed_dynamic_linker,
               "dynamic linker path outside command rejected");
    }

    {
        auto bytes = metadata_image();
        put_u32(bytes, 160 + 8, 56);
        const auto result = macosarm::macho::parse(bytes);
        expect(result.error == macosarm::macho::ErrorCode::malformed_dylib,
               "dylib path outside command rejected");
    }

    {
        auto bytes = metadata_image();
        put_u32(bytes, 216 + 8, 40);
        const auto result = macosarm::macho::parse(bytes);
        expect(result.error == macosarm::macho::ErrorCode::malformed_runpath,
               "runpath outside command rejected");
    }

    {
        auto bytes = metadata_image();
        put_u32(bytes, 256 + 8, 0x3f0);
        put_u32(bytes, 256 + 12, 0x40);
        const auto result = macosarm::macho::parse(bytes);
        expect(result.error == macosarm::macho::ErrorCode::malformed_linkedit_data,
               "linkedit range past EOF rejected");
    }

    {
        auto bytes = metadata_image();
        put_u32(bytes, 272, macosarm::macho::kLcDyldExportsTrie);
        const auto result = macosarm::macho::parse(bytes);
        expect(result.error == macosarm::macho::ErrorCode::duplicate_exports_trie,
               "duplicate exports trie rejected");
    }

    {
        auto bytes = metadata_image();
        put_u32(bytes, 160, macosarm::macho::kLcLoadDylinker);
        const auto result = macosarm::macho::parse(bytes);
        expect(result.error == macosarm::macho::ErrorCode::duplicate_dynamic_linker,
               "duplicate dynamic linker rejected");
    }

    expect(macosarm::macho::error_name(macosarm::macho::ErrorCode::malformed_dynamic_linker) ==
               "malformed_dynamic_linker",
           "new parser errors have stable names");

    if (failures != 0) {
        std::cerr << failures << " test(s) failed\n";
        return EXIT_FAILURE;
    }

    std::cout << "all Mach-O parser tests passed\n";
    return EXIT_SUCCESS;
}
