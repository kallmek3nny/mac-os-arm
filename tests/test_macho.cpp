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
        expect(result.error == macosarm::macho::ErrorCode::malformed_load_commands, "oversized command region rejected");
    }

    {
        auto bytes = valid_image();
        put_u32(bytes, 32 + 4, 4);
        const auto result = macosarm::macho::parse(bytes);
        expect(result.error == macosarm::macho::ErrorCode::malformed_load_commands, "undersized load command rejected");
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
        expect(result.error == macosarm::macho::ErrorCode::malformed_load_commands, "entrypoint past EOF rejected");
    }

    if (failures != 0) {
        std::cerr << failures << " test(s) failed\n";
        return EXIT_FAILURE;
    }

    std::cout << "all Mach-O parser tests passed\n";
    return EXIT_SUCCESS;
}
