#include "macosarm/image_loader.hpp"
#include "macosarm/macho.hpp"

#include <array>
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

std::vector<std::byte> synthetic_executable() {
    constexpr std::uint32_t command_bytes = 72 + 72 + 24;
    std::vector<std::byte> bytes(0x4000, std::byte{0});

    put_u32(bytes, 0, macosarm::macho::kMhMagic64);
    put_u32(bytes, 4, static_cast<std::uint32_t>(macosarm::macho::kCpuTypeArm64));
    put_u32(bytes, 8, static_cast<std::uint32_t>(macosarm::macho::kCpuSubtypeArm64All));
    put_u32(bytes, 12, macosarm::macho::kMhExecute);
    put_u32(bytes, 16, 3);
    put_u32(bytes, 20, command_bytes);
    put_u32(bytes, 24, 0x00200000U);
    put_u32(bytes, 28, 0);

    std::size_t command = 32;
    put_u32(bytes, command, macosarm::macho::kLcSegment64);
    put_u32(bytes, command + 4, 72);
    put_name(bytes, command + 8, "__PAGEZERO");
    put_u64(bytes, command + 24, 0);
    put_u64(bytes, command + 32, 0x100000000ULL);
    put_u64(bytes, command + 40, 0);
    put_u64(bytes, command + 48, 0);
    put_u32(bytes, command + 56, 0);
    put_u32(bytes, command + 60, 0);
    put_u32(bytes, command + 64, 0);
    put_u32(bytes, command + 68, 0);

    command += 72;
    put_u32(bytes, command, macosarm::macho::kLcSegment64);
    put_u32(bytes, command + 4, 72);
    put_name(bytes, command + 8, "__TEXT");
    put_u64(bytes, command + 24, 0x100000000ULL);
    put_u64(bytes, command + 32, 0x4000);
    put_u64(bytes, command + 40, 0);
    put_u64(bytes, command + 48, 0x4000);
    put_u32(bytes, command + 56, 5);
    put_u32(bytes, command + 60, 5);
    put_u32(bytes, command + 64, 0);
    put_u32(bytes, command + 68, 0);

    command += 72;
    put_u32(bytes, command, macosarm::macho::kLcMain);
    put_u32(bytes, command + 4, 24);
    put_u64(bytes, command + 8, 0x200);
    put_u64(bytes, command + 16, 0);

    bytes[0x200] = std::byte{0x20};
    bytes[0x201] = std::byte{0x00};
    bytes[0x202] = std::byte{0x80};
    bytes[0x203] = std::byte{0xd2}; // mov x0, #1
    return bytes;
}

} // namespace

int main() {
    const auto file = synthetic_executable();
    const auto parsed = macosarm::macho::parse(file);
    expect(static_cast<bool>(parsed), "raw synthetic Mach-O parses");
    if (!parsed) {
        return EXIT_FAILURE;
    }

    expect(parsed.image.segments.size() == 2, "parser exposes PAGEZERO and TEXT");
    expect(parsed.image.has_entry_point, "parser exposes LC_MAIN");
    expect(parsed.image.entry_file_offset == 0x200, "parser preserves entry file offset");

    macosarm::GuestAddressSpace vm;
    const auto loaded = macosarm::load_executable(parsed.image, file, vm);
    expect(static_cast<bool>(loaded), "parsed executable loads into guest memory");
    if (!loaded) {
        return EXIT_FAILURE;
    }

    expect(loaded.image.preferred_load_address == 0x100000000ULL,
           "loader derives preferred base from parsed TEXT");
    expect(loaded.image.entry_address == 0x100000200ULL,
           "loader derives guest PC from parsed LC_MAIN");
    expect(vm.resident_page_count() == 1,
           "4 GiB PAGEZERO remains sparse while TEXT materializes one page");

    std::array<std::byte, 4> instruction{};
    expect(static_cast<bool>(vm.read(loaded.image.entry_address, instruction)),
           "entry instruction is readable from guest memory");
    expect(instruction[0] == std::byte{0x20} && instruction[1] == std::byte{0x00} &&
           instruction[2] == std::byte{0x80} && instruction[3] == std::byte{0xd2},
           "raw file instruction survives parse and load unchanged");

    const std::array<std::byte, 1> patch{std::byte{0xff}};
    expect(vm.write(loaded.image.entry_address, patch).error == macosarm::VmError::protection,
           "parsed TEXT protection survives into guest memory");

    if (failures != 0) {
        std::cerr << failures << " test(s) failed\n";
        return EXIT_FAILURE;
    }
    std::cout << "parse-to-load integration test passed\n";
    return EXIT_SUCCESS;
}
