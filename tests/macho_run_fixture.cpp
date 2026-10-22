// Writes minimal raw ARM64 Mach-O executables for end-to-end macho-run
// tests. The layout mirrors executable_with_write_and_exit() in
// tests/test_session_dynarmic.cpp. Load-command constants are spelled out
// from <mach-o/loader.h> so the fixture does not reuse the parser it tests.
//
//   hello: write(1, "hello", 5); exit(7)
//   argc:  exit(argc), loaded from the Darwin startup stack at [sp]
//   echo:  n = read(0, buf, 64); write(1, buf, n); exit(n), or exit(100)
//          when read fails

#include <array>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <string_view>
#include <vector>

namespace {

constexpr std::uint32_t kMhMagic64 = 0xfeedfacfU;
constexpr std::uint32_t kCpuTypeArm64 = 0x0100000cU;
constexpr std::uint32_t kCpuSubtypeArm64All = 0U;
constexpr std::uint32_t kMhExecute = 0x2U;
constexpr std::uint32_t kMhPie = 0x00200000U;
constexpr std::uint32_t kLcSegment64 = 0x19U;
constexpr std::uint32_t kLcMain = 0x80000028U;

constexpr std::uint64_t kTextVm = 0x100000000ULL;
constexpr std::uint64_t kDataVm = 0x100004000ULL;
constexpr std::size_t kDataFileOffset = 0x4000U;
constexpr std::size_t kEntryFileOffset = 0x200U;
constexpr std::string_view kMessage = "hello";

void put_u32(std::vector<std::byte>& bytes, std::size_t offset, std::uint32_t value) {
    for (std::size_t i = 0; i < 4U; ++i) {
        bytes.at(offset + i) = static_cast<std::byte>((value >> (i * 8U)) & 0xffU);
    }
}

void put_u64(std::vector<std::byte>& bytes, std::size_t offset, std::uint64_t value) {
    for (std::size_t i = 0; i < 8U; ++i) {
        bytes.at(offset + i) = static_cast<std::byte>((value >> (i * 8U)) & 0xffU);
    }
}

void put_string(std::vector<std::byte>& bytes, std::size_t offset, std::string_view value) {
    for (std::size_t i = 0; i < value.size(); ++i) {
        bytes.at(offset + i) = static_cast<std::byte>(static_cast<unsigned char>(value[i]));
    }
}

void put_segment(std::vector<std::byte>& bytes, std::size_t command, std::string_view name,
                 std::uint64_t vm_address, std::uint64_t vm_size, std::uint64_t file_offset,
                 std::uint64_t file_size, std::uint32_t protection) {
    put_u32(bytes, command, kLcSegment64);
    put_u32(bytes, command + 4U, 72U);
    put_string(bytes, command + 8U, name);
    put_u64(bytes, command + 24U, vm_address);
    put_u64(bytes, command + 32U, vm_size);
    put_u64(bytes, command + 40U, file_offset);
    put_u64(bytes, command + 48U, file_size);
    put_u32(bytes, command + 56U, protection); // maxprot
    put_u32(bytes, command + 60U, protection); // initprot
}

template <std::size_t N>
std::vector<std::byte> image(const std::array<std::uint32_t, N>& code) {
    std::vector<std::byte> bytes(kDataFileOffset + kMessage.size(), std::byte{0});
    put_u32(bytes, 0U, kMhMagic64);
    put_u32(bytes, 4U, kCpuTypeArm64);
    put_u32(bytes, 8U, kCpuSubtypeArm64All);
    put_u32(bytes, 12U, kMhExecute);
    put_u32(bytes, 16U, 4U);                    // ncmds
    put_u32(bytes, 20U, 72U + 72U + 72U + 24U); // sizeofcmds
    put_u32(bytes, 24U, kMhPie);

    put_segment(bytes, 32U, "__PAGEZERO", 0U, kTextVm, 0U, 0U, 0U);
    put_segment(bytes, 104U, "__TEXT", kTextVm, 0x4000U, 0U, 0x4000U, 5U);
    put_segment(bytes, 176U, "__DATA", kDataVm, 0x4000U, kDataFileOffset, kMessage.size(), 3U);
    put_u32(bytes, 248U, kLcMain);
    put_u32(bytes, 252U, 24U);
    put_u64(bytes, 256U, kEntryFileOffset); // entryoff; stacksize stays 0

    for (std::size_t i = 0; i < N; ++i) {
        put_u32(bytes, kEntryFileOffset + i * 4U, code[i]);
    }
    put_string(bytes, kDataFileOffset, kMessage);
    return bytes;
}

constexpr std::array<std::uint32_t, 9> kHelloCode{
    0xd2800020U, // mov x0, #1
    0xd2880001U, // mov x1, #0x4000
    0xf2c00021U, // movk x1, #1, lsl #32 -> 0x100004000
    0xd28000a2U, // mov x2, #5
    0xd2800090U, // mov x16, #4 (write)
    0xd4001001U, // svc #0x80
    0xd28000e0U, // mov x0, #7
    0xd2800030U, // mov x16, #1 (exit)
    0xd4001001U, // svc #0x80
};

constexpr std::array<std::uint32_t, 3> kArgcCode{
    0xf94003e0U, // ldr x0, [sp] -> argc
    0xd2800030U, // mov x16, #1 (exit)
    0xd4001001U, // svc #0x80
};

// n = read(0, buffer, 64); write(1, buffer, n); exit(n). A failed read
// (carry set) exits 100 instead, so an errno cannot pass for a byte count.
// The buffer lies in the zero-filled tail of __DATA, past "hello".
constexpr std::array<std::uint32_t, 19> kEchoCode{
    0xd2800000U, // mov x0, #0 (stdin)
    0xd2882001U, // mov x1, #0x4100
    0xf2c00021U, // movk x1, #1, lsl #32 -> 0x100004100
    0xd2800802U, // mov x2, #64
    0xd2800070U, // mov x16, #3 (read)
    0xd4001001U, // svc #0x80
    0x54000142U, // b.cs read_failed (+40)
    0xaa0003e2U, // mov x2, x0 -> bytes read
    0xd2800020U, // mov x0, #1 (stdout)
    0xd2882001U, // mov x1, #0x4100
    0xf2c00021U, // movk x1, #1, lsl #32
    0xd2800090U, // mov x16, #4 (write)
    0xd4001001U, // svc #0x80
    0xaa0203e0U, // mov x0, x2
    0xd2800030U, // mov x16, #1 (exit)
    0xd4001001U, // svc #0x80
    0xd2800c80U, // read_failed: mov x0, #100
    0xd2800030U, // mov x16, #1 (exit)
    0xd4001001U, // svc #0x80
};

int usage() {
    std::cerr << "usage: macho_run_fixture <hello|argc|echo> <output-path>\n";
    return 2;
}

} // namespace

int main(int argc, char** argv) {
    if (argc != 3) {
        return usage();
    }
    const std::string_view kind(argv[1]);
    std::vector<std::byte> bytes;
    if (kind == "hello") {
        bytes = image(kHelloCode);
    } else if (kind == "argc") {
        bytes = image(kArgcCode);
    } else if (kind == "echo") {
        bytes = image(kEchoCode);
    } else {
        return usage();
    }

    std::ofstream output(argv[2], std::ios::binary | std::ios::trunc);
    output.write(reinterpret_cast<const char*>(bytes.data()),
                 static_cast<std::streamsize>(bytes.size()));
    output.close();
    if (!output) {
        std::cerr << "error: unable to write '" << argv[2] << "'\n";
        return 1;
    }
    return 0;
}
