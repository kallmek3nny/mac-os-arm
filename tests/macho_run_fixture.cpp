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

// close(1); write(1, "hello", 5); exit(errno). Once the guest closes stdout,
// the write must fail with EBADF, so the exit status is that errno and no
// byte reaches the host stdout. A failed close exits 100 instead, and a
// write that still succeeds exits 101, so neither can pass for EBADF.
constexpr std::array<std::uint32_t, 19> kCloseStdoutCode{
    0xd2800020U, // mov x0, #1 (stdout)
    0xd28000d0U, // mov x16, #6 (close)
    0xd4001001U, // svc #0x80
    0x54000142U, // b.cs close_failed (+40)
    0xd2800020U, // mov x0, #1 (stdout)
    0xd2880001U, // mov x1, #0x4000
    0xf2c00021U, // movk x1, #1, lsl #32 -> 0x100004000
    0xd28000a2U, // mov x2, #5
    0xd2800090U, // mov x16, #4 (write)
    0xd4001001U, // svc #0x80
    0x540000c3U, // b.cc write_succeeded (+24)
    0xd2800030U, // mov x16, #1 (exit) with the write errno still in x0
    0xd4001001U, // svc #0x80
    0xd2800c80U, // close_failed: mov x0, #100
    0xd2800030U, // mov x16, #1 (exit)
    0xd4001001U, // svc #0x80
    0xd2800ca0U, // write_succeeded: mov x0, #101
    0xd2800030U, // mov x16, #1 (exit)
    0xd4001001U, // svc #0x80
};

// fstat64(0, buffer); exit(st_mode >> 12). The exit status is the Darwin
// S_IF* file type of the guest's stdin, which macho_run_check.cmake always
// redirects from a file, so a correct host reports S_IFREG (8). A failed
// fstat64 exits 100 instead, so an errno cannot pass for a file type. The
// buffer address is rebuilt after the call rather than trusting x1 to survive
// it, and the 144-byte stat64 lands in the zero-filled tail of __DATA.
constexpr std::array<std::uint32_t, 15> kFstatStdinCode{
    0xd2800000U, // mov x0, #0 (stdin)
    0xd2882001U, // mov x1, #0x4100
    0xf2c00021U, // movk x1, #1, lsl #32 -> 0x100004100
    0xd2802a70U, // mov x16, #339 (fstat64)
    0xd4001001U, // svc #0x80
    0x540000e2U, // b.cs fstat_failed (+28)
    0xd2882001U, // mov x1, #0x4100
    0xf2c00021U, // movk x1, #1, lsl #32
    0x79400820U, // ldrh w0, [x1, #4] -> st_mode
    0x530c7c00U, // lsr w0, w0, #12 -> S_IF* file type
    0xd2800030U, // mov x16, #1 (exit)
    0xd4001001U, // svc #0x80
    0xd2800c80U, // fstat_failed: mov x0, #100
    0xd2800030U, // mov x16, #1 (exit)
    0xd4001001U, // svc #0x80
};

// ioctl(0, TIOCGETA, buffer); exit(errno). macho_run_check.cmake always
// redirects guest stdin from a file, so the TIOCGETA probe behind isatty(3)
// must fail with ENOTTY and the exit status is that errno (25). An ioctl that
// succeeds exits 101 instead, so a fabricated terminal cannot pass for ENOTTY.
// The 72-byte termios buffer lies in the zero-filled tail of __DATA.
constexpr std::array<std::uint32_t, 13> kIoctlStdinCode{
    0xd2800000U, // mov x0, #0 (stdin)
    0xd28e8261U, // mov x1, #0x7413
    0xf2a80901U, // movk x1, #0x4048, lsl #16 -> TIOCGETA 0x40487413
    0xd2882002U, // mov x2, #0x4100
    0xf2c00022U, // movk x2, #1, lsl #32 -> 0x100004100
    0xd28006d0U, // mov x16, #54 (ioctl)
    0xd4001001U, // svc #0x80
    0x54000063U, // b.cc ioctl_succeeded (+12)
    0xd2800030U, // mov x16, #1 (exit) with the ioctl errno still in x0
    0xd4001001U, // svc #0x80
    0xd2800ca0U, // ioctl_succeeded: mov x0, #101
    0xd2800030U, // mov x16, #1 (exit)
    0xd4001001U, // svc #0x80
};

// writev(1, iov, 3); exit(bytes written). The three 16-byte arm64 struct
// iovec records { iov_base; iov_len; } are built in the zero-filled tail of
// __DATA as {"hel", 3}, {"hello", 0} and {"lo", 2}, so a correct gather writes
// "hello" to stdout, skips the empty middle vector and exits with the 5-byte
// total. A failed writev (carry set) exits 100 instead, so an errno cannot
// pass for a byte count.
constexpr std::array<std::uint32_t, 21> kWritevStdoutCode{
    0xd2880009U, // mov x9, #0x4000
    0xf2c00029U, // movk x9, #1, lsl #32 -> "hello" at 0x100004000
    0xd288200aU, // mov x10, #0x4100
    0xf2c0002aU, // movk x10, #1, lsl #32 -> iovec array at 0x100004100
    0xd280006bU, // mov x11, #3
    0xa9002d49U, // stp x9, x11, [x10] -> iov[0] = {"hel", 3}
    0xa9017d49U, // stp x9, xzr, [x10, #16] -> iov[1] = {"hello", 0}
    0x91000d2cU, // add x12, x9, #3 -> "lo"
    0xd280004dU, // mov x13, #2
    0xa902354cU, // stp x12, x13, [x10, #32] -> iov[2] = {"lo", 2}
    0xd2800020U, // mov x0, #1 (stdout)
    0xaa0a03e1U, // mov x1, x10 -> iovec array
    0xd2800062U, // mov x2, #3 (iovcnt)
    0xd2800f30U, // mov x16, #121 (writev)
    0xd4001001U, // svc #0x80
    0x54000062U, // b.cs writev_failed (+12)
    0xd2800030U, // mov x16, #1 (exit) with the byte count still in x0
    0xd4001001U, // svc #0x80
    0xd2800c80U, // writev_failed: mov x0, #100
    0xd2800030U, // mov x16, #1 (exit)
    0xd4001001U, // svc #0x80
};

// readv(0, iov, 3); write(1, buffer, n); exit(n). The three 16-byte arm64
// struct iovec records are built in the zero-filled tail of __DATA as
// {buffer + 2, 2}, {buffer + 8, 0} and {buffer, 3}, with the buffer past the
// iovec array. Scattering the 4-byte stdin "ping" stores "pi" at buffer + 2,
// skips the empty middle vector without touching its base and stores "ng"
// at buffer, so writing back the n bytes at buffer shows "ngpi" and the exit
// status is the 4-byte total, short of the 5 bytes requested. A failed readv
// (carry set) exits 100 instead, so an errno cannot pass for a byte count.
constexpr std::array<std::uint32_t, 29> kReadvStdinCode{
    0xd2884009U, // mov x9, #0x4200
    0xf2c00029U, // movk x9, #1, lsl #32 -> buffer at 0x100004200
    0xd288200aU, // mov x10, #0x4100
    0xf2c0002aU, // movk x10, #1, lsl #32 -> iovec array at 0x100004100
    0x9100092bU, // add x11, x9, #2 -> buffer + 2
    0xd280004cU, // mov x12, #2
    0xa900314bU, // stp x11, x12, [x10] -> iov[0] = {buffer + 2, 2}
    0x9100212dU, // add x13, x9, #8 -> buffer + 8
    0xa9017d4dU, // stp x13, xzr, [x10, #16] -> iov[1] = {buffer + 8, 0}
    0xd280006eU, // mov x14, #3
    0xa9023949U, // stp x9, x14, [x10, #32] -> iov[2] = {buffer, 3}
    0xd2800000U, // mov x0, #0 (stdin)
    0xaa0a03e1U, // mov x1, x10 -> iovec array
    0xd2800062U, // mov x2, #3 (iovcnt)
    0xd2800f10U, // mov x16, #120 (readv)
    0xd4001001U, // svc #0x80
    0x54000142U, // b.cs readv_failed (+40)
    0xaa0003e2U, // mov x2, x0 -> bytes read
    0xd2800020U, // mov x0, #1 (stdout)
    0xd2884001U, // mov x1, #0x4200
    0xf2c00021U, // movk x1, #1, lsl #32 -> buffer
    0xd2800090U, // mov x16, #4 (write)
    0xd4001001U, // svc #0x80
    0xaa0203e0U, // mov x0, x2
    0xd2800030U, // mov x16, #1 (exit)
    0xd4001001U, // svc #0x80
    0xd2800c80U, // readv_failed: mov x0, #100
    0xd2800030U, // mov x16, #1 (exit)
    0xd4001001U, // svc #0x80
};

// off = lseek(0, -3, SEEK_END); n = read(0, buffer, 64); write(1, buffer, n);
// exit(off). macho_run_check.cmake redirects guest stdin from a file, so for
// the 8-byte stdin "seekable" the seek lands 3 bytes before end-of-file at
// offset 5, the read resumes there and the guest writes back "ble" and exits
// with that offset. A failed lseek (carry set) exits 100 and a failed read
// exits 101, so neither errno can pass for an offset. The offset is kept in
// x19 across the read and write, and the buffer lies in the zero-filled tail
// of __DATA, past "hello".
constexpr std::array<std::uint32_t, 29> kLseekStdinCode{
    0xd2800000U, // mov x0, #0 (stdin)
    0x92800041U, // mov x1, #-3 (movn x1, #2)
    0xd2800042U, // mov x2, #2 (SEEK_END)
    0xd28018f0U, // mov x16, #199 (lseek)
    0xd4001001U, // svc #0x80
    0x54000242U, // b.cs lseek_failed (+72)
    0xaa0003f3U, // mov x19, x0 -> new offset
    0xd2800000U, // mov x0, #0 (stdin)
    0xd2882001U, // mov x1, #0x4100
    0xf2c00021U, // movk x1, #1, lsl #32 -> 0x100004100
    0xd2800802U, // mov x2, #64
    0xd2800070U, // mov x16, #3 (read)
    0xd4001001U, // svc #0x80
    0x540001a2U, // b.cs read_failed (+52)
    0xaa0003e2U, // mov x2, x0 -> bytes read
    0xd2800020U, // mov x0, #1 (stdout)
    0xd2882001U, // mov x1, #0x4100
    0xf2c00021U, // movk x1, #1, lsl #32
    0xd2800090U, // mov x16, #4 (write)
    0xd4001001U, // svc #0x80
    0xaa1303e0U, // mov x0, x19 -> offset lseek returned
    0xd2800030U, // mov x16, #1 (exit)
    0xd4001001U, // svc #0x80
    0xd2800c80U, // lseek_failed: mov x0, #100
    0xd2800030U, // mov x16, #1 (exit)
    0xd4001001U, // svc #0x80
    0xd2800ca0U, // read_failed: mov x0, #101
    0xd2800030U, // mov x16, #1 (exit)
    0xd4001001U, // svc #0x80
};

int usage() {
    std::cerr << "usage: macho_run_fixture "
                 "<hello|argc|echo|close-stdout|fstat-stdin|ioctl-stdin|writev-stdout|"
                 "readv-stdin|lseek-stdin> "
                 "<output-path>\n";
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
    } else if (kind == "close-stdout") {
        bytes = image(kCloseStdoutCode);
    } else if (kind == "fstat-stdin") {
        bytes = image(kFstatStdinCode);
    } else if (kind == "ioctl-stdin") {
        bytes = image(kIoctlStdinCode);
    } else if (kind == "writev-stdout") {
        bytes = image(kWritevStdoutCode);
    } else if (kind == "readv-stdin") {
        bytes = image(kReadvStdinCode);
    } else if (kind == "lseek-stdin") {
        bytes = image(kLseekStdinCode);
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
