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

// n = pread(0, buffer, 3, 4); write(1, buffer, n); m = read(0, buffer, 64);
// write(1, buffer, m); exit(n). macho_run_check.cmake redirects guest stdin
// from a file, so for the 10-byte stdin "positioned" the pread copies "tio"
// from offset 4. Because pread(2) never moves the file offset, the read that
// follows still starts at offset 0 and returns the whole file, so the guest
// writes back "tiopositioned" and exits with the pread count. A failed pread
// (carry set) exits 100 and a failed read exits 101, so neither errno can
// pass for a count. The count is kept in x19 across the later calls, and the
// buffer lies in the zero-filled tail of __DATA, past "hello".
constexpr std::array<std::uint32_t, 37> kPreadStdinCode{
    0xd2800000U, // mov x0, #0 (stdin)
    0xd2882001U, // mov x1, #0x4100
    0xf2c00021U, // movk x1, #1, lsl #32 -> 0x100004100
    0xd2800062U, // mov x2, #3 (nbyte)
    0xd2800083U, // mov x3, #4 (offset)
    0xd2801330U, // mov x16, #153 (pread)
    0xd4001001U, // svc #0x80
    0x54000302U, // b.cs pread_failed (+96)
    0xaa0003f3U, // mov x19, x0 -> pread count
    0xaa0003e2U, // mov x2, x0
    0xd2800020U, // mov x0, #1 (stdout)
    0xd2882001U, // mov x1, #0x4100
    0xf2c00021U, // movk x1, #1, lsl #32
    0xd2800090U, // mov x16, #4 (write)
    0xd4001001U, // svc #0x80
    0xd2800000U, // mov x0, #0 (stdin)
    0xd2882001U, // mov x1, #0x4100
    0xf2c00021U, // movk x1, #1, lsl #32
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
    0xaa1303e0U, // mov x0, x19 -> pread count
    0xd2800030U, // mov x16, #1 (exit)
    0xd4001001U, // svc #0x80
    0xd2800c80U, // pread_failed: mov x0, #100
    0xd2800030U, // mov x16, #1 (exit)
    0xd4001001U, // svc #0x80
    0xd2800ca0U, // read_failed: mov x0, #101
    0xd2800030U, // mov x16, #1 (exit)
    0xd4001001U, // svc #0x80
};

// fcntl(0, F_GETFD); fcntl(0, F_SETFD, FD_CLOEXEC); fcntl(0, F_GETFD);
// fcntl(1, F_GETFL); exit(before << 6 | after << 4 | getfl). The standard
// streams start without FD_CLOEXEC, so F_GETFD reports 0 before the F_SETFD
// and 1 after it. macho_run_check.cmake captures guest stdout through a pipe
// opened without O_APPEND, so F_GETFL reports O_WRONLY (1) and a correct host
// exits 17. Each failed fcntl (carry set) exits with its own status from 100
// to 103, so no errno can pass for a flag word. The two F_GETFD results are
// kept in x19 and x20 across the later calls.
constexpr std::array<std::uint32_t, 39> kFcntlStdioCode{
    0xd2800000U, // mov x0, #0 (stdin)
    0xd2800021U, // mov x1, #1 (F_GETFD)
    0xd2800b90U, // mov x16, #92 (fcntl)
    0xd4001001U, // svc #0x80
    0x540002e2U, // b.cs first_getfd_failed (+92)
    0xaa0003f3U, // mov x19, x0 -> descriptor flags before F_SETFD
    0xd2800000U, // mov x0, #0 (stdin)
    0xd2800041U, // mov x1, #2 (F_SETFD)
    0xd2800022U, // mov x2, #1 (FD_CLOEXEC)
    0xd2800b90U, // mov x16, #92 (fcntl)
    0xd4001001U, // svc #0x80
    0x54000262U, // b.cs setfd_failed (+76)
    0xd2800000U, // mov x0, #0 (stdin)
    0xd2800021U, // mov x1, #1 (F_GETFD)
    0xd2800b90U, // mov x16, #92 (fcntl)
    0xd4001001U, // svc #0x80
    0x54000222U, // b.cs second_getfd_failed (+68)
    0xaa0003f4U, // mov x20, x0 -> descriptor flags after F_SETFD
    0xd2800020U, // mov x0, #1 (stdout)
    0xd2800061U, // mov x1, #3 (F_GETFL)
    0xd2800b90U, // mov x16, #92 (fcntl)
    0xd4001001U, // svc #0x80
    0x540001c2U, // b.cs getfl_failed (+56)
    0xaa141000U, // orr x0, x0, x20, lsl #4 -> after << 4 | getfl
    0xaa131800U, // orr x0, x0, x19, lsl #6 -> before << 6
    0xd2800030U, // mov x16, #1 (exit)
    0xd4001001U, // svc #0x80
    0xd2800c80U, // first_getfd_failed: mov x0, #100
    0xd2800030U, // mov x16, #1 (exit)
    0xd4001001U, // svc #0x80
    0xd2800ca0U, // setfd_failed: mov x0, #101
    0xd2800030U, // mov x16, #1 (exit)
    0xd4001001U, // svc #0x80
    0xd2800cc0U, // second_getfd_failed: mov x0, #102
    0xd2800030U, // mov x16, #1 (exit)
    0xd4001001U, // svc #0x80
    0xd2800ce0U, // getfl_failed: mov x0, #103
    0xd2800030U, // mov x16, #1 (exit)
    0xd4001001U, // svc #0x80
};

// fcntl(1, F_GETFL); fcntl(1, F_SETFL, flags); fcntl(1, F_SETFL, flags |
// O_NONBLOCK); fcntl(1, F_GETFL); exit(getfl << 6 | errno). Handing F_SETFL
// back the flags F_GETFL reported changes nothing, so it succeeds with 0.
// macho-run's standard streams only do blocking I/O, so the O_NONBLOCK
// request fails, and the second F_GETFL proves it left the flags unchanged.
// macho_run_check.cmake captures guest stdout through a pipe opened without
// O_APPEND, so F_GETFL reports O_WRONLY (1), the O_NONBLOCK request fails
// with ENOTSUP (45) and a correct host exits 109. Every other outcome has its
// own status from 100 to 104: a failed first F_GETFL, a failed or nonzero
// unchanged F_SETFL, an O_NONBLOCK request that succeeds, a failed second
// F_GETFL and flags that changed. The first F_GETFL result and the errno
// are kept in x19 and x20 across the later calls.
constexpr std::array<std::uint32_t, 45> kFcntlSetflStdioCode{
    0xd2800020U, // mov x0, #1 (stdout)
    0xd2800061U, // mov x1, #3 (F_GETFL)
    0xd2800b90U, // mov x16, #92 (fcntl)
    0xd4001001U, // svc #0x80
    0x54000342U, // b.cs first_getfl_failed (+104)
    0xaa0003f3U, // mov x19, x0 -> status flags before F_SETFL
    0xd2800020U, // mov x0, #1 (stdout)
    0xd2800081U, // mov x1, #4 (F_SETFL)
    0xaa1303e2U, // mov x2, x19 (the flags F_GETFL reported)
    0xd2800b90U, // mov x16, #92 (fcntl)
    0xd4001001U, // svc #0x80
    0x540002c2U, // b.cs same_setfl_failed (+88)
    0xb50002a0U, // cbnz x0, same_setfl_failed (+84)
    0xd2800020U, // mov x0, #1 (stdout)
    0xd2800081U, // mov x1, #4 (F_SETFL)
    0xb27e0262U, // orr x2, x19, #0x4 (O_NONBLOCK)
    0xd2800b90U, // mov x16, #92 (fcntl)
    0xd4001001U, // svc #0x80
    0x54000243U, // b.cc nonblock_setfl_succeeded (+72)
    0xaa0003f4U, // mov x20, x0 -> errno of the O_NONBLOCK request
    0xd2800020U, // mov x0, #1 (stdout)
    0xd2800061U, // mov x1, #3 (F_GETFL)
    0xd2800b90U, // mov x16, #92 (fcntl)
    0xd4001001U, // svc #0x80
    0x540001e2U, // b.cs second_getfl_failed (+60)
    0xeb13001fU, // cmp x0, x19
    0x54000201U, // b.ne flags_changed (+64)
    0xaa131a80U, // orr x0, x20, x19, lsl #6 -> getfl << 6 | errno
    0xd2800030U, // mov x16, #1 (exit)
    0xd4001001U, // svc #0x80
    0xd2800c80U, // first_getfl_failed: mov x0, #100
    0xd2800030U, // mov x16, #1 (exit)
    0xd4001001U, // svc #0x80
    0xd2800ca0U, // same_setfl_failed: mov x0, #101
    0xd2800030U, // mov x16, #1 (exit)
    0xd4001001U, // svc #0x80
    0xd2800cc0U, // nonblock_setfl_succeeded: mov x0, #102
    0xd2800030U, // mov x16, #1 (exit)
    0xd4001001U, // svc #0x80
    0xd2800ce0U, // second_getfl_failed: mov x0, #103
    0xd2800030U, // mov x16, #1 (exit)
    0xd4001001U, // svc #0x80
    0xd2800d00U, // flags_changed: mov x0, #104
    0xd2800030U, // mov x16, #1 (exit)
    0xd4001001U, // svc #0x80
};

// getrlimit(RLIMIT_STACK, sp); getrlimit(RLIMIT_NOFILE, sp); exit(errno).
// macho-run reports its fixed 8 MiB main-thread stack mapping as both the
// soft and the hard RLIMIT_STACK limit, and enforces no descriptor limit, so
// RLIMIT_NOFILE fails with ENOSYS (78) and a correct host exits 78. Every
// other outcome has its own status from 100 to 103: a failed or nonzero
// RLIMIT_STACK query, a soft limit that differs from the hard limit, a stack
// limit other than 8 MiB, and an RLIMIT_NOFILE query that succeeds. The
// struct rlimit lands in 16 bytes reserved below the startup stack pointer.
constexpr std::array<std::uint32_t, 32> kGetrlimitStackCode{
    0xd10043ffU, // sub sp, sp, #16 (struct rlimit)
    0xd2800060U, // mov x0, #3 (RLIMIT_STACK)
    0x910003e1U, // mov x1, sp
    0xd2801850U, // mov x16, #194 (getrlimit)
    0xd4001001U, // svc #0x80
    0x540001e2U, // b.cs stack_failed (+60)
    0xb50001c0U, // cbnz x0, stack_failed (+56)
    0xa9402be9U, // ldp x9, x10, [sp] -> rlim_cur, rlim_max
    0xeb0a013fU, // cmp x9, x10
    0x540001c1U, // b.ne limits_differ (+56)
    0xd2a0100bU, // mov x11, #0x800000 (8 MiB)
    0xeb0b013fU, // cmp x9, x11
    0x540001c1U, // b.ne wrong_stack_limit (+56)
    0xd2800100U, // mov x0, #8 (RLIMIT_NOFILE)
    0x910003e1U, // mov x1, sp
    0xd2801850U, // mov x16, #194 (getrlimit)
    0xd4001001U, // svc #0x80
    0x54000183U, // b.cc nofile_succeeded (+48)
    0xd2800030U, // mov x16, #1 (exit) -> exit(errno of RLIMIT_NOFILE)
    0xd4001001U, // svc #0x80
    0xd2800c80U, // stack_failed: mov x0, #100
    0xd2800030U, // mov x16, #1 (exit)
    0xd4001001U, // svc #0x80
    0xd2800ca0U, // limits_differ: mov x0, #101
    0xd2800030U, // mov x16, #1 (exit)
    0xd4001001U, // svc #0x80
    0xd2800cc0U, // wrong_stack_limit: mov x0, #102
    0xd2800030U, // mov x16, #1 (exit)
    0xd4001001U, // svc #0x80
    0xd2800ce0U, // nofile_succeeded: mov x0, #103
    0xd2800030U, // mov x16, #1 (exit)
    0xd4001001U, // svc #0x80
};

// getrlimit(RLIMIT_STACK, sp); setrlimit(RLIMIT_STACK, sp) to restate, lower
// and raise the limit; getrlimit(RLIMIT_STACK, sp) again;
// setrlimit(RLIMIT_NOFILE, sp); exit(errno). macho-run reports its fixed 8 MiB
// main-thread stack mapping as both RLIMIT_STACK limits, so restating them
// succeeds. Lowering the soft limit to 4 MiB fails with EINVAL (22) because
// the mapping cannot shrink, and raising both limits to 16 MiB fails with
// EPERM (1) because the synthetic user is not root. Neither failure changes
// the limits, so the second getrlimit still reports 8 MiB for both.
// RLIMIT_NOFILE is not enforced, so it fails with ENOSYS (78) and a correct
// host exits 78. Every other outcome has its own status from 100 to 108. The
// struct rlimit lands in 16 bytes reserved below the startup stack pointer.
constexpr std::array<std::uint32_t, 81> kSetrlimitStackCode{
    0xd10043ffU, // sub sp, sp, #16 (struct rlimit)
    0xd2800060U, // mov x0, #3 (RLIMIT_STACK)
    0x910003e1U, // mov x1, sp
    0xd2801850U, // mov x16, #194 (getrlimit)
    0xd4001001U, // svc #0x80
    0x54000622U, // b.cs getrlimit_failed (+196)
    0xa9402be9U, // ldp x9, x10, [sp] -> rlim_cur, rlim_max
    0xd2a0100bU, // mov x11, #0x800000 (8 MiB)
    0xeb0b013fU, // cmp x9, x11
    0x54000601U, // b.ne wrong_limits (+192)
    0xeb0b015fU, // cmp x10, x11
    0x540005c1U, // b.ne wrong_limits (+184)
    0xd2800060U, // mov x0, #3 (RLIMIT_STACK)
    0x910003e1U, // mov x1, sp -> { 8 MiB, 8 MiB }
    0xd2801870U, // mov x16, #195 (setrlimit)
    0xd4001001U, // svc #0x80
    0x54000582U, // b.cs restate_failed (+176)
    0xb5000560U, // cbnz x0, restate_failed (+172)
    0xd2a0080cU, // mov x12, #0x400000 (4 MiB)
    0xf90003ecU, // str x12, [sp] -> { 4 MiB, 8 MiB }
    0xd2800060U, // mov x0, #3 (RLIMIT_STACK)
    0x910003e1U, // mov x1, sp
    0xd2801870U, // mov x16, #195 (setrlimit)
    0xd4001001U, // svc #0x80
    0x540004e3U, // b.cc lower_succeeded (+156)
    0xf100581fU, // cmp x0, #22 (EINVAL)
    0x54000501U, // b.ne lower_wrong_errno (+160)
    0xd2a0200dU, // mov x13, #0x1000000 (16 MiB)
    0xa90037edU, // stp x13, x13, [sp] -> { 16 MiB, 16 MiB }
    0xd2800060U, // mov x0, #3 (RLIMIT_STACK)
    0x910003e1U, // mov x1, sp
    0xd2801870U, // mov x16, #195 (setrlimit)
    0xd4001001U, // svc #0x80
    0x54000483U, // b.cc raise_succeeded (+144)
    0xf100041fU, // cmp x0, #1 (EPERM)
    0x540004a1U, // b.ne raise_wrong_errno (+148)
    0xd2800060U, // mov x0, #3 (RLIMIT_STACK)
    0x910003e1U, // mov x1, sp
    0xd2801850U, // mov x16, #194 (getrlimit)
    0xd4001001U, // svc #0x80
    0x540001c2U, // b.cs getrlimit_failed (+56)
    0xa9402be9U, // ldp x9, x10, [sp] -> rlim_cur, rlim_max
    0xd2a0100bU, // mov x11, #0x800000 (8 MiB)
    0xeb0b013fU, // cmp x9, x11
    0x540003e1U, // b.ne limits_changed (+124)
    0xeb0b015fU, // cmp x10, x11
    0x540003a1U, // b.ne limits_changed (+116)
    0xd2800100U, // mov x0, #8 (RLIMIT_NOFILE)
    0x910003e1U, // mov x1, sp
    0xd2801870U, // mov x16, #195 (setrlimit)
    0xd4001001U, // svc #0x80
    0x54000363U, // b.cc nofile_succeeded (+108)
    0xd2800030U, // mov x16, #1 (exit) -> exit(errno of RLIMIT_NOFILE)
    0xd4001001U, // svc #0x80
    0xd2800c80U, // getrlimit_failed: mov x0, #100
    0xd2800030U, // mov x16, #1 (exit)
    0xd4001001U, // svc #0x80
    0xd2800ca0U, // wrong_limits: mov x0, #101
    0xd2800030U, // mov x16, #1 (exit)
    0xd4001001U, // svc #0x80
    0xd2800cc0U, // restate_failed: mov x0, #102
    0xd2800030U, // mov x16, #1 (exit)
    0xd4001001U, // svc #0x80
    0xd2800ce0U, // lower_succeeded: mov x0, #103
    0xd2800030U, // mov x16, #1 (exit)
    0xd4001001U, // svc #0x80
    0xd2800d00U, // lower_wrong_errno: mov x0, #104
    0xd2800030U, // mov x16, #1 (exit)
    0xd4001001U, // svc #0x80
    0xd2800d20U, // raise_succeeded: mov x0, #105
    0xd2800030U, // mov x16, #1 (exit)
    0xd4001001U, // svc #0x80
    0xd2800d40U, // raise_wrong_errno: mov x0, #106
    0xd2800030U, // mov x16, #1 (exit)
    0xd4001001U, // svc #0x80
    0xd2800d60U, // limits_changed: mov x0, #107
    0xd2800030U, // mov x16, #1 (exit)
    0xd4001001U, // svc #0x80
    0xd2800d80U, // nofile_succeeded: mov x0, #108
    0xd2800030U, // mov x16, #1 (exit)
    0xd4001001U, // svc #0x80
};

// getdtablesize(); exit(errno). getdtablesize(2) reports the soft
// RLIMIT_NOFILE limit, and macho-run enforces no descriptor limit, so the
// call fails with ENOSYS (78) exactly as getrlimit(RLIMIT_NOFILE) does and a
// correct host exits 78. A getdtablesize that succeeds exits 100, so no table
// size can pass for the errno.
constexpr std::array<std::uint32_t, 8> kGetdtablesizeCode{
    0xd2800b30U, // mov x16, #89 (getdtablesize)
    0xd4001001U, // svc #0x80
    0x54000063U, // b.cc succeeded (+12)
    0xd2800030U, // mov x16, #1 (exit) -> exit(errno of getdtablesize)
    0xd4001001U, // svc #0x80
    0xd2800c80U, // succeeded: mov x0, #100
    0xd2800030U, // mov x16, #1 (exit)
    0xd4001001U, // svc #0x80
};

// fd = dup(1); close(1); write(fd, "hello", 5); again = dup(fd);
// exit(fd << 4 | again). dup(2) takes the lowest free descriptor, so the
// first copy of stdout is 3 and, once the guest has closed 1, the second copy
// reuses slot 1. A copy names the same stream, so "hello" still reaches the
// host stdout after the guest closes descriptor 1, and a correct host exits
// 49 (3 << 4 | 1). A failed first dup, close, write or second dup exits 100
// to 103 instead, so no errno can pass for a descriptor. The first copy is
// kept in x19 across the later calls.
constexpr std::array<std::uint32_t, 35> kDupStdoutCode{
    0xd2800020U, // mov x0, #1 (stdout)
    0xd2800530U, // mov x16, #41 (dup)
    0xd4001001U, // svc #0x80
    0x54000282U, // b.cs dup_failed (+80)
    0xaa0003f3U, // mov x19, x0 -> first copy of stdout
    0xd2800020U, // mov x0, #1 (stdout)
    0xd28000d0U, // mov x16, #6 (close)
    0xd4001001U, // svc #0x80
    0x54000242U, // b.cs close_failed (+72)
    0xaa1303e0U, // mov x0, x19 -> first copy
    0xd2880001U, // mov x1, #0x4000
    0xf2c00021U, // movk x1, #1, lsl #32 -> 0x100004000
    0xd28000a2U, // mov x2, #5
    0xd2800090U, // mov x16, #4 (write)
    0xd4001001U, // svc #0x80
    0x540001c2U, // b.cs write_failed (+56)
    0xaa1303e0U, // mov x0, x19 -> first copy
    0xd2800530U, // mov x16, #41 (dup)
    0xd4001001U, // svc #0x80
    0x540001a2U, // b.cs second_dup_failed (+52)
    0xaa131000U, // orr x0, x0, x19, lsl #4 -> first << 4 | second
    0xd2800030U, // mov x16, #1 (exit)
    0xd4001001U, // svc #0x80
    0xd2800c80U, // dup_failed: mov x0, #100
    0xd2800030U, // mov x16, #1 (exit)
    0xd4001001U, // svc #0x80
    0xd2800ca0U, // close_failed: mov x0, #101
    0xd2800030U, // mov x16, #1 (exit)
    0xd4001001U, // svc #0x80
    0xd2800cc0U, // write_failed: mov x0, #102
    0xd2800030U, // mov x16, #1 (exit)
    0xd4001001U, // svc #0x80
    0xd2800ce0U, // second_dup_failed: mov x0, #103
    0xd2800030U, // mov x16, #1 (exit)
    0xd4001001U, // svc #0x80
};

int usage() {
    std::cerr << "usage: macho_run_fixture "
                 "<hello|argc|echo|close-stdout|fstat-stdin|ioctl-stdin|writev-stdout|"
                 "readv-stdin|lseek-stdin|pread-stdin|fcntl-stdio|fcntl-setfl-stdio|"
                 "getrlimit-stack|setrlimit-stack|getdtablesize|dup-stdout> "
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
    } else if (kind == "pread-stdin") {
        bytes = image(kPreadStdinCode);
    } else if (kind == "fcntl-stdio") {
        bytes = image(kFcntlStdioCode);
    } else if (kind == "fcntl-setfl-stdio") {
        bytes = image(kFcntlSetflStdioCode);
    } else if (kind == "getrlimit-stack") {
        bytes = image(kGetrlimitStackCode);
    } else if (kind == "setrlimit-stack") {
        bytes = image(kSetrlimitStackCode);
    } else if (kind == "getdtablesize") {
        bytes = image(kGetdtablesizeCode);
    } else if (kind == "dup-stdout") {
        bytes = image(kDupStdoutCode);
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
