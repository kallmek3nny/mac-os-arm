#include "macosarm/dynarmic_backend.hpp"
#include "macosarm/session.hpp"

#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <iterator>
#include <span>
#include <string_view>
#include <system_error>
#include <vector>

// Host services: getentropy(2) reads only the host operating system's CSPRNG,
// fstat64(2) asks the host only for a standard stream's file type, ioctl(2)
// asks only whether a standard stream is a terminal and its size, lseek(2)
// asks only for a redirected standard stream's offset and file size, and
// pread(2) and pwrite(2) reach only the regular file behind a redirected
// standard stream.
#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <bcrypt.h>
#else
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace {

// XNU bsd/sys/errno.h values reported to the guest, never host errno values.
constexpr std::uint32_t kGuestErrnoEio = 5;
constexpr std::uint32_t kGuestErrnoEnxio = 6;
constexpr std::uint32_t kGuestErrnoEbadf = 9;
constexpr std::uint32_t kGuestErrnoEnotty = 25;
constexpr std::uint32_t kGuestErrnoEspipe = 29;

// st_blksize reported for every guest standard descriptor. Darwin libc sizes
// stdio buffers from it, so it must be positive; it describes no host file.
constexpr std::int32_t kGuestBlockSize = 4096;

// The Darwin S_IF* file type of host standard stream fd (0, 1 or 2), or 0
// when the host cannot classify it. Only the type comes from the host: a
// terminal is a character device, a pipe a FIFO and a redirected file a
// regular file, which is what Darwin libc checks to choose stdio buffering.
std::uint16_t host_stream_type(std::int32_t fd) noexcept {
    if (fd < 0 || fd > 2) {
        return 0;
    }
#if defined(_WIN32)
    constexpr DWORD kStandardHandles[] = {STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE};
    const HANDLE handle = ::GetStdHandle(kStandardHandles[static_cast<std::size_t>(fd)]);
    if (handle == nullptr || handle == INVALID_HANDLE_VALUE) {
        return 0;
    }
    switch (::GetFileType(handle)) {
    case FILE_TYPE_CHAR:
        return macosarm::kDarwinModeCharDevice;
    case FILE_TYPE_PIPE:
        return macosarm::kDarwinModeFifo;
    case FILE_TYPE_DISK:
        return macosarm::kDarwinModeRegular;
    default:
        return 0;
    }
#else
    struct stat host_status {};
    if (::fstat(fd, &host_status) != 0) {
        return 0;
    }
    const auto mode = host_status.st_mode;
    if (S_ISCHR(mode)) {
        return macosarm::kDarwinModeCharDevice;
    }
    if (S_ISFIFO(mode)) {
        return macosarm::kDarwinModeFifo;
    }
    if (S_ISREG(mode)) {
        return macosarm::kDarwinModeRegular;
    }
    if (S_ISDIR(mode)) {
        return macosarm::kDarwinModeDirectory;
    }
    if (S_ISBLK(mode)) {
        return macosarm::kDarwinModeBlockDevice;
    }
    if (S_ISSOCK(mode)) {
        return macosarm::kDarwinModeSocket;
    }
    return 0;
#endif
}

// What the host reveals about standard stream fd (0, 1 or 2) for ioctl(2):
// only whether it is an interactive terminal and that terminal's window size.
// No host terminal settings reach the guest. A dimension the host cannot
// report stays zero, as XNU reports for a never-sized terminal.
struct HostStreamTerminal {
    bool is_terminal{};
    std::uint16_t rows{};
    std::uint16_t columns{};
    std::uint16_t x_pixels{};
    std::uint16_t y_pixels{};
};

HostStreamTerminal host_stream_terminal(std::int32_t fd) noexcept {
    HostStreamTerminal terminal{};
    if (fd < 0 || fd > 2) {
        return terminal;
    }
#if defined(_WIN32)
    constexpr DWORD kStandardHandles[] = {STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE};
    const HANDLE handle = ::GetStdHandle(kStandardHandles[static_cast<std::size_t>(fd)]);
    if (handle == nullptr || handle == INVALID_HANDLE_VALUE) {
        return terminal;
    }
    // NUL is also a character device, so only a handle with a console mode
    // counts as a terminal. A console input handle has no screen buffer, so
    // stdin reports an unknown size.
    DWORD mode = 0;
    if (::GetFileType(handle) != FILE_TYPE_CHAR || ::GetConsoleMode(handle, &mode) == 0) {
        return terminal;
    }
    terminal.is_terminal = true;
    CONSOLE_SCREEN_BUFFER_INFO info{};
    if (::GetConsoleScreenBufferInfo(handle, &info) != 0) {
        const int columns = static_cast<int>(info.srWindow.Right) - info.srWindow.Left + 1;
        const int rows = static_cast<int>(info.srWindow.Bottom) - info.srWindow.Top + 1;
        if (columns > 0 && rows > 0 && columns <= 0xffff && rows <= 0xffff) {
            terminal.columns = static_cast<std::uint16_t>(columns);
            terminal.rows = static_cast<std::uint16_t>(rows);
        }
    }
#else
    if (::isatty(fd) != 1) {
        return terminal;
    }
    terminal.is_terminal = true;
    struct winsize window {};
    if (::ioctl(fd, TIOCGWINSZ, &window) == 0) {
        terminal.rows = static_cast<std::uint16_t>(window.ws_row);
        terminal.columns = static_cast<std::uint16_t>(window.ws_col);
        terminal.x_pixels = static_cast<std::uint16_t>(window.ws_xpixel);
        terminal.y_pixels = static_cast<std::uint16_t>(window.ws_ypixel);
    }
#endif
    return terminal;
}

// The host C stream behind standard descriptor fd (0, 1 or 2), or nullptr.
std::FILE* host_stream(std::int32_t fd) noexcept {
    switch (fd) {
    case 0:
        return stdin;
    case 1:
        return stdout;
    case 2:
        return stderr;
    default:
        return nullptr;
    }
}

// What the host reveals about standard stream fd (0, 1 or 2) for lseek(2):
// only the logical offset of its host C stream and the size of the regular
// file behind it. The C stream's offset already excludes bytes stdio has
// buffered but not yet handed to the guest, so a seek after a short read
// starts exactly where the guest stopped reading. Both helpers report -1
// when the host cannot report the value, never a guessed one.
std::int64_t host_stream_offset(std::int32_t fd) noexcept {
    std::FILE* const stream = host_stream(fd);
    if (stream == nullptr) {
        return -1;
    }
#if defined(_WIN32)
    return static_cast<std::int64_t>(::_ftelli64(stream));
#else
    return static_cast<std::int64_t>(::ftello(stream));
#endif
}

std::int64_t host_stream_size(std::int32_t fd) noexcept {
    if (fd < 0 || fd > 2) {
        return -1;
    }
#if defined(_WIN32)
    constexpr DWORD kStandardHandles[] = {STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE};
    const HANDLE handle = ::GetStdHandle(kStandardHandles[static_cast<std::size_t>(fd)]);
    LARGE_INTEGER size{};
    if (handle == nullptr || handle == INVALID_HANDLE_VALUE || ::GetFileSizeEx(handle, &size) == 0) {
        return -1;
    }
    return static_cast<std::int64_t>(size.QuadPart);
#else
    struct stat host_status {};
    if (::fstat(fd, &host_status) != 0 || !S_ISREG(host_status.st_mode)) {
        return -1;
    }
    return static_cast<std::int64_t>(host_status.st_size);
#endif
}

// Move host stream fd to byte offset from the start of its file, reporting
// whether the host accepted the new position. Only offsets the dispatcher
// has already validated reach here, so a negative one is refused outright.
bool seek_host_stream(std::int32_t fd, std::int64_t offset) noexcept {
    std::FILE* const stream = host_stream(fd);
    if (stream == nullptr || offset < 0) {
        return false;
    }
#if defined(_WIN32)
    return ::_fseeki64(stream, offset, SEEK_SET) == 0;
#else
    return ::fseeko(stream, static_cast<off_t>(offset), SEEK_SET) == 0;
#endif
}

#if defined(_WIN32)
// A positioned ReadFile or WriteFile on a synchronous handle starts at the
// OVERLAPPED offset but leaves the file pointer after the transfer, so the
// helpers below save the pointer first and restore it afterwards.
OVERLAPPED overlapped_at(std::int64_t offset) noexcept {
    OVERLAPPED at{};
    const auto position = static_cast<std::uint64_t>(offset);
    at.Offset = static_cast<DWORD>(position & 0xffffffffULL);
    at.OffsetHigh = static_cast<DWORD>(position >> 32U);
    return at;
}

DWORD clamp_transfer(std::size_t size) noexcept {
    return size < MAXDWORD ? static_cast<DWORD>(size) : MAXDWORD;
}
#endif

// pread(2) and pwrite(2) for standard stream fd. Each moves at most
// bytes.size() bytes at offset without moving the host descriptor's file
// offset, so the host C stream, and any stdin bytes stdio has buffered,
// resume exactly where the guest's read(2), write(2) and lseek(2) left
// them. Each reports the bytes transferred, or -1 when the host refused the
// transfer or could not restore its file pointer, never a guessed count.
// Only offsets the dispatcher has already validated reach here, so a
// negative one is refused outright.
std::int64_t read_host_stream_at(
    std::int32_t fd, std::span<std::byte> bytes, std::int64_t offset) noexcept {
    if (fd != 0 || offset < 0) {
        return -1;
    }
#if defined(_WIN32)
    const HANDLE handle = ::GetStdHandle(STD_INPUT_HANDLE);
    LARGE_INTEGER saved{};
    if (handle == nullptr || handle == INVALID_HANDLE_VALUE ||
        ::SetFilePointerEx(handle, LARGE_INTEGER{}, &saved, FILE_CURRENT) == 0) {
        return -1;
    }
    OVERLAPPED at = overlapped_at(offset);
    DWORD received = 0;
    const bool succeeded =
        ::ReadFile(handle, bytes.data(), clamp_transfer(bytes.size()), &received, &at) != 0;
    // A read at or past end-of-file reports ERROR_HANDLE_EOF, which pread(2)
    // sees as end-of-file rather than an error.
    const bool at_end = !succeeded && ::GetLastError() == ERROR_HANDLE_EOF;
    const bool restored = ::SetFilePointerEx(handle, saved, nullptr, FILE_BEGIN) != 0;
    if ((!succeeded && !at_end) || !restored) {
        return -1;
    }
    return at_end ? 0 : static_cast<std::int64_t>(received);
#else
    const ssize_t received =
        ::pread(fd, bytes.data(), bytes.size(), static_cast<off_t>(offset));
    return received < 0 ? -1 : static_cast<std::int64_t>(received);
#endif
}

std::int64_t write_host_stream_at(
    std::int32_t fd, std::span<const std::byte> bytes, std::int64_t offset) noexcept {
    if ((fd != 1 && fd != 2) || offset < 0) {
        return -1;
    }
    // Flush first so anything the host C stream still holds reaches the
    // file ahead of this write, in the order the guest issued them.
    if (std::fflush(host_stream(fd)) != 0) {
        return -1;
    }
#if defined(_WIN32)
    const HANDLE handle = ::GetStdHandle(fd == 1 ? STD_OUTPUT_HANDLE : STD_ERROR_HANDLE);
    LARGE_INTEGER saved{};
    if (handle == nullptr || handle == INVALID_HANDLE_VALUE ||
        ::SetFilePointerEx(handle, LARGE_INTEGER{}, &saved, FILE_CURRENT) == 0) {
        return -1;
    }
    OVERLAPPED at = overlapped_at(offset);
    DWORD written = 0;
    const bool succeeded =
        ::WriteFile(handle, bytes.data(), clamp_transfer(bytes.size()), &written, &at) != 0;
    const bool restored = ::SetFilePointerEx(handle, saved, nullptr, FILE_BEGIN) != 0;
    if (!succeeded || !restored) {
        return -1;
    }
    return static_cast<std::int64_t>(written);
#else
#if !defined(__APPLE__)
    // XNU's vn_write ignores O_APPEND for pwrite(2), but Linux appends to an
    // O_APPEND descriptor whatever the offset. Refuse rather than write
    // somewhere the guest did not ask.
    const int flags = ::fcntl(fd, F_GETFL);
    if (flags < 0 || (flags & O_APPEND) != 0) {
        return -1;
    }
#endif
    const ssize_t written =
        ::pwrite(fd, bytes.data(), bytes.size(), static_cast<off_t>(offset));
    return written < 0 ? -1 : static_cast<std::int64_t>(written);
#endif
}

// The guest's stdin, stdout and stderr reach the host's, as raw bytes. No
// other descriptor exists in the translated process yet, so those report
// EBADF, as does a standard descriptor after the guest has closed it.
class ConsoleHost final : public macosarm::DarwinHostServices {
    // Bit n is set while guest descriptor n (stdin, stdout, stderr) is open.
    unsigned open_descriptors_ = 0b111U;
    // Bit n is set while guest descriptor n has its close-on-exec flag set. A
    // process inherits its standard descriptors without FD_CLOEXEC.
    unsigned close_on_exec_descriptors_ = 0U;

    [[nodiscard]] bool is_open(std::int32_t fd) const noexcept {
        return fd >= 0 && fd <= 2 &&
               (open_descriptors_ & (1U << static_cast<unsigned>(fd))) != 0U;
    }

public:
    // close(2) releases only the guest's view of a standard descriptor; the
    // host's own streams stay open for macho-run diagnostics. A released or
    // unknown descriptor reports EBADF, so a second close never succeeds.
    // Releasing a descriptor also drops its close-on-exec flag, as XNU clears
    // a released slot's descriptor flags, so no stale flag outlives it.
    macosarm::HostCloseResult close(std::int32_t fd) override {
        if (!is_open(fd)) {
            return {kGuestErrnoEbadf};
        }
        const unsigned bit = 1U << static_cast<unsigned>(fd);
        open_descriptors_ &= ~bit;
        close_on_exec_descriptors_ &= ~bit;
        return {0};
    }

    // fstat64(2) describes only a standard descriptor the guest still has
    // open. The host contributes just the file type; ownership is the
    // translated process's synthetic user, the permissions are owner
    // read/write, and every other field stays zero, so no host inode, device,
    // size or timestamp reaches the guest. A stream the host cannot classify
    // reports EIO rather than a guessed type.
    macosarm::HostStatResult file_status(std::int32_t fd) override {
        if (!is_open(fd)) {
            return {{}, kGuestErrnoEbadf};
        }
        const std::uint16_t type = host_stream_type(fd);
        if (type == 0) {
            return {{}, kGuestErrnoEio};
        }
        macosarm::HostFileStatus status{};
        status.mode = static_cast<std::uint16_t>(type | 0600U);
        status.link_count = 1;
        status.user_id = macosarm::kDarwinSyntheticUserId;
        status.group_id = macosarm::kDarwinSyntheticGroupId;
        status.block_size = kGuestBlockSize;
        return {status, 0};
    }

    // ioctl(2) TIOCGETA and TIOCGWINSZ describe only a standard descriptor
    // the guest still has open. The host contributes just whether the stream
    // is an interactive terminal and its window size; the dispatcher encodes
    // a synthetic termios, so no host terminal settings reach the guest. A
    // redirected or piped stream reports ENOTTY, as isatty(3) expects.
    macosarm::HostTerminalResult terminal_status(std::int32_t fd) override {
        if (!is_open(fd)) {
            return {0, 0, 0, 0, kGuestErrnoEbadf};
        }
        const HostStreamTerminal terminal = host_stream_terminal(fd);
        if (!terminal.is_terminal) {
            return {0, 0, 0, 0, kGuestErrnoEnotty};
        }
        return {terminal.rows, terminal.columns, terminal.x_pixels, terminal.y_pixels, 0};
    }

    // lseek(2) describes only a standard descriptor the guest still has open.
    // As XNU refuses a FIFO, socket or terminal with ESPIPE, so does a piped,
    // socket-backed or console stream here; only a stream redirected from or
    // to a file can seek. The host contributes just its C stream's logical
    // offset and the regular file's size, so no other host metadata reaches
    // the guest. A stream the host cannot classify or position reports EIO
    // rather than a guessed offset. A host C stream never holds a negative
    // position, so no stream claims a character device's negative-offset
    // allowance and the dispatcher fails a negative result with EINVAL
    // before anything is committed.
    macosarm::HostSeekResult seek_status(std::int32_t fd) override {
        if (!is_open(fd)) {
            return {0, 0, 0, false, kGuestErrnoEbadf};
        }
        const std::uint16_t type = host_stream_type(fd);
        if (type == 0) {
            return {0, 0, 0, false, kGuestErrnoEio};
        }
        if (type == macosarm::kDarwinModeFifo || type == macosarm::kDarwinModeSocket ||
            host_stream_terminal(fd).is_terminal) {
            return {0, 0, 0, false, kGuestErrnoEspipe};
        }
        const std::int64_t offset = host_stream_offset(fd);
        if (offset < 0) {
            return {0, 0, 0, false, kGuestErrnoEio};
        }
        // An unknown size, as for a non-file character device, fails only
        // SEEK_END, like a failed vnode_size.
        const std::int64_t size = host_stream_size(fd);
        if (size < 0) {
            return {offset, 0, kGuestErrnoEio, false, 0};
        }
        return {offset, size, 0, false, 0};
    }

    // Commit a validated lseek(2) offset by repositioning the host C stream,
    // which also discards any stdin bytes stdio buffered from the old
    // position. If the host rejects the position, the guest sees EIO.
    macosarm::HostSetOffsetResult set_offset(std::int32_t fd, std::int64_t offset) override {
        if (!is_open(fd)) {
            return {kGuestErrnoEbadf};
        }
        if (!seek_host_stream(fd, offset)) {
            return {kGuestErrnoEio};
        }
        return {0};
    }

    // pread(2) and pwrite(2) describe only a standard descriptor the guest
    // still has open, and only in the direction the guest can use it: stdin
    // is open just for reading and stdout and stderr just for writing, so the
    // other direction reports EBADF, as preparefileread and preparefilewrite
    // do. As valid_for_random_access refuses a FIFO or socket with ESPIPE and
    // a terminal with ENXIO, so does a piped, socket-backed or console stream
    // here; only a stream redirected from or to a file is accessed at an
    // offset. A stream the host cannot classify reports EIO rather than a
    // guessed type. As for lseek(2), no stream claims a character device's
    // negative-offset allowance, so the dispatcher fails a negative offset
    // with EINVAL before the host is asked to transfer anything.
    macosarm::HostRandomAccessResult random_access_status(
        std::int32_t fd,
        bool for_write) override {
        const bool usable = for_write ? (fd == 1 || fd == 2) : fd == 0;
        if (!usable || !is_open(fd)) {
            return {false, kGuestErrnoEbadf};
        }
        const std::uint16_t type = host_stream_type(fd);
        if (type == 0) {
            return {false, kGuestErrnoEio};
        }
        if (type == macosarm::kDarwinModeFifo || type == macosarm::kDarwinModeSocket) {
            return {false, kGuestErrnoEspipe};
        }
        if (host_stream_terminal(fd).is_terminal) {
            return {false, kGuestErrnoEnxio};
        }
        return {false, 0};
    }

    // Read stdin's file at offset for pread(2) without moving its host file
    // offset or disturbing bytes stdio has buffered for read(2). A host
    // failure reports EIO; a successful zero-byte result is end-of-file.
    macosarm::HostReadResult read_at(
        std::int32_t fd,
        std::span<std::byte> bytes,
        std::int64_t offset) override {
        if (fd != 0 || !is_open(fd)) {
            return {0, kGuestErrnoEbadf};
        }
        const std::int64_t received = read_host_stream_at(fd, bytes, offset);
        if (received < 0) {
            return {0, kGuestErrnoEio};
        }
        return {static_cast<std::uint64_t>(received), 0};
    }

    // Write stdout's or stderr's file at offset for pwrite(2) without moving
    // its host file offset. As for write(2), a host that stores none of a
    // nonempty request reports EIO.
    macosarm::HostWriteResult write_at(
        std::int32_t fd,
        std::span<const std::byte> bytes,
        std::int64_t offset) override {
        if ((fd != 1 && fd != 2) || !is_open(fd)) {
            return {0, kGuestErrnoEbadf};
        }
        const std::int64_t written = write_host_stream_at(fd, bytes, offset);
        if (written < 0 || (written == 0 && !bytes.empty())) {
            return {0, kGuestErrnoEio};
        }
        return {static_cast<std::uint64_t>(written), 0};
    }

    // fcntl(2) F_GETFD, F_SETFD and F_GETFL describe only a standard
    // descriptor the guest still has open. The close-on-exec flag is the
    // guest's own, changed only through F_SETFD. The access mode follows the
    // direction the guest can use the stream, as for pread(2) and pwrite(2):
    // stdin is open just for reading and stdout and stderr just for writing.
    // macho-run never puts a stream in nonblocking, asynchronous or
    // synchronous mode, so of the host's status flags only O_APPEND can reach
    // the guest, on a POSIX host whose descriptor really appends every write.
    // A host that cannot report its flags reports EIO rather than guessed ones.
    macosarm::HostDescriptorFlagsResult descriptor_flags(std::int32_t fd) override {
        if (!is_open(fd)) {
            return {false, 0, kGuestErrnoEbadf};
        }
        std::uint32_t status_flags =
            fd == 0 ? macosarm::kDarwinOpenReadOnly : macosarm::kDarwinOpenWriteOnly;
#if !defined(_WIN32)
        const int host_flags = ::fcntl(fd, F_GETFL);
        if (host_flags < 0) {
            return {false, 0, kGuestErrnoEio};
        }
        if ((host_flags & O_APPEND) != 0) {
            status_flags |= macosarm::kDarwinOpenAppend;
        }
#endif
        const bool close_on_exec =
            (close_on_exec_descriptors_ & (1U << static_cast<unsigned>(fd))) != 0U;
        return {close_on_exec, status_flags, 0};
    }

    // Set or clear the guest's own close-on-exec flag for fcntl(2) F_SETFD.
    // The host descriptor's flags never change, so macho-run's own streams
    // stay as they were for its diagnostics.
    macosarm::HostSetCloseOnExecResult set_close_on_exec(
        std::int32_t fd,
        bool close_on_exec) override {
        if (!is_open(fd)) {
            return {kGuestErrnoEbadf};
        }
        const unsigned bit = 1U << static_cast<unsigned>(fd);
        if (close_on_exec) {
            close_on_exec_descriptors_ |= bit;
        } else {
            close_on_exec_descriptors_ &= ~bit;
        }
        return {0};
    }

    // Like a canonical-mode terminal read, return after a newline, a full
    // buffer or end-of-file rather than blocking until the buffer fills.
    // A zero-length request only validates the descriptor and consumes nothing.
    macosarm::HostReadResult read(
        std::int32_t fd,
        std::span<std::byte> bytes) override {
        if (fd != 0 || !is_open(fd)) {
            return {0, kGuestErrnoEbadf};
        }
        std::size_t received = 0;
        while (received < bytes.size()) {
            const int value = std::fgetc(stdin);
            if (value == EOF) {
                break;
            }
            bytes[received++] = static_cast<std::byte>(static_cast<unsigned char>(value));
            if (value == '\n') {
                break;
            }
        }
        const bool failed = received == 0 && !bytes.empty() && std::ferror(stdin) != 0;
        // Keep end-of-file non-sticky, like a terminal after an EOF keystroke.
        std::clearerr(stdin);
        if (failed) {
            return {0, kGuestErrnoEio};
        }
        return {received, 0};
    }

    macosarm::HostWriteResult write(
        std::int32_t fd,
        std::span<const std::byte> bytes) override {
        // Once the guest closes stdout or stderr, its writes no longer reach
        // the host stream and report EBADF like any other unknown descriptor.
        std::FILE* const stream =
            !is_open(fd) ? nullptr : fd == 1 ? stdout : fd == 2 ? stderr : nullptr;
        if (stream == nullptr) {
            return {0, kGuestErrnoEbadf};
        }
        const std::size_t written = std::fwrite(bytes.data(), 1, bytes.size(), stream);
        std::fflush(stream);
        if (written == 0 && !bytes.empty()) {
            return {0, kGuestErrnoEio};
        }
        return {written, 0};
    }

    // getentropy(2) bytes come only from the host operating system's CSPRNG,
    // drawn in bounded chunks. Any host failure reports EIO; the dispatcher
    // then discards the staging buffer rather than copying partial output.
    macosarm::HostEntropyResult fill_entropy(std::span<std::byte> bytes) override {
        constexpr std::size_t kEntropyChunk = 256;
        std::size_t offset = 0;
        while (offset < bytes.size()) {
            const std::size_t remaining = bytes.size() - offset;
            const std::size_t count = remaining < kEntropyChunk ? remaining : kEntropyChunk;
#if defined(_WIN32)
            const NTSTATUS status = ::BCryptGenRandom(
                nullptr,
                reinterpret_cast<PUCHAR>(bytes.data() + offset),
                static_cast<ULONG>(count),
                BCRYPT_USE_SYSTEM_PREFERRED_RNG);
            if (!BCRYPT_SUCCESS(status)) {
                return {kGuestErrnoEio};
            }
#else
            if (::getentropy(bytes.data() + offset, count) != 0) {
                return {kGuestErrnoEio};
            }
#endif
            offset += count;
        }
        return {0};
    }

    // gettimeofday(2) time comes only from the host's real-time clock, as
    // whole seconds plus microseconds since the Unix epoch. Flooring keeps
    // the microsecond part in [0, 1000000) even for a pre-epoch host clock.
    macosarm::HostWallClockResult wall_clock() override {
        const auto since_epoch = std::chrono::time_point_cast<std::chrono::microseconds>(
            std::chrono::system_clock::now()).time_since_epoch();
        const auto whole = std::chrono::floor<std::chrono::seconds>(since_epoch);
        const auto fraction = since_epoch - whole;
        return {static_cast<std::int64_t>(whole.count()),
                static_cast<std::uint32_t>(fraction.count()), 0};
    }
};

int usage() {
    std::cerr << "usage: macho-run [--budget <instructions>] <arm64-mach-o> [guest-args...]\n";
    return 2;
}

} // namespace

int main(int argc, char** argv) {
    std::uint64_t budget = macosarm::SessionConfig{}.instruction_budget;
    int index = 1;
    if (index < argc && std::string_view(argv[index]) == "--budget") {
        if (index + 1 >= argc) {
            return usage();
        }
        const std::string_view text(argv[index + 1]);
        const char* const last = text.data() + text.size();
        const auto parsed = std::from_chars(text.data(), last, budget);
        if (parsed.ec != std::errc{} || parsed.ptr != last || budget == 0) {
            std::cerr << "error: invalid instruction budget '" << text << "'\n";
            return 2;
        }
        index += 2;
    }
    if (index >= argc) {
        return usage();
    }

    std::ifstream input(argv[index], std::ios::binary);
    if (!input) {
        std::cerr << "error: unable to open '" << argv[index] << "'\n";
        return 2;
    }
    const std::vector<char> raw((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    std::vector<std::byte> bytes;
    bytes.reserve(raw.size());
    for (const char value : raw) {
        bytes.push_back(static_cast<std::byte>(static_cast<unsigned char>(value)));
    }

    // The guest argv starts with the image path, like a native exec.
    const std::vector<std::string_view> arguments(argv + index, argv + argc);
    macosarm::DynarmicBackend backend;
    ConsoleHost host;
    macosarm::SessionConfig config{};
    config.instruction_budget = budget;
    config.startup.arguments = std::span<const std::string_view>(arguments);

    const auto result = macosarm::run_macho_session(bytes, backend, host, config);
    if (!result) {
        std::cerr << "macho-run: session error [" << macosarm::session_error_name(result.error) << ']';
        if (result.error == macosarm::SessionError::parse_failure) {
            std::cerr << " parse=" << macosarm::macho::error_name(result.parse_error);
        } else if (result.error == macosarm::SessionError::cpu_init_failure) {
            std::cerr << " cpu=" << macosarm::cpu_init_error_name(result.cpu_error);
        }
        std::cerr << '\n';
        return 1;
    }

    const macosarm::ProcessResult& process = result.process;
    if (process.reason == macosarm::ProcessStopReason::exited) {
        return process.exit_status;
    }
    // Any other stop means the guest did not finish; never report success.
    std::cerr << "macho-run: stop=" << macosarm::process_stop_reason_name(process.reason)
              << " instructions=" << process.instructions_executed
              << " pc=0x" << std::hex << result.final_state.pc << std::dec;
    if (process.syscall_error != macosarm::SyscallDispatchError::none) {
        std::cerr << " syscall=" << macosarm::syscall_dispatch_error_name(process.syscall_error);
    }
    std::cerr << '\n';
    return 1;
}
