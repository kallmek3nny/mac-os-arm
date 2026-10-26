#include "macosarm/dynarmic_backend.hpp"
#include "macosarm/session.hpp"

#include <array>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <iterator>
#include <limits>
#include <map>
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
constexpr std::uint32_t kGuestErrnoEmfile = 24;
constexpr std::uint32_t kGuestErrnoEnotty = 25;
constexpr std::uint32_t kGuestErrnoEspipe = 29;
constexpr std::uint32_t kGuestErrnoEnotsup = 45;
constexpr std::uint32_t kGuestErrnoEnosys = 78;

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

// Move the file behind standard stream fd (0, 1 or 2) to stable storage for
// fsync(2), fsync_nocancel and fdatasync(2), reporting whether the host
// managed it. stdout and stderr flush their host C stream first, though
// write(2) already flushes after every guest write, so nothing the guest
// wrote can stay behind in stdio. stdin is never written through, and
// fflush on an input stream is undefined, so it goes straight to the host.
// data_only asks for fdatasync(2)'s data-only flush where the host has one;
// elsewhere the full flush, which covers it, runs instead.
bool sync_host_stream(std::int32_t fd, bool data_only) noexcept {
    if (fd < 0 || fd > 2) {
        return false;
    }
    if (fd != 0 && std::fflush(host_stream(fd)) != 0) {
        return false;
    }
#if defined(_WIN32)
    static_cast<void>(data_only);
    constexpr DWORD kStandardHandles[] = {STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE};
    const HANDLE handle = ::GetStdHandle(kStandardHandles[static_cast<std::size_t>(fd)]);
    // FlushFileBuffers needs write access, so a stdin handle opened only for
    // reading fails here rather than reporting a flush that never happened.
    return handle != nullptr && handle != INVALID_HANDLE_VALUE && ::FlushFileBuffers(handle) != 0;
#elif defined(__APPLE__)
    // The macOS SDK declares no fdatasync, so the full fsync, which covers
    // it, runs for both.
    static_cast<void>(data_only);
    return ::fsync(fd) == 0;
#else
    return (data_only ? ::fdatasync(fd) : ::fsync(fd)) == 0;
#endif
}

// The guest's stdin, stdout and stderr reach the host's, as raw bytes. Each
// open guest descriptor names one of those three host streams: the guest
// starts with descriptors 0, 1 and 2 naming them in order, and dup(2) and
// dup2(2) give a stream further descriptors that share its open file
// description. Any other descriptor reports EBADF, as does one the guest has
// closed.
class ConsoleHost final : public macosarm::DarwinHostServices {
    // One open guest descriptor. stream is the host standard stream (0, 1 or
    // 2) whose open file description the descriptor names. close_on_exec is
    // the descriptor's own FD_CLOEXEC flag, which a duplicate never shares.
    struct GuestDescriptor {
        std::int32_t stream;
        bool close_on_exec;
    };

    // The guest descriptor table, keyed by descriptor and holding only the
    // open ones, none of them negative. macho-run enforces no RLIMIT_NOFILE
    // limit, so every descriptor an int can name is in range and dup2(2) may
    // name one far above the rest. Keeping the table sparse means that costs
    // a single entry, never a slot for every descriptor below it.
    std::map<std::int32_t, GuestDescriptor> descriptors_;
    // Size in bytes of the main-thread stack the session maps for the guest.
    // That mapping never grows, so getrlimit(2) RLIMIT_STACK reports it as
    // both the soft and the hard limit.
    std::uint64_t stack_size_;
    // FG_NOSIGPIPE of each host standard stream's open file description,
    // indexed by stream (0, 1 or 2). fcntl(2) F_SETNOSIGPIPE through any
    // descriptor naming a stream changes that stream's entry, so every dup(2)
    // copy reports the same flag. Each starts clear, as for a fresh open.
    std::array<bool, 3> no_sigpipe_{};

    // The host standard stream guest descriptor fd names, or -1 when fd is
    // not an open guest descriptor.
    [[nodiscard]] std::int32_t stream_of(std::int32_t fd) const noexcept {
        const auto found = descriptors_.find(fd);
        return found == descriptors_.end() ? -1 : found->second.stream;
    }

    [[nodiscard]] bool is_open(std::int32_t fd) const noexcept {
        return stream_of(fd) >= 0;
    }

public:
    // stack_size must be the SessionConfig::stack_size the session maps, so
    // the limit the guest reads describes its real stack. A process inherits
    // its standard descriptors without FD_CLOEXEC.
    explicit ConsoleHost(std::uint64_t stack_size)
        : descriptors_{{0, {0, false}}, {1, {1, false}}, {2, {2, false}}},
          stack_size_(stack_size) {}

    // close(2) releases only the guest descriptor; the host stream it names
    // stays open for macho-run diagnostics and for any other guest descriptor
    // that still names it. A released or unknown descriptor reports EBADF, so
    // a second close never succeeds. Releasing a descriptor also drops its
    // close-on-exec flag, as XNU clears a released slot's descriptor flags,
    // so no stale flag outlives it, and frees it for a later dup(2).
    macosarm::HostCloseResult close(std::int32_t fd) override {
        if (descriptors_.erase(fd) == 0) {
            return {kGuestErrnoEbadf};
        }
        return {0};
    }

    // dup(2), as fdalloc and finishdup do together: the lowest free guest
    // descriptor now names the same standard stream as fd, so the two share
    // its file offset and status flags, while the new descriptor's own
    // close-on-exec flag starts clear. The table is ordered and holds no
    // negative descriptor, so the lowest free one is the first gap in its
    // keys counting up from 0. macho-run enforces no RLIMIT_NOFILE limit, so
    // dup(2) reports EMFILE only once no int could name a further
    // descriptor. On error nothing is allocated.
    macosarm::HostDuplicateResult duplicate(std::int32_t fd) override {
        const std::int32_t stream = stream_of(fd);
        if (stream < 0) {
            return {0, kGuestErrnoEbadf};
        }
        std::int64_t lowest = 0;
        for (const auto& entry : descriptors_) {
            if (entry.first != lowest) {
                break;
            }
            ++lowest;
        }
        if (lowest > std::numeric_limits<std::int32_t>::max()) {
            return {0, kGuestErrnoEmfile};
        }
        const auto descriptor = static_cast<std::int32_t>(lowest);
        descriptors_.emplace(descriptor, GuestDescriptor{stream, false});
        return {descriptor, 0};
    }

    // dup2(2), as XNU's dup2 does: a from the guest does not have open
    // reports EBADF. macho-run enforces no RLIMIT_NOFILE limit, so no to
    // that is not negative lies at or above it, and the sparse table records
    // even the highest one as a single entry. A to equal to from returns to
    // and changes nothing, not even its close-on-exec flag. Otherwise any
    // descriptor open at to is released, which for a guest descriptor never
    // fails, so there is no close error to discard, and to then names from's
    // standard stream with its own close-on-exec flag clear. On error no
    // descriptor changes.
    macosarm::HostDuplicateResult duplicate_to(std::int32_t from, std::int32_t to) override {
        const std::int32_t stream = stream_of(from);
        if (stream < 0 || to < 0) {
            return {0, kGuestErrnoEbadf};
        }
        if (to != from) {
            descriptors_.insert_or_assign(to, GuestDescriptor{stream, false});
        }
        return {to, 0};
    }

    // fcntl(2) F_DUPFD and F_DUPFD_CLOEXEC, as fdalloc and finishdup do
    // together: the lowest free guest descriptor at or above minimum now
    // names the same standard stream as fd, so the two share its file offset
    // and status flags, while the new descriptor's own close-on-exec flag is
    // set exactly when close_on_exec is true. The table is ordered and holds
    // no negative descriptor, so the lowest free one is the first gap in its
    // keys counting up from minimum, and it is never fd, which is open. A fd
    // the guest does not have open reports EBADF and a negative minimum,
    // which the dispatcher never passes, reports EINVAL as XNU does.
    // macho-run enforces no RLIMIT_NOFILE limit, so this reports EMFILE only
    // once no int at or above minimum could name a further descriptor. On
    // error nothing is allocated.
    macosarm::HostDuplicateResult duplicate_at_least(
        std::int32_t fd,
        std::int32_t minimum,
        bool close_on_exec) override {
        const std::int32_t stream = stream_of(fd);
        if (stream < 0) {
            return {0, kGuestErrnoEbadf};
        }
        if (minimum < 0) {
            return {0, macosarm::kDarwinErrnoEinval};
        }
        std::int64_t lowest = minimum;
        for (auto entry = descriptors_.lower_bound(minimum);
             entry != descriptors_.end() && entry->first == lowest;
             ++entry) {
            ++lowest;
        }
        if (lowest > std::numeric_limits<std::int32_t>::max()) {
            return {0, kGuestErrnoEmfile};
        }
        const auto descriptor = static_cast<std::int32_t>(lowest);
        descriptors_.emplace(descriptor, GuestDescriptor{stream, close_on_exec});
        return {descriptor, 0};
    }

    // fstat64(2) describes only an open guest descriptor, through the
    // standard stream it names. The host contributes just the file type;
    // ownership is the translated process's synthetic user, the permissions
    // are owner read/write, and every other field stays zero, so no host
    // inode, device, size or timestamp reaches the guest. A stream the host
    // cannot classify reports EIO rather than a guessed type.
    macosarm::HostStatResult file_status(std::int32_t fd) override {
        const std::int32_t stream = stream_of(fd);
        if (stream < 0) {
            return {{}, kGuestErrnoEbadf};
        }
        const std::uint16_t type = host_stream_type(stream);
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

    // ioctl(2) TIOCGETA and TIOCGWINSZ describe only an open guest
    // descriptor, through the standard stream it names. The host contributes
    // just whether the stream is an interactive terminal and its window size;
    // the dispatcher encodes a synthetic termios, so no host terminal settings
    // reach the guest. A redirected or piped stream reports ENOTTY, as
    // isatty(3) expects.
    macosarm::HostTerminalResult terminal_status(std::int32_t fd) override {
        const std::int32_t stream = stream_of(fd);
        if (stream < 0) {
            return {0, 0, 0, 0, kGuestErrnoEbadf};
        }
        const HostStreamTerminal terminal = host_stream_terminal(stream);
        if (!terminal.is_terminal) {
            return {0, 0, 0, 0, kGuestErrnoEnotty};
        }
        return {terminal.rows, terminal.columns, terminal.x_pixels, terminal.y_pixels, 0};
    }

    // lseek(2) describes only an open guest descriptor, through the standard
    // stream it names, so a dup(2) copy shares that stream's offset. As XNU
    // refuses a FIFO, socket or terminal with ESPIPE, so does a piped,
    // socket-backed or console stream here; only a stream redirected from or
    // to a file can seek. The host contributes just its C stream's logical
    // offset and the regular file's size, so no other host metadata reaches
    // the guest. A stream the host cannot classify or position reports EIO
    // rather than a guessed offset. A host C stream never holds a negative
    // position, so no stream claims a character device's negative-offset
    // allowance and the dispatcher fails a negative result with EINVAL
    // before anything is committed.
    macosarm::HostSeekResult seek_status(std::int32_t fd) override {
        const std::int32_t stream = stream_of(fd);
        if (stream < 0) {
            return {0, 0, 0, false, kGuestErrnoEbadf};
        }
        const std::uint16_t type = host_stream_type(stream);
        if (type == 0) {
            return {0, 0, 0, false, kGuestErrnoEio};
        }
        if (type == macosarm::kDarwinModeFifo || type == macosarm::kDarwinModeSocket ||
            host_stream_terminal(stream).is_terminal) {
            return {0, 0, 0, false, kGuestErrnoEspipe};
        }
        const std::int64_t offset = host_stream_offset(stream);
        if (offset < 0) {
            return {0, 0, 0, false, kGuestErrnoEio};
        }
        // An unknown size, as for a non-file character device, fails only
        // SEEK_END, like a failed vnode_size.
        const std::int64_t size = host_stream_size(stream);
        if (size < 0) {
            return {offset, 0, kGuestErrnoEio, false, 0};
        }
        return {offset, size, 0, false, 0};
    }

    // Commit a validated lseek(2) offset by repositioning the host C stream,
    // which also discards any stdin bytes stdio buffered from the old
    // position. If the host rejects the position, the guest sees EIO.
    macosarm::HostSetOffsetResult set_offset(std::int32_t fd, std::int64_t offset) override {
        const std::int32_t stream = stream_of(fd);
        if (stream < 0) {
            return {kGuestErrnoEbadf};
        }
        if (!seek_host_stream(stream, offset)) {
            return {kGuestErrnoEio};
        }
        return {0};
    }

    // pread(2) and pwrite(2) describe only an open guest descriptor, through
    // the standard stream it names, and only in the direction the guest can use
    // that stream: stdin is open just for reading and stdout and stderr just
    // for writing, so the other direction reports EBADF, as preparefileread and
    // preparefilewrite do. As valid_for_random_access refuses a FIFO or socket
    // with ESPIPE and a terminal with ENXIO, so does a piped, socket-backed or
    // console stream here; only a stream redirected from or to a file is
    // accessed at an offset. A stream the host cannot classify reports EIO
    // rather than a guessed type. As for lseek(2), no stream claims a character
    // device's negative-offset allowance, so the dispatcher fails a negative
    // offset with EINVAL before the host is asked to transfer anything.
    macosarm::HostRandomAccessResult random_access_status(
        std::int32_t fd,
        bool for_write) override {
        const std::int32_t stream = stream_of(fd);
        const bool usable = for_write ? (stream == 1 || stream == 2) : stream == 0;
        if (!usable) {
            return {false, kGuestErrnoEbadf};
        }
        const std::uint16_t type = host_stream_type(stream);
        if (type == 0) {
            return {false, kGuestErrnoEio};
        }
        if (type == macosarm::kDarwinModeFifo || type == macosarm::kDarwinModeSocket) {
            return {false, kGuestErrnoEspipe};
        }
        if (host_stream_terminal(stream).is_terminal) {
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
        const std::int32_t stream = stream_of(fd);
        if (stream != 0) {
            return {0, kGuestErrnoEbadf};
        }
        const std::int64_t received = read_host_stream_at(stream, bytes, offset);
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
        const std::int32_t stream = stream_of(fd);
        if (stream != 1 && stream != 2) {
            return {0, kGuestErrnoEbadf};
        }
        const std::int64_t written = write_host_stream_at(stream, bytes, offset);
        if (written < 0 || (written == 0 && !bytes.empty())) {
            return {0, kGuestErrnoEio};
        }
        return {static_cast<std::uint64_t>(written), 0};
    }

    // fcntl(2) F_GETFD, F_SETFD and F_GETFL describe only an open guest
    // descriptor. The close-on-exec flag is that descriptor's own, changed only
    // through F_SETFD and never shared with a dup(2) copy, while the status
    // flags belong to the standard stream it names. The access mode follows the
    // direction the guest can use that stream, as for pread(2) and pwrite(2):
    // stdin is open just for reading and stdout and stderr just for writing.
    // macho-run never puts a stream in nonblocking, asynchronous or synchronous
    // mode, so of the host's status flags only O_APPEND can reach the guest, on
    // a POSIX host whose descriptor really appends every write. A host that
    // cannot report its flags reports EIO rather than guessed ones.
    macosarm::HostDescriptorFlagsResult descriptor_flags(std::int32_t fd) override {
        const std::int32_t stream = stream_of(fd);
        if (stream < 0) {
            return {false, 0, kGuestErrnoEbadf};
        }
        std::uint32_t status_flags =
            stream == 0 ? macosarm::kDarwinOpenReadOnly : macosarm::kDarwinOpenWriteOnly;
#if !defined(_WIN32)
        const int host_flags = ::fcntl(stream, F_GETFL);
        if (host_flags < 0) {
            return {false, 0, kGuestErrnoEio};
        }
        if ((host_flags & O_APPEND) != 0) {
            status_flags |= macosarm::kDarwinOpenAppend;
        }
#endif
        const bool close_on_exec = descriptors_.at(fd).close_on_exec;
        return {close_on_exec, status_flags, 0};
    }

    // Set or clear guest descriptor fd's own close-on-exec flag for fcntl(2)
    // F_SETFD and ioctl(2) FIOCLEX and FIONCLEX; any other descriptor naming
    // the same stream keeps its own. The host descriptor's flags never
    // change, so macho-run's own streams stay as they were for its
    // diagnostics.
    macosarm::HostSetCloseOnExecResult set_close_on_exec(
        std::int32_t fd,
        bool close_on_exec) override {
        if (!is_open(fd)) {
            return {kGuestErrnoEbadf};
        }
        descriptors_.at(fd).close_on_exec = close_on_exec;
        return {0};
    }

    // fcntl(2) F_SETFL and ioctl(2) FIONBIO and FIOASYNC can only keep a
    // standard stream's status flags as descriptor_flags reports them. Any
    // change would have to reach the host's open file description, which
    // macho-run shares with its own diagnostics and with the process that
    // launched it, and the streams cannot honor nonblocking, asynchronous
    // or synchronous I/O. A request to change them reports ENOTSUP, never a
    // fabricated success, and leaves the flags as they were, so a later
    // F_GETFL still tells the truth.
    macosarm::HostSetStatusFlagsResult set_status_flags(
        std::int32_t fd,
        std::uint32_t status_flags) override {
        const macosarm::HostDescriptorFlagsResult current = descriptor_flags(fd);
        if (!current) {
            return {current.error};
        }
        if (status_flags != current.status_flags) {
            return {kGuestErrnoEnotsup};
        }
        return {0};
    }

    // Every standard stream does blocking I/O, so the FIONBIO step of
    // fcntl(2) F_SETFL and ioctl(2) FIONBIO can only confirm that mode;
    // asking for nonblocking I/O reports ENOTSUP rather than a mode the
    // stream would not honor.
    macosarm::HostFileModeResult set_nonblocking_io(
        std::int32_t fd,
        bool nonblocking) override {
        if (!is_open(fd)) {
            return {kGuestErrnoEbadf};
        }
        return {nonblocking ? kGuestErrnoEnotsup : 0U};
    }

    // No standard stream ever raises SIGIO, so the FIOASYNC step of fcntl(2)
    // F_SETFL and ioctl(2) FIOASYNC can only confirm ordinary I/O; asking
    // for asynchronous I/O reports ENOTSUP.
    macosarm::HostFileModeResult set_async_io(
        std::int32_t fd,
        bool asynchronous) override {
        if (!is_open(fd)) {
            return {kGuestErrnoEbadf};
        }
        return {asynchronous ? kGuestErrnoEnotsup : 0U};
    }

    // fcntl(2) F_SETNOSIGPIPE and F_GETNOSIGPIPE keep FG_NOSIGPIPE with the
    // open file description, which for a guest descriptor is the standard
    // stream it names: setting it through one descriptor shows through every
    // dup(2) copy of that stream, while another stream keeps its own flag.
    // Every flag starts clear, as for a freshly opened file. Only the guest's
    // view changes; the host stream and macho-run's own diagnostics are never
    // touched, and a write keeps reporting failures exactly as before.
    macosarm::HostSetNoSigpipeResult set_no_sigpipe(
        std::int32_t fd,
        bool enabled) override {
        const std::int32_t stream = stream_of(fd);
        if (stream < 0) {
            return {kGuestErrnoEbadf};
        }
        no_sigpipe_.at(static_cast<std::size_t>(stream)) = enabled;
        return {0};
    }

    macosarm::HostNoSigpipeResult no_sigpipe(std::int32_t fd) override {
        const std::int32_t stream = stream_of(fd);
        if (stream < 0) {
            return {false, kGuestErrnoEbadf};
        }
        return {no_sigpipe_.at(static_cast<std::size_t>(stream)), 0};
    }

    // fsync(2), fsync_nocancel and fdatasync(2), as fsync_common does: a
    // descriptor the guest does not have open reports EBADF. fp_getfvp
    // accepts only a vnode, so a standard stream backed by a pipe or socket
    // reports ENOTSUP. A terminal is a character device, whose VNOP_FSYNC
    // succeeds without flushing anything, so it reports success without
    // asking the host, which may refuse to sync a terminal. A regular file,
    // directory or block device is flushed through the host, data_only
    // choosing fdatasync(2)'s data-only flush, and a host failure reports
    // EIO, leaving the descriptor open. A stream the host cannot classify
    // names no file the host could flush, so it reports EIO too rather than
    // a fabricated success.
    macosarm::HostSyncResult synchronize_file(
        std::int32_t fd,
        bool data_only) override {
        const std::int32_t stream = stream_of(fd);
        if (stream < 0) {
            return {kGuestErrnoEbadf};
        }
        switch (host_stream_type(stream)) {
        case macosarm::kDarwinModeFifo:
        case macosarm::kDarwinModeSocket:
            return {kGuestErrnoEnotsup};
        case macosarm::kDarwinModeCharDevice:
            return {0};
        case macosarm::kDarwinModeRegular:
        case macosarm::kDarwinModeDirectory:
        case macosarm::kDarwinModeBlockDevice:
            return {sync_host_stream(stream, data_only) ? 0U : kGuestErrnoEio};
        default:
            return {kGuestErrnoEio};
        }
    }

    // Like a canonical-mode terminal read, return after a newline, a full
    // buffer or end-of-file rather than blocking until the buffer fills.
    // A zero-length request only validates the descriptor and consumes nothing.
    macosarm::HostReadResult read(
        std::int32_t fd,
        std::span<std::byte> bytes) override {
        if (stream_of(fd) != 0) {
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
        // Only a descriptor naming stdout or stderr reaches a host stream.
        // Once the guest closes one, its writes report EBADF like any other
        // unknown descriptor, while a dup(2) copy still reaches the stream.
        const std::int32_t named = stream_of(fd);
        std::FILE* const stream = named == 1 ? stdout : named == 2 ? stderr : nullptr;
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

    // getrlimit(2) reports only a limit the session really imposes on the
    // guest. RLIMIT_STACK is the fixed main-thread stack mapping, reported as
    // both the soft and the hard limit and capped at RLIM_INFINITY so the
    // dispatcher's contract holds. RLIMIT_NOFILE is RLIM_INFINITY for both:
    // the sparse descriptor table bounds descriptors only by the int range,
    // and with no maxfilesperproc sysctl modeled an unlimited soft limit is
    // exactly what getdtablesize(2) and fdalloc cap at INT_MAX, the bound
    // dup(2), dup2(2) and fcntl(2) F_DUPFD enforce here. Reporting it lets
    // F_DUPFD consult the limit as XNU does instead of failing for every
    // guest. No other resource is enforced, so each reports ENOSYS rather
    // than a fabricated limit.
    macosarm::HostResourceLimitResult resource_limit(std::uint32_t resource) override {
        if (resource == macosarm::kDarwinRlimitStack) {
            const std::uint64_t limit = stack_size_ < macosarm::kDarwinRlimInfinity
                                            ? stack_size_
                                            : macosarm::kDarwinRlimInfinity;
            return {limit, limit, 0};
        }
        if (resource == macosarm::kDarwinRlimitNofile) {
            return {macosarm::kDarwinRlimInfinity, macosarm::kDarwinRlimInfinity, 0};
        }
        return {0, 0, kGuestErrnoEnosys};
    }

    // setrlimit(2) changes only a limit the session really imposes. The
    // dispatcher has already refused raising either RLIMIT_STACK limit above
    // the fixed main-thread stack mapping with EPERM, so a request reaching
    // here either restates that limit or lowers it. Restating it changes
    // nothing and succeeds. Lowering it would need the stack beyond the new
    // soft limit made inaccessible, as XNU's dosetrlimit protects it, and the
    // session's mapping cannot shrink, so the request reports EINVAL as XNU
    // does when the stack protection cannot change, and the previous limits
    // stay in effect. RLIMIT_NOFILE reads as RLIM_INFINITY because the sparse
    // descriptor table enforces no limit, and the table cannot start
    // enforcing one, so a request for it reports ENOSYS rather than a limit
    // dup(2), dup2(2) and fcntl(2) F_DUPFD would ignore. No other resource is
    // enforced, so each reports ENOSYS, matching getrlimit(2).
    macosarm::HostSetResourceLimitResult set_resource_limit(
        std::uint32_t resource,
        std::uint64_t soft_limit,
        std::uint64_t hard_limit) override {
        if (resource != macosarm::kDarwinRlimitStack) {
            return {kGuestErrnoEnosys};
        }
        const std::uint64_t limit = stack_size_ < macosarm::kDarwinRlimInfinity
                                        ? stack_size_
                                        : macosarm::kDarwinRlimInfinity;
        if (soft_limit != limit || hard_limit != limit) {
            return {macosarm::kDarwinErrnoEinval};
        }
        return {0};
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
    macosarm::SessionConfig config{};
    config.instruction_budget = budget;
    config.startup.arguments = std::span<const std::string_view>(arguments);
    // The host reports RLIMIT_STACK from the very stack mapping the session
    // creates, so it is built only after the session config is final.
    ConsoleHost host(config.stack_size);

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
