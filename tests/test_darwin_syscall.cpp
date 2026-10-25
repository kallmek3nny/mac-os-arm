#include "macosarm/darwin_syscall.hpp"
#include "macosarm/mach_trap.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <span>
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

struct CaptureHost final : macosarm::DarwinHostServices {
    std::vector<std::byte> captured;
    std::vector<std::int32_t> fds;
    std::size_t largest_request{};
    std::uint32_t next_error{};
    std::uint64_t short_write{};
    bool violate_contract{};

    macosarm::HostWriteResult write(
        std::int32_t fd,
        std::span<const std::byte> bytes) override {
        fds.push_back(fd);
        largest_request = std::max(largest_request, bytes.size());

        if (next_error != 0) {
            const std::uint32_t error = next_error;
            next_error = 0;
            return {0, error};
        }
        if (violate_contract) {
            return {static_cast<std::uint64_t>(bytes.size()) + 1, 0};
        }

        std::size_t count = bytes.size();
        if (short_write != 0) {
            count = static_cast<std::size_t>(std::min<std::uint64_t>(short_write, bytes.size()));
            short_write = 0;
        }
        captured.insert(captured.end(), bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>(count));
        return {count, 0};
    }
};

// Scripted descriptor input for read(2). Only readable_fd has data; every
// other descriptor reports EBADF, including zero-length descriptor probes.
// Every host call is recorded so tests can prove input is never consumed
// when the guest destination is rejected first.
struct ReadHost final : macosarm::DarwinHostServices {
    std::vector<std::byte> input;
    std::size_t consumed{};
    std::vector<std::int32_t> fds;
    std::vector<std::size_t> requests;
    std::int32_t readable_fd{0};
    std::uint32_t next_error{};
    bool violate_contract{};

    macosarm::HostWriteResult write(
        std::int32_t fd,
        std::span<const std::byte> bytes) override {
        static_cast<void>(fd);
        static_cast<void>(bytes);
        return {0, macosarm::kDarwinErrnoEbadf};
    }

    macosarm::HostReadResult read(
        std::int32_t fd,
        std::span<std::byte> bytes) override {
        fds.push_back(fd);
        requests.push_back(bytes.size());
        if (fd != readable_fd) {
            return {0, macosarm::kDarwinErrnoEbadf};
        }
        if (next_error != 0) {
            const std::uint32_t error = next_error;
            next_error = 0;
            return {0, error};
        }
        if (violate_contract) {
            return {static_cast<std::uint64_t>(bytes.size()) + 1, 0};
        }
        const std::size_t count = std::min(bytes.size(), input.size() - consumed);
        std::copy_n(input.begin() + static_cast<std::ptrdiff_t>(consumed), count, bytes.begin());
        consumed += count;
        return {count, 0};
    }
};

// Scripted entropy source for getentropy(2). It fills a deterministic,
// position-dependent pattern so tests can prove exactly which guest bytes
// were written. Every host call is recorded so tests can prove no entropy is
// drawn when the size or the guest destination is rejected first.
struct EntropyHost final : macosarm::DarwinHostServices {
    std::vector<std::size_t> requests;
    std::uint32_t next_error{};

    static std::byte pattern(std::size_t index) {
        return static_cast<std::byte>((index * 7U + 3U) & 0xffU);
    }

    macosarm::HostWriteResult write(
        std::int32_t fd,
        std::span<const std::byte> bytes) override {
        static_cast<void>(fd);
        static_cast<void>(bytes);
        return {0, macosarm::kDarwinErrnoEbadf};
    }

    macosarm::HostEntropyResult fill_entropy(std::span<std::byte> bytes) override {
        requests.push_back(bytes.size());
        if (next_error != 0) {
            const std::uint32_t error = next_error;
            next_error = 0;
            // A failing source may leave partial output; the dispatcher must
            // never copy it to the guest.
            std::fill(bytes.begin(), bytes.end(), std::byte{0xee});
            return {error};
        }
        for (std::size_t i = 0; i < bytes.size(); ++i) {
            bytes[i] = pattern(i);
        }
        return {0};
    }
};

macosarm::ExecutionResult svc(std::uint32_t immediate = macosarm::kDarwinSvcImmediate) {
    return {
        macosarm::StopReason::supervisor_call,
        1,
        immediate,
        macosarm::VmError::none,
    };
}

bool carry_is_set(const macosarm::CpuState& state) {
    return (state.pstate & macosarm::kA64PstateCarry) != 0;
}

void load_readable(
    macosarm::GuestAddressSpace& vm,
    std::uint64_t base,
    std::span<const std::byte> bytes) {
    const std::uint64_t rounded =
        ((bytes.size() + macosarm::GuestAddressSpace::kPageSize - 1) /
         macosarm::GuestAddressSpace::kPageSize) * macosarm::GuestAddressSpace::kPageSize;
    expect(static_cast<bool>(vm.map(base, rounded, macosarm::Protection::read)), "test buffer maps");
    expect(static_cast<bool>(vm.load_bytes(base, bytes)), "test buffer loads");
}

// getentropy(2) fixtures: one writable guest page pre-filled with a sentinel
// so tests can prove exactly which guest bytes a dispatch wrote.
constexpr std::uint64_t kEntropyBase = 0x200000000ULL;
constexpr std::uint64_t kEntropyPage = macosarm::GuestAddressSpace::kPageSize;
constexpr std::byte kEntropySentinel{0xcc};

void map_entropy_page(macosarm::GuestAddressSpace& vm) {
    const std::vector<std::byte> sentinel(kEntropyPage, kEntropySentinel);
    expect(static_cast<bool>(vm.map(kEntropyBase, kEntropyPage,
                                    macosarm::Protection::read | macosarm::Protection::write)),
           "entropy buffer maps writable");
    expect(static_cast<bool>(vm.load_bytes(kEntropyBase, sentinel)), "entropy sentinel loads");
}

// True when every entropy-page byte from offset onward is still the sentinel.
bool entropy_sentinel_from(macosarm::GuestAddressSpace& vm, std::size_t offset) {
    std::vector<std::byte> bytes(kEntropyPage);
    if (!vm.read(kEntropyBase, bytes)) {
        return false;
    }
    return std::all_of(bytes.begin() + static_cast<std::ptrdiff_t>(offset), bytes.end(),
                       [](std::byte value) { return value == kEntropySentinel; });
}

// True when the first count guest bytes hold EntropyHost's fill pattern.
bool entropy_pattern_written(macosarm::GuestAddressSpace& vm, std::size_t count) {
    std::vector<std::byte> bytes(count);
    if (!vm.read(kEntropyBase, bytes)) {
        return false;
    }
    for (std::size_t i = 0; i < count; ++i) {
        if (bytes[i] != EntropyHost::pattern(i)) {
            return false;
        }
    }
    return true;
}

macosarm::SyscallDispatchResult run_getentropy(
    macosarm::GuestAddressSpace& vm,
    macosarm::DarwinHostServices& host,
    macosarm::CpuState& state,
    std::uint64_t address,
    std::uint64_t size,
    bool preset_carry) {
    state = {};
    state.x[0] = address;
    state.x[1] = size;
    state.x[16] = macosarm::kDarwinSysGetentropy;
    state.pstate = preset_carry ? macosarm::kA64PstateCarry : 0U;
    return macosarm::dispatch_darwin_syscall(state, vm, svc(), host);
}

// Scripted wall clock for gettimeofday(2). Every host call is counted so
// tests can prove the clock is never read when the request fails closed or
// the timeval destination is rejected first.
struct ClockHost final : macosarm::DarwinHostServices {
    std::int64_t seconds{};
    std::uint32_t microseconds{};
    std::uint32_t next_error{};
    std::size_t calls{};

    macosarm::HostWriteResult write(
        std::int32_t fd,
        std::span<const std::byte> bytes) override {
        static_cast<void>(fd);
        static_cast<void>(bytes);
        return {0, macosarm::kDarwinErrnoEbadf};
    }

    macosarm::HostWallClockResult wall_clock() override {
        ++calls;
        if (next_error != 0) {
            const std::uint32_t error = next_error;
            next_error = 0;
            return {0, 0, error};
        }
        return {seconds, microseconds, 0};
    }
};

// gettimeofday(2) fixtures: one guest page pre-filled with a sentinel so
// tests can prove exactly which bytes each copyout wrote.
constexpr std::uint64_t kClockBase = 0xB00000000ULL;
constexpr std::uint64_t kClockPage = macosarm::GuestAddressSpace::kPageSize;
constexpr std::byte kClockSentinel{0xcc};

void map_clock_page(macosarm::GuestAddressSpace& vm, macosarm::Protection protection) {
    const std::vector<std::byte> sentinel(kClockPage, kClockSentinel);
    expect(static_cast<bool>(vm.map(kClockBase, kClockPage, protection)),
           "clock buffer maps");
    expect(static_cast<bool>(vm.load_bytes(kClockBase, sentinel)), "clock sentinel loads");
}

// Decode a little-endian guest integer of width bytes (at most 8). Returns
// false when any byte is unreadable.
bool read_guest_le(macosarm::GuestAddressSpace& vm,
                   std::uint64_t address,
                   std::size_t width,
                   std::uint64_t& value) {
    std::array<std::byte, 8> bytes{};
    if (width > bytes.size() ||
        !vm.read(address, std::span<std::byte>(bytes.data(), width))) {
        return false;
    }
    value = 0;
    for (std::size_t i = 0; i < width; ++i) {
        value |= static_cast<std::uint64_t>(std::to_integer<unsigned char>(bytes[i]))
                 << (8U * i);
    }
    return true;
}

// True when count guest bytes starting at address all still hold the sentinel.
bool clock_sentinel_at(macosarm::GuestAddressSpace& vm,
                       std::uint64_t address,
                       std::size_t count) {
    std::vector<std::byte> bytes(count);
    if (!vm.read(address, bytes)) {
        return false;
    }
    return std::all_of(bytes.begin(), bytes.end(),
                       [](std::byte value) { return value == kClockSentinel; });
}

macosarm::SyscallDispatchResult run_gettimeofday(
    macosarm::GuestAddressSpace& vm,
    macosarm::DarwinHostServices& host,
    macosarm::CpuState& state,
    std::uint64_t timeval_address,
    std::uint64_t timezone_address,
    std::uint64_t absolute_time_address) {
    state = {};
    state.x[0] = timeval_address;
    state.x[1] = timezone_address;
    state.x[2] = absolute_time_address;
    state.x[16] = macosarm::kDarwinSysGettimeofday;
    // Preset carry so every success test proves the dispatcher clears it.
    state.pstate = macosarm::kA64PstateCarry;
    return macosarm::dispatch_darwin_syscall(state, vm, svc(), host);
}

// Scripted resource limits for getrlimit(2). Every host query is recorded so
// tests can prove out-of-range resources and rejected destinations never
// reach the host, and that _RLIMIT_POSIX_FLAG is stripped before it does.
struct LimitHost final : macosarm::DarwinHostServices {
    std::uint64_t soft_limit{};
    std::uint64_t hard_limit{};
    std::uint32_t next_error{};
    std::vector<std::uint32_t> queries;

    macosarm::HostWriteResult write(
        std::int32_t fd,
        std::span<const std::byte> bytes) override {
        static_cast<void>(fd);
        static_cast<void>(bytes);
        return {0, macosarm::kDarwinErrnoEbadf};
    }

    macosarm::HostResourceLimitResult resource_limit(std::uint32_t resource) override {
        queries.push_back(resource);
        if (next_error != 0) {
            const std::uint32_t error = next_error;
            next_error = 0;
            return {0, 0, error};
        }
        return {soft_limit, hard_limit, 0};
    }

    // setrlimit(2) commits, recorded as (resource, soft, hard) so tests can
    // prove rejected requests never reach the host. A successful commit
    // replaces the scripted limits so a later getrlimit sees the new values.
    struct Commit {
        std::uint32_t resource{};
        std::uint64_t soft{};
        std::uint64_t hard{};

        bool operator==(const Commit&) const = default;
    };
    std::vector<Commit> commits;
    std::uint32_t commit_error{};

    macosarm::HostSetResourceLimitResult set_resource_limit(
        std::uint32_t resource,
        std::uint64_t soft,
        std::uint64_t hard) override {
        commits.push_back({resource, soft, hard});
        if (commit_error != 0) {
            const std::uint32_t error = commit_error;
            commit_error = 0;
            return {error};
        }
        soft_limit = soft;
        hard_limit = hard;
        return {};
    }
};

// Store a little-endian LP64 struct rlimit { rlim_cur; rlim_max; } at address.
bool write_guest_rlimit(macosarm::GuestAddressSpace& vm,
                        std::uint64_t address,
                        std::uint64_t soft,
                        std::uint64_t hard) {
    std::vector<std::byte> bytes(macosarm::kDarwinRlimitSize);
    for (std::size_t i = 0; i < 8U; ++i) {
        bytes[i] = static_cast<std::byte>((soft >> (8U * i)) & 0xffU);
        bytes[8U + i] = static_cast<std::byte>((hard >> (8U * i)) & 0xffU);
    }
    return static_cast<bool>(vm.load_bytes(address, bytes));
}

macosarm::SyscallDispatchResult run_setrlimit(
    macosarm::GuestAddressSpace& vm,
    macosarm::DarwinHostServices& host,
    macosarm::CpuState& state,
    std::uint64_t which,
    std::uint64_t limit_address) {
    state = {};
    state.x[0] = which;
    state.x[1] = limit_address;
    state.x[16] = macosarm::kDarwinSysSetrlimit;
    // Preset carry so every success test proves the dispatcher clears it.
    state.pstate = macosarm::kA64PstateCarry;
    return macosarm::dispatch_darwin_syscall(state, vm, svc(), host);
}

macosarm::SyscallDispatchResult run_getrlimit(
    macosarm::GuestAddressSpace& vm,
    macosarm::DarwinHostServices& host,
    macosarm::CpuState& state,
    std::uint64_t which,
    std::uint64_t limit_address) {
    state = {};
    state.x[0] = which;
    state.x[1] = limit_address;
    state.x[16] = macosarm::kDarwinSysGetrlimit;
    // Preset carry so every success test proves the dispatcher clears it.
    state.pstate = macosarm::kA64PstateCarry;
    return macosarm::dispatch_darwin_syscall(state, vm, svc(), host);
}

// Scripted descriptor table for close(2). Every host close is recorded so
// tests can prove negative descriptors never reach the host and that a
// descriptor is released at most once, even when the host reports an error
// after releasing it (as XNU does when the final closef fails).
struct CloseHost final : macosarm::DarwinHostServices {
    std::vector<std::int32_t> open_fds;
    std::vector<std::int32_t> requests;
    std::uint32_t release_error{};

    macosarm::HostWriteResult write(
        std::int32_t fd,
        std::span<const std::byte> bytes) override {
        static_cast<void>(fd);
        static_cast<void>(bytes);
        return {0, macosarm::kDarwinErrnoEbadf};
    }

    macosarm::HostCloseResult close(std::int32_t fd) override {
        requests.push_back(fd);
        const auto open = std::find(open_fds.begin(), open_fds.end(), fd);
        if (open == open_fds.end()) {
            return {macosarm::kDarwinErrnoEbadf};
        }
        open_fds.erase(open);
        const std::uint32_t error = release_error;
        release_error = 0;
        return {error};
    }
};

bool close_host_has_open(const CloseHost& host, std::int32_t fd) {
    return std::find(host.open_fds.begin(), host.open_fds.end(), fd) != host.open_fds.end();
}

macosarm::SyscallDispatchResult run_close(
    macosarm::DarwinHostServices& host,
    macosarm::CpuState& state,
    std::uint64_t syscall_number,
    std::uint64_t fd_register) {
    macosarm::GuestAddressSpace vm;
    state = {};
    state.x[0] = fd_register;
    state.x[16] = syscall_number;
    // Preset carry so every success test proves the dispatcher clears it.
    state.pstate = macosarm::kA64PstateCarry;
    return macosarm::dispatch_darwin_syscall(state, vm, svc(), host);
}

// Scripted descriptor metadata for fstat64(2). Only described_fd has a
// status; every other descriptor reports EBADF. Every host call is recorded
// so tests can prove negative descriptors never reach the host and that a
// host error or malformed status is never copied to the guest.
struct StatHost final : macosarm::DarwinHostServices {
    std::int32_t described_fd{3};
    macosarm::HostFileStatus status{};
    std::uint32_t next_error{};
    std::vector<std::int32_t> requests;

    macosarm::HostWriteResult write(
        std::int32_t fd,
        std::span<const std::byte> bytes) override {
        static_cast<void>(fd);
        static_cast<void>(bytes);
        return {0, macosarm::kDarwinErrnoEbadf};
    }

    macosarm::HostStatResult file_status(std::int32_t fd) override {
        requests.push_back(fd);
        if (next_error != 0) {
            const std::uint32_t error = next_error;
            next_error = 0;
            return {{}, error};
        }
        if (fd != described_fd) {
            return {{}, macosarm::kDarwinErrnoEbadf};
        }
        return {status, 0};
    }
};

// A regular file owned by the synthetic guest user. Every field holds a
// distinct value, including a negative st_dev and a pre-epoch birth time,
// so a misplaced, truncated, or sign-extended encoding is detectable.
macosarm::HostFileStatus sample_file_status() {
    macosarm::HostFileStatus status{};
    status.device = static_cast<std::int32_t>(0x81020304U);
    status.mode = static_cast<std::uint16_t>(macosarm::kDarwinModeRegular | 0644U);
    status.link_count = 2;
    status.inode = 0x0123456789abcdefULL;
    status.user_id = macosarm::kDarwinSyntheticUserId;
    status.group_id = macosarm::kDarwinSyntheticGroupId;
    status.special_device = 0x0a0b0c0d;
    status.access_time = {1700000000, 111111111};
    status.modification_time = {1700000001, 222222222};
    status.change_time = {1700000002, 333333333};
    status.birth_time = {-1, 999999999};
    status.size = 0x0000000100000fffLL;
    status.blocks = 0x2008;
    status.block_size = 4096;
    status.flags = 0x00008000U; // UF_HIDDEN
    return status;
}

// fstat64(2) fixtures: one guest page pre-filled with a sentinel so tests
// can prove the 144-byte record is written whole or not at all.
constexpr std::uint64_t kStatBase = 0xC00000000ULL;
constexpr std::uint64_t kStatPage = macosarm::GuestAddressSpace::kPageSize;
constexpr std::byte kStatSentinel{0xcc};

void map_stat_page(macosarm::GuestAddressSpace& vm, macosarm::Protection protection) {
    const std::vector<std::byte> sentinel(kStatPage, kStatSentinel);
    expect(static_cast<bool>(vm.map(kStatBase, kStatPage, protection)), "stat buffer maps");
    expect(static_cast<bool>(vm.load_bytes(kStatBase, sentinel)), "stat sentinel loads");
}

macosarm::SyscallDispatchResult run_fstat64(
    macosarm::GuestAddressSpace& vm,
    macosarm::DarwinHostServices& host,
    macosarm::CpuState& state,
    std::uint64_t fd_register,
    std::uint64_t stat_address) {
    state = {};
    state.x[0] = fd_register;
    state.x[1] = stat_address;
    state.x[16] = macosarm::kDarwinSysFstat64;
    // Preset carry so every success test proves the dispatcher clears it.
    state.pstate = macosarm::kA64PstateCarry;
    return macosarm::dispatch_darwin_syscall(state, vm, svc(), host);
}

// Scripted terminal state for ioctl(2). terminal_fd is a terminal with the
// scripted window size, file_fd is open but not a terminal (ENOTTY), and
// every other descriptor reports EBADF. Every host call is recorded so tests
// can prove negative descriptors and copyin faults never reach the host.
struct TerminalHost final : macosarm::DarwinHostServices {
    std::int32_t terminal_fd{0};
    std::int32_t file_fd{3};
    std::uint16_t rows{0x1234};
    std::uint16_t columns{0x5678};
    std::uint16_t x_pixels{0x9abc};
    std::uint16_t y_pixels{0xdef0};
    std::vector<std::int32_t> requests;

    macosarm::HostWriteResult write(
        std::int32_t fd,
        std::span<const std::byte> bytes) override {
        static_cast<void>(fd);
        static_cast<void>(bytes);
        return {0, macosarm::kDarwinErrnoEbadf};
    }

    macosarm::HostTerminalResult terminal_status(std::int32_t fd) override {
        requests.push_back(fd);
        if (fd == terminal_fd) {
            return {rows, columns, x_pixels, y_pixels, 0};
        }
        if (fd == file_fd) {
            return {0, 0, 0, 0, macosarm::kDarwinErrnoEnotty};
        }
        return {0, 0, 0, 0, macosarm::kDarwinErrnoEbadf};
    }

    // ioctl(2) FIOCLEX and FIONCLEX. terminal_fd and file_fd each keep their
    // own close-on-exec flag, starting clear; every other descriptor is
    // EBADF. A nonzero update_error fails the next update once and leaves the
    // flag unchanged. Every update request is recorded in call order.
    struct Update {
        std::int32_t fd{};
        bool close_on_exec{};

        friend bool operator==(const Update&, const Update&) = default;
    };

    bool terminal_close_on_exec{};
    bool file_close_on_exec{};
    std::uint32_t update_error{};
    std::vector<Update> updates;

    macosarm::HostSetCloseOnExecResult set_close_on_exec(
        std::int32_t fd,
        bool close_on_exec) override {
        updates.push_back({fd, close_on_exec});
        bool* const flag = fd == terminal_fd ? &terminal_close_on_exec
                           : fd == file_fd   ? &file_close_on_exec
                                             : nullptr;
        if (flag == nullptr) {
            return {macosarm::kDarwinErrnoEbadf};
        }
        if (update_error != 0) {
            const std::uint32_t failure = update_error;
            update_error = 0;
            return {failure};
        }
        *flag = close_on_exec;
        return {0};
    }
};

// ioctl(2) fixtures: one guest page pre-filled with a sentinel so tests can
// prove each record is written whole or not at all.
constexpr std::uint64_t kIoctlBase = 0xD00000000ULL;
constexpr std::uint64_t kIoctlPage = macosarm::GuestAddressSpace::kPageSize;
constexpr std::byte kIoctlSentinel{0xcc};

void map_ioctl_page(macosarm::GuestAddressSpace& vm, macosarm::Protection protection) {
    const std::vector<std::byte> sentinel(kIoctlPage, kIoctlSentinel);
    expect(static_cast<bool>(vm.map(kIoctlBase, kIoctlPage, protection)), "ioctl buffer maps");
    expect(static_cast<bool>(vm.load_bytes(kIoctlBase, sentinel)), "ioctl sentinel loads");
}

// True when every ioctl-page byte from offset onward is still the sentinel.
bool ioctl_sentinel_from(macosarm::GuestAddressSpace& vm, std::size_t offset) {
    std::vector<std::byte> bytes(kIoctlPage);
    if (!vm.read(kIoctlBase, bytes)) {
        return false;
    }
    return std::all_of(bytes.begin() + static_cast<std::ptrdiff_t>(offset), bytes.end(),
                       [](std::byte value) { return value == kIoctlSentinel; });
}

macosarm::SyscallDispatchResult run_ioctl(
    macosarm::GuestAddressSpace& vm,
    macosarm::DarwinHostServices& host,
    macosarm::CpuState& state,
    std::uint64_t fd_register,
    std::uint64_t command,
    std::uint64_t data_address) {
    state = {};
    state.x[0] = fd_register;
    state.x[1] = command;
    state.x[2] = data_address;
    state.x[16] = macosarm::kDarwinSysIoctl;
    // Preset carry so every success test proves the dispatcher clears it.
    state.pstate = macosarm::kA64PstateCarry;
    return macosarm::dispatch_darwin_syscall(state, vm, svc(), host);
}

// One committed lseek(2) offset, recorded in call order.
struct SeekCommit {
    std::int32_t fd{};
    std::int64_t offset{};
};

// Scripted seek state for lseek(2). file_fd is a regular file at the
// scripted offset and size, device_fd a character device whose offset may
// go negative, pipe_fd cannot seek (ESPIPE), and every other descriptor
// reports EBADF. Every host call is recorded so tests can prove negative
// descriptors never reach the host and a failed check commits nothing.
struct SeekHost final : macosarm::DarwinHostServices {
    std::int32_t file_fd{3};
    std::int32_t device_fd{4};
    std::int32_t pipe_fd{5};
    std::int64_t file_offset{0x100};
    std::int64_t file_size{0x1000};
    std::uint32_t size_error{0};
    std::int64_t device_offset{0};
    std::uint32_t commit_error{0};
    std::vector<std::int32_t> requests;
    std::vector<SeekCommit> commits;

    macosarm::HostWriteResult write(
        std::int32_t fd,
        std::span<const std::byte> bytes) override {
        static_cast<void>(fd);
        static_cast<void>(bytes);
        return {0, macosarm::kDarwinErrnoEbadf};
    }

    macosarm::HostSeekResult seek_status(std::int32_t fd) override {
        requests.push_back(fd);
        if (fd == file_fd) {
            return {file_offset, file_size, size_error, false, 0};
        }
        if (fd == device_fd) {
            return {device_offset, 0, 0, true, 0};
        }
        if (fd == pipe_fd) {
            return {0, 0, 0, false, macosarm::kDarwinErrnoEspipe};
        }
        return {0, 0, 0, false, macosarm::kDarwinErrnoEbadf};
    }

    macosarm::HostSetOffsetResult set_offset(std::int32_t fd, std::int64_t offset) override {
        commits.push_back({fd, offset});
        if (commit_error != 0) {
            return {commit_error};
        }
        if (fd == file_fd) {
            file_offset = offset;
            return {0};
        }
        if (fd == device_fd) {
            device_offset = offset;
            return {0};
        }
        return {macosarm::kDarwinErrnoEbadf};
    }
};

macosarm::SyscallDispatchResult run_lseek(
    macosarm::GuestAddressSpace& vm,
    macosarm::DarwinHostServices& host,
    macosarm::CpuState& state,
    std::uint64_t fd_register,
    std::uint64_t offset_register,
    std::uint64_t whence_register) {
    state = {};
    state.x[0] = fd_register;
    state.x[1] = offset_register;
    state.x[2] = whence_register;
    state.x[16] = macosarm::kDarwinSysLseek;
    // Preset carry so every success test proves the dispatcher clears it.
    state.pstate = macosarm::kA64PstateCarry;
    return macosarm::dispatch_darwin_syscall(state, vm, svc(), host);
}

// One host pread(2) or pwrite(2) transfer, recorded in call order.
struct PositionedTransfer {
    std::int32_t fd{};
    std::size_t size{};
    std::int64_t offset{};
};

// Scripted random-access descriptors for pread(2) and pwrite(2). file_fd is
// a regular file open for reading and writing over contents, read_only_fd a
// regular file over the same contents that is not open for writing,
// device_fd a character device that accepts negative offsets, pipe_fd a pipe
// (ESPIPE) and tty_fd a terminal (ENXIO); every other descriptor is EBADF.
// Device reads return an index pattern and device writes are captured
// without file storage, so offsets near INT64_MAX never allocate. A nonzero
// error fails the transfer at index error_at once, so tests can prove
// partial pwrite results. Every host call is recorded so tests can prove
// rejected requests transfer nothing and offsets reach the host unchanged.
struct RandomAccessHost final : macosarm::DarwinHostServices {
    std::int32_t file_fd{3};
    std::int32_t device_fd{4};
    std::int32_t read_only_fd{5};
    std::int32_t pipe_fd{6};
    std::int32_t tty_fd{7};
    std::vector<std::byte> contents;
    std::vector<std::byte> device_output;
    std::uint32_t error{};
    std::size_t error_at{};
    std::uint64_t short_count{};
    bool violate_contract{};
    std::vector<std::int32_t> requests;
    std::vector<PositionedTransfer> transfers;

    macosarm::HostWriteResult write(
        std::int32_t fd,
        std::span<const std::byte> bytes) override {
        static_cast<void>(fd);
        static_cast<void>(bytes);
        return {0, macosarm::kDarwinErrnoEbadf};
    }

    macosarm::HostRandomAccessResult random_access_status(
        std::int32_t fd,
        bool for_write) override {
        requests.push_back(fd);
        if (fd == file_fd || (fd == read_only_fd && !for_write)) {
            return {false, 0};
        }
        if (fd == device_fd) {
            return {true, 0};
        }
        if (fd == pipe_fd) {
            return {false, macosarm::kDarwinErrnoEspipe};
        }
        if (fd == tty_fd) {
            return {false, macosarm::kDarwinErrnoEnxio};
        }
        return {false, macosarm::kDarwinErrnoEbadf};
    }

    // Record one transfer and report the scripted failure due at its index.
    std::uint32_t record(std::int32_t fd, std::size_t size, std::int64_t offset) {
        transfers.push_back({fd, size, offset});
        if (error != 0 && transfers.size() == error_at + 1U) {
            const std::uint32_t failure = error;
            error = 0;
            return failure;
        }
        return 0;
    }

    macosarm::HostReadResult read_at(
        std::int32_t fd,
        std::span<std::byte> bytes,
        std::int64_t offset) override {
        if (const std::uint32_t failure = record(fd, bytes.size(), offset); failure != 0) {
            return {0, failure};
        }
        if (violate_contract) {
            return {static_cast<std::uint64_t>(bytes.size()) + 1U, 0};
        }
        if (fd == device_fd) {
            for (std::size_t i = 0; i < bytes.size(); ++i) {
                bytes[i] = static_cast<std::byte>((i * 5U + 1U) & 0xffU);
            }
            return {bytes.size(), 0};
        }
        if (offset < 0 || static_cast<std::uint64_t>(offset) >= contents.size()) {
            return {0, 0};
        }
        const auto start = static_cast<std::size_t>(offset);
        const std::size_t count = std::min(bytes.size(), contents.size() - start);
        std::copy_n(contents.begin() + static_cast<std::ptrdiff_t>(start), count, bytes.begin());
        return {count, 0};
    }

    macosarm::HostWriteResult write_at(
        std::int32_t fd,
        std::span<const std::byte> bytes,
        std::int64_t offset) override {
        if (const std::uint32_t failure = record(fd, bytes.size(), offset); failure != 0) {
            return {0, failure};
        }
        if (violate_contract) {
            return {static_cast<std::uint64_t>(bytes.size()) + 1U, 0};
        }
        std::size_t count = bytes.size();
        if (short_count != 0) {
            count = static_cast<std::size_t>(std::min<std::uint64_t>(short_count, count));
            short_count = 0;
        }
        if (fd == device_fd) {
            device_output.insert(device_output.end(), bytes.begin(),
                                 bytes.begin() + static_cast<std::ptrdiff_t>(count));
            return {count, 0};
        }
        const auto start = static_cast<std::size_t>(offset);
        if (contents.size() < start + count) {
            contents.resize(start + count);
        }
        std::copy_n(bytes.begin(), count, contents.begin() + static_cast<std::ptrdiff_t>(start));
        return {count, 0};
    }
};

// pread(2) and pwrite(2) fixtures: one guest page pre-filled with a sentinel
// so tests can prove exactly which guest bytes a pread wrote and that a
// pwrite only reads its source.
constexpr std::uint64_t kPositionedBase = 0xE00000000ULL;
constexpr std::uint64_t kPositionedPage = macosarm::GuestAddressSpace::kPageSize;
constexpr std::byte kPositionedSentinel{0xcc};

void map_positioned_page(macosarm::GuestAddressSpace& vm, macosarm::Protection protection) {
    const std::vector<std::byte> sentinel(kPositionedPage, kPositionedSentinel);
    expect(static_cast<bool>(vm.map(kPositionedBase, kPositionedPage, protection)),
           "positioned I/O buffer maps");
    expect(static_cast<bool>(vm.load_bytes(kPositionedBase, sentinel)),
           "positioned I/O sentinel loads");
}

// True when every positioned-page byte from offset onward is still the sentinel.
bool positioned_sentinel_from(macosarm::GuestAddressSpace& vm, std::size_t offset) {
    std::vector<std::byte> bytes(kPositionedPage);
    if (!vm.read(kPositionedBase, bytes)) {
        return false;
    }
    return std::all_of(bytes.begin() + static_cast<std::ptrdiff_t>(offset), bytes.end(),
                       [](std::byte value) { return value == kPositionedSentinel; });
}

// True when the guest bytes at kPositionedBase + offset equal expected.
bool positioned_bytes_at(macosarm::GuestAddressSpace& vm,
                         std::size_t offset,
                         std::span<const std::byte> expected) {
    std::vector<std::byte> bytes(expected.size());
    if (!vm.read(kPositionedBase + offset, bytes)) {
        return false;
    }
    return std::equal(bytes.begin(), bytes.end(), expected.begin(), expected.end());
}

std::vector<std::byte> text_bytes(const std::string& text) {
    std::vector<std::byte> bytes(text.size());
    std::transform(text.begin(), text.end(), bytes.begin(),
                   [](char c) { return static_cast<std::byte>(c); });
    return bytes;
}

macosarm::SyscallDispatchResult run_positioned(
    macosarm::GuestAddressSpace& vm,
    macosarm::DarwinHostServices& host,
    macosarm::CpuState& state,
    std::uint64_t syscall_number,
    std::uint64_t fd_register,
    std::uint64_t buffer_address,
    std::uint64_t nbyte,
    std::uint64_t offset_register) {
    state = {};
    state.x[0] = fd_register;
    state.x[1] = buffer_address;
    state.x[2] = nbyte;
    state.x[3] = offset_register;
    state.x[16] = syscall_number;
    // Preset carry so every success test proves the dispatcher clears it.
    state.pstate = macosarm::kA64PstateCarry;
    return macosarm::dispatch_darwin_syscall(state, vm, svc(), host);
}

// One fcntl(2) F_SETFD request that reached the host, recorded in call order.
struct CloseOnExecUpdate {
    std::int32_t fd{};
    bool close_on_exec{};
};

// Scripted guest descriptors for fcntl(2). Each entry of descriptors is an
// open descriptor with its own close-on-exec flag and its open file
// description's OFLAGS(f_flag) status flags; every other descriptor is
// EBADF. status_flags is reported verbatim, so tests can hand the
// dispatcher flags that break the host contract. A nonzero update_error
// fails the next set_close_on_exec once and leaves the flag unchanged.
// Every host call is recorded so tests can prove a negative descriptor never
// reaches the host and a rejected request changes nothing.
struct DescriptorFlagsHost final : macosarm::DarwinHostServices {
    struct Descriptor {
        std::int32_t fd{};
        bool close_on_exec{};
        std::uint32_t status_flags{};
    };

    std::vector<Descriptor> descriptors;
    std::uint32_t update_error{};
    std::vector<std::int32_t> described;
    std::vector<CloseOnExecUpdate> updates;

    [[nodiscard]] Descriptor* find(std::int32_t fd) noexcept {
        const auto found = std::find_if(descriptors.begin(), descriptors.end(),
                                        [fd](const Descriptor& entry) { return entry.fd == fd; });
        return found == descriptors.end() ? nullptr : &*found;
    }

    macosarm::HostWriteResult write(
        std::int32_t fd,
        std::span<const std::byte> bytes) override {
        static_cast<void>(fd);
        static_cast<void>(bytes);
        return {0, macosarm::kDarwinErrnoEbadf};
    }

    macosarm::HostDescriptorFlagsResult descriptor_flags(std::int32_t fd) override {
        described.push_back(fd);
        if (const Descriptor* entry = find(fd); entry != nullptr) {
            return {entry->close_on_exec, entry->status_flags, 0};
        }
        return {false, 0, macosarm::kDarwinErrnoEbadf};
    }

    macosarm::HostSetCloseOnExecResult set_close_on_exec(
        std::int32_t fd,
        bool close_on_exec) override {
        updates.push_back({fd, close_on_exec});
        Descriptor* entry = find(fd);
        if (entry == nullptr) {
            return {macosarm::kDarwinErrnoEbadf};
        }
        if (update_error != 0) {
            const std::uint32_t failure = update_error;
            update_error = 0;
            return {failure};
        }
        entry->close_on_exec = close_on_exec;
        return {0};
    }

    // One fcntl(2) F_SETFL step that reached the host, recorded in call order
    // across set_status_flags, set_nonblocking_io and set_async_io. value is
    // the committed OFLAGS(f_flag) for a status_flags step and 1 or 0 for the
    // mode an I/O mode step asked for.
    struct Step {
        enum class Kind { status_flags, nonblocking_io, async_io };

        Kind kind{};
        std::int32_t fd{};
        std::uint32_t value{};

        friend bool operator==(const Step&, const Step&) = default;
    };

    // A nonzero status_error, nonblocking_error or async_error fails the next
    // set_status_flags, set_nonblocking_io or set_async_io call once, leaving
    // that state unchanged. A successful set_status_flags replaces the
    // descriptor's status_flags, so a later F_GETFL reports what F_SETFL
    // committed.
    std::uint32_t status_error{};
    std::uint32_t nonblocking_error{};
    std::uint32_t async_error{};
    std::vector<Step> steps;

    // Report and clear a one-shot scripted failure.
    [[nodiscard]] static std::uint32_t take(std::uint32_t& error) noexcept {
        const std::uint32_t failure = error;
        error = 0;
        return failure;
    }

    macosarm::HostSetStatusFlagsResult set_status_flags(
        std::int32_t fd,
        std::uint32_t status_flags) override {
        steps.push_back({Step::Kind::status_flags, fd, status_flags});
        Descriptor* entry = find(fd);
        if (entry == nullptr) {
            return {macosarm::kDarwinErrnoEbadf};
        }
        if (status_error != 0) {
            return {take(status_error)};
        }
        entry->status_flags = status_flags;
        return {0};
    }

    macosarm::HostFileModeResult set_nonblocking_io(
        std::int32_t fd,
        bool nonblocking) override {
        steps.push_back({Step::Kind::nonblocking_io, fd, nonblocking ? 1U : 0U});
        if (find(fd) == nullptr) {
            return {macosarm::kDarwinErrnoEbadf};
        }
        return {take(nonblocking_error)};
    }

    macosarm::HostFileModeResult set_async_io(
        std::int32_t fd,
        bool asynchronous) override {
        steps.push_back({Step::Kind::async_io, fd, asynchronous ? 1U : 0U});
        if (find(fd) == nullptr) {
            return {macosarm::kDarwinErrnoEbadf};
        }
        return {take(async_error)};
    }

    // fcntl(2) F_DUPFD and F_DUPFD_CLOEXEC. resource_limit reports
    // soft_limit and hard_limit verbatim for every resource, so tests can
    // hand the dispatcher an inverted or out-of-range snapshot, unless a
    // nonzero limit_error fails it. duplicate_at_least allocates the lowest
    // descriptor at or above minimum that is not scripted and lies below the
    // soft limit capped at INT_MAX, as fdalloc does, giving it the source's
    // status flags and the requested close-on-exec flag, or reports EMFILE
    // and allocates nothing. With force_duplicate set it instead reports
    // forced_descriptor verbatim and allocates nothing, so tests can hand the
    // dispatcher a duplicate that breaks the host contract. Every limit query
    // and duplication request is recorded in call order.
    struct Duplication {
        std::int32_t fd{};
        std::int32_t minimum{};
        bool close_on_exec{};

        friend bool operator==(const Duplication&, const Duplication&) = default;
    };

    std::uint64_t soft_limit{256U};
    std::uint64_t hard_limit{macosarm::kDarwinRlimInfinity};
    std::uint32_t limit_error{};
    bool force_duplicate{};
    std::int32_t forced_descriptor{};
    std::vector<std::uint32_t> limit_queries;
    std::vector<Duplication> duplications;

    macosarm::HostResourceLimitResult resource_limit(std::uint32_t resource) override {
        limit_queries.push_back(resource);
        if (limit_error != 0) {
            return {0, 0, limit_error};
        }
        return {soft_limit, hard_limit, 0};
    }

    macosarm::HostDuplicateResult duplicate_at_least(
        std::int32_t fd,
        std::int32_t minimum,
        bool close_on_exec) override {
        duplications.push_back({fd, minimum, close_on_exec});
        const Descriptor* source = find(fd);
        if (source == nullptr) {
            return {0, macosarm::kDarwinErrnoEbadf};
        }
        if (force_duplicate) {
            return {forced_descriptor, 0};
        }
        // Copy the flags before push_back can move the descriptor table.
        const std::uint32_t status_flags = source->status_flags;
        constexpr std::uint64_t kIntMax = 0x7fffffffU;
        const std::uint64_t limit = soft_limit < kIntMax ? soft_limit : kIntMax;
        for (auto slot = static_cast<std::uint64_t>(minimum); slot < limit; ++slot) {
            const auto candidate = static_cast<std::int32_t>(slot);
            if (find(candidate) == nullptr) {
                descriptors.push_back({candidate, close_on_exec, status_flags});
                return {candidate, 0};
            }
        }
        return {0, macosarm::kDarwinErrnoEmfile};
    }

    // True when descriptor fd is scripted with exactly this close-on-exec flag.
    [[nodiscard]] bool close_on_exec_is(std::int32_t fd, bool expected) noexcept {
        const Descriptor* entry = find(fd);
        return entry != nullptr && entry->close_on_exec == expected;
    }
};

macosarm::SyscallDispatchResult run_fcntl(
    macosarm::GuestAddressSpace& vm,
    macosarm::DarwinHostServices& host,
    macosarm::CpuState& state,
    std::uint64_t syscall_number,
    std::uint64_t fd_register,
    std::uint64_t command_register,
    std::uint64_t argument_register) {
    state = {};
    state.x[0] = fd_register;
    state.x[1] = command_register;
    state.x[2] = argument_register;
    state.x[16] = syscall_number;
    // Preset carry so every success test proves the dispatcher clears it.
    state.pstate = macosarm::kA64PstateCarry;
    return macosarm::dispatch_darwin_syscall(state, vm, svc(), host);
}

// True when the last syscall failed with error: carry set and errno in x0.
bool fcntl_failed_with(const macosarm::CpuState& state, std::uint32_t error) {
    return carry_is_set(state) && state.x[0] == error;
}

} // namespace

int main() {
    constexpr std::uint64_t buffer_base = 0x200000000ULL;

    {
        // getentropy(2) success fills exactly the requested guest bytes,
        // returns 0 in x0 and clears a stale carry flag.
        macosarm::GuestAddressSpace vm;
        map_entropy_page(vm);
        EntropyHost host;
        macosarm::CpuState state{};
        const auto result = run_getentropy(vm, host, state, kEntropyBase, 32, true);
        expect(static_cast<bool>(result) && result.action == macosarm::SyscallAction::resume,
               "getentropy dispatch resumes guest");
        expect(result.syscall_number == macosarm::kDarwinSysGetentropy,
               "getentropy syscall number reported");
        expect(state.x[0] == 0 && !carry_is_set(state),
               "getentropy success returns 0 and clears carry");
        expect(host.requests == std::vector<std::size_t>{32},
               "getentropy draws exactly the requested size");
        expect(entropy_pattern_written(vm, 32), "getentropy copies host entropy to guest");
        expect(entropy_sentinel_from(vm, 32), "getentropy writes no bytes past the request");
    }

    {
        // The 256-byte kernel buffer bound is inclusive. Larger sizes fail
        // with EINVAL before the destination is validated or entropy drawn,
        // and 64-bit sizes are never truncated into an accepted length.
        macosarm::GuestAddressSpace vm;
        map_entropy_page(vm);
        EntropyHost host;
        macosarm::CpuState state{};
        const auto full = run_getentropy(vm, host, state, kEntropyBase, 256, true);
        expect(static_cast<bool>(full) && state.x[0] == 0 && !carry_is_set(state),
               "getentropy accepts the 256-byte maximum");
        expect(entropy_pattern_written(vm, 256) && entropy_sentinel_from(vm, 256),
               "maximum getentropy fills exactly 256 bytes");

        macosarm::GuestAddressSpace fresh;
        map_entropy_page(fresh);
        EntropyHost rejecting;
        const std::array<std::uint64_t, 3> oversized{
            257U, 0x100000000ULL + 16U, ~std::uint64_t{0}};
        for (const std::uint64_t size : oversized) {
            const auto rejected =
                run_getentropy(fresh, rejecting, state, kEntropyBase, size, false);
            expect(static_cast<bool>(rejected) &&
                       state.x[0] == macosarm::kDarwinErrnoEinval && carry_is_set(state),
                   "oversized getentropy returns EINVAL and sets carry");
        }
        const auto null_oversized = run_getentropy(fresh, rejecting, state, 0, 257, false);
        expect(static_cast<bool>(null_oversized) && state.x[0] == macosarm::kDarwinErrnoEinval,
               "getentropy size check precedes buffer validation");
        expect(rejecting.requests.empty() && entropy_sentinel_from(fresh, 0),
               "rejected getentropy draws no entropy and writes no guest bytes");
    }

    {
        // Zero bytes succeed even for a null buffer, without host entropy.
        // Unmapped, page-crossing and read-only destinations fault before
        // any host entropy is drawn, leaving guest memory untouched.
        macosarm::GuestAddressSpace vm;
        map_entropy_page(vm);
        constexpr std::uint64_t readonly_base = 0x300000000ULL;
        const std::vector<std::byte> readonly_bytes(64, std::byte{0x11});
        load_readable(vm, readonly_base, readonly_bytes);
        EntropyHost host;
        macosarm::CpuState state{};

        const auto empty = run_getentropy(vm, host, state, 0, 0, true);
        expect(static_cast<bool>(empty) && state.x[0] == 0 && !carry_is_set(state),
               "zero-length getentropy succeeds for a null buffer");

        const auto check_fault = [&](std::uint64_t address, std::uint64_t size,
                                     const std::string& label) {
            const auto faulted = run_getentropy(vm, host, state, address, size, false);
            expect(static_cast<bool>(faulted) &&
                       state.x[0] == macosarm::kDarwinErrnoEfault && carry_is_set(state),
                   label + " returns EFAULT and sets carry");
        };
        check_fault(0, 16, "null getentropy buffer");
        check_fault(0xdead00000000ULL, 16, "unmapped getentropy buffer");
        check_fault(kEntropyBase + kEntropyPage - 8U, 16, "page-crossing getentropy buffer");
        check_fault(readonly_base, 16, "read-only getentropy buffer");

        expect(host.requests.empty() && entropy_sentinel_from(vm, 0),
               "faulting getentropy draws no entropy and writes no guest bytes");
        std::vector<std::byte> readonly_after(readonly_bytes.size());
        expect(static_cast<bool>(vm.read(readonly_base, readonly_after)) &&
                   readonly_after == readonly_bytes,
               "read-only getentropy destination stays unchanged");
    }

    {
        // A failing host source reports its errno and none of its partial
        // output reaches the guest; hosts without a source report ENOSYS.
        macosarm::GuestAddressSpace vm;
        map_entropy_page(vm);
        EntropyHost host;
        host.next_error = macosarm::kDarwinErrnoEio;
        macosarm::CpuState state{};
        const auto failed = run_getentropy(vm, host, state, kEntropyBase, 64, false);
        expect(static_cast<bool>(failed) && state.x[0] == macosarm::kDarwinErrnoEio &&
                   carry_is_set(state),
               "host entropy failure returns its errno and sets carry");
        expect(host.requests == std::vector<std::size_t>{64} && entropy_sentinel_from(vm, 0),
               "failed host entropy is never copied to the guest");

        CaptureHost no_source;
        const auto unsupported = run_getentropy(vm, no_source, state, kEntropyBase, 16, false);
        expect(static_cast<bool>(unsupported) && state.x[0] == macosarm::kDarwinErrnoEnosys &&
                   carry_is_set(state),
               "host without an entropy source returns ENOSYS");
        expect(entropy_sentinel_from(vm, 0) && no_source.fds.empty(),
               "unsupported getentropy writes no guest bytes");
    }

    {
        macosarm::GuestAddressSpace vm;
        const std::vector<std::byte> message{
            std::byte{'h'}, std::byte{'e'}, std::byte{'l'}, std::byte{'l'}, std::byte{'o'}};
        load_readable(vm, buffer_base, message);

        CaptureHost host;
        macosarm::CpuState state{};
        state.x[16] = macosarm::kDarwinSysWrite;
        state.x[0] = 1;
        state.x[1] = buffer_base;
        state.x[2] = message.size();
        state.pstate = macosarm::kA64PstateCarry;

        const auto result = macosarm::dispatch_darwin_syscall(state, vm, svc(), host);
        expect(static_cast<bool>(result), "write dispatch succeeds");
        expect(result.action == macosarm::SyscallAction::resume, "write resumes guest");
        expect(result.syscall_number == macosarm::kDarwinSysWrite, "write syscall number reported");
        expect(state.x[0] == message.size(), "write byte count returned in x0");
        expect(!carry_is_set(state), "successful write clears carry");
        expect(host.fds.size() == 1 && host.fds[0] == 1, "write fd forwarded");
        expect(host.captured == message, "write bytes copied from guest memory");
    }

    {
        macosarm::GuestAddressSpace vm;
        CaptureHost host;
        macosarm::CpuState state{};
        state.x[16] = macosarm::kDarwinSysWrite;
        state.x[0] = 2;
        state.x[1] = buffer_base;
        state.x[2] = 8;

        const auto result = macosarm::dispatch_darwin_syscall(state, vm, svc(), host);
        expect(static_cast<bool>(result), "guest EFAULT is a handled syscall");
        expect(state.x[0] == macosarm::kDarwinErrnoEfault, "unmapped write returns EFAULT");
        expect(carry_is_set(state), "EFAULT sets carry");
        expect(host.fds.empty(), "EFAULT does not call host write");
    }

    {
        macosarm::GuestAddressSpace vm;
        const std::vector<std::byte> message{std::byte{'x'}};
        load_readable(vm, buffer_base, message);

        CaptureHost host;
        host.next_error = 32;
        macosarm::CpuState state{};
        state.x[16] = macosarm::kDarwinSysWrite;
        state.x[0] = 1;
        state.x[1] = buffer_base;
        state.x[2] = 1;

        const auto result = macosarm::dispatch_darwin_syscall(state, vm, svc(), host);
        expect(static_cast<bool>(result), "host errno is handled");
        expect(state.x[0] == 32, "host errno returned in x0");
        expect(carry_is_set(state), "host errno sets carry");
    }

    {
        macosarm::GuestAddressSpace vm;
        const std::vector<std::byte> message{
            std::byte{'a'}, std::byte{'b'}, std::byte{'c'}, std::byte{'d'}};
        load_readable(vm, buffer_base, message);

        CaptureHost host;
        host.short_write = 2;
        macosarm::CpuState state{};
        state.x[16] = macosarm::kDarwinSysWrite;
        state.x[0] = 1;
        state.x[1] = buffer_base;
        state.x[2] = message.size();

        const auto result = macosarm::dispatch_darwin_syscall(state, vm, svc(), host);
        expect(static_cast<bool>(result), "short write is handled");
        expect(state.x[0] == 2, "short write count returned");
        expect(!carry_is_set(state), "short write is still success");
        expect(host.captured.size() == 2, "short write stops after host short count");
    }

    {
        macosarm::GuestAddressSpace vm;
        std::vector<std::byte> large(64 * 1024 + 3, std::byte{0x5a});
        load_readable(vm, buffer_base, large);

        CaptureHost host;
        macosarm::CpuState state{};
        state.x[16] = macosarm::kDarwinSysWrite;
        state.x[0] = 1;
        state.x[1] = buffer_base;
        state.x[2] = large.size();

        const auto result = macosarm::dispatch_darwin_syscall(state, vm, svc(), host);
        expect(static_cast<bool>(result), "large write succeeds");
        expect(state.x[0] == large.size(), "large write returns full byte count");
        expect(host.fds.size() == 2, "large write is split into bounded chunks");
        expect(host.largest_request <= 64 * 1024, "host write chunk is capped at 64 KiB");
        expect(host.captured == large, "chunked write preserves guest bytes");
    }

    {
        // XNU _bsdthread_register performs validation/copyin before
        // registration. A valid request must still fail closed with ENOSYS.
        macosarm::GuestAddressSpace vm;
        std::array<std::byte, 56> record{};
        record[0] = std::byte{56}; // packed registration version (u64)
        record[8] = std::byte{160}; // dispatch_queue_offset (u64)
        load_readable(vm, buffer_base, record);
        CaptureHost host;
        macosarm::CpuState state{};
        const auto check = [&](std::uint64_t pthread_size,
                               std::uint64_t record_address,
                               std::uint64_t record_size,
                               std::uint32_t expected_errno,
                               const std::string& label) {
            state = {};
            state.x[0] = buffer_base;
            state.x[1] = buffer_base;
            state.x[2] = pthread_size;
            state.x[3] = record_address;
            state.x[4] = record_size;
            state.x[5] = 160;
            state.x[16] = macosarm::kDarwinSysBsdthreadRegister;
            const auto result = macosarm::dispatch_darwin_syscall(state, vm, svc(), host);
            expect(static_cast<bool>(result) && result.action == macosarm::SyscallAction::resume,
                   label + " is handled without registration");
            expect(state.x[0] == expected_errno && carry_is_set(state),
                   label + " returns Darwin error and sets carry");
        };

        check(16384, buffer_base, record.size(), macosarm::kDarwinErrnoEnosys,
              "valid pthread registration stays unsupported");
        check(0xffffffffU, buffer_base, record.size(), macosarm::kDarwinErrnoEinval,
              "negative signed pthread allocation size");
        check(65537, buffer_base, record.size(), macosarm::kDarwinErrnoEinval,
              "oversized pthread allocation");
        check(16384, buffer_base, 7, macosarm::kDarwinErrnoEinval,
              "registration shorter than version field");
        check(16384, 0xdead00000000ULL, record.size(), macosarm::kDarwinErrnoEfault,
              "invalid registration copyin");
        check(16384, buffer_base, record.size() - 1U, macosarm::kDarwinErrnoEinval,
              "registration version mismatch");
        check(16384, buffer_base + macosarm::GuestAddressSpace::kPageSize - 4U,
              record.size(), macosarm::kDarwinErrnoEfault,
              "registration copyin crossing unmapped page");
        check(16384, 0, 0, macosarm::kDarwinErrnoEnosys,
              "legacy registration without record stays unsupported");
        macosarm::MachContext owner;
        macosarm::MachContext independent;
        // Seed the source-defined packed copyin offsets on a read-only page.
        const auto write32 = [&](std::size_t offset, std::uint32_t val) {
            for (std::size_t i = 0; i < 4U; ++i) {
                record[offset + i] = static_cast<std::byte>((val >> (8U * i)) & 0xffU);
            }
        };
        write32(24U, 224U);
        write32(28U, 40U);
        write32(32U, 24U);
        write32(48U, 392U);
        write32(52U, 960U);
        expect(static_cast<bool>(vm.load_bytes(buffer_base, record)),
               "packed pthread registration fixture copies to read-only VM");
        state = {};
        state.x[0] = 0x120000000ULL;
        state.x[1] = 0x130000000ULL;
        state.x[2] = 16384U;
        state.x[3] = buffer_base;
        state.x[4] = 56U;
        state.x[5] = 999U;
        state.x[16] = macosarm::kDarwinSysBsdthreadRegister;
        const auto valid = macosarm::dispatch_darwin_syscall(state, vm, svc(), host, owner);
        const auto& staged = owner.pthread_registration_preflight();
        expect(static_cast<bool>(valid) &&
                   state.x[0] == macosarm::kDarwinErrnoEnosys &&
                   carry_is_set(state) && staged.has_value() &&
                   staged->threadstart == 0x120000000ULL &&
                   staged->wqthread == 0x130000000ULL &&
                   staged->pthread_size == 16384U &&
                   staged->record_size == 56U &&
                   staged->tsd_offset == 224U &&
                   staged->dispatch_queue_offset == 160U &&
                   staged->return_to_kernel_offset == 40U &&
                   staged->mach_thread_self_offset == 24U &&
                   staged->wq_quantum_expiry_offset == 960U &&
                   staged->joinable_offset_bits == 392U &&
                   staged->record_address == buffer_base &&
                   staged->copyout_size == 56U &&
                   !staged->threadstart_executable &&
                   !staged->wqthread_executable &&
                   !staged->copyout_writable &&
                   !owner.pthread_registered() &&
                   !independent.pthread_registration_preflight(),
               "parsed pthread registration belongs only to requesting process");
        std::array<std::byte, 56> untouched{};
        expect(static_cast<bool>(vm.read(buffer_base, untouched)) && untouched == record,
               "read-only pthread record remains unchanged on unsupported syscall");
        state = {};
        state.x[16] = macosarm::kDarwinSysBsdthreadCreate;
        const auto still_unregistered =
            macosarm::dispatch_darwin_syscall(state, vm, svc(), host, owner);
        expect(static_cast<bool>(still_unregistered) &&
                   state.x[0] == macosarm::kDarwinErrnoEinval &&
                   carry_is_set(state),
               "successful copyin does not grant bsdthread_create support");
        state = {};
        state.x[2] = 16384U;
        state.x[3] = 0xdead00000000ULL;
        state.x[4] = 56U;
        state.x[16] = macosarm::kDarwinSysBsdthreadRegister;
        const auto failed_retry =
            macosarm::dispatch_darwin_syscall(state, vm, svc(), host, owner);
        expect(static_cast<bool>(failed_retry) &&
                   state.x[0] == macosarm::kDarwinErrnoEfault &&
                   owner.pthread_registration_preflight()->threadstart ==
                       0x120000000ULL,
               "malformed retry does not corrupt prior process preflight");
        // Forward/backward structure compatibility: a smaller versioned
        // record fills absent fields with zero and never reads beyond size.
        std::array<std::byte, 8> short_record{};
        short_record[0] = std::byte{8};
        const auto short_address = buffer_base + 128U;
        expect(static_cast<bool>(vm.load_bytes(short_address, short_record)),
               "short versioned pthread record copied to guest");
        state = {};
        state.x[2] = 16U;
        state.x[3] = short_address;
        state.x[4] = 8U;
        state.x[16] = macosarm::kDarwinSysBsdthreadRegister;
        const auto short_result =
            macosarm::dispatch_darwin_syscall(state, vm, svc(), host, independent);
        const auto& short_snapshot = independent.pthread_registration_preflight();
        expect(static_cast<bool>(short_result) &&
                   state.x[0] == macosarm::kDarwinErrnoEnosys &&
                   short_snapshot.has_value() && short_snapshot->record_size == 8U &&
                   short_snapshot->copyout_size == 8U &&
                   short_snapshot->record_address == short_address &&
                   short_snapshot->tsd_offset == 0U &&
                   short_snapshot->dispatch_queue_offset == 0U &&
                   !short_snapshot->copyout_writable,
               "short registration copyin zero pads the missing fields");
        write32(24U, 16384U);
        write32(52U, 0xffffffffU);
        expect(static_cast<bool>(vm.load_bytes(buffer_base, record)),
               "invalid pthread TSD bounds fixture loaded");
        state = {};
        state.x[2] = 16384U;
        state.x[3] = buffer_base;
        state.x[4] = 56U;
        state.x[16] = macosarm::kDarwinSysBsdthreadRegister;
        const auto bounds =
            macosarm::dispatch_darwin_syscall(state, vm, svc(), host, independent);
        const auto& bounds_snapshot = independent.pthread_registration_preflight();
        expect(static_cast<bool>(bounds) &&
                   state.x[0] == macosarm::kDarwinErrnoEnosys &&
                   bounds_snapshot.has_value() &&
                   bounds_snapshot->tsd_offset == 0U &&
                   bounds_snapshot->dispatch_queue_offset == 0U &&
                   bounds_snapshot->return_to_kernel_offset == 0U &&
                   bounds_snapshot->wq_quantum_expiry_offset == 0U,
               "out-of-range TSD offsets are zeroed, not trusted");
        // Record versions larger than Apple's known 56-byte layout still
        // consume and would copy out only the known prefix. The 64-bit size
        // is compared exactly; trailing guest memory is never accessed.
        std::array<std::byte, 56> newer_record{};
        newer_record[0] = std::byte{120};
        constexpr std::uint64_t newer_address = buffer_base + 256U;
        expect(static_cast<bool>(vm.load_bytes(newer_address, newer_record)),
               "newer pthread record header loads");
        state = {};
        state.x[2] = 16384U;
        state.x[3] = newer_address;
        state.x[4] = 120U;
        state.x[16] = macosarm::kDarwinSysBsdthreadRegister;
        const auto newer_result = macosarm::dispatch_darwin_syscall(
            state, vm, svc(), host, independent);
        const auto& newer = independent.pthread_registration_preflight();
        expect(static_cast<bool>(newer_result) &&
                   state.x[0] == macosarm::kDarwinErrnoEnosys &&
                   newer && newer->record_size == 120U &&
                   newer->record_address == newer_address &&
                   newer->copyout_size == 56U && !newer->copyout_writable,
               "forward record version uses bounded 56-byte copyout plan");

        // Neither a source-visible entrypoint nor a valid copyin grants
        // pthread registration. Check executable ARM64 veneers separately
        // from the record's copyout permissions.
        constexpr std::uint64_t executable_base = 0x190000000ULL;
        std::array<std::byte, 4> nop{std::byte{0x1f}, std::byte{0x20},
                                     std::byte{0x03}, std::byte{0xd5}};
        expect(static_cast<bool>(vm.map(
                   executable_base, macosarm::GuestAddressSpace::kPageSize,
                   macosarm::Protection::read | macosarm::Protection::execute)) &&
                   static_cast<bool>(vm.load_bytes(executable_base, nop)),
               "pthread startup entrypoint maps executable ARM64 veneer");
        state = {};
        state.x[0] = executable_base;
        state.x[1] = executable_base + 4U;
        state.x[2] = 16384U;
        state.x[3] = buffer_base;
        state.x[4] = 56U;
        state.x[16] = macosarm::kDarwinSysBsdthreadRegister;
        const auto executable_result = macosarm::dispatch_darwin_syscall(
            state, vm, svc(), host, owner);
        const auto& executable = owner.pthread_registration_preflight();
        expect(static_cast<bool>(executable_result) &&
                   state.x[0] == macosarm::kDarwinErrnoEnosys &&
                   executable && executable->threadstart_executable &&
                   executable->wqthread_executable && !executable->copyout_writable &&
                   !owner.pthread_registered(),
               "executable veneers are observed but cannot commit registration");
        state.x[0] = executable_base + 1U;
        state.x[1] = 0xdead00000000ULL;
        state.x[2] = 16384U;
        state.x[3] = buffer_base;
        state.x[4] = 56U;
        state.x[16] = macosarm::kDarwinSysBsdthreadRegister;
        const auto bad_entry = macosarm::dispatch_darwin_syscall(
            state, vm, svc(), host, owner);
        const auto& not_ready = owner.pthread_registration_preflight();
        expect(static_cast<bool>(bad_entry) &&
                   state.x[0] == macosarm::kDarwinErrnoEnosys &&
                   not_ready && !not_ready->threadstart_executable &&
                   !not_ready->wqthread_executable && !owner.pthread_registered(),
               "misaligned and unmapped entrypoints never become executable");

        // Registration copyout may cross adjacent VM mapping fragments.
        // Probe the complete XNU-sized prefix without guest writes, even
        // when the second fragment is read-only.
        macosarm::GuestAddressSpace split_vm;
        constexpr std::uint64_t split_base = 0x340000000ULL;
        constexpr std::uint64_t split_record =
            split_base + macosarm::GuestAddressSpace::kPageSize - 24U;
        std::array<std::byte, 56> split_data{};
        split_data[0] = std::byte{56};
        expect(static_cast<bool>(split_vm.map(
                   split_base, macosarm::GuestAddressSpace::kPageSize,
                   macosarm::Protection::read | macosarm::Protection::write)) &&
                   static_cast<bool>(split_vm.map(
                       split_base + macosarm::GuestAddressSpace::kPageSize,
                       macosarm::GuestAddressSpace::kPageSize,
                       macosarm::Protection::read | macosarm::Protection::write)) &&
                   static_cast<bool>(split_vm.load_bytes(split_record, split_data)),
               "cross-fragment registration copyin setup");
        macosarm::MachContext split_context;
        state = {};
        state.x[2] = 16384U;
        state.x[3] = split_record;
        state.x[4] = 56U;
        state.x[16] = macosarm::kDarwinSysBsdthreadRegister;
        const auto split_good = macosarm::dispatch_darwin_syscall(
            state, split_vm, svc(), host, split_context);
        expect(static_cast<bool>(split_good) &&
                   state.x[0] == macosarm::kDarwinErrnoEnosys &&
                   split_context.pthread_registration_preflight() &&
                   split_context.pthread_registration_preflight()->copyout_writable &&
                   split_context.pthread_registration_preflight()->copyout_size == 56U,
               "cross-fragment writable copyout prefix is detected");
        expect(static_cast<bool>(split_vm.protect_range(
                   split_base + macosarm::GuestAddressSpace::kPageSize,
                   macosarm::GuestAddressSpace::kPageSize,
                   macosarm::Protection::read)),
               "second registration fragment becomes read-only");
        const auto split_read_only = macosarm::dispatch_darwin_syscall(
            state, split_vm, svc(), host, split_context);
        std::array<std::byte, 56> split_unchanged{};
        expect(static_cast<bool>(split_read_only) &&
                   state.x[0] == macosarm::kDarwinErrnoEnosys &&
                   split_context.pthread_registration_preflight() &&
                   !split_context.pthread_registration_preflight()->copyout_writable &&
                   static_cast<bool>(split_vm.read(split_record, split_unchanged)) &&
                   split_unchanged == split_data && !split_context.pthread_registered(),
               "partial guest read-only copyout cannot silently become registration");
        expect(host.fds.empty(), "registration preflight never calls host write");
        std::array<std::byte, 56> unchanged{};
        expect(static_cast<bool>(vm.read(buffer_base, unchanged)) && unchanged == record,
               "registration preflight does not mutate guest data");
    }

    {
        // XNU syscalls.master #20: getpid is a successful 32-bit BSD return,
        // independent of host pid and stable across a process's syscalls.
        macosarm::GuestAddressSpace vm;
        CaptureHost host;
        macosarm::MachContext first_process;
        macosarm::MachContext second_process;
        macosarm::CpuState state{};
        state.x[0] = UINT64_MAX;
        state.x[16] = macosarm::kDarwinSysGetpid;
        state.pstate = macosarm::kA64PstateCarry;
        const auto first = macosarm::dispatch_darwin_syscall(
            state, vm, svc(), host, first_process);
        const std::uint64_t pid = state.x[0];
        expect(static_cast<bool>(first) &&
                   first.syscall_number == macosarm::kDarwinSysGetpid &&
                   first.action == macosarm::SyscallAction::resume,
               "getpid is dispatched as BSD syscall 20");
        expect(pid == first_process.process_id() && pid >=
                   macosarm::MachContext::kFirstSyntheticProcessId &&
                   pid <= INT32_MAX,
               "getpid returns a bounded synthetic POSIX pid");
        expect(!carry_is_set(state), "successful getpid clears stale carry");

        state.x[0] = 0;
        state.pstate = macosarm::kA64PstateCarry;
        const auto repeated = macosarm::dispatch_darwin_syscall(
            state, vm, svc(), host, first_process);
        expect(static_cast<bool>(repeated) && state.x[0] == pid && !carry_is_set(state),
               "repeated getpid keeps process identity stable");

        state.pstate = macosarm::kA64PstateCarry;
        const auto isolated = macosarm::dispatch_darwin_syscall(
            state, vm, svc(), host, second_process);
        expect(static_cast<bool>(isolated) &&
                   state.x[0] == second_process.process_id() &&
                   state.x[0] != pid && !carry_is_set(state),
               "independent Mach contexts have isolated process ids");

        state.x[16] = macosarm::kDarwinSysBsdthreadRegister;
        state.x[2] = 16384;
        state.x[3] = 0;
        state.x[4] = 0;
        const auto unsupported = macosarm::dispatch_darwin_syscall(
            state, vm, svc(), host, first_process);
        expect(static_cast<bool>(unsupported) &&
                   state.x[0] == macosarm::kDarwinErrnoEnosys && carry_is_set(state),
               "unsupported pthread registration still fails closed");
        state.x[16] = macosarm::kDarwinSysGetpid;
        const auto after_rejection = macosarm::dispatch_darwin_syscall(
            state, vm, svc(), host, first_process);
        expect(static_cast<bool>(after_rejection) &&
                   state.x[0] == pid && !carry_is_set(state),
               "failed registration leaves process pid unchanged");
        expect(host.fds.empty(), "identity calls never invoke host writes");
    }

    {
        macosarm::GuestAddressSpace vm;
        CaptureHost host;
        macosarm::MachContext context;
        macosarm::CpuState state{};
        state.x[16] = macosarm::kDarwinSysThreadSelfid;
        state.pstate = macosarm::kA64PstateCarry;
        const auto first = macosarm::dispatch_darwin_syscall(
            state, vm, svc(), host, context);
        const std::uint64_t id = state.x[0];
        expect(static_cast<bool>(first) &&
                   first.syscall_number == macosarm::kDarwinSysThreadSelfid &&
                   first.action == macosarm::SyscallAction::resume,
               "thread_selfid returns through normal BSD syscall dispatch");
        expect(id == context.thread_id() && id != 0 && id != UINT64_MAX &&
                   id != context.thread_self_port() && id > UINT32_MAX,
               "thread_selfid is a stable full-width synthetic thread ID, not a port");
        expect(!carry_is_set(state), "thread_selfid clears stale BSD carry flag");

        state.x[0] = 0;
        state.pstate = macosarm::kA64PstateCarry;
        const auto repeated = macosarm::dispatch_darwin_syscall(
            state, vm, svc(), host, context);
        expect(static_cast<bool>(repeated) && state.x[0] == id && !carry_is_set(state),
               "thread_selfid preserves identity across repeated calls");
        expect(host.fds.empty(), "thread_selfid never calls host write");
    }

    {
        // XNU syscalls.master #24 getuid, #25 geteuid, #39 getppid,
        // #43 getegid, #47 getgid and #327 issetugid always succeed. Their
        // answers are synthetic, host-independent POSIX credentials.
        expect(macosarm::kDarwinSysGetuid == 24U &&
                   macosarm::kDarwinSysGeteuid == 25U &&
                   macosarm::kDarwinSysGetppid == 39U &&
                   macosarm::kDarwinSysGetegid == 43U &&
                   macosarm::kDarwinSysGetgid == 47U &&
                   macosarm::kDarwinSysIssetugid == 327U,
               "credential syscalls use XNU BSD syscall numbers");
        expect(macosarm::kDarwinSyntheticUserId == 501U &&
                   macosarm::kDarwinSyntheticGroupId == 20U &&
                   macosarm::kDarwinSyntheticParentProcessId == 1U,
               "synthetic credentials are a non-root staff user under launchd");

        macosarm::GuestAddressSpace vm;
        CaptureHost host;
        macosarm::MachContext context;
        macosarm::MachContext other;
        macosarm::CpuState state{};
        const auto query = [&](macosarm::MachContext& process,
                               std::uint64_t number,
                               std::uint64_t expected,
                               const std::string& label) {
            state = {};
            state.x[0] = UINT64_MAX;
            state.x[16] = number;
            state.pstate = macosarm::kA64PstateCarry;
            const auto result = macosarm::dispatch_darwin_syscall(
                state, vm, svc(), host, process);
            expect(static_cast<bool>(result) &&
                       result.action == macosarm::SyscallAction::resume &&
                       static_cast<std::uint64_t>(result.syscall_number) == number &&
                       state.x[0] == expected && !carry_is_set(state),
                   label + " returns synthetic value and clears stale carry");
        };
        const std::uint64_t uid = macosarm::kDarwinSyntheticUserId;
        const std::uint64_t gid = macosarm::kDarwinSyntheticGroupId;
        const std::uint64_t ppid = macosarm::kDarwinSyntheticParentProcessId;
        query(context, macosarm::kDarwinSysGetuid, uid, "getuid");
        query(context, macosarm::kDarwinSysGeteuid, uid, "geteuid");
        query(context, macosarm::kDarwinSysGetgid, gid, "getgid");
        query(context, macosarm::kDarwinSysGetegid, gid, "getegid");
        query(context, macosarm::kDarwinSysGetppid, ppid, "getppid");
        query(context, macosarm::kDarwinSysIssetugid, 0U, "issetugid");
        expect(ppid != static_cast<std::uint64_t>(context.process_id()),
               "getppid never reports the translated process as its own parent");

        // Credentials stay stable after a rejected syscall and do not vary
        // with per-process synthetic identity state.
        state = {};
        state.x[16] = 0xfeedU;
        const auto rejected = macosarm::dispatch_darwin_syscall(
            state, vm, svc(), host, context);
        expect(static_cast<bool>(rejected) &&
                   state.x[0] == macosarm::kDarwinErrnoEnosys && carry_is_set(state),
               "unknown syscall between credential queries fails closed");
        query(context, macosarm::kDarwinSysGetuid, uid, "getuid after rejection");
        query(other, macosarm::kDarwinSysGeteuid, uid, "geteuid in another process");
        query(other, macosarm::kDarwinSysGetegid, gid, "getegid in another process");
        query(other, macosarm::kDarwinSysGetppid, ppid, "getppid in another process");
        expect(host.fds.empty(), "credential queries never invoke host writes");
    }

    {
        // XNU's _bsdthread_create checks proc_get_register(p) before using
        // thread entry points. Every translated process is unregistered
        // until full bsdthread_register and thread support is implemented.
        macosarm::GuestAddressSpace vm;
        CaptureHost host;
        macosarm::MachContext context;
        macosarm::CpuState state{};
        const auto check_create = [&](std::uint64_t threadstart,
                                      std::uint64_t pthread,
                                      const std::string& label) {
            state = {};
            state.x[0] = threadstart;
            state.x[1] = 0x1000U;
            state.x[2] = 0x2000U;
            state.x[3] = pthread;
            state.x[4] = 0x01000000U; // PTHREAD_START_CUSTOM
            state.x[16] = macosarm::kDarwinSysBsdthreadCreate;
            const auto result = macosarm::dispatch_darwin_syscall(
                state, vm, svc(), host, context);
            expect(static_cast<bool>(result) &&
                       result.action == macosarm::SyscallAction::resume &&
                       result.syscall_number == macosarm::kDarwinSysBsdthreadCreate &&
                       state.x[0] == macosarm::kDarwinErrnoEinval &&
                       carry_is_set(state),
                   label + " is rejected as unregistered with EINVAL and carry");
        };
        check_create(0U, 0U, "missing thread entry and pthread");
        check_create(0x100000000ULL, 0x200000000ULL,
                     "apparently valid thread entry and pthread");
        check_create(UINT64_MAX, UINT64_MAX,
                     "invalid pointers still hit the early registration guard");

        // A correctly formed registration currently returns ENOSYS. That
        // failure must not accidentally enable later bsdthread_create calls.
        std::array<std::byte, 56> registration{};
        registration[0] = std::byte{56};
        load_readable(vm, buffer_base, registration);
        state = {};
        state.x[2] = 16384U;
        state.x[3] = buffer_base;
        state.x[4] = registration.size();
        state.x[16] = macosarm::kDarwinSysBsdthreadRegister;
        const auto registration_result = macosarm::dispatch_darwin_syscall(
            state, vm, svc(), host, context);
        expect(static_cast<bool>(registration_result) &&
                   state.x[0] == macosarm::kDarwinErrnoEnosys &&
                   carry_is_set(state),
               "unimplemented valid registration still fails closed");
        check_create(0x100000000ULL, 0x200000000ULL,
                     "thread creation after failed registration");

        std::array<std::byte, 56> unchanged{};
        expect(static_cast<bool>(vm.read(buffer_base, unchanged)) &&
                   unchanged == registration,
               "thread creation and failed registration preserve guest memory");
        expect(host.fds.empty(), "thread creation never calls host write");
    }


    {
        // XNU BSD #73 munmap -> mach_vm_deallocate. The address must be
        // page-aligned, length nonzero, and range nonwrapping. Lengths
        // within a page round up before changing guest page mappings.
        macosarm::GuestAddressSpace vm;
        CaptureHost host;
        constexpr std::uint64_t page = macosarm::GuestAddressSpace::kPageSize;
        constexpr std::uint64_t base = 0x500000000ULL;
        const auto rw = macosarm::Protection::read | macosarm::Protection::write;
        expect(static_cast<bool>(vm.map(base, 3U * page, rw)),
               "bsd munmap test maps three guest pages");
        std::array<std::byte, 1> marker{std::byte{0x4b}};
        expect(static_cast<bool>(vm.write(base, marker)) &&
                   static_cast<bool>(vm.write(base + page, marker)) &&
                   static_cast<bool>(vm.write(base + 2U * page, marker)),
               "bsd munmap fixture writes each guest page");

        macosarm::CpuState state{};
        const auto call = [&](std::uint64_t address,
                              std::uint64_t length,
                              std::uint32_t expected_errno,
                              const std::string& label) {
            state = {};
            state.pstate = macosarm::kA64PstateCarry;
            state.x[0] = address;
            state.x[1] = length;
            state.x[16] = macosarm::kDarwinSysMunmap;
            const auto result = macosarm::dispatch_darwin_syscall(state, vm, svc(), host);
            expect(static_cast<bool>(result) &&
                       result.syscall_number == macosarm::kDarwinSysMunmap &&
                       result.action == macosarm::SyscallAction::resume &&
                       state.x[0] == expected_errno &&
                       carry_is_set(state) == (expected_errno != 0U),
                   label + " returns Darwin errno and carry");
        };

        call(base + 1U, page, macosarm::kDarwinErrnoEinval,
             "unaligned munmap start");
        call(base + page, 0U, macosarm::kDarwinErrnoEinval,
             "zero-length munmap");
        call(UINT64_MAX - 1U, 4U, macosarm::kDarwinErrnoEinval,
             "wrapping munmap range");
        call(0xffffffffffffc000ULL, page + 1U, macosarm::kDarwinErrnoEinval,
             "rounded munmap end overflow");
        expect(vm.mappings().size() == 1U && vm.resident_page_count() == 3U,
               "invalid munmap preserves original mapping and resident pages");

        call(base + page, 1U, 0U, "subpage length rounds to guest page");
        std::array<std::byte, 1> readback{};
        expect(vm.read(base + page, readback).error == macosarm::VmError::unmapped,
               "bsd munmap removes rounded guest page");
        expect(static_cast<bool>(vm.read(base, readback)) &&
                   readback == marker &&
                   static_cast<bool>(vm.read(base + 2U * page, readback)) &&
                   readback == marker &&
                   vm.resident_page_count() == 2U,
               "bsd munmap leaves adjacent resident pages untouched");
        call(base + page, 1U, 0U, "repeat munmap over an existing hole");
        call(base, 3U * page, 0U, "munmap spans fragmented mapping and hole");
        expect(vm.mappings().empty() && vm.resident_page_count() == 0U &&
                   host.fds.empty(),
               "bsd munmap finishes without host writes or leaked guest pages");
    }


    {
        // XNU BSD #197: support bounded zero-fill private anonymous memory.
        // Valid but unavailable MAP_FIXED, MAP_JIT, file and shared requests
        // fail closed; none must change guest mappings.
        macosarm::GuestAddressSpace vm;
        CaptureHost host;
        constexpr std::uint64_t page = macosarm::GuestAddressSpace::kPageSize;
        macosarm::CpuState state{};
        const auto request = [&](std::uint64_t hint, std::uint64_t size,
                                 std::uint32_t prot, std::uint32_t flags,
                                 std::int64_t fd, std::uint64_t position) {
            state = {};
            state.pstate = macosarm::kA64PstateCarry;
            state.x[0] = hint;
            state.x[1] = size;
            state.x[2] = prot;
            state.x[3] = flags;
            state.x[4] = static_cast<std::uint64_t>(fd);
            state.x[5] = position;
            state.x[16] = macosarm::kDarwinSysMmap;
            const auto result = macosarm::dispatch_darwin_syscall(
                state, vm, svc(), host);
            expect(static_cast<bool>(result) &&
                       result.action == macosarm::SyscallAction::resume &&
                       result.syscall_number == macosarm::kDarwinSysMmap,
                   "anonymous mmap dispatch resumes translated process");
            return state.x[0];
        };
        constexpr std::uint32_t flags =
            macosarm::kDarwinMapPrivate | macosarm::kDarwinMapAnonymous;
        const auto first = request(0, 1U, 3U, flags, -1, 0);
        expect(!carry_is_set(state) && first >= 0x100000000ULL &&
                   first % page == 0 && vm.mappings().size() == 1U &&
                   vm.mappings()[0].size == page && vm.resident_page_count() == 0,
               "mmap returns a rounded, lazy private anonymous guest page");
        std::array<std::byte, 1> readback{};
        expect(static_cast<bool>(vm.read(first, readback)) &&
                   readback[0] == std::byte{0},
               "fresh anonymous guest memory reads as zero");
        constexpr std::array<std::byte, 1> marker{std::byte{0x6a}};
        expect(static_cast<bool>(vm.write(first, marker)) &&
                   static_cast<bool>(vm.read(first, readback)) &&
                   readback == marker,
               "private anonymous guest mapping is writable and persistent");
        const auto second = request(first, page + 1U, 1U,
                                    flags | macosarm::kDarwinMapUnix03, -1, 0);
        expect(!carry_is_set(state) && second != first &&
                   second % page == 0 && vm.mappings().size() == 2U &&
                   vm.resident_page_count() == 1U,
               "mmap rounds a multi-page length and avoids an occupied hint");
        expect(vm.write(second, marker).error == macosarm::VmError::protection &&
                   static_cast<bool>(vm.read(second, readback)) &&
                   readback[0] == std::byte{0},
               "read-only anonymous mappings prohibit guest writes");

        const auto before_failures = vm.mappings().size();
        const auto check_error = [&](std::uint64_t size, std::uint32_t prot,
                                     std::uint32_t request_flags, std::int64_t fd,
                                     std::uint64_t position, std::uint32_t error,
                                     const std::string& label) {
            expect(request(0, size, prot, request_flags, fd, position) == error &&
                       carry_is_set(state) &&
                       vm.mappings().size() == before_failures &&
                       vm.resident_page_count() == 1U,
                   label + " fails atomically with Darwin errno");
        };
        check_error(0, 3, flags, -1, 0, macosarm::kDarwinErrnoEinval,
                    "empty allocation");
        check_error(UINT64_MAX, 3, flags, -1, 0, macosarm::kDarwinErrnoEinval,
                    "overflowing allocation");
        check_error(256ULL * 1024ULL * 1024ULL + 1ULL, 3, flags, -1, 0,
                    macosarm::kDarwinErrnoEnomem, "bounded guest VM allocation");
        check_error(page, 8, flags, -1, 0, macosarm::kDarwinErrnoEinval,
                    "invalid protection bits");
        check_error(page, 3, flags | 0x80000000U, -1, 0,
                    macosarm::kDarwinErrnoEinval, "unknown mmap flags");
        check_error(page, 3, flags | macosarm::kDarwinMapFixed, -1, 0,
                    macosarm::kDarwinErrnoEnosys, "atomic MAP_FIXED overwrite");
        check_error(page, 3, flags | macosarm::kDarwinMapJit, -1, 0,
                    macosarm::kDarwinErrnoEnosys, "unimplemented MAP_JIT");
        check_error(page, 4, flags, -1, 0, macosarm::kDarwinErrnoEnosys,
                    "unimplemented executable mapping and code-signing");
        check_error(page, 3, macosarm::kDarwinMapAnonymous | 1U, -1, 0,
                    macosarm::kDarwinErrnoEnosys, "unimplemented MAP_SHARED");
        check_error(page, 3, macosarm::kDarwinMapPrivate, 3, 0,
                    macosarm::kDarwinErrnoEnosys, "unimplemented file mapping");
        check_error(page, 3, flags, 7, 0, macosarm::kDarwinErrnoEnosys,
                    "unimplemented anonymous fd alias");
        check_error(page, 3, flags, -1, 1, macosarm::kDarwinErrnoEnosys,
                    "unimplemented nonzero anonymous position");

        state = {};
        state.x[0] = first;
        state.x[1] = 1U;
        state.x[16] = macosarm::kDarwinSysMunmap;
        const auto unmapped = macosarm::dispatch_darwin_syscall(
            state, vm, svc(), host);
        expect(static_cast<bool>(unmapped) && state.x[0] == 0 &&
                   !carry_is_set(state) &&
                   vm.read(first, readback).error == macosarm::VmError::unmapped,
               "munmap deallocates a dynamically mapped anonymous guest page");
        const auto remapped = request(first, 1U, 3U, flags, -1, 0);
        expect(!carry_is_set(state) && remapped == first &&
                   static_cast<bool>(vm.read(remapped, readback)) &&
                   readback[0] == std::byte{0},
               "mmap reuses freed hint but does not leak stale page contents");
        expect(host.fds.empty(), "mmap and munmap never invoke host write");
    }


    {
        // XNU BSD #74 mprotect translates Mach VM protection failures into
        // EACCES and unmapped ranges into ENOMEM, preserving adjacent data.
        macosarm::GuestAddressSpace vm;
        CaptureHost host;
        constexpr std::uint64_t base = 0x700000000ULL;
        constexpr std::uint64_t page = macosarm::GuestAddressSpace::kPageSize;
        const auto rw = macosarm::Protection::read | macosarm::Protection::write;
        expect(static_cast<bool>(vm.map(base, 3U * page, rw)),
               "BSD mprotect test maps three pages");
        const auto call = [&](std::uint64_t addr, std::uint64_t length,
                              std::uint32_t prot, std::uint32_t error,
                              const std::string& label) {
            macosarm::CpuState state{};
            state.x[0] = addr;
            state.x[1] = length;
            state.x[2] = prot;
            state.x[16] = macosarm::kDarwinSysMprotect;
            state.pstate = macosarm::kA64PstateCarry;
            const auto result = macosarm::dispatch_darwin_syscall(
                state, vm, svc(), host);
            expect(static_cast<bool>(result) &&
                       result.action == macosarm::SyscallAction::resume &&
                       result.syscall_number == macosarm::kDarwinSysMprotect &&
                       state.x[0] == error &&
                       carry_is_set(state) == (error != 0U),
                   label + " returns source-defined Darwin errno and carry");
        };
        call(base + 1U, page, 1U, macosarm::kDarwinErrnoEinval,
             "unaligned mprotect");
        call(UINT64_MAX - page + 1U, page + 1U, 1U,
             macosarm::kDarwinErrnoEinval, "overflowing mprotect");
        call(base, 0U, 1U, 0U, "zero-size mprotect no-op");
        call(base + page, 1U, 1U, 0U, "page-rounded mprotect downgrade");
        constexpr std::array<std::byte, 1> marker{std::byte{0x5e}};
        std::array<std::byte, 1> readback{};
        expect(vm.write(base + page, marker).error == macosarm::VmError::protection &&
                   static_cast<bool>(vm.read(base + page, readback)) &&
                   static_cast<bool>(vm.write(base, marker)),
               "mprotect enforces only requested guest-page permissions");
        call(base, 3U * page, 4U, macosarm::kDarwinErrnoEacces,
             "mprotect cannot escalate above maximum execute rights");
        expect(vm.write(base + page, marker).error == macosarm::VmError::protection,
               "failed EACCES leaves original read-only fragment unchanged");
        expect(static_cast<bool>(vm.unmap_range(base + 2U * page, page)),
               "mprotect gap fixture removes last page");
        call(base + page, 2U * page, 3U, macosarm::kDarwinErrnoEnomem,
             "mprotect missing guest range");
        expect(vm.write(base + page, marker).error == macosarm::VmError::protection,
               "failed ENOMEM does not partially restore earlier permissions");
        call(base + page, page, 3U, 0U, "mprotect restore maximum-supported write");
        expect(static_cast<bool>(vm.write(base + page, marker)) && host.fds.empty(),
               "restored write works without host I/O");

        // BSD mmap (MAP_ANON) supplies RW maximum even if initially READ;
        // the subsequent BSD mprotect can promote it to RW.
        macosarm::GuestAddressSpace anon_vm;
        macosarm::CpuState state{};
        state.x[1] = page;
        state.x[2] = 1U;
        state.x[3] = macosarm::kDarwinMapPrivate | macosarm::kDarwinMapAnonymous;
        state.x[4] = UINT64_MAX;
        state.x[16] = macosarm::kDarwinSysMmap;
        const auto mapped = macosarm::dispatch_darwin_syscall(
            state, anon_vm, svc(), host);
        const auto addr = state.x[0];
        expect(static_cast<bool>(mapped) &&
                   (state.pstate & macosarm::kA64PstateCarry) == 0 &&
                   anon_vm.write(addr, marker).error == macosarm::VmError::protection,
               "anonymous mmap begins read-only");
        state = {};
        state.x[0] = addr;
        state.x[1] = page;
        state.x[2] = 3U;
        state.x[16] = macosarm::kDarwinSysMprotect;
        const auto modified = macosarm::dispatch_darwin_syscall(
            state, anon_vm, svc(), host);
        expect(static_cast<bool>(modified) && state.x[0] == 0 &&
                   !carry_is_set(state) &&
                   static_cast<bool>(anon_vm.write(addr, marker)),
               "translated process may promote anonymous memory within its declared maximum");
    }

    {
        macosarm::GuestAddressSpace vm;
        CaptureHost host;
        macosarm::CpuState state{};
        state.x[16] = 0xfeed;

        const auto result = macosarm::dispatch_darwin_syscall(state, vm, svc(), host);
        expect(static_cast<bool>(result), "unknown syscall is handled");
        expect(state.x[0] == macosarm::kDarwinErrnoEnosys, "unknown syscall returns ENOSYS");
        expect(carry_is_set(state), "ENOSYS sets carry");
    }

    {
        macosarm::GuestAddressSpace vm;
        CaptureHost host;
        macosarm::CpuState state{};
        state.x[16] = macosarm::kDarwinSysExit;
        state.x[0] = 0x12345678ULL;

        const auto result = macosarm::dispatch_darwin_syscall(state, vm, svc(), host);
        expect(static_cast<bool>(result), "exit dispatch succeeds");
        expect(result.action == macosarm::SyscallAction::exit_process, "exit terminates guest process");
        expect(result.exit_status == static_cast<std::int32_t>(0x12345678U), "exit preserves 32-bit status");
    }

    {
        macosarm::GuestAddressSpace vm;
        CaptureHost host;
        macosarm::CpuState state{};
        macosarm::ExecutionResult execution{};
        execution.reason = macosarm::StopReason::instruction_budget;

        const auto result = macosarm::dispatch_darwin_syscall(state, vm, execution, host);
        expect(result.error == macosarm::SyscallDispatchError::not_supervisor_call,
               "non-SVC stop is rejected");

        const auto wrong_svc = macosarm::dispatch_darwin_syscall(state, vm, svc(0x42), host);
        expect(wrong_svc.error == macosarm::SyscallDispatchError::unsupported_svc,
               "non-Darwin SVC immediate is rejected");
    }

    {
        macosarm::GuestAddressSpace vm;
        const std::vector<std::byte> message{std::byte{'z'}};
        load_readable(vm, buffer_base, message);

        CaptureHost host;
        host.violate_contract = true;
        macosarm::CpuState state{};
        state.x[16] = macosarm::kDarwinSysWrite;
        state.x[0] = 1;
        state.x[1] = buffer_base;
        state.x[2] = 1;

        const auto result = macosarm::dispatch_darwin_syscall(state, vm, svc(), host);
        expect(result.error == macosarm::SyscallDispatchError::host_contract_violation,
               "impossible host write count is rejected");
    }

    {
        // XNU bsd/kern/sys_generic.c read(2): a bad descriptor wins over
        // argument errors, nbyte > INT_MAX is EINVAL, and an unwritable
        // destination is EFAULT without consuming any host input.
        constexpr std::uint64_t page = macosarm::GuestAddressSpace::kPageSize;
        constexpr std::uint64_t read_base = 0x800000000ULL;
        constexpr std::uint64_t io_chunk = 64U * 1024U; // dispatcher's bounded host read
        constexpr std::int32_t closed_fd = 7;
        const auto rw = macosarm::Protection::read | macosarm::Protection::write;
        const auto run_read = [](macosarm::GuestAddressSpace& vm, ReadHost& host,
                                 std::int32_t fd, std::uint64_t address,
                                 std::uint64_t nbyte, macosarm::CpuState& state) {
            state = {};
            state.x[0] = static_cast<std::uint32_t>(fd);
            state.x[1] = address;
            state.x[2] = nbyte;
            state.x[16] = macosarm::kDarwinSysRead;
            return macosarm::dispatch_darwin_syscall(state, vm, svc(), host);
        };
        const auto failed_with = [](const macosarm::SyscallDispatchResult& result,
                                    macosarm::CpuState& state, std::uint32_t error) {
            return static_cast<bool>(result) && carry_is_set(state) && state.x[0] == error;
        };

        {
            macosarm::GuestAddressSpace vm;
            ReadHost host;
            host.input = {std::byte{'h'}, std::byte{'e'}, std::byte{'y'}};
            expect(static_cast<bool>(vm.map(read_base, page, rw)), "read destination maps");
            macosarm::CpuState state{};
            const auto result = run_read(vm, host, 0, read_base, 16U, state);
            std::array<std::byte, 3> landed{};
            expect(static_cast<bool>(result) && !carry_is_set(state) && state.x[0] == 3U &&
                       host.consumed == 3U &&
                       host.requests == std::vector<std::size_t>{16U} &&
                       static_cast<bool>(vm.read(read_base, landed)) &&
                       std::equal(landed.begin(), landed.end(), host.input.begin()),
                   "read copies one short host result without blocking to refill");
            const auto at_eof = run_read(vm, host, 0, read_base, 16U, state);
            expect(static_cast<bool>(at_eof) && !carry_is_set(state) && state.x[0] == 0U,
                   "read at end of file succeeds with zero bytes");
        }

        {
            macosarm::GuestAddressSpace vm;
            ReadHost host;
            host.input = {std::byte{'x'}};
            macosarm::CpuState state{};
            const auto empty = run_read(vm, host, 0, read_base, 0U, state);
            expect(static_cast<bool>(empty) && !carry_is_set(state) && state.x[0] == 0U &&
                       host.consumed == 0U && host.requests == std::vector<std::size_t>{0U},
                   "zero-length read probes the descriptor without touching guest memory");
            const auto closed = run_read(vm, host, closed_fd, read_base, 0U, state);
            expect(failed_with(closed, state, macosarm::kDarwinErrnoEbadf),
                   "zero-length read on a closed descriptor is EBADF");
            constexpr std::uint64_t too_large = 0x80000000ULL;
            const auto oversized = run_read(vm, host, 0, read_base, too_large, state);
            expect(failed_with(oversized, state, macosarm::kDarwinErrnoEinval) &&
                       host.consumed == 0U,
                   "read rejects nbyte above INT_MAX with EINVAL");
            const auto closed_oversized =
                run_read(vm, host, closed_fd, read_base, too_large, state);
            expect(failed_with(closed_oversized, state, macosarm::kDarwinErrnoEbadf),
                   "bad descriptor wins over oversized nbyte");
            const auto unmapped = run_read(vm, host, 0, read_base, 1U, state);
            expect(failed_with(unmapped, state, macosarm::kDarwinErrnoEfault) &&
                       host.consumed == 0U,
                   "unmapped read destination is EFAULT without consuming input");
            const auto closed_unmapped = run_read(vm, host, closed_fd, read_base, 1U, state);
            expect(failed_with(closed_unmapped, state, macosarm::kDarwinErrnoEbadf),
                   "bad descriptor wins over an unmapped destination");
            const std::vector<std::byte> original{std::byte{'r'}};
            load_readable(vm, read_base, original);
            const auto read_only = run_read(vm, host, 0, read_base, 1U, state);
            std::array<std::byte, 1> kept{};
            expect(failed_with(read_only, state, macosarm::kDarwinErrnoEfault) &&
                       host.consumed == 0U &&
                       static_cast<bool>(vm.read(read_base, kept)) && kept[0] == std::byte{'r'},
                   "read-only destination is EFAULT and preserves guest bytes");
        }

        {
            macosarm::GuestAddressSpace vm;
            ReadHost host;
            host.input.assign(static_cast<std::size_t>(io_chunk + page), std::byte{0x5a});
            expect(static_cast<bool>(vm.map(read_base, 2U * io_chunk, rw)),
                   "large read destination maps");
            macosarm::CpuState state{};
            const auto bounded = run_read(vm, host, 0, read_base, 2U * io_chunk, state);
            expect(static_cast<bool>(bounded) && !carry_is_set(state) &&
                       state.x[0] == io_chunk && host.consumed == io_chunk &&
                       host.requests ==
                           std::vector<std::size_t>{static_cast<std::size_t>(io_chunk)},
                   "read issues exactly one bounded host read per syscall");
            host.next_error = macosarm::kDarwinErrnoEio;
            const auto failed = run_read(vm, host, 0, read_base, 1U, state);
            expect(failed_with(failed, state, macosarm::kDarwinErrnoEio) &&
                       host.consumed == io_chunk,
                   "host read errors propagate to the guest");
            host.violate_contract = true;
            const auto violated = run_read(vm, host, 0, read_base, 1U, state);
            expect(violated.error == macosarm::SyscallDispatchError::host_contract_violation,
                   "impossible host read count is rejected");
            const auto violated_probe = run_read(vm, host, 0, read_base, 0U, state);
            expect(violated_probe.error ==
                       macosarm::SyscallDispatchError::host_contract_violation,
                   "nonzero descriptor probe count is rejected");
        }
    }

    {
        // XNU syscalls.master #396 read_nocancel / #397 write_nocancel take
        // the same arguments and report the same results as read / write.
        constexpr std::uint64_t page = macosarm::GuestAddressSpace::kPageSize;
        constexpr std::uint64_t nocancel_base = 0x900000000ULL;
        constexpr std::uint64_t unmapped_base = 0xA00000000ULL;
        const auto rw = macosarm::Protection::read | macosarm::Protection::write;

        {
            macosarm::GuestAddressSpace vm;
            const std::vector<std::byte> message{std::byte{'n'}, std::byte{'c'}};
            load_readable(vm, buffer_base, message);
            CaptureHost host;
            macosarm::CpuState state{};
            state.x[16] = macosarm::kDarwinSysWriteNocancel;
            state.x[0] = 1;
            state.x[1] = buffer_base;
            state.x[2] = message.size();
            const auto result = macosarm::dispatch_darwin_syscall(state, vm, svc(), host);
            expect(static_cast<bool>(result) && !carry_is_set(state) &&
                       state.x[0] == message.size() &&
                       result.syscall_number == macosarm::kDarwinSysWriteNocancel &&
                       host.captured == message &&
                       host.fds == std::vector<std::int32_t>{1},
                   "write_nocancel writes guest bytes like write");

            state = {};
            state.x[16] = macosarm::kDarwinSysWriteNocancel;
            state.x[0] = 1;
            state.x[1] = unmapped_base;
            state.x[2] = 1;
            const auto faulted = macosarm::dispatch_darwin_syscall(state, vm, svc(), host);
            expect(static_cast<bool>(faulted) && carry_is_set(state) &&
                       state.x[0] == macosarm::kDarwinErrnoEfault &&
                       host.captured == message,
                   "write_nocancel from unmapped memory is EFAULT");
        }

        {
            macosarm::GuestAddressSpace vm;
            ReadHost host;
            host.input = {std::byte{'a'}, std::byte{'b'}, std::byte{'c'}};
            expect(static_cast<bool>(vm.map(nocancel_base, page, rw)),
                   "read_nocancel destination maps");
            macosarm::CpuState state{};
            state.x[16] = macosarm::kDarwinSysReadNocancel;
            state.x[0] = 0;
            state.x[1] = nocancel_base;
            state.x[2] = 16U;
            const auto result = macosarm::dispatch_darwin_syscall(state, vm, svc(), host);
            std::array<std::byte, 3> landed{};
            expect(static_cast<bool>(result) && !carry_is_set(state) && state.x[0] == 3U &&
                       result.syscall_number == macosarm::kDarwinSysReadNocancel &&
                       host.consumed == 3U &&
                       static_cast<bool>(vm.read(nocancel_base, landed)) &&
                       std::equal(landed.begin(), landed.end(), host.input.begin()),
                   "read_nocancel copies host input like read");

            state = {};
            state.x[16] = macosarm::kDarwinSysReadNocancel;
            state.x[0] = 7;
            state.x[1] = nocancel_base;
            state.x[2] = 1U;
            const auto closed = macosarm::dispatch_darwin_syscall(state, vm, svc(), host);
            expect(static_cast<bool>(closed) && carry_is_set(state) &&
                       state.x[0] == macosarm::kDarwinErrnoEbadf,
                   "read_nocancel on a closed descriptor is EBADF");
        }
    }

    {
        // XNU syscalls.master #121 writev / #412 writev_nocancel validate the
        // whole LP64 iovec array before resolving the descriptor, then write
        // each vector in order through the bounded host write path.
        constexpr std::uint64_t data_base = 0xB00000000ULL;
        constexpr std::uint64_t vector_ok = 0xC00000000ULL;
        constexpr std::uint64_t vector_overflow = 0xC00100000ULL;
        constexpr std::uint64_t vector_bad_base = 0xC00200000ULL;
        constexpr std::uint64_t vector_partial = 0xC00300000ULL;
        constexpr std::uint64_t unmapped_base = 0xD00000000ULL;
        constexpr std::uint64_t bad_fd = 0xffffffffULL;
        const auto encode = [](const std::vector<std::uint64_t>& fields) {
            std::vector<std::byte> bytes;
            for (const std::uint64_t value : fields) {
                for (std::size_t i = 0; i < sizeof(std::uint64_t); ++i) {
                    bytes.push_back(static_cast<std::byte>((value >> (8U * i)) & 0xffU));
                }
            }
            return bytes;
        };
        const auto run_writev = [](macosarm::GuestAddressSpace& space, CaptureHost& target,
                                   std::uint64_t number, std::uint64_t fd,
                                   std::uint64_t vectors, std::uint64_t count,
                                   macosarm::CpuState& cpu) {
            cpu = {};
            cpu.pstate = macosarm::kA64PstateCarry;
            cpu.x[16] = number;
            cpu.x[0] = fd;
            cpu.x[1] = vectors;
            cpu.x[2] = count;
            return macosarm::dispatch_darwin_syscall(cpu, space, svc(), target);
        };
        const auto writev_failed = [](const macosarm::SyscallDispatchResult& outcome,
                                      const macosarm::CpuState& cpu, std::uint32_t error) {
            return static_cast<bool>(outcome) && carry_is_set(cpu) && cpu.x[0] == error;
        };

        macosarm::GuestAddressSpace vm;
        const std::vector<std::byte> data{std::byte{'a'}, std::byte{'b'}, std::byte{'c'},
                                          std::byte{'d'}, std::byte{'e'}, std::byte{'f'}};
        load_readable(vm, data_base, data);
        load_readable(vm, vector_ok, encode({data_base, 2U, 0U, 0U, data_base + 2U, 4U}));
        load_readable(vm, vector_overflow,
                      encode({data_base, 0x7fffffffffffffffULL, data_base, 1U}));
        load_readable(vm, vector_bad_base, encode({unmapped_base, 1U}));
        load_readable(vm, vector_partial, encode({data_base, 2U, unmapped_base, 1U}));
        macosarm::CpuState state{};

        CaptureHost host;
        const auto gathered =
            run_writev(vm, host, macosarm::kDarwinSysWritev, 1U, vector_ok, 3U, state);
        expect(static_cast<bool>(gathered) && !carry_is_set(state) &&
                   state.x[0] == data.size() &&
                   gathered.syscall_number == macosarm::kDarwinSysWritev &&
                   host.captured == data && host.fds == std::vector<std::int32_t>{1, 1, 1},
               "writev writes vectors in order and skips empty ones");

        CaptureHost nocancel_host;
        const auto nocancel = run_writev(
            vm, nocancel_host, macosarm::kDarwinSysWritevNocancel, 2U, vector_ok, 3U, state);
        expect(static_cast<bool>(nocancel) && !carry_is_set(state) &&
                   state.x[0] == data.size() &&
                   nocancel.syscall_number == macosarm::kDarwinSysWritevNocancel &&
                   nocancel_host.captured == data &&
                   nocancel_host.fds == std::vector<std::int32_t>{2, 2, 2},
               "writev_nocancel gathers vectors like writev");

        CaptureHost idle;
        const auto no_vectors =
            run_writev(vm, idle, macosarm::kDarwinSysWritev, 1U, vector_ok, 0U, state);
        expect(writev_failed(no_vectors, state, macosarm::kDarwinErrnoEinval),
               "writev with no vectors is EINVAL");
        const auto too_many = run_writev(vm, idle, macosarm::kDarwinSysWritev, 1U, vector_ok,
                                         macosarm::kDarwinIovMax + 1U, state);
        expect(writev_failed(too_many, state, macosarm::kDarwinErrnoEinval),
               "writev above UIO_MAXIOV vectors is EINVAL");
        const auto unreadable =
            run_writev(vm, idle, macosarm::kDarwinSysWritev, 1U, unmapped_base, 1U, state);
        expect(writev_failed(unreadable, state, macosarm::kDarwinErrnoEfault),
               "writev with an unmapped iovec array is EFAULT");
        const auto oversized =
            run_writev(vm, idle, macosarm::kDarwinSysWritev, bad_fd, vector_overflow, 2U, state);
        expect(writev_failed(oversized, state, macosarm::kDarwinErrnoEinval),
               "writev total above SSIZE_MAX is EINVAL before descriptor checks");
        const auto negative =
            run_writev(vm, idle, macosarm::kDarwinSysWritev, bad_fd, vector_bad_base, 1U, state);
        expect(writev_failed(negative, state, macosarm::kDarwinErrnoEbadf) && idle.fds.empty(),
               "writev argument errors and negative descriptors never reach the host");

        CaptureHost closed;
        closed.next_error = macosarm::kDarwinErrnoEbadf;
        const auto bad_descriptor =
            run_writev(vm, closed, macosarm::kDarwinSysWritev, 5U, vector_bad_base, 1U, state);
        expect(writev_failed(bad_descriptor, state, macosarm::kDarwinErrnoEbadf) &&
                   closed.fds == std::vector<std::int32_t>{5} && closed.captured.empty(),
               "bad writev descriptor wins over an unmapped iov_base");
        const auto bad_base =
            run_writev(vm, closed, macosarm::kDarwinSysWritev, 1U, vector_bad_base, 1U, state);
        expect(writev_failed(bad_base, state, macosarm::kDarwinErrnoEfault) &&
                   closed.fds == std::vector<std::int32_t>{5, 1} && closed.captured.empty(),
               "unmapped iov_base with nothing written is EFAULT");
        const auto partial =
            run_writev(vm, closed, macosarm::kDarwinSysWritev, 1U, vector_partial, 2U, state);
        expect(static_cast<bool>(partial) && !carry_is_set(state) && state.x[0] == 2U &&
                   closed.captured == std::vector<std::byte>{data[0], data[1]},
               "writev reports bytes written before a later fault");
        closed.violate_contract = true;
        const auto violated =
            run_writev(vm, closed, macosarm::kDarwinSysWritev, 1U, vector_ok, 3U, state);
        expect(violated.error == macosarm::SyscallDispatchError::host_contract_violation,
               "nonzero writev descriptor probe count is rejected");
    }

    {
        // XNU syscalls.master #120 readv / #411 readv_nocancel validate the
        // whole LP64 iovec array before resolving the descriptor, then fill
        // the vectors in order from exactly one bounded host read.
        constexpr std::uint64_t page = macosarm::GuestAddressSpace::kPageSize;
        constexpr std::uint64_t dest_base = 0xE00000000ULL;
        constexpr std::uint64_t vector_scatter = 0xE00100000ULL;
        constexpr std::uint64_t unmapped_base = 0xF00000000ULL;
        constexpr std::byte sentinel{0xcc};
        const auto rw = macosarm::Protection::read | macosarm::Protection::write;
        const auto encode = [](const std::vector<std::uint64_t>& fields) {
            std::vector<std::byte> bytes;
            for (const std::uint64_t value : fields) {
                for (std::size_t i = 0; i < sizeof(std::uint64_t); ++i) {
                    bytes.push_back(static_cast<std::byte>((value >> (8U * i)) & 0xffU));
                }
            }
            return bytes;
        };
        // A sentinel-filled writable page plus a read-only iovec array that
        // fills two bytes, skips an empty vector whose base is unmapped, then
        // fills four bytes at offset 8.
        const auto prepare = [&](macosarm::GuestAddressSpace& vm) {
            const std::vector<std::byte> fill(static_cast<std::size_t>(page), sentinel);
            expect(static_cast<bool>(vm.map(dest_base, page, rw)) &&
                       static_cast<bool>(vm.load_bytes(dest_base, fill)),
                   "readv destination maps writable");
            load_readable(vm, vector_scatter,
                          encode({dest_base, 2U, unmapped_base, 0U, dest_base + 8U, 4U}));
        };
        const auto run_readv = [](macosarm::GuestAddressSpace& vm, ReadHost& host,
                                  std::uint64_t number, std::uint64_t fd,
                                  std::uint64_t vectors, std::uint64_t count,
                                  macosarm::CpuState& state) {
            state = {};
            state.pstate = macosarm::kA64PstateCarry;
            state.x[16] = number;
            state.x[0] = fd;
            state.x[1] = vectors;
            state.x[2] = count;
            return macosarm::dispatch_darwin_syscall(state, vm, svc(), host);
        };
        // True when the first 12 destination bytes match expected, where '.'
        // stands for an untouched sentinel byte.
        const auto landed = [&](macosarm::GuestAddressSpace& vm, const std::string& expected) {
            std::array<std::byte, 12> bytes{};
            if (expected.size() != bytes.size() || !vm.read(dest_base, bytes)) {
                return false;
            }
            for (std::size_t i = 0; i < bytes.size(); ++i) {
                const std::byte want =
                    expected[i] == '.' ? sentinel : static_cast<std::byte>(expected[i]);
                if (bytes[i] != want) {
                    return false;
                }
            }
            return true;
        };

        {
            macosarm::GuestAddressSpace vm;
            prepare(vm);
            ReadHost host;
            host.input = {std::byte{'a'}, std::byte{'b'}, std::byte{'c'},
                          std::byte{'d'}, std::byte{'e'}, std::byte{'f'}};
            macosarm::CpuState state{};
            const auto scattered =
                run_readv(vm, host, macosarm::kDarwinSysReadv, 0U, vector_scatter, 3U, state);
            expect(static_cast<bool>(scattered) && !carry_is_set(state) && state.x[0] == 6U &&
                       scattered.syscall_number == macosarm::kDarwinSysReadv &&
                       host.fds == std::vector<std::int32_t>{0, 0} &&
                       host.requests == std::vector<std::size_t>{0U, 6U} &&
                       landed(vm, "ab......cdef"),
                   "readv scatters one host read in order and skips empty vectors");
            const auto at_eof =
                run_readv(vm, host, macosarm::kDarwinSysReadv, 0U, vector_scatter, 3U, state);
            expect(static_cast<bool>(at_eof) && !carry_is_set(state) && state.x[0] == 0U &&
                       landed(vm, "ab......cdef"),
                   "readv at end of file succeeds with zero bytes");
        }

        {
            macosarm::GuestAddressSpace vm;
            prepare(vm);
            ReadHost host;
            host.input = {std::byte{'x'}, std::byte{'y'}, std::byte{'z'}};
            macosarm::CpuState state{};
            const auto short_read = run_readv(
                vm, host, macosarm::kDarwinSysReadvNocancel, 0U, vector_scatter, 3U, state);
            expect(static_cast<bool>(short_read) && !carry_is_set(state) && state.x[0] == 3U &&
                       short_read.syscall_number == macosarm::kDarwinSysReadvNocancel &&
                       host.consumed == 3U &&
                       host.requests == std::vector<std::size_t>{0U, 6U} &&
                       landed(vm, "xy......z..."),
                   "readv_nocancel delivers a short host read without refilling");
        }

        // Argument errors follow XNU's order: iovcnt (EINVAL), the iovec copyin
        // (EFAULT), then iov_len totals (EINVAL), all before the descriptor
        // resolves (EBADF), so none of them reaches the host.
        const auto failed_with = [](const macosarm::SyscallDispatchResult& result,
                                    macosarm::CpuState& state, std::uint32_t error) {
            return static_cast<bool>(result) && carry_is_set(state) && state.x[0] == error;
        };
        constexpr std::uint64_t readv_number = macosarm::kDarwinSysReadv;
        constexpr std::uint64_t closed_fd = 7U;

        {
            macosarm::GuestAddressSpace vm;
            prepare(vm);
            constexpr std::uint64_t vector_overflow = 0xE00200000ULL;
            constexpr std::uint64_t vector_too_long = 0xE00300000ULL;
            constexpr std::uint64_t half = 0x4000000000000000ULL;
            load_readable(vm, vector_overflow, encode({dest_base, half, dest_base, half}));
            load_readable(vm, vector_too_long, encode({dest_base, 2U * half}));
            ReadHost host;
            host.input = {std::byte{'q'}};
            macosarm::CpuState state{};
            const auto no_vectors = run_readv(vm, host, readv_number, 0U, vector_scatter, 0U, state);
            expect(failed_with(no_vectors, state, macosarm::kDarwinErrnoEinval),
                   "readv rejects a zero iovcnt with EINVAL");
            const auto truncated =
                run_readv(vm, host, readv_number, 0U, vector_scatter, 0x100000000ULL, state);
            expect(failed_with(truncated, state, macosarm::kDarwinErrnoEinval),
                   "readv counts only the low 32 bits of iovcnt");
            const auto too_many = run_readv(vm, host, readv_number, closed_fd, unmapped_base,
                                            macosarm::kDarwinIovMax + 1U, state);
            expect(failed_with(too_many, state, macosarm::kDarwinErrnoEinval),
                   "readv rejects iovcnt above UIO_MAXIOV before copying the vectors");
            const auto unmapped_vectors =
                run_readv(vm, host, readv_number, closed_fd, unmapped_base, 1U, state);
            expect(failed_with(unmapped_vectors, state, macosarm::kDarwinErrnoEfault),
                   "readv faults on an unmapped iovec array before resolving the descriptor");
            const auto overflow =
                run_readv(vm, host, readv_number, closed_fd, vector_overflow, 2U, state);
            expect(failed_with(overflow, state, macosarm::kDarwinErrnoEinval),
                   "readv rejects an iov_len total above SSIZE_MAX before resolving the descriptor");
            const auto too_long = run_readv(vm, host, readv_number, 0U, vector_too_long, 1U, state);
            expect(failed_with(too_long, state, macosarm::kDarwinErrnoEinval),
                   "readv rejects a single iov_len above SSIZE_MAX");
            expect(host.requests.empty() && host.consumed == 0U && landed(vm, "............"),
                   "rejected readv arguments never reach the host or guest memory");
            const auto closed = run_readv(vm, host, readv_number, closed_fd, vector_scatter, 3U, state);
            expect(failed_with(closed, state, macosarm::kDarwinErrnoEbadf) &&
                       host.consumed == 0U && landed(vm, "............"),
                   "readv on a closed descriptor is EBADF without touching guest memory");
            const auto negative =
                run_readv(vm, host, readv_number, 0xffffffffULL, vector_scatter, 3U, state);
            expect(failed_with(negative, state, macosarm::kDarwinErrnoEbadf) && host.consumed == 0U,
                   "readv on a negative descriptor is EBADF");
        }

        {
            // Destinations are probed before the host read, so only the
            // leading writable vectors receive input and none is dropped.
            macosarm::GuestAddressSpace vm;
            prepare(vm);
            constexpr std::uint64_t vector_unmapped = 0xE00200000ULL;
            constexpr std::uint64_t vector_read_only = 0xE00300000ULL;
            constexpr std::uint64_t vector_partial = 0xE00400000ULL;
            constexpr std::uint64_t vector_empty = 0xE00500000ULL;
            load_readable(vm, vector_unmapped, encode({unmapped_base, 4U}));
            load_readable(vm, vector_read_only, encode({vector_scatter, 4U}));
            load_readable(vm, vector_partial, encode({dest_base, 2U, unmapped_base, 4U}));
            load_readable(vm, vector_empty, encode({unmapped_base, 0U}));
            ReadHost host;
            host.input = {std::byte{'p'}, std::byte{'q'}, std::byte{'r'}, std::byte{'s'}};
            macosarm::CpuState state{};
            const auto unmapped = run_readv(vm, host, readv_number, 0U, vector_unmapped, 1U, state);
            expect(failed_with(unmapped, state, macosarm::kDarwinErrnoEfault) &&
                       host.consumed == 0U && host.requests == std::vector<std::size_t>{0U},
                   "readv into an unmapped first vector is EFAULT without consuming input");
            const auto read_only =
                run_readv(vm, host, readv_number, 0U, vector_read_only, 1U, state);
            expect(failed_with(read_only, state, macosarm::kDarwinErrnoEfault) && host.consumed == 0U,
                   "readv into a read-only vector is EFAULT without consuming input");
            const auto partial = run_readv(vm, host, readv_number, 0U, vector_partial, 2U, state);
            expect(static_cast<bool>(partial) && !carry_is_set(state) && state.x[0] == 2U &&
                       host.consumed == 2U && host.requests.back() == 2U &&
                       landed(vm, "pq.........."),
                   "readv limits the host read to the leading writable vectors");
            const auto empty = run_readv(vm, host, readv_number, 0U, vector_empty, 1U, state);
            expect(static_cast<bool>(empty) && !carry_is_set(state) && state.x[0] == 0U &&
                       host.consumed == 2U,
                   "readv of only empty vectors succeeds without touching their bases");
            host.next_error = macosarm::kDarwinErrnoEio;
            const auto failed = run_readv(vm, host, readv_number, 0U, vector_scatter, 3U, state);
            expect(failed_with(failed, state, macosarm::kDarwinErrnoEio) && host.consumed == 2U &&
                       landed(vm, "pq.........."),
                   "host readv errors propagate to the guest");
            host.violate_contract = true;
            const auto violated = run_readv(vm, host, readv_number, 0U, vector_scatter, 3U, state);
            expect(violated.error == macosarm::SyscallDispatchError::host_contract_violation,
                   "nonzero readv descriptor probe count is rejected");
        }
    }

    {
        // XNU bsd/kern/kern_time.c gettimeofday: a 64-bit process receives a
        // 16-byte struct user64_timeval { int64 tv_sec; int32 tv_usec; } with
        // zeroed tail padding and an 8-byte struct timezone. Success returns 0
        // in x0 and clears carry; the time itself never travels in registers.
        constexpr std::uint64_t clock_tv = kClockBase;
        constexpr std::uint64_t clock_tz = kClockBase + 32U;
        const auto clock_rw = macosarm::Protection::read | macosarm::Protection::write;

        {
            macosarm::GuestAddressSpace vm;
            map_clock_page(vm, clock_rw);
            ClockHost host;
            host.seconds = 1700000000;
            host.microseconds = 123456U;
            macosarm::CpuState state{};
            const auto result = run_gettimeofday(vm, host, state, clock_tv, clock_tz, 0U);
            std::uint64_t seconds = 0;
            std::uint64_t microseconds = 0;
            std::uint64_t padding = 1;
            std::uint64_t zone = 1;
            expect(static_cast<bool>(result) &&
                       result.action == macosarm::SyscallAction::resume &&
                       result.syscall_number == macosarm::kDarwinSysGettimeofday &&
                       state.x[0] == 0U && !carry_is_set(state) && host.calls == 1U,
                   "gettimeofday succeeds with exactly one wall-clock read");
            expect(read_guest_le(vm, clock_tv, 8U, seconds) && seconds == 1700000000U &&
                       read_guest_le(vm, clock_tv + 8U, 4U, microseconds) &&
                       microseconds == 123456U &&
                       read_guest_le(vm, clock_tv + 12U, 4U, padding) && padding == 0U,
                   "gettimeofday copies out a little-endian user64_timeval");
            expect(read_guest_le(vm, clock_tz, 8U, zone) && zone == 0U,
                   "gettimeofday reports synthetic UTC without DST");
            expect(clock_sentinel_at(vm, clock_tv + 16U, 16U) &&
                       clock_sentinel_at(vm, clock_tz + 8U, 64U),
                   "gettimeofday writes only the timeval and timezone records");
        }

        {
            // tv_sec is signed 64-bit: pre-epoch and post-2106 clocks keep
            // every bit instead of wrapping through a 32-bit truncation.
            const std::array<std::int64_t, 3> wall_clocks{-1, 0x100000005LL, -31536000LL};
            for (const std::int64_t wall_seconds : wall_clocks) {
                macosarm::GuestAddressSpace vm;
                map_clock_page(vm, clock_rw);
                ClockHost host;
                host.seconds = wall_seconds;
                host.microseconds = 999999U;
                macosarm::CpuState state{};
                const auto result = run_gettimeofday(vm, host, state, clock_tv, 0U, 0U);
                std::uint64_t seconds = 0;
                std::uint64_t microseconds = 0;
                expect(static_cast<bool>(result) && state.x[0] == 0U && !carry_is_set(state) &&
                           read_guest_le(vm, clock_tv, 8U, seconds) &&
                           seconds == static_cast<std::uint64_t>(wall_seconds) &&
                           read_guest_le(vm, clock_tv + 8U, 4U, microseconds) &&
                           microseconds == 999999U,
                       "gettimeofday preserves signed 64-bit tv_sec " +
                           std::to_string(wall_seconds));
                expect(clock_sentinel_at(vm, clock_tz, 8U),
                       "null timezone pointer leaves guest memory untouched");
            }
        }

        {
            macosarm::GuestAddressSpace vm;
            map_clock_page(vm, clock_rw);
            ClockHost host;
            macosarm::CpuState state{};
            const auto neither = run_gettimeofday(vm, host, state, 0U, 0U, 0U);
            expect(static_cast<bool>(neither) && state.x[0] == 0U && !carry_is_set(state) &&
                       host.calls == 0U && clock_sentinel_at(vm, kClockBase, kClockPage),
                   "gettimeofday without destinations succeeds without a clock read");

            const auto zone_only = run_gettimeofday(vm, host, state, 0U, clock_tz, 0U);
            std::uint64_t zone = 1;
            expect(static_cast<bool>(zone_only) && state.x[0] == 0U && !carry_is_set(state) &&
                       host.calls == 0U && read_guest_le(vm, clock_tz, 8U, zone) &&
                       zone == 0U && clock_sentinel_at(vm, clock_tv, 16U),
                   "timezone-only gettimeofday zeroes the zone without a clock read");
        }
    }

    {
        // gettimeofday failure paths fail closed: a rejected timeval
        // destination is detected before the wall clock is read, host errors
        // and contract violations leave guest memory untouched, and the
        // unimplemented mach_absolute_time out-parameter is refused up front.
        constexpr std::uint64_t clock_tv = kClockBase;
        constexpr std::uint64_t clock_tz = kClockBase + 32U;
        constexpr std::uint64_t clock_unmapped = 0xdead00000000ULL;
        const auto clock_rw = macosarm::Protection::read | macosarm::Protection::write;

        {
            macosarm::GuestAddressSpace vm;
            map_clock_page(vm, clock_rw);
            ClockHost host;
            host.seconds = 1700000000;
            macosarm::CpuState state{};
            const auto unmapped = run_gettimeofday(vm, host, state, clock_unmapped, clock_tz, 0U);
            expect(static_cast<bool>(unmapped) &&
                       state.x[0] == macosarm::kDarwinErrnoEfault && carry_is_set(state) &&
                       host.calls == 0U && clock_sentinel_at(vm, kClockBase, kClockPage),
                   "unmapped timeval faults before the clock read and timezone copyout");

            const auto crossing =
                run_gettimeofday(vm, host, state, kClockBase + kClockPage - 8U, 0U, 0U);
            expect(static_cast<bool>(crossing) &&
                       state.x[0] == macosarm::kDarwinErrnoEfault && carry_is_set(state) &&
                       host.calls == 0U && clock_sentinel_at(vm, kClockBase, kClockPage),
                   "timeval crossing into an unmapped page faults without partial copyout");
        }

        {
            macosarm::GuestAddressSpace vm;
            map_clock_page(vm, macosarm::Protection::read);
            ClockHost host;
            macosarm::CpuState state{};
            const auto result = run_gettimeofday(vm, host, state, clock_tv, 0U, 0U);
            expect(static_cast<bool>(result) &&
                       state.x[0] == macosarm::kDarwinErrnoEfault && carry_is_set(state) &&
                       host.calls == 0U && clock_sentinel_at(vm, kClockBase, kClockPage),
                   "read-only timeval page faults without a clock read");
        }

        {
            macosarm::GuestAddressSpace vm;
            map_clock_page(vm, clock_rw);
            ClockHost host;
            host.next_error = 5U; // EIO reported by the host clock
            macosarm::CpuState state{};
            const auto result = run_gettimeofday(vm, host, state, clock_tv, clock_tz, 0U);
            expect(static_cast<bool>(result) && state.x[0] == 5U && carry_is_set(state) &&
                       host.calls == 1U && clock_sentinel_at(vm, kClockBase, kClockPage),
                   "host clock errno is returned without timeval or timezone copyout");
        }

        {
            macosarm::GuestAddressSpace vm;
            map_clock_page(vm, clock_rw);
            ClockHost host;
            host.seconds = 1700000000;
            host.microseconds = 1000000U;
            macosarm::CpuState state{};
            const auto result = run_gettimeofday(vm, host, state, clock_tv, clock_tz, 0U);
            expect(!static_cast<bool>(result) && host.calls == 1U &&
                       clock_sentinel_at(vm, kClockBase, kClockPage),
                   "out-of-range host microseconds is a contract violation with no copyout");
        }

        {
            macosarm::GuestAddressSpace vm;
            map_clock_page(vm, clock_rw);
            ClockHost host;
            macosarm::CpuState state{};
            const auto result =
                run_gettimeofday(vm, host, state, clock_tv, clock_tz, kClockBase + 64U);
            expect(static_cast<bool>(result) &&
                       state.x[0] == macosarm::kDarwinErrnoEnosys && carry_is_set(state) &&
                       host.calls == 0U && clock_sentinel_at(vm, kClockBase, kClockPage),
                   "mach_absolute_time out-parameter is refused before any copyout");
        }

        {
            // XNU copies the timeval out before the timezone, so a bad zone
            // pointer still reports EFAULT after the time was delivered.
            macosarm::GuestAddressSpace vm;
            map_clock_page(vm, clock_rw);
            ClockHost host;
            host.seconds = 1700000000;
            host.microseconds = 42U;
            macosarm::CpuState state{};
            const auto result = run_gettimeofday(vm, host, state, clock_tv, clock_unmapped, 0U);
            std::uint64_t seconds = 0;
            std::uint64_t microseconds = 0;
            expect(static_cast<bool>(result) &&
                       state.x[0] == macosarm::kDarwinErrnoEfault && carry_is_set(state) &&
                       host.calls == 1U && read_guest_le(vm, clock_tv, 8U, seconds) &&
                       seconds == 1700000000U &&
                       read_guest_le(vm, clock_tv + 8U, 4U, microseconds) && microseconds == 42U,
                   "unmapped timezone faults after the timeval copyout, matching XNU order");
        }
    }

    {
        // getrlimit(2): XNU syscalls.master #194. Only w0 selects the resource,
        // _RLIMIT_POSIX_FLAG is stripped before the host is asked, and the LP64
        // struct rlimit is the only thing copied out.
        constexpr std::uint64_t limit_buffer = kClockBase;
        constexpr std::uint64_t limit_unmapped = 0xdead00000000ULL;
        const auto limit_rw = macosarm::Protection::read | macosarm::Protection::write;

        {
            macosarm::GuestAddressSpace vm;
            map_clock_page(vm, limit_rw);
            LimitHost host;
            host.soft_limit = 256U;
            host.hard_limit = macosarm::kDarwinRlimInfinity;
            macosarm::CpuState state{};
            const auto result =
                run_getrlimit(vm, host, state, macosarm::kDarwinRlimitNofile, limit_buffer);
            std::uint64_t soft = 0;
            std::uint64_t hard = 0;
            expect(static_cast<bool>(result) &&
                       result.action == macosarm::SyscallAction::resume &&
                       result.syscall_number == macosarm::kDarwinSysGetrlimit &&
                       state.x[0] == 0U && !carry_is_set(state) &&
                       host.queries == std::vector<std::uint32_t>{macosarm::kDarwinRlimitNofile} &&
                       read_guest_le(vm, limit_buffer, 8U, soft) && soft == 256U &&
                       read_guest_le(vm, limit_buffer + 8U, 8U, hard) &&
                       hard == macosarm::kDarwinRlimInfinity &&
                       clock_sentinel_at(vm, limit_buffer + macosarm::kDarwinRlimitSize,
                                         kClockPage - macosarm::kDarwinRlimitSize),
                   "getrlimit copies rlim_cur and rlim_max out as a 16-byte struct rlimit");

            host.queries.clear();
            host.soft_limit = 8U * 1024U * 1024U;
            host.hard_limit = 64U * 1024U * 1024U;
            const std::uint64_t which = 0xffffffff00000000ULL |
                                        macosarm::kDarwinRlimitPosixFlag |
                                        macosarm::kDarwinRlimitStack;
            const auto flagged = run_getrlimit(vm, host, state, which, limit_buffer);
            expect(static_cast<bool>(flagged) && state.x[0] == 0U && !carry_is_set(state) &&
                       host.queries == std::vector<std::uint32_t>{macosarm::kDarwinRlimitStack} &&
                       read_guest_le(vm, limit_buffer, 8U, soft) && soft == 8U * 1024U * 1024U &&
                       read_guest_le(vm, limit_buffer + 8U, 8U, hard) &&
                       hard == 64U * 1024U * 1024U,
                   "getrlimit ignores the upper half of x0 and strips _RLIMIT_POSIX_FLAG");
        }

        {
            // Out-of-range resources report EINVAL before the destination is
            // checked, and no rejected call ever queries the host or writes.
            macosarm::GuestAddressSpace vm;
            map_clock_page(vm, limit_rw);
            LimitHost host;
            macosarm::CpuState state{};
            const auto past_end =
                run_getrlimit(vm, host, state, macosarm::kDarwinRlimNlimits, limit_buffer);
            const bool past_end_rejected = static_cast<bool>(past_end) &&
                                           state.x[0] == macosarm::kDarwinErrnoEinval &&
                                           carry_is_set(state);
            const auto flagged = run_getrlimit(
                vm, host, state, macosarm::kDarwinRlimitPosixFlag | macosarm::kDarwinRlimNlimits,
                limit_unmapped);
            expect(past_end_rejected && static_cast<bool>(flagged) &&
                       state.x[0] == macosarm::kDarwinErrnoEinval && carry_is_set(state) &&
                       host.queries.empty() && clock_sentinel_at(vm, kClockBase, kClockPage),
                   "resources at or above RLIM_NLIMITS report EINVAL before EFAULT");

            const auto unmapped =
                run_getrlimit(vm, host, state, macosarm::kDarwinRlimitCore, limit_unmapped);
            const bool unmapped_faults = static_cast<bool>(unmapped) &&
                                         state.x[0] == macosarm::kDarwinErrnoEfault &&
                                         carry_is_set(state);
            const auto crossing = run_getrlimit(vm, host, state, macosarm::kDarwinRlimitCore,
                                                kClockBase + kClockPage - 8U);
            expect(unmapped_faults && static_cast<bool>(crossing) &&
                       state.x[0] == macosarm::kDarwinErrnoEfault && carry_is_set(state) &&
                       host.queries.empty() && clock_sentinel_at(vm, kClockBase, kClockPage),
                   "unmapped or page-crossing struct rlimit faults before any host query");

            macosarm::GuestAddressSpace read_only_vm;
            map_clock_page(read_only_vm, macosarm::Protection::read);
            const auto read_only = run_getrlimit(read_only_vm, host, state,
                                                 macosarm::kDarwinRlimitNofile, limit_buffer);
            expect(static_cast<bool>(read_only) &&
                       state.x[0] == macosarm::kDarwinErrnoEfault && carry_is_set(state) &&
                       host.queries.empty() &&
                       clock_sentinel_at(read_only_vm, kClockBase, kClockPage),
                   "a read-only struct rlimit destination faults before any host query");
        }

        {
            // A host error is reported as is, after exactly one query, and
            // leaves the destination untouched.
            macosarm::GuestAddressSpace vm;
            map_clock_page(vm, limit_rw);
            LimitHost host;
            host.next_error = macosarm::kDarwinErrnoEbadf;
            macosarm::CpuState state{};
            const auto result =
                run_getrlimit(vm, host, state, macosarm::kDarwinRlimitNofile, limit_buffer);
            expect(static_cast<bool>(result) &&
                       state.x[0] == macosarm::kDarwinErrnoEbadf && carry_is_set(state) &&
                       host.queries == std::vector<std::uint32_t>{macosarm::kDarwinRlimitNofile} &&
                       clock_sentinel_at(vm, kClockBase, kClockPage),
                   "a host getrlimit error is reported without a copyout");
        }

        {
            // A soft limit above the hard limit, or a hard limit above
            // RLIM_INFINITY, is a host contract violation: nothing reaches the
            // guest. Equal limits at RLIM_INFINITY are still valid.
            struct Violation {
                std::uint64_t soft;
                std::uint64_t hard;
            };
            const std::array<Violation, 2> violations{{
                {512U, 256U},
                {macosarm::kDarwinRlimInfinity, ~std::uint64_t{0}},
            }};
            for (const Violation& violation : violations) {
                macosarm::GuestAddressSpace vm;
                map_clock_page(vm, limit_rw);
                LimitHost host;
                host.soft_limit = violation.soft;
                host.hard_limit = violation.hard;
                macosarm::CpuState state{};
                const auto violated =
                    run_getrlimit(vm, host, state, macosarm::kDarwinRlimitNofile, limit_buffer);
                expect(violated.error == macosarm::SyscallDispatchError::host_contract_violation &&
                           host.queries.size() == 1U &&
                           clock_sentinel_at(vm, kClockBase, kClockPage),
                       "getrlimit rejects inverted or out-of-range host limits");
            }

            macosarm::GuestAddressSpace vm;
            map_clock_page(vm, limit_rw);
            LimitHost host;
            host.soft_limit = macosarm::kDarwinRlimInfinity;
            host.hard_limit = macosarm::kDarwinRlimInfinity;
            macosarm::CpuState state{};
            const auto unlimited =
                run_getrlimit(vm, host, state, macosarm::kDarwinRlimitCpu, limit_buffer);
            std::uint64_t soft = 0;
            std::uint64_t hard = 0;
            expect(static_cast<bool>(unlimited) && state.x[0] == 0U && !carry_is_set(state) &&
                       read_guest_le(vm, limit_buffer, 8U, soft) &&
                       soft == macosarm::kDarwinRlimInfinity &&
                       read_guest_le(vm, limit_buffer + 8U, 8U, hard) &&
                       hard == macosarm::kDarwinRlimInfinity,
                   "getrlimit accepts equal soft and hard limits at RLIM_INFINITY");
        }

        {
            // Hosts that do not override resource_limit report ENOSYS, never
            // a fabricated limit.
            struct NoLimitHost final : macosarm::DarwinHostServices {
                macosarm::HostWriteResult write(std::int32_t,
                                                std::span<const std::byte>) override {
                    return {0, macosarm::kDarwinErrnoEbadf};
                }
            };
            macosarm::GuestAddressSpace vm;
            map_clock_page(vm, limit_rw);
            NoLimitHost host;
            macosarm::CpuState state{};
            const auto result =
                run_getrlimit(vm, host, state, macosarm::kDarwinRlimitNofile, limit_buffer);
            expect(static_cast<bool>(result) &&
                       state.x[0] == macosarm::kDarwinErrnoEnosys && carry_is_set(state) &&
                       clock_sentinel_at(vm, kClockBase, kClockPage),
                   "the default host reports ENOSYS for getrlimit");
        }
    }

    {
        // setrlimit(2): XNU syscalls.master #195. The struct rlimit is copied
        // in first, so a bad rlp is EFAULT whatever which is. Only w0 selects
        // the resource and _RLIMIT_POSIX_FLAG is stripped before the host is
        // asked. The synthetic non-root guest may lower either limit but never
        // raise one above the current hard limit, and nothing is copied out.
        constexpr std::uint64_t limit_buffer = kClockBase;
        constexpr std::uint64_t limit_unmapped = 0xdead00000000ULL;
        const auto limit_rw = macosarm::Protection::read | macosarm::Protection::write;
        using Commit = LimitHost::Commit;

        {
            macosarm::GuestAddressSpace vm;
            map_clock_page(vm, limit_rw);
            LimitHost host;
            host.soft_limit = 256U;
            host.hard_limit = 10240U;
            macosarm::CpuState state{};
            expect(write_guest_rlimit(vm, limit_buffer, 1024U, 10240U), "setrlimit request stores");
            const auto result =
                run_setrlimit(vm, host, state, macosarm::kDarwinRlimitNofile, limit_buffer);
            std::uint64_t soft = 0;
            std::uint64_t hard = 0;
            expect(static_cast<bool>(result) &&
                       result.action == macosarm::SyscallAction::resume &&
                       result.syscall_number == macosarm::kDarwinSysSetrlimit &&
                       state.x[0] == 0U && !carry_is_set(state) &&
                       host.queries == std::vector<std::uint32_t>{macosarm::kDarwinRlimitNofile} &&
                       host.commits ==
                           std::vector<Commit>{Commit{macosarm::kDarwinRlimitNofile, 1024U, 10240U}} &&
                       read_guest_le(vm, limit_buffer, 8U, soft) && soft == 1024U &&
                       read_guest_le(vm, limit_buffer + 8U, 8U, hard) && hard == 10240U &&
                       clock_sentinel_at(vm, limit_buffer + macosarm::kDarwinRlimitSize,
                                         kClockPage - macosarm::kDarwinRlimitSize),
                   "setrlimit raises the soft limit within the hard limit and copies nothing out");

            const auto readback = run_getrlimit(vm, host, state, macosarm::kDarwinRlimitNofile,
                                                limit_buffer + macosarm::kDarwinRlimitSize);
            expect(static_cast<bool>(readback) && state.x[0] == 0U && !carry_is_set(state) &&
                       read_guest_le(vm, limit_buffer + macosarm::kDarwinRlimitSize, 8U, soft) &&
                       soft == 1024U &&
                       read_guest_le(vm, limit_buffer + macosarm::kDarwinRlimitSize + 8U, 8U,
                                     hard) &&
                       hard == 10240U,
                   "getrlimit reports the limits a successful setrlimit committed");

            host.queries.clear();
            host.commits.clear();
            expect(write_guest_rlimit(vm, limit_buffer, 512U, 2048U), "setrlimit request stores");
            const std::uint64_t which = 0xffffffff00000000ULL |
                                        macosarm::kDarwinRlimitPosixFlag |
                                        macosarm::kDarwinRlimitNofile;
            const auto lowered = run_setrlimit(vm, host, state, which, limit_buffer);
            expect(static_cast<bool>(lowered) && state.x[0] == 0U && !carry_is_set(state) &&
                       host.queries == std::vector<std::uint32_t>{macosarm::kDarwinRlimitNofile} &&
                       host.commits ==
                           std::vector<Commit>{Commit{macosarm::kDarwinRlimitNofile, 512U, 2048U}},
                   "setrlimit ignores the upper half of x0, strips _RLIMIT_POSIX_FLAG and "
                   "lowers the hard limit");

            host.queries.clear();
            host.commits.clear();
            expect(write_guest_rlimit(vm, limit_buffer, 512U, 10240U), "setrlimit request stores");
            const auto raised =
                run_setrlimit(vm, host, state, macosarm::kDarwinRlimitNofile, limit_buffer);
            expect(static_cast<bool>(raised) && state.x[0] == macosarm::kDarwinErrnoEperm &&
                       carry_is_set(state) &&
                       host.queries == std::vector<std::uint32_t>{macosarm::kDarwinRlimitNofile} &&
                       host.commits.empty() && host.soft_limit == 512U && host.hard_limit == 2048U,
                   "a lowered hard limit can never be raised again by the non-root guest");
        }

        {
            // The copyin comes first: a bad rlp faults even for an out-of-range
            // resource. Neither a fault nor an out-of-range resource reaches
            // the host.
            macosarm::GuestAddressSpace vm;
            map_clock_page(vm, limit_rw);
            LimitHost host;
            macosarm::CpuState state{};
            const auto unmapped =
                run_setrlimit(vm, host, state, macosarm::kDarwinRlimitCore, limit_unmapped);
            const bool unmapped_faults = static_cast<bool>(unmapped) &&
                                         state.x[0] == macosarm::kDarwinErrnoEfault &&
                                         carry_is_set(state);
            const auto past_end_unmapped =
                run_setrlimit(vm, host, state, macosarm::kDarwinRlimNlimits, limit_unmapped);
            const bool past_end_faults = static_cast<bool>(past_end_unmapped) &&
                                         state.x[0] == macosarm::kDarwinErrnoEfault &&
                                         carry_is_set(state);
            const auto crossing = run_setrlimit(vm, host, state, macosarm::kDarwinRlimitCore,
                                                kClockBase + kClockPage - 8U);
            expect(unmapped_faults && past_end_faults && static_cast<bool>(crossing) &&
                       state.x[0] == macosarm::kDarwinErrnoEfault && carry_is_set(state) &&
                       host.queries.empty() && host.commits.empty(),
                   "an unmapped or page-crossing struct rlimit faults before EINVAL "
                   "or any host query");

            expect(write_guest_rlimit(vm, limit_buffer, 0U, 0U), "setrlimit request stores");
            const auto past_end =
                run_setrlimit(vm, host, state, macosarm::kDarwinRlimNlimits, limit_buffer);
            const bool past_end_rejected = static_cast<bool>(past_end) &&
                                           state.x[0] == macosarm::kDarwinErrnoEinval &&
                                           carry_is_set(state);
            const auto flagged = run_setrlimit(
                vm, host, state, macosarm::kDarwinRlimitPosixFlag | macosarm::kDarwinRlimNlimits,
                limit_buffer);
            expect(past_end_rejected && static_cast<bool>(flagged) &&
                       state.x[0] == macosarm::kDarwinErrnoEinval && carry_is_set(state) &&
                       host.queries.empty() && host.commits.empty(),
                   "resources at or above RLIM_NLIMITS report EINVAL without a host query");
        }

        {
            // Every request that copies in and names a valid resource is
            // checked against one snapshot of the current limits: an inverted
            // request is EINVAL even when it would also raise the hard limit,
            // and raising either limit above the current hard limit is EPERM.
            // No rejected request commits anything.
            struct Rejection {
                std::uint64_t soft;
                std::uint64_t hard;
                std::uint32_t error;
            };
            const std::array<Rejection, 4> rejections{{
                {2048U, 1024U, macosarm::kDarwinErrnoEinval},
                {8192U, 4096U, macosarm::kDarwinErrnoEinval},
                {8192U, 8192U, macosarm::kDarwinErrnoEperm},
                {256U, 8192U, macosarm::kDarwinErrnoEperm},
            }};
            for (const Rejection& rejection : rejections) {
                macosarm::GuestAddressSpace vm;
                map_clock_page(vm, limit_rw);
                LimitHost host;
                host.soft_limit = 256U;
                host.hard_limit = 4096U;
                macosarm::CpuState state{};
                expect(write_guest_rlimit(vm, limit_buffer, rejection.soft, rejection.hard),
                       "setrlimit request stores");
                const auto rejected =
                    run_setrlimit(vm, host, state, macosarm::kDarwinRlimitNofile, limit_buffer);
                expect(static_cast<bool>(rejected) && state.x[0] == rejection.error &&
                           carry_is_set(state) &&
                           host.queries ==
                               std::vector<std::uint32_t>{macosarm::kDarwinRlimitNofile} &&
                           host.commits.empty() && host.soft_limit == 256U &&
                           host.hard_limit == 4096U,
                       "setrlimit rejects inverted requests with EINVAL and raised limits "
                       "with EPERM");
            }

            macosarm::GuestAddressSpace vm;
            map_clock_page(vm, limit_rw);
            LimitHost host;
            host.soft_limit = 256U;
            host.hard_limit = 4096U;
            macosarm::CpuState state{};
            expect(write_guest_rlimit(vm, limit_buffer, 4096U, 4096U), "setrlimit request stores");
            const auto at_hard =
                run_setrlimit(vm, host, state, macosarm::kDarwinRlimitNofile, limit_buffer);
            const bool at_hard_accepted =
                static_cast<bool>(at_hard) && state.x[0] == 0U && !carry_is_set(state) &&
                host.commits ==
                    std::vector<Commit>{Commit{macosarm::kDarwinRlimitNofile, 4096U, 4096U}};

            host.soft_limit = macosarm::kDarwinRlimInfinity;
            host.hard_limit = macosarm::kDarwinRlimInfinity;
            host.commits.clear();
            expect(write_guest_rlimit(vm, limit_buffer, macosarm::kDarwinRlimInfinity,
                                      macosarm::kDarwinRlimInfinity),
                   "setrlimit request stores");
            const auto unlimited =
                run_setrlimit(vm, host, state, macosarm::kDarwinRlimitCpu, limit_buffer);
            expect(at_hard_accepted && static_cast<bool>(unlimited) && state.x[0] == 0U &&
                       !carry_is_set(state) &&
                       host.commits == std::vector<Commit>{Commit{macosarm::kDarwinRlimitCpu,
                                                                  macosarm::kDarwinRlimInfinity,
                                                                  macosarm::kDarwinRlimInfinity}},
                   "setrlimit accepts limits equal to the current hard limit, including "
                   "RLIM_INFINITY");
        }

        {
            // A host error from the current-limits snapshot or from the commit
            // is reported as is, and a failed commit keeps the previous limits.
            macosarm::GuestAddressSpace vm;
            map_clock_page(vm, limit_rw);
            LimitHost host;
            host.soft_limit = 256U;
            host.hard_limit = 4096U;
            host.next_error = macosarm::kDarwinErrnoEio;
            macosarm::CpuState state{};
            expect(write_guest_rlimit(vm, limit_buffer, 512U, 4096U), "setrlimit request stores");
            const auto snapshot_failed =
                run_setrlimit(vm, host, state, macosarm::kDarwinRlimitNofile, limit_buffer);
            const bool snapshot_error_reported =
                static_cast<bool>(snapshot_failed) && state.x[0] == macosarm::kDarwinErrnoEio &&
                carry_is_set(state) && host.queries.size() == 1U && host.commits.empty();

            host.queries.clear();
            host.commit_error = macosarm::kDarwinErrnoEio;
            const auto commit_failed =
                run_setrlimit(vm, host, state, macosarm::kDarwinRlimitNofile, limit_buffer);
            expect(snapshot_error_reported && static_cast<bool>(commit_failed) &&
                       state.x[0] == macosarm::kDarwinErrnoEio && carry_is_set(state) &&
                       host.queries == std::vector<std::uint32_t>{macosarm::kDarwinRlimitNofile} &&
                       host.commits ==
                           std::vector<Commit>{Commit{macosarm::kDarwinRlimitNofile, 512U, 4096U}} &&
                       host.soft_limit == 256U && host.hard_limit == 4096U,
                   "host snapshot and commit errors are reported as is and keep the previous "
                   "limits");
        }

        {
            // An inverted or out-of-range current-limits snapshot is a host
            // contract violation, and nothing is committed.
            struct Violation {
                std::uint64_t soft;
                std::uint64_t hard;
            };
            const std::array<Violation, 2> violations{{
                {512U, 256U},
                {macosarm::kDarwinRlimInfinity, ~std::uint64_t{0}},
            }};
            for (const Violation& violation : violations) {
                macosarm::GuestAddressSpace vm;
                map_clock_page(vm, limit_rw);
                LimitHost host;
                host.soft_limit = violation.soft;
                host.hard_limit = violation.hard;
                macosarm::CpuState state{};
                expect(write_guest_rlimit(vm, limit_buffer, 0U, 0U), "setrlimit request stores");
                const auto violated =
                    run_setrlimit(vm, host, state, macosarm::kDarwinRlimitNofile, limit_buffer);
                expect(violated.error == macosarm::SyscallDispatchError::host_contract_violation &&
                           host.queries.size() == 1U && host.commits.empty(),
                       "setrlimit rejects an inverted or out-of-range current-limits snapshot");
            }
        }

        {
            // A host that cannot report limits fails with ENOSYS before any
            // commit, and a host that reports limits but cannot change them
            // reports ENOSYS from the commit: never a fabricated success.
            struct NoLimitHost final : macosarm::DarwinHostServices {
                macosarm::HostWriteResult write(std::int32_t,
                                                std::span<const std::byte>) override {
                    return {0, macosarm::kDarwinErrnoEbadf};
                }
            };
            struct FixedLimitHost final : macosarm::DarwinHostServices {
                macosarm::HostWriteResult write(std::int32_t,
                                                std::span<const std::byte>) override {
                    return {0, macosarm::kDarwinErrnoEbadf};
                }
                macosarm::HostResourceLimitResult resource_limit(std::uint32_t) override {
                    return {256U, 4096U, 0};
                }
            };
            macosarm::GuestAddressSpace vm;
            map_clock_page(vm, limit_rw);
            expect(write_guest_rlimit(vm, limit_buffer, 128U, 4096U), "setrlimit request stores");
            NoLimitHost no_limits;
            macosarm::CpuState state{};
            const auto unreported =
                run_setrlimit(vm, no_limits, state, macosarm::kDarwinRlimitNofile, limit_buffer);
            const bool unreported_enosys = static_cast<bool>(unreported) &&
                                           state.x[0] == macosarm::kDarwinErrnoEnosys &&
                                           carry_is_set(state);
            FixedLimitHost fixed_limits;
            const auto unchangeable =
                run_setrlimit(vm, fixed_limits, state, macosarm::kDarwinRlimitNofile, limit_buffer);
            expect(unreported_enosys && static_cast<bool>(unchangeable) &&
                       state.x[0] == macosarm::kDarwinErrnoEnosys && carry_is_set(state),
                   "default hosts report ENOSYS for setrlimit");
        }
    }

    {
        // getdtablesize(2): XNU syscalls.master #89. The result is the host's
        // soft RLIMIT_NOFILE limit capped at INT_MAX, and no argument register
        // or guest memory is read.
        struct DtableHost final : macosarm::DarwinHostServices {
            std::vector<std::uint32_t> queries;
            std::uint64_t soft_limit{256U};
            std::uint64_t hard_limit{10240U};
            std::uint32_t next_error{};

            macosarm::HostWriteResult write(std::int32_t,
                                            std::span<const std::byte>) override {
                return {0, macosarm::kDarwinErrnoEbadf};
            }
            macosarm::HostResourceLimitResult resource_limit(std::uint32_t resource) override {
                queries.push_back(resource);
                if (next_error != 0) {
                    const std::uint32_t error = next_error;
                    next_error = 0;
                    return {0, 0, error};
                }
                return {soft_limit, hard_limit, 0};
            }
        };
        const auto run_getdtablesize = [](macosarm::DarwinHostServices& host,
                                          macosarm::CpuState& state) {
            // An empty address space proves no guest memory is touched, and
            // garbage argument registers prove none of them is read.
            macosarm::GuestAddressSpace vm;
            state = {};
            state.x[0] = 0xdeadbeefcafef00dULL;
            state.x[1] = 0x0123456789abcdefULL;
            state.x[16] = macosarm::kDarwinSysGetdtablesize;
            // Preset carry so every success test proves the dispatcher clears it.
            state.pstate = macosarm::kA64PstateCarry;
            return macosarm::dispatch_darwin_syscall(state, vm, svc(), host);
        };

        {
            DtableHost host;
            macosarm::CpuState state{};
            const auto result = run_getdtablesize(host, state);
            expect(static_cast<bool>(result) &&
                       result.action == macosarm::SyscallAction::resume &&
                       result.syscall_number == macosarm::kDarwinSysGetdtablesize &&
                       state.x[0] == 256U && !carry_is_set(state) &&
                       host.queries.size() == 1U &&
                       host.queries[0] == macosarm::kDarwinRlimitNofile,
                   "getdtablesize reports the soft RLIMIT_NOFILE limit and clears carry");
        }

        {
            struct Capped {
                std::uint64_t soft;
                std::uint64_t hard;
                std::uint64_t expected;
            };
            const Capped cases[] = {
                {0U, 0U, 0U},
                {0x7ffffffeU, 0x7ffffffeU, 0x7ffffffeU},
                {0x7fffffffU, 0x80000000U, 0x7fffffffU},
                {0x80000000U, 0x80000000U, 0x7fffffffU},
                {0x100000000ULL, macosarm::kDarwinRlimInfinity, 0x7fffffffU},
                {macosarm::kDarwinRlimInfinity, macosarm::kDarwinRlimInfinity, 0x7fffffffU},
            };
            bool all_capped = true;
            for (const Capped& c : cases) {
                DtableHost host;
                host.soft_limit = c.soft;
                host.hard_limit = c.hard;
                macosarm::CpuState state{};
                const auto result = run_getdtablesize(host, state);
                all_capped = all_capped && static_cast<bool>(result) &&
                             state.x[0] == c.expected && !carry_is_set(state);
            }
            expect(all_capped,
                   "getdtablesize caps the soft limit at INT_MAX, including RLIM_INFINITY");
        }

        {
            DtableHost host;
            host.next_error = macosarm::kDarwinErrnoEio;
            macosarm::CpuState state{};
            const auto result = run_getdtablesize(host, state);
            expect(static_cast<bool>(result) &&
                       state.x[0] == macosarm::kDarwinErrnoEio && carry_is_set(state) &&
                       host.queries.size() == 1U,
                   "getdtablesize reports a host resource_limit error as is");
        }

        {
            DtableHost inverted;
            inverted.soft_limit = 4096U;
            inverted.hard_limit = 1024U;
            macosarm::CpuState state{};
            const auto inverted_result = run_getdtablesize(inverted, state);
            DtableHost out_of_range;
            out_of_range.soft_limit = 1024U;
            out_of_range.hard_limit = macosarm::kDarwinRlimInfinity + 1U;
            const auto out_of_range_result = run_getdtablesize(out_of_range, state);
            expect(!static_cast<bool>(inverted_result) &&
                       !static_cast<bool>(out_of_range_result),
                   "getdtablesize rejects an inverted or out-of-range limits snapshot");
        }

        {
            struct NoLimitHost final : macosarm::DarwinHostServices {
                macosarm::HostWriteResult write(std::int32_t,
                                                std::span<const std::byte>) override {
                    return {0, macosarm::kDarwinErrnoEbadf};
                }
            };
            NoLimitHost host;
            macosarm::CpuState state{};
            const auto result = run_getdtablesize(host, state);
            expect(static_cast<bool>(result) &&
                       state.x[0] == macosarm::kDarwinErrnoEnosys && carry_is_set(state),
                   "default hosts report ENOSYS for getdtablesize");
        }
    }

    {
        // dup(2): XNU syscalls.master #41. fd is a u_int, so only w0 counts;
        // a value negative as an int is EBADF before the host sees it. The
        // host's descriptor reaches the guest as is, including one below fd,
        // but a negative descriptor or fd itself is a host contract violation.
        struct DupHost final : macosarm::DarwinHostServices {
            std::vector<std::int32_t> open_fds{0, 1, 2};
            std::vector<std::int32_t> requests;
            std::int32_t table_size{256};
            bool forced{false};
            std::int32_t forced_descriptor{};

            macosarm::HostWriteResult write(std::int32_t,
                                            std::span<const std::byte>) override {
                return {0, macosarm::kDarwinErrnoEbadf};
            }
            macosarm::HostDuplicateResult duplicate(std::int32_t fd) override {
                requests.push_back(fd);
                if (std::find(open_fds.begin(), open_fds.end(), fd) == open_fds.end()) {
                    return {0, macosarm::kDarwinErrnoEbadf};
                }
                if (forced) {
                    return {forced_descriptor, 0};
                }
                for (std::int32_t candidate = 0; candidate < table_size; ++candidate) {
                    if (std::find(open_fds.begin(), open_fds.end(), candidate) ==
                        open_fds.end()) {
                        open_fds.push_back(candidate);
                        return {candidate, 0};
                    }
                }
                return {0, macosarm::kDarwinErrnoEmfile};
            }
        };
        const auto run_dup = [](macosarm::DarwinHostServices& host,
                                macosarm::CpuState& state,
                                std::uint64_t x0,
                                bool preset_carry) {
            // An empty address space proves no guest memory is touched.
            macosarm::GuestAddressSpace vm;
            state = {};
            state.x[0] = x0;
            state.x[1] = 0x0123456789abcdefULL;
            state.x[16] = macosarm::kDarwinSysDup;
            if (preset_carry) {
                state.pstate = macosarm::kA64PstateCarry;
            }
            return macosarm::dispatch_darwin_syscall(state, vm, svc(), host);
        };

        {
            DupHost host;
            macosarm::CpuState state{};
            const auto result = run_dup(host, state, 1U, true);
            expect(static_cast<bool>(result) &&
                       result.action == macosarm::SyscallAction::resume &&
                       result.syscall_number == macosarm::kDarwinSysDup &&
                       state.x[0] == 3U && !carry_is_set(state) &&
                       host.requests == std::vector<std::int32_t>{1},
                   "dup returns the host's new descriptor and clears carry");
        }

        {
            DupHost host;
            macosarm::CpuState state{};
            const auto result = run_dup(host, state, 0xffffffff00000002ULL, true);
            expect(static_cast<bool>(result) && state.x[0] == 3U && !carry_is_set(state) &&
                       host.requests == std::vector<std::int32_t>{2},
                   "dup reads only w0 for its u_int descriptor");
        }

        {
            DupHost host;
            host.open_fds = {0, 2, 3};
            macosarm::CpuState state{};
            const auto result = run_dup(host, state, 3U, true);
            expect(static_cast<bool>(result) && state.x[0] == 1U && !carry_is_set(state),
                   "dup passes through a lowest free descriptor below fd");
        }

        {
            const std::uint64_t negatives[] = {0x80000000ULL, 0xfffffffeULL, 0xffffffffULL};
            bool all_rejected = true;
            for (const std::uint64_t x0 : negatives) {
                DupHost host;
                macosarm::CpuState state{};
                const auto result = run_dup(host, state, x0, false);
                all_rejected = all_rejected && static_cast<bool>(result) &&
                               state.x[0] == macosarm::kDarwinErrnoEbadf &&
                               carry_is_set(state) && host.requests.empty();
            }
            expect(all_rejected, "dup rejects a negative descriptor with EBADF before the host");
        }

        {
            DupHost host;
            macosarm::CpuState state{};
            const auto result = run_dup(host, state, 7U, false);
            expect(static_cast<bool>(result) &&
                       state.x[0] == macosarm::kDarwinErrnoEbadf && carry_is_set(state) &&
                       host.requests == std::vector<std::int32_t>{7} &&
                       host.open_fds.size() == 3U,
                   "dup reports the host's EBADF for a descriptor that is not open");
        }

        {
            DupHost host;
            host.table_size = 3;
            macosarm::CpuState state{};
            const auto result = run_dup(host, state, 0U, false);
            expect(static_cast<bool>(result) &&
                       state.x[0] == macosarm::kDarwinErrnoEmfile && carry_is_set(state) &&
                       host.open_fds.size() == 3U,
                   "dup reports EMFILE for a full descriptor table");
        }

        {
            DupHost negative;
            negative.forced = true;
            negative.forced_descriptor = -1;
            macosarm::CpuState state{};
            const auto negative_result = run_dup(negative, state, 1U, false);
            DupHost same;
            same.forced = true;
            same.forced_descriptor = 2;
            const auto same_result = run_dup(same, state, 2U, false);
            expect(!static_cast<bool>(negative_result) && !static_cast<bool>(same_result),
                   "dup rejects a negative descriptor or fd itself from the host");
        }

        {
            struct NoDupHost final : macosarm::DarwinHostServices {
                macosarm::HostWriteResult write(std::int32_t,
                                                std::span<const std::byte>) override {
                    return {0, macosarm::kDarwinErrnoEbadf};
                }
            };
            NoDupHost host;
            macosarm::CpuState state{};
            const auto result = run_dup(host, state, 1U, false);
            expect(static_cast<bool>(result) &&
                       state.x[0] == macosarm::kDarwinErrnoEbadf && carry_is_set(state),
                   "default hosts report EBADF for dup");
        }
    }

    {
        // dup2(2): XNU syscalls.master #90. from and to are u_ints, so only w0
        // and w1 count; a value negative as an int is EBADF before the host
        // sees it. A host success must name to; any other descriptor is a host
        // contract violation and never reaches the guest.
        struct Dup2Host final : macosarm::DarwinHostServices {
            std::vector<std::int32_t> open_fds{0, 1, 2};
            std::vector<std::int32_t> from_requests;
            std::vector<std::int32_t> to_requests;
            std::int32_t table_size{256};
            bool forced{false};
            std::int32_t forced_descriptor{};

            macosarm::HostWriteResult write(std::int32_t,
                                            std::span<const std::byte>) override {
                return {0, macosarm::kDarwinErrnoEbadf};
            }
            [[nodiscard]] bool has_open(std::int32_t fd) const {
                return std::find(open_fds.begin(), open_fds.end(), fd) != open_fds.end();
            }
            macosarm::HostDuplicateResult duplicate_to(std::int32_t from,
                                                       std::int32_t to) override {
                from_requests.push_back(from);
                to_requests.push_back(to);
                if (!has_open(from) || to >= table_size) {
                    return {0, macosarm::kDarwinErrnoEbadf};
                }
                if (forced) {
                    return {forced_descriptor, 0};
                }
                if (!has_open(to)) {
                    open_fds.push_back(to);
                }
                return {to, 0};
            }
        };
        const auto run_dup2 = [](macosarm::DarwinHostServices& host,
                                 macosarm::CpuState& state,
                                 std::uint64_t x0,
                                 std::uint64_t x1,
                                 bool preset_carry) {
            // An empty address space proves no guest memory is touched.
            macosarm::GuestAddressSpace vm;
            state = {};
            state.x[0] = x0;
            state.x[1] = x1;
            state.x[2] = 0x0123456789abcdefULL;
            state.x[16] = macosarm::kDarwinSysDup2;
            if (preset_carry) {
                state.pstate = macosarm::kA64PstateCarry;
            }
            return macosarm::dispatch_darwin_syscall(state, vm, svc(), host);
        };

        {
            Dup2Host host;
            macosarm::CpuState state{};
            const auto result = run_dup2(host, state, 1U, 5U, true);
            expect(static_cast<bool>(result) &&
                       result.action == macosarm::SyscallAction::resume &&
                       result.syscall_number == macosarm::kDarwinSysDup2 &&
                       state.x[0] == 5U && !carry_is_set(state) &&
                       host.from_requests == std::vector<std::int32_t>{1} &&
                       host.to_requests == std::vector<std::int32_t>{5} &&
                       host.has_open(5),
                   "dup2 returns to as the host's duplicate and clears carry");
        }

        {
            Dup2Host host;
            macosarm::CpuState state{};
            const auto result =
                run_dup2(host, state, 0xffffffff00000001ULL, 0xabcdef0000000004ULL, true);
            expect(static_cast<bool>(result) && state.x[0] == 4U && !carry_is_set(state) &&
                       host.from_requests == std::vector<std::int32_t>{1} &&
                       host.to_requests == std::vector<std::int32_t>{4},
                   "dup2 reads only w0 and w1 for its u_int descriptors");
        }

        {
            Dup2Host host;
            macosarm::CpuState state{};
            const auto result = run_dup2(host, state, 2U, 2U, true);
            expect(static_cast<bool>(result) && state.x[0] == 2U && !carry_is_set(state) &&
                       host.open_fds.size() == 3U,
                   "dup2 onto from itself returns to and changes nothing");
        }

        {
            const std::uint64_t negatives[][2] = {{0x80000000ULL, 3U},
                                                  {1U, 0xffffffffULL},
                                                  {0xfffffffeULL, 0x80000000ULL}};
            bool all_rejected = true;
            for (const auto& args : negatives) {
                Dup2Host host;
                macosarm::CpuState state{};
                const auto result = run_dup2(host, state, args[0], args[1], false);
                all_rejected = all_rejected && static_cast<bool>(result) &&
                               state.x[0] == macosarm::kDarwinErrnoEbadf &&
                               carry_is_set(state) && host.from_requests.empty();
            }
            expect(all_rejected,
                   "dup2 rejects a negative from or to with EBADF before the host");
        }

        {
            Dup2Host host;
            macosarm::CpuState state{};
            const auto result = run_dup2(host, state, 7U, 3U, false);
            expect(static_cast<bool>(result) &&
                       state.x[0] == macosarm::kDarwinErrnoEbadf && carry_is_set(state) &&
                       host.from_requests == std::vector<std::int32_t>{7} &&
                       !host.has_open(3),
                   "dup2 reports the host's EBADF for a from that is not open");
        }

        {
            Dup2Host host;
            host.table_size = 8;
            macosarm::CpuState state{};
            const auto result = run_dup2(host, state, 1U, 8U, false);
            expect(static_cast<bool>(result) &&
                       state.x[0] == macosarm::kDarwinErrnoEbadf && carry_is_set(state) &&
                       host.to_requests == std::vector<std::int32_t>{8} &&
                       host.open_fds.size() == 3U,
                   "dup2 reports the host's EBADF for a to at the descriptor limit");
        }

        {
            Dup2Host other;
            other.forced = true;
            other.forced_descriptor = 4;
            macosarm::CpuState state{};
            const auto other_result = run_dup2(other, state, 1U, 5U, false);
            Dup2Host negative;
            negative.forced = true;
            negative.forced_descriptor = -1;
            const auto negative_result = run_dup2(negative, state, 1U, 5U, false);
            Dup2Host source;
            source.forced = true;
            source.forced_descriptor = 1;
            const auto source_result = run_dup2(source, state, 1U, 5U, false);
            expect(!static_cast<bool>(other_result) && !static_cast<bool>(negative_result) &&
                       !static_cast<bool>(source_result),
                   "dup2 rejects a host success that does not name to");
        }

        {
            struct NoDup2Host final : macosarm::DarwinHostServices {
                macosarm::HostWriteResult write(std::int32_t,
                                                std::span<const std::byte>) override {
                    return {0, macosarm::kDarwinErrnoEbadf};
                }
            };
            NoDup2Host host;
            macosarm::CpuState state{};
            const auto result = run_dup2(host, state, 1U, 5U, false);
            expect(static_cast<bool>(result) &&
                       state.x[0] == macosarm::kDarwinErrnoEbadf && carry_is_set(state),
                   "default hosts report EBADF for dup2");
        }
    }

    {
        // close(2) / close_nocancel(2): XNU syscalls.master #6 and #399.
        {
            CloseHost host;
            host.open_fds = {3, 4};
            macosarm::CpuState state{};
            const auto result = run_close(host, state, macosarm::kDarwinSysClose, 3U);
            expect(static_cast<bool>(result) &&
                       result.action == macosarm::SyscallAction::resume &&
                       result.syscall_number == macosarm::kDarwinSysClose &&
                       state.x[0] == 0U && !carry_is_set(state) &&
                       host.requests.size() == 1U && host.requests[0] == 3 &&
                       !close_host_has_open(host, 3) && close_host_has_open(host, 4),
                   "close releases only the requested descriptor and clears carry");
        }

        {
            CloseHost host;
            host.open_fds = {5};
            macosarm::CpuState state{};
            const auto result =
                run_close(host, state, macosarm::kDarwinSysCloseNocancel, 5U);
            expect(static_cast<bool>(result) &&
                       result.action == macosarm::SyscallAction::resume &&
                       result.syscall_number == macosarm::kDarwinSysCloseNocancel &&
                       state.x[0] == 0U && !carry_is_set(state) &&
                       host.requests.size() == 1U && host.requests[0] == 5 &&
                       host.open_fds.empty(),
                   "close_nocancel shares close's descriptor contract");
        }

        {
            CloseHost host;
            host.open_fds = {3};
            macosarm::CpuState state{};
            const auto first = run_close(host, state, macosarm::kDarwinSysClose, 3U);
            const bool first_closed =
                static_cast<bool>(first) && state.x[0] == 0U && !carry_is_set(state);
            const auto second = run_close(host, state, macosarm::kDarwinSysClose, 3U);
            expect(first_closed && static_cast<bool>(second) &&
                       state.x[0] == macosarm::kDarwinErrnoEbadf && carry_is_set(state) &&
                       host.requests.size() == 2U,
                   "closing an already released descriptor reports EBADF");
        }

        {
            // A negative descriptor fails before the host is consulted.
            CloseHost host;
            host.open_fds = {0};
            macosarm::CpuState state{};
            const auto result =
                run_close(host, state, macosarm::kDarwinSysClose, 0xffffffffULL);
            expect(static_cast<bool>(result) &&
                       state.x[0] == macosarm::kDarwinErrnoEbadf && carry_is_set(state) &&
                       host.requests.empty() && close_host_has_open(host, 0),
                   "negative descriptor returns EBADF without a host close");
        }

        {
            // XNU reads the int fd from the low 32 bits of x0.
            CloseHost host;
            host.open_fds = {7};
            macosarm::CpuState state{};
            const auto result =
                run_close(host, state, macosarm::kDarwinSysClose, 0xffffffff00000007ULL);
            expect(static_cast<bool>(result) && state.x[0] == 0U && !carry_is_set(state) &&
                       host.requests.size() == 1U && host.requests[0] == 7 &&
                       host.open_fds.empty(),
                   "close truncates the descriptor register to a 32-bit int");
        }

        {
            // The host may release the descriptor and still report an error;
            // the error is returned once and the close is never retried.
            CloseHost host;
            host.open_fds = {9};
            host.release_error = macosarm::kDarwinErrnoEio;
            macosarm::CpuState state{};
            const auto result = run_close(host, state, macosarm::kDarwinSysClose, 9U);
            expect(static_cast<bool>(result) &&
                       state.x[0] == macosarm::kDarwinErrnoEio && carry_is_set(state) &&
                       host.requests.size() == 1U && !close_host_has_open(host, 9),
                   "host close error after release is reported once without retry");
        }
    }

    {
        // fstat64(2): descriptor resolution, arm64 stat64 encoding, copyout
        // faults and host contract enforcement.
        const auto rw = macosarm::Protection::read | macosarm::Protection::write;
        const auto stat_sentinel_intact = [](macosarm::GuestAddressSpace& space) {
            std::vector<std::byte> page(static_cast<std::size_t>(kStatPage));
            return static_cast<bool>(space.read(kStatBase, page)) &&
                   std::all_of(page.begin(), page.end(),
                               [](std::byte value) { return value == kStatSentinel; });
        };

        {
            // Success writes all 144 bytes at their XNU offsets with zero
            // padding and spares, returns 0 in x0 and clears a stale carry.
            macosarm::GuestAddressSpace vm;
            map_stat_page(vm, rw);
            StatHost host;
            host.status = sample_file_status();
            macosarm::CpuState state{};
            const auto result = run_fstat64(vm, host, state, 3U, kStatBase);
            expect(static_cast<bool>(result) && result.action == macosarm::SyscallAction::resume &&
                       result.syscall_number == macosarm::kDarwinSysFstat64,
                   "fstat64 dispatch resumes guest and reports its syscall number");
            expect(state.x[0] == 0 && !carry_is_set(state) &&
                       host.requests == std::vector<std::int32_t>{3},
                   "fstat64 success returns 0, clears carry and queries the fd once");

            std::vector<std::byte> record(macosarm::kDarwinStat64Size + 8U);
            expect(static_cast<bool>(vm.read(kStatBase, record)), "stat64 record reads back");
            const auto field = [&](std::size_t offset, std::size_t width) {
                std::uint64_t value = 0;
                for (std::size_t i = 0; i < width; ++i) {
                    value |= static_cast<std::uint64_t>(record[offset + i]) << (8U * i);
                }
                return value;
            };
            expect(field(0, 4) == 0x81020304U && field(4, 2) == 0x81a4U && field(6, 2) == 2U &&
                       field(8, 8) == 0x0123456789abcdefULL,
                   "stat64 encodes st_dev, st_mode, st_nlink and st_ino");
            expect(field(16, 4) == macosarm::kDarwinSyntheticUserId &&
                       field(20, 4) == macosarm::kDarwinSyntheticGroupId &&
                       field(24, 4) == 0x0a0b0c0dU && field(28, 4) == 0U,
                   "stat64 encodes st_uid, st_gid, st_rdev and zero padding");
            expect(field(32, 8) == 1700000000U && field(40, 8) == 111111111U &&
                       field(48, 8) == 1700000001U && field(56, 8) == 222222222U &&
                       field(64, 8) == 1700000002U && field(72, 8) == 333333333U,
                   "stat64 encodes access, modification and change times");
            expect(field(80, 8) == ~std::uint64_t{0} && field(88, 8) == 999999999U,
                   "stat64 sign-extends a pre-epoch birth time");
            expect(field(96, 8) == 0x0000000100000fffULL && field(104, 8) == 0x2008U &&
                       field(112, 4) == 4096U && field(116, 4) == 0x8000U,
                   "stat64 encodes st_size, st_blocks, st_blksize and st_flags");
            const auto zero = [](std::byte value) { return value == std::byte{0}; };
            const auto sentinel = [](std::byte value) { return value == kStatSentinel; };
            expect(std::all_of(record.begin() + 120, record.begin() + 144, zero) &&
                       std::all_of(record.begin() + 144, record.end(), sentinel),
                   "stat64 zeroes st_gen and spares and writes nothing past 144 bytes");
        }

        {
            // Negative descriptors (taken from w0) fail with EBADF before the
            // host is consulted; host errors set carry and copy nothing out.
            macosarm::GuestAddressSpace vm;
            map_stat_page(vm, rw);
            StatHost host;
            host.status = sample_file_status();
            macosarm::CpuState state{};
            const std::array<std::uint64_t, 2> negative{0xffffffffULL, 0x80000000ULL};
            for (const std::uint64_t fd : negative) {
                const auto rejected = run_fstat64(vm, host, state, fd, kStatBase);
                expect(static_cast<bool>(rejected) &&
                           state.x[0] == macosarm::kDarwinErrnoEbadf && carry_is_set(state),
                       "negative fstat64 descriptor returns EBADF and sets carry");
            }
            expect(host.requests.empty(), "negative fstat64 descriptors never reach the host");

            const auto unknown = run_fstat64(vm, host, state, 4U, kStatBase);
            expect(static_cast<bool>(unknown) && state.x[0] == macosarm::kDarwinErrnoEbadf &&
                       carry_is_set(state),
                   "unknown fstat64 descriptor returns the host EBADF");
            host.next_error = macosarm::kDarwinErrnoEio;
            const auto failed = run_fstat64(vm, host, state, 3U, kStatBase);
            expect(static_cast<bool>(failed) && state.x[0] == macosarm::kDarwinErrnoEio &&
                       carry_is_set(state),
                   "host fstat64 failure returns its errno and sets carry");
            expect(host.requests == std::vector<std::int32_t>{4, 3} && stat_sentinel_intact(vm),
                   "failed fstat64 queries each fd once and writes no guest bytes");

            const auto widened = run_fstat64(vm, host, state, 0xffffffff00000003ULL, kStatBase);
            expect(static_cast<bool>(widened) && state.x[0] == 0 && !carry_is_set(state),
                   "fstat64 ignores the upper 32 bits of the descriptor register");
        }

        {
            // Copyout faults: the descriptor resolves first, as in XNU, then an
            // unwritable, unmapped or page-crossing destination fails with
            // EFAULT before any byte of the record reaches guest memory.
            const auto check_fault = [&](macosarm::Protection protection, std::uint64_t address,
                                         const std::string& label) {
                macosarm::GuestAddressSpace vm;
                map_stat_page(vm, protection);
                StatHost host;
                host.status = sample_file_status();
                macosarm::CpuState state{};
                const auto faulted = run_fstat64(vm, host, state, 3U, address);
                expect(static_cast<bool>(faulted) &&
                           state.x[0] == macosarm::kDarwinErrnoEfault && carry_is_set(state),
                       label + " returns EFAULT and sets carry");
                expect(host.requests == std::vector<std::int32_t>{3} && stat_sentinel_intact(vm),
                       label + " resolves the fd once and writes no guest bytes");
            };
            check_fault(macosarm::Protection::read, kStatBase, "read-only fstat64 buffer");
            check_fault(rw, 0xdead00000000ULL, "unmapped fstat64 buffer");
            check_fault(rw, kStatBase + kStatPage - 64U, "fstat64 buffer crossing an unmapped page");
        }

        {
            // A malformed host status is a host contract violation: no errno
            // is delivered and no part of the record is copied to the guest.
            const auto check_violation = [&](const macosarm::HostFileStatus& status,
                                             const std::string& label) {
                macosarm::GuestAddressSpace vm;
                map_stat_page(vm, rw);
                StatHost host;
                host.status = status;
                macosarm::CpuState state{};
                const auto result = run_fstat64(vm, host, state, 3U, kStatBase);
                expect(result.error == macosarm::SyscallDispatchError::host_contract_violation &&
                           result.syscall_number == macosarm::kDarwinSysFstat64,
                       label + " is a host contract violation");
                expect(host.requests.size() == 1U && stat_sentinel_intact(vm),
                       label + " queries the host once and writes no guest bytes");
            };
            auto untyped = sample_file_status();
            untyped.mode = static_cast<std::uint16_t>(0644U);
            check_violation(untyped, "fstat64 mode without a file type");
            auto whiteout = sample_file_status();
            whiteout.mode = static_cast<std::uint16_t>(0160000U | 0644U); // S_IFWHT
            check_violation(whiteout, "fstat64 whiteout file type");
            auto full_second = sample_file_status();
            full_second.modification_time.nanoseconds = 1000000000;
            check_violation(full_second, "fstat64 nanoseconds of a full second");
            auto negative_nanoseconds = sample_file_status();
            negative_nanoseconds.birth_time.nanoseconds = -1;
            check_violation(negative_nanoseconds, "fstat64 negative nanoseconds");
        }
    }

    {
        // ioctl(2): TIOCGETA / TIOCGWINSZ record encoding, descriptor
        // resolution, copyin/copyout fault ordering and the unmodeled
        // file-table requests.
        const auto rw = macosarm::Protection::read | macosarm::Protection::write;
        const auto le_field = [](std::span<const std::byte> record,
                                 std::size_t offset,
                                 std::size_t width) {
            std::uint64_t value = 0;
            for (std::size_t i = 0; i < width; ++i) {
                value |= static_cast<std::uint64_t>(record[offset + i]) << (8U * i);
            }
            return value;
        };

        {
            // TIOCGWINSZ on a terminal copies out exactly the 8-byte winsize,
            // returns 0 in x0 and clears a stale carry.
            macosarm::GuestAddressSpace vm;
            map_ioctl_page(vm, rw);
            TerminalHost host;
            macosarm::CpuState state{};
            const auto result =
                run_ioctl(vm, host, state, 0U, macosarm::kDarwinIoctlTiocgwinsz, kIoctlBase);
            expect(static_cast<bool>(result) && result.action == macosarm::SyscallAction::resume &&
                       result.syscall_number == macosarm::kDarwinSysIoctl,
                   "ioctl dispatch resumes guest and reports its syscall number");
            expect(state.x[0] == 0 && !carry_is_set(state) &&
                       host.requests == std::vector<std::int32_t>{0},
                   "TIOCGWINSZ success returns 0, clears carry and queries the fd once");
            std::vector<std::byte> record(macosarm::kDarwinWinsizeSize);
            expect(static_cast<bool>(vm.read(kIoctlBase, record)) &&
                       le_field(record, 0, 2) == 0x1234U && le_field(record, 2, 2) == 0x5678U &&
                       le_field(record, 4, 2) == 0x9abcU && le_field(record, 6, 2) == 0xdef0U,
                   "TIOCGWINSZ encodes ws_row, ws_col, ws_xpixel and ws_ypixel");
            expect(ioctl_sentinel_from(vm, macosarm::kDarwinWinsizeSize),
                   "TIOCGWINSZ writes nothing past the 8-byte winsize");
        }

        {
            // TIOCGETA on a terminal copies out the synthetic cooked-mode
            // termios: XNU ttydefaults.h flags, ttydefchars and B9600.
            macosarm::GuestAddressSpace vm;
            map_ioctl_page(vm, rw);
            TerminalHost host;
            macosarm::CpuState state{};
            const auto result =
                run_ioctl(vm, host, state, 0U, macosarm::kDarwinIoctlTiocgeta, kIoctlBase);
            expect(static_cast<bool>(result) && state.x[0] == 0 && !carry_is_set(state) &&
                       host.requests == std::vector<std::int32_t>{0},
                   "TIOCGETA success returns 0, clears carry and queries the fd once");
            std::vector<std::byte> record(macosarm::kDarwinTermiosSize);
            expect(static_cast<bool>(vm.read(kIoctlBase, record)), "termios record reads back");
            expect(le_field(record, 0, 8) == 0x2b02U && le_field(record, 8, 8) == 0x0003U &&
                       le_field(record, 16, 8) == 0x4b00U && le_field(record, 24, 8) == 0x05cbU,
                   "TIOCGETA encodes TTYDEF_IFLAG, OFLAG, CFLAG and LFLAG");
            // ttydefchars: CEOF, CEOL, CEOL, CERASE, CWERASE, CKILL, CREPRINT,
            // spare, CINTR, CQUIT, CSUSP, CDSUSP, CSTART, CSTOP, CLNEXT,
            // CDISCARD, CMIN, CTIME, CSTATUS, spare; 0xff is _POSIX_VDISABLE.
            constexpr std::array<std::uint8_t, macosarm::kDarwinTermiosControlCharCount> chars{
                0x04, 0xff, 0xff, 0x7f, 0x17, 0x15, 0x12, 0xff, 0x03, 0x1c,
                0x1a, 0x19, 0x11, 0x13, 0x16, 0x0f, 0x01, 0x00, 0x14, 0xff,
            };
            bool chars_match = true;
            for (std::size_t i = 0; i < chars.size(); ++i) {
                chars_match = chars_match && le_field(record, 32U + i, 1) == chars[i];
            }
            expect(chars_match, "TIOCGETA encodes ttydefchars in c_cc index order");
            expect(le_field(record, 52, 4) == 0U && le_field(record, 56, 8) == 9600U &&
                       le_field(record, 64, 8) == 9600U,
                   "TIOCGETA zeroes the c_cc padding and reports B9600 speeds");
            expect(ioctl_sentinel_from(vm, macosarm::kDarwinTermiosSize),
                   "TIOCGETA writes nothing past the 72-byte termios");
        }

        // An ioctl failure reports its errno in x0 with carry set.
        const auto failed_with = [](const macosarm::CpuState& cpu, std::uint32_t error) {
            return cpu.x[0] == error && carry_is_set(cpu);
        };

        {
            // Descriptor resolution: a negative fd is EBADF without a host
            // query, an unknown fd is EBADF, an open non-terminal is ENOTTY,
            // no failure writes, and only the low 32 bits of x0 name the fd.
            macosarm::GuestAddressSpace vm;
            map_ioctl_page(vm, rw);
            TerminalHost host;
            macosarm::CpuState state{};
            static_cast<void>(run_ioctl(
                vm, host, state, 0xffffffffU, macosarm::kDarwinIoctlTiocgwinsz, kIoctlBase));
            expect(failed_with(state, macosarm::kDarwinErrnoEbadf) && host.requests.empty(),
                   "ioctl negative fd reports EBADF without querying the host");
            static_cast<void>(run_ioctl(
                vm, host, state, 7U, macosarm::kDarwinIoctlTiocgwinsz, kIoctlBase));
            expect(failed_with(state, macosarm::kDarwinErrnoEbadf) &&
                       host.requests == std::vector<std::int32_t>{7},
                   "ioctl unknown fd reports EBADF");
            static_cast<void>(run_ioctl(
                vm, host, state, 3U, macosarm::kDarwinIoctlTiocgeta, kIoctlBase));
            expect(failed_with(state, macosarm::kDarwinErrnoEnotty),
                   "TIOCGETA on an open non-terminal reports ENOTTY");
            expect(ioctl_sentinel_from(vm, 0), "failed ioctl requests write nothing");
            static_cast<void>(run_ioctl(vm, host, state, 0xffffffff00000000ULL,
                                        macosarm::kDarwinIoctlTiocgwinsz, kIoctlBase));
            expect(state.x[0] == 0 && !carry_is_set(state) &&
                       host.requests == std::vector<std::int32_t>{7, 3, 0},
                   "ioctl takes the fd from the low 32 bits of x0");
        }

        {
            // Copy-in precedes descriptor resolution: an unreadable IOC_IN
            // argument is EFAULT even for a negative fd and never reaches the
            // host; a readable one proceeds to the negative-fd check.
            macosarm::GuestAddressSpace vm;
            map_ioctl_page(vm, rw);
            TerminalHost host;
            macosarm::CpuState state{};
            const std::uint64_t unmapped = kIoctlBase + kIoctlPage;
            static_cast<void>(run_ioctl(
                vm, host, state, 0xffffffffU, macosarm::kDarwinIoctlFionbio, unmapped));
            expect(failed_with(state, macosarm::kDarwinErrnoEfault) && host.requests.empty(),
                   "ioctl copyin fault reports EFAULT before EBADF and the host query");
            static_cast<void>(run_ioctl(
                vm, host, state, 0xffffffffU, macosarm::kDarwinIoctlFionbio, kIoctlBase));
            expect(failed_with(state, macosarm::kDarwinErrnoEbadf) && host.requests.empty(),
                   "ioctl readable argument proceeds to the negative-fd check");
        }

        {
            // Copy-out follows terminal resolution: a record straddling the end
            // of the mapping or landing on a read-only page is EFAULT, the host
            // was still queried, and no partial record reaches the guest.
            TerminalHost host;
            macosarm::CpuState state{};
            {
                macosarm::GuestAddressSpace vm;
                map_ioctl_page(vm, rw);
                static_cast<void>(run_ioctl(vm, host, state, 0U,
                                            macosarm::kDarwinIoctlTiocgwinsz,
                                            kIoctlBase + kIoctlPage - 4U));
                expect(failed_with(state, macosarm::kDarwinErrnoEfault) &&
                           ioctl_sentinel_from(vm, 0),
                       "TIOCGWINSZ straddling the mapping reports EFAULT and writes nothing");
            }
            {
                macosarm::GuestAddressSpace vm;
                map_ioctl_page(vm, macosarm::Protection::read);
                static_cast<void>(run_ioctl(
                    vm, host, state, 0U, macosarm::kDarwinIoctlTiocgeta, kIoctlBase));
                expect(failed_with(state, macosarm::kDarwinErrnoEfault) &&
                           ioctl_sentinel_from(vm, 0),
                       "TIOCGETA to a read-only page reports EFAULT and writes nothing");
            }
            expect(host.requests == std::vector<std::int32_t>{0, 0},
                   "ioctl copyout faults still query the terminal once each");
        }

        {
            // FIOCLEX and FIONCLEX set and clear the descriptor's own
            // close-on-exec flag on any open descriptor, terminal or not, as
            // fcntl(2) F_SETFD does, and only w0 names the descriptor. They
            // resolve it first, so an unknown fd is EBADF and never reaches
            // the update. As _IO requests they read no argument, so an
            // unmapped data address is fine, and they write nothing.
            macosarm::GuestAddressSpace vm;
            map_ioctl_page(vm, rw);
            TerminalHost host;
            macosarm::CpuState state{};
            const std::uint64_t unmapped = kIoctlBase + kIoctlPage;
            const auto succeeded = [&state]() {
                return (state.pstate & macosarm::kA64PstateCarry) == 0U && state.x[0] == 0U;
            };

            const auto acknowledged =
                run_ioctl(vm, host, state, 0U, macosarm::kDarwinIoctlFioclex, unmapped);
            expect(static_cast<bool>(acknowledged) && succeeded() &&
                       host.terminal_close_on_exec && !host.file_close_on_exec,
                   "FIOCLEX sets close-on-exec on a terminal and clears carry");
            static_cast<void>(run_ioctl(vm, host, state, 0xFFFFFFFF00000003ULL,
                                        macosarm::kDarwinIoctlFioclex, unmapped));
            expect(succeeded() && host.file_close_on_exec,
                   "FIOCLEX on an open non-terminal sets close-on-exec and reads only w0");
            static_cast<void>(
                run_ioctl(vm, host, state, 0U, macosarm::kDarwinIoctlFionclex, unmapped));
            expect(succeeded() && !host.terminal_close_on_exec && host.file_close_on_exec,
                   "FIONCLEX clears only that descriptor's close-on-exec flag");
            static_cast<void>(
                run_ioctl(vm, host, state, 7U, macosarm::kDarwinIoctlFioclex, unmapped));
            expect(failed_with(state, macosarm::kDarwinErrnoEbadf),
                   "FIOCLEX on an unknown fd reports EBADF");
            host.update_error = macosarm::kDarwinErrnoEio;
            static_cast<void>(
                run_ioctl(vm, host, state, 3U, macosarm::kDarwinIoctlFionclex, unmapped));
            expect(failed_with(state, macosarm::kDarwinErrnoEio) && host.file_close_on_exec,
                   "a host FIONCLEX failure is reported and leaves close-on-exec unchanged");
            using Update = TerminalHost::Update;
            expect(host.updates ==
                       std::vector<Update>{{0, true}, {3, true}, {0, false}, {3, false}},
                   "FIOCLEX and FIONCLEX update only resolved descriptors, in call order");
            expect(host.requests == std::vector<std::int32_t>{0, 3, 0, 7, 3},
                   "FIOCLEX and FIONCLEX resolve the descriptor once each");
            expect(ioctl_sentinel_from(vm, 0), "FIOCLEX and FIONCLEX write nothing");
        }

        {
            // FIOGETOWN, FIOSETOWN, FIOASYNC and FIONBIO are not modeled for
            // ioctl yet: on any open descriptor, terminal or not, they report
            // ENOSYS, change no close-on-exec flag and write nothing. They
            // still resolve the descriptor first, so an unknown fd is EBADF.
            macosarm::GuestAddressSpace vm;
            map_ioctl_page(vm, rw);
            TerminalHost host;
            macosarm::CpuState state{};
            constexpr std::array<std::uint64_t, 4> file_table_requests{
                macosarm::kDarwinIoctlFiogetown, macosarm::kDarwinIoctlFiosetown,
                macosarm::kDarwinIoctlFioasync,  macosarm::kDarwinIoctlFionbio,
            };
            bool on_terminal = true;
            bool on_file = true;
            bool on_unknown = true;
            for (const std::uint64_t request : file_table_requests) {
                static_cast<void>(run_ioctl(vm, host, state, 0U, request, kIoctlBase));
                on_terminal = on_terminal && failed_with(state, macosarm::kDarwinErrnoEnosys);
                static_cast<void>(run_ioctl(vm, host, state, 3U, request, kIoctlBase));
                on_file = on_file && failed_with(state, macosarm::kDarwinErrnoEnosys);
                static_cast<void>(run_ioctl(vm, host, state, 7U, request, kIoctlBase));
                on_unknown = on_unknown && failed_with(state, macosarm::kDarwinErrnoEbadf);
            }
            expect(on_terminal, "file-table ioctl requests on a terminal report ENOSYS");
            expect(on_file, "file-table ioctl requests on an open non-terminal report ENOSYS");
            expect(on_unknown, "file-table ioctl requests on an unknown fd report EBADF");
            expect(host.requests.size() == 3U * file_table_requests.size(),
                   "file-table ioctl requests resolve the descriptor once each");
            expect(ioctl_sentinel_from(vm, 0), "file-table ioctl requests write nothing");
        }

        {
            // Every other request reaches the device. A terminal rejects one it
            // does not recognize with ENOTTY, and the command keeps all 64
            // bits, so TIOCGWINSZ with bit 32 set is unrecognized rather than
            // truncated into a match. TIOCGWINSZ on a non-terminal is ENOTTY.
            macosarm::GuestAddressSpace vm;
            map_ioctl_page(vm, rw);
            TerminalHost host;
            macosarm::CpuState state{};
            constexpr std::uint64_t unrecognized = 0x40047a7fULL; // _IOR('z', 127, int)
            static_cast<void>(run_ioctl(vm, host, state, 0U, unrecognized, kIoctlBase));
            expect(failed_with(state, macosarm::kDarwinErrnoEnotty),
                   "unrecognized ioctl request on a terminal reports ENOTTY");
            static_cast<void>(run_ioctl(vm, host, state, 0U,
                                        macosarm::kDarwinIoctlTiocgwinsz | (std::uint64_t{1} << 32U),
                                        kIoctlBase));
            expect(failed_with(state, macosarm::kDarwinErrnoEnotty),
                   "ioctl matches the full 64-bit command, never a truncated one");
            static_cast<void>(run_ioctl(
                vm, host, state, 3U, macosarm::kDarwinIoctlTiocgwinsz, kIoctlBase));
            expect(failed_with(state, macosarm::kDarwinErrnoEnotty),
                   "TIOCGWINSZ on an open non-terminal reports ENOTTY");
            expect(host.requests == std::vector<std::int32_t>{0, 0, 3} &&
                       ioctl_sentinel_from(vm, 0),
                   "unrecognized ioctl requests reach the device and write nothing");
        }
    }

    // An lseek failure reports its errno in x0 with carry set.
    const auto failed_with = [](const macosarm::CpuState& cpu, std::uint32_t error) {
        return cpu.x[0] == error && carry_is_set(cpu);
    };

    {
        // lseek(2) on a regular file: SEEK_SET, SEEK_CUR and SEEK_END return the
        // new offset in x0 with carry clear and commit it once each. Only w0
        // names the descriptor and only w2 the whence value.
        macosarm::GuestAddressSpace vm;
        SeekHost host;
        macosarm::CpuState state{};
        const auto from_set = run_lseek(vm, host, state, 3U, 0x40U, macosarm::kDarwinSeekSet);
        expect(static_cast<bool>(from_set) && !carry_is_set(state) && state.x[0] == 0x40U,
               "lseek SEEK_SET returns the requested offset");
        const auto from_cur = run_lseek(vm, host, state, 3U,
                                        static_cast<std::uint64_t>(std::int64_t{-0x10}),
                                        macosarm::kDarwinSeekCur);
        expect(static_cast<bool>(from_cur) && !carry_is_set(state) && state.x[0] == 0x30U,
               "lseek SEEK_CUR adds a negative delta to the current offset");
        constexpr std::uint64_t high = std::uint64_t{1} << 32U;
        const auto from_end = run_lseek(vm, host, state, high | 3U, 0x20U,
                                        high | macosarm::kDarwinSeekEnd);
        expect(static_cast<bool>(from_end) && !carry_is_set(state) && state.x[0] == 0x1020U,
               "lseek SEEK_END adds to the size and ignores upper fd and whence bits");
        expect(host.commits.size() == 3U && host.commits[0].offset == 0x40 &&
                   host.commits[1].offset == 0x30 && host.commits[2].fd == 3 &&
                   host.commits[2].offset == 0x1020 && host.file_offset == 0x1020,
               "lseek commits each successful offset exactly once");
    }

    {
        // Descriptor checks come first: a negative fd never reaches the host,
        // an unknown fd is EBADF and a pipe is ESPIPE whatever whence says.
        // Then an unknown whence is EINVAL, and SEEK_HOLE and SEEK_DATA report
        // ENOTTY because hole maps are not modeled. None of them commit.
        macosarm::GuestAddressSpace vm;
        SeekHost host;
        macosarm::CpuState state{};
        static_cast<void>(run_lseek(vm, host, state, 0xffffffffU, 0U, macosarm::kDarwinSeekSet));
        expect(failed_with(state, macosarm::kDarwinErrnoEbadf) && host.requests.empty(),
               "lseek on a negative fd reports EBADF without querying the host");
        static_cast<void>(run_lseek(vm, host, state, 7U, 0U, macosarm::kDarwinSeekSet));
        expect(failed_with(state, macosarm::kDarwinErrnoEbadf), "lseek on an unknown fd reports EBADF");
        static_cast<void>(run_lseek(vm, host, state, 5U, 0U, 9U));
        expect(failed_with(state, macosarm::kDarwinErrnoEspipe),
               "lseek on a pipe reports ESPIPE before validating whence");
        static_cast<void>(run_lseek(vm, host, state, 3U, 0U, 9U));
        expect(failed_with(state, macosarm::kDarwinErrnoEinval),
               "lseek with an unknown whence reports EINVAL");
        static_cast<void>(run_lseek(vm, host, state, 3U, 0U, macosarm::kDarwinSeekHole));
        const bool hole = failed_with(state, macosarm::kDarwinErrnoEnotty);
        static_cast<void>(run_lseek(vm, host, state, 3U, 0U, macosarm::kDarwinSeekData));
        expect(hole && failed_with(state, macosarm::kDarwinErrnoEnotty),
               "lseek SEEK_HOLE and SEEK_DATA report ENOTTY");
        expect(host.requests == std::vector<std::int32_t>{7, 5, 3, 3, 3} &&
                   host.commits.empty() && host.file_offset == 0x100,
               "rejected lseek requests resolve the fd once each and commit nothing");
    }

    {
        // XNU's wrapping off_t arithmetic: a positive request that wraps
        // negative is EOVERFLOW, any other negative result on a regular file
        // is EINVAL, and an unknown size fails SEEK_END with the host's error.
        macosarm::GuestAddressSpace vm;
        SeekHost host;
        macosarm::CpuState state{};
        static_cast<void>(run_lseek(vm, host, state, 3U, 0x7fffffffffffffffULL,
                                    macosarm::kDarwinSeekCur));
        expect(failed_with(state, macosarm::kDarwinErrnoEoverflow),
               "lseek SEEK_CUR past the off_t maximum reports EOVERFLOW");
        static_cast<void>(run_lseek(vm, host, state, 3U,
                                    static_cast<std::uint64_t>(std::int64_t{-0x200}),
                                    macosarm::kDarwinSeekCur));
        expect(failed_with(state, macosarm::kDarwinErrnoEinval),
               "lseek SEEK_CUR before the start of a regular file reports EINVAL");
        static_cast<void>(run_lseek(vm, host, state, 3U,
                                    static_cast<std::uint64_t>(std::int64_t{-1}),
                                    macosarm::kDarwinSeekSet));
        expect(failed_with(state, macosarm::kDarwinErrnoEinval),
               "lseek SEEK_SET to a negative offset on a regular file reports EINVAL");
        host.size_error = macosarm::kDarwinErrnoEio;
        static_cast<void>(run_lseek(vm, host, state, 3U, 0U, macosarm::kDarwinSeekEnd));
        expect(failed_with(state, macosarm::kDarwinErrnoEio),
               "lseek SEEK_END with an unknown size reports the host size error");
        expect(host.commits.empty() && host.file_offset == 0x100,
               "out-of-range lseek requests leave the offset unchanged");
        const auto still_set = run_lseek(vm, host, state, 3U, 0x80U, macosarm::kDarwinSeekSet);
        expect(static_cast<bool>(still_set) && !carry_is_set(state) && state.x[0] == 0x80U,
               "an unknown size fails only SEEK_END");
    }

    {
        // A character device may seek to a negative offset, yet a positive
        // request that wraps is still EOVERFLOW. A failed host commit is
        // reported as-is, and a negative size, or a negative offset on
        // anything but a character device, violates the host contract.
        macosarm::GuestAddressSpace vm;
        SeekHost host;
        macosarm::CpuState state{};
        const auto negative = run_lseek(vm, host, state, 4U,
                                        static_cast<std::uint64_t>(std::int64_t{-8}),
                                        macosarm::kDarwinSeekSet);
        expect(static_cast<bool>(negative) && !carry_is_set(state) &&
                   state.x[0] == static_cast<std::uint64_t>(std::int64_t{-8}) &&
                   host.device_offset == -8,
               "lseek moves a character device to a negative offset");
        host.device_offset = 1;
        static_cast<void>(run_lseek(vm, host, state, 4U, 0x7fffffffffffffffULL,
                                    macosarm::kDarwinSeekCur));
        expect(failed_with(state, macosarm::kDarwinErrnoEoverflow) && host.device_offset == 1,
               "lseek on a character device still reports EOVERFLOW on wrap");
        host.commit_error = macosarm::kDarwinErrnoEio;
        static_cast<void>(run_lseek(vm, host, state, 3U, 0x10U, macosarm::kDarwinSeekSet));
        expect(failed_with(state, macosarm::kDarwinErrnoEio) && host.file_offset == 0x100,
               "a failed lseek commit reports the host error and keeps the offset");
        host.commit_error = 0;
        host.file_offset = -1;
        const auto bad_offset = run_lseek(vm, host, state, 3U, 0U, macosarm::kDarwinSeekSet);
        host.file_offset = 0x100;
        host.file_size = -1;
        const auto bad_size = run_lseek(vm, host, state, 3U, 0U, macosarm::kDarwinSeekSet);
        expect(bad_offset.error == macosarm::SyscallDispatchError::host_contract_violation &&
                   bad_size.error == macosarm::SyscallDispatchError::host_contract_violation,
               "lseek rejects a negative regular-file offset or size from the host");
        expect(host.commits.size() == 2U, "lseek commits only after every check passes");
    }

    constexpr auto positioned_rw = macosarm::Protection::read | macosarm::Protection::write;

    {
        // pread(2) on a regular file copies the bytes at the offset into the
        // guest and returns their count in x0 with carry clear. Only w0 names
        // the descriptor, a read crossing end-of-file is short and one at
        // end-of-file returns 0. Both entry points share one handler.
        macosarm::GuestAddressSpace vm;
        map_positioned_page(vm, positioned_rw);
        RandomAccessHost host;
        host.contents = text_bytes("0123456789abcdef");
        macosarm::CpuState state{};
        constexpr std::uint64_t upper_fd_bits = std::uint64_t{1} << 32U;
        const auto first = run_positioned(vm, host, state, macosarm::kDarwinSysPread,
                                          upper_fd_bits | 3U, kPositionedBase, 4U, 6U);
        expect(static_cast<bool>(first) && first.action == macosarm::SyscallAction::resume &&
                   first.syscall_number == macosarm::kDarwinSysPread,
               "pread dispatch resumes the guest");
        expect(!carry_is_set(state) && state.x[0] == 4U &&
                   positioned_bytes_at(vm, 0, text_bytes("6789")),
               "pread copies the bytes at the offset and clears carry");
        const auto tail = run_positioned(vm, host, state, macosarm::kDarwinSysPreadNocancel,
                                         3U, kPositionedBase + 8U, 8U, 12U);
        expect(static_cast<bool>(tail) &&
                   tail.syscall_number == macosarm::kDarwinSysPreadNocancel &&
                   !carry_is_set(state) && state.x[0] == 4U,
               "pread_nocancel crossing end-of-file returns a short count");
        expect(positioned_bytes_at(vm, 8, text_bytes("cdef")) && positioned_sentinel_from(vm, 12),
               "pread writes no guest bytes past the transferred count");
        const auto at_end = run_positioned(vm, host, state, macosarm::kDarwinSysPread, 3U,
                                           kPositionedBase + 12U, 8U, 16U);
        expect(static_cast<bool>(at_end) && !carry_is_set(state) && state.x[0] == 0U &&
                   positioned_sentinel_from(vm, 12),
               "pread at end-of-file returns 0 and writes nothing");
        expect(host.requests == std::vector<std::int32_t>{3, 3, 3} &&
                   host.transfers.size() == 3U && host.transfers[0].size == 4U &&
                   host.transfers[0].offset == 6 && host.transfers[1].offset == 12 &&
                   host.transfers[2].offset == 16,
               "pread reads once at the unchanged requested offset");
    }

    {
        // nbyte above INT_MAX is EINVAL before the descriptor is resolved,
        // with no 64-bit truncation. Then an unknown fd is EBADF, a pipe
        // ESPIPE, a terminal ENXIO and a negative offset on a regular file
        // EINVAL. None of them transfer or write guest bytes.
        macosarm::GuestAddressSpace vm;
        map_positioned_page(vm, positioned_rw);
        RandomAccessHost host;
        host.contents = text_bytes("0123456789abcdef");
        macosarm::CpuState state{};
        const auto pread_fd = [&](std::uint64_t fd, std::uint64_t nbyte, std::int64_t offset) {
            static_cast<void>(run_positioned(vm, host, state, macosarm::kDarwinSysPread, fd,
                                             kPositionedBase, nbyte,
                                             static_cast<std::uint64_t>(offset)));
        };
        pread_fd(3U, 0x80000000ULL, 0);
        const bool over_int_max = failed_with(state, macosarm::kDarwinErrnoEinval);
        pread_fd(3U, 0x100000004ULL, 0);
        expect(over_int_max && failed_with(state, macosarm::kDarwinErrnoEinval) &&
                   host.requests.empty(),
               "pread above INT_MAX reports EINVAL before resolving the fd");
        pread_fd(9U, 4U, 0);
        expect(failed_with(state, macosarm::kDarwinErrnoEbadf), "pread on an unknown fd reports EBADF");
        pread_fd(6U, 4U, 0);
        expect(failed_with(state, macosarm::kDarwinErrnoEspipe), "pread on a pipe reports ESPIPE");
        pread_fd(7U, 4U, 0);
        expect(failed_with(state, macosarm::kDarwinErrnoEnxio), "pread on a terminal reports ENXIO");
        pread_fd(3U, 4U, -4);
        expect(failed_with(state, macosarm::kDarwinErrnoEinval),
               "pread at a negative offset on a regular file reports EINVAL");
        expect(host.requests == std::vector<std::int32_t>{9, 6, 7, 3} && host.transfers.empty() &&
                   positioned_sentinel_from(vm, 0),
               "rejected pread requests resolve the fd once each and transfer nothing");
    }

    {
        // A character device accepts a negative offset, passed to the host
        // unchanged. A read is clipped so it never passes INT64_MAX, and one
        // at INT64_MAX itself returns 0 without a host read. A zero-length
        // read still resolves the descriptor, even for a null buffer, but
        // never reaches the host.
        macosarm::GuestAddressSpace vm;
        map_positioned_page(vm, positioned_rw);
        RandomAccessHost host;
        macosarm::CpuState state{};
        constexpr std::int64_t max_offset = 0x7fffffffffffffffLL;
        std::vector<std::byte> device_pattern(8);
        for (std::size_t i = 0; i < device_pattern.size(); ++i) {
            device_pattern[i] = static_cast<std::byte>((i * 5U + 1U) & 0xffU);
        }
        const auto negative = run_positioned(vm, host, state, macosarm::kDarwinSysPread, 4U,
                                             kPositionedBase, 8U,
                                             static_cast<std::uint64_t>(std::int64_t{-16}));
        expect(static_cast<bool>(negative) && !carry_is_set(state) && state.x[0] == 8U &&
                   positioned_bytes_at(vm, 0, device_pattern),
               "pread on a character device accepts a negative offset");
        const auto clipped = run_positioned(vm, host, state, macosarm::kDarwinSysPread, 4U,
                                            kPositionedBase + 16U, 8U,
                                            static_cast<std::uint64_t>(max_offset - 4));
        expect(static_cast<bool>(clipped) && !carry_is_set(state) && state.x[0] == 4U &&
                   positioned_bytes_at(vm, 16, std::span<const std::byte>(device_pattern).first(4)) &&
                   positioned_sentinel_from(vm, 20),
               "pread near INT64_MAX is clipped so it ends at INT64_MAX");
        const auto at_max = run_positioned(vm, host, state, macosarm::kDarwinSysPread, 4U,
                                           kPositionedBase, 8U,
                                           static_cast<std::uint64_t>(max_offset));
        expect(static_cast<bool>(at_max) && !carry_is_set(state) && state.x[0] == 0U,
               "pread at INT64_MAX returns 0");
        const auto empty =
            run_positioned(vm, host, state, macosarm::kDarwinSysPread, 3U, 0U, 0U, 0U);
        expect(static_cast<bool>(empty) && !carry_is_set(state) && state.x[0] == 0U,
               "zero-length pread succeeds for a null buffer");
        static_cast<void>(
            run_positioned(vm, host, state, macosarm::kDarwinSysPread, 9U, 0U, 0U, 0U));
        expect(failed_with(state, macosarm::kDarwinErrnoEbadf),
               "zero-length pread still reports EBADF for an unknown fd");
        expect(host.requests == std::vector<std::int32_t>{4, 4, 4, 3, 9} &&
                   host.transfers.size() == 2U && host.transfers[0].size == 8U &&
                   host.transfers[0].offset == -16 && host.transfers[1].size == 4U &&
                   host.transfers[1].offset == max_offset - 4,
               "only nonempty pread transfers reach the host, at unchanged offsets");
    }

    {
        // The destination is probed before the host read, so an unmapped,
        // page-crossing or read-only buffer is EFAULT without consuming
        // input. A host error is reported as-is and writes nothing, and a
        // host claiming more bytes than requested violates its contract.
        macosarm::GuestAddressSpace vm;
        map_positioned_page(vm, positioned_rw);
        macosarm::GuestAddressSpace readonly_vm;
        map_positioned_page(readonly_vm, macosarm::Protection::read);
        RandomAccessHost host;
        host.contents = text_bytes("0123456789abcdef");
        macosarm::CpuState state{};
        static_cast<void>(run_positioned(vm, host, state, macosarm::kDarwinSysPread, 3U,
                                         0xdead00000000ULL, 4U, 0U));
        const bool unmapped = failed_with(state, macosarm::kDarwinErrnoEfault);
        static_cast<void>(run_positioned(vm, host, state, macosarm::kDarwinSysPread, 3U,
                                         kPositionedBase + kPositionedPage - 2U, 4U, 0U));
        const bool crossing = failed_with(state, macosarm::kDarwinErrnoEfault);
        static_cast<void>(run_positioned(readonly_vm, host, state, macosarm::kDarwinSysPread, 3U,
                                         kPositionedBase, 4U, 0U));
        expect(unmapped && crossing && failed_with(state, macosarm::kDarwinErrnoEfault),
               "pread to an unmapped, page-crossing or read-only buffer reports EFAULT");
        expect(host.requests.size() == 3U && host.transfers.empty() &&
                   positioned_sentinel_from(vm, 0) && positioned_sentinel_from(readonly_vm, 0),
               "faulting pread resolves the fd but never reads from the host");
        host.error = macosarm::kDarwinErrnoEio;
        static_cast<void>(run_positioned(vm, host, state, macosarm::kDarwinSysPread, 3U,
                                         kPositionedBase, 4U, 0U));
        expect(failed_with(state, macosarm::kDarwinErrnoEio) && host.transfers.size() == 1U &&
                   positioned_sentinel_from(vm, 0),
               "a pread host error is reported and writes no guest bytes");
        host.violate_contract = true;
        const auto violated = run_positioned(vm, host, state, macosarm::kDarwinSysPread, 3U,
                                             kPositionedBase, 4U, 0U);
        expect(violated.error == macosarm::SyscallDispatchError::host_contract_violation &&
                   positioned_sentinel_from(vm, 0),
               "pread rejects a host count above the request");
    }

    {
        // A large pread performs one host read of at most 64 KiB, so input
        // past the first chunk is left for the guest's next call.
        macosarm::GuestAddressSpace vm;
        constexpr std::uint64_t large_size = 5U * macosarm::GuestAddressSpace::kPageSize;
        expect(static_cast<bool>(vm.map(kPositionedBase, large_size, positioned_rw)),
               "large pread buffer maps writable");
        RandomAccessHost host;
        macosarm::CpuState state{};
        const auto large = run_positioned(vm, host, state, macosarm::kDarwinSysPread, 4U,
                                          kPositionedBase, 64U * 1024U + 3U, 0U);
        expect(static_cast<bool>(large) && !carry_is_set(state) && state.x[0] == 64U * 1024U &&
                   host.transfers.size() == 1U && host.transfers[0].size == 64U * 1024U,
               "large pread performs one host read capped at 64 KiB");
    }

    {
        // pwrite(2) on a regular file stores the guest bytes at the offset
        // and returns their count in x0 with carry clear, leaving the guest
        // source untouched. Only w0 names the descriptor, the file grows when
        // a write passes its end, and both entry points share one handler.
        // A read-only source page is enough because pwrite only reads it.
        macosarm::GuestAddressSpace vm;
        map_positioned_page(vm, macosarm::Protection::read);
        const std::vector<std::byte> message = text_bytes("WXYZ");
        expect(static_cast<bool>(vm.load_bytes(kPositionedBase, message)),
               "pwrite source loads");
        RandomAccessHost host;
        host.contents = text_bytes("0123456789abcdef");
        macosarm::CpuState state{};
        constexpr std::uint64_t upper_fd_bits = std::uint64_t{1} << 32U;
        const auto inside = run_positioned(vm, host, state, macosarm::kDarwinSysPwrite,
                                           upper_fd_bits | 3U, kPositionedBase, 4U, 4U);
        expect(static_cast<bool>(inside) && inside.action == macosarm::SyscallAction::resume &&
                   inside.syscall_number == macosarm::kDarwinSysPwrite &&
                   !carry_is_set(state) && state.x[0] == 4U,
               "pwrite returns the stored count and clears carry");
        expect(host.contents == text_bytes("0123WXYZ89abcdef"),
               "pwrite stores the guest bytes at the requested offset");
        const auto past_end = run_positioned(vm, host, state, macosarm::kDarwinSysPwriteNocancel,
                                             3U, kPositionedBase, 2U, 18U);
        std::vector<std::byte> grown = text_bytes("0123WXYZ89abcdef");
        grown.push_back(std::byte{0});
        grown.push_back(std::byte{0});
        grown.push_back(std::byte{'W'});
        grown.push_back(std::byte{'X'});
        expect(static_cast<bool>(past_end) &&
                   past_end.syscall_number == macosarm::kDarwinSysPwriteNocancel &&
                   !carry_is_set(state) && state.x[0] == 2U && host.contents == grown,
               "pwrite_nocancel past end-of-file grows the file");
        expect(positioned_bytes_at(vm, 0, message) && positioned_sentinel_from(vm, message.size()),
               "pwrite leaves the guest source unchanged");
        expect(host.requests == std::vector<std::int32_t>{3, 3} && host.transfers.size() == 2U &&
                   host.transfers[0].size == 4U && host.transfers[0].offset == 4 &&
                   host.transfers[1].size == 2U && host.transfers[1].offset == 18,
               "pwrite writes once at the unchanged requested offset");
    }

    {
        // pwrite rejects an offset of exactly -1 with EINVAL before anything
        // else, even on a character device, and nbyte above INT_MAX with
        // EINVAL before the descriptor is resolved. Then an unknown fd or one
        // not open for writing is EBADF, a pipe ESPIPE, a terminal ENXIO and
        // another negative offset on a regular file EINVAL. None transfer.
        macosarm::GuestAddressSpace vm;
        map_positioned_page(vm, positioned_rw);
        RandomAccessHost host;
        host.contents = text_bytes("0123456789abcdef");
        macosarm::CpuState state{};
        const auto pwrite_fd = [&](std::uint64_t fd, std::uint64_t nbyte, std::int64_t offset) {
            static_cast<void>(run_positioned(vm, host, state, macosarm::kDarwinSysPwrite, fd,
                                             kPositionedBase, nbyte,
                                             static_cast<std::uint64_t>(offset)));
        };
        pwrite_fd(4U, 4U, -1);
        const bool minus_one_device = failed_with(state, macosarm::kDarwinErrnoEinval);
        pwrite_fd(9U, 0x80000000ULL, -1);
        expect(minus_one_device && failed_with(state, macosarm::kDarwinErrnoEinval) &&
                   host.requests.empty(),
               "pwrite at offset -1 reports EINVAL before any other check");
        pwrite_fd(3U, 0x80000000ULL, 0);
        const bool over_int_max = failed_with(state, macosarm::kDarwinErrnoEinval);
        pwrite_fd(9U, 0x100000004ULL, 0);
        expect(over_int_max && failed_with(state, macosarm::kDarwinErrnoEinval) &&
                   host.requests.empty(),
               "pwrite above INT_MAX reports EINVAL before resolving the fd");
        pwrite_fd(9U, 4U, 0);
        expect(failed_with(state, macosarm::kDarwinErrnoEbadf), "pwrite on an unknown fd reports EBADF");
        pwrite_fd(5U, 4U, 0);
        expect(failed_with(state, macosarm::kDarwinErrnoEbadf),
               "pwrite on a descriptor not open for writing reports EBADF");
        pwrite_fd(6U, 4U, 0);
        expect(failed_with(state, macosarm::kDarwinErrnoEspipe), "pwrite on a pipe reports ESPIPE");
        pwrite_fd(7U, 4U, 0);
        expect(failed_with(state, macosarm::kDarwinErrnoEnxio), "pwrite on a terminal reports ENXIO");
        pwrite_fd(3U, 4U, -2);
        expect(failed_with(state, macosarm::kDarwinErrnoEinval),
               "pwrite at a negative offset on a regular file reports EINVAL");
        expect(host.requests == std::vector<std::int32_t>{9, 5, 6, 7, 3} && host.transfers.empty() &&
                   host.contents == text_bytes("0123456789abcdef"),
               "rejected pwrite requests resolve the fd once each and transfer nothing");
        const auto readable = run_positioned(vm, host, state, macosarm::kDarwinSysPread, 5U,
                                             kPositionedBase, 4U, 0U);
        expect(static_cast<bool>(readable) && !carry_is_set(state) && state.x[0] == 4U &&
                   positioned_bytes_at(vm, 0, text_bytes("0123")),
               "pread on the descriptor not open for writing still succeeds");
    }

    {
        // A character device accepts a negative offset other than -1, passed
        // to the host unchanged. pwrite at INT64_MAX itself is EFBIG, and one
        // near INT64_MAX is clipped so it ends there. A zero-length pwrite
        // still resolves the descriptor, even for a null buffer, but never
        // reaches the host.
        macosarm::GuestAddressSpace vm;
        map_positioned_page(vm, macosarm::Protection::read);
        const std::vector<std::byte> message = text_bytes("ABCDEFGH");
        expect(static_cast<bool>(vm.load_bytes(kPositionedBase, message)),
               "device pwrite source loads");
        RandomAccessHost host;
        macosarm::CpuState state{};
        constexpr std::int64_t max_offset = 0x7fffffffffffffffLL;
        const auto negative = run_positioned(vm, host, state, macosarm::kDarwinSysPwrite, 4U,
                                             kPositionedBase, 8U,
                                             static_cast<std::uint64_t>(std::int64_t{-16}));
        expect(static_cast<bool>(negative) && !carry_is_set(state) && state.x[0] == 8U &&
                   host.device_output == message,
               "pwrite on a character device accepts a negative offset");
        static_cast<void>(run_positioned(vm, host, state, macosarm::kDarwinSysPwrite, 4U,
                                         kPositionedBase, 8U,
                                         static_cast<std::uint64_t>(max_offset)));
        expect(failed_with(state, macosarm::kDarwinErrnoEfbig),
               "pwrite at INT64_MAX reports EFBIG");
        const auto clipped = run_positioned(vm, host, state, macosarm::kDarwinSysPwrite, 4U,
                                            kPositionedBase, 8U,
                                            static_cast<std::uint64_t>(max_offset - 4));
        expect(static_cast<bool>(clipped) && !carry_is_set(state) && state.x[0] == 4U,
               "pwrite near INT64_MAX is clipped so it ends at INT64_MAX");
        const auto empty =
            run_positioned(vm, host, state, macosarm::kDarwinSysPwrite, 3U, 0U, 0U, 0U);
        expect(static_cast<bool>(empty) && !carry_is_set(state) && state.x[0] == 0U,
               "zero-length pwrite succeeds for a null buffer");
        static_cast<void>(
            run_positioned(vm, host, state, macosarm::kDarwinSysPwrite, 9U, 0U, 0U, 0U));
        expect(failed_with(state, macosarm::kDarwinErrnoEbadf),
               "zero-length pwrite still reports EBADF for an unknown fd");
        std::vector<std::byte> expected_output = message;
        expected_output.insert(expected_output.end(), message.begin(), message.begin() + 4);
        expect(host.requests == std::vector<std::int32_t>{4, 4, 4, 3, 9} &&
                   host.transfers.size() == 2U && host.transfers[0].size == 8U &&
                   host.transfers[0].offset == -16 && host.transfers[1].size == 4U &&
                   host.transfers[1].offset == max_offset - 4 &&
                   host.device_output == expected_output,
               "only nonempty pwrite transfers reach the host, at unchanged offsets");
    }

    {
        // A pwrite larger than one 64 KiB chunk reaches the host as bounded
        // chunks in order, each at the offset where the previous one ended,
        // and returns the full count. A short host write ends the call with
        // its count. A host error after the first chunk reports the bytes
        // already written, while one on the first chunk is reported as-is.
        // A host claiming more bytes than requested violates its contract.
        constexpr std::size_t chunk = 64U * 1024U;
        macosarm::GuestAddressSpace vm;
        expect(static_cast<bool>(vm.map(kPositionedBase,
                                        5U * macosarm::GuestAddressSpace::kPageSize,
                                        macosarm::Protection::read)),
               "large pwrite source maps");
        std::vector<std::byte> source(chunk + 3U);
        for (std::size_t i = 0; i < source.size(); ++i) {
            source[i] = static_cast<std::byte>((i * 7U + 3U) & 0xffU);
        }
        expect(static_cast<bool>(vm.load_bytes(kPositionedBase, source)),
               "large pwrite source loads");
        const auto source_prefix = [&](std::size_t count) {
            return std::vector<std::byte>(
                source.begin(), source.begin() + static_cast<std::ptrdiff_t>(count));
        };
        macosarm::CpuState state{};

        RandomAccessHost host;
        const auto large = run_positioned(vm, host, state, macosarm::kDarwinSysPwrite, 3U,
                                          kPositionedBase, source.size(), 8U);
        std::vector<std::byte> stored(8U, std::byte{0});
        stored.insert(stored.end(), source.begin(), source.end());
        expect(static_cast<bool>(large) && !carry_is_set(state) &&
                   state.x[0] == source.size() && host.contents == stored,
               "large pwrite stores every byte and returns the full count");
        expect(host.requests == std::vector<std::int32_t>{3} && host.transfers.size() == 2U &&
                   host.transfers[0].size == chunk && host.transfers[0].offset == 8 &&
                   host.transfers[1].size == 3U &&
                   host.transfers[1].offset == static_cast<std::int64_t>(8U + chunk),
               "large pwrite is split into 64 KiB chunks at advancing offsets");

        RandomAccessHost short_host;
        short_host.short_count = 100U;
        const auto shortened = run_positioned(vm, short_host, state, macosarm::kDarwinSysPwrite,
                                              3U, kPositionedBase, source.size(), 0U);
        expect(static_cast<bool>(shortened) && !carry_is_set(state) && state.x[0] == 100U &&
                   short_host.transfers.size() == 1U && short_host.contents == source_prefix(100U),
               "a short host pwrite ends the call with its count");

        RandomAccessHost late_failure;
        late_failure.error = macosarm::kDarwinErrnoEio;
        late_failure.error_at = 1U;
        const auto partial = run_positioned(vm, late_failure, state, macosarm::kDarwinSysPwrite,
                                            3U, kPositionedBase, source.size(), 0U);
        expect(static_cast<bool>(partial) && !carry_is_set(state) && state.x[0] == chunk &&
                   late_failure.transfers.size() == 2U &&
                   late_failure.contents == source_prefix(chunk),
               "a pwrite host error after the first chunk reports the bytes already written");

        RandomAccessHost early_failure;
        early_failure.error = macosarm::kDarwinErrnoEio;
        static_cast<void>(run_positioned(vm, early_failure, state, macosarm::kDarwinSysPwrite,
                                         3U, kPositionedBase, source.size(), 0U));
        expect(failed_with(state, macosarm::kDarwinErrnoEio) &&
                   early_failure.transfers.size() == 1U && early_failure.contents.empty(),
               "a pwrite host error on the first chunk is reported as-is");

        RandomAccessHost violating;
        violating.violate_contract = true;
        const auto violated = run_positioned(vm, violating, state, macosarm::kDarwinSysPwrite,
                                             3U, kPositionedBase, 4U, 0U);
        expect(violated.error == macosarm::SyscallDispatchError::host_contract_violation &&
                   violating.contents.empty(),
               "pwrite rejects a host count above the request");
    }

    {
        // pwrite copies each chunk of the guest source in just before the
        // host write, so an unmapped source is EFAULT after the descriptor
        // is resolved but before any transfer, and a source that ends after
        // the first 64 KiB chunk reports the bytes already written.
        constexpr std::size_t chunk = 64U * 1024U;
        macosarm::GuestAddressSpace vm;
        expect(static_cast<bool>(vm.map(kPositionedBase, chunk, macosarm::Protection::read)),
               "truncated pwrite source maps");
        macosarm::CpuState state{};

        RandomAccessHost unmapped;
        static_cast<void>(run_positioned(vm, unmapped, state, macosarm::kDarwinSysPwrite, 3U,
                                         0xdead00000000ULL, 4U, 0U));
        expect(failed_with(state, macosarm::kDarwinErrnoEfault) &&
                   unmapped.requests == std::vector<std::int32_t>{3} &&
                   unmapped.transfers.empty() && unmapped.contents.empty(),
               "pwrite from an unmapped source reports EFAULT and transfers nothing");

        RandomAccessHost truncated;
        const auto partial = run_positioned(vm, truncated, state, macosarm::kDarwinSysPwrite, 3U,
                                            kPositionedBase, chunk + 3U, 0U);
        expect(static_cast<bool>(partial) && !carry_is_set(state) && state.x[0] == chunk &&
                   truncated.transfers.size() == 1U && truncated.transfers[0].size == chunk &&
                   truncated.contents.size() == chunk,
               "a pwrite source fault after the first chunk reports the bytes already written");
    }

    {
        // fcntl(2) F_GETFD reports FD_CLOEXEC from the descriptor's own flag,
        // F_SETFD consults only bit 0 of arg, and F_GETFL reports the open
        // file description's OFLAGS(f_flag) as-is. fcntl and fcntl_nocancel
        // share one handler, and only w0 and w1 count.
        macosarm::GuestAddressSpace vm;
        macosarm::CpuState state{};
        DescriptorFlagsHost host;
        host.descriptors = {
            {0, false, macosarm::kDarwinOpenReadOnly},
            {1, true, macosarm::kDarwinOpenWriteOnly | macosarm::kDarwinOpenAppend},
            {3, false,
             macosarm::kDarwinOpenReadWrite | macosarm::kDarwinOpenNonblock |
                 macosarm::kDarwinOpenDsync},
        };

        const auto plain = run_fcntl(vm, host, state, macosarm::kDarwinSysFcntl, 0U,
                                     macosarm::kDarwinFcntlGetfd, 0U);
        expect(static_cast<bool>(plain) && !carry_is_set(state) && state.x[0] == 0U &&
                   plain.syscall_number == macosarm::kDarwinSysFcntl,
               "fcntl F_GETFD reports 0 for a descriptor without close-on-exec");

        const auto marked = run_fcntl(vm, host, state, macosarm::kDarwinSysFcntlNocancel,
                                      0xFFFFFFFF00000001ULL,
                                      0xABCD000000000000ULL | macosarm::kDarwinFcntlGetfd, 0U);
        expect(static_cast<bool>(marked) && !carry_is_set(state) &&
                   state.x[0] == macosarm::kDarwinFdCloexec &&
                   marked.syscall_number == macosarm::kDarwinSysFcntlNocancel &&
                   host.described.back() == 1,
               "fcntl_nocancel F_GETFD reports FD_CLOEXEC and reads only w0 and w1");

        static_cast<void>(run_fcntl(vm, host, state, macosarm::kDarwinSysFcntl, 0U,
                                    macosarm::kDarwinFcntlSetfd, 0xFFFFFFFFFFFFFFF1ULL));
        expect(!carry_is_set(state) && state.x[0] == 0U && host.close_on_exec_is(0, true),
               "fcntl F_SETFD sets close-on-exec from bit 0 of arg");

        static_cast<void>(run_fcntl(vm, host, state, macosarm::kDarwinSysFcntl, 0U,
                                    macosarm::kDarwinFcntlSetfd, 0xFFFFFFFFFFFFFFFEULL));
        expect(!carry_is_set(state) && state.x[0] == 0U && host.close_on_exec_is(0, false) &&
                   host.updates.size() == 2U && host.updates[1].fd == 0 &&
                   !host.updates[1].close_on_exec,
               "fcntl F_SETFD clears close-on-exec and ignores every other bit of arg");

        static_cast<void>(run_fcntl(vm, host, state, macosarm::kDarwinSysFcntl, 1U,
                                    macosarm::kDarwinFcntlGetfl, 0U));
        expect(!carry_is_set(state) &&
                   state.x[0] == (macosarm::kDarwinOpenWriteOnly | macosarm::kDarwinOpenAppend),
               "fcntl F_GETFL reports the access mode and O_APPEND");

        static_cast<void>(run_fcntl(vm, host, state, macosarm::kDarwinSysFcntl, 3U,
                                    macosarm::kDarwinFcntlGetfl, 0U));
        expect(!carry_is_set(state) &&
                   state.x[0] == (macosarm::kDarwinOpenReadWrite | macosarm::kDarwinOpenNonblock |
                                  macosarm::kDarwinOpenDsync),
               "fcntl F_GETFL reports O_RDWR with O_NONBLOCK and O_DSYNC");
    }

    {
        // fcntl resolves the descriptor before it looks at the command: a
        // negative fd is EBADF without asking the host, an unknown one is the
        // host's EBADF, and a command that is not modeled reports ENOSYS on
        // an open descriptor, never a fabricated success.
        macosarm::GuestAddressSpace vm;
        macosarm::CpuState state{};
        DescriptorFlagsHost host;
        host.descriptors = {{2, false, macosarm::kDarwinOpenWriteOnly}};

        static_cast<void>(run_fcntl(vm, host, state, macosarm::kDarwinSysFcntl, 0xFFFFFFFFU,
                                    macosarm::kDarwinFcntlGetfd, 0U));
        expect(fcntl_failed_with(state, macosarm::kDarwinErrnoEbadf) && host.described.empty(),
               "fcntl on a negative descriptor reports EBADF without asking the host");

        static_cast<void>(run_fcntl(vm, host, state, macosarm::kDarwinSysFcntl, 9U,
                                    macosarm::kDarwinFcntlDupfd, 0U));
        expect(fcntl_failed_with(state, macosarm::kDarwinErrnoEbadf) &&
                   host.described == std::vector<std::int32_t>{9},
               "fcntl on an unknown descriptor reports EBADF before the command");

        // F_GETOWN (5) needs process-group ownership state that is not modeled.
        const std::array<std::uint64_t, 2> unmodeled{5U, 0x7fffffffU};
        for (const std::uint64_t command : unmodeled) {
            static_cast<void>(
                run_fcntl(vm, host, state, macosarm::kDarwinSysFcntl, 2U, command, 1U));
            expect(fcntl_failed_with(state, macosarm::kDarwinErrnoEnosys) &&
                       host.updates.empty() && host.steps.empty() &&
                       host.limit_queries.empty() && host.duplications.empty(),
                   "fcntl reports ENOSYS for a command it does not model");
        }

        host.update_error = macosarm::kDarwinErrnoEio;
        static_cast<void>(run_fcntl(vm, host, state, macosarm::kDarwinSysFcntl, 2U,
                                    macosarm::kDarwinFcntlSetfd, macosarm::kDarwinFdCloexec));
        expect(fcntl_failed_with(state, macosarm::kDarwinErrnoEio) &&
                   host.close_on_exec_is(2, false) && host.updates.size() == 1U,
               "a host F_SETFD failure is reported and leaves close-on-exec unchanged");
    }

    {
        // OFLAGS(f_flag) always holds exactly one access mode and only FMASK
        // status bits, so the dispatcher refuses anything else as a host
        // contract violation before any command reaches the guest or host.
        macosarm::GuestAddressSpace vm;
        macosarm::CpuState state{};
        DescriptorFlagsHost host;
        host.descriptors = {{3, false, macosarm::kDarwinOpenAccessMode},
                            {4, false, macosarm::kDarwinOpenReadOnly | 0x0010U}};
        const std::array<std::int32_t, 2> violating{3, 4};
        for (const std::int32_t fd : violating) {
            const auto violated =
                run_fcntl(vm, host, state, macosarm::kDarwinSysFcntl,
                          static_cast<std::uint64_t>(fd), macosarm::kDarwinFcntlSetfd,
                          macosarm::kDarwinFdCloexec);
            expect(violated.error == macosarm::SyscallDispatchError::host_contract_violation &&
                       host.updates.empty() && host.close_on_exec_is(fd, false),
                   "fcntl rejects host status flags outside OFLAGS(f_flag)");
        }
    }

    {
        // fcntl(2) F_SETFL replaces every FCNTLFLAGS bit with FFLAGS((int)arg)
        // and keeps the access mode, then hands the file its O_NONBLOCK state
        // through FIONBIO and its O_ASYNC state through FIOASYNC, in that
        // order. A later F_GETFL reports exactly what F_SETFL committed.
        using Step = DescriptorFlagsHost::Step;
        using Kind = Step::Kind;
        macosarm::GuestAddressSpace vm;
        macosarm::CpuState state{};
        DescriptorFlagsHost host;
        host.descriptors = {
            {0, false, macosarm::kDarwinOpenReadOnly},
            {1, false, macosarm::kDarwinOpenWriteOnly | macosarm::kDarwinOpenAppend},
        };
        const std::uint32_t nonblocking_writer =
            macosarm::kDarwinOpenWriteOnly | macosarm::kDarwinOpenNonblock;

        const auto plain = run_fcntl(vm, host, state, macosarm::kDarwinSysFcntl, 1U,
                                     macosarm::kDarwinFcntlSetfl, macosarm::kDarwinOpenNonblock);
        expect(static_cast<bool>(plain) && !carry_is_set(state) && state.x[0] == 0U &&
                   plain.syscall_number == macosarm::kDarwinSysFcntl &&
                   (host.steps == std::vector<Step>{{Kind::status_flags, 1, nonblocking_writer},
                                                    {Kind::nonblocking_io, 1, 1U},
                                                    {Kind::async_io, 1, 0U}}),
               "fcntl F_SETFL sets O_NONBLOCK, drops O_APPEND, then FIONBIO and FIOASYNC");

        static_cast<void>(run_fcntl(vm, host, state, macosarm::kDarwinSysFcntl, 1U,
                                    macosarm::kDarwinFcntlGetfl, 0U));
        expect(!carry_is_set(state) && state.x[0] == nonblocking_writer,
               "fcntl F_GETFL reports the status flags F_SETFL committed");

        host.steps.clear();
        const auto nocancel =
            run_fcntl(vm, host, state, macosarm::kDarwinSysFcntlNocancel, 0xFFFFFFFF00000000ULL,
                      macosarm::kDarwinFcntlSetfl,
                      macosarm::kDarwinOpenWriteOnly | macosarm::kDarwinOpenAsync);
        expect(static_cast<bool>(nocancel) && !carry_is_set(state) && state.x[0] == 0U &&
                   nocancel.syscall_number == macosarm::kDarwinSysFcntlNocancel &&
                   (host.steps == std::vector<Step>{
                        {Kind::status_flags, 0, macosarm::kDarwinOpenAsync},
                        {Kind::nonblocking_io, 0, 0U},
                        {Kind::async_io, 0, 1U}}),
               "fcntl_nocancel F_SETFL sets O_ASYNC, keeps O_RDONLY and reads only w0");

        host.steps.clear();
        static_cast<void>(run_fcntl(vm, host, state, macosarm::kDarwinSysFcntl, 0U,
                                    macosarm::kDarwinFcntlSetfl, macosarm::kDarwinOpenAccessMode));
        expect(!carry_is_set(state) && state.x[0] == 0U &&
                   (host.steps == std::vector<Step>{
                        {Kind::status_flags, 0, macosarm::kDarwinOpenNonblock},
                        {Kind::nonblocking_io, 0, 1U},
                        {Kind::async_io, 0, 0U}}),
               "fcntl F_SETFL carries an O_ACCMODE arg into O_NONBLOCK as FFLAGS does");

        host.steps.clear();
        static_cast<void>(run_fcntl(
            vm, host, state, macosarm::kDarwinSysFcntl, 1U, macosarm::kDarwinFcntlSetfl,
            macosarm::kDarwinOpenAccessMode | macosarm::kDarwinOpenNonblock));
        expect(!carry_is_set(state) && state.x[0] == 0U &&
                   (host.steps == std::vector<Step>{
                        {Kind::status_flags, 1,
                         macosarm::kDarwinOpenWriteOnly | macosarm::kDarwinOpenAppend},
                        {Kind::nonblocking_io, 1, 0U},
                        {Kind::async_io, 1, 0U}}),
               "fcntl F_SETFL lets the FFLAGS carry ripple past O_NONBLOCK into O_APPEND");

        host.steps.clear();
        static_cast<void>(run_fcntl(
            vm, host, state, macosarm::kDarwinSysFcntl, 1U, macosarm::kDarwinFcntlSetfl,
            macosarm::kDarwinOpenExec | macosarm::kDarwinOpenAccessMode |
                macosarm::kDarwinOpenNonblock));
        expect(!carry_is_set(state) && state.x[0] == 0U &&
                   (host.steps == std::vector<Step>{{Kind::status_flags, 1, nonblocking_writer},
                                                    {Kind::nonblocking_io, 1, 1U},
                                                    {Kind::async_io, 1, 0U}}),
               "fcntl F_SETFL with O_EXEC clears the access mode bits instead of adding one");
    }

    {
        // A failed F_SETFL step stops where XNU stops: a set_status_flags
        // failure changes nothing, a FIONBIO failure is reported with the new
        // status flags already committed, and a FIOASYNC failure clears
        // O_NONBLOCK again, returns the file to blocking I/O and reports the
        // FIOASYNC error rather than either undo step's result.
        using Step = DescriptorFlagsHost::Step;
        using Kind = Step::Kind;
        macosarm::GuestAddressSpace vm;
        macosarm::CpuState state{};
        DescriptorFlagsHost host;
        host.descriptors = {{2, false, macosarm::kDarwinOpenWriteOnly}};
        const std::uint64_t requested = macosarm::kDarwinOpenNonblock | macosarm::kDarwinOpenAsync;
        const std::uint32_t committed = macosarm::kDarwinOpenWriteOnly |
                                        macosarm::kDarwinOpenNonblock | macosarm::kDarwinOpenAsync;
        const std::uint32_t asynchronous_writer =
            macosarm::kDarwinOpenWriteOnly | macosarm::kDarwinOpenAsync;

        host.status_error = macosarm::kDarwinErrnoEio;
        static_cast<void>(run_fcntl(vm, host, state, macosarm::kDarwinSysFcntl, 2U,
                                    macosarm::kDarwinFcntlSetfl, requested));
        expect(fcntl_failed_with(state, macosarm::kDarwinErrnoEio) &&
                   (host.steps == std::vector<Step>{{Kind::status_flags, 2, committed}}),
               "a host F_SETFL status flags failure is reported before FIONBIO");
        static_cast<void>(run_fcntl(vm, host, state, macosarm::kDarwinSysFcntl, 2U,
                                    macosarm::kDarwinFcntlGetfl, 0U));
        expect(!carry_is_set(state) && state.x[0] == macosarm::kDarwinOpenWriteOnly,
               "a failed F_SETFL commit leaves the status flags unchanged");

        host.steps.clear();
        host.nonblocking_error = macosarm::kDarwinErrnoEnxio;
        static_cast<void>(run_fcntl(vm, host, state, macosarm::kDarwinSysFcntl, 2U,
                                    macosarm::kDarwinFcntlSetfl, requested));
        expect(fcntl_failed_with(state, macosarm::kDarwinErrnoEnxio) &&
                   (host.steps == std::vector<Step>{{Kind::status_flags, 2, committed},
                                                    {Kind::nonblocking_io, 2, 1U}}),
               "a host FIONBIO failure is reported and FIOASYNC is never asked");
        static_cast<void>(run_fcntl(vm, host, state, macosarm::kDarwinSysFcntl, 2U,
                                    macosarm::kDarwinFcntlGetfl, 0U));
        expect(!carry_is_set(state) && state.x[0] == committed,
               "a FIONBIO failure leaves the status flags F_SETFL committed");

        host.steps.clear();
        host.async_error = macosarm::kDarwinErrnoEio;
        static_cast<void>(run_fcntl(vm, host, state, macosarm::kDarwinSysFcntl, 2U,
                                    macosarm::kDarwinFcntlSetfl, requested));
        expect(fcntl_failed_with(state, macosarm::kDarwinErrnoEio) &&
                   (host.steps == std::vector<Step>{
                        {Kind::status_flags, 2, committed},
                        {Kind::nonblocking_io, 2, 1U},
                        {Kind::async_io, 2, 1U},
                        {Kind::status_flags, 2, asynchronous_writer},
                        {Kind::nonblocking_io, 2, 0U}}),
               "a host FIOASYNC failure clears O_NONBLOCK and restores blocking I/O");
        static_cast<void>(run_fcntl(vm, host, state, macosarm::kDarwinSysFcntl, 2U,
                                    macosarm::kDarwinFcntlGetfl, 0U));
        expect(!carry_is_set(state) && state.x[0] == asynchronous_writer,
               "after a FIOASYNC failure F_GETFL reports O_ASYNC without O_NONBLOCK");
    }

    {
        // fcntl(2) F_DUPFD and F_DUPFD_CLOEXEC allocate the lowest free
        // descriptor at or above the int low half of arg and below the soft
        // RLIMIT_NOFILE limit, naming the source's open file description so the
        // two share its status flags. Only F_DUPFD_CLOEXEC sets the new
        // descriptor's own close-on-exec flag; the source's never carries over.
        using Duplication = DescriptorFlagsHost::Duplication;
        macosarm::GuestAddressSpace vm;
        macosarm::CpuState state{};
        DescriptorFlagsHost host;
        host.descriptors = {
            {0, false, macosarm::kDarwinOpenReadOnly},
            {1, false, macosarm::kDarwinOpenWriteOnly | macosarm::kDarwinOpenAppend},
            {2, true, macosarm::kDarwinOpenWriteOnly},
        };

        const auto lowest = run_fcntl(vm, host, state, macosarm::kDarwinSysFcntl, 1U,
                                      macosarm::kDarwinFcntlDupfd, 0U);
        expect(static_cast<bool>(lowest) && !carry_is_set(state) && state.x[0] == 3U &&
                   lowest.syscall_number == macosarm::kDarwinSysFcntl &&
                   (host.limit_queries ==
                    std::vector<std::uint32_t>{macosarm::kDarwinRlimitNofile}) &&
                   (host.duplications == std::vector<Duplication>{{1, 0, false}}) &&
                   host.close_on_exec_is(3, false),
               "fcntl F_DUPFD returns the lowest free descriptor with close-on-exec clear");

        static_cast<void>(run_fcntl(vm, host, state, macosarm::kDarwinSysFcntl, 3U,
                                    macosarm::kDarwinFcntlGetfl, 0U));
        expect(!carry_is_set(state) &&
                   state.x[0] == (macosarm::kDarwinOpenWriteOnly | macosarm::kDarwinOpenAppend),
               "a F_DUPFD duplicate reports the source's status flags");

        static_cast<void>(run_fcntl(vm, host, state, macosarm::kDarwinSysFcntl, 2U,
                                    macosarm::kDarwinFcntlDupfd, 0U));
        expect(!carry_is_set(state) && state.x[0] == 4U && host.close_on_exec_is(4, false) &&
                   host.close_on_exec_is(2, true),
               "fcntl F_DUPFD never copies the source's close-on-exec flag");

        host.duplications.clear();
        const auto cloexec =
            run_fcntl(vm, host, state, macosarm::kDarwinSysFcntlNocancel, 0xFFFFFFFF00000000ULL,
                      0xFFFFFFFF00000000ULL | macosarm::kDarwinFcntlDupfdCloexec,
                      0xFFFFFFFF0000000AULL);
        expect(static_cast<bool>(cloexec) && !carry_is_set(state) && state.x[0] == 10U &&
                   cloexec.syscall_number == macosarm::kDarwinSysFcntlNocancel &&
                   (host.duplications == std::vector<Duplication>{{0, 10, true}}) &&
                   host.close_on_exec_is(10, true),
               "fcntl_nocancel F_DUPFD_CLOEXEC reads only w0, w1 and w2 and sets FD_CLOEXEC");

        static_cast<void>(run_fcntl(vm, host, state, macosarm::kDarwinSysFcntl, 0U,
                                    macosarm::kDarwinFcntlDupfd, 255U));
        expect(!carry_is_set(state) && state.x[0] == 255U && host.close_on_exec_is(255, false),
               "fcntl F_DUPFD accepts a minimum just below the soft RLIMIT_NOFILE limit");
    }

    if (failures != 0) {
        std::cerr << failures << " test(s) failed\n";
        return EXIT_FAILURE;
    }

    std::cout << "Darwin syscall dispatch tests passed\n";
    return EXIT_SUCCESS;
}
