#pragma once

#include "macosarm/address_space.hpp"
#include "macosarm/execution.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace macosarm {

constexpr std::uint32_t kDarwinSvcImmediate = 0x80;
constexpr std::uint64_t kDarwinSysExit = 1;
constexpr std::uint64_t kDarwinSysRead = 3;
constexpr std::uint64_t kDarwinSysWrite = 4;
constexpr std::uint64_t kDarwinSysGetpid = 20;
constexpr std::uint64_t kDarwinSysGetuid = 24;
constexpr std::uint64_t kDarwinSysGeteuid = 25;
constexpr std::uint64_t kDarwinSysGetppid = 39;
constexpr std::uint64_t kDarwinSysGetegid = 43;
constexpr std::uint64_t kDarwinSysGetgid = 47;
constexpr std::uint64_t kDarwinSysMunmap = 73;
constexpr std::uint64_t kDarwinSysMprotect = 74;
constexpr std::uint64_t kDarwinSysMmap = 197;
constexpr std::uint64_t kDarwinSysIssetugid = 327;
constexpr std::uint64_t kDarwinSysBsdthreadCreate = 360;
constexpr std::uint64_t kDarwinSysBsdthreadTerminate = 361;
constexpr std::uint64_t kDarwinSysBsdthreadRegister = 366;
constexpr std::uint64_t kDarwinSysThreadSelfid = 372;
constexpr std::uint64_t kDarwinSysReadNocancel = 396;
constexpr std::uint64_t kDarwinSysWriteNocancel = 397;
constexpr std::uint64_t kDarwinSysGetentropy = 500;
// XNU syscalls.master #116: int gettimeofday(struct timeval *tp,
// struct timezone *tzp, uint64_t *mach_absolute_time).
constexpr std::uint64_t kDarwinSysGettimeofday = 116;
// XNU syscalls.master #6: int close(int fd). #399 close_nocancel shares its
// argument and error contract; only the pthread cancellation point differs.
constexpr std::uint64_t kDarwinSysClose = 6;
constexpr std::uint64_t kDarwinSysCloseNocancel = 399;
constexpr std::uint32_t kDarwinErrnoEio = 5;
constexpr std::uint32_t kDarwinErrnoEbadf = 9;
constexpr std::uint32_t kDarwinErrnoEnomem = 12;
constexpr std::uint32_t kDarwinErrnoEacces = 13;
constexpr std::uint32_t kDarwinErrnoEinval = 22;
constexpr std::uint32_t kDarwinErrnoEfault = 14;
constexpr std::uint32_t kDarwinErrnoEnosys = 78;

// Synthetic POSIX credentials for a translated process: an ordinary,
// non-setugid macOS login user (uid 501, gid 20 "staff") whose parent is
// launchd (pid 1). These never reflect host credentials or host process
// ancestry, and they do not imply set*id, fork, or exec support.
constexpr std::uint32_t kDarwinSyntheticUserId = 501;
constexpr std::uint32_t kDarwinSyntheticGroupId = 20;
constexpr std::uint32_t kDarwinSyntheticParentProcessId = 1;
constexpr std::uint32_t kA64PstateCarry = 1u << 29;

// XNU bsd/sys/mman.h, kept separate from host OS mmap flags.
constexpr std::uint32_t kDarwinMapPrivate = 0x0002;
constexpr std::uint32_t kDarwinMapFixed = 0x0010;
constexpr std::uint32_t kDarwinMapJit = 0x0800;
constexpr std::uint32_t kDarwinMapAnonymous = 0x1000;
constexpr std::uint32_t kDarwinMapUnix03 = 0x40000;

class MachContext;
struct MachThreadIdentity;

struct HostWriteResult {
    std::uint64_t bytes_written{};
    std::uint32_t error{};

    [[nodiscard]] explicit operator bool() const noexcept {
        return error == 0;
    }
};

struct HostReadResult {
    std::uint64_t bytes_read{};
    std::uint32_t error{};

    [[nodiscard]] explicit operator bool() const noexcept {
        return error == 0;
    }
};

// Entropy is all-or-nothing: on success every requested byte was filled.
struct HostEntropyResult {
    std::uint32_t error{};

    [[nodiscard]] explicit operator bool() const noexcept {
        return error == 0;
    }
};

// Host wall-clock time for gettimeofday(2): seconds and microseconds since
// the Unix epoch. A successful result always has microseconds below one
// million; the dispatcher treats anything else as a host contract violation.
struct HostWallClockResult {
    std::int64_t seconds{};
    std::uint32_t microseconds{};
    std::uint32_t error{};

    [[nodiscard]] explicit operator bool() const noexcept {
        return error == 0;
    }
};

// Outcome of releasing a guest descriptor for close(2). There is no byte
// count; as in XNU, an error other than EBADF may still have released fd,
// so the dispatcher reports it once and never retries the close.
struct HostCloseResult {
    std::uint32_t error{};

    [[nodiscard]] explicit operator bool() const noexcept {
        return error == 0;
    }
};

class DarwinHostServices {
public:
    virtual ~DarwinHostServices() = default;

    [[nodiscard]] virtual HostWriteResult write(
        std::int32_t fd,
        std::span<const std::byte> bytes) = 0;

    // Fill at most bytes.size() bytes from guest descriptor fd. A successful
    // zero-byte result is end-of-file. Hosts that do not override this expose
    // no readable descriptors and report EBADF, never fabricated input.
    [[nodiscard]] virtual HostReadResult read(
        std::int32_t fd,
        std::span<std::byte> bytes) {
        static_cast<void>(fd);
        static_cast<void>(bytes);
        return {0, kDarwinErrnoEbadf};
    }

    // Fill every byte of bytes from a cryptographically secure host source
    // for getentropy(2), or fail with a Darwin errno. Hosts that do not
    // override this have no entropy source and report ENOSYS, never
    // predictable or fabricated bytes.
    [[nodiscard]] virtual HostEntropyResult fill_entropy(std::span<std::byte> bytes) {
        static_cast<void>(bytes);
        return {kDarwinErrnoEnosys};
    }

    // Report the host's current wall-clock time for gettimeofday(2) as
    // seconds and microseconds since the Unix epoch. Hosts that do not
    // override this have no clock and report ENOSYS, never a fabricated time.
    [[nodiscard]] virtual HostWallClockResult wall_clock() {
        return {0, 0, kDarwinErrnoEnosys};
    }

    // Release guest descriptor fd for close(2). As in XNU, any result other
    // than EBADF means fd was released and must not be closed again. Hosts
    // that do not override this expose no closable descriptors and report
    // EBADF, never a fabricated success.
    [[nodiscard]] virtual HostCloseResult close(std::int32_t fd) {
        static_cast<void>(fd);
        return {kDarwinErrnoEbadf};
    }
};

enum class SyscallAction {
    resume,
    exit_process,
    exit_thread,
};

enum class SyscallDispatchError {
    none,
    not_supervisor_call,
    unsupported_svc,
    host_contract_violation,
};

struct SyscallDispatchResult {
    SyscallDispatchError error{SyscallDispatchError::none};
    SyscallAction action{SyscallAction::resume};
    std::uint64_t syscall_number{};
    std::int32_t exit_status{};

    [[nodiscard]] explicit operator bool() const noexcept {
        return error == SyscallDispatchError::none;
    }
};

[[nodiscard]] SyscallDispatchResult dispatch_darwin_syscall(
    CpuState& state,
    GuestAddressSpace& address_space,
    const ExecutionResult& execution,
    DarwinHostServices& host);

// Process execution passes its shared Mach context, keeping BSD thread IDs
// consistent across translated initializers, main, and Mach traps.
[[nodiscard]] SyscallDispatchResult dispatch_darwin_syscall(
    CpuState& state,
    GuestAddressSpace& address_space,
    const ExecutionResult& execution,
    DarwinHostServices& host,
    const MachContext& context);

[[nodiscard]] SyscallDispatchResult dispatch_darwin_syscall(
    CpuState& state,
    GuestAddressSpace& address_space,
    const ExecutionResult& execution,
    DarwinHostServices& host,
    const MachContext& context,
    const MachThreadIdentity* current_thread);

[[nodiscard]] std::string_view syscall_dispatch_error_name(SyscallDispatchError error) noexcept;

} // namespace macosarm
