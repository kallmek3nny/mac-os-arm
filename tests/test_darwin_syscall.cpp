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

    if (failures != 0) {
        std::cerr << failures << " test(s) failed\n";
        return EXIT_FAILURE;
    }

    std::cout << "Darwin syscall dispatch tests passed\n";
    return EXIT_SUCCESS;
}
