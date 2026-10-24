#include "macosarm/darwin_syscall.hpp"
#include "macosarm/mach_trap.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>

namespace macosarm {
namespace {

constexpr std::size_t kIoChunkSize = 64 * 1024;

void set_success(CpuState& state, std::uint64_t value) noexcept {
    state.x[0] = value;
    state.pstate &= ~kA64PstateCarry;
}

void set_error(CpuState& state, std::uint32_t error) noexcept {
    state.x[0] = error;
    state.pstate |= kA64PstateCarry;
}

[[nodiscard]] SyscallDispatchResult dispatch_write(
    CpuState& state,
    GuestAddressSpace& address_space,
    DarwinHostServices& host,
    std::uint64_t syscall_number) {

    const auto fd = static_cast<std::int32_t>(static_cast<std::uint32_t>(state.x[0]));
    std::uint64_t guest_address = state.x[1];
    std::uint64_t remaining = state.x[2];
    std::uint64_t total_written = 0;
    std::array<std::byte, kIoChunkSize> chunk{};

    while (remaining != 0) {
        const auto requested = static_cast<std::size_t>(
            std::min<std::uint64_t>(remaining, chunk.size()));
        const auto read_result = address_space.read(
            guest_address,
            std::span<std::byte>(chunk.data(), requested));
        if (!read_result) {
            if (total_written == 0) {
                set_error(state, kDarwinErrnoEfault);
            } else {
                set_success(state, total_written);
            }
            return {SyscallDispatchError::none, SyscallAction::resume, syscall_number, 0};
        }

        const HostWriteResult host_result = host.write(
            fd,
            std::span<const std::byte>(chunk.data(), requested));
        if (!host_result) {
            if (total_written == 0) {
                set_error(state, host_result.error);
            } else {
                set_success(state, total_written);
            }
            return {SyscallDispatchError::none, SyscallAction::resume, syscall_number, 0};
        }
        if (host_result.bytes_written > requested) {
            return {
                SyscallDispatchError::host_contract_violation,
                SyscallAction::resume,
                syscall_number,
                0,
            };
        }

        total_written += host_result.bytes_written;
        if (host_result.bytes_written != requested) {
            set_success(state, total_written);
            return {SyscallDispatchError::none, SyscallAction::resume, syscall_number, 0};
        }

        if (guest_address > std::numeric_limits<std::uint64_t>::max() - requested) {
            set_success(state, total_written);
            return {SyscallDispatchError::none, SyscallAction::resume, syscall_number, 0};
        }
        guest_address += requested;
        remaining -= requested;
    }

    set_success(state, total_written);
    return {SyscallDispatchError::none, SyscallAction::resume, syscall_number, 0};
}

// XNU bsd/kern/sys_generic.c: writev_nocancel rejects iovcnt outside
// [1, UIO_MAXIOV] (EINVAL) and copies the whole iovec array in (EFAULT),
// then uio_calculateresid_user rejects any iov_len or running total above
// SSIZE_MAX (EINVAL), all before fp_lookup resolves the descriptor (EBADF).
// A zero-length host write resolves it without emitting bytes, so a bad
// descriptor wins over a bad iov_base even when every vector is empty. The
// vectors are then written in order and empty ones are skipped without
// touching their bases. Like this dispatcher's write(2), a short host write
// ends the call, and a later fault or host error reports the bytes already
// written; an error is reported only when none were.
[[nodiscard]] SyscallDispatchResult dispatch_writev(
    CpuState& state,
    GuestAddressSpace& address_space,
    DarwinHostServices& host,
    std::uint64_t syscall_number) {

    static_assert(kDarwinIovecSize == 16U, "LP64 struct iovec is 16 bytes");
    const auto finish = [&]() {
        return SyscallDispatchResult{
            SyscallDispatchError::none, SyscallAction::resume, syscall_number, 0};
    };
    const auto fail = [&](std::uint32_t error) {
        set_error(state, error);
        return finish();
    };
    const auto contract_violation = [&]() {
        return SyscallDispatchResult{
            SyscallDispatchError::host_contract_violation,
            SyscallAction::resume, syscall_number, 0};
    };

    const auto fd = static_cast<std::int32_t>(static_cast<std::uint32_t>(state.x[0]));
    const std::uint64_t vector_address = state.x[1];
    const auto count = static_cast<std::uint32_t>(state.x[2]);
    if (count == 0U || count > kDarwinIovMax) {
        return fail(kDarwinErrnoEinval);
    }

    std::array<std::byte, kDarwinIovMax * kDarwinIovecSize> vectors{};
    const std::size_t vector_bytes = static_cast<std::size_t>(count) * kDarwinIovecSize;
    if (!address_space.read(vector_address, std::span<std::byte>(vectors.data(), vector_bytes))) {
        return fail(kDarwinErrnoEfault);
    }
    // Little-endian { iov_base, iov_len } fields of the vector at index.
    const auto field = [&](std::size_t index, std::size_t offset) {
        std::uint64_t value = 0;
        for (std::size_t i = 0; i < sizeof(std::uint64_t); ++i) {
            value |= static_cast<std::uint64_t>(std::to_integer<unsigned char>(
                         vectors[index * kDarwinIovecSize + offset + i]))
                     << (8U * i);
        }
        return value;
    };

    constexpr auto ssize_max =
        static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());
    std::uint64_t total = 0;
    for (std::size_t index = 0; index < count; ++index) {
        const std::uint64_t length = field(index, 8U);
        if (length > ssize_max - total) {
            return fail(kDarwinErrnoEinval);
        }
        total += length;
    }

    if (fd < 0) {
        return fail(kDarwinErrnoEbadf);
    }
    const HostWriteResult probe = host.write(fd, std::span<const std::byte>{});
    if (probe.bytes_written != 0U) {
        return contract_violation();
    }
    if (!probe) {
        return fail(probe.error);
    }

    std::uint64_t total_written = 0;
    const auto stop = [&](std::uint32_t error) {
        if (total_written == 0U) {
            set_error(state, error);
        } else {
            set_success(state, total_written);
        }
        return finish();
    };
    std::array<std::byte, kIoChunkSize> chunk{};
    for (std::size_t index = 0; index < count; ++index) {
        std::uint64_t guest_address = field(index, 0U);
        std::uint64_t remaining = field(index, 8U);
        while (remaining != 0U) {
            const auto requested = static_cast<std::size_t>(
                std::min<std::uint64_t>(remaining, chunk.size()));
            if (!address_space.read(guest_address, std::span<std::byte>(chunk.data(), requested))) {
                return stop(kDarwinErrnoEfault);
            }
            const HostWriteResult written = host.write(
                fd, std::span<const std::byte>(chunk.data(), requested));
            if (!written) {
                return stop(written.error);
            }
            if (written.bytes_written > requested) {
                return contract_violation();
            }
            total_written += written.bytes_written;
            if (written.bytes_written != requested) {
                set_success(state, total_written);
                return finish();
            }
            remaining -= requested;
            if (remaining != 0U &&
                guest_address > std::numeric_limits<std::uint64_t>::max() - requested) {
                return stop(kDarwinErrnoEfault);
            }
            guest_address += requested;
        }
    }
    set_success(state, total_written);
    return finish();
}

// XNU bsd/kern/sys_generic.c: readv_nocancel rejects iovcnt outside
// [1, UIO_MAXIOV] (EINVAL), copies the whole iovec array in (EFAULT) and
// rejects any iov_len or running total above SSIZE_MAX (EINVAL), all before
// rd_uio resolves the descriptor (EBADF) through a zero-length host read.
// As in this dispatcher's read(2), exactly one bounded host read then fills
// the vectors in order and never blocks again to fill them all. Empty
// vectors are skipped without touching their bases. Destinations are probed
// first and the read is limited to the leading vectors that can receive it,
// so host input is never consumed and then dropped; EFAULT is reported only
// when the first nonempty vector cannot receive a byte.
[[nodiscard]] SyscallDispatchResult dispatch_readv(
    CpuState& state,
    GuestAddressSpace& address_space,
    DarwinHostServices& host,
    std::uint64_t syscall_number) {

    static_assert(kDarwinIovecSize == 16U, "LP64 struct iovec is 16 bytes");
    const auto finish = [&]() {
        return SyscallDispatchResult{
            SyscallDispatchError::none, SyscallAction::resume, syscall_number, 0};
    };
    const auto fail = [&](std::uint32_t error) {
        set_error(state, error);
        return finish();
    };
    const auto contract_violation = [&]() {
        return SyscallDispatchResult{
            SyscallDispatchError::host_contract_violation,
            SyscallAction::resume, syscall_number, 0};
    };

    const auto fd = static_cast<std::int32_t>(static_cast<std::uint32_t>(state.x[0]));
    const std::uint64_t vector_address = state.x[1];
    const auto count = static_cast<std::uint32_t>(state.x[2]);
    if (count == 0U || count > kDarwinIovMax) {
        return fail(kDarwinErrnoEinval);
    }

    std::array<std::byte, kDarwinIovMax * kDarwinIovecSize> vectors{};
    const std::size_t vector_bytes = static_cast<std::size_t>(count) * kDarwinIovecSize;
    if (!address_space.read(vector_address, std::span<std::byte>(vectors.data(), vector_bytes))) {
        return fail(kDarwinErrnoEfault);
    }
    // Little-endian { iov_base, iov_len } fields of the vector at index.
    const auto field = [&](std::size_t index, std::size_t offset) {
        std::uint64_t value = 0;
        for (std::size_t i = 0; i < sizeof(std::uint64_t); ++i) {
            value |= static_cast<std::uint64_t>(std::to_integer<unsigned char>(
                         vectors[index * kDarwinIovecSize + offset + i]))
                     << (8U * i);
        }
        return value;
    };

    constexpr auto ssize_max =
        static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());
    std::uint64_t total = 0;
    for (std::size_t index = 0; index < count; ++index) {
        const std::uint64_t length = field(index, 8U);
        if (length > ssize_max - total) {
            return fail(kDarwinErrnoEinval);
        }
        total += length;
    }

    if (fd < 0) {
        return fail(kDarwinErrnoEbadf);
    }
    const HostReadResult probe = host.read(fd, std::span<std::byte>{});
    if (probe.bytes_read != 0U) {
        return contract_violation();
    }
    if (!probe) {
        return fail(probe.error);
    }

    // Bound the single host read by the chunk size and by the leading
    // nonempty vectors whose destinations can receive it.
    std::size_t requested = 0;
    for (std::size_t index = 0; index < count && requested < kIoChunkSize; ++index) {
        const std::uint64_t length = field(index, 8U);
        if (length == 0U) {
            continue;
        }
        const auto piece = static_cast<std::size_t>(
            std::min<std::uint64_t>(length, kIoChunkSize - requested));
        if (!address_space.probe_write(field(index, 0U), piece)) {
            break;
        }
        requested += piece;
    }
    if (requested == 0U) {
        if (total != 0U) {
            return fail(kDarwinErrnoEfault);
        }
        set_success(state, 0U);
        return finish();
    }

    std::array<std::byte, kIoChunkSize> chunk{};
    const HostReadResult host_result = host.read(
        fd, std::span<std::byte>(chunk.data(), requested));
    if (!host_result) {
        return fail(host_result.error);
    }
    if (host_result.bytes_read > requested) {
        return contract_violation();
    }
    const auto received = static_cast<std::size_t>(host_result.bytes_read);
    std::size_t delivered = 0;
    for (std::size_t index = 0; index < count && delivered < received; ++index) {
        const auto piece = static_cast<std::size_t>(
            std::min<std::uint64_t>(field(index, 8U), received - delivered));
        if (piece != 0U &&
            !address_space.write(field(index, 0U),
                                 std::span<const std::byte>(chunk.data() + delivered, piece))) {
            return fail(kDarwinErrnoEfault);
        }
        delivered += piece;
    }
    set_success(state, host_result.bytes_read);
    return finish();
}

// XNU bsd/kern/sys_generic.c: read_nocancel resolves the descriptor (EBADF)
// before dofileread rejects nbyte > INT_MAX (EINVAL) or copyout faults
// (EFAULT). A read may legally return fewer bytes than requested, so issue
// exactly one bounded host read and never block again to fill the buffer.
// The destination is probed first, so host input is never consumed and then
// dropped because the guest buffer cannot receive it.
[[nodiscard]] SyscallDispatchResult dispatch_read(
    CpuState& state,
    GuestAddressSpace& address_space,
    DarwinHostServices& host,
    std::uint64_t syscall_number) {

    const auto finish = [&]() {
        return SyscallDispatchResult{
            SyscallDispatchError::none, SyscallAction::resume, syscall_number, 0};
    };
    const auto contract_violation = [&]() {
        return SyscallDispatchResult{
            SyscallDispatchError::host_contract_violation,
            SyscallAction::resume, syscall_number, 0};
    };

    const auto fd = static_cast<std::int32_t>(static_cast<std::uint32_t>(state.x[0]));
    const std::uint64_t guest_address = state.x[1];
    const std::uint64_t nbyte = state.x[2];

    // A zero-length host read validates the descriptor without consuming
    // input; a bad descriptor wins over any later argument error.
    const auto check_descriptor =
        [&](std::uint32_t fallback_error) -> SyscallDispatchResult {
        const HostReadResult probe = host.read(fd, std::span<std::byte>{});
        if (probe.bytes_read != 0U) {
            return contract_violation();
        }
        if (!probe) {
            set_error(state, probe.error);
        } else if (fallback_error != 0U) {
            set_error(state, fallback_error);
        } else {
            set_success(state, 0U);
        }
        return finish();
    };

    if (nbyte == 0U) {
        return check_descriptor(0U);
    }
    if (nbyte > static_cast<std::uint64_t>(std::numeric_limits<std::int32_t>::max())) {
        return check_descriptor(kDarwinErrnoEinval);
    }
    const auto requested = static_cast<std::size_t>(
        std::min<std::uint64_t>(nbyte, kIoChunkSize));
    if (!address_space.probe_write(guest_address, requested)) {
        return check_descriptor(kDarwinErrnoEfault);
    }

    std::array<std::byte, kIoChunkSize> chunk{};
    const HostReadResult host_result = host.read(
        fd, std::span<std::byte>(chunk.data(), requested));
    if (!host_result) {
        set_error(state, host_result.error);
        return finish();
    }
    if (host_result.bytes_read > requested) {
        return contract_violation();
    }
    const auto received = static_cast<std::size_t>(host_result.bytes_read);
    if (received != 0U &&
        !address_space.write(guest_address,
                             std::span<const std::byte>(chunk.data(), received))) {
        set_error(state, kDarwinErrnoEfault);
        return finish();
    }
    set_success(state, host_result.bytes_read);
    return finish();
}

// The narrow anonymous mmap contract used by guest malloc and libsystem.
// XNU bsd/kern/kern_mman.c uses mach_vm_map_kernel for MAP_ANON and
// treats non-fixed addr as a start hint. We currently have neither vnode
// pagers nor atomic MAP_FIXED replacement, MAP_JIT entitlements, shared VM,
// or executable-memory code-signing. Those requests remain unsupported.
[[nodiscard]] SyscallDispatchResult dispatch_mmap(
    CpuState& state,
    GuestAddressSpace& address_space,
    std::uint64_t syscall_number) {

    const auto reject = [&](std::uint32_t error) {
        set_error(state, error);
        return SyscallDispatchResult{
            SyscallDispatchError::none, SyscallAction::resume, syscall_number, 0};
    };

    constexpr std::uint64_t page_size = GuestAddressSpace::kPageSize;
    constexpr std::uint64_t allocation_base = 0x2000000000ULL;
    constexpr std::uint64_t max_allocation_size = 256ULL * 1024ULL * 1024ULL;
    constexpr std::size_t max_mappings = 4096;
    constexpr std::uint32_t prot_mask = 7U;
    constexpr std::uint32_t valid_flags =
        kDarwinMapPrivate | kDarwinMapFixed | kDarwinMapJit |
        kDarwinMapAnonymous | kDarwinMapUnix03 | 1U; // MAP_SHARED

    const std::uint64_t length = state.x[1];
    const std::uint32_t prot = static_cast<std::uint32_t>(state.x[2]);
    const std::uint32_t flags = static_cast<std::uint32_t>(state.x[3]);
    const std::int32_t fd = static_cast<std::int32_t>(
        static_cast<std::uint32_t>(state.x[4]));
    const std::uint64_t position = state.x[5];

    if (length == 0 || (flags & ~valid_flags) != 0 ||
        (prot & ~prot_mask) != 0) {
        return reject(kDarwinErrnoEinval);
    }
    if (length > std::numeric_limits<std::uint64_t>::max() - (page_size - 1U)) {
        return reject(kDarwinErrnoEinval);
    }
    const std::uint64_t rounded_size =
        (length + page_size - 1U) & ~(page_size - 1U);
    if (rounded_size > max_allocation_size) {
        return reject(kDarwinErrnoEnomem);
    }

    // Only private, anonymous, non-fixed, non-JIT read/write regions
    // have an implemented backing and protection contract.
    if ((flags & ~kDarwinMapUnix03) !=
            (kDarwinMapPrivate | kDarwinMapAnonymous) ||
        (prot & 4U) != 0U || fd != -1 || position != 0U) {
        return reject(kDarwinErrnoEnosys);
    }
    const auto mappings = address_space.mappings();
    if (mappings.size() >= max_mappings) {
        return reject(kDarwinErrnoEnomem);
    }

    // Scan a finite snapshot of existing mappings to find a full hole.
    // Preserve caller-owned images and PAGEZERO without touching host VM.
    const auto free_region = [&](std::uint64_t start) -> std::optional<std::uint64_t> {
        std::uint64_t candidate = start;
        for (const Mapping& mapped : mappings) {
            const std::uint64_t end = mapped.base + mapped.size;
            if (end <= candidate) {
                continue;
            }
            if (mapped.base > candidate &&
                mapped.base - candidate >= rounded_size) {
                return candidate;
            }
            candidate = end;
            if (candidate > std::numeric_limits<std::uint64_t>::max() - rounded_size) {
                return std::nullopt;
            }
        }
        if (candidate > std::numeric_limits<std::uint64_t>::max() - rounded_size) {
            return std::nullopt;
        }
        return candidate;
    };

    const std::uint64_t hint = state.x[0];
    const std::uint64_t start =
        hint == 0U ||
        hint > std::numeric_limits<std::uint64_t>::max() - (page_size - 1U)
            ? allocation_base
            : (hint + page_size - 1U) & ~(page_size - 1U);
    auto address = free_region(start);
    if (!address.has_value() && start != allocation_base) {
        address = free_region(allocation_base);
    }
    if (!address.has_value()) {
        return reject(kDarwinErrnoEnomem);
    }

    Protection protection = Protection::none;
    if ((prot & 1U) != 0U) {
        protection = protection | Protection::read;
    }
    if ((prot & 2U) != 0U) {
        protection = protection | Protection::write;
    }
    if (!address_space.map(*address, rounded_size, protection,
                           Protection::read | Protection::write)) {
        return reject(kDarwinErrnoEnomem);
    }

    set_success(state, *address);
    return {SyscallDispatchError::none, SyscallAction::resume, syscall_number, 0};
}

[[nodiscard]] SyscallDispatchResult dispatch_mprotect(
    CpuState& state,
    GuestAddressSpace& address_space,
    std::uint64_t syscall_number) {

    // XNU bsd/kern/kern_mman.c: mprotect_sanitize checks alignment and
    // rounded range; mach_vm_protect returns ENOMEM for unmapped gaps and
    // EACCES when requested permissions exceed maximum map protections.
    const auto reject = [&](std::uint32_t error) {
        set_error(state, error);
        return SyscallDispatchResult{
            SyscallDispatchError::none, SyscallAction::resume, syscall_number, 0};
    };
    constexpr std::uint64_t page_size = GuestAddressSpace::kPageSize;
    const std::uint64_t address = state.x[0];
    const std::uint64_t length = state.x[1];
    // XNU's BSD protection sanitizer masks unknown bits.
    const std::uint32_t bits = static_cast<std::uint32_t>(state.x[2]) & 7U;
    if ((address % page_size) != 0U ||
        length > std::numeric_limits<std::uint64_t>::max() - (page_size - 1U)) {
        return reject(kDarwinErrnoEinval);
    }
    if (length == 0) {
        // XNU explicitly allows SIZE_ZERO_FALLTHROUGH.
        set_success(state, 0);
        return {SyscallDispatchError::none, SyscallAction::resume, syscall_number, 0};
    }
    const std::uint64_t rounded_size =
        (length + page_size - 1U) & ~(page_size - 1U);
    if (rounded_size > std::numeric_limits<std::uint64_t>::max() - address) {
        return reject(kDarwinErrnoEinval);
    }

    Protection protection = Protection::none;
    if ((bits & 1U) != 0U) {
        protection = protection | Protection::read;
    }
    if ((bits & 2U) != 0U) {
        protection = protection | Protection::write;
    }
    if ((bits & 4U) != 0U) {
        protection = protection | Protection::execute;
    }

    const VmResult result = address_space.protect_range(
        address, rounded_size, protection);
    if (!result) {
        return reject(result.error == VmError::unmapped ? kDarwinErrnoEnomem :
                      result.error == VmError::protection ? kDarwinErrnoEacces :
                      kDarwinErrnoEinval);
    }
    set_success(state, 0);
    return {SyscallDispatchError::none, SyscallAction::resume, syscall_number, 0};
}

[[nodiscard]] SyscallDispatchResult dispatch_munmap(
    CpuState& state,
    GuestAddressSpace& address_space,
    std::uint64_t syscall_number) {

    // XNU bsd/kern/kern_mman.c: munmap validates page alignment, nonzero
    // length and arithmetic range before calling mach_vm_deallocate().
    // mach_vm_deallocate rounds the length to the task's page size.
    const std::uint64_t base = state.x[0];
    const std::uint64_t size = state.x[1];
    constexpr std::uint64_t page_size = GuestAddressSpace::kPageSize;
    const std::uint64_t remainder = size % page_size;

    if ((base % page_size) != 0 || size == 0 ||
        size > std::numeric_limits<std::uint64_t>::max() - base) {
        set_error(state, kDarwinErrnoEinval);
        return {SyscallDispatchError::none, SyscallAction::resume, syscall_number, 0};
    }

    const std::uint64_t padding = remainder == 0 ? 0 : page_size - remainder;
    if (size > std::numeric_limits<std::uint64_t>::max() - padding) {
        set_error(state, kDarwinErrnoEinval);
        return {SyscallDispatchError::none, SyscallAction::resume, syscall_number, 0};
    }
    const std::uint64_t rounded_size = size + padding;
    if (rounded_size > std::numeric_limits<std::uint64_t>::max() - base ||
        !address_space.unmap_range(base, rounded_size)) {
        set_error(state, kDarwinErrnoEinval);
    } else {
        set_success(state, 0);
    }
    return {SyscallDispatchError::none, SyscallAction::resume, syscall_number, 0};
}

// Apple libpthread/kern/kern_internal.h: fixed, packed 56-byte record.
// Extract little-endian input fields after the copyin and size-version check.
[[nodiscard]] std::uint64_t pthread_record_u64(
    const std::array<std::byte, 56>& bytes, std::size_t offset) noexcept {
    std::uint64_t value = 0;
    for (std::size_t i = 0; i < 8U; ++i) {
        value |= static_cast<std::uint64_t>(
            std::to_integer<unsigned char>(bytes[offset + i])) << (i * 8U);
    }
    return value;
}

[[nodiscard]] std::uint32_t pthread_record_u32(
    const std::array<std::byte, 56>& bytes, std::size_t offset) noexcept {
    std::uint32_t value = 0;
    for (std::size_t i = 0; i < 4U; ++i) {
        value |= static_cast<std::uint32_t>(
            std::to_integer<unsigned char>(bytes[offset + i])) << (i * 8U);
    }
    return value;
}

// Preflight *never* commits registration or edits guest bytes. A valid
// request still returns ENOSYS instead of pretending support for pthread
// creation, registration copyout, workqueue scheduling, or QoS policies.
[[nodiscard]] SyscallDispatchResult dispatch_bsdthread_register_preflight(
    CpuState& state,
    GuestAddressSpace& address_space,
    const MachContext& context,
    std::uint64_t syscall_number) {
    const auto reject = [&](std::uint32_t error) {
        set_error(state, error);
        return SyscallDispatchResult{
            SyscallDispatchError::none, SyscallAction::resume, syscall_number, 0};
    };
    const auto pthread_size = static_cast<std::int32_t>(
        static_cast<std::uint32_t>(state.x[2]));
    if (pthread_size < 0 || pthread_size > 64 * 1024) {
        return reject(kDarwinErrnoEinval);
    }
    PthreadRegistrationPreflight candidate{};
    candidate.threadstart = state.x[0];
    candidate.wqthread = state.x[1];
    candidate.pthread_size = static_cast<std::uint32_t>(pthread_size);
    const std::uint64_t data_address = state.x[3];
    const std::uint64_t data_size = state.x[4];
    if (data_address != 0U) {
        if (data_size < sizeof(std::uint64_t)) {
            return reject(kDarwinErrnoEinval);
        }
        std::array<std::byte, 56> record{};
        const std::size_t copied = static_cast<std::size_t>(
            std::min<std::uint64_t>(data_size, record.size()));
        if (!address_space.read(data_address, std::span<std::byte>(record).first(copied))) {
            return reject(kDarwinErrnoEfault);
        }
        if (pthread_record_u64(record, 0U) != data_size) {
            return reject(kDarwinErrnoEinval);
        }
        candidate.record_size = data_size;
        candidate.record_address = data_address;
        candidate.copyout_size = static_cast<std::uint32_t>(copied);
        candidate.dispatch_queue_offset = pthread_record_u64(record, 8U);
        candidate.tsd_offset = pthread_record_u32(record, 24U);
        candidate.return_to_kernel_offset = pthread_record_u32(record, 28U);
        candidate.mach_thread_self_offset = pthread_record_u32(record, 32U);
        candidate.joinable_offset_bits = pthread_record_u32(record, 48U);
        candidate.wq_quantum_expiry_offset = pthread_record_u32(record, 52U);
        candidate.copyout_writable =
            static_cast<bool>(address_space.probe_write(data_address, copied));
    } else {
        candidate.dispatch_queue_offset = state.x[5];
    }
    // Match libpthread's source-observed per-process offsets. Values outside
    // the pthread structure's 64-bit TSD slot are ignored, not accepted.
    constexpr std::uint32_t slot_size = sizeof(std::uint64_t);
    std::uint32_t maximum_offset = 0U;
    if (candidate.pthread_size >= slot_size &&
        candidate.tsd_offset <= candidate.pthread_size - slot_size) {
        maximum_offset = candidate.pthread_size - candidate.tsd_offset - slot_size;
    } else {
        candidate.tsd_offset = 0U;
    }
    if (candidate.dispatch_queue_offset > maximum_offset) {
        candidate.dispatch_queue_offset = 0U;
    }
    if (candidate.return_to_kernel_offset > maximum_offset) {
        candidate.return_to_kernel_offset = 0U;
    }
    if (candidate.mach_thread_self_offset > maximum_offset) {
        candidate.mach_thread_self_offset = 0U;
    }
    if (candidate.wq_quantum_expiry_offset > maximum_offset) {
        candidate.wq_quantum_expiry_offset = 0U;
    }
    // ARM64 bsdthread_create eventually jumps through the registered
    // libpthread startup veneers. Observe whether both targets are aligned
    // and executable in the guest VM, without changing XNU's register-time
    // error ordering or claiming that their instructions are valid.
    // In particular, never dereference a guest entrypoint as host memory.
    const auto executable_entry = [&](std::uint64_t address) {
        if (address == 0U || (address & 3U) != 0U) {
            return false;
        }
        std::array<std::byte, 4> instruction{};
        return static_cast<bool>(address_space.fetch_code(address, instruction));
    };
    candidate.threadstart_executable = executable_entry(candidate.threadstart);
    candidate.wqthread_executable = executable_entry(candidate.wqthread);

    context.observe_pthread_registration_preflight(candidate);
    return reject(kDarwinErrnoEnosys);
}

// XNU bsd/kern/kern_descrip.c: fstat64(fd, ub) resolves the descriptor
// (EBADF) before vn_stat fills the kernel stat and copyout writes the
// 144-byte arm64 struct stat64 (EFAULT); success returns 0 in x0. The host
// reports only guest-visible metadata and the dispatcher encodes the layout
// itself, so no host stat structure reaches the guest. A malformed status is
// a host contract violation and is never copied out. A negative descriptor
// never reaches the host, and the destination is probed before any write.
[[nodiscard]] SyscallDispatchResult dispatch_fstat64(
    CpuState& state,
    GuestAddressSpace& address_space,
    DarwinHostServices& host,
    std::uint64_t syscall_number) {

    static_assert(kDarwinStat64Size == 144U, "arm64 struct stat64 is 144 bytes");
    constexpr std::int64_t nanoseconds_per_second = 1000000000;
    const auto finish = [&]() {
        return SyscallDispatchResult{
            SyscallDispatchError::none, SyscallAction::resume, syscall_number, 0};
    };

    const auto fd = static_cast<std::int32_t>(static_cast<std::uint32_t>(state.x[0]));
    const std::uint64_t guest_address = state.x[1];
    if (fd < 0) {
        set_error(state, kDarwinErrnoEbadf);
        return finish();
    }
    const HostStatResult described = host.file_status(fd);
    if (!described) {
        set_error(state, described.error);
        return finish();
    }

    const HostFileStatus& status = described.status;
    const auto file_type = static_cast<std::uint16_t>(status.mode & kDarwinModeTypeMask);
    const bool known_type =
        file_type == kDarwinModeFifo || file_type == kDarwinModeCharDevice ||
        file_type == kDarwinModeDirectory || file_type == kDarwinModeBlockDevice ||
        file_type == kDarwinModeRegular || file_type == kDarwinModeSymlink ||
        file_type == kDarwinModeSocket;
    const auto valid_time = [&](const DarwinTimespec& stamp) {
        return stamp.nanoseconds >= 0 && stamp.nanoseconds < nanoseconds_per_second;
    };
    if (!known_type || !valid_time(status.access_time) ||
        !valid_time(status.modification_time) || !valid_time(status.change_time) ||
        !valid_time(status.birth_time)) {
        return SyscallDispatchResult{
            SyscallDispatchError::host_contract_violation,
            SyscallAction::resume, syscall_number, 0};
    }

    // Little-endian arm64 layout; unset bytes, including the padding at
    // offset 28, stay zero so no stale staging data reaches the guest.
    std::array<std::byte, kDarwinStat64Size> record{};
    const auto put = [&](std::size_t offset, std::uint64_t value, std::size_t width) {
        for (std::size_t i = 0; i < width; ++i) {
            record[offset + i] = static_cast<std::byte>((value >> (8U * i)) & 0xffU);
        }
    };
    const auto put_time = [&](std::size_t offset, const DarwinTimespec& stamp) {
        put(offset, static_cast<std::uint64_t>(stamp.seconds), 8U);
        put(offset + 8U, static_cast<std::uint64_t>(stamp.nanoseconds), 8U);
    };
    put(0U, static_cast<std::uint32_t>(status.device), 4U);
    put(4U, status.mode, 2U);
    put(6U, status.link_count, 2U);
    put(8U, status.inode, 8U);
    put(16U, status.user_id, 4U);
    put(20U, status.group_id, 4U);
    put(24U, static_cast<std::uint32_t>(status.special_device), 4U);
    put_time(32U, status.access_time);
    put_time(48U, status.modification_time);
    put_time(64U, status.change_time);
    put_time(80U, status.birth_time);
    put(96U, static_cast<std::uint64_t>(status.size), 8U);
    put(104U, static_cast<std::uint64_t>(status.blocks), 8U);
    put(112U, static_cast<std::uint32_t>(status.block_size), 4U);
    put(116U, status.flags, 4U);
    // st_gen (120), st_lspare (124) and st_qspare (128-143) stay zero: XNU's
    // vn_stat withholds st_gen from non-root callers, and the synthetic guest
    // user is never root.

    if (!address_space.probe_write(guest_address, record.size()) ||
        !address_space.write(guest_address, std::span<const std::byte>(record))) {
        set_error(state, kDarwinErrnoEfault);
        return finish();
    }
    set_success(state, 0U);
    return finish();
}

// XNU bsd/vfs/vfs_syscalls.c: lseek(fd, offset, whence) resolves the
// descriptor first (EBADF), refuses a pipe, socket, FIFO or terminal
// (ESPIPE), and only then checks whence (EINVAL). The new offset uses
// XNU's wrapping off_t arithmetic: a positive request whose result wraps
// negative is EOVERFLOW, and any other negative result is EINVAL except
// on a character device. The host commits nothing until every check
// passes, so a failed lseek never moves the descriptor's offset.
[[nodiscard]] SyscallDispatchResult dispatch_lseek(
    CpuState& state,
    DarwinHostServices& host,
    std::uint64_t syscall_number) {

    const auto finish = [&]() {
        return SyscallDispatchResult{
            SyscallDispatchError::none, SyscallAction::resume, syscall_number, 0};
    };
    // off_t addition as XNU performs it: two's-complement wrap, never UB.
    const auto wrapping_add = [](std::int64_t lhs, std::int64_t rhs) {
        return static_cast<std::int64_t>(
            static_cast<std::uint64_t>(lhs) + static_cast<std::uint64_t>(rhs));
    };

    const auto fd = static_cast<std::int32_t>(static_cast<std::uint32_t>(state.x[0]));
    const auto requested = static_cast<std::int64_t>(state.x[1]);
    const auto whence = static_cast<std::uint32_t>(state.x[2]);
    if (fd < 0) {
        set_error(state, kDarwinErrnoEbadf);
        return finish();
    }
    const HostSeekResult described = host.seek_status(fd);
    if (!described) {
        set_error(state, described.error);
        return finish();
    }
    // A known size is never negative, and only a character device may
    // already sit at a negative offset.
    if ((described.size_error == 0 && described.size < 0) ||
        (described.offset < 0 && !described.character_device)) {
        return SyscallDispatchResult{
            SyscallDispatchError::host_contract_violation,
            SyscallAction::resume, syscall_number, 0};
    }

    std::int64_t offset = requested;
    std::uint32_t error = 0;
    switch (whence) {
    case kDarwinSeekCur:
        offset = wrapping_add(offset, described.offset);
        break;
    case kDarwinSeekEnd:
        if (described.size_error != 0) {
            error = described.size_error;
            break;
        }
        offset = wrapping_add(offset, described.size);
        break;
    case kDarwinSeekSet:
        break;
    case kDarwinSeekHole:
    case kDarwinSeekData:
        // XNU asks the filesystem through VNOP_IOCTL(FSIOC_FIOSEEKHOLE or
        // FSIOC_FIOSEEKDATA). Hole maps are not modeled, so, like a vnode
        // whose filesystem lacks those requests, the query fails with
        // ENOTTY rather than reporting a fabricated hole layout.
        error = kDarwinErrnoEnotty;
        break;
    default:
        error = kDarwinErrnoEinval;
        break;
    }
    if (error == 0) {
        if (requested > 0 && offset < 0) {
            error = kDarwinErrnoEoverflow;
        } else if (offset < 0 && !described.character_device) {
            error = kDarwinErrnoEinval;
        }
    }
    if (error != 0) {
        set_error(state, error);
        return finish();
    }
    const HostSetOffsetResult committed = host.set_offset(fd, offset);
    if (!committed) {
        set_error(state, committed.error);
        return finish();
    }
    set_success(state, static_cast<std::uint64_t>(offset));
    return finish();
}

// XNU bsd/dev/random/randomdev.c: getentropy(buffer, size) rejects sizes
// above its 256-byte kernel buffer with EINVAL (OpenBSD compatibility),
// fills that buffer from the kernel CSPRNG, then copies it out (EFAULT).
// There is no short count: success returns 0 with every byte written.
// The guest destination is probed first so host entropy is never drawn for
// a buffer that cannot receive it, and the staging copy is scrubbed after.
[[nodiscard]] SyscallDispatchResult dispatch_getentropy(
    CpuState& state,
    GuestAddressSpace& address_space,
    DarwinHostServices& host,
    std::uint64_t syscall_number) {

    constexpr std::size_t max_entropy_size = 256;
    const auto finish = [&]() {
        return SyscallDispatchResult{
            SyscallDispatchError::none, SyscallAction::resume, syscall_number, 0};
    };

    const std::uint64_t guest_address = state.x[0];
    const std::uint64_t size = state.x[1];
    if (size > max_entropy_size) {
        set_error(state, kDarwinErrnoEinval);
        return finish();
    }
    if (size == 0U) {
        // XNU copyout returns success for zero bytes before validating the
        // user address, so even a null buffer succeeds without host entropy.
        set_success(state, 0U);
        return finish();
    }
    const auto requested = static_cast<std::size_t>(size);
    if (!address_space.probe_write(guest_address, requested)) {
        set_error(state, kDarwinErrnoEfault);
        return finish();
    }

    std::array<std::byte, max_entropy_size> staging{};
    const std::span<std::byte> filled(staging.data(), requested);
    const HostEntropyResult host_result = host.fill_entropy(filled);
    if (!host_result) {
        set_error(state, host_result.error);
    } else if (!address_space.write(guest_address, std::span<const std::byte>(filled))) {
        set_error(state, kDarwinErrnoEfault);
    } else {
        set_success(state, 0U);
    }
    // Volatile stores keep the scrub from being elided as a dead write.
    volatile std::byte* const scrub = staging.data();
    for (std::size_t i = 0; i < staging.size(); ++i) {
        scrub[i] = std::byte{0};
    }
    return finish();
}

// XNU bsd/kern/kern_time.c: gettimeofday(tp, tzp, mach_absolute_time)
// samples the clock only when tp or mach_absolute_time is requested, then
// copies out a 64-bit timeval (tv_sec cast through uint32_t to match the
// arm64 commpage), the kernel timezone and the Mach absolute time, in that
// order. A failing copyout returns EFAULT at once while earlier copyouts
// stay visible; success returns 0 in x0, never the time in registers.
// No Mach timebase exists yet, so a paired absolute-time request fails
// closed with ENOSYS before any clock read or guest write. Each destination
// is probed before it is written (the timeval before the host clock is even
// read), and the timezone is always UTC without DST, never the host's zone.
[[nodiscard]] SyscallDispatchResult dispatch_gettimeofday(
    CpuState& state,
    GuestAddressSpace& address_space,
    DarwinHostServices& host,
    std::uint64_t syscall_number) {

    constexpr std::size_t timeval_size = 16; // struct user64_timeval
    constexpr std::size_t timezone_size = 8; // struct timezone
    constexpr std::uint32_t microseconds_per_second = 1000000U;
    const auto finish = [&]() {
        return SyscallDispatchResult{
            SyscallDispatchError::none, SyscallAction::resume, syscall_number, 0};
    };
    const auto fault = [&]() {
        set_error(state, kDarwinErrnoEfault);
        return finish();
    };

    const std::uint64_t timeval_address = state.x[0];
    const std::uint64_t timezone_address = state.x[1];
    const std::uint64_t absolute_time_address = state.x[2];
    if (absolute_time_address != 0U) {
        set_error(state, kDarwinErrnoEnosys);
        return finish();
    }

    if (timeval_address != 0U) {
        if (!address_space.probe_write(timeval_address, timeval_size)) {
            return fault();
        }
        const HostWallClockResult now = host.wall_clock();
        if (!now) {
            set_error(state, now.error);
            return finish();
        }
        if (now.microseconds >= microseconds_per_second) {
            return SyscallDispatchResult{
                SyscallDispatchError::host_contract_violation,
                SyscallAction::resume, syscall_number, 0};
        }
        // { int64 tv_sec; int32 tv_usec; } plus four zeroed padding bytes.
        // Keep all 64 signed tv_sec bits: a uint32 cast would wrap pre-epoch
        // clocks into the far future and truncate times past 2106.
        const auto seconds = static_cast<std::uint64_t>(now.seconds);
        std::array<std::byte, timeval_size> time_record{};
        for (std::size_t i = 0; i < 8U; ++i) {
            time_record[i] = static_cast<std::byte>((seconds >> (8U * i)) & 0xffU);
        }
        for (std::size_t i = 0; i < 4U; ++i) {
            time_record[8U + i] =
                static_cast<std::byte>((now.microseconds >> (8U * i)) & 0xffU);
        }
        if (!address_space.write(timeval_address,
                                 std::span<const std::byte>(time_record))) {
            return fault();
        }
    }

    if (timezone_address != 0U) {
        // { int tz_minuteswest; int tz_dsttime; } is all zero for UTC.
        const std::array<std::byte, timezone_size> zone_record{};
        if (!address_space.probe_write(timezone_address, zone_record.size()) ||
            !address_space.write(timezone_address,
                                 std::span<const std::byte>(zone_record))) {
            return fault();
        }
    }

    set_success(state, 0U);
    return finish();
}

// The guest-visible struct termios for ioctl(2) TIOCGETA: XNU
// bsd/sys/ttydefaults.h TTYDEF_IFLAG, TTYDEF_OFLAG, TTYDEF_CFLAG,
// TTYDEF_LFLAG, ttydefchars and TTYDEF_SPEED (B9600), the canonical, echoing
// mode of a freshly opened terminal. It is synthetic: no host terminal
// settings reach the guest. Little-endian LP64 layout; the c_cc padding at
// offsets 52-55 stays zero.
[[nodiscard]] std::array<std::byte, kDarwinTermiosSize> synthetic_termios() noexcept {
    static_assert(kDarwinTermiosSize == 72U, "LP64 struct termios is 72 bytes");
    static_assert(kDarwinTermiosControlCharCount == 20U, "Darwin NCCS is 20");
    // bsd/sys/termios.h flag bits.
    constexpr std::uint64_t input_flags = 0x2b02;   // BRKINT|ICRNL|IXON|IXANY|IMAXBEL
    constexpr std::uint64_t output_flags = 0x0003;  // OPOST|ONLCR
    constexpr std::uint64_t control_flags = 0x4b00; // CS8|CREAD|HUPCL
    constexpr std::uint64_t local_flags = 0x05cb;   // ECHOKE|ECHOE|ECHO|ECHOCTL|ISIG|ICANON|IEXTEN
    constexpr std::uint64_t speed = 9600;           // B9600
    // ttydefchars in V* index order; 0xff is _POSIX_VDISABLE.
    constexpr std::array<std::uint8_t, kDarwinTermiosControlCharCount> control_chars{
        0x04, 0xff, 0xff, 0x7f, 0x17, 0x15, 0x12, 0xff, 0x03, 0x1c, // VEOF..VQUIT
        0x1a, 0x19, 0x11, 0x13, 0x16, 0x0f, 0x01, 0x00, 0x14, 0xff, // VSUSP..spare
    };

    std::array<std::byte, kDarwinTermiosSize> record{};
    const auto put = [&](std::size_t offset, std::uint64_t value) {
        for (std::size_t i = 0; i < sizeof(std::uint64_t); ++i) {
            record[offset + i] = static_cast<std::byte>((value >> (8U * i)) & 0xffU);
        }
    };
    put(0U, input_flags);    // c_iflag
    put(8U, output_flags);   // c_oflag
    put(16U, control_flags); // c_cflag
    put(24U, local_flags);   // c_lflag
    for (std::size_t i = 0; i < control_chars.size(); ++i) {
        record[32U + i] = static_cast<std::byte>(control_chars[i]);
    }
    put(56U, speed); // c_ispeed
    put(64U, speed); // c_ospeed
    return record;
}

// XNU bsd/kern/sys_generic.c: ioctl(fd, com, data) sizes the argument from
// bits 16-28 of com and copies an IOC_IN argument in (EFAULT) before it
// resolves the descriptor (EBADF). FIOCLEX, FIONCLEX, FIONBIO, FIOASYNC,
// FIOSETOWN and FIOGETOWN act on the file table entry itself; descriptor
// flags and ownership are not modeled yet, so they report ENOSYS and are
// never acknowledged. Every other request reaches the device, which reports
// ENOTTY for a request it does not recognize, and an IOC_OUT result is
// copied out only on success (EFAULT). Only TIOCGETA and TIOCGWINSZ on a
// host terminal are recognized; the host reports just that fd is a terminal
// and its window size, and the dispatcher encodes both records itself. A
// negative descriptor never reaches the host.
[[nodiscard]] SyscallDispatchResult dispatch_ioctl(
    CpuState& state,
    GuestAddressSpace& address_space,
    DarwinHostServices& host,
    std::uint64_t syscall_number) {

    const auto finish = [&]() {
        return SyscallDispatchResult{
            SyscallDispatchError::none, SyscallAction::resume, syscall_number, 0};
    };

    const auto fd = static_cast<std::int32_t>(static_cast<std::uint32_t>(state.x[0]));
    const std::uint64_t command = state.x[1];
    const std::uint64_t guest_address = state.x[2];
    const auto size = static_cast<std::size_t>((command >> 16U) & kDarwinIocParmMask);

    if ((command & kDarwinIocIn) != 0U && size != 0U) {
        // Staged only to reproduce XNU's copyin fault ordering; no request
        // handled here consumes guest input yet.
        std::array<std::byte, kDarwinIocParmMask + 1U> argument{};
        if (!address_space.read(guest_address, std::span<std::byte>(argument.data(), size))) {
            set_error(state, kDarwinErrnoEfault);
            return finish();
        }
    }
    if (fd < 0) {
        set_error(state, kDarwinErrnoEbadf);
        return finish();
    }
    // The terminal query doubles as descriptor resolution: EBADF names no
    // guest descriptor, ENOTTY an open descriptor that is not a terminal.
    const HostTerminalResult terminal = host.terminal_status(fd);
    if (terminal.error == kDarwinErrnoEbadf) {
        set_error(state, kDarwinErrnoEbadf);
        return finish();
    }

    const auto copy_out = [&](std::span<const std::byte> record) {
        if (!address_space.probe_write(guest_address, record.size()) ||
            !address_space.write(guest_address, record)) {
            set_error(state, kDarwinErrnoEfault);
        } else {
            set_success(state, 0U);
        }
        return finish();
    };

    switch (command) {
    case kDarwinIoctlFioclex:
    case kDarwinIoctlFionclex:
    case kDarwinIoctlFiogetown:
    case kDarwinIoctlFiosetown:
    case kDarwinIoctlFioasync:
    case kDarwinIoctlFionbio:
        set_error(state, kDarwinErrnoEnosys);
        return finish();
    case kDarwinIoctlTiocgeta: {
        if (!terminal) {
            set_error(state, terminal.error);
            return finish();
        }
        const std::array<std::byte, kDarwinTermiosSize> record = synthetic_termios();
        return copy_out(record);
    }
    case kDarwinIoctlTiocgwinsz: {
        if (!terminal) {
            set_error(state, terminal.error);
            return finish();
        }
        static_assert(kDarwinWinsizeSize == 8U, "struct winsize is four unsigned shorts");
        const std::array<std::uint16_t, 4> fields{
            terminal.rows, terminal.columns, terminal.x_pixels, terminal.y_pixels};
        std::array<std::byte, kDarwinWinsizeSize> record{};
        for (std::size_t i = 0; i < fields.size(); ++i) {
            record[2U * i] = static_cast<std::byte>(fields[i] & 0xffU);
            record[2U * i + 1U] = static_cast<std::byte>(fields[i] >> 8U);
        }
        return copy_out(record);
    }
    default:
        set_error(state, terminal ? kDarwinErrnoEnotty : terminal.error);
        return finish();
    }
}

} // namespace

SyscallDispatchResult dispatch_darwin_syscall(
    CpuState& state,
    GuestAddressSpace& address_space,
    const ExecutionResult& execution,
    DarwinHostServices& host,
    const MachContext& context,
    const MachThreadIdentity* current_thread) {

    if (execution.reason != StopReason::supervisor_call) {
        return {SyscallDispatchError::not_supervisor_call, SyscallAction::resume, 0, 0};
    }
    if (execution.supervisor_call != kDarwinSvcImmediate) {
        return {SyscallDispatchError::unsupported_svc, SyscallAction::resume, 0, 0};
    }

    const std::uint64_t syscall_number = state.x[16];
    switch (syscall_number) {
    case kDarwinSysExit:
        return {
            SyscallDispatchError::none,
            SyscallAction::exit_process,
            syscall_number,
            static_cast<std::int32_t>(static_cast<std::uint32_t>(state.x[0])),
        };
    case kDarwinSysRead:
    case kDarwinSysReadNocancel:
        // XNU syscalls.master #396 read_nocancel shares read's argument and
        // error contract; only the pthread cancellation point differs, and
        // no guest pthread can be cancelled yet.
        return dispatch_read(state, address_space, host, syscall_number);
    case kDarwinSysReadv:
    case kDarwinSysReadvNocancel:
        // XNU syscalls.master #120 readv / #411 readv_nocancel scatter one
        // bounded host read across the guest's iovec array, in order. No
        // guest pthread can be cancelled yet, so both entry points share one
        // handler.
        return dispatch_readv(state, address_space, host, syscall_number);
    case kDarwinSysWrite:
    case kDarwinSysWriteNocancel:
        // XNU syscalls.master #397 write_nocancel likewise aliases write.
        return dispatch_write(state, address_space, host, syscall_number);
    case kDarwinSysWritev:
    case kDarwinSysWritevNocancel:
        // XNU syscalls.master #121 writev / #412 writev_nocancel gather the
        // guest's iovec array; each vector reaches the host only through the
        // same bounded write path, in order. No guest pthread can be
        // cancelled yet, so both entry points share one handler.
        return dispatch_writev(state, address_space, host, syscall_number);
    case kDarwinSysMmap:
        return dispatch_mmap(state, address_space, syscall_number);
    case kDarwinSysMprotect:
        return dispatch_mprotect(state, address_space, syscall_number);
    case kDarwinSysMunmap:
        return dispatch_munmap(state, address_space, syscall_number);
    case kDarwinSysFstat64:
        // XNU syscalls.master #339: int fstat64(int fd, user_addr_t ub). On
        // arm64, libSystem's fstat(3) traps here. Metadata comes only from the
        // host's guest-descriptor view and the dispatcher encodes the layout.
        return dispatch_fstat64(state, address_space, host, syscall_number);
    case kDarwinSysIoctl:
        // XNU syscalls.master #54: int ioctl(int fd, u_long com, caddr_t data).
        // libSystem's isatty(3) and stdio's line-buffering probe issue
        // TIOCGETA; terminal state comes only from the host's view of the
        // guest descriptor and the dispatcher encodes every record itself.
        return dispatch_ioctl(state, address_space, host, syscall_number);
    case kDarwinSysLseek:
        // XNU syscalls.master #199: off_t lseek(int fd, off_t offset, int whence).
        // libSystem's lseek(3) traps here, and stdio's fseeko(3), ftello(3) and
        // rewind(3) reach it through __sseek. arm64 passes the whole off_t in
        // x1 and returns the new offset in x0. The current offset and size
        // come only from the host's view of the guest descriptor; the
        // dispatcher applies XNU's whence arithmetic and range checks itself.
        return dispatch_lseek(state, host, syscall_number);
    case kDarwinSysGetentropy:
        // XNU syscalls.master #500: int getentropy(void *buffer, size_t size).
        // libSystem seeds arc4random and malloc/stack guards from it; bytes
        // come only from the host's secure source, never a fabricated seed.
        return dispatch_getentropy(state, address_space, host, syscall_number);
    case kDarwinSysGettimeofday:
        // XNU syscalls.master #116: int gettimeofday(struct timeval *tp,
        // struct timezone *tzp, uint64_t *mach_absolute_time). Time comes
        // only from the host wall clock; the zone is always synthetic UTC.
        return dispatch_gettimeofday(state, address_space, host, syscall_number);
    case kDarwinSysClose:
    case kDarwinSysCloseNocancel: {
        // XNU bsd/kern/kern_descrip.c: close_nocancel rejects a descriptor
        // outside the file table with EBADF before releasing anything. A
        // negative fd can never name a guest descriptor, so it never reaches
        // the host. Any other host error is reported once and the descriptor
        // is never closed a second time.
        const auto fd = static_cast<std::int32_t>(static_cast<std::uint32_t>(state.x[0]));
        if (fd < 0) {
            set_error(state, kDarwinErrnoEbadf);
            return {SyscallDispatchError::none, SyscallAction::resume, syscall_number, 0};
        }
        const HostCloseResult closed = host.close(fd);
        if (!closed) {
            set_error(state, closed.error);
        } else {
            set_success(state, 0U);
        }
        return {SyscallDispatchError::none, SyscallAction::resume, syscall_number, 0};
    }
    case kDarwinSysGetpid:
        // XNU bsd/kern/syscalls.master: BSD #20, int getpid(void).
        // Process identity belongs to the shared context, never to the host.
        set_success(state, context.process_id());
        return {SyscallDispatchError::none, SyscallAction::resume, syscall_number, 0};
    case kDarwinSysGetppid:
        // XNU syscalls.master #39: int getppid(void). A translated process is
        // reported as a child of launchd, never of the host parent process.
        set_success(state, kDarwinSyntheticParentProcessId);
        return {SyscallDispatchError::none, SyscallAction::resume, syscall_number, 0};
    case kDarwinSysGetuid:
    case kDarwinSysGeteuid:
        // XNU syscalls.master #24 getuid / #25 geteuid: both always succeed.
        // Real and effective ids are the same synthetic non-root login user;
        // host credentials are never consulted or exposed.
        set_success(state, kDarwinSyntheticUserId);
        return {SyscallDispatchError::none, SyscallAction::resume, syscall_number, 0};
    case kDarwinSysGetgid:
    case kDarwinSysGetegid:
        // XNU syscalls.master #47 getgid / #43 getegid: synthetic "staff".
        set_success(state, kDarwinSyntheticGroupId);
        return {SyscallDispatchError::none, SyscallAction::resume, syscall_number, 0};
    case kDarwinSysIssetugid:
        // XNU syscalls.master #327: int issetugid(void). The synthetic
        // credentials never change and no image is launched set-id, so the
        // process is not tainted; libSystem may then honor environment vars.
        set_success(state, 0U);
        return {SyscallDispatchError::none, SyscallAction::resume, syscall_number, 0};
    case kDarwinSysBsdthreadRegister:
        return dispatch_bsdthread_register_preflight(
            state, address_space, context, syscall_number);
    case kDarwinSysBsdthreadTerminate:
        // XNU syscalls.master #361: (stackaddr, freesize, port, sema_or_ulock).
        // A registered pthread can also request stack deallocation, Mach
        // right release and semaphore signaling. We cannot perform those
        // kernel lifetime operations yet, so never acknowledge such a call.
        // For manually constructed, resource-free guest execution contexts
        // only, terminate the caller without killing sibling contexts.
        if (current_thread == nullptr || state.x[0] != 0 ||
            state.x[1] != 0 || state.x[2] != 0 || state.x[3] != 0) {
            set_error(state, kDarwinErrnoEnosys);
            return {SyscallDispatchError::none, SyscallAction::resume, syscall_number, 0};
        }
        return {SyscallDispatchError::none, SyscallAction::exit_thread, syscall_number, 0};
    case kDarwinSysBsdthreadCreate:
        // libpthread/kern/kern_support.c: _bsdthread_create rejects a
        // process before allocating a thread when proc_get_register(p) == 0.
        // Our bsdthread_register cannot succeed yet; remain unregistered and
        // reject creation with XNU's EINVAL, without claiming thread support.
        // A validated preflight is not a successful registration.
        set_error(state, context.pthread_registered()
                             ? kDarwinErrnoEnosys : kDarwinErrnoEinval);
        return {SyscallDispatchError::none, SyscallAction::resume, syscall_number, 0};
    case kDarwinSysThreadSelfid:
        // _thread_selfid reports a 64-bit thread ID, not the Mach port name.
        // The current thread is the process main thread in the legacy path.
        set_success(state, current_thread != nullptr
                               ? current_thread->thread_id : context.thread_id());
        return {SyscallDispatchError::none, SyscallAction::resume, syscall_number, 0};
    default:
        set_error(state, kDarwinErrnoEnosys);
        return {SyscallDispatchError::none, SyscallAction::resume, syscall_number, 0};
    }
}

SyscallDispatchResult dispatch_darwin_syscall(
    CpuState& state,
    GuestAddressSpace& address_space,
    const ExecutionResult& execution,
    DarwinHostServices& host,
    const MachContext& context) {
    return dispatch_darwin_syscall(state, address_space, execution, host, context, nullptr);
}

SyscallDispatchResult dispatch_darwin_syscall(
    CpuState& state,
    GuestAddressSpace& address_space,
    const ExecutionResult& execution,
    DarwinHostServices& host) {
    MachContext context;
    return dispatch_darwin_syscall(state, address_space, execution, host, context);
}

std::string_view syscall_dispatch_error_name(SyscallDispatchError error) noexcept {
    switch (error) {
    case SyscallDispatchError::none: return "none";
    case SyscallDispatchError::not_supervisor_call: return "not_supervisor_call";
    case SyscallDispatchError::unsupported_svc: return "unsupported_svc";
    case SyscallDispatchError::host_contract_violation: return "host_contract_violation";
    }
    return "unknown";
}

} // namespace macosarm
