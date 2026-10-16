#pragma once

#include "macosarm/address_space.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace macosarm {

constexpr std::uint64_t kDarwinCommpageDataAddress = 0x0000000FFFFFC000ULL;
constexpr std::uint64_t kDarwinCommpageReadOnlyAddress = 0x0000000FFFFF4000ULL;
constexpr std::uint64_t kDarwinCommpageKdebugEnableAddress =
    kDarwinCommpageDataAddress + 0x100ULL;
constexpr std::uint64_t kDarwinCommpageUserPageShift64Address =
    kDarwinCommpageReadOnlyAddress + 0x025ULL;
constexpr std::uint64_t kDarwinCommpageKernelPageShiftAddress =
    kDarwinCommpageReadOnlyAddress + 0x037ULL;
constexpr std::uint8_t kDarwinCommpagePageShift = 14U;

static_assert((std::uint64_t{1} << kDarwinCommpagePageShift) == GuestAddressSpace::kPageSize);
static_assert((kDarwinCommpageDataAddress % GuestAddressSpace::kPageSize) == 0);
static_assert((kDarwinCommpageReadOnlyAddress % GuestAddressSpace::kPageSize) == 0);

enum class DarwinCommpageError {
    none,
    data_map_failure,
    read_only_map_failure,
    user_page_shift_failure,
    kernel_page_shift_failure,
};

struct DarwinCommpageResult {
    DarwinCommpageError error{DarwinCommpageError::none};
    VmError vm_error{VmError::none};

    [[nodiscard]] explicit operator bool() const noexcept {
        return error == DarwinCommpageError::none;
    }
};

[[nodiscard]] inline DarwinCommpageResult materialize_darwin_commpage(
    GuestAddressSpace& address_space) {

    const VmResult data_mapping = address_space.map(
        kDarwinCommpageDataAddress,
        GuestAddressSpace::kPageSize,
        Protection::read);
    if (!data_mapping) {
        return {DarwinCommpageError::data_map_failure, data_mapping.error};
    }

    const VmResult read_only_mapping = address_space.map(
        kDarwinCommpageReadOnlyAddress,
        GuestAddressSpace::kPageSize,
        Protection::read);
    if (!read_only_mapping) {
        (void)address_space.unmap(kDarwinCommpageDataAddress, GuestAddressSpace::kPageSize);
        return {DarwinCommpageError::read_only_map_failure, read_only_mapping.error};
    }

    const std::array<std::byte, 1> page_shift{
        static_cast<std::byte>(kDarwinCommpagePageShift)};
    const VmResult user_shift = address_space.load_bytes(
        kDarwinCommpageUserPageShift64Address,
        std::span<const std::byte>(page_shift));
    if (!user_shift) {
        (void)address_space.unmap(kDarwinCommpageReadOnlyAddress, GuestAddressSpace::kPageSize);
        (void)address_space.unmap(kDarwinCommpageDataAddress, GuestAddressSpace::kPageSize);
        return {DarwinCommpageError::user_page_shift_failure, user_shift.error};
    }

    const VmResult kernel_shift = address_space.load_bytes(
        kDarwinCommpageKernelPageShiftAddress,
        std::span<const std::byte>(page_shift));
    if (!kernel_shift) {
        (void)address_space.unmap(kDarwinCommpageReadOnlyAddress, GuestAddressSpace::kPageSize);
        (void)address_space.unmap(kDarwinCommpageDataAddress, GuestAddressSpace::kPageSize);
        return {DarwinCommpageError::kernel_page_shift_failure, kernel_shift.error};
    }

    return {};
}

[[nodiscard]] inline std::string_view darwin_commpage_error_name(
    DarwinCommpageError error) noexcept {
    switch (error) {
    case DarwinCommpageError::none: return "none";
    case DarwinCommpageError::data_map_failure: return "data_map_failure";
    case DarwinCommpageError::read_only_map_failure: return "read_only_map_failure";
    case DarwinCommpageError::user_page_shift_failure: return "user_page_shift_failure";
    case DarwinCommpageError::kernel_page_shift_failure: return "kernel_page_shift_failure";
    }
    return "unknown";
}

} // namespace macosarm
