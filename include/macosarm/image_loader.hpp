#pragma once

#include "macosarm/address_space.hpp"
#include "macosarm/macho.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace macosarm {

enum class LoadError {
    none,
    missing_entry_point,
    missing_text_segment,
    malformed_segment,
    unaligned_segment,
    bad_entry_point,
    vm_failure,
};

struct LoadedImage {
    std::uint64_t preferred_load_address{};
    std::uint64_t entry_address{};
    std::size_t mapped_segments{};
};

struct LoadResult {
    LoadedImage image;
    LoadError error{LoadError::none};
    VmError vm_error{VmError::none};

    [[nodiscard]] explicit operator bool() const noexcept {
        return error == LoadError::none;
    }
};

[[nodiscard]] LoadResult load_executable(
    const macho::Image& image,
    std::span<const std::byte> file_bytes,
    GuestAddressSpace& address_space);

[[nodiscard]] std::string_view load_error_name(LoadError error) noexcept;

} // namespace macosarm
