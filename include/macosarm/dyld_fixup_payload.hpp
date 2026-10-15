#pragma once

#include "macosarm/macho.hpp"

#include <cstddef>
#include <span>
#include <string_view>
#include <vector>

namespace macosarm::dyld {

constexpr std::size_t kDefaultMaxChainedFixupPayloadBytes = 64U * 1024U * 1024U;

enum class ChainedFixupPayloadError {
    none,
    payload_limit,
    range_out_of_bounds,
};

struct ChainedFixupPayloadResult {
    std::vector<std::byte> payload;
    ChainedFixupPayloadError error{ChainedFixupPayloadError::none};

    [[nodiscard]] explicit operator bool() const noexcept {
        return error == ChainedFixupPayloadError::none;
    }
};

[[nodiscard]] inline ChainedFixupPayloadResult copy_image_chained_fixup_payload(
    const macho::Image& image,
    std::span<const std::byte> file_bytes,
    std::size_t max_payload_bytes = kDefaultMaxChainedFixupPayloadBytes) {
    ChainedFixupPayloadResult result;
    const macho::FileRange& range = image.chained_fixups;
    if (!range.present || range.size == 0) {
        return result;
    }

    const std::size_t offset = static_cast<std::size_t>(range.offset);
    const std::size_t size = static_cast<std::size_t>(range.size);
    if (size > max_payload_bytes) {
        result.error = ChainedFixupPayloadError::payload_limit;
        return result;
    }
    if (offset > file_bytes.size() || size > file_bytes.size() - offset) {
        result.error = ChainedFixupPayloadError::range_out_of_bounds;
        return result;
    }

    result.payload.assign(
        file_bytes.begin() + static_cast<std::ptrdiff_t>(offset),
        file_bytes.begin() + static_cast<std::ptrdiff_t>(offset + size));
    return result;
}

[[nodiscard]] inline std::string_view chained_fixup_payload_error_name(
    ChainedFixupPayloadError error) noexcept {
    switch (error) {
    case ChainedFixupPayloadError::none: return "none";
    case ChainedFixupPayloadError::payload_limit: return "payload_limit";
    case ChainedFixupPayloadError::range_out_of_bounds: return "range_out_of_bounds";
    }
    return "unknown";
}

} // namespace macosarm::dyld
