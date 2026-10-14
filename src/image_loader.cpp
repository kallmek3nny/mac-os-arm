#include "macosarm/image_loader.hpp"

#include <limits>
#include <vector>

namespace macosarm {
namespace {

[[nodiscard]] bool add_overflows(std::uint64_t a, std::uint64_t b) noexcept {
    return b > std::numeric_limits<std::uint64_t>::max() - a;
}

[[nodiscard]] Protection decode_protection(std::uint32_t macho_protection) noexcept {
    Protection result = Protection::none;
    if ((macho_protection & 0x1U) != 0) {
        result = result | Protection::read;
    }
    if ((macho_protection & 0x2U) != 0) {
        result = result | Protection::write;
    }
    if ((macho_protection & 0x4U) != 0) {
        result = result | Protection::execute;
    }
    return result;
}

[[nodiscard]] bool entry_is_executable(const macho::Image& image, std::uint64_t entry) noexcept {
    for (const auto& segment : image.segments) {
        if (!has_protection(decode_protection(segment.initial_protection), Protection::execute)) {
            continue;
        }
        if (segment.vm_size == 0 || add_overflows(segment.vm_address, segment.vm_size)) {
            continue;
        }
        if (entry >= segment.vm_address && entry < segment.vm_address + segment.vm_size) {
            return true;
        }
    }
    return false;
}

} // namespace

LoadResult load_executable(
    const macho::Image& image,
    std::span<const std::byte> file_bytes,
    GuestAddressSpace& address_space) {

    if (!image.has_entry_point) {
        return {{}, LoadError::missing_entry_point, VmError::none};
    }

    const macho::Segment* text = nullptr;
    for (const auto& segment : image.segments) {
        if (segment.name == "__TEXT") {
            text = &segment;
            break;
        }
    }
    if (text == nullptr) {
        return {{}, LoadError::missing_text_segment, VmError::none};
    }
    if (text->vm_address < text->file_offset) {
        return {{}, LoadError::bad_entry_point, VmError::none};
    }

    const std::uint64_t preferred_load_address = text->vm_address - text->file_offset;
    if (add_overflows(preferred_load_address, image.entry_file_offset)) {
        return {{}, LoadError::bad_entry_point, VmError::none};
    }
    const std::uint64_t entry_address = preferred_load_address + image.entry_file_offset;

    for (const auto& segment : image.segments) {
        if (segment.vm_size == 0) {
            if (segment.file_size != 0) {
                return {{}, LoadError::malformed_segment, VmError::none};
            }
            continue;
        }
        if ((segment.vm_address % GuestAddressSpace::kPageSize) != 0 ||
            (segment.vm_size % GuestAddressSpace::kPageSize) != 0) {
            return {{}, LoadError::unaligned_segment, VmError::none};
        }
        if (segment.file_size > segment.vm_size) {
            return {{}, LoadError::malformed_segment, VmError::none};
        }
        if (add_overflows(segment.file_offset, segment.file_size) ||
            segment.file_offset + segment.file_size > file_bytes.size()) {
            return {{}, LoadError::malformed_segment, VmError::none};
        }
    }

    if (!entry_is_executable(image, entry_address)) {
        return {{}, LoadError::bad_entry_point, VmError::none};
    }

    std::vector<Mapping> created;
    created.reserve(image.segments.size());

    auto rollback = [&]() {
        for (auto it = created.rbegin(); it != created.rend(); ++it) {
            (void)address_space.unmap(it->base, it->size);
        }
    };

    for (const auto& segment : image.segments) {
        if (segment.vm_size == 0) {
            continue;
        }

        const Protection protection = decode_protection(segment.initial_protection);
        const VmResult mapped = address_space.map(segment.vm_address, segment.vm_size, protection);
        if (!mapped) {
            rollback();
            return {{}, LoadError::vm_failure, mapped.error};
        }
        created.push_back(Mapping{segment.vm_address, segment.vm_size, protection});

        if (segment.file_size != 0) {
            const auto offset = static_cast<std::size_t>(segment.file_offset);
            const auto size = static_cast<std::size_t>(segment.file_size);
            const VmResult loaded = address_space.load_bytes(
                segment.vm_address,
                file_bytes.subspan(offset, size));
            if (!loaded) {
                rollback();
                return {{}, LoadError::vm_failure, loaded.error};
            }
        }
    }

    return {LoadedImage{preferred_load_address, entry_address, created.size()}, LoadError::none, VmError::none};
}

std::string_view load_error_name(LoadError error) noexcept {
    switch (error) {
    case LoadError::none: return "none";
    case LoadError::missing_entry_point: return "missing_entry_point";
    case LoadError::missing_text_segment: return "missing_text_segment";
    case LoadError::malformed_segment: return "malformed_segment";
    case LoadError::unaligned_segment: return "unaligned_segment";
    case LoadError::bad_entry_point: return "bad_entry_point";
    case LoadError::vm_failure: return "vm_failure";
    }
    return "unknown";
}

} // namespace macosarm
