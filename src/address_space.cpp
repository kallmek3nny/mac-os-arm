#include "macosarm/address_space.hpp"

#include <algorithm>
#include <limits>

namespace macosarm {
namespace {

[[nodiscard]] bool range_overflows(std::uint64_t base, std::uint64_t size) noexcept {
    return size > std::numeric_limits<std::uint64_t>::max() - base;
}

[[nodiscard]] std::uint64_t page_base(std::uint64_t address) noexcept {
    return address & ~(GuestAddressSpace::kPageSize - 1);
}

} // namespace

VmResult GuestAddressSpace::map(std::uint64_t base, std::uint64_t size, Protection protection) {
    return map(base, size, protection, protection);
}

VmResult GuestAddressSpace::map(std::uint64_t base, std::uint64_t size,
                                Protection protection, Protection maximum_protection) {
    if (size == 0) {
        return {VmError::zero_size};
    }
    if ((base % kPageSize) != 0 || (size % kPageSize) != 0) {
        return {VmError::unaligned};
    }
    if (range_overflows(base, size)) {
        return {VmError::address_overflow};
    }

    const std::uint64_t end = base + size;
    auto next = mappings_.lower_bound(base);
    if (next != mappings_.end() && next->second.base < end) {
        return {VmError::overlap};
    }
    if (next != mappings_.begin()) {
        const auto previous = std::prev(next);
        if (previous->second.base + previous->second.size > base) {
            return {VmError::overlap};
        }
    }

    if (!has_protection(maximum_protection, protection)) {
        return {VmError::protection};
    }
    if (next_allocation_id_ == std::numeric_limits<std::uint64_t>::max()) {
        return {VmError::resource_exhausted};
    }
    mappings_.emplace(base, Mapping{
        base, size, protection, maximum_protection, next_allocation_id_});
    ++next_allocation_id_;
    return {};
}

VmResult GuestAddressSpace::unmap(std::uint64_t base, std::uint64_t size) {
    Mapping* mapping = find_exact_mapping(base, size);
    if (mapping == nullptr) {
        return {VmError::not_exact_mapping};
    }

    const std::uint64_t end = base + size;
    for (auto it = pages_.begin(); it != pages_.end();) {
        if (it->first >= base && it->first < end) {
            it = pages_.erase(it);
        } else {
            ++it;
        }
    }
    mappings_.erase(base);
    return {};
}

VmResult GuestAddressSpace::unmap_range(std::uint64_t base, std::uint64_t size) {
    // Validate the entire range before changing any mappings or resident
    // pages. BSD munmap performs page rounding before reaching this API.
    if (size == 0) {
        return {VmError::zero_size};
    }
    if ((base % kPageSize) != 0 || (size % kPageSize) != 0) {
        return {VmError::unaligned};
    }
    if (range_overflows(base, size)) {
        return {VmError::address_overflow};
    }

    const std::uint64_t end = base + size;
    auto it = mappings_.lower_bound(base);
    if (it != mappings_.begin()) {
        --it; // The preceding mapping can straddle the removal start.
    }

    while (it != mappings_.end() && it->second.base < end) {
        const Mapping current = it->second;
        const std::uint64_t current_end = current.base + current.size;
        if (current_end <= base) {
            ++it;
            continue;
        }

        // map::erase invalidates only the erased iterator. Untouched left and
        // right fragments retain their existing protection and resident data.
        it = mappings_.erase(it);
        if (current.base < base) {
            mappings_.emplace(
                current.base,
                Mapping{current.base, base - current.base,
                        current.protection, current.maximum_protection,
                        current.allocation_id});
        }
        if (current_end > end) {
            mappings_.emplace(
                end,
                Mapping{end, current_end - end,
                        current.protection, current.maximum_protection,
                        current.allocation_id});
            break;
        }
    }

    for (auto page = pages_.begin(); page != pages_.end();) {
        if (page->first >= base && page->first < end) {
            page = pages_.erase(page);
        } else {
            ++page;
        }
    }
    // vm_map_remove(..., VM_MAP_REMOVE_NO_FLAGS) tolerates holes.
    return {};
}

std::optional<std::uint64_t> GuestAddressSpace::allocation_id_at(
    std::uint64_t address) const noexcept {
    auto it = mappings_.upper_bound(address);
    if (it == mappings_.begin()) return std::nullopt;
    --it;
    if (address >= it->second.base + it->second.size) return std::nullopt;
    return it->second.allocation_id;
}

VmResult GuestAddressSpace::unmap_allocation(
    std::uint64_t base, std::uint64_t size, std::uint64_t allocation_id) {
    if (size == 0) return {VmError::zero_size};
    if ((base % kPageSize) != 0 || (size % kPageSize) != 0) {
        return {VmError::unaligned};
    }
    if (range_overflows(base, size)) return {VmError::address_overflow};
    if (allocation_id == 0) return {VmError::not_exact_mapping};

    const std::uint64_t end = base + size;
    std::uint64_t cursor = base;
    auto it = mappings_.upper_bound(base);
    if (it != mappings_.begin()) --it;
    while (cursor < end) {
        while (it != mappings_.end() &&
               it->second.base + it->second.size <= cursor) ++it;
        if (it == mappings_.end() || it->second.base > cursor ||
            it->second.allocation_id != allocation_id) {
            return {VmError::not_exact_mapping};
        }
        cursor = std::min(end, it->second.base + it->second.size);
        ++it;
    }
    return unmap_range(base, size);
}

VmResult GuestAddressSpace::protect(std::uint64_t base, std::uint64_t size, Protection protection) {
    Mapping* mapping = find_exact_mapping(base, size);
    if (mapping == nullptr) {
        return {VmError::not_exact_mapping};
    }
    if (!has_protection(mapping->maximum_protection, protection)) {
        return {VmError::protection};
    }
    mapping->protection = protection;
    return {};
}

VmResult GuestAddressSpace::protect_range(
    std::uint64_t base, std::uint64_t size, Protection protection) {

    if (size == 0) {
        return {VmError::zero_size};
    }
    if ((base % kPageSize) != 0 || (size % kPageSize) != 0) {
        return {VmError::unaligned};
    }
    if (range_overflows(base, size)) {
        return {VmError::address_overflow};
    }
    const std::uint64_t end = base + size;

    // Validate complete coverage and maximum rights before changing any
    // existing mappings or resident guest pages. This includes gaps between
    // individually mapped regions.
    std::uint64_t cursor = base;
    auto it = mappings_.upper_bound(base);
    if (it != mappings_.begin()) {
        --it;
    }
    while (cursor < end) {
        while (it != mappings_.end() &&
               it->second.base + it->second.size <= cursor) {
            ++it;
        }
        if (it == mappings_.end() || it->second.base > cursor) {
            return {VmError::unmapped};
        }
        if (!has_protection(it->second.maximum_protection, protection)) {
            return {VmError::protection};
        }
        cursor = std::min(end, it->second.base + it->second.size);
        ++it;
    }

    // Copy/split into a temporary map, then publish atomically: even an
    // allocation exception cannot leave partially changed VM protections.
    auto updated = mappings_;
    for (const auto& [key, mapping] : mappings_) {
        const std::uint64_t mapping_end = mapping.base + mapping.size;
        if (mapping_end <= base || mapping.base >= end) {
            continue;
        }
        const std::uint64_t change_start = std::max(base, mapping.base);
        const std::uint64_t change_end = std::min(end, mapping_end);
        updated.erase(key);
        if (mapping.base < change_start) {
            updated.emplace(mapping.base, Mapping{
                mapping.base, change_start - mapping.base,
                mapping.protection, mapping.maximum_protection,
                mapping.allocation_id});
        }
        updated.emplace(change_start, Mapping{
            change_start, change_end - change_start,
            protection, mapping.maximum_protection,
            mapping.allocation_id});
        if (change_end < mapping_end) {
            updated.emplace(change_end, Mapping{
                change_end, mapping_end - change_end,
                mapping.protection, mapping.maximum_protection,
                mapping.allocation_id});
        }
    }
    mappings_.swap(updated);
    return {};
}


VmResult GuestAddressSpace::restrict_maximum_protection_range(
    std::uint64_t base, std::uint64_t size, Protection maximum_protection) {
    if (size == 0) return {VmError::zero_size};
    if ((base % kPageSize) != 0 || (size % kPageSize) != 0) {
        return {VmError::unaligned};
    }
    if (range_overflows(base, size)) return {VmError::address_overflow};

    // Reject holes, rights escalation, and restrictions that would revoke
    // currently active rights before making any mapping changes.
    const std::uint64_t end = base + size;
    std::uint64_t cursor = base;
    auto it = mappings_.upper_bound(base);
    if (it != mappings_.begin()) --it;
    while (cursor < end) {
        while (it != mappings_.end() &&
               it->second.base + it->second.size <= cursor) ++it;
        if (it == mappings_.end() || it->second.base > cursor) {
            return {VmError::unmapped};
        }
        if (!has_protection(it->second.maximum_protection, maximum_protection) ||
            !has_protection(maximum_protection, it->second.protection)) {
            return {VmError::protection};
        }
        cursor = std::min(end, it->second.base + it->second.size);
        ++it;
    }

    auto updated = mappings_;
    for (const auto& [key, mapping] : mappings_) {
        const std::uint64_t mapping_end = mapping.base + mapping.size;
        if (mapping_end <= base || mapping.base >= end) continue;
        const std::uint64_t first = std::max(base, mapping.base);
        const std::uint64_t last = std::min(end, mapping_end);
        updated.erase(key);
        if (mapping.base < first) {
            updated.emplace(mapping.base, Mapping{
                mapping.base, first - mapping.base, mapping.protection,
                mapping.maximum_protection, mapping.allocation_id});
        }
        updated.emplace(first, Mapping{
            first, last - first, mapping.protection, maximum_protection,
            mapping.allocation_id});
        if (last < mapping_end) {
            updated.emplace(last, Mapping{
                last, mapping_end - last, mapping.protection,
                mapping.maximum_protection, mapping.allocation_id});
        }
    }
    mappings_.swap(updated);
    return {};
}

VmResult GuestAddressSpace::load_bytes(std::uint64_t address, std::span<const std::byte> bytes) {
    if (bytes.empty()) {
        return {};
    }
    const VmResult validation = validate_range(address, bytes.size(), Protection::none);
    if (!validation) {
        return validation;
    }
    return copy_into(address, bytes);
}

VmResult GuestAddressSpace::read(std::uint64_t address, std::span<std::byte> out) const {
    if (out.empty()) {
        return {};
    }
    const VmResult validation = validate_range(address, out.size(), Protection::read);
    if (!validation) {
        return validation;
    }
    return copy_out(address, out);
}

VmResult GuestAddressSpace::fetch_code(std::uint64_t address, std::span<std::byte> out) const {
    if (out.empty()) {
        return {};
    }
    const VmResult validation = validate_range(address, out.size(), Protection::execute);
    if (!validation) {
        return validation;
    }
    return copy_out(address, out);
}

VmResult GuestAddressSpace::write(std::uint64_t address, std::span<const std::byte> bytes) {
    if (bytes.empty()) {
        return {};
    }
    const VmResult validation = validate_range(address, bytes.size(), Protection::write);
    if (!validation) {
        return validation;
    }
    return copy_into(address, bytes);
}

VmResult GuestAddressSpace::probe_write(std::uint64_t address, std::size_t size) const {
    if (size == 0) {
        return {};
    }
    return validate_range(address, size, Protection::write);
}

std::vector<Mapping> GuestAddressSpace::mappings() const {
    std::vector<Mapping> result;
    result.reserve(mappings_.size());
    for (const auto& [base, mapping] : mappings_) {
        (void)base;
        result.push_back(mapping);
    }
    return result;
}

VmResult GuestAddressSpace::validate_range(
    std::uint64_t address, std::uint64_t size, Protection required) const noexcept {
    if (size == 0) {
        return {};
    }
    if (range_overflows(address, size)) {
        return {VmError::unmapped};
    }

    const std::uint64_t end = address + size;
    std::uint64_t cursor = address;
    auto it = mappings_.upper_bound(address);
    if (it != mappings_.begin()) {
        --it;
    }

    // A contiguous VM span may contain several mapping records after a
    // page-granular mprotect or an adjacent independent map. Validate the
    // entire span before copying any data, including mixed-rights pages.
    while (cursor < end) {
        while (it != mappings_.end() &&
               it->second.base + it->second.size <= cursor) {
            ++it;
        }
        if (it == mappings_.end() || it->second.base > cursor) {
            return {VmError::unmapped};
        }
        if (!has_protection(it->second.protection, required)) {
            return {VmError::protection};
        }
        cursor = std::min(end, it->second.base + it->second.size);
        ++it;
    }
    return {};
}

Mapping* GuestAddressSpace::find_exact_mapping(std::uint64_t base, std::uint64_t size) {
    const auto it = mappings_.find(base);
    if (it == mappings_.end() || it->second.size != size) {
        return nullptr;
    }
    return &it->second;
}

VmResult GuestAddressSpace::copy_out(std::uint64_t address, std::span<std::byte> out) const {
    std::size_t copied = 0;
    while (copied < out.size()) {
        const std::uint64_t current = address + copied;
        const std::uint64_t current_page = page_base(current);
        const std::size_t page_offset = static_cast<std::size_t>(current - current_page);
        const std::size_t chunk = std::min<std::size_t>(kPageSize - page_offset, out.size() - copied);

        const auto page = pages_.find(current_page);
        if (page == pages_.end()) {
            std::fill_n(out.data() + copied, chunk, std::byte{0});
        } else {
            std::copy_n(page->second->data() + page_offset, chunk, out.data() + copied);
        }
        copied += chunk;
    }
    return {};
}

VmResult GuestAddressSpace::copy_into(std::uint64_t address, std::span<const std::byte> bytes) {
    std::size_t copied = 0;
    while (copied < bytes.size()) {
        const std::uint64_t current = address + copied;
        const std::uint64_t current_page = page_base(current);
        const std::size_t page_offset = static_cast<std::size_t>(current - current_page);
        const std::size_t chunk = std::min<std::size_t>(kPageSize - page_offset, bytes.size() - copied);

        Page& page = page_for_write(current_page);
        std::copy_n(bytes.data() + copied, chunk, page.data() + page_offset);
        copied += chunk;
    }
    return {};
}

GuestAddressSpace::Page& GuestAddressSpace::page_for_write(std::uint64_t base) {
    auto [it, inserted] = pages_.try_emplace(base);
    if (inserted) {
        it->second = std::make_unique<Page>();
        it->second->fill(std::byte{0});
    }
    return *it->second;
}

std::string_view vm_error_name(VmError error) noexcept {
    switch (error) {
    case VmError::none: return "none";
    case VmError::zero_size: return "zero_size";
    case VmError::unaligned: return "unaligned";
    case VmError::address_overflow: return "address_overflow";
    case VmError::overlap: return "overlap";
    case VmError::unmapped: return "unmapped";
    case VmError::protection: return "protection";
    case VmError::not_exact_mapping: return "not_exact_mapping";
    case VmError::resource_exhausted: return "resource_exhausted";
    }
    return "unknown";
}

} // namespace macosarm
