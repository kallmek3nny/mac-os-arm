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

    mappings_.emplace(base, Mapping{base, size, protection});
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

VmResult GuestAddressSpace::protect(std::uint64_t base, std::uint64_t size, Protection protection) {
    Mapping* mapping = find_exact_mapping(base, size);
    if (mapping == nullptr) {
        return {VmError::not_exact_mapping};
    }
    mapping->protection = protection;
    return {};
}

VmResult GuestAddressSpace::load_bytes(std::uint64_t address, std::span<const std::byte> bytes) {
    if (bytes.empty()) {
        return {};
    }
    if (find_mapping(address, bytes.size()) == nullptr) {
        return {VmError::unmapped};
    }
    return copy_into(address, bytes);
}

VmResult GuestAddressSpace::read(std::uint64_t address, std::span<std::byte> out) const {
    if (out.empty()) {
        return {};
    }
    const Mapping* mapping = find_mapping(address, out.size());
    if (mapping == nullptr) {
        return {VmError::unmapped};
    }
    if (!has_protection(mapping->protection, Protection::read)) {
        return {VmError::protection};
    }
    return copy_out(address, out);
}

VmResult GuestAddressSpace::fetch_code(std::uint64_t address, std::span<std::byte> out) const {
    if (out.empty()) {
        return {};
    }
    const Mapping* mapping = find_mapping(address, out.size());
    if (mapping == nullptr) {
        return {VmError::unmapped};
    }
    if (!has_protection(mapping->protection, Protection::execute)) {
        return {VmError::protection};
    }
    return copy_out(address, out);
}

VmResult GuestAddressSpace::write(std::uint64_t address, std::span<const std::byte> bytes) {
    if (bytes.empty()) {
        return {};
    }
    const Mapping* mapping = find_mapping(address, bytes.size());
    if (mapping == nullptr) {
        return {VmError::unmapped};
    }
    if (!has_protection(mapping->protection, Protection::write)) {
        return {VmError::protection};
    }
    return copy_into(address, bytes);
}

VmResult GuestAddressSpace::probe_write(std::uint64_t address, std::size_t size) const {
    if (size == 0) {
        return {};
    }
    const Mapping* mapping = find_mapping(address, size);
    if (mapping == nullptr) {
        return {VmError::unmapped};
    }
    if (!has_protection(mapping->protection, Protection::write)) {
        return {VmError::protection};
    }
    return {};
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

const Mapping* GuestAddressSpace::find_mapping(std::uint64_t address, std::uint64_t size) const {
    if (size == 0 || range_overflows(address, size)) {
        return nullptr;
    }

    auto next = mappings_.upper_bound(address);
    if (next == mappings_.begin()) {
        return nullptr;
    }
    --next;

    const Mapping& mapping = next->second;
    const std::uint64_t request_end = address + size;
    const std::uint64_t mapping_end = mapping.base + mapping.size;
    if (address < mapping.base || request_end > mapping_end) {
        return nullptr;
    }
    return &mapping;
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
    }
    return "unknown";
}

} // namespace macosarm
