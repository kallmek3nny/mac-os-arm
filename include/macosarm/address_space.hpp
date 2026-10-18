#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <span>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace macosarm {

enum class Protection : std::uint8_t {
    none = 0,
    read = 1u << 0,
    write = 1u << 1,
    execute = 1u << 2,
};

[[nodiscard]] constexpr Protection operator|(Protection lhs, Protection rhs) noexcept {
    return static_cast<Protection>(static_cast<std::uint8_t>(lhs) | static_cast<std::uint8_t>(rhs));
}

[[nodiscard]] constexpr bool has_protection(Protection value, Protection required) noexcept {
    const auto v = static_cast<std::uint8_t>(value);
    const auto r = static_cast<std::uint8_t>(required);
    return (v & r) == r;
}

struct Mapping {
    std::uint64_t base{};
    std::uint64_t size{};
    Protection protection{Protection::none};
    Protection maximum_protection{Protection::none};
};

enum class VmError {
    none,
    zero_size,
    unaligned,
    address_overflow,
    overlap,
    unmapped,
    protection,
    not_exact_mapping,
};

struct VmResult {
    VmError error{VmError::none};

    [[nodiscard]] explicit operator bool() const noexcept {
        return error == VmError::none;
    }
};

class GuestAddressSpace {
public:
    static constexpr std::uint64_t kPageSize = 0x4000;

    [[nodiscard]] VmResult map(std::uint64_t base, std::uint64_t size, Protection protection);
    [[nodiscard]] VmResult map(std::uint64_t base, std::uint64_t size,
                               Protection protection, Protection maximum_protection);
    [[nodiscard]] VmResult unmap(std::uint64_t base, std::uint64_t size);
    // Range removal for Darwin munmap: accepts page-aligned subranges,
    // splits surviving mappings, and treats holes as already unmapped.
    // Unlike unmap(), this is not an exact-mapping operation.
    [[nodiscard]] VmResult unmap_range(std::uint64_t base, std::uint64_t size);
    [[nodiscard]] VmResult protect(std::uint64_t base, std::uint64_t size, Protection protection);
    // Transactional subrange permissions for BSD mprotect; reject holes
    // or requests beyond the original mapping maximum before mutation.
    [[nodiscard]] VmResult protect_range(std::uint64_t base, std::uint64_t size,
                                         Protection protection);

    // Loader-only population path. This intentionally ignores guest write permission
    // but still requires the complete destination range to already be mapped.
    [[nodiscard]] VmResult load_bytes(std::uint64_t address, std::span<const std::byte> bytes);

    [[nodiscard]] VmResult read(std::uint64_t address, std::span<std::byte> out) const;
    // Instruction fetch requires execute permission, not ordinary read permission.
    [[nodiscard]] VmResult fetch_code(std::uint64_t address, std::span<std::byte> out) const;
    [[nodiscard]] VmResult write(std::uint64_t address, std::span<const std::byte> bytes);
    // Side-effect-free permission and range check for kernel-style guest copyout.
    [[nodiscard]] VmResult probe_write(std::uint64_t address, std::size_t size) const;

    [[nodiscard]] std::vector<Mapping> mappings() const;
    [[nodiscard]] std::size_t resident_page_count() const noexcept { return pages_.size(); }

private:
    using Page = std::array<std::byte, kPageSize>;

    // Check every contiguous fragment before a guest operation; protection
    // splits do not turn neighboring virtual pages into holes.
    [[nodiscard]] VmResult validate_range(std::uint64_t address, std::uint64_t size,
                                          Protection required) const noexcept;
    [[nodiscard]] Mapping* find_exact_mapping(std::uint64_t base, std::uint64_t size);
    [[nodiscard]] VmResult copy_out(std::uint64_t address, std::span<std::byte> out) const;
    [[nodiscard]] VmResult copy_into(std::uint64_t address, std::span<const std::byte> bytes);
    [[nodiscard]] Page& page_for_write(std::uint64_t page_base);

    std::map<std::uint64_t, Mapping> mappings_;
    std::unordered_map<std::uint64_t, std::unique_ptr<Page>> pages_;
};

[[nodiscard]] std::string_view vm_error_name(VmError error) noexcept;

} // namespace macosarm
