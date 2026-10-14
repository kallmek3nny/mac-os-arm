#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace macosarm::macho {

constexpr std::uint32_t kMhMagic64 = 0xfeedfacfU;
constexpr std::int32_t kCpuTypeArm64 = 0x0100000c;
constexpr std::int32_t kCpuSubtypeArm64All = 0;
constexpr std::int32_t kCpuSubtypeArm64e = 2;
constexpr std::uint32_t kMhExecute = 2;
constexpr std::uint32_t kLcSegment64 = 0x19;
constexpr std::uint32_t kLcMain = 0x80000028U;

struct Segment {
    std::string name;
    std::uint64_t vm_address{};
    std::uint64_t vm_size{};
    std::uint64_t file_offset{};
    std::uint64_t file_size{};
    std::uint32_t max_protection{};
    std::uint32_t initial_protection{};
};

struct Image {
    std::int32_t cpu_type{};
    std::int32_t cpu_subtype{};
    std::uint32_t file_type{};
    std::uint32_t flags{};
    std::uint64_t entry_file_offset{};
    bool has_entry_point{};
    std::vector<Segment> segments;
};

enum class ErrorCode {
    none,
    truncated,
    bad_magic,
    unsupported_cpu,
    unsupported_file_type,
    malformed_load_commands,
    malformed_segment,
    duplicate_entry_point,
};

struct ParseResult {
    Image image;
    ErrorCode error{ErrorCode::none};
    std::string message;

    [[nodiscard]] explicit operator bool() const noexcept {
        return error == ErrorCode::none;
    }
};

[[nodiscard]] ParseResult parse(std::span<const std::byte> bytes);
[[nodiscard]] std::string_view error_name(ErrorCode error) noexcept;

} // namespace macosarm::macho
