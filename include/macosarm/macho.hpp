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
constexpr std::uint32_t kMhDylib = 6;
constexpr std::uint32_t kMhDylinker = 7;
constexpr std::uint32_t kLcReqDyld = 0x80000000U;
constexpr std::uint32_t kLcLoadDylib = 0x0c;
constexpr std::uint32_t kLcIdDylib = 0x0d;
constexpr std::uint32_t kLcLoadDylinker = 0x0e;
constexpr std::uint32_t kLcLoadWeakDylib = 0x18U | kLcReqDyld;
constexpr std::uint32_t kLcSegment64 = 0x19;
constexpr std::uint32_t kLcRpath = 0x1cU | kLcReqDyld;
constexpr std::uint32_t kLcReexportDylib = 0x1fU | kLcReqDyld;
constexpr std::uint32_t kLcLazyLoadDylib = 0x20;
constexpr std::uint32_t kLcLoadUpwardDylib = 0x23U | kLcReqDyld;
constexpr std::uint32_t kLcMain = 0x80000028U;
constexpr std::uint32_t kLcDyldExportsTrie = 0x33U | kLcReqDyld;
constexpr std::uint32_t kLcDyldChainedFixups = 0x34U | kLcReqDyld;

struct Segment {
    std::string name;
    std::uint64_t vm_address{};
    std::uint64_t vm_size{};
    std::uint64_t file_offset{};
    std::uint64_t file_size{};
    std::uint32_t max_protection{};
    std::uint32_t initial_protection{};
};

enum class DylibLoadKind {
    normal,
    weak,
    reexport,
    lazy,
    upward,
};

struct DylibDependency {
    std::string path;
    DylibLoadKind kind{DylibLoadKind::normal};
    std::uint32_t timestamp{};
    std::uint32_t current_version{};
    std::uint32_t compatibility_version{};
};

struct DylibIdentity {
    std::string install_name;
    std::uint32_t timestamp{};
    std::uint32_t current_version{};
    std::uint32_t compatibility_version{};
};

struct FileRange {
    std::uint32_t offset{};
    std::uint32_t size{};
    bool present{};
};

struct Image {
    std::int32_t cpu_type{};
    std::int32_t cpu_subtype{};
    std::uint32_t file_type{};
    std::uint32_t flags{};
    std::uint64_t entry_file_offset{};
    bool has_entry_point{};
    std::string dynamic_linker;
    bool has_dynamic_linker{};
    DylibIdentity dylib_identity;
    bool has_dylib_identity{};
    std::vector<std::string> runpaths;
    std::vector<DylibDependency> dependencies;
    FileRange exports_trie;
    FileRange chained_fixups;
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
    malformed_dynamic_linker,
    malformed_dylib,
    malformed_dylib_identity,
    malformed_runpath,
    malformed_linkedit_data,
    missing_dylib_identity,
    duplicate_entry_point,
    duplicate_dynamic_linker,
    duplicate_dylib_identity,
    duplicate_exports_trie,
    duplicate_chained_fixups,
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
[[nodiscard]] std::string_view dylib_load_kind_name(DylibLoadKind kind) noexcept;

} // namespace macosarm::macho
