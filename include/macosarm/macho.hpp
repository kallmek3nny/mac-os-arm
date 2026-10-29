#pragma once

#include <array>
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
constexpr std::uint32_t kLcSymtab = 0x02;
constexpr std::uint32_t kLcDysymtab = 0x0b;
constexpr std::uint32_t kLcLoadDylib = 0x0c;
constexpr std::uint32_t kLcIdDylib = 0x0d;
constexpr std::uint32_t kLcLoadDylinker = 0x0e;
constexpr std::uint32_t kLcLoadWeakDylib = 0x18U | kLcReqDyld;
constexpr std::uint32_t kLcSegment64 = 0x19;
constexpr std::uint32_t kLcUuid = 0x1b;
constexpr std::uint32_t kLcRpath = 0x1cU | kLcReqDyld;
constexpr std::uint32_t kLcCodeSignature = 0x1d;
constexpr std::uint32_t kLcReexportDylib = 0x1fU | kLcReqDyld;
constexpr std::uint32_t kLcLazyLoadDylib = 0x20;
constexpr std::uint32_t kLcDyldInfo = 0x22;
constexpr std::uint32_t kLcDyldInfoOnly = 0x22U | kLcReqDyld;
constexpr std::uint32_t kLcLoadUpwardDylib = 0x23U | kLcReqDyld;
constexpr std::uint32_t kLcVersionMinMacosx = 0x24;
constexpr std::uint32_t kLcVersionMinIphoneos = 0x25;
constexpr std::uint32_t kLcFunctionStarts = 0x26;
constexpr std::uint32_t kLcMain = 0x80000028U;
constexpr std::uint32_t kLcDataInCode = 0x29;
constexpr std::uint32_t kLcSourceVersion = 0x2a;
constexpr std::uint32_t kLcVersionMinTvos = 0x2f;
constexpr std::uint32_t kLcVersionMinWatchos = 0x30;
constexpr std::uint32_t kLcBuildVersion = 0x32;
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

struct SymbolTable {
    std::uint32_t symbol_offset{};
    std::uint32_t symbol_count{};
    std::uint32_t string_offset{};
    std::uint32_t string_size{};
    bool present{};
};

struct DynamicSymbolTable {
    std::uint32_t local_symbol_index{};
    std::uint32_t local_symbol_count{};
    std::uint32_t external_symbol_index{};
    std::uint32_t external_symbol_count{};
    std::uint32_t undefined_symbol_index{};
    std::uint32_t undefined_symbol_count{};
    std::uint32_t indirect_symbol_offset{};
    std::uint32_t indirect_symbol_count{};
    bool present{};
};

struct BuildTool {
    std::uint32_t tool{};
    std::uint32_t version{};
};

struct BuildVersion {
    std::uint32_t platform{};
    std::uint32_t minimum_os{};
    std::uint32_t sdk{};
    std::vector<BuildTool> tools;
};

// One LC_VERSION_MIN_MACOSX, LC_VERSION_MIN_IPHONEOS, LC_VERSION_MIN_TVOS or LC_VERSION_MIN_WATCHOS command, in
// load-command order. command keeps the raw load command, which names the platform. sdk keeps the raw field: the
// original LC_VERSION_MIN_MACOSX had no sdk field, so old macOS images leave it 0.
struct VersionMin {
    std::uint32_t command{};
    std::uint32_t version{};
    std::uint32_t sdk{};
};

// One LC_DYLD_INFO or LC_DYLD_INFO_ONLY command: the rebase, bind, weak-bind and lazy-bind opcode streams and the
// export trie that predate LC_DYLD_CHAINED_FIXUPS and LC_DYLD_EXPORTS_TRIE. command keeps the raw load command, so
// LC_DYLD_INFO_ONLY stays distinguishable. Each stream keeps its raw file offset and size and is present only when
// its size is nonzero, matching the streams dyld walks.
struct DyldInfo {
    std::uint32_t command{};
    FileRange rebase;
    FileRange bind;
    FileRange weak_bind;
    FileRange lazy_bind;
    FileRange export_trie;
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
    DyldInfo dyld_info;
    std::vector<Segment> segments;
    SymbolTable symbol_table;
    DynamicSymbolTable dynamic_symbol_table;
    std::array<std::uint8_t, 16> uuid{};
    bool has_uuid{};
    std::vector<BuildVersion> build_versions;
    std::vector<VersionMin> version_mins;
    std::uint64_t source_version{};
    bool has_source_version{};
    FileRange code_signature;
    FileRange function_starts;
    FileRange data_in_code;
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
    malformed_symbol_table,
    malformed_dynamic_symbol_table,
    malformed_uuid,
    malformed_build_version,
    malformed_source_version,
    duplicate_load_command,
    malformed_version_min,
    incompatible_platforms,
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
