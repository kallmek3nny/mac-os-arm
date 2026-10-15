#pragma once

#include "macosarm/macho.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace macosarm::dyld {

constexpr std::uint64_t kExportKindMask = 0x03;
constexpr std::uint64_t kExportKindRegular = 0x00;
constexpr std::uint64_t kExportKindThreadLocal = 0x01;
constexpr std::uint64_t kExportKindAbsolute = 0x02;
constexpr std::uint64_t kExportWeakDefinition = 0x04;
constexpr std::uint64_t kExportReexport = 0x08;
constexpr std::uint64_t kExportStubAndResolver = 0x10;
constexpr std::uint64_t kExportFunctionVariant = 0x20;
constexpr std::uint64_t kExportKnownFlagsMask = 0x3f;

constexpr std::size_t kMaxExportNameLength = 4096;
constexpr std::size_t kMaxExportTrieDepth = 512;

enum class ExportKind {
    regular,
    thread_local,
    absolute,
    reexport,
    stub_and_resolver,
    function_variant,
};

struct ExportSymbol {
    std::string name;
    ExportKind kind{ExportKind::regular};
    std::uint64_t flags{};
    std::uint64_t value{};
    std::uint64_t other{};
    std::string import_name;
    bool weak_definition{};
};

enum class ExportTrieError {
    none,
    range_out_of_bounds,
    malformed_uleb,
    terminal_out_of_bounds,
    missing_children_count,
    child_name_unterminated,
    empty_child_name,
    child_offset_zero,
    child_offset_out_of_bounds,
    cycle,
    too_deep,
    symbol_name_too_long,
    unknown_flags,
    unsupported_kind,
    incompatible_flags,
    malformed_terminal,
    duplicate_symbol,
};

struct ExportTrieResult {
    std::vector<ExportSymbol> symbols;
    ExportTrieError error{ExportTrieError::none};
    std::size_t error_offset{};

    [[nodiscard]] explicit operator bool() const noexcept {
        return error == ExportTrieError::none;
    }
};

// Decode a raw LC_DYLD_EXPORTS_TRIE payload.
[[nodiscard]] ExportTrieResult parse_exports_trie(std::span<const std::byte> trie_bytes);

// Decode the range recorded in a parsed Mach-O image. An absent or zero-sized
// exports trie is valid and produces an empty symbol set.
[[nodiscard]] ExportTrieResult parse_image_exports(
    const macho::Image& image,
    std::span<const std::byte> file_bytes);

[[nodiscard]] std::string_view export_kind_name(ExportKind kind) noexcept;
[[nodiscard]] std::string_view export_trie_error_name(ExportTrieError error) noexcept;

} // namespace macosarm::dyld
