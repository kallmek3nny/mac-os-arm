#pragma once

#include "macosarm/dyld_graph.hpp"

#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <string_view>

namespace macosarm::dyld {

enum class ResolvedSymbolKind {
    image_relative,
    absolute,
};

struct ResolvedSymbol {
    std::string name;
    std::size_t image_index{std::numeric_limits<std::size_t>::max()};
    ResolvedSymbolKind kind{ResolvedSymbolKind::image_relative};
    std::uint64_t address{};
    bool weak_definition{};
};

enum class SymbolResolutionStatus {
    found,
    not_found,
    error,
};

enum class SymbolResolutionError {
    none,
    bad_image_index,
    empty_symbol_name,
    invalid_reexport_ordinal,
    unavailable_reexport,
    address_overflow,
    address_out_of_image,
    unsupported_thread_local,
    unsupported_stub_and_resolver,
    unsupported_function_variant,
    visit_limit,
};

struct SymbolResolutionConfig {
    // Bounds unique (image, symbol-name) states visited while following explicit
    // and LC_REEXPORT_DYLIB edges. This also terminates re-export cycles.
    std::size_t max_visits{1024};
};

struct SymbolResolutionResult {
    SymbolResolutionStatus status{SymbolResolutionStatus::not_found};
    SymbolResolutionError error{SymbolResolutionError::none};
    ResolvedSymbol symbol;

    [[nodiscard]] explicit operator bool() const noexcept {
        return status == SymbolResolutionStatus::found;
    }
};

// Resolve one export from a specific loaded image. The search first checks the
// image's own exports trie, follows explicit EXPORT_SYMBOL_FLAGS_REEXPORT
// ordinals, then searches dependencies declared with LC_REEXPORT_DYLIB.
//
// Ordinary exports currently use LoadedImage::preferred_load_address as the
// mapped image base because phase 17 still maps images at their preferred VM
// addresses. Absolute exports are returned verbatim. TLS, resolver, and
// function-variant exports are rejected explicitly until their runtime
// semantics are implemented rather than being flattened into fake addresses.
[[nodiscard]] SymbolResolutionResult resolve_symbol(
    const LoadedImageGraph& graph,
    std::size_t image_index,
    std::string_view symbol_name,
    bool weak_import = false,
    const SymbolResolutionConfig& config = {});

[[nodiscard]] std::string_view resolved_symbol_kind_name(ResolvedSymbolKind kind) noexcept;
[[nodiscard]] std::string_view symbol_resolution_status_name(SymbolResolutionStatus status) noexcept;
[[nodiscard]] std::string_view symbol_resolution_error_name(SymbolResolutionError error) noexcept;

} // namespace macosarm::dyld
