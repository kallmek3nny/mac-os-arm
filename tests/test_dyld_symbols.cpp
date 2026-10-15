#include "macosarm/dyld_symbols.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <string>
#include <utility>

namespace {

int failures = 0;

void expect(bool condition, const std::string& label) {
    if (!condition) {
        std::cerr << "FAIL: " << label << '\n';
        ++failures;
    }
}

macosarm::dyld::GraphImage image(
    std::string path,
    std::uint64_t base,
    std::uint64_t size = 0x4000) {
    macosarm::dyld::GraphImage result;
    result.path = std::move(path);
    result.mapping.preferred_load_address = base;
    result.image.segments.push_back(
        macosarm::macho::Segment{"__TEXT", base, size, 0, 0, 5, 5});
    return result;
}

macosarm::dyld::ExportSymbol export_symbol(
    std::string name,
    macosarm::dyld::ExportKind kind,
    std::uint64_t value,
    std::string import_name = {},
    bool weak_definition = false) {
    macosarm::dyld::ExportSymbol result;
    result.name = std::move(name);
    result.kind = kind;
    result.value = value;
    result.import_name = std::move(import_name);
    result.weak_definition = weak_definition;
    return result;
}

macosarm::dyld::GraphDependency loaded_dependency(
    std::size_t image_index,
    macosarm::macho::DylibLoadKind kind = macosarm::macho::DylibLoadKind::normal) {
    macosarm::dyld::GraphDependency result;
    result.dependency.kind = kind;
    result.dependency.path = "/dep.dylib";
    result.state = macosarm::dyld::GraphDependencyState::loaded;
    result.image_index = image_index;
    result.resolved_path = "/dep.dylib";
    return result;
}

macosarm::dyld::GraphDependency missing_dependency() {
    macosarm::dyld::GraphDependency result;
    result.dependency.kind = macosarm::macho::DylibLoadKind::weak;
    result.dependency.path = "/missing.dylib";
    result.state = macosarm::dyld::GraphDependencyState::missing_weak;
    return result;
}

macosarm::dyld::LoadedImageGraph fixture_graph() {
    using macosarm::dyld::ExportKind;
    using macosarm::macho::DylibLoadKind;

    macosarm::dyld::LoadedImageGraph graph;
    graph.images.push_back(image("/root", 0x100000000ULL));
    graph.images.push_back(image("/libA.dylib", 0x200000000ULL));
    graph.images.push_back(image("/libCycle.dylib", 0x300000000ULL));
    graph.images.push_back(image("/libFallback.dylib", 0x400000000ULL));

    graph.images[1].exports.push_back(
        export_symbol("_target", ExportKind::regular, 0x80, {}, true));
    graph.images[1].exports.push_back(
        export_symbol("_oob", ExportKind::regular, 0x8000));

    graph.images[3].exports.push_back(
        export_symbol("_fallback", ExportKind::regular, 0x120));

    graph.images[0].dependencies.push_back(loaded_dependency(1));
    graph.images[0].dependencies.push_back(loaded_dependency(2, DylibLoadKind::reexport));
    graph.images[0].dependencies.push_back(loaded_dependency(3, DylibLoadKind::reexport));
    graph.images[0].dependencies.push_back(missing_dependency());
    graph.images[2].dependencies.push_back(loaded_dependency(0, DylibLoadKind::reexport));

    graph.images[0].exports.push_back(
        export_symbol("_regular", ExportKind::regular, 0x100, {}, true));
    graph.images[0].exports.push_back(
        export_symbol("_absolute", ExportKind::absolute, 0xfeedfaceULL));
    graph.images[0].exports.push_back(
        export_symbol("_alias", ExportKind::reexport, 1, "_target"));
    graph.images[0].exports.push_back(
        export_symbol("_same", ExportKind::reexport, 1, "_target"));
    graph.images[0].exports.push_back(
        export_symbol("_bad_zero", ExportKind::reexport, 0));
    graph.images[0].exports.push_back(
        export_symbol("_bad_large", ExportKind::reexport, 99));
    graph.images[0].exports.push_back(
        export_symbol("_weak_missing", ExportKind::reexport, 4, "_target"));
    graph.images[0].exports.push_back(
        export_symbol("_tls", ExportKind::thread_local_storage, 0x20));
    graph.images[0].exports.push_back(
        export_symbol("_stub", ExportKind::stub_and_resolver, 0x200));
    graph.images[0].exports.push_back(
        export_symbol("_variant", ExportKind::function_variant, 0x300));

    return graph;
}

} // namespace

int main() {
    using macosarm::dyld::ResolvedSymbolKind;
    using macosarm::dyld::SymbolResolutionConfig;
    using macosarm::dyld::SymbolResolutionError;
    using macosarm::dyld::SymbolResolutionStatus;

    {
        const auto graph = fixture_graph();
        const auto result = macosarm::dyld::resolve_symbol(graph, 0, "_regular");
        expect(static_cast<bool>(result), "direct regular export resolves");
        expect(result.symbol.image_index == 0 &&
                   result.symbol.kind == ResolvedSymbolKind::image_relative &&
                   result.symbol.address == 0x100000100ULL &&
                   result.symbol.weak_definition,
               "regular export returns mapped guest address and weak-definition bit");
    }

    {
        const auto graph = fixture_graph();
        const auto result = macosarm::dyld::resolve_symbol(graph, 0, "_absolute");
        expect(static_cast<bool>(result), "absolute export resolves");
        expect(result.symbol.kind == ResolvedSymbolKind::absolute &&
                   result.symbol.address == 0xfeedfaceULL,
               "absolute export is not rebased");
    }

    {
        const auto graph = fixture_graph();
        const auto result = macosarm::dyld::resolve_symbol(graph, 0, "_alias");
        expect(static_cast<bool>(result), "explicit reexport resolves");
        expect(result.symbol.image_index == 1 && result.symbol.name == "_target" &&
                   result.symbol.address == 0x200000080ULL &&
                   result.symbol.weak_definition,
               "explicit reexport follows one-based ordinal and import rename");
    }

    {
        const auto graph = fixture_graph();
        const auto result = macosarm::dyld::resolve_symbol(graph, 0, "_fallback");
        expect(static_cast<bool>(result), "LC_REEXPORT_DYLIB fallback resolves");
        expect(result.symbol.image_index == 3 && result.symbol.address == 0x400000120ULL,
               "reexport fallback skips cycle and reaches later dependency");
    }

    {
        const auto graph = fixture_graph();
        const auto result = macosarm::dyld::resolve_symbol(graph, 0, "_missing");
        expect(result.status == SymbolResolutionStatus::not_found &&
                   result.error == SymbolResolutionError::none,
               "missing symbol is distinct from resolver error");
    }

    {
        const auto graph = fixture_graph();
        const auto zero = macosarm::dyld::resolve_symbol(graph, 0, "_bad_zero");
        expect(zero.status == SymbolResolutionStatus::error &&
                   zero.error == SymbolResolutionError::invalid_reexport_ordinal,
               "zero reexport ordinal rejected");
        const auto large = macosarm::dyld::resolve_symbol(graph, 0, "_bad_large");
        expect(large.error == SymbolResolutionError::invalid_reexport_ordinal,
               "out-of-range reexport ordinal rejected");
    }

    {
        const auto graph = fixture_graph();
        const auto strong = macosarm::dyld::resolve_symbol(graph, 0, "_weak_missing", false);
        expect(strong.status == SymbolResolutionStatus::error &&
                   strong.error == SymbolResolutionError::unavailable_reexport,
               "strong lookup does not fake unavailable reexport target");
        const auto weak = macosarm::dyld::resolve_symbol(graph, 0, "_weak_missing", true);
        expect(weak.status == SymbolResolutionStatus::not_found &&
                   weak.error == SymbolResolutionError::none,
               "weak lookup tolerates unavailable reexport target");
    }

    {
        const auto graph = fixture_graph();
        expect(macosarm::dyld::resolve_symbol(graph, 0, "_tls").error ==
                   SymbolResolutionError::unsupported_thread_local,
               "TLS export is rejected until TLV runtime exists");
        expect(macosarm::dyld::resolve_symbol(graph, 0, "_stub").error ==
                   SymbolResolutionError::unsupported_stub_and_resolver,
               "stub/resolver export is rejected until resolver execution exists");
        expect(macosarm::dyld::resolve_symbol(graph, 0, "_variant").error ==
                   SymbolResolutionError::unsupported_function_variant,
               "function-variant export is rejected until variant selection exists");
    }

    {
        const auto graph = fixture_graph();
        const auto result = macosarm::dyld::resolve_symbol(graph, 1, "_oob");
        expect(result.status == SymbolResolutionStatus::error &&
                   result.error == SymbolResolutionError::address_out_of_image,
               "corrupt image-relative export outside mapped segments rejected");
    }

    {
        auto graph = fixture_graph();
        graph.images.push_back(image(
            "/overflow.dylib",
            std::numeric_limits<std::uint64_t>::max() - 0x100ULL,
            0x100));
        graph.images.back().exports.push_back(
            export_symbol("_overflow", macosarm::dyld::ExportKind::regular, 0x200));
        const auto result = macosarm::dyld::resolve_symbol(
            graph,
            graph.images.size() - 1,
            "_overflow");
        expect(result.error == SymbolResolutionError::address_overflow,
               "image-base plus export offset overflow rejected");
    }

    {
        const auto graph = fixture_graph();
        const auto bad_image = macosarm::dyld::resolve_symbol(graph, 99, "_x");
        expect(bad_image.error == SymbolResolutionError::bad_image_index,
               "bad starting image index rejected");
        const auto empty = macosarm::dyld::resolve_symbol(graph, 0, "");
        expect(empty.error == SymbolResolutionError::empty_symbol_name,
               "empty symbol name rejected");
    }

    {
        const auto graph = fixture_graph();
        SymbolResolutionConfig config;
        config.max_visits = 1;
        const auto result = macosarm::dyld::resolve_symbol(
            graph,
            0,
            "_fallback",
            false,
            config);
        expect(result.status == SymbolResolutionStatus::error &&
                   result.error == SymbolResolutionError::visit_limit,
               "symbol-search abuse bound enforced");
    }

    expect(macosarm::dyld::resolved_symbol_kind_name(ResolvedSymbolKind::absolute) == "absolute",
           "resolved symbol kinds have stable names");
    expect(macosarm::dyld::symbol_resolution_status_name(SymbolResolutionStatus::not_found) ==
               "not_found",
           "symbol resolution statuses have stable names");
    expect(macosarm::dyld::symbol_resolution_error_name(SymbolResolutionError::visit_limit) ==
               "visit_limit",
           "symbol resolution errors have stable names");

    if (failures != 0) {
        std::cerr << failures << " test(s) failed\n";
        return EXIT_FAILURE;
    }

    std::cout << "dyld symbol resolution tests passed\n";
    return EXIT_SUCCESS;
}
