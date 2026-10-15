#include "macosarm/dyld_symbols.hpp"

#include <limits>
#include <utility>
#include <vector>

namespace macosarm::dyld {
namespace {

struct Visit {
    std::size_t image_index{};
    std::string symbol_name;
};

class SymbolResolver {
public:
    SymbolResolver(
        const LoadedImageGraph& graph,
        bool weak_import,
        const SymbolResolutionConfig& config)
        : graph_(graph), weak_import_(weak_import), config_(config) {}

    [[nodiscard]] SymbolResolutionResult run(
        std::size_t image_index,
        std::string_view symbol_name) {
        if (image_index >= graph_.images.size()) {
            return error(SymbolResolutionError::bad_image_index);
        }
        if (symbol_name.empty()) {
            return error(SymbolResolutionError::empty_symbol_name);
        }
        return search(image_index, symbol_name);
    }

private:
    [[nodiscard]] SymbolResolutionResult error(SymbolResolutionError code) const {
        SymbolResolutionResult result;
        result.status = SymbolResolutionStatus::error;
        result.error = code;
        return result;
    }

    [[nodiscard]] static SymbolResolutionResult not_found() {
        SymbolResolutionResult result;
        result.status = SymbolResolutionStatus::not_found;
        return result;
    }

    [[nodiscard]] bool already_visited(
        std::size_t image_index,
        std::string_view symbol_name) const {
        for (const Visit& visit : visited_) {
            if (visit.image_index == image_index && visit.symbol_name == symbol_name) {
                return true;
            }
        }
        return false;
    }

    [[nodiscard]] const ExportSymbol* find_export(
        const GraphImage& image,
        std::string_view symbol_name) const noexcept {
        for (const ExportSymbol& symbol : image.exports) {
            if (symbol.name == symbol_name) {
                return &symbol;
            }
        }
        return nullptr;
    }

    [[nodiscard]] static bool add_overflows(
        std::uint64_t left,
        std::uint64_t right) noexcept {
        return right > std::numeric_limits<std::uint64_t>::max() - left;
    }

    [[nodiscard]] static bool address_belongs_to_image(
        const GraphImage& image,
        std::uint64_t address) noexcept {
        for (const macho::Segment& segment : image.image.segments) {
            if (segment.vm_size == 0 || add_overflows(segment.vm_address, segment.vm_size)) {
                continue;
            }
            if (address >= segment.vm_address && address < segment.vm_address + segment.vm_size) {
                return true;
            }
        }
        return false;
    }

    [[nodiscard]] SymbolResolutionResult resolve_local(
        std::size_t image_index,
        const ExportSymbol& symbol) const {
        const GraphImage& image = graph_.images[image_index];
        ResolvedSymbol resolved;
        resolved.name = symbol.name;
        resolved.image_index = image_index;
        resolved.weak_definition = symbol.weak_definition;

        switch (symbol.kind) {
        case ExportKind::regular:
            if (add_overflows(image.mapping.preferred_load_address, symbol.value)) {
                return error(SymbolResolutionError::address_overflow);
            }
            resolved.kind = ResolvedSymbolKind::image_relative;
            resolved.address = image.mapping.preferred_load_address + symbol.value;
            if (!address_belongs_to_image(image, resolved.address)) {
                return error(SymbolResolutionError::address_out_of_image);
            }
            break;
        case ExportKind::absolute:
            resolved.kind = ResolvedSymbolKind::absolute;
            resolved.address = symbol.value;
            break;
        case ExportKind::thread_local_storage:
            return error(SymbolResolutionError::unsupported_thread_local);
        case ExportKind::stub_and_resolver:
            return error(SymbolResolutionError::unsupported_stub_and_resolver);
        case ExportKind::function_variant:
            return error(SymbolResolutionError::unsupported_function_variant);
        case ExportKind::reexport:
            return error(SymbolResolutionError::invalid_reexport_ordinal);
        }

        SymbolResolutionResult result;
        result.status = SymbolResolutionStatus::found;
        result.symbol = std::move(resolved);
        return result;
    }

    [[nodiscard]] SymbolResolutionResult follow_reexport(
        std::size_t image_index,
        const ExportSymbol& symbol) {
        const GraphImage& image = graph_.images[image_index];
        if (symbol.value == 0 || symbol.value > image.dependencies.size()) {
            return error(SymbolResolutionError::invalid_reexport_ordinal);
        }

        const GraphDependency& dependency =
            image.dependencies[static_cast<std::size_t>(symbol.value - 1)];
        if (dependency.state != GraphDependencyState::loaded ||
            dependency.image_index == GraphDependency::kNoImage ||
            dependency.image_index >= graph_.images.size()) {
            if (weak_import_) {
                return not_found();
            }
            return error(SymbolResolutionError::unavailable_reexport);
        }

        const std::string_view import_name =
            symbol.import_name.empty() ? std::string_view(symbol.name)
                                       : std::string_view(symbol.import_name);
        return search(dependency.image_index, import_name);
    }

    [[nodiscard]] SymbolResolutionResult search(
        std::size_t image_index,
        std::string_view symbol_name) {
        if (image_index >= graph_.images.size()) {
            return error(SymbolResolutionError::bad_image_index);
        }
        if (already_visited(image_index, symbol_name)) {
            return not_found();
        }
        if (visited_.size() >= config_.max_visits) {
            return error(SymbolResolutionError::visit_limit);
        }
        visited_.push_back(Visit{image_index, std::string(symbol_name)});

        const GraphImage& image = graph_.images[image_index];
        if (const ExportSymbol* symbol = find_export(image, symbol_name)) {
            if (symbol->kind == ExportKind::reexport) {
                return follow_reexport(image_index, *symbol);
            }
            return resolve_local(image_index, *symbol);
        }

        for (const GraphDependency& dependency : image.dependencies) {
            if (dependency.dependency.kind != macho::DylibLoadKind::reexport ||
                dependency.state != GraphDependencyState::loaded ||
                dependency.image_index == GraphDependency::kNoImage ||
                dependency.image_index >= graph_.images.size()) {
                continue;
            }

            SymbolResolutionResult child = search(dependency.image_index, symbol_name);
            if (child.status == SymbolResolutionStatus::found ||
                child.status == SymbolResolutionStatus::error) {
                return child;
            }
        }

        return not_found();
    }

    const LoadedImageGraph& graph_;
    bool weak_import_{};
    const SymbolResolutionConfig& config_;
    std::vector<Visit> visited_;
};

} // namespace

SymbolResolutionResult resolve_symbol(
    const LoadedImageGraph& graph,
    std::size_t image_index,
    std::string_view symbol_name,
    bool weak_import,
    const SymbolResolutionConfig& config) {
    return SymbolResolver(graph, weak_import, config).run(image_index, symbol_name);
}

std::string_view resolved_symbol_kind_name(ResolvedSymbolKind kind) noexcept {
    switch (kind) {
    case ResolvedSymbolKind::image_relative: return "image_relative";
    case ResolvedSymbolKind::absolute: return "absolute";
    }
    return "unknown";
}

std::string_view symbol_resolution_status_name(SymbolResolutionStatus status) noexcept {
    switch (status) {
    case SymbolResolutionStatus::found: return "found";
    case SymbolResolutionStatus::not_found: return "not_found";
    case SymbolResolutionStatus::error: return "error";
    }
    return "unknown";
}

std::string_view symbol_resolution_error_name(SymbolResolutionError error_code) noexcept {
    switch (error_code) {
    case SymbolResolutionError::none: return "none";
    case SymbolResolutionError::bad_image_index: return "bad_image_index";
    case SymbolResolutionError::empty_symbol_name: return "empty_symbol_name";
    case SymbolResolutionError::invalid_reexport_ordinal: return "invalid_reexport_ordinal";
    case SymbolResolutionError::unavailable_reexport: return "unavailable_reexport";
    case SymbolResolutionError::address_overflow: return "address_overflow";
    case SymbolResolutionError::address_out_of_image: return "address_out_of_image";
    case SymbolResolutionError::unsupported_thread_local: return "unsupported_thread_local";
    case SymbolResolutionError::unsupported_stub_and_resolver: return "unsupported_stub_and_resolver";
    case SymbolResolutionError::unsupported_function_variant: return "unsupported_function_variant";
    case SymbolResolutionError::visit_limit: return "visit_limit";
    }
    return "unknown";
}

} // namespace macosarm::dyld
