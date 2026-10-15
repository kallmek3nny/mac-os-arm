#include "macosarm/dyld_paths.hpp"

#include <algorithm>

namespace macosarm::dyld {
namespace {

[[nodiscard]] bool is_absolute(std::string_view path) noexcept {
    return !path.empty() && path.front() == '/';
}

[[nodiscard]] bool image_directory(std::string_view image_path, std::string& out) {
    if (!is_absolute(image_path) || image_path.size() <= 1 || image_path.back() == '/') {
        return false;
    }
    const std::size_t slash = image_path.find_last_of('/');
    if (slash == std::string_view::npos) {
        return false;
    }
    out = slash == 0 ? "/" : std::string(image_path.substr(0, slash));
    return true;
}

[[nodiscard]] bool is_token_path(std::string_view path, std::string_view token) noexcept {
    return path == token ||
           (path.size() > token.size() && path.substr(0, token.size()) == token &&
            path[token.size()] == '/');
}

[[nodiscard]] std::string append_component(std::string_view base, std::string_view tail) {
    if (tail.empty()) {
        return std::string(base);
    }
    if (base == "/") {
        return "/" + std::string(tail);
    }
    if (!base.empty() && base.back() == '/') {
        return std::string(base) + std::string(tail);
    }
    return std::string(base) + "/" + std::string(tail);
}

[[nodiscard]] bool expand_image_token(
    std::string_view path,
    std::string_view token,
    std::string_view image_path,
    std::string& out) {

    if (!is_token_path(path, token)) {
        return false;
    }

    std::string directory;
    if (!image_directory(image_path, directory)) {
        return false;
    }

    if (path == token) {
        out = std::move(directory);
        return true;
    }

    const std::string_view tail = path.substr(token.size() + 1);
    out = append_component(directory, tail);
    return true;
}

void append_unique(std::vector<std::string>& paths, std::string path) {
    if (std::find(paths.begin(), paths.end(), path) == paths.end()) {
        paths.push_back(std::move(path));
    }
}

[[nodiscard]] bool expand_runpath(
    const RunPathEntry& entry,
    const PathResolutionContext& context,
    std::string& out) {

    if (is_absolute(entry.path)) {
        out = entry.path;
        return true;
    }
    if (is_token_path(entry.path, "@loader_path")) {
        return expand_image_token(entry.path, "@loader_path", entry.owner_image_path, out);
    }
    if (is_token_path(entry.path, "@executable_path")) {
        return expand_image_token(entry.path, "@executable_path", context.executable_path, out);
    }
    return false;
}

} // namespace

PathResolutionResult resolve_load_path(
    std::string_view load_path,
    const PathResolutionContext& context) {

    PathResolutionResult result;
    if (load_path.empty()) {
        result.error = PathResolutionError::empty_load_path;
        return result;
    }

    if (is_absolute(load_path)) {
        result.candidates.emplace_back(load_path);
        return result;
    }

    if (is_token_path(load_path, "@executable_path")) {
        std::string expanded;
        if (!expand_image_token(load_path, "@executable_path", context.executable_path, expanded)) {
            result.error = PathResolutionError::bad_executable_path;
            return result;
        }
        result.candidates.push_back(std::move(expanded));
        return result;
    }

    if (is_token_path(load_path, "@loader_path")) {
        std::string expanded;
        if (!expand_image_token(load_path, "@loader_path", context.loader_path, expanded)) {
            result.error = PathResolutionError::bad_loader_path;
            return result;
        }
        result.candidates.push_back(std::move(expanded));
        return result;
    }

    if (load_path == "@rpath") {
        result.error = PathResolutionError::malformed_token;
        return result;
    }

    constexpr std::string_view kRpathPrefix = "@rpath/";
    if (load_path.starts_with(kRpathPrefix)) {
        const std::string_view tail = load_path.substr(kRpathPrefix.size());
        if (tail.empty()) {
            result.error = PathResolutionError::malformed_token;
            return result;
        }
        if (context.run_path_stack.empty()) {
            result.error = PathResolutionError::no_runpaths;
            return result;
        }

        for (const RunPathEntry& entry : context.run_path_stack) {
            std::string base;
            if (!expand_runpath(entry, context, base)) {
                ++result.ignored_runpaths;
                continue;
            }
            append_unique(result.candidates, append_component(base, tail));
        }

        if (result.candidates.empty()) {
            result.error = PathResolutionError::unusable_runpaths;
        }
        return result;
    }

    if (load_path.front() == '@') {
        result.error = PathResolutionError::unsupported_token;
        return result;
    }

    result.error = PathResolutionError::relative_path_unsupported;
    return result;
}

std::string_view path_resolution_error_name(PathResolutionError error) noexcept {
    switch (error) {
    case PathResolutionError::none: return "none";
    case PathResolutionError::empty_load_path: return "empty_load_path";
    case PathResolutionError::bad_executable_path: return "bad_executable_path";
    case PathResolutionError::bad_loader_path: return "bad_loader_path";
    case PathResolutionError::no_runpaths: return "no_runpaths";
    case PathResolutionError::unusable_runpaths: return "unusable_runpaths";
    case PathResolutionError::malformed_token: return "malformed_token";
    case PathResolutionError::unsupported_token: return "unsupported_token";
    case PathResolutionError::relative_path_unsupported: return "relative_path_unsupported";
    }
    return "unknown";
}

} // namespace macosarm::dyld
