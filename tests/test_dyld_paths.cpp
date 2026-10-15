#include "macosarm/dyld_paths.hpp"

#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

namespace {

int failures = 0;

void expect(bool condition, const std::string& label) {
    if (!condition) {
        std::cerr << "FAIL: " << label << '\n';
        ++failures;
    }
}

macosarm::dyld::PathResolutionContext base_context() {
    macosarm::dyld::PathResolutionContext context;
    context.executable_path = "/Applications/Test.app/Contents/MacOS/Test";
    context.loader_path = "/Applications/Test.app/Contents/PlugIns/Foo.bundle/Contents/MacOS/Foo";
    return context;
}

} // namespace

int main() {
    using macosarm::dyld::PathResolutionError;
    using macosarm::dyld::RunPathEntry;

    {
        const auto result = macosarm::dyld::resolve_load_path(
            "/usr/lib/libSystem.B.dylib", base_context());
        expect(static_cast<bool>(result), "absolute path resolves");
        expect(result.candidates == std::vector<std::string>{"/usr/lib/libSystem.B.dylib"},
               "absolute path remains unchanged");
    }

    {
        const auto result = macosarm::dyld::resolve_load_path(
            "@executable_path/../Frameworks/AppKitShim.dylib", base_context());
        expect(static_cast<bool>(result), "@executable_path resolves");
        expect(result.candidates == std::vector<std::string>{
                   "/Applications/Test.app/Contents/MacOS/../Frameworks/AppKitShim.dylib"},
               "@executable_path uses main executable directory");
    }

    {
        const auto result = macosarm::dyld::resolve_load_path(
            "@loader_path/../Frameworks/PluginShim.dylib", base_context());
        expect(static_cast<bool>(result), "@loader_path resolves");
        expect(result.candidates == std::vector<std::string>{
                   "/Applications/Test.app/Contents/PlugIns/Foo.bundle/Contents/MacOS/../Frameworks/PluginShim.dylib"},
               "@loader_path uses current image directory");
    }

    {
        auto context = base_context();
        context.run_path_stack = {
            RunPathEntry{
                "@loader_path/../Frameworks",
                "/Applications/Test.app/Contents/PlugIns/Foo.bundle/Contents/MacOS/Foo"},
            RunPathEntry{
                "@executable_path/../Frameworks",
                "/Applications/Test.app/Contents/MacOS/Test"},
            RunPathEntry{
                "/System/Library/Frameworks",
                "/Applications/Test.app/Contents/MacOS/Test"},
        };

        const auto result = macosarm::dyld::resolve_load_path("@rpath/Widget.dylib", context);
        expect(static_cast<bool>(result), "@rpath resolves across dependency stack");
        const std::vector<std::string> expected{
            "/Applications/Test.app/Contents/PlugIns/Foo.bundle/Contents/MacOS/../Frameworks/Widget.dylib",
            "/Applications/Test.app/Contents/MacOS/../Frameworks/Widget.dylib",
            "/System/Library/Frameworks/Widget.dylib",
        };
        expect(result.candidates == expected, "@rpath preserves current-loader to parent search order");
        expect(result.ignored_runpaths == 0, "valid rpath stack ignores nothing");
    }

    {
        auto context = base_context();
        context.run_path_stack = {
            RunPathEntry{"relative/not-supported", context.loader_path},
            RunPathEntry{"@loader_path/Frameworks", context.loader_path},
        };
        const auto result = macosarm::dyld::resolve_load_path("@rpath/libKeepGoing.dylib", context);
        expect(static_cast<bool>(result), "invalid rpath does not poison later valid entry");
        expect(result.ignored_runpaths == 1, "invalid rpath count is reported");
        expect(result.candidates == std::vector<std::string>{
                   "/Applications/Test.app/Contents/PlugIns/Foo.bundle/Contents/MacOS/Frameworks/libKeepGoing.dylib"},
               "valid rpath after invalid entry still resolves");
    }

    {
        auto context = base_context();
        context.run_path_stack = {
            RunPathEntry{"@loader_path/Frameworks", "relative/owner"},
            RunPathEntry{"also-relative", context.loader_path},
        };
        const auto result = macosarm::dyld::resolve_load_path("@rpath/libMissing.dylib", context);
        expect(result.error == PathResolutionError::unusable_runpaths,
               "all unusable rpaths return explicit error");
        expect(result.ignored_runpaths == 2, "all unusable rpaths are counted");
        expect(result.candidates.empty(), "unusable rpaths produce no candidates");
    }

    {
        auto context = base_context();
        context.run_path_stack = {
            RunPathEntry{"/Frameworks", context.loader_path},
            RunPathEntry{"/Frameworks", context.executable_path},
            RunPathEntry{"/Other", context.loader_path},
        };
        const auto result = macosarm::dyld::resolve_load_path("@rpath/libUnique.dylib", context);
        expect(static_cast<bool>(result), "duplicate rpath candidates resolve");
        expect(result.candidates == std::vector<std::string>{
                   "/Frameworks/libUnique.dylib", "/Other/libUnique.dylib"},
               "duplicate candidates are removed without changing first-hit order");
    }

    {
        auto context = base_context();
        context.run_path_stack.clear();
        const auto result = macosarm::dyld::resolve_load_path("@rpath/libNoStack.dylib", context);
        expect(result.error == PathResolutionError::no_runpaths, "empty rpath stack is explicit");
    }

    {
        auto context = base_context();
        context.executable_path = "relative/Test";
        const auto result = macosarm::dyld::resolve_load_path("@executable_path/libBad.dylib", context);
        expect(result.error == PathResolutionError::bad_executable_path,
               "relative executable context rejected");
    }

    {
        auto context = base_context();
        context.loader_path = "/Applications/Test.app/Contents/MacOS/";
        const auto result = macosarm::dyld::resolve_load_path("@loader_path/libBad.dylib", context);
        expect(result.error == PathResolutionError::bad_loader_path,
               "directory-valued loader context rejected");
    }

    {
        auto context = base_context();
        context.loader_path = "/Foo";
        const auto result = macosarm::dyld::resolve_load_path("@loader_path/libRoot.dylib", context);
        expect(static_cast<bool>(result), "root-level loader path resolves");
        expect(result.candidates == std::vector<std::string>{"/libRoot.dylib"},
               "root-level loader directory joins without duplicate slash");
    }

    {
        const auto empty = macosarm::dyld::resolve_load_path("", base_context());
        expect(empty.error == PathResolutionError::empty_load_path, "empty load path rejected");

        const auto exact_rpath = macosarm::dyld::resolve_load_path("@rpath", base_context());
        expect(exact_rpath.error == PathResolutionError::malformed_token,
               "bare @rpath token rejected");

        const auto slash_rpath = macosarm::dyld::resolve_load_path("@rpath/", base_context());
        expect(slash_rpath.error == PathResolutionError::malformed_token,
               "empty @rpath tail rejected");

        const auto unknown = macosarm::dyld::resolve_load_path("@unknown/libX.dylib", base_context());
        expect(unknown.error == PathResolutionError::unsupported_token, "unknown @ token rejected");

        const auto relative = macosarm::dyld::resolve_load_path("Frameworks/libX.dylib", base_context());
        expect(relative.error == PathResolutionError::relative_path_unsupported,
               "file-relative path fails closed until process CWD is modeled");
    }

    expect(macosarm::dyld::path_resolution_error_name(PathResolutionError::unusable_runpaths) ==
               "unusable_runpaths",
           "resolver errors have stable names");

    if (failures != 0) {
        std::cerr << failures << " test(s) failed\n";
        return EXIT_FAILURE;
    }

    std::cout << "dyld path resolution tests passed\n";
    return EXIT_SUCCESS;
}
