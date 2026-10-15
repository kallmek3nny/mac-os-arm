#include "macosarm/dyld_dependencies.hpp"

#include <cstdlib>
#include <iostream>
#include <string>
#include <utility>
#include <vector>

namespace {

int failures = 0;

void expect(bool condition, const std::string& label) {
    if (!condition) {
        std::cerr << "FAIL: " << label << '\n';
        ++failures;
    }
}

macosarm::dyld::DependencyPlanContext root_context() {
    macosarm::dyld::DependencyPlanContext context;
    context.executable_path = "/Applications/Test.app/Contents/MacOS/Test";
    context.image_path = context.executable_path;
    return context;
}

macosarm::macho::DylibDependency dependency(
    std::string path,
    macosarm::macho::DylibLoadKind kind,
    std::uint32_t timestamp = 0,
    std::uint32_t current = 0,
    std::uint32_t compatibility = 0) {
    macosarm::macho::DylibDependency result;
    result.path = std::move(path);
    result.kind = kind;
    result.timestamp = timestamp;
    result.current_version = current;
    result.compatibility_version = compatibility;
    return result;
}

} // namespace

int main() {
    using macosarm::dyld::DependencyPlanError;
    using macosarm::dyld::DependencyPlanResult;
    using macosarm::dyld::PathResolutionError;
    using macosarm::dyld::RunPathEntry;
    using macosarm::macho::DylibLoadKind;

    {
        macosarm::macho::Image image;
        image.runpaths = {
            "@loader_path/../Frameworks",
            "/System/Library/Frameworks",
        };
        image.dependencies = {
            dependency("@rpath/Alpha.dylib", DylibLoadKind::normal, 7, 0x10002, 0x10000),
            dependency("@loader_path/Local/Beta.dylib", DylibLoadKind::weak),
            dependency("/usr/lib/Gamma.dylib", DylibLoadKind::reexport),
        };

        const auto result = macosarm::dyld::plan_dependencies(image, root_context());
        expect(static_cast<bool>(result), "root dependency plan succeeds");
        expect(result.run_path_stack.size() == 2, "root LC_RPATH entries become search stack");
        expect(result.run_path_stack[0].owner_image_path == root_context().image_path,
               "root runpath records its owner image");
        expect(result.dependencies.size() == 3, "all dependency commands are planned in order");

        const std::vector<std::string> alpha_expected{
            "/Applications/Test.app/Contents/MacOS/../Frameworks/Alpha.dylib",
            "/System/Library/Frameworks/Alpha.dylib",
        };
        expect(result.dependencies[0].candidates == alpha_expected,
               "@rpath dependency receives ordered candidate list");
        expect(result.dependencies[0].dependency.kind == DylibLoadKind::normal,
               "dependency kind is preserved");
        expect(result.dependencies[0].dependency.timestamp == 7 &&
                   result.dependencies[0].dependency.current_version == 0x10002 &&
                   result.dependencies[0].dependency.compatibility_version == 0x10000,
               "dependency version metadata is preserved");
        expect(result.dependencies[1].dependency.kind == DylibLoadKind::weak,
               "weak dependency metadata is preserved without policy decisions");
        expect(result.dependencies[1].candidates == std::vector<std::string>{
                   "/Applications/Test.app/Contents/MacOS/Local/Beta.dylib"},
               "@loader_path dependency uses current image");
        expect(result.dependencies[2].dependency.kind == DylibLoadKind::reexport,
               "reexport dependency metadata is preserved");
        expect(result.dependencies[2].candidates == std::vector<std::string>{"/usr/lib/Gamma.dylib"},
               "absolute dependency stays direct");
        expect(result.failed_dependency_index == DependencyPlanResult::kNoDependency,
               "successful plan has no failed dependency index");
    }

    {
        macosarm::macho::Image child;
        child.runpaths = {"@loader_path/Nested"};
        child.dependencies = {
            dependency("@rpath/Leaf.dylib", DylibLoadKind::upward),
        };

        macosarm::dyld::DependencyPlanContext context;
        context.executable_path = "/Applications/Test.app/Contents/MacOS/Test";
        context.image_path = "/Applications/Test.app/Contents/Frameworks/Child.dylib";
        context.inherited_run_path_stack = {
            RunPathEntry{"@executable_path/../Frameworks", context.executable_path},
            RunPathEntry{"/Fallback", context.executable_path},
        };

        const auto result = macosarm::dyld::plan_dependencies(child, context);
        expect(static_cast<bool>(result), "child dependency plan succeeds");
        expect(result.run_path_stack.size() == 3, "child runpaths prepend inherited stack");
        expect(result.run_path_stack[0].path == "@loader_path/Nested" &&
                   result.run_path_stack[0].owner_image_path == context.image_path,
               "child runpath is first and owned by child image");
        expect(result.run_path_stack[1].path == "@executable_path/../Frameworks" &&
                   result.run_path_stack[2].path == "/Fallback",
               "parent stack order is preserved after child entries");

        const std::vector<std::string> expected{
            "/Applications/Test.app/Contents/Frameworks/Nested/Leaf.dylib",
            "/Applications/Test.app/Contents/MacOS/../Frameworks/Leaf.dylib",
            "/Fallback/Leaf.dylib",
        };
        expect(result.dependencies.size() == 1 && result.dependencies[0].candidates == expected,
               "recursive rpath search uses child then parent chain");
        expect(result.dependencies[0].dependency.kind == DylibLoadKind::upward,
               "upward dependency stays metadata-only in planner");
    }

    {
        macosarm::macho::Image image;
        image.runpaths = {"relative/ignored"};
        image.dependencies = {
            dependency("@rpath/Recovered.dylib", DylibLoadKind::normal),
        };
        auto context = root_context();
        context.inherited_run_path_stack = {
            RunPathEntry{"/Fallback", context.executable_path},
        };

        const auto result = macosarm::dyld::plan_dependencies(image, context);
        expect(static_cast<bool>(result), "invalid current rpath can fall through to parent");
        expect(result.dependencies[0].ignored_runpaths == 1,
               "planner preserves ignored-rpath diagnostic count");
        expect(result.dependencies[0].candidates == std::vector<std::string>{
                   "/Fallback/Recovered.dylib"},
               "parent candidate survives invalid current rpath");
    }

    {
        macosarm::macho::Image image;
        image.dependencies = {
            dependency("/usr/lib/First.dylib", DylibLoadKind::normal),
            dependency("@unknown/Second.dylib", DylibLoadKind::weak),
            dependency("/usr/lib/NeverReached.dylib", DylibLoadKind::normal),
        };

        const auto result = macosarm::dyld::plan_dependencies(image, root_context());
        expect(result.error == DependencyPlanError::path_resolution_failure,
               "dependency path error fails planning explicitly");
        expect(result.failed_dependency_index == 1, "planner reports exact failing dependency index");
        expect(result.path_error == PathResolutionError::unsupported_token,
               "planner preserves underlying path resolution error");
        expect(result.dependencies.size() == 1 &&
                   result.dependencies[0].candidates == std::vector<std::string>{"/usr/lib/First.dylib"},
               "already-planned dependencies remain visible for diagnostics");
    }

    {
        macosarm::macho::Image image;
        image.runpaths = {"/One", "/Two"};
        const auto result = macosarm::dyld::plan_dependencies(image, root_context());
        expect(static_cast<bool>(result), "dependency-free image still plans context");
        expect(result.dependencies.empty(), "dependency-free image has empty plan list");
        expect(result.run_path_stack.size() == 2, "dependency-free image still exports child rpath stack");
    }

    {
        auto context = root_context();
        context.executable_path = "relative/Test";
        macosarm::macho::Image image;
        const auto result = macosarm::dyld::plan_dependencies(image, context);
        expect(result.error == DependencyPlanError::bad_executable_path,
               "planner rejects non-absolute process executable path");
        expect(result.failed_dependency_index == DependencyPlanResult::kNoDependency,
               "bad process context does not blame a dependency");
    }

    {
        auto context = root_context();
        context.image_path = "/Applications/Test.app/Contents/Frameworks/";
        macosarm::macho::Image image;
        const auto result = macosarm::dyld::plan_dependencies(image, context);
        expect(result.error == DependencyPlanError::bad_image_path,
               "planner rejects directory-valued image path");
    }

    expect(macosarm::dyld::dependency_plan_error_name(DependencyPlanError::path_resolution_failure) ==
               "path_resolution_failure",
           "dependency plan errors have stable names");

    if (failures != 0) {
        std::cerr << failures << " test(s) failed\n";
        return EXIT_FAILURE;
    }

    std::cout << "dyld dependency planning tests passed\n";
    return EXIT_SUCCESS;
}
