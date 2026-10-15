#include "macosarm/dyld_graph.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>
#include <string_view>
#include <unordered_map>
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

void put_u32(std::vector<std::byte>& bytes, std::size_t offset, std::uint32_t value) {
    for (std::size_t index = 0; index < 4; ++index) {
        bytes[offset + index] = static_cast<std::byte>((value >> (index * 8)) & 0xffU);
    }
}

void put_u64(std::vector<std::byte>& bytes, std::size_t offset, std::uint64_t value) {
    for (std::size_t index = 0; index < 8; ++index) {
        bytes[offset + index] = static_cast<std::byte>((value >> (index * 8)) & 0xffU);
    }
}

std::size_t align8(std::size_t value) {
    return (value + 7U) & ~std::size_t{7U};
}

void put_string(std::vector<std::byte>& bytes, std::size_t offset, std::string_view value) {
    for (std::size_t index = 0; index < value.size(); ++index) {
        bytes[offset + index] = static_cast<std::byte>(static_cast<unsigned char>(value[index]));
    }
}

std::uint32_t dependency_command(macosarm::macho::DylibLoadKind kind) {
    using macosarm::macho::DylibLoadKind;
    switch (kind) {
    case DylibLoadKind::normal: return macosarm::macho::kLcLoadDylib;
    case DylibLoadKind::weak: return macosarm::macho::kLcLoadWeakDylib;
    case DylibLoadKind::reexport: return macosarm::macho::kLcReexportDylib;
    case DylibLoadKind::lazy: return macosarm::macho::kLcLazyLoadDylib;
    case DylibLoadKind::upward: return macosarm::macho::kLcLoadUpwardDylib;
    }
    return 0;
}

void append_segment(std::vector<std::byte>& commands, std::uint64_t vm_address) {
    constexpr std::size_t kCommandSize = 72;
    const std::size_t base = commands.size();
    commands.resize(base + kCommandSize, std::byte{0});
    put_u32(commands, base, macosarm::macho::kLcSegment64);
    put_u32(commands, base + 4, static_cast<std::uint32_t>(kCommandSize));
    put_string(commands, base + 8, "__TEXT");
    put_u64(commands, base + 24, vm_address);
    put_u64(commands, base + 32, 0x4000);
    put_u64(commands, base + 40, 0);
    put_u64(commands, base + 48, 0x4000);
    put_u32(commands, base + 56, 5);
    put_u32(commands, base + 60, 5);
    put_u32(commands, base + 64, 0);
    put_u32(commands, base + 68, 0);
}

void append_dylib_command(
    std::vector<std::byte>& commands,
    std::uint32_t command,
    std::string_view path) {

    constexpr std::size_t kFixedSize = 24;
    const std::size_t command_size = align8(kFixedSize + path.size() + 1);
    const std::size_t base = commands.size();
    commands.resize(base + command_size, std::byte{0});
    put_u32(commands, base, command);
    put_u32(commands, base + 4, static_cast<std::uint32_t>(command_size));
    put_u32(commands, base + 8, static_cast<std::uint32_t>(kFixedSize));
    put_u32(commands, base + 12, 0);
    put_u32(commands, base + 16, 0x00010000U);
    put_u32(commands, base + 20, 0x00010000U);
    put_string(commands, base + kFixedSize, path);
}

void append_rpath(std::vector<std::byte>& commands, std::string_view path) {
    constexpr std::size_t kFixedSize = 12;
    const std::size_t command_size = align8(kFixedSize + path.size() + 1);
    const std::size_t base = commands.size();
    commands.resize(base + command_size, std::byte{0});
    put_u32(commands, base, macosarm::macho::kLcRpath);
    put_u32(commands, base + 4, static_cast<std::uint32_t>(command_size));
    put_u32(commands, base + 8, static_cast<std::uint32_t>(kFixedSize));
    put_string(commands, base + kFixedSize, path);
}

void append_exports_command(
    std::vector<std::byte>& commands,
    std::uint32_t offset,
    std::uint32_t size) {

    constexpr std::size_t kCommandSize = 16;
    const std::size_t base = commands.size();
    commands.resize(base + kCommandSize, std::byte{0});
    put_u32(commands, base, macosarm::macho::kLcDyldExportsTrie);
    put_u32(commands, base + 4, static_cast<std::uint32_t>(kCommandSize));
    put_u32(commands, base + 8, offset);
    put_u32(commands, base + 12, size);
}

std::vector<std::byte> single_export_trie(std::string_view name, unsigned value) {
    if (name.empty() || name.size() > 120 || value > 0x7fU) {
        std::abort();
    }

    std::vector<std::byte> trie;
    trie.push_back(std::byte{0});
    trie.push_back(std::byte{1});
    for (char ch : name) {
        trie.push_back(static_cast<std::byte>(static_cast<unsigned char>(ch)));
    }
    trie.push_back(std::byte{0});
    const std::size_t leaf_offset = 2 + name.size() + 1 + 1;
    trie.push_back(static_cast<std::byte>(leaf_offset));
    trie.push_back(std::byte{2});
    trie.push_back(std::byte{0});
    trie.push_back(static_cast<std::byte>(value));
    trie.push_back(std::byte{0});
    return trie;
}

struct DependencySpec {
    std::string path;
    macosarm::macho::DylibLoadKind kind{macosarm::macho::DylibLoadKind::normal};
};

std::vector<std::byte> make_dylib(
    std::string_view install_name,
    std::uint64_t vm_address,
    const std::vector<DependencySpec>& dependencies = {},
    const std::vector<std::string>& runpaths = {},
    const std::vector<std::byte>& exports = {}) {

    constexpr std::uint32_t kExportsOffset = 0x3000;
    std::vector<std::byte> commands;
    std::uint32_t command_count = 0;

    append_segment(commands, vm_address);
    ++command_count;
    append_dylib_command(commands, macosarm::macho::kLcIdDylib, install_name);
    ++command_count;
    for (const std::string& runpath : runpaths) {
        append_rpath(commands, runpath);
        ++command_count;
    }
    for (const DependencySpec& dependency : dependencies) {
        append_dylib_command(commands, dependency_command(dependency.kind), dependency.path);
        ++command_count;
    }
    if (!exports.empty()) {
        append_exports_command(
            commands,
            kExportsOffset,
            static_cast<std::uint32_t>(exports.size()));
        ++command_count;
    }

    if (32 + commands.size() > kExportsOffset ||
        kExportsOffset + exports.size() > 0x4000) {
        std::abort();
    }

    std::vector<std::byte> file(0x4000, std::byte{0});
    put_u32(file, 0, macosarm::macho::kMhMagic64);
    put_u32(file, 4, static_cast<std::uint32_t>(macosarm::macho::kCpuTypeArm64));
    put_u32(file, 8, static_cast<std::uint32_t>(macosarm::macho::kCpuSubtypeArm64All));
    put_u32(file, 12, macosarm::macho::kMhDylib);
    put_u32(file, 16, command_count);
    put_u32(file, 20, static_cast<std::uint32_t>(commands.size()));
    put_u32(file, 24, 0);
    put_u32(file, 28, 0);
    std::copy(commands.begin(), commands.end(), file.begin() + 32);
    if (!exports.empty()) {
        std::copy(exports.begin(), exports.end(), file.begin() + kExportsOffset);
    }
    return file;
}

macosarm::macho::DylibDependency dependency(
    std::string path,
    macosarm::macho::DylibLoadKind kind = macosarm::macho::DylibLoadKind::normal) {
    macosarm::macho::DylibDependency result;
    result.path = std::move(path);
    result.kind = kind;
    return result;
}

macosarm::macho::Image root_image(
    std::vector<macosarm::macho::DylibDependency> dependencies,
    std::vector<std::string> runpaths = {}) {
    macosarm::macho::Image image;
    image.cpu_type = macosarm::macho::kCpuTypeArm64;
    image.cpu_subtype = macosarm::macho::kCpuSubtypeArm64All;
    image.file_type = macosarm::macho::kMhExecute;
    image.dependencies = std::move(dependencies);
    image.runpaths = std::move(runpaths);
    return image;
}

struct MemoryLookup {
    std::unordered_map<std::string, std::vector<std::byte>> files;
    std::size_t calls{};

    macosarm::dyld::ImageLookup callback() {
        return [this](std::string_view path) {
            ++calls;
            const auto found = files.find(std::string(path));
            if (found == files.end()) {
                return macosarm::dyld::ImageLookupResult{
                    macosarm::dyld::ImageLookupStatus::not_found,
                    {}};
            }
            return macosarm::dyld::ImageLookupResult{
                macosarm::dyld::ImageLookupStatus::found,
                found->second};
        };
    }
};

} // namespace

int main() {
    using macosarm::GuestAddressSpace;
    using macosarm::LoadedImage;
    using macosarm::Protection;
    using macosarm::VmError;
    using macosarm::dyld::DependencyGraphConfig;
    using macosarm::dyld::DependencyGraphError;
    using macosarm::dyld::ExportTrieError;
    using macosarm::dyld::GraphDependencyState;
    using macosarm::macho::DylibLoadKind;

    const std::vector<std::byte> no_root_bytes;
    const LoadedImage root_mapping{0x100000000ULL, 0x100000200ULL, 2};
    constexpr std::string_view kExecutable = "/Applications/Test.app/Contents/MacOS/Test";

    {
        MemoryLookup store;
        store.files.emplace(
            "/opt/lib/libA.dylib",
            make_dylib(
                "@rpath/libA.dylib",
                0x200000000ULL,
                {{"@rpath/libB.dylib", DylibLoadKind::normal}},
                {},
                single_export_trie("_a", 0x20)));
        store.files.emplace(
            "/opt/lib/libB.dylib",
            make_dylib(
                "@rpath/libB.dylib",
                0x200004000ULL,
                {{"/opt/lib/libA.dylib", DylibLoadKind::reexport}},
                {},
                single_export_trie("_b", 0x30)));

        const auto root = root_image(
            {
                dependency("@rpath/libA.dylib"),
                dependency("/missing/libWeak.dylib", DylibLoadKind::weak),
                dependency("/lazy/libLater.dylib", DylibLoadKind::lazy),
            },
            {"/opt/lib"});
        GuestAddressSpace vm;
        const auto lookup = store.callback();
        const auto result = macosarm::dyld::load_dependency_graph(
            root,
            no_root_bytes,
            root_mapping,
            kExecutable,
            kExecutable,
            vm,
            lookup);

        expect(static_cast<bool>(result), "recursive dependency graph loads");
        expect(result.graph.images.size() == 3, "root plus two dylibs recorded once");
        expect(result.graph.images[0].mapping.entry_address == root_mapping.entry_address,
               "root mapping metadata preserved");
        expect(!result.graph.images[0].owns_mapping, "root mapping stays caller-owned");
        expect(result.graph.images[1].owns_mapping && result.graph.images[2].owns_mapping,
               "loaded dylib mappings are graph-owned");
        expect(result.graph.images[0].dependencies.size() == 3,
               "root dependency order preserved");
        expect(result.graph.images[0].dependencies[0].state == GraphDependencyState::loaded &&
                   result.graph.images[0].dependencies[0].image_index == 1 &&
                   result.graph.images[0].dependencies[0].resolved_path == "/opt/lib/libA.dylib",
               "root @rpath dependency resolves to loaded image");
        expect(result.graph.images[0].dependencies[1].state == GraphDependencyState::missing_weak &&
                   result.graph.images[0].dependencies[1].image_index ==
                       macosarm::dyld::GraphDependency::kNoImage,
               "missing weak dependency is explicit and non-fatal");
        expect(result.graph.images[0].dependencies[2].state == GraphDependencyState::deferred_lazy &&
                   result.graph.images[0].dependencies[2].resolved_path.empty(),
               "lazy dependency is deferred without pretending it loaded");
        expect(result.graph.images[1].dependencies.size() == 1 &&
                   result.graph.images[1].dependencies[0].image_index == 2 &&
                   result.graph.images[1].dependencies[0].resolved_path == "/opt/lib/libB.dylib",
               "inherited root runpath resolves child dependency");
        expect(result.graph.images[2].dependencies.size() == 1 &&
                   result.graph.images[2].dependencies[0].image_index == 1,
               "dependency cycle reuses already-loaded image");
        expect(result.graph.images[1].exports.size() == 1 &&
                   result.graph.images[1].exports[0].name == "_a" &&
                   result.graph.images[1].exports[0].value == 0x20,
               "first dylib exports decoded into graph");
        expect(result.graph.images[2].exports.size() == 1 &&
                   result.graph.images[2].exports[0].name == "_b" &&
                   result.graph.images[2].exports[0].value == 0x30,
               "second dylib exports decoded into graph");
        expect(vm.mappings().size() == 2, "only dependency mappings added to VM");
        expect(store.calls == 3,
               "lookup skips lazy dependency and already-loaded cycle target");
    }

    {
        MemoryLookup store;
        store.files.emplace(
            "/libs/libA.dylib",
            make_dylib("/libs/libA.dylib", 0x300000000ULL));
        const auto root = root_image({
            dependency("/libs/libA.dylib"),
            dependency("/libs/missing.dylib"),
        });
        GuestAddressSpace vm;
        expect(static_cast<bool>(vm.map(0x700000000ULL, 0x4000, Protection::read)),
               "preexisting mapping installed for rollback test");
        const auto lookup = store.callback();
        const auto result = macosarm::dyld::load_dependency_graph(
            root,
            no_root_bytes,
            root_mapping,
            kExecutable,
            kExecutable,
            vm,
            lookup);

        expect(result.error == DependencyGraphError::dependency_not_found,
               "required missing dependency fails graph");
        expect(result.failed_image_index == 0 && result.failed_dependency_index == 1,
               "missing dependency location reported");
        expect(result.graph.images.empty(), "failed graph returns no partial nodes");
        const auto mappings = vm.mappings();
        expect(mappings.size() == 1 && mappings[0].base == 0x700000000ULL,
               "graph rollback removes loaded dylibs and preserves caller mapping");
    }

    {
        MemoryLookup store;
        store.files.emplace(
            "/libs/libA.dylib",
            make_dylib("/libs/libA.dylib", 0x400000000ULL));
        store.files.emplace(
            "/libs/libB.dylib",
            make_dylib("/libs/libB.dylib", 0x400000000ULL));
        const auto root = root_image({
            dependency("/libs/libA.dylib"),
            dependency("/libs/libB.dylib"),
        });
        GuestAddressSpace vm;
        const auto lookup = store.callback();
        const auto result = macosarm::dyld::load_dependency_graph(
            root,
            no_root_bytes,
            root_mapping,
            kExecutable,
            kExecutable,
            vm,
            lookup);

        expect(result.error == DependencyGraphError::load_failure,
               "overlapping dependency mapping fails graph");
        expect(result.load_error == macosarm::LoadError::vm_failure &&
                   result.vm_error == VmError::overlap,
               "VM overlap details preserved");
        expect(result.graph.images.empty() && vm.mappings().empty(),
               "overlap failure rolls back earlier dependency mapping");
    }

    {
        MemoryLookup store;
        const std::vector<std::byte> malformed_trie{
            std::byte{5}, std::byte{0}, std::byte{0}};
        store.files.emplace(
            "/libs/libBadExports.dylib",
            make_dylib(
                "/libs/libBadExports.dylib",
                0x500000000ULL,
                {},
                {},
                malformed_trie));
        const auto root = root_image({dependency("/libs/libBadExports.dylib")});
        GuestAddressSpace vm;
        const auto lookup = store.callback();
        const auto result = macosarm::dyld::load_dependency_graph(
            root,
            no_root_bytes,
            root_mapping,
            kExecutable,
            kExecutable,
            vm,
            lookup);

        expect(result.error == DependencyGraphError::exports_failure,
               "malformed dependency exports reject graph");
        expect(result.exports_error == ExportTrieError::terminal_out_of_bounds,
               "exports corruption reason preserved");
        expect(vm.mappings().empty(), "exports are validated before mapping dependency");
    }

    {
        MemoryLookup store;
        store.files.emplace(
            "/libs/libA.dylib",
            make_dylib("/libs/libA.dylib", 0x600000000ULL));
        const auto root = root_image({dependency("/libs/libA.dylib")});
        GuestAddressSpace vm;
        const auto lookup = store.callback();
        DependencyGraphConfig config;
        config.max_images = 1;
        const auto result = macosarm::dyld::load_dependency_graph(
            root,
            no_root_bytes,
            root_mapping,
            kExecutable,
            kExecutable,
            vm,
            lookup,
            config);

        expect(result.error == DependencyGraphError::image_limit,
               "image-count abuse bound enforced");
        expect(result.graph.images.empty() && vm.mappings().empty(),
               "image-limit failure leaves VM unchanged");
    }

    {
        MemoryLookup store;
        store.files.emplace(
            "/libs/libA.dylib",
            make_dylib("/libs/libA.dylib", 0x600004000ULL));
        const auto root = root_image({dependency("/libs/libA.dylib")});
        GuestAddressSpace vm;
        const auto lookup = store.callback();
        DependencyGraphConfig config;
        config.max_depth = 0;
        const auto result = macosarm::dyld::load_dependency_graph(
            root,
            no_root_bytes,
            root_mapping,
            kExecutable,
            kExecutable,
            vm,
            lookup,
            config);

        expect(result.error == DependencyGraphError::depth_limit,
               "dependency-depth abuse bound enforced");
        expect(result.graph.images.empty() && vm.mappings().empty(),
               "depth-limit failure leaves VM unchanged");
    }

    {
        MemoryLookup store;
        const auto root = root_image({});
        GuestAddressSpace vm;
        const auto lookup = store.callback();
        const auto result = macosarm::dyld::load_dependency_graph(
            root,
            no_root_bytes,
            root_mapping,
            "relative/Test",
            kExecutable,
            vm,
            lookup);

        expect(result.error == DependencyGraphError::dependency_plan_failure &&
                   result.plan_error == macosarm::dyld::DependencyPlanError::bad_image_path,
               "invalid root path rejected through dependency planner");
        expect(result.graph.images.empty(), "path-planning failure is atomic");
    }

    expect(macosarm::dyld::graph_dependency_state_name(GraphDependencyState::missing_weak) ==
               "missing_weak",
           "dependency states have stable names");
    expect(macosarm::dyld::dependency_graph_error_name(DependencyGraphError::load_failure) ==
               "load_failure",
           "dependency graph errors have stable names");

    if (failures != 0) {
        std::cerr << failures << " test(s) failed\n";
        return EXIT_FAILURE;
    }

    std::cout << "dyld dependency graph tests passed\n";
    return EXIT_SUCCESS;
}
