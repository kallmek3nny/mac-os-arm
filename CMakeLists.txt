cmake_minimum_required(VERSION 3.20)
project(mac_os_arm VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

function(macosarm_enable_warnings target)
    target_compile_options(${target} PRIVATE
        $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-Wall;-Wextra;-Wpedantic;-Werror>
        $<$<CXX_COMPILER_ID:MSVC>:/W4;/WX>
    )
endfunction()

add_library(macosarm_macho
    src/macho.cpp
    src/address_space.cpp
    src/image_loader.cpp
    src/dyld_paths.cpp
    src/dyld_dependencies.cpp
    src/dyld_exports.cpp
    src/dyld_graph.cpp
    src/dyld_symbols.cpp
    src/dyld_fixups.cpp
    src/dyld_fixup_apply.cpp
    src/dyld_fixup_pauth.cpp
    src/pointer_auth.cpp
    src/execution.cpp
    src/darwin_syscall.cpp
    src/mach_trap.cpp
    src/process.cpp
    src/session.cpp
)
target_include_directories(macosarm_macho PUBLIC include)
macosarm_enable_warnings(macosarm_macho)

add_executable(macho-inspect src/macho_inspect.cpp)
target_link_libraries(macho-inspect PRIVATE macosarm_macho)

option(MACOSARM_ENABLE_DYNARMIC "Build the pinned Dynarmic ARM64 JIT backend" OFF)

if(MACOSARM_ENABLE_DYNARMIC)
    include(FetchContent)
    set(DYNARMIC_FRONTENDS "A64" CACHE STRING "" FORCE)
    set(DYNARMIC_TESTS OFF CACHE BOOL "" FORCE)
    set(DYNARMIC_TESTS_USE_UNICORN OFF CACHE BOOL "" FORCE)
    set(DYNARMIC_USE_LLVM OFF CACHE BOOL "" FORCE)
    set(DYNARMIC_USE_BUNDLED_EXTERNALS ON CACHE BOOL "" FORCE)
    set(DYNARMIC_WARNINGS_AS_ERRORS OFF CACHE BOOL "" FORCE)

    FetchContent_Declare(
        dynarmic
        GIT_REPOSITORY https://github.com/azahar-emu/dynarmic.git
        GIT_TAG a46601580d5512d324104f985b5f0209dc980ddc
        GIT_SHALLOW FALSE
        GIT_SUBMODULES_RECURSE TRUE
    )
    FetchContent_MakeAvailable(dynarmic)

    add_library(macosarm_dynarmic src/dynarmic_backend.cpp)
    target_include_directories(macosarm_dynarmic PUBLIC include)
    target_link_libraries(macosarm_dynarmic PUBLIC macosarm_macho PRIVATE dynarmic)
    macosarm_enable_warnings(macosarm_dynarmic)
endif()

include(CTest)
if(BUILD_TESTING)
    add_executable(test_macho tests/test_macho.cpp)
    target_link_libraries(test_macho PRIVATE macosarm_macho)
    macosarm_enable_warnings(test_macho)
    add_test(NAME macho-parser COMMAND test_macho)

    add_executable(test_address_space tests/test_address_space.cpp)
    target_link_libraries(test_address_space PRIVATE macosarm_macho)
    macosarm_enable_warnings(test_address_space)
    add_test(NAME guest-address-space COMMAND test_address_space)

    add_executable(test_image_loader tests/test_image_loader.cpp)
    target_link_libraries(test_image_loader PRIVATE macosarm_macho)
    macosarm_enable_warnings(test_image_loader)
    add_test(NAME image-loader COMMAND test_image_loader)

    add_executable(test_dyld_paths tests/test_dyld_paths.cpp)
    target_link_libraries(test_dyld_paths PRIVATE macosarm_macho)
    macosarm_enable_warnings(test_dyld_paths)
    add_test(NAME dyld-path-resolution COMMAND test_dyld_paths)

    add_executable(test_dyld_dependencies tests/test_dyld_dependencies.cpp)
    target_link_libraries(test_dyld_dependencies PRIVATE macosarm_macho)
    macosarm_enable_warnings(test_dyld_dependencies)
    add_test(NAME dyld-dependency-planning COMMAND test_dyld_dependencies)

    add_executable(test_dyld_exports tests/test_dyld_exports.cpp)
    target_link_libraries(test_dyld_exports PRIVATE macosarm_macho)
    macosarm_enable_warnings(test_dyld_exports)
    add_test(NAME dyld-exports-trie COMMAND test_dyld_exports)

    add_executable(test_dyld_graph tests/test_dyld_graph.cpp)
    target_link_libraries(test_dyld_graph PRIVATE macosarm_macho)
    macosarm_enable_warnings(test_dyld_graph)
    add_test(NAME dyld-loaded-image-graph COMMAND test_dyld_graph)

    add_executable(test_dyld_symbols tests/test_dyld_symbols.cpp)
    target_link_libraries(test_dyld_symbols PRIVATE macosarm_macho)
    macosarm_enable_warnings(test_dyld_symbols)
    add_test(NAME dyld-symbol-resolution COMMAND test_dyld_symbols)

    add_executable(test_dyld_fixups tests/test_dyld_fixups.cpp)
    target_link_libraries(test_dyld_fixups PRIVATE macosarm_macho)
    macosarm_enable_warnings(test_dyld_fixups)
    add_test(NAME dyld-chained-fixups-metadata COMMAND test_dyld_fixups)

    add_executable(test_dyld_fixup_apply tests/test_dyld_fixup_apply.cpp)
    target_link_libraries(test_dyld_fixup_apply PRIVATE macosarm_macho)
    macosarm_enable_warnings(test_dyld_fixup_apply)
    add_test(NAME dyld-generic-chained-fixup-apply COMMAND test_dyld_fixup_apply)

    add_executable(test_dyld_fixup_arm64e tests/test_dyld_fixup_arm64e.cpp)
    target_link_libraries(test_dyld_fixup_arm64e PRIVATE macosarm_macho)
    macosarm_enable_warnings(test_dyld_fixup_arm64e)
    add_test(NAME dyld-arm64e-chained-fixup-apply COMMAND test_dyld_fixup_arm64e)

    add_executable(test_dyld_fixup_pauth tests/test_dyld_fixup_pauth.cpp)
    target_link_libraries(test_dyld_fixup_pauth PRIVATE macosarm_macho)
    macosarm_enable_warnings(test_dyld_fixup_pauth)
    add_test(NAME dyld-authenticated-arm64e-fixup-apply COMMAND test_dyld_fixup_pauth)

    add_executable(test_pointer_auth tests/test_pointer_auth.cpp)
    target_link_libraries(test_pointer_auth PRIVATE macosarm_macho)
    macosarm_enable_warnings(test_pointer_auth)
    add_test(NAME pointer-auth-policy COMMAND test_pointer_auth)

    add_executable(test_parse_load_integration tests/test_parse_load_integration.cpp)
    target_link_libraries(test_parse_load_integration PRIVATE macosarm_macho)
    macosarm_enable_warnings(test_parse_load_integration)
    add_test(NAME parse-load-integration COMMAND test_parse_load_integration)

    add_executable(test_execution tests/test_execution.cpp)
    target_link_libraries(test_execution PRIVATE macosarm_macho)
    macosarm_enable_warnings(test_execution)
    add_test(NAME execution-contract COMMAND test_execution)

    add_executable(test_darwin_syscall tests/test_darwin_syscall.cpp)
    target_link_libraries(test_darwin_syscall PRIVATE macosarm_macho)
    macosarm_enable_warnings(test_darwin_syscall)
    add_test(NAME darwin-syscall-dispatch COMMAND test_darwin_syscall)

    add_executable(test_mach_trap tests/test_mach_trap.cpp)
    target_link_libraries(test_mach_trap PRIVATE macosarm_macho)
    macosarm_enable_warnings(test_mach_trap)
    add_test(NAME mach-trap-dispatch COMMAND test_mach_trap)

    add_executable(test_mach_msg tests/test_mach_msg.cpp)
    target_link_libraries(test_mach_msg PRIVATE macosarm_macho)
    macosarm_enable_warnings(test_mach_msg)
    add_test(NAME mach-msg-transport COMMAND test_mach_msg)

    add_executable(test_process tests/test_process.cpp)
    target_link_libraries(test_process PRIVATE macosarm_macho)
    macosarm_enable_warnings(test_process)
    add_test(NAME process-runner COMMAND test_process)

    add_executable(test_session tests/test_session.cpp)
    target_link_libraries(test_session PRIVATE macosarm_macho)
    macosarm_enable_warnings(test_session)
    add_test(NAME macho-session-bootstrap COMMAND test_session)

    if(MACOSARM_ENABLE_DYNARMIC)
        add_executable(test_dynarmic tests/test_dynarmic.cpp)
        target_link_libraries(test_dynarmic PRIVATE macosarm_dynarmic)
        macosarm_enable_warnings(test_dynarmic)
        add_test(NAME dynarmic-arm64-jit COMMAND test_dynarmic)

        add_executable(test_session_dynarmic tests/test_session_dynarmic.cpp)
        target_link_libraries(test_session_dynarmic PRIVATE macosarm_dynarmic)
        macosarm_enable_warnings(test_session_dynarmic)
        add_test(NAME raw-macho-dynarmic-session COMMAND test_session_dynarmic)

        add_executable(test_program_vars_dynarmic tests/test_program_vars_dynarmic.cpp)
        target_link_libraries(test_program_vars_dynarmic PRIVATE macosarm_dynarmic)
        macosarm_enable_warnings(test_program_vars_dynarmic)
        add_test(
            NAME raw-macho-dynarmic-session-program-vars
            COMMAND test_program_vars_dynarmic)

        add_executable(test_mach_msg_dynarmic tests/test_mach_msg_dynarmic.cpp)
        target_link_libraries(test_mach_msg_dynarmic PRIVATE macosarm_dynarmic)
        macosarm_enable_warnings(test_mach_msg_dynarmic)
        add_test(NAME dynarmic-mach-msg-transport COMMAND test_mach_msg_dynarmic)
    endif()
endif()

if(BUILD_TESTING)
    add_executable(test_darwin_commpage tests/test_darwin_commpage.cpp)
    target_link_libraries(test_darwin_commpage PRIVATE macosarm_macho)
    macosarm_enable_warnings(test_darwin_commpage)
    add_test(NAME darwin-commpage-bootstrap COMMAND test_darwin_commpage)

    if(MACOSARM_ENABLE_DYNARMIC)
        add_executable(test_commpage_dynarmic tests/test_commpage_dynarmic.cpp)
        target_link_libraries(test_commpage_dynarmic PRIVATE macosarm_dynarmic)
        macosarm_enable_warnings(test_commpage_dynarmic)
        add_test(
            NAME raw-macho-dynarmic-session-commpage
            COMMAND test_commpage_dynarmic)
    endif()
endif()
