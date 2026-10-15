cmake_minimum_required(VERSION 3.20)
project(mac_os_arm VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(macosarm_macho
    src/macho.cpp
    src/address_space.cpp
    src/image_loader.cpp
    src/execution.cpp
    src/darwin_syscall.cpp
)
target_include_directories(macosarm_macho PUBLIC include)
target_compile_options(macosarm_macho PRIVATE
    $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-Wall;-Wextra;-Wpedantic;-Werror>
    $<$<CXX_COMPILER_ID:MSVC>:/W4;/WX>
)

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
    target_compile_options(macosarm_dynarmic PRIVATE
        $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-Wall;-Wextra;-Wpedantic;-Werror>
        $<$<CXX_COMPILER_ID:MSVC>:/W4;/WX>
    )
endif()

include(CTest)
if(BUILD_TESTING)
    add_executable(test_macho tests/test_macho.cpp)
    target_link_libraries(test_macho PRIVATE macosarm_macho)
    target_compile_options(test_macho PRIVATE
        $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-Wall;-Wextra;-Wpedantic;-Werror>
        $<$<CXX_COMPILER_ID:MSVC>:/W4;/WX>
    )
    add_test(NAME macho-parser COMMAND test_macho)

    add_executable(test_address_space tests/test_address_space.cpp)
    target_link_libraries(test_address_space PRIVATE macosarm_macho)
    target_compile_options(test_address_space PRIVATE
        $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-Wall;-Wextra;-Wpedantic;-Werror>
        $<$<CXX_COMPILER_ID:MSVC>:/W4;/WX>
    )
    add_test(NAME guest-address-space COMMAND test_address_space)

    add_executable(test_image_loader tests/test_image_loader.cpp)
    target_link_libraries(test_image_loader PRIVATE macosarm_macho)
    target_compile_options(test_image_loader PRIVATE
        $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-Wall;-Wextra;-Wpedantic;-Werror>
        $<$<CXX_COMPILER_ID:MSVC>:/W4;/WX>
    )
    add_test(NAME image-loader COMMAND test_image_loader)

    add_executable(test_parse_load_integration tests/test_parse_load_integration.cpp)
    target_link_libraries(test_parse_load_integration PRIVATE macosarm_macho)
    target_compile_options(test_parse_load_integration PRIVATE
        $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-Wall;-Wextra;-Wpedantic;-Werror>
        $<$<CXX_COMPILER_ID:MSVC>:/W4;/WX>
    )
    add_test(NAME parse-load-integration COMMAND test_parse_load_integration)

    add_executable(test_execution tests/test_execution.cpp)
    target_link_libraries(test_execution PRIVATE macosarm_macho)
    target_compile_options(test_execution PRIVATE
        $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-Wall;-Wextra;-Wpedantic;-Werror>
        $<$<CXX_COMPILER_ID:MSVC>:/W4;/WX>
    )
    add_test(NAME execution-contract COMMAND test_execution)

    add_executable(test_darwin_syscall tests/test_darwin_syscall.cpp)
    target_link_libraries(test_darwin_syscall PRIVATE macosarm_macho)
    target_compile_options(test_darwin_syscall PRIVATE
        $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-Wall;-Wextra;-Wpedantic;-Werror>
        $<$<CXX_COMPILER_ID:MSVC>:/W4;/WX>
    )
    add_test(NAME darwin-syscall-dispatch COMMAND test_darwin_syscall)

    if(MACOSARM_ENABLE_DYNARMIC)
        add_executable(test_dynarmic tests/test_dynarmic.cpp)
        target_link_libraries(test_dynarmic PRIVATE macosarm_dynarmic)
        target_compile_options(test_dynarmic PRIVATE
            $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-Wall;-Wextra;-Wpedantic;-Werror>
            $<$<CXX_COMPILER_ID:MSVC>:/W4;/WX>
        )
        add_test(NAME dynarmic-arm64-jit COMMAND test_dynarmic)
    endif()
endif()
