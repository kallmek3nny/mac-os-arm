cmake_minimum_required(VERSION 3.20)
project(mac_os_arm VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(macosarm_macho
    src/macho.cpp
)
target_include_directories(macosarm_macho PUBLIC include)
target_compile_options(macosarm_macho PRIVATE
    $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-Wall;-Wextra;-Wpedantic;-Werror>
    $<$<CXX_COMPILER_ID:MSVC>:/W4;/WX>
)

add_executable(macho-inspect src/macho_inspect.cpp)
target_link_libraries(macho-inspect PRIVATE macosarm_macho)

include(CTest)
if(BUILD_TESTING)
    add_executable(test_macho tests/test_macho.cpp)
    target_link_libraries(test_macho PRIVATE macosarm_macho)
    target_compile_options(test_macho PRIVATE
        $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-Wall;-Wextra;-Wpedantic;-Werror>
        $<$<CXX_COMPILER_ID:MSVC>:/W4;/WX>
    )
    add_test(NAME macho-parser COMMAND test_macho)
endif()
