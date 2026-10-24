cmake_minimum_required(VERSION 3.20)
project(mac_os_arm VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

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

    # Runs a raw ARM64 Mach-O through the Dynarmic session. Only guest stdout
    # and stderr reach the host; every other descriptor reports EBADF.
    add_executable(macho-run src/macho_run.cpp)
    target_link_libraries(macho-run PRIVATE macosarm_dynarmic)
    # The console host serves guest getentropy(2) from BCryptGenRandom on
    # Windows; other hosts use libc getentropy and need no extra library.
    if(WIN32)
        target_link_libraries(macho-run PRIVATE bcrypt)
    endif()
    target_compile_options(macho-run PRIVATE
        $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-Wall;-Wextra;-Wpedantic;-Werror>
        $<$<CXX_COMPILER_ID:MSVC>:/W4;/WX>
    )
    # MinGW: no executable that links the JIT backend (macho-run and every
    # Dynarmic test) may resolve libstdc++-6.dll or libgcc_s_seh-1.dll from
    # PATH at load time. If PATH finds an older, ABI-incompatible copy first
    # (for example Git's mingw64/bin), the executable fails to start with
    # STATUS_ENTRYPOINT_NOT_FOUND (0xc0000139) under CTest. INTERFACE link
    # options carry over to the link step of each consumer.
    if(MINGW)
        target_link_options(macosarm_dynarmic INTERFACE -static-libstdc++ -static-libgcc)
    endif()
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

    add_executable(test_dyld_paths tests/test_dyld_paths.cpp)
    target_link_libraries(test_dyld_paths PRIVATE macosarm_macho)
    target_compile_options(test_dyld_paths PRIVATE
        $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-Wall;-Wextra;-Wpedantic;-Werror>
        $<$<CXX_COMPILER_ID:MSVC>:/W4;/WX>
    )
    add_test(NAME dyld-path-resolution COMMAND test_dyld_paths)

    add_executable(test_dyld_dependencies tests/test_dyld_dependencies.cpp)
    target_link_libraries(test_dyld_dependencies PRIVATE macosarm_macho)
    target_compile_options(test_dyld_dependencies PRIVATE
        $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-Wall;-Wextra;-Wpedantic;-Werror>
        $<$<CXX_COMPILER_ID:MSVC>:/W4;/WX>
    )
    add_test(NAME dyld-dependency-planning COMMAND test_dyld_dependencies)

    add_executable(test_dyld_exports tests/test_dyld_exports.cpp)
    target_link_libraries(test_dyld_exports PRIVATE macosarm_macho)
    target_compile_options(test_dyld_exports PRIVATE
        $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-Wall;-Wextra;-Wpedantic;-Werror>
        $<$<CXX_COMPILER_ID:MSVC>:/W4;/WX>
    )
    add_test(NAME dyld-exports-trie COMMAND test_dyld_exports)

    add_executable(test_dyld_graph tests/test_dyld_graph.cpp)
    target_link_libraries(test_dyld_graph PRIVATE macosarm_macho)
    target_compile_options(test_dyld_graph PRIVATE
        $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-Wall;-Wextra;-Wpedantic;-Werror>
        $<$<CXX_COMPILER_ID:MSVC>:/W4;/WX>
    )
    add_test(NAME dyld-loaded-image-graph COMMAND test_dyld_graph)

    add_executable(test_dyld_symbols tests/test_dyld_symbols.cpp)
    target_link_libraries(test_dyld_symbols PRIVATE macosarm_macho)
    target_compile_options(test_dyld_symbols PRIVATE
        $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-Wall;-Wextra;-Wpedantic;-Werror>
        $<$<CXX_COMPILER_ID:MSVC>:/W4;/WX>
    )
    add_test(NAME dyld-symbol-resolution COMMAND test_dyld_symbols)

    add_executable(test_dyld_fixups tests/test_dyld_fixups.cpp)
    target_link_libraries(test_dyld_fixups PRIVATE macosarm_macho)
    target_compile_options(test_dyld_fixups PRIVATE
        $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-Wall;-Wextra;-Wpedantic;-Werror>
        $<$<CXX_COMPILER_ID:MSVC>:/W4;/WX>
    )
    add_test(NAME dyld-chained-fixups-metadata COMMAND test_dyld_fixups)

    add_executable(test_dyld_fixup_apply tests/test_dyld_fixup_apply.cpp)
    target_link_libraries(test_dyld_fixup_apply PRIVATE macosarm_macho)
    target_compile_options(test_dyld_fixup_apply PRIVATE
        $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-Wall;-Wextra;-Wpedantic;-Werror>
        $<$<CXX_COMPILER_ID:MSVC>:/W4;/WX>
    )
    add_test(NAME dyld-generic-chained-fixup-apply COMMAND test_dyld_fixup_apply)

    add_executable(test_dyld_fixup_arm64e tests/test_dyld_fixup_arm64e.cpp)
    target_link_libraries(test_dyld_fixup_arm64e PRIVATE macosarm_macho)
    target_compile_options(test_dyld_fixup_arm64e PRIVATE
        $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-Wall;-Wextra;-Wpedantic;-Werror>
        $<$<CXX_COMPILER_ID:MSVC>:/W4;/WX>
    )
    add_test(NAME dyld-arm64e-chained-fixup-apply COMMAND test_dyld_fixup_arm64e)

    add_executable(test_dyld_fixup_pauth tests/test_dyld_fixup_pauth.cpp)
    target_link_libraries(test_dyld_fixup_pauth PRIVATE macosarm_macho)
    target_compile_options(test_dyld_fixup_pauth PRIVATE
        $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-Wall;-Wextra;-Wpedantic;-Werror>
        $<$<CXX_COMPILER_ID:MSVC>:/W4;/WX>
    )
    add_test(NAME dyld-authenticated-arm64e-fixup-apply COMMAND test_dyld_fixup_pauth)

    add_executable(test_pointer_auth tests/test_pointer_auth.cpp)
    target_link_libraries(test_pointer_auth PRIVATE macosarm_macho)
    target_compile_options(test_pointer_auth PRIVATE
        $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-Wall;-Wextra;-Wpedantic;-Werror>
        $<$<CXX_COMPILER_ID:MSVC>:/W4;/WX>
    )
    add_test(NAME pointer-auth-policy COMMAND test_pointer_auth)

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

    add_executable(test_mach_trap tests/test_mach_trap.cpp)
    target_link_libraries(test_mach_trap PRIVATE macosarm_macho)
    target_compile_options(test_mach_trap PRIVATE
        $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-Wall;-Wextra;-Wpedantic;-Werror>
        $<$<CXX_COMPILER_ID:MSVC>:/W4;/WX>
    )
    add_test(NAME mach-trap-dispatch COMMAND test_mach_trap)

    add_executable(test_mach_msg tests/test_mach_msg.cpp)
    target_link_libraries(test_mach_msg PRIVATE macosarm_macho)
    target_compile_options(test_mach_msg PRIVATE
        $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-Wall;-Wextra;-Wpedantic;-Werror>
        $<$<CXX_COMPILER_ID:MSVC>:/W4;/WX>
    )
    add_test(NAME mach-msg-transport COMMAND test_mach_msg)

    add_executable(test_process tests/test_process.cpp)
    target_link_libraries(test_process PRIVATE macosarm_macho)
    target_compile_options(test_process PRIVATE
        $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-Wall;-Wextra;-Wpedantic;-Werror>
        $<$<CXX_COMPILER_ID:MSVC>:/W4;/WX>
    )
    add_test(NAME process-runner COMMAND test_process)

    add_executable(test_session tests/test_session.cpp)
    target_link_libraries(test_session PRIVATE macosarm_macho)
    target_compile_options(test_session PRIVATE
        $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-Wall;-Wextra;-Wpedantic;-Werror>
        $<$<CXX_COMPILER_ID:MSVC>:/W4;/WX>
    )
    add_test(NAME macho-session-bootstrap COMMAND test_session)

    if(MACOSARM_ENABLE_DYNARMIC)
        add_executable(test_dynarmic tests/test_dynarmic.cpp)
        target_link_libraries(test_dynarmic PRIVATE macosarm_dynarmic)
        target_compile_options(test_dynarmic PRIVATE
            $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-Wall;-Wextra;-Wpedantic;-Werror>
            $<$<CXX_COMPILER_ID:MSVC>:/W4;/WX>
        )
        add_test(NAME dynarmic-arm64-jit COMMAND test_dynarmic)

        add_executable(test_session_dynarmic tests/test_session_dynarmic.cpp)
        target_link_libraries(test_session_dynarmic PRIVATE macosarm_dynarmic)
        target_compile_options(test_session_dynarmic PRIVATE
            $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-Wall;-Wextra;-Wpedantic;-Werror>
            $<$<CXX_COMPILER_ID:MSVC>:/W4;/WX>
        )
        add_test(NAME raw-macho-dynarmic-session COMMAND test_session_dynarmic)

        add_executable(test_program_vars_dynarmic tests/test_program_vars_dynarmic.cpp)
        target_link_libraries(test_program_vars_dynarmic PRIVATE macosarm_dynarmic)
        target_compile_options(test_program_vars_dynarmic PRIVATE
            $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-Wall;-Wextra;-Wpedantic;-Werror>
            $<$<CXX_COMPILER_ID:MSVC>:/W4;/WX>
        )
        add_test(
            NAME raw-macho-dynarmic-session-program-vars
            COMMAND test_program_vars_dynarmic)

        add_executable(test_mach_msg_dynarmic tests/test_mach_msg_dynarmic.cpp)
        target_link_libraries(test_mach_msg_dynarmic PRIVATE macosarm_dynarmic)
        target_compile_options(test_mach_msg_dynarmic PRIVATE
            $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-Wall;-Wextra;-Wpedantic;-Werror>
            $<$<CXX_COMPILER_ID:MSVC>:/W4;/WX>
        )
        add_test(NAME dynarmic-mach-msg-transport COMMAND test_mach_msg_dynarmic)

        # End-to-end macho-run checks. The fixture tool writes a raw ARM64
        # Mach-O; macho_run_check.cmake runs it through macho-run and compares
        # the exact guest exit status and stdout bytes.
        add_executable(macho_run_fixture tests/macho_run_fixture.cpp)
        target_compile_options(macho_run_fixture PRIVATE
            $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-Wall;-Wextra;-Wpedantic;-Werror>
            $<$<CXX_COMPILER_ID:MSVC>:/W4;/WX>
        )
        # MinGW: an ABI-incompatible libstdc++-6.dll found earlier on PATH
        # (for example Git's mingw64/bin) crashes the generator inside
        # std::ofstream. Link the GCC runtime statically so the fixture does
        # not depend on whichever runtime DLL the PATH resolves first.
        if(MINGW)
            target_link_options(macho_run_fixture PRIVATE -static-libstdc++ -static-libgcc)
        endif()
        add_test(
            NAME macho-run-hello-exit-status
            COMMAND "${CMAKE_COMMAND}"
                "-DFIXTURE_TOOL=$<TARGET_FILE:macho_run_fixture>"
                "-DRUNNER=$<TARGET_FILE:macho-run>"
                -DKIND=hello
                "-DIMAGE=${CMAKE_CURRENT_BINARY_DIR}/macho-run-hello.bin"
                -DEXPECTED_EXIT=7
                -DEXPECTED_STDOUT=hello
                -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/macho_run_check.cmake")
        add_test(
            NAME macho-run-guest-argc
            COMMAND "${CMAKE_COMMAND}"
                "-DFIXTURE_TOOL=$<TARGET_FILE:macho_run_fixture>"
                "-DRUNNER=$<TARGET_FILE:macho-run>"
                -DKIND=argc
                "-DIMAGE=${CMAKE_CURRENT_BINARY_DIR}/macho-run-argc.bin"
                "-DGUEST_ARGS=one two"
                -DEXPECTED_EXIT=3
                -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/macho_run_check.cmake")
        # Guest stdin is a file that macho_run_check.cmake writes next to
        # IMAGE, so each stdin test needs its own IMAGE path. The echo fixture
        # reads once, writes back exactly the bytes received and exits with
        # that count; a failed read exits 100.
        add_test(
            NAME macho-run-stdin-echo
            COMMAND "${CMAKE_COMMAND}"
                "-DFIXTURE_TOOL=$<TARGET_FILE:macho_run_fixture>"
                "-DRUNNER=$<TARGET_FILE:macho-run>"
                -DKIND=echo
                "-DIMAGE=${CMAKE_CURRENT_BINARY_DIR}/macho-run-echo.bin"
                -DSTDIN_TEXT=ping
                -DEXPECTED_EXIT=4
                -DEXPECTED_STDOUT=ping
                -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/macho_run_check.cmake")
        # Empty stdin is end-of-file: read succeeds with 0 bytes, not an errno.
        add_test(
            NAME macho-run-stdin-eof
            COMMAND "${CMAKE_COMMAND}"
                "-DFIXTURE_TOOL=$<TARGET_FILE:macho_run_fixture>"
                "-DRUNNER=$<TARGET_FILE:macho-run>"
                -DKIND=echo
                "-DIMAGE=${CMAKE_CURRENT_BINARY_DIR}/macho-run-echo-eof.bin"
                -DEXPECTED_EXIT=0
                -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/macho_run_check.cmake")
        # close(2) end to end: once the guest closes stdout, its write fails
        # with EBADF, so the guest exits 9 and no byte reaches the host stdout.
        # A failed close exits 100 and a write that still succeeds exits 101.
        add_test(
            NAME macho-run-close-stdout
            COMMAND "${CMAKE_COMMAND}"
                "-DFIXTURE_TOOL=$<TARGET_FILE:macho_run_fixture>"
                "-DRUNNER=$<TARGET_FILE:macho-run>"
                -DKIND=close-stdout
                "-DIMAGE=${CMAKE_CURRENT_BINARY_DIR}/macho-run-close-stdout.bin"
                -DEXPECTED_EXIT=9
                "-DEXPECTED_STDOUT="
                -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/macho_run_check.cmake")
        # fstat64(2) end to end: macho_run_check.cmake always redirects guest
        # stdin from a file, so the guest exits with its S_IFREG file type
        # (st_mode >> 12 == 8) and writes nothing. A failed fstat64 exits 100,
        # so an errno cannot pass for a file type.
        add_test(
            NAME macho-run-fstat-stdin
            COMMAND "${CMAKE_COMMAND}"
                "-DFIXTURE_TOOL=$<TARGET_FILE:macho_run_fixture>"
                "-DRUNNER=$<TARGET_FILE:macho-run>"
                -DKIND=fstat-stdin
                "-DIMAGE=${CMAKE_CURRENT_BINARY_DIR}/macho-run-fstat-stdin.bin"
                -DEXPECTED_EXIT=8
                "-DEXPECTED_STDOUT="
                -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/macho_run_check.cmake")
        # ioctl(2) end to end: macho_run_check.cmake always redirects guest
        # stdin from a file, so the TIOCGETA probe behind isatty(3) fails with
        # ENOTTY and the guest exits 25 without writing. An ioctl that succeeds
        # exits 101, so a fabricated terminal cannot pass for ENOTTY.
        add_test(
            NAME macho-run-ioctl-stdin
            COMMAND "${CMAKE_COMMAND}"
                "-DFIXTURE_TOOL=$<TARGET_FILE:macho_run_fixture>"
                "-DRUNNER=$<TARGET_FILE:macho-run>"
                -DKIND=ioctl-stdin
                "-DIMAGE=${CMAKE_CURRENT_BINARY_DIR}/macho-run-ioctl-stdin.bin"
                -DEXPECTED_EXIT=25
                "-DEXPECTED_STDOUT="
                -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/macho_run_check.cmake")

        # writev(1, iov, 3) gathers {"hel", 3}, {"hello", 0} and {"lo", 2} into
        # the host stdout, so the guest writes "hello", skips the empty middle
        # vector and exits with the 5-byte total. A failed writev exits 100, so
        # an errno cannot pass for a byte count.
        add_test(
            NAME macho-run-writev-stdout
            COMMAND "${CMAKE_COMMAND}"
                "-DFIXTURE_TOOL=$<TARGET_FILE:macho_run_fixture>"
                "-DRUNNER=$<TARGET_FILE:macho-run>"
                -DKIND=writev-stdout
                "-DIMAGE=${CMAKE_CURRENT_BINARY_DIR}/macho-run-writev-stdout.bin"
                -DEXPECTED_EXIT=5
                "-DEXPECTED_STDOUT=hello"
                -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/macho_run_check.cmake")

        # readv(0, iov, 3) scatters the 4-byte stdin "ping" as "pi" into
        # buffer + 2, skips the empty middle vector without touching its base
        # and stores "ng" at buffer, so the guest writes back "ngpi" and exits
        # with the 4-byte total, short of the 5 bytes requested. A failed readv
        # exits 100, so an errno cannot pass for a byte count.
        add_test(
            NAME macho-run-readv-stdin
            COMMAND "${CMAKE_COMMAND}"
                "-DFIXTURE_TOOL=$<TARGET_FILE:macho_run_fixture>"
                "-DRUNNER=$<TARGET_FILE:macho-run>"
                -DKIND=readv-stdin
                "-DIMAGE=${CMAKE_CURRENT_BINARY_DIR}/macho-run-readv-stdin.bin"
                -DSTDIN_TEXT=ping
                -DEXPECTED_EXIT=4
                "-DEXPECTED_STDOUT=ngpi"
                -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/macho_run_check.cmake")

        # lseek(0, -3, SEEK_END) on the 8-byte stdin file "seekable" lands at
        # offset 5, so the following read resumes there, the guest writes back
        # "ble" and exits with that offset. A failed lseek exits 100 and a
        # failed read exits 101, so neither errno can pass for an offset.
        add_test(
            NAME macho-run-lseek-stdin
            COMMAND "${CMAKE_COMMAND}"
                "-DFIXTURE_TOOL=$<TARGET_FILE:macho_run_fixture>"
                "-DRUNNER=$<TARGET_FILE:macho-run>"
                -DKIND=lseek-stdin
                "-DIMAGE=${CMAKE_CURRENT_BINARY_DIR}/macho-run-lseek-stdin.bin"
                -DSTDIN_TEXT=seekable
                -DEXPECTED_EXIT=5
                "-DEXPECTED_STDOUT=ble"
                -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/macho_run_check.cmake")

        # pread(0, buffer, 3, 4) on the 10-byte stdin file "positioned" copies
        # "tio" from offset 4 without moving the file offset, so the read that
        # follows still starts at offset 0 and returns the whole file. The guest
        # writes back "tiopositioned" and exits with the 3-byte pread count. A
        # failed pread exits 100 and a failed read exits 101, so neither errno
        # can pass for a count.
        add_test(
            NAME macho-run-pread-stdin
            COMMAND "${CMAKE_COMMAND}"
                "-DFIXTURE_TOOL=$<TARGET_FILE:macho_run_fixture>"
                "-DRUNNER=$<TARGET_FILE:macho-run>"
                -DKIND=pread-stdin
                "-DIMAGE=${CMAKE_CURRENT_BINARY_DIR}/macho-run-pread-stdin.bin"
                -DSTDIN_TEXT=positioned
                -DEXPECTED_EXIT=3
                "-DEXPECTED_STDOUT=tiopositioned"
                -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/macho_run_check.cmake")

        # fcntl(2) end to end: the guest's stdin starts without FD_CLOEXEC, so
        # F_GETFD reports 0, F_SETFD sets it and the next F_GETFD reports 1.
        # macho_run_check.cmake captures guest stdout through a pipe opened
        # without O_APPEND, so F_GETFL on stdout reports O_WRONLY (1). The guest
        # exits with before << 6 | after << 4 | getfl == 17 and writes nothing.
        # Each failed fcntl exits with its own status from 100 to 103, so no
        # errno can pass for a flag word.
        add_test(
            NAME macho-run-fcntl-stdio
            COMMAND "${CMAKE_COMMAND}"
                "-DFIXTURE_TOOL=$<TARGET_FILE:macho_run_fixture>"
                "-DRUNNER=$<TARGET_FILE:macho-run>"
                -DKIND=fcntl-stdio
                "-DIMAGE=${CMAKE_CURRENT_BINARY_DIR}/macho-run-fcntl-stdio.bin"
                -DEXPECTED_EXIT=17
                "-DEXPECTED_STDOUT="
                -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/macho_run_check.cmake")

        # fcntl(2) F_SETFL end to end: handing stdout's F_GETFL flags back to
        # F_SETFL changes nothing and succeeds with 0, while asking for
        # O_NONBLOCK fails with ENOTSUP (45) because macho-run's standard
        # streams only do blocking I/O. A second F_GETFL proves the flags are
        # still O_WRONLY (1), as the pipe macho_run_check.cmake opens is not
        # O_APPEND. The guest exits with getfl << 6 | errno == 109 and writes
        # nothing; every other outcome exits with its own status from 100 to
        # 104.
        add_test(
            NAME macho-run-fcntl-setfl-stdio
            COMMAND "${CMAKE_COMMAND}"
                "-DFIXTURE_TOOL=$<TARGET_FILE:macho_run_fixture>"
                "-DRUNNER=$<TARGET_FILE:macho-run>"
                -DKIND=fcntl-setfl-stdio
                "-DIMAGE=${CMAKE_CURRENT_BINARY_DIR}/macho-run-fcntl-setfl-stdio.bin"
                -DEXPECTED_EXIT=109
                "-DEXPECTED_STDOUT="
                -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/macho_run_check.cmake")

        # getrlimit(2) end to end: RLIMIT_STACK reports macho-run's fixed 8 MiB
        # main-thread stack mapping as both the soft and the hard limit, while
        # RLIMIT_NOFILE fails with ENOSYS (78) because macho-run enforces no
        # descriptor limit. The guest exits with that errno and writes nothing;
        # every other outcome exits with its own status from 100 to 103.
        add_test(
            NAME macho-run-getrlimit-stack
            COMMAND "${CMAKE_COMMAND}"
                "-DFIXTURE_TOOL=$<TARGET_FILE:macho_run_fixture>"
                "-DRUNNER=$<TARGET_FILE:macho-run>"
                -DKIND=getrlimit-stack
                "-DIMAGE=${CMAKE_CURRENT_BINARY_DIR}/macho-run-getrlimit-stack.bin"
                -DEXPECTED_EXIT=78
                "-DEXPECTED_STDOUT="
                -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/macho_run_check.cmake")

        # setrlimit(2) end to end: restating macho-run's fixed 8 MiB RLIMIT_STACK
        # limits succeeds, lowering the soft limit fails with EINVAL because the
        # main-thread stack mapping cannot shrink, and raising both limits fails
        # with EPERM because the synthetic user is not root. Neither failure
        # changes the limits. RLIMIT_NOFILE fails with ENOSYS (78), so the guest
        # exits 78 and writes nothing; every other outcome exits from 100 to 108.
        add_test(
            NAME macho-run-setrlimit-stack
            COMMAND "${CMAKE_COMMAND}"
                "-DFIXTURE_TOOL=$<TARGET_FILE:macho_run_fixture>"
                "-DRUNNER=$<TARGET_FILE:macho-run>"
                -DKIND=setrlimit-stack
                "-DIMAGE=${CMAKE_CURRENT_BINARY_DIR}/macho-run-setrlimit-stack.bin"
                -DEXPECTED_EXIT=78
                "-DEXPECTED_STDOUT="
                -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/macho_run_check.cmake")

        # getdtablesize(2) end to end: the call reports the soft RLIMIT_NOFILE
        # limit, and macho-run enforces no descriptor limit, so it fails with
        # ENOSYS (78) exactly as getrlimit(RLIMIT_NOFILE) does. The guest exits
        # with that errno and writes nothing; a getdtablesize that succeeds
        # exits 100, so no table size can pass for the errno.
        add_test(
            NAME macho-run-getdtablesize
            COMMAND "${CMAKE_COMMAND}"
                "-DFIXTURE_TOOL=$<TARGET_FILE:macho_run_fixture>"
                "-DRUNNER=$<TARGET_FILE:macho-run>"
                -DKIND=getdtablesize
                "-DIMAGE=${CMAKE_CURRENT_BINARY_DIR}/macho-run-getdtablesize.bin"
                -DEXPECTED_EXIT=78
                "-DEXPECTED_STDOUT="
                -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/macho_run_check.cmake")
    endif()
endif()

if(BUILD_TESTING)
    add_executable(test_darwin_commpage tests/test_darwin_commpage.cpp)
    target_link_libraries(test_darwin_commpage PRIVATE macosarm_macho)
    target_compile_options(test_darwin_commpage PRIVATE
        $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-Wall;-Wextra;-Wpedantic;-Werror>
        $<$<CXX_COMPILER_ID:MSVC>:/W4;/WX>
    )
    add_test(NAME darwin-commpage-bootstrap COMMAND test_darwin_commpage)

    if(MACOSARM_ENABLE_DYNARMIC)
        add_executable(test_commpage_dynarmic tests/test_commpage_dynarmic.cpp)
        target_link_libraries(test_commpage_dynarmic PRIVATE macosarm_dynarmic)
        target_compile_options(test_commpage_dynarmic PRIVATE
            $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-Wall;-Wextra;-Wpedantic;-Werror>
            $<$<CXX_COMPILER_ID:MSVC>:/W4;/WX>
        )
        add_test(
            NAME raw-macho-dynarmic-session-commpage
            COMMAND test_commpage_dynarmic)
    endif()
endif()
