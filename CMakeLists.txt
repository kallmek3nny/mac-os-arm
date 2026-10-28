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
macosarm_enable_warnings(macho-inspect)
# MinGW: macho-inspect prints its report through libstdc++ iostreams. If PATH
# resolves an older, ABI-incompatible libstdc++-6.dll first (for example Git's
# mingw64/bin), the tool segfaults instead of printing. Link the GCC runtime
# statically so it behaves the same from any shell.
if(MINGW)
    target_link_options(macho-inspect PRIVATE -static-libstdc++ -static-libgcc)
endif()

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

    # Runs a raw ARM64 Mach-O through the Dynarmic session. Only guest stdout
    # and stderr reach the host; every other descriptor reports EBADF.
    add_executable(macho-run src/macho_run.cpp)
    target_link_libraries(macho-run PRIVATE macosarm_dynarmic)
    # The console host serves guest getentropy(2) from BCryptGenRandom on
    # Windows; other hosts use libc getentropy and need no extra library.
    if(WIN32)
        target_link_libraries(macho-run PRIVATE bcrypt)
    endif()
    macosarm_enable_warnings(macho-run)
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

        # End-to-end macho-run checks. The fixture tool writes a raw ARM64
        # Mach-O; macho_run_check.cmake runs it through macho-run and compares
        # the exact guest exit status and stdout bytes.
        add_executable(macho_run_fixture tests/macho_run_fixture.cpp)
        macosarm_enable_warnings(macho_run_fixture)
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
        # main-thread stack mapping as both the soft and the hard limit, and
        # RLIMIT_NOFILE reports RLIM_INFINITY as both because the sparse
        # descriptor table bounds descriptors only by the int range. The guest
        # exits with the top byte of RLIM_INFINITY, 127, and writes nothing;
        # every other outcome exits with its own status from 100 to 104.
        add_test(
            NAME macho-run-getrlimit-stack
            COMMAND "${CMAKE_COMMAND}"
                "-DFIXTURE_TOOL=$<TARGET_FILE:macho_run_fixture>"
                "-DRUNNER=$<TARGET_FILE:macho-run>"
                -DKIND=getrlimit-stack
                "-DIMAGE=${CMAKE_CURRENT_BINARY_DIR}/macho-run-getrlimit-stack.bin"
                -DEXPECTED_EXIT=127
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
        # limit capped at INT_MAX, and macho-run reports RLIM_INFINITY for it
        # because the sparse descriptor table bounds descriptors only by the
        # int range, so the call returns INT_MAX. The guest exits with its top
        # byte, 127, and writes nothing; a failed getdtablesize exits 100 and
        # any other table size exits 101, so no errno can pass for INT_MAX.
        add_test(
            NAME macho-run-getdtablesize
            COMMAND "${CMAKE_COMMAND}"
                "-DFIXTURE_TOOL=$<TARGET_FILE:macho_run_fixture>"
                "-DRUNNER=$<TARGET_FILE:macho-run>"
                -DKIND=getdtablesize
                "-DIMAGE=${CMAKE_CURRENT_BINARY_DIR}/macho-run-getdtablesize.bin"
                -DEXPECTED_EXIT=127
                "-DEXPECTED_STDOUT="
                -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/macho_run_check.cmake")

        # dup(2) end to end: dup(1) takes the lowest free descriptor, 3, which
        # still writes "hello" to the host stdout after the guest closes 1, and
        # duplicating it again reuses the freed slot 1. The guest exits with
        # the first copy << 4 | the second, so a correct host exits 49; a
        # failed dup, close, write or second dup exits 100 to 103 instead.
        add_test(
            NAME macho-run-dup-stdout
            COMMAND "${CMAKE_COMMAND}"
                "-DFIXTURE_TOOL=$<TARGET_FILE:macho_run_fixture>"
                "-DRUNNER=$<TARGET_FILE:macho-run>"
                -DKIND=dup-stdout
                "-DIMAGE=${CMAKE_CURRENT_BINARY_DIR}/macho-run-dup-stdout.bin"
                -DEXPECTED_EXIT=49
                -DEXPECTED_STDOUT=hello
                -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/macho_run_check.cmake")

        # dup2(2) end to end: dup2(1, 9) names 9 even though only 0 to 2 are
        # open, since macho-run enforces no RLIMIT_NOFILE limit, and that copy
        # writes "hel" after the guest closes 1. dup2(9, 9) returns 9 and
        # changes nothing, and dup2(9, 1) reopens 1 onto the same stream,
        # which writes "lo" after the guest closes 9. The guest exits with
        # the copy << 4 | the reopened descriptor, so a correct host exits 145;
        # a failed call along the way exits 100 to 106 instead.
        add_test(
            NAME macho-run-dup2-stdout
            COMMAND "${CMAKE_COMMAND}"
                "-DFIXTURE_TOOL=$<TARGET_FILE:macho_run_fixture>"
                "-DRUNNER=$<TARGET_FILE:macho-run>"
                -DKIND=dup2-stdout
                "-DIMAGE=${CMAKE_CURRENT_BINARY_DIR}/macho-run-dup2-stdout.bin"
                -DEXPECTED_EXIT=145
                -DEXPECTED_STDOUT=hello
                -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/macho_run_check.cmake")

        # fcntl(2) F_DUPFD end to end: fcntl(1, F_DUPFD, 5) names 5, the lowest
        # free descriptor at or above newmin while only 0 to 2 are open, and a
        # negative newmin fails with EINVAL. That copy writes "hel" after the
        # guest closes 1, and fcntl(5, F_DUPFD_CLOEXEC, 0) then reuses slot 1
        # with its own close-on-exec flag set while 5 keeps its flag clear.
        # The reused 1 writes "lo" after the guest closes 5, and the guest
        # exits with the copy << 4 | the reused descriptor, so a correct host
        # exits 81; a failed call along the way exits 100 to 106 instead.
        add_test(
            NAME macho-run-fcntl-dupfd-stdout
            COMMAND "${CMAKE_COMMAND}"
                "-DFIXTURE_TOOL=$<TARGET_FILE:macho_run_fixture>"
                "-DRUNNER=$<TARGET_FILE:macho-run>"
                -DKIND=fcntl-dupfd-stdout
                "-DIMAGE=${CMAKE_CURRENT_BINARY_DIR}/macho-run-fcntl-dupfd-stdout.bin"
                -DEXPECTED_EXIT=81
                -DEXPECTED_STDOUT=hello
                -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/macho_run_check.cmake")

        # ioctl(2) FIOCLEX and FIONCLEX end to end: FIOCLEX sets stdout's own
        # close-on-exec flag, so F_GETFD reports FD_CLOEXEC while stdout still
        # writes "hel", and the dup(2) copy, 3, starts with its flag clear.
        # FIONCLEX clears stdout's flag again. stdin, redirected from a file
        # and so no terminal, accepts FIOCLEX too, as XNU acts on the file
        # table entry before the device sees it, while ioctl(9, FIOCLEX) fails
        # with EBADF (9) because 9 is not open. The copy writes "lo" and the
        # guest exits with the copy << 4 | that errno, so a correct host exits
        # 57; a failed call or wrong flag along the way exits 100 to 107.
        add_test(
            NAME macho-run-ioctl-fioclex-stdio
            COMMAND "${CMAKE_COMMAND}"
                "-DFIXTURE_TOOL=$<TARGET_FILE:macho_run_fixture>"
                "-DRUNNER=$<TARGET_FILE:macho-run>"
                -DKIND=ioctl-fioclex-stdio
                "-DIMAGE=${CMAKE_CURRENT_BINARY_DIR}/macho-run-ioctl-fioclex-stdio.bin"
                -DEXPECTED_EXIT=57
                -DEXPECTED_STDOUT=hello
                -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/macho_run_check.cmake")

        # ioctl(2) FIONBIO and FIOASYNC end to end: macho-run's standard
        # streams only do blocking, ordinary I/O, so turning either mode on
        # for stdout fails with ENOTSUP (45) and leaves F_GETFL as it was,
        # while turning either mode off succeeds with 0 on stdout and on
        # stdin, which is no terminal. ioctl(9, FIONBIO) fails with EBADF (9)
        # because 9 is not open, and a NULL argument fails with EFAULT (14)
        # even for descriptor 9, as XNU copies the int in before it resolves
        # the descriptor. The pipe macho_run_check.cmake opens is not
        # O_APPEND, so F_GETFL reports O_WRONLY (1). The guest writes "hello"
        # and exits with getfl << 6 | errno, so a correct host exits 109; a
        # failed call or wrong result along the way exits 100 to 108.
        add_test(
            NAME macho-run-ioctl-fionbio-stdio
            COMMAND "${CMAKE_COMMAND}"
                "-DFIXTURE_TOOL=$<TARGET_FILE:macho_run_fixture>"
                "-DRUNNER=$<TARGET_FILE:macho-run>"
                -DKIND=ioctl-fionbio-stdio
                "-DIMAGE=${CMAKE_CURRENT_BINARY_DIR}/macho-run-ioctl-fionbio-stdio.bin"
                -DEXPECTED_EXIT=109
                -DEXPECTED_STDOUT=hello
                -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/macho_run_check.cmake")

        # fcntl(2) F_SETNOSIGPIPE and F_GETNOSIGPIPE end to end: FG_NOSIGPIPE
        # belongs to the open file description, so setting it on stdout shows
        # through a dup(2) copy while stderr keeps its own flag clear, and an
        # arg whose int low half is 0 clears it again through the copy.
        # fcntl(9, F_SETNOSIGPIPE) fails with EBADF (9) because 9 is not open.
        # The guest writes "hello" through the copy, descriptor 3, and exits
        # with nosigpipe << 6 | copy << 4 | errno, so a correct host exits
        # 121; a failed call or wrong result along the way exits 100 to 108.
        add_test(
            NAME macho-run-fcntl-nosigpipe-stdio
            COMMAND "${CMAKE_COMMAND}"
                "-DFIXTURE_TOOL=$<TARGET_FILE:macho_run_fixture>"
                "-DRUNNER=$<TARGET_FILE:macho-run>"
                -DKIND=fcntl-nosigpipe-stdio
                "-DIMAGE=${CMAKE_CURRENT_BINARY_DIR}/macho-run-fcntl-nosigpipe-stdio.bin"
                -DEXPECTED_EXIT=121
                -DEXPECTED_STDOUT=hello
                -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/macho_run_check.cmake")

        # fsync(2), fsync_nocancel and fdatasync(2) end to end: with stdout
        # redirected to a regular file, fsync(1) and fdatasync(1) flush it
        # through the host and succeed with 0, as does fsync_nocancel through
        # the dup(2) copy, 3, that names the same file. stderr reaches
        # macho_run_check.cmake through a pipe or socket, neither of which
        # names a vnode, so fsync(2) on it fails with ENOTSUP (45), and once
        # the guest closes the copy fdatasync on it fails with EBADF (9). The
        # guest writes "hello" and exits with copy << 6 | the ENOTSUP errno,
        # so a correct host exits 237; a failed call or wrong result along the
        # way exits 100 to 107 instead.
        add_test(
            NAME macho-run-fsync-stdio
            COMMAND "${CMAKE_COMMAND}"
                "-DFIXTURE_TOOL=$<TARGET_FILE:macho_run_fixture>"
                "-DRUNNER=$<TARGET_FILE:macho-run>"
                -DKIND=fsync-stdio
                "-DIMAGE=${CMAKE_CURRENT_BINARY_DIR}/macho-run-fsync-stdio.bin"
                -DSTDOUT_TO_FILE=ON
                -DEXPECTED_EXIT=237
                -DEXPECTED_STDOUT=hello
                -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/macho_run_check.cmake")
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
