cmake_minimum_required(VERSION 3.16)

# End-to-end check for one macho-run case, run by CTest as:
#   cmake -DFIXTURE_TOOL=<path> -DRUNNER=<path> -DKIND=<hello|argc>
#         -DIMAGE=<path> -DEXPECTED_EXIT=<n> [-DEXPECTED_STDOUT=<bytes>]
#         [-DRUNNER_ARGS="..."] [-DGUEST_ARGS="..."] -P macho_run_check.cmake
#
# Generates a raw ARM64 Mach-O with macho_run_fixture, runs it through
# macho-run, then compares the host exit status (the guest exit status after
# a clean guest exit) and the exact guest stdout. CTest's own pass/fail only
# distinguishes zero from nonzero, which cannot express "exit 7".
# RUNNER_ARGS and GUEST_ARGS are space-separated argument strings.

foreach(required IN ITEMS FIXTURE_TOOL RUNNER KIND IMAGE EXPECTED_EXIT)
    if(NOT DEFINED ${required} OR "${${required}}" STREQUAL "")
        message(FATAL_ERROR "macho_run_check: ${required} must be set")
    endif()
endforeach()

execute_process(
    COMMAND "${FIXTURE_TOOL}" "${KIND}" "${IMAGE}"
    RESULT_VARIABLE fixture_result
    OUTPUT_VARIABLE fixture_stdout
    ERROR_VARIABLE fixture_stderr)
if(NOT "${fixture_result}" STREQUAL "0")
    message(FATAL_ERROR
        "macho_run_check: fixture '${KIND}' generation failed (${fixture_result})\n"
        "${fixture_stderr}")
endif()

set(runner_args "")
if(DEFINED RUNNER_ARGS)
    separate_arguments(runner_args UNIX_COMMAND "${RUNNER_ARGS}")
endif()
set(guest_args "")
if(DEFINED GUEST_ARGS)
    separate_arguments(guest_args UNIX_COMMAND "${GUEST_ARGS}")
endif()

# Guest stdin comes from a file, never the CTest console: STDIN_TEXT is
# written verbatim, otherwise the file is empty and the guest sees end-of-file.
set(stdin_file "${IMAGE}.stdin")
if(DEFINED STDIN_TEXT)
    file(WRITE "${stdin_file}" "${STDIN_TEXT}")
else()
    file(WRITE "${stdin_file}" "")
endif()

# With STDOUT_TO_FILE set, guest stdout goes to a regular file, as a shell
# redirection would send it, and is read back for the EXPECTED_STDOUT
# comparison. Otherwise this script captures it directly.
set(stdout_capture OUTPUT_VARIABLE run_stdout)
if(STDOUT_TO_FILE)
    set(stdout_file "${IMAGE}.stdout")
    set(stdout_capture OUTPUT_FILE "${stdout_file}")
endif()

execute_process(
    COMMAND "${RUNNER}" ${runner_args} "${IMAGE}" ${guest_args}
    INPUT_FILE "${stdin_file}"
    ${stdout_capture}
    RESULT_VARIABLE run_result
    ERROR_VARIABLE run_stderr)
if(STDOUT_TO_FILE)
    file(READ "${stdout_file}" run_stdout)
endif()

if(NOT "${run_result}" STREQUAL "${EXPECTED_EXIT}")
    message(FATAL_ERROR
        "macho_run_check: '${KIND}' exited with '${run_result}', expected '${EXPECTED_EXIT}'\n"
        "stdout: [${run_stdout}]\n"
        "stderr: [${run_stderr}]")
endif()
if(DEFINED EXPECTED_STDOUT AND NOT "${run_stdout}" STREQUAL "${EXPECTED_STDOUT}")
    message(FATAL_ERROR
        "macho_run_check: '${KIND}' stdout was [${run_stdout}], expected [${EXPECTED_STDOUT}]\n"
        "stderr: [${run_stderr}]")
endif()

message(STATUS "macho_run_check: '${KIND}' exit=${run_result} stdout=[${run_stdout}]")
