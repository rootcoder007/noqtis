# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Black-box tests of the noqtis tool: tcli runs it as a user would and
# checks exit codes, outputs and files. Plain C, so it runs on Windows too.
add_executable(tcli tcli.c)
target_compile_options(tcli PRIVATE ${NQWARN})
add_dependencies(tcli nqcli)
add_test(NAME tcli COMMAND tcli $<TARGET_FILE:nqcli>
         WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
# a sanitizer report must not pass for the "invalid" exit status 1
set_tests_properties(tcli PROPERTIES
  ENVIRONMENT
  "ASAN_OPTIONS=exitcode=86;UBSAN_OPTIONS=exitcode=86:print_stacktrace=1"
  TIMEOUT 900)
