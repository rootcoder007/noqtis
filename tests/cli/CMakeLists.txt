# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Black-box tests of the noqtis tool: tcli runs it as a user would and
# checks exit codes, outputs and files. Plain C, so it runs on Windows too.
add_executable(tcli tcli.c)
target_compile_options(tcli PRIVATE ${NQWARN})
add_dependencies(tcli nqcli tsad)
# tsad: a local RFC 3161 TSA over HTTP, so seal --tsa needs no network
add_executable(tsad tsad.c)
target_compile_options(tsad PRIVATE ${NQWARN})
if(WIN32)
  target_link_libraries(tsad PRIVATE ws2_32)
endif()
add_test(NAME tcli COMMAND tcli $<TARGET_FILE:nqcli> $<TARGET_FILE:tsad>
         ${PROJECT_SOURCE_DIR}/tests
         WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
# the shell completions parse and offer every command and option the
# manual pages list
if(NOT WIN32)
  add_test(NAME comp COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/comp.sh
           ${PROJECT_SOURCE_DIR})
endif()
# a sanitizer report must not pass for the "invalid" exit status 1
set_tests_properties(tcli PROPERTIES
  ENVIRONMENT
  "ASAN_OPTIONS=exitcode=86;UBSAN_OPTIONS=exitcode=86:print_stacktrace=1"
  TIMEOUT 900)
# tbl: interop with rmoriebricklayer, live, both ways (tests/interop/
# run.sh); skipped (exit 77) without Rscript and the R package
if(NOT WIN32)
  add_test(NAME tbl COMMAND sh ${PROJECT_SOURCE_DIR}/tests/interop/run.sh
           $<TARGET_FILE:nqcli> ${PROJECT_SOURCE_DIR}/tests)
  set_tests_properties(tbl PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 900)
endif()
