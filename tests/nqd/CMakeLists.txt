# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Tests of the data layer: C tests that compile nqd's sources with the
# test (so they reach its internals in a shared build too), and the
# tool's data commands from a POSIX shell (tests/nqd/cli.sh).
file(GLOB NQDSRC CONFIGURE_DEPENDS ${PROJECT_SOURCE_DIR}/nqd/*.c)
file(GLOB NQDTST CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/t*.c)
foreach(t ${NQDTST})
  get_filename_component(name ${t} NAME_WE)
  add_executable(${name} ${t} ${NQDSRC})
  target_link_libraries(${name} PRIVATE noqtis)
  if(NOT WIN32)
    target_link_libraries(${name} PRIVATE m)
  endif()
  target_include_directories(${name} PRIVATE ${PROJECT_SOURCE_DIR}
                             ${PROJECT_SOURCE_DIR}/tests)
  target_compile_options(${name} PRIVATE ${NQWARN})
  if(IOS)
    # as the tests of the library: simctl spawn starts a program in /, so
    # tests/cwd.c is main, moves to $NQCWD and calls the test's own main
    target_sources(${name} PRIVATE ${PROJECT_SOURCE_DIR}/tests/cwd.c)
    set_source_files_properties(${t} PROPERTIES
      COMPILE_DEFINITIONS main=nqmain
      COMPILE_OPTIONS -Wno-missing-prototypes)
    file(STRINGS ${t} nqmv REGEX "^int main\\(void\\)")
    if(nqmv)
      target_compile_definitions(${name} PRIVATE NQMAINV)
    endif()
  endif()
  add_test(NAME ${name} COMMAND ${name}
           WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/tests)
endforeach()
if(NQCLI AND NOT WIN32 AND NOT EMSCRIPTEN)
  # the tool again with its test hooks (NQTEST): -r swaps a folder for a
  # link between the walk and the run (cli/io.c, nctswap)
  file(GLOB NQCSRC CONFIGURE_DEPENDS ${PROJECT_SOURCE_DIR}/cli/*.c)
  add_executable(nqclit ${NQCSRC})
  target_compile_definitions(nqclit PRIVATE NQTEST)
  target_link_libraries(nqclit PRIVATE nqd noqtis)
  set(THREADS_PREFER_PTHREAD_FLAG ON)
  find_package(Threads REQUIRED)
  target_link_libraries(nqclit PRIVATE Threads::Threads)
  target_compile_options(nqclit PRIVATE ${NQWARN})
  add_test(NAME tdcli COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/cli.sh
           $<TARGET_FILE:nqcli> ${PROJECT_SOURCE_DIR}/tests
           $<TARGET_FILE:nqclit>)
  set_tests_properties(tdcli PROPERTIES
    ENVIRONMENT
    "ASAN_OPTIONS=exitcode=86;UBSAN_OPTIONS=exitcode=86:print_stacktrace=1"
    TIMEOUT 600)
endif()
