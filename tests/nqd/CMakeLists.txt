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
  add_test(NAME ${name} COMMAND ${name}
           WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/tests)
endforeach()
