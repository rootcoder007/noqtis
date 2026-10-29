# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# The side-channel harnesses (-DNQCT=ON): nqdd, the dudect timing test,
# and, in a build with -DNQTVLA=ON, nqtv, the simulated TVLA. They are not
# ctest tests: they run for minutes and a timing verdict depends on the
# machine. Both call internal functions, so they need the static library.
if(NQSHARED)
  message(FATAL_ERROR "NQCT needs the static library: set NQSHARED=OFF")
endif()

add_executable(nqdd dd.c ${PROJECT_SOURCE_DIR}/cli/b64.c)
target_link_libraries(nqdd PRIVATE noqtis)
target_include_directories(nqdd PRIVATE ${PROJECT_SOURCE_DIR}/src
                           ${PROJECT_SOURCE_DIR}/cli)
target_compile_options(nqdd PRIVATE ${NQWARN})

if(NQTVLA)
  add_executable(nqtv tv.c)
  target_link_libraries(nqtv PRIVATE noqtis)
  target_include_directories(nqtv PRIVATE ${PROJECT_SOURCE_DIR}/src)
  target_compile_definitions(nqtv PRIVATE NQTVLA)
  target_compile_options(nqtv PRIVATE ${NQWARN})
endif()

if(NOT MSVC)
  target_link_libraries(nqdd PRIVATE m)
  if(NQTVLA)
    target_link_libraries(nqtv PRIVATE m)
  endif()
endif()
