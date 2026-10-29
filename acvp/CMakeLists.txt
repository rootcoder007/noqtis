# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# The ACVP harnesses (see README.md): one program per algorithm family,
# on the library's internal interfaces, so they link the test library.
# Each vector set in tests/vectors/acvp/ is a test: the harness answers
# its prompt and compares the response with expectedResults.json.
set(NQACV acvsh acvhm acvdr acvmd acvsl acvmk)
foreach(h ${NQACV})
  add_executable(${h} ${h}.c acv.c)
  target_link_libraries(${h} PRIVATE nqint)
  target_include_directories(${h} PRIVATE ${PROJECT_SOURCE_DIR}/src)
  target_compile_options(${h} PRIVATE ${NQWARN})
endforeach()

# the harnesses are tools for a lab's host; the WebAssembly build runs
# the same vectors through tests/t*.c, within its job's time
if(EMSCRIPTEN)
  return()
endif()

set(NQAVEC ${PROJECT_SOURCE_DIR}/tests/vectors/acvp)
file(GLOB NQASETS RELATIVE ${NQAVEC} CONFIGURE_DEPENDS ${NQAVEC}/*)
foreach(s ${NQASETS})
  if(s MATCHES "^HMAC-")
    set(h acvhm)
  elseif(s MATCHES "^SHA|^SHAKE")
    set(h acvsh)
  elseif(s MATCHES "^hmacDRBG")
    set(h acvdr)
  elseif(s MATCHES "^ML-DSA")
    set(h acvmd)
  elseif(s MATCHES "^SLH-DSA")
    set(h acvsl)
  elseif(s MATCHES "^ML-KEM")
    set(h acvmk)
  else()
    continue()
  endif()
  add_test(NAME acvp-${s} COMMAND ${h} ${NQAVEC}/${s}/prompt.json
           ${CMAKE_CURRENT_BINARY_DIR}/${s}.json
           ${NQAVEC}/${s}/expectedResults.json)
  # the large-data hash tests (gigabytes) are left out here, as
  # tests/thash.c does; SLH-DSA signing answers every 32nd test (an "s"
  # signature takes seconds; tests/tslh.c checks every vector it runs)
  if(s MATCHES "^SLH-DSA-sigGen")
    set_tests_properties(acvp-${s} PROPERTIES ENVIRONMENT "NQSLSUB=32")
  elseif(h STREQUAL acvsh OR h STREQUAL acvsl)
    set_tests_properties(acvp-${s} PROPERTIES ENVIRONMENT "NQFAST=1")
  endif()
endforeach()
