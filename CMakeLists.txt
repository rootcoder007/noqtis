# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
cmake_minimum_required(VERSION 3.20)
project(noqtis VERSION 0.1.1 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
# WASI: wasm-ld gives a program 64 KiB of stack, less than ML-DSA (masked)
# and HQC use; programs linked here get 8 MiB, as the npm build does
if(CMAKE_SYSTEM_NAME STREQUAL "WASI")
  add_link_options(-Wl,-z,stack-size=8388608)
endif()
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

option(NQWERROR "Treat warnings as errors" ON)
option(NQSAN "Build with AddressSanitizer and UBSan" OFF)
option(NQTESTS "Build the tests" ON)
option(NQSHARED "Build a shared library instead of a static one" OFF)
option(NQCLI "Build the noqtis command-line tool" ON)
option(NQCT "Build the dudect and TVLA harnesses in ct/" OFF)
option(NQTVLA "Compile the TVLA leakage hooks (a test build, never a release)" OFF)
# the TLS 1.3 client (src/tls) in the public API (nqtl*) and the tool's
# https:// URLs; off until it has been reviewed: nqtl* then return
# NQENOSUP, and the tests reach the client through its internal API
option(NQTLS "Enable the TLS 1.3 client (not yet reviewed)" OFF)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

if(WIN32)
  # fopen() and sscanf() are ISO C; MSVC's "use the _s variant" deprecation
  # would otherwise fail the build under /WX
  add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
endif()

if(MSVC)
  set(NQWARN /W4)
  if(NQWERROR)
    list(APPEND NQWARN /WX)
  endif()
else()
  set(NQWARN -Wall -Wextra -Wpedantic -Wconversion -Wshadow
      -Wstrict-prototypes -Wcast-qual -Wvla -Wmissing-prototypes)
  if(NQWERROR)
    list(APPEND NQWARN -Werror)
  endif()
endif()

if(NQTLS)
  add_compile_definitions(NQTLSON)
endif()

if(NQSAN AND NOT MSVC)
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer
                      -fno-sanitize-recover=all)
  add_link_options(-fsanitize=address,undefined)
endif()

# every module is a folder under src/; its .c files make up the library.
# They compile once, as objects with every symbol hidden except those
# noqtis.h marks NQAPI; the installed library and the test library are
# both made from these objects.
# src/tls compiles twice: for the library, and with NQTEST (its test
# hooks, src/tls/tls.h) for the test library alone.
file(GLOB NQSRC CONFIGURE_DEPENDS ${PROJECT_SOURCE_DIR}/src/*/*.c)
file(GLOB NQTLSRC CONFIGURE_DEPENDS ${PROJECT_SOURCE_DIR}/src/tls/*.c)
list(REMOVE_ITEM NQSRC ${NQTLSRC})
function(nqobjlib name)
  add_library(${name} OBJECT ${ARGN})
  target_include_directories(${name}
    PUBLIC ${PROJECT_SOURCE_DIR}/include
    PRIVATE ${PROJECT_SOURCE_DIR}/src)
  target_compile_options(${name} PRIVATE ${NQWARN})
  target_compile_definitions(${name} PRIVATE NQBUILD)
  if(NQTVLA)
    target_compile_definitions(${name} PRIVATE NQTVLA)
  endif()
  set_target_properties(${name} PROPERTIES
    C_VISIBILITY_PRESET hidden
    POSITION_INDEPENDENT_CODE ${NQSHARED})
  if(NQSHARED AND WIN32)
    target_compile_definitions(${name} PRIVATE NQDLL)
  endif()
endfunction()
nqobjlib(nqobj ${NQSRC})
nqobjlib(nqtl ${NQTLSRC})

if(NQSHARED)
  add_library(noqtis SHARED $<TARGET_OBJECTS:nqobj> $<TARGET_OBJECTS:nqtl>)
  set_target_properties(noqtis PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR})
  # ELF: symbol versions from src/noqtis.map (macOS and Windows have none)
  include(CheckLinkerFlag)
  set(NQMAP ${PROJECT_SOURCE_DIR}/src/noqtis.map)
  check_linker_flag(C "-Wl,--version-script=${NQMAP}" NQHAVEMAP)
  if(NQHAVEMAP AND NOT APPLE AND NOT WIN32)
    target_link_options(noqtis PRIVATE "-Wl,--version-script=${NQMAP}")
    set_property(TARGET noqtis APPEND PROPERTY LINK_DEPENDS ${NQMAP})
  endif()
  if(WIN32)
    # noqtis-0.dll beside the noqtis.lib import library
    set_target_properties(noqtis PROPERTIES PREFIX ""
      RUNTIME_OUTPUT_NAME noqtis-${PROJECT_VERSION_MAJOR})
    target_compile_definitions(noqtis INTERFACE NQDLL)
  endif()
else()
  add_library(noqtis STATIC $<TARGET_OBJECTS:nqobj> $<TARGET_OBJECTS:nqtl>)
endif()
add_library(noqtis::noqtis ALIAS noqtis)
target_include_directories(noqtis PUBLIC
  $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
if(WIN32)
  target_link_libraries(noqtis PRIVATE bcrypt)
endif()

# the command-line tool (cli/), on the public API only
if(NQCLI)
  add_subdirectory(cli)
endif()

if(NQTESTS)
  enable_testing()
  # the tests call internal functions, which a shared library hides, so
  # they link a static library made from the same objects, with src/tls
  # built with its test hooks (NQTEST)
  nqobjlib(nqtlt ${NQTLSRC})
  target_compile_definitions(nqtlt PRIVATE NQTEST)
  add_library(nqint STATIC $<TARGET_OBJECTS:nqobj> $<TARGET_OBJECTS:nqtlt>)
  target_include_directories(nqint PUBLIC ${PROJECT_SOURCE_DIR}/include)
  if(WIN32)
    target_link_libraries(nqint PUBLIC bcrypt)
  endif()
  # one executable per tests/t*.c
  file(GLOB NQTSRC CONFIGURE_DEPENDS ${PROJECT_SOURCE_DIR}/tests/t*.c)
  foreach(t ${NQTSRC})
    get_filename_component(name ${t} NAME_WE)
    add_executable(${name} ${t})
    target_link_libraries(${name} PRIVATE nqint)
    target_include_directories(${name} PRIVATE ${PROJECT_SOURCE_DIR}/src
                               ${PROJECT_SOURCE_DIR}/tests)
    target_compile_options(${name} PRIVATE ${NQWARN})
    target_compile_definitions(${name} PRIVATE NQTEST)
    if(CMAKE_SYSTEM_NAME STREQUAL "WASI")
      # the tests time loops with clock(), which wasi-libc emulates
      target_compile_definitions(${name} PRIVATE _WASI_EMULATED_PROCESS_CLOCKS)
      target_link_libraries(${name} PRIVATE wasi-emulated-process-clocks)
    endif()
    add_test(NAME ${name} COMMAND ${name}
             WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/tests)
  endforeach()
  # the consumer program against the library as built (shared or static),
  # through the public header only
  add_executable(nquse tests/consumer/use.c)
  target_link_libraries(nquse PRIVATE noqtis)
  target_compile_options(nquse PRIVATE ${NQWARN})
  add_test(NAME nquse COMMAND nquse)
  # the cross-check against OpenSSL 3.5 or later (tests/ossl), where it
  # is found: the same keys, signatures, ciphertexts and digests
  # off by default on Windows, where a found OpenSSL may be built for
  # another architecture (the x64 one on the ARM64 runners)
  if(WIN32)
    set(NQOSSLDEF OFF)
  else()
    set(NQOSSLDEF ON)
  endif()
  option(NQOSSL "cross-check against OpenSSL 3.5 when it is found" ${NQOSSLDEF})
  if(NQOSSL)
    find_package(OpenSSL 3.5 QUIET COMPONENTS Crypto)
    if(OpenSSL_FOUND)
      add_executable(xossl tests/ossl/xossl.c)
      target_link_libraries(xossl PRIVATE nqint OpenSSL::Crypto)
      target_include_directories(xossl PRIVATE ${PROJECT_SOURCE_DIR}/src
                                 ${PROJECT_SOURCE_DIR}/tests)
      target_compile_options(xossl PRIVATE ${NQWARN})
      add_test(NAME xossl COMMAND xossl)
      message(STATUS "noqtis: cross-check against OpenSSL ${OPENSSL_VERSION}")
    endif()
  endif()
  # the ACVP harnesses, each run on the vector sets in tests/vectors/acvp
  add_subdirectory(acvp)
  # the TLS client against OpenSSL's s_server on the loopback
  # (tests/tls/srv.sh): OpenSSL is the peer only, never linked; skipped
  # (77) without OpenSSL 3.5 or later
  if(NOT WIN32 AND NOT EMSCRIPTEN AND NOT CMAKE_SYSTEM_NAME STREQUAL "WASI")
    add_executable(tlcli tests/tls/tlcli.c)
    target_link_libraries(tlcli PRIVATE nqint)
    target_include_directories(tlcli PRIVATE ${PROJECT_SOURCE_DIR}/src)
    target_compile_options(tlcli PRIVATE ${NQWARN})
    target_compile_definitions(tlcli PRIVATE NQTEST)
    # the tool's HTTP client (cli/net.c, included by tlget.c)
    set(NQTLGET "")
    if(NQCLI)
      add_executable(tlget tests/tls/tlget.c cli/io.c)
      target_link_libraries(tlget PRIVATE noqtis)
      set(THREADS_PREFER_PTHREAD_FLAG ON)
      find_package(Threads REQUIRED)
      target_link_libraries(tlget PRIVATE Threads::Threads)
      target_include_directories(tlget PRIVATE ${PROJECT_SOURCE_DIR}/cli)
      target_compile_options(tlget PRIVATE ${NQWARN})
      if(NQTLS)
        set(NQTLGET $<TARGET_FILE:tlget> on)
      else()
        set(NQTLGET $<TARGET_FILE:tlget> off)
      endif()
      # public HTTPS servers, only with NQNET=1 in the environment
      add_test(NAME tlnet COMMAND sh ${PROJECT_SOURCE_DIR}/tests/tls/net.sh
               $<TARGET_FILE:tlcli> $<TARGET_FILE:tlget>)
      set_tests_properties(tlnet PROPERTIES SKIP_RETURN_CODE 77)
    endif()
    find_program(NQOSSLBIN openssl)
    if(NQOSSLBIN)
      add_test(NAME tlsrv COMMAND sh ${PROJECT_SOURCE_DIR}/tests/tls/srv.sh
               $<TARGET_FILE:tlcli> ${NQTLGET})
      set_tests_properties(tlsrv PROPERTIES SKIP_RETURN_CODE 77
                           ENVIRONMENT OPENSSL=${NQOSSLBIN})
    endif()
  endif()
  # tcli runs the tool as a child process, which emscripten cannot do
  if(NQCLI AND NOT EMSCRIPTEN)
    add_subdirectory(tests/cli)
  endif()
endif()

# the side-channel harnesses (ct/), on the static library
if(NQCT)
  add_subdirectory(ct)
endif()

# ---- install ----------------------------------------------------------

install(TARGETS noqtis EXPORT noqtisTargets
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES include/noqtis.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

# noqtis.pc finds ${prefix} from its own place (pcfiledir) when the install
# dirs are relative, so `cmake --install --prefix` and a moved tree work
set(NQPCPRE "${CMAKE_INSTALL_PREFIX}")
if(NOT IS_ABSOLUTE "${CMAKE_INSTALL_LIBDIR}")
  file(RELATIVE_PATH NQPCUP "/nq/${CMAKE_INSTALL_LIBDIR}/pkgconfig" "/nq")
  string(REGEX REPLACE "/$" "" NQPCUP "${NQPCUP}")
  set(NQPCPRE "\${pcfiledir}/${NQPCUP}")
endif()
set(NQPCLIB "\${prefix}/${CMAKE_INSTALL_LIBDIR}")
set(NQPCINC "\${prefix}/${CMAKE_INSTALL_INCLUDEDIR}")
if(IS_ABSOLUTE "${CMAKE_INSTALL_LIBDIR}")
  set(NQPCLIB "${CMAKE_INSTALL_LIBDIR}")
endif()
if(IS_ABSOLUTE "${CMAKE_INSTALL_INCLUDEDIR}")
  set(NQPCINC "${CMAKE_INSTALL_INCLUDEDIR}")
endif()
set(NQPCDEF "")
set(NQPCPRIV "")
if(WIN32)
  set(NQPCPRIV "-lbcrypt")
  if(NQSHARED)
    set(NQPCDEF " -DNQDLL")
  endif()
endif()
configure_file(cmake/noqtis.pc.in noqtis.pc @ONLY)
install(FILES ${PROJECT_BINARY_DIR}/noqtis.pc
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)

# find_package(noqtis CONFIG) gives noqtis::noqtis
set(NQCMDIR ${CMAKE_INSTALL_LIBDIR}/cmake/noqtis)
install(EXPORT noqtisTargets NAMESPACE noqtis:: DESTINATION ${NQCMDIR})
configure_package_config_file(cmake/noqtisConfig.cmake.in
  ${PROJECT_BINARY_DIR}/noqtisConfig.cmake INSTALL_DESTINATION ${NQCMDIR})
write_basic_package_version_file(${PROJECT_BINARY_DIR}/noqtisConfigVersion.cmake
  COMPATIBILITY SameMinorVersion)
install(FILES ${PROJECT_BINARY_DIR}/noqtisConfig.cmake
  ${PROJECT_BINARY_DIR}/noqtisConfigVersion.cmake DESTINATION ${NQCMDIR})

# the manual pages (man/), installed by docs/CMakeLists.txt
option(NQMAN "Install the manual pages" ON)
if(NQMAN)
  add_subdirectory(docs)
endif()
