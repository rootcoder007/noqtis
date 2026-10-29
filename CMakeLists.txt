# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
cmake_minimum_required(VERSION 3.20)
project(noqtis VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

option(NQWERROR "Treat warnings as errors" ON)
option(NQSAN "Build with AddressSanitizer and UBSan" OFF)
option(NQTESTS "Build the tests" ON)
option(NQSHARED "Build a shared library instead of a static one" OFF)
option(NQCLI "Build the noqtis command-line tool" ON)
option(NQCT "Build the dudect and TVLA harnesses in ct/" OFF)
option(NQTVLA "Compile the TVLA leakage hooks (a test build, never a release)" OFF)

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

if(NQSAN AND NOT MSVC)
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer
                      -fno-sanitize-recover=all)
  add_link_options(-fsanitize=address,undefined)
endif()

# every module is a folder under src/; its .c files make up the library.
# They compile once, as objects with every symbol hidden except those
# noqtis.h marks NQAPI; the installed library and the test library are
# both made from these objects.
file(GLOB NQSRC CONFIGURE_DEPENDS ${PROJECT_SOURCE_DIR}/src/*/*.c)
add_library(nqobj OBJECT ${NQSRC})
target_include_directories(nqobj
  PUBLIC ${PROJECT_SOURCE_DIR}/include
  PRIVATE ${PROJECT_SOURCE_DIR}/src)
target_compile_options(nqobj PRIVATE ${NQWARN})
target_compile_definitions(nqobj PRIVATE NQBUILD)
if(NQTVLA)
  target_compile_definitions(nqobj PRIVATE NQTVLA)
endif()
set_target_properties(nqobj PROPERTIES
  C_VISIBILITY_PRESET hidden
  POSITION_INDEPENDENT_CODE ${NQSHARED})
if(NQSHARED AND WIN32)
  target_compile_definitions(nqobj PRIVATE NQDLL)
endif()

if(NQSHARED)
  add_library(noqtis SHARED $<TARGET_OBJECTS:nqobj>)
  set_target_properties(noqtis PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR})
  if(WIN32)
    # noqtis-0.dll beside the noqtis.lib import library
    set_target_properties(noqtis PROPERTIES PREFIX ""
      RUNTIME_OUTPUT_NAME noqtis-${PROJECT_VERSION_MAJOR})
    target_compile_definitions(noqtis INTERFACE NQDLL)
  endif()
else()
  add_library(noqtis STATIC $<TARGET_OBJECTS:nqobj>)
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
  # they link a static library made from the same objects
  if(NQSHARED)
    add_library(nqint STATIC $<TARGET_OBJECTS:nqobj>)
    target_include_directories(nqint PUBLIC ${PROJECT_SOURCE_DIR}/include)
    if(WIN32)
      target_link_libraries(nqint PUBLIC bcrypt)
    endif()
  else()
    add_library(nqint ALIAS noqtis)
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
    add_test(NAME ${name} COMMAND ${name}
             WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/tests)
  endforeach()
  # the consumer program against the library as built (shared or static),
  # through the public header only
  add_executable(nquse tests/consumer/use.c)
  target_link_libraries(nquse PRIVATE noqtis)
  target_compile_options(nquse PRIVATE ${NQWARN})
  add_test(NAME nquse COMMAND nquse)
  # the ACVP harnesses, each run on the vector sets in tests/vectors/acvp
  add_subdirectory(acvp)
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
