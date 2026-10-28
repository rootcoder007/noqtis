cmake_minimum_required(VERSION 3.20)
project(noqtis VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

option(NQWERROR "Treat warnings as errors" ON)
option(NQSAN "Build with AddressSanitizer and UBSan" OFF)
option(NQTESTS "Build the tests" ON)

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

# every module is a folder under src/; its .c files make up the library
file(GLOB NQSRC CONFIGURE_DEPENDS ${PROJECT_SOURCE_DIR}/src/*/*.c)
add_library(noqtis ${NQSRC})
target_include_directories(noqtis
  PUBLIC ${PROJECT_SOURCE_DIR}/include
  PRIVATE ${PROJECT_SOURCE_DIR}/src)
target_compile_options(noqtis PRIVATE ${NQWARN})
if(WIN32)
  target_link_libraries(noqtis PRIVATE bcrypt)
endif()

if(NQSAN AND NOT MSVC)
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer
                      -fno-sanitize-recover=all)
  add_link_options(-fsanitize=address,undefined)
  target_compile_options(noqtis PRIVATE -fsanitize=address,undefined
                         -fno-omit-frame-pointer -fno-sanitize-recover=all)
  target_link_options(noqtis PUBLIC -fsanitize=address,undefined)
endif()

if(NQTESTS)
  enable_testing()
  # one executable per tests/t*.c
  file(GLOB NQTSRC CONFIGURE_DEPENDS ${PROJECT_SOURCE_DIR}/tests/t*.c)
  foreach(t ${NQTSRC})
    get_filename_component(name ${t} NAME_WE)
    add_executable(${name} ${t})
    target_link_libraries(${name} PRIVATE noqtis)
    target_include_directories(${name} PRIVATE ${PROJECT_SOURCE_DIR}/src
                               ${PROJECT_SOURCE_DIR}/tests)
    target_compile_options(${name} PRIVATE ${NQWARN})
    add_test(NAME ${name} COMMAND ${name}
             WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/tests)
  endforeach()
endif()
