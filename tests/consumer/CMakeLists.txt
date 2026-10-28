# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Builds use.c against an installed noqtis found with find_package:
#   cmake -S tests/consumer -B b -DCMAKE_PREFIX_PATH=<prefix>
cmake_minimum_required(VERSION 3.20)
project(nqconsumer LANGUAGES C)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
find_package(noqtis 0.1 CONFIG REQUIRED)
add_executable(use use.c)
target_link_libraries(use PRIVATE noqtis::noqtis)
