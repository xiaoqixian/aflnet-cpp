# Date:   Fri Mar 28 11:19:01 AM 2025
# Mail:   lunar_ubuntu@qq.com
# Author: https://github.com/xiaoqixian

cmake_minimum_required(VERSION 3.14)
project(MyProject LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_COMPILER /usr/bin/clang++-18)
set(CMAKE_C_COMPILER /usr/bin/clang++-18)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

add_executable(afl-fuzz aflnet.cpp afl-fuzz.cpp)

foreach(TARGET afl-fuzz)
  target_compile_options(${TARGET} PRIVATE -Wall -Wextra -Wpedantic)
endforeach()
