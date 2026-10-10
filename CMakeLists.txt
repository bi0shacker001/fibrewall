# sandbox: a process sandbox library (seccomp lockdown + syscall broker).
# Copyright (C) 2026 the sandbox authors. GPL-3.0-or-later.
cmake_minimum_required(VERSION 3.18)
project(sandbox C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

option(SBX_TESTS "Build the end-to-end test" ON)
option(SBX_SANITIZE "Build with AddressSanitizer and UndefinedBehaviorSanitizer" OFF)

find_package(Threads REQUIRED)

add_library(sbx STATIC src/lockdown.c src/broker.c)
target_include_directories(sbx PUBLIC include PRIVATE src)
target_link_libraries(sbx PUBLIC Threads::Threads)
target_compile_options(sbx PRIVATE -Wall -Wextra -Werror -fvisibility=hidden)
set_target_properties(sbx PROPERTIES POSITION_INDEPENDENT_CODE ON)

if(SBX_SANITIZE)
  target_compile_options(sbx PUBLIC -fsanitize=address,undefined -fno-omit-frame-pointer)
  target_link_options(sbx PUBLIC -fsanitize=address,undefined)
endif()

if(SBX_TESTS)
  add_executable(sbx_test tests/sbx_test.c)
  target_link_libraries(sbx_test PRIVATE sbx)
  target_compile_options(sbx_test PRIVATE -Wall -Wextra -Werror)
endif()
