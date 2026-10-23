# sandbox: a process sandbox library (seccomp lockdown + syscall broker).
# Copyright (C) 2026 the sandbox authors. GPL-3.0-or-later.
cmake_minimum_required(VERSION 3.18)
project(sandbox C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

option(SBX_TESTS "Build the end-to-end test" ON)
option(SBX_SANITIZE "Build with AddressSanitizer and UndefinedBehaviorSanitizer" OFF)

if(WIN32)
  # Windows: an AppContainer and job object at spawn, and an explicit broker (docs/design.md, "Windows").
  # The C runtime is linked in, so a confined program needs no runtime DLL beside it.
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
  add_library(sbx STATIC src/windows.c src/windows_client.c)
  target_include_directories(sbx PUBLIC include PRIVATE src)
  target_link_libraries(sbx PUBLIC userenv advapi32 ntdll)
  if(MSVC)
    target_compile_options(sbx PRIVATE /W4 /WX /wd4204 /wd4221 /wd4127 /D_CRT_SECURE_NO_WARNINGS)
  else()
    target_compile_options(sbx PRIVATE -Wall -Wextra -Werror)
  endif()
  if(SBX_TESTS)
    add_executable(sbx_test_win tests/sbx_test_win.c)
    target_link_libraries(sbx_test_win PRIVATE sbx ws2_32)
    if(MSVC)
      target_compile_options(sbx_test_win PRIVATE /W4 /WX /wd4204 /wd4221 /wd4127 /D_CRT_SECURE_NO_WARNINGS)
    else()
      target_compile_options(sbx_test_win PRIVATE -Wall -Wextra -Werror)
    endif()
  endif()
  return()
endif()

find_package(Threads REQUIRED)

add_library(sbx STATIC src/lockdown.c src/broker.c src/spawn.c src/open.c src/attach.c)
target_include_directories(sbx PUBLIC include PRIVATE src)
target_link_libraries(sbx PUBLIC Threads::Threads)
target_compile_options(sbx PRIVATE -Wall -Wextra -Werror -fvisibility=hidden)
set_target_properties(sbx PROPERTIES POSITION_INDEPENDENT_CODE ON)

# libsbx_child.so: on LD_PRELOAD, each process of a tree attaches to the host's broker before main.
add_library(sbx_child SHARED src/child.c)
target_link_libraries(sbx_child PRIVATE sbx)
target_compile_options(sbx_child PRIVATE -Wall -Wextra -Werror)

if(SBX_SANITIZE)
  target_compile_options(sbx PUBLIC -fsanitize=address,undefined -fno-omit-frame-pointer)
  target_link_options(sbx PUBLIC -fsanitize=address,undefined)
endif()

if(SBX_TESTS)
  add_executable(sbx_test tests/sbx_test.c)
  target_link_libraries(sbx_test PRIVATE sbx)
  target_compile_options(sbx_test PRIVATE -Wall -Wextra -Werror)
endif()

# The native-kind feasibility probe: GPU drawing from a locked-down process with no ART (Android only).
if(SBX_TESTS AND ANDROID)
  add_executable(gpu_probe tests/android/gpu_probe.c)
  target_link_libraries(gpu_probe PRIVATE sbx EGL GLESv2 nativewindow)
  target_compile_options(gpu_probe PRIVATE -Wall -Wextra -Werror)
endif()
