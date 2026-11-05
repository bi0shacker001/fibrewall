# sandbox: a process sandbox library (seccomp lockdown + syscall broker).
# Copyright (C) 2026 the sandbox authors. GPL-3.0-or-later.
cmake_minimum_required(VERSION 3.18)
project(fibrewall VERSION 0.6.1 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

option(SBX_TESTS "Build the end-to-end test" ON)
option(SBX_SANITIZE "Build with AddressSanitizer and UndefinedBehaviorSanitizer" OFF)

if(WIN32)
  # Windows: an AppContainer and job object at spawn, and an explicit broker (docs/design.md, "Windows").
  # Built on its own (the test), the C runtime is linked in, so a confined program needs no runtime DLL
  # beside it. Inside another project the library takes that project's runtime (Rust's MSVC targets use
  # the DLL one, /MD), unless the project asks for the static one.
  if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
    set(SBX_TOP_LEVEL ON)
  else()
    set(SBX_TOP_LEVEL OFF)
  endif()
  option(SBX_MSVC_STATIC_RUNTIME "Link the MSVC C runtime statically (/MT)" ${SBX_TOP_LEVEL})
  if(SBX_MSVC_STATIC_RUNTIME)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
  endif()
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
    target_link_libraries(sbx_test_win PRIVATE sbx)
    if(MSVC)
      target_compile_options(sbx_test_win PRIVATE /W4 /WX /wd4204 /wd4221 /wd4127 /D_CRT_SECURE_NO_WARNINGS)
    else()
      target_compile_options(sbx_test_win PRIVATE -Wall -Wextra -Werror)
    endif()
  endif()
  return()
endif()

find_package(Threads REQUIRED)

add_library(sbx STATIC src/lockdown.c src/broker.c src/net.c src/zones.c src/spawn.c src/open.c src/attach.c src/contract.c)
target_include_directories(sbx PUBLIC include PRIVATE src)
target_link_libraries(sbx PUBLIC Threads::Threads)
target_compile_options(sbx PRIVATE -Wall -Wextra -Werror -fvisibility=hidden)
set_target_properties(sbx PROPERTIES POSITION_INDEPENDENT_CODE ON)

# libsbx_child.so: on LD_PRELOAD, each process of a tree attaches to the host's broker before main.
add_library(sbx_child SHARED src/child.c)
target_link_libraries(sbx_child PRIVATE sbx)
target_compile_options(sbx_child PRIVATE -Wall -Wextra -Werror)

# sbx-exec: static and freestanding, linked at a fixed address above 4 GB (docs/design.md, "SBX_LOCK_EXEC").
if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|AMD64|aarch64|arm64)$")
  add_executable(sbx-exec src/exec_helper.c)
  target_include_directories(sbx-exec PRIVATE src include)
  target_compile_options(sbx-exec PRIVATE -std=c11 -O2 -Wall -Wextra -Werror -ffreestanding -fno-builtin
                         -fno-stack-protector -fpie -fno-sanitize=all)
  # 256 MB above the trampoline page (src/exec_shared.h).
  if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|AMD64)$")
    set(SBX_EXEC_ADDRESS 0x200010000000)
  else()
    set(SBX_EXEC_ADDRESS 0x5c0000000)
  endif()
  if(ANDROID)
    set(SBX_EXEC_BASE -Wl,--image-base=${SBX_EXEC_ADDRESS})
  else()
    set(SBX_EXEC_BASE -Wl,-Ttext-segment=${SBX_EXEC_ADDRESS})
  endif()
  target_link_options(sbx-exec PRIVATE -nostdlib -static -Wl,-no-pie ${SBX_EXEC_BASE} -fno-sanitize=all)
endif()

if(SBX_SANITIZE)
  target_compile_options(sbx PUBLIC -fsanitize=address,undefined -fno-omit-frame-pointer)
  target_link_options(sbx PUBLIC -fsanitize=address,undefined)
endif()

if(SBX_TESTS)
  # The cost of confinement, for Droidtop/tracker#791: a measurement, not a gate.
  add_executable(sbx_bench tests/sbx_bench.c)
  target_link_libraries(sbx_bench PRIVATE sbx)
  target_compile_options(sbx_bench PRIVATE -Wall -Wextra -Werror -O2)
  add_executable(sbx_test tests/sbx_test.c)
  target_link_libraries(sbx_test PRIVATE sbx)
  # src/ for protocol.h: the broker-protocol harness builds requests in the real wire format.
  target_include_directories(sbx_test PRIVATE src)
  # Frame records in the test's own functions: the fault test walks them (fault_check).
  target_compile_options(sbx_test PRIVATE -Wall -Wextra -Werror -fno-omit-frame-pointer)
  # FFmpeg decoding under SBX_LOCK_COMPUTE (Droidtop/tracker#906), when FFmpeg's libraries are here.
  find_package(PkgConfig QUIET)
  if(PKG_CONFIG_FOUND)
    pkg_check_modules(SBX_FFMPEG QUIET IMPORTED_TARGET libavformat libavcodec libavutil)
    if(SBX_FFMPEG_FOUND)
      add_executable(sbx_decode_test tests/sbx_decode_test.c)
      target_link_libraries(sbx_decode_test PRIVATE sbx PkgConfig::SBX_FFMPEG)
      target_compile_options(sbx_decode_test PRIVATE -Wall -Wextra -Werror)
    endif()
  endif()
endif()

# The broker fuzz target (tests/fuzz_broker.c): clang's libFuzzer + ASan/UBSan on the request path.
# It includes broker.c to reach the static serve_one, so it does not link libsbx (that would double-define).
option(SBX_FUZZ "Build the broker libFuzzer target (clang only)" OFF)
if(SBX_FUZZ)
  add_executable(fuzz_broker tests/fuzz_broker.c src/net.c)
  target_include_directories(fuzz_broker PRIVATE src include)
  target_compile_options(fuzz_broker PRIVATE -g -O1 -fno-omit-frame-pointer -fsanitize=fuzzer,address,undefined)
  target_link_options(fuzz_broker PRIVATE -fsanitize=fuzzer,address,undefined)
  target_link_libraries(fuzz_broker PRIVATE Threads::Threads)
endif()

# The native-kind feasibility probe: GPU drawing from a locked-down process with no ART (Android only).
if(SBX_TESTS AND ANDROID)
  add_executable(gpu_probe tests/android/gpu_probe.c)
  target_link_libraries(gpu_probe PRIVATE sbx EGL GLESv2 nativewindow)
  target_compile_options(gpu_probe PRIVATE -Wall -Wextra -Werror)
endif()
