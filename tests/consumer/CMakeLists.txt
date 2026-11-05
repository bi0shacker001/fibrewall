# A consumer of the library, as droidtop-agent is (Droidtop/tracker#606): it adds the library with
# add_subdirectory and builds with the DLL C runtime (/MD), CMake's default. The library must never force
# /MT on a consumer (70d69f8): a runtime mismatch fails this link (LNK2038).
# Copyright (C) 2026 the sandbox authors. GPL-3.0-or-later.
cmake_minimum_required(VERSION 3.18)
project(sbx_consumer C)
set(SBX_TESTS OFF CACHE BOOL "" FORCE)
add_subdirectory(../.. fibrewall)
add_executable(sbx_consumer consumer.c)
target_link_libraries(sbx_consumer PRIVATE sbx)
