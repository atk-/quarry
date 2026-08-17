cmake_minimum_required(VERSION 3.20)
project(quarry_hooks C)

set(CMAKE_C_STANDARD 11)

# Require Windows
if(NOT WIN32)
    message(FATAL_ERROR "Hook DLL only builds on Windows")
endif()

add_library(quarry_hooks SHARED
    dllmain.c
    hooks.c
    ipc.c
    dumper.c
)

target_compile_definitions(quarry_hooks PRIVATE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    _CRT_SECURE_NO_WARNINGS
)

target_link_libraries(quarry_hooks PRIVATE
    kernel32
    user32
    advapi32
    ntdll
)

# Output name reflects architecture: quarry_hooks_x64.dll or quarry_hooks_x86.dll
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set_target_properties(quarry_hooks PROPERTIES OUTPUT_NAME "quarry_hooks_x64")
else()
    set_target_properties(quarry_hooks PROPERTIES OUTPUT_NAME "quarry_hooks_x86")
endif()

# Disable incremental linking and manifest embedding for a clean DLL
if(MSVC)
    target_link_options(quarry_hooks PRIVATE /INCREMENTAL:NO /MANIFEST:NO)
endif()
