cmake_minimum_required(VERSION 3.16)
project(audit_ebpf C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Architecture detection
execute_process(COMMAND uname -m OUTPUT_VARIABLE HOST_ARCH OUTPUT_STRIP_TRAILING_WHITESPACE)
if(NOT ARCH)
    if(HOST_ARCH STREQUAL "aarch64")
        set(ARCH "arm64")
    elseif(HOST_ARCH STREQUAL "x86_64")
        set(ARCH "x86_64")
    else()
        set(ARCH "${HOST_ARCH}")
    endif()
endif()

# Map ARCH to clang BPF target
if(ARCH STREQUAL "arm64")
    set(BPF_ARCH "arm64")
elseif(ARCH STREQUAL "x86_64" OR ARCH STREQUAL "x86")
    set(BPF_ARCH "x86")
else()
    message(FATAL_ERROR "Unknown ARCH=${ARCH}. Supported: arm64, x86_64")
endif()

message(STATUS "Configuring for architecture: ${ARCH} (BPF target: ${BPF_ARCH})")

# Include libbpf download module
include(cmake/DownloadLibbpf.cmake)

# BPF object
set(BPF_SRC audit.bpf.c)
set(BPF_OBJ audit.bpf.o)

# Find llvm-strip
find_program(LLVM_STRIP NAMES llvm-strip llvm-strip-14 llvm-strip-15)

add_custom_target(bpf_program ALL
    COMMAND clang -g -O2 -target bpf -D__TARGET_ARCH_${BPF_ARCH} -c
            -I${CMAKE_CURRENT_SOURCE_DIR}
            -I${LIBBPF_SRC_DIR}/src
            ${CMAKE_CURRENT_SOURCE_DIR}/${BPF_SRC} -o ${CMAKE_CURRENT_BINARY_DIR}/${BPF_OBJ}
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/${BPF_SRC}
    COMMENT "Building eBPF program: ${BPF_OBJ}"
    BYPRODUCTS ${CMAKE_CURRENT_BINARY_DIR}/${BPF_OBJ}
)

# Optional: strip debug info if llvm-strip found
if(LLVM_STRIP)
    add_custom_command(TARGET bpf_program POST_BUILD
        COMMAND ${LLVM_STRIP} -g ${CMAKE_CURRENT_BINARY_DIR}/${BPF_OBJ}
        COMMENT "Stripping debug symbols from BPF object"
    )
endif()

# Loader shared library
set(LOADER_SRC loader.c)
set(LOADER_SO loader.so)

add_library(loader SHARED ${LOADER_SRC})
add_dependencies(loader libbpf)

target_include_directories(loader PRIVATE
    ${LIBBPF_INCLUDE_DIRS}
)

target_link_libraries(loader PRIVATE
    ${CMAKE_BINARY_DIR}/libbpf-build/libbpf.a
    elf
    z
    pthread
)

set_target_properties(loader PROPERTIES
    OUTPUT_NAME "loader"
    PREFIX ""  # Prevent "libloader.so", we want "loader.so"
    LINK_FLAGS "-static-libgcc"
)

# Build all target
add_custom_target(build ALL DEPENDS bpf_program loader)
