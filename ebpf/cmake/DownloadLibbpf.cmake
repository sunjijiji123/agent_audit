# libbpf v1.4.0 - static build from local source
# Source: 3rdp/libbpf/ (pre-downloaded)
set(LIBBPF_VERSION "1.4.0")
set(LIBBPF_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../3rdp/libbpf")

if(NOT EXISTS ${LIBBPF_SRC_DIR}/src/libbpf.c)
    message(FATAL_ERROR "libbpf source not found at ${LIBBPF_SRC_DIR}")
endif()

message(STATUS "Using libbpf ${LIBBPF_VERSION} from: ${LIBBPF_SRC_DIR}")

add_custom_target(libbpf ALL
    COMMAND make -C ${LIBBPF_SRC_DIR}/src
        BUILD_STATIC_ONLY=1
        OBJDIR=${CMAKE_BINARY_DIR}/libbpf-build
        NO_PKG_CONFIG=1
        CC=${CMAKE_C_COMPILER}
        AR=${CMAKE_AR}
        CFLAGS=${CMAKE_C_FLAGS}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMENT "Building libbpf ${LIBBPF_VERSION} static library"
    BYPRODUCTS ${CMAKE_BINARY_DIR}/libbpf-build/libbpf.a
)

set(LIBBPF_INCLUDE_DIRS
    ${LIBBPF_SRC_DIR}/include
    ${LIBBPF_SRC_DIR}/include/uapi
)
