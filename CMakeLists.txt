cmake_minimum_required(VERSION 3.16)
project(snort3_heavydb_logger VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------
option(SNORT3_INCLUDE_DIR "Path to Snort 3 include directory" "")
option(HEAVYDB_INCLUDE_DIR "Path to HeavyDB include directory (optional)" "")

# ---------------------------------------------------------------------------
# Find required packages
# ---------------------------------------------------------------------------

# --- Snort 3 headers ---
if(NOT SNORT3_INCLUDE_DIR)
    # Try pkg-config first
    find_package(PkgConfig QUIET)
    if(PkgConfig_FOUND)
        pkg_check_modules(SNORT3 snort)
    endif()

    # Fall back to common install paths
    find_path(SNORT3_INCLUDE_DIR
        NAMES framework/logger.h
        PATHS
            /usr/include/snort
            /usr/local/include/snort
            /opt/snort/include/snort
            ${CMAKE_SYSROOT}/usr/include/snort
        DOC "Snort 3 include directory"
    )
endif()

if(NOT EXISTS "${SNORT3_INCLUDE_DIR}/framework/logger.h")
    message(FATAL_ERROR
        "Could not find Snort 3 headers. "
        "Set -DSNORT3_INCLUDE_DIR=/path/to/snort3/include")
endif()
message(STATUS "Snort 3 includes: ${SNORT3_INCLUDE_DIR}")

# --- libcurl ---
find_package(CURL REQUIRED)
message(STATUS "libcurl: ${CURL_VERSION_STRING}")

# --- nlohmann/json (header-only) ---
find_package(nlohmann_json 3.10 QUIET)
if(NOT nlohmann_json_FOUND)
    # Try system include path
    find_path(NLOHMANN_JSON_INCLUDE_DIR
        NAMES nlohmann/json.hpp
        PATHS
            /usr/include
            /usr/local/include
            ${CMAKE_CURRENT_SOURCE_DIR}/third_party
        DOC "nlohmann/json include directory"
    )
    if(NOT NLOHMANN_JSON_INCLUDE_DIR)
        message(FATAL_ERROR
            "nlohmann/json not found. Install via your package manager "
            "(apt: nlohmann-json3-dev, brew: nlohmann-json) or place "
            "single-header json.hpp under third_party/nlohmann/json.hpp")
    endif()
    add_library(nlohmann_json INTERFACE)
    target_include_directories(nlohmann_json INTERFACE ${NLOHMANN_JSON_INCLUDE_DIR})
    message(STATUS "nlohmann/json (manual): ${NLOHMANN_JSON_INCLUDE_DIR}")
endif()

# ---------------------------------------------------------------------------
# Shared library target — Snort loads this as a plugin at runtime
# ---------------------------------------------------------------------------
add_library(snort3_heavydb_logger MODULE
    heavydb_connector.cc
    snort3_heavydb_logger.cc
)

target_include_directories(snort3_heavydb_logger PRIVATE
    ${SNORT3_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(snort3_heavydb_logger PRIVATE
    CURL::libcurl
    nlohmann_json
)

# Snort plugins must NOT have the "lib" prefix
set_target_properties(snort3_heavydb_logger PROPERTIES
    PREFIX ""
    OUTPUT_NAME "snort3_heavydb_logger"
)

# Strict warnings
target_compile_options(snort3_heavydb_logger PRIVATE
    -Wall -Wextra -Wpedantic
    -Wno-unused-parameter          # Snort API callbacks often leave params unnamed
    -fvisibility=hidden
)

# Release optimisations when not in Debug mode
if(NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(snort3_heavydb_logger PRIVATE -O2)
endif()

# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------
include(GNUInstallDirs)

# Default plugin install dir — overridable via -DCMAKE_INSTALL_LIBDIR
install(TARGETS snort3_heavydb_logger
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}/snort/plugins/logger
)

install(FILES
    heavydb_connector.h
    snort3_heavydb_logger.h
    json_binding.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/snort3_heavydb
)

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
message(STATUS "")
message(STATUS "=== snort3_heavydb_logger build summary ===")
message(STATUS "  Build type   : ${CMAKE_BUILD_TYPE}")
message(STATUS "  Snort3 inc   : ${SNORT3_INCLUDE_DIR}")
message(STATUS "  Install to   : ${CMAKE_INSTALL_PREFIX}")
message(STATUS "===========================================")
message(STATUS "")
