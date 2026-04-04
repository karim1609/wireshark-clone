cmake_minimum_required(VERSION 3.16)

include_guard(GLOBAL)

function(_third_party_add_interface_alias alias_name)
    set(options)
    set(oneValueArgs target)
    set(multiValueArgs include_dirs link_libraries compile_definitions)
    cmake_parse_arguments(ARG "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

    if(NOT TARGET "${alias_name}")
        add_library("${alias_name}" INTERFACE)
        if(ARG_include_dirs)
            target_include_directories("${alias_name}" INTERFACE ${ARG_include_dirs})
        endif()
        if(ARG_link_libraries)
            target_link_libraries("${alias_name}" INTERFACE ${ARG_link_libraries})
        endif()
        if(ARG_compile_definitions)
            target_compile_definitions("${alias_name}" INTERFACE ${ARG_compile_definitions})
        endif()
    endif()

    if(ARG_target AND NOT TARGET "${ARG_target}")
        add_library("${ARG_target}" ALIAS "${alias_name}")
    endif()
endfunction()

set(THIRD_PARTY_DIR "${CMAKE_CURRENT_SOURCE_DIR}")

# libpcap / Npcap
if(WIN32)
    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        set(_pcap_lib_dir "${THIRD_PARTY_DIR}/Lib/x64")
    else()
        set(_pcap_lib_dir "${THIRD_PARTY_DIR}/Lib")
    endif()

    set(_pcap_include_dir "${THIRD_PARTY_DIR}/Include")
    set(_pcap_library "${_pcap_lib_dir}/wpcap.lib")
    set(_packet_library "${_pcap_lib_dir}/Packet.lib")

    if(NOT EXISTS "${_pcap_library}")
        message(FATAL_ERROR "Npcap library not found: ${_pcap_library}")
    endif()

    if(NOT EXISTS "${_packet_library}")
        message(FATAL_ERROR "Npcap Packet library not found: ${_packet_library}")
    endif()

    add_library(third_party_pcap INTERFACE)
    target_include_directories(third_party_pcap INTERFACE "${_pcap_include_dir}")
    target_link_libraries(third_party_pcap INTERFACE "${_pcap_library}" "${_packet_library}" ws2_32)
elseif(UNIX)
    find_package(PCAP REQUIRED)
    add_library(third_party_pcap INTERFACE)
    target_link_libraries(third_party_pcap INTERFACE PCAP::PCAP)
else()
    message(FATAL_ERROR "Unsupported platform for libpcap integration.")
endif()

if(NOT TARGET pcap)
    add_library(pcap ALIAS third_party_pcap)
endif()

# sqlite3
set(_sqlite_dir "${THIRD_PARTY_DIR}/sqlite")
set(_sqlite_include_candidates
    "${_sqlite_dir}"
    "${_sqlite_dir}/include"
)
set(_sqlite_header_candidates
    "${_sqlite_dir}/sqlite3.h"
    "${_sqlite_dir}/include/sqlite3.h"
)
set(_sqlite_source_candidates
    "${_sqlite_dir}/sqlite3.c"
    "${_sqlite_dir}/src/sqlite3.c"
)
set(_sqlite_library_candidates
    "${_sqlite_dir}/lib/sqlite3.lib"
    "${_sqlite_dir}/lib/libsqlite3.a"
    "${_sqlite_dir}/sqlite3.lib"
    "${_sqlite_dir}/libsqlite3.a"
)

set(_sqlite_header "")
foreach(candidate IN LISTS _sqlite_header_candidates)
    if(EXISTS "${candidate}")
        set(_sqlite_header "${candidate}")
        break()
    endif()
endforeach()

set(_sqlite_source "")
foreach(candidate IN LISTS _sqlite_source_candidates)
    if(EXISTS "${candidate}")
        set(_sqlite_source "${candidate}")
        break()
    endif()
endforeach()

set(_sqlite_library "")
foreach(candidate IN LISTS _sqlite_library_candidates)
    if(EXISTS "${candidate}")
        set(_sqlite_library "${candidate}")
        break()
    endif()
endforeach()

if(_sqlite_source)
    add_library(third_party_sqlite3 STATIC "${_sqlite_source}")
    get_filename_component(_sqlite_header_dir "${_sqlite_header}" DIRECTORY)
    target_include_directories(third_party_sqlite3 PUBLIC "${_sqlite_header_dir}")
elseif(_sqlite_header AND _sqlite_library)
    get_filename_component(_sqlite_header_dir "${_sqlite_header}" DIRECTORY)
    add_library(third_party_sqlite3 STATIC IMPORTED GLOBAL)
    set_target_properties(third_party_sqlite3 PROPERTIES
        IMPORTED_LOCATION "${_sqlite_library}"
        INTERFACE_INCLUDE_DIRECTORIES "${_sqlite_header_dir}"
    )
elseif(_sqlite_header)
    get_filename_component(_sqlite_header_dir "${_sqlite_header}" DIRECTORY)
    add_library(third_party_sqlite3 INTERFACE)
    target_include_directories(third_party_sqlite3 INTERFACE "${_sqlite_header_dir}")
else()
    message(WARNING "sqlite3 sources were not found under third_party/sqlite. Creating an empty interface target.")
    add_library(third_party_sqlite3 INTERFACE)
    target_include_directories(third_party_sqlite3 INTERFACE "${_sqlite_dir}")
endif()

if(NOT TARGET sqlite3)
    add_library(sqlite3 ALIAS third_party_sqlite3)
endif()

# fmt
set(_fmt_dir "${THIRD_PARTY_DIR}/fmt")

if(EXISTS "${_fmt_dir}/include/fmt/core.h")
    _third_party_add_interface_alias(
        third_party_fmt
        target third_party_fmt_interface
        include_dirs "${_fmt_dir}/include"
        compile_definitions FMT_HEADER_ONLY=1
    )
elseif(EXISTS "${_fmt_dir}/fmt/core.h")
    _third_party_add_interface_alias(
        third_party_fmt
        target third_party_fmt_interface
        include_dirs "${_fmt_dir}"
        compile_definitions FMT_HEADER_ONLY=1
    )
else()
    message(WARNING "fmt was not found under third_party/fmt. Creating an empty interface target.")
    add_library(third_party_fmt INTERFACE)
endif()

if(NOT TARGET fmt)
    add_library(fmt ALIAS third_party_fmt)
endif()

# spdlog
set(_spdlog_dir "${THIRD_PARTY_DIR}/spdlog")

if(EXISTS "${_spdlog_dir}/include/spdlog/spdlog.h")
    _third_party_add_interface_alias(
        third_party_spdlog
        target third_party_spdlog_interface
        include_dirs "${_spdlog_dir}/include"
        link_libraries third_party_fmt
        compile_definitions SPDLOG_FMT_EXTERNAL=1
    )
elseif(EXISTS "${_spdlog_dir}/spdlog/spdlog.h")
    _third_party_add_interface_alias(
        third_party_spdlog
        target third_party_spdlog_interface
        include_dirs "${_spdlog_dir}"
        link_libraries third_party_fmt
        compile_definitions SPDLOG_FMT_EXTERNAL=1
    )
else()
    message(WARNING "spdlog was not found under third_party/spdlog. Creating an empty interface target.")
    add_library(third_party_spdlog INTERFACE)
endif()

if(NOT TARGET spdlog)
    add_library(spdlog ALIAS third_party_spdlog)
endif()

# nlohmann/json
set(_json_dir "${THIRD_PARTY_DIR}/json")

if(EXISTS "${_json_dir}/include/nlohmann/json.hpp")
    _third_party_add_interface_alias(
        third_party_json
        target third_party_json_interface
        include_dirs "${_json_dir}/include"
    )
elseif(EXISTS "${_json_dir}/nlohmann/json.hpp")
    _third_party_add_interface_alias(
        third_party_json
        target third_party_json_interface
        include_dirs "${_json_dir}"
    )
else()
    message(WARNING "nlohmann/json was not found under third_party/json. Creating an empty interface target.")
    add_library(third_party_json INTERFACE)
endif()

if(NOT TARGET json)
    add_library(json ALIAS third_party_json)
endif()
