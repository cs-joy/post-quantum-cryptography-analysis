cmake_minimum_required(VERSION 3.16)
project(pqc_flow_starter C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Options
option(ENABLE_TESTS "Build unit tests" ON)

# Find libpcap (using find_library since macOS homebrew doesn't provide pkg-config file)
find_path(PCAP_INCLUDE_DIR
  NAMES pcap.h
  PATHS /opt/homebrew/include /usr/local/include /usr/include
)

find_library(PCAP_LIBRARY
  NAMES pcap
  PATHS /opt/homebrew/lib /usr/local/lib /usr/lib
)

if(NOT PCAP_INCLUDE_DIR OR NOT PCAP_LIBRARY)
  message(FATAL_ERROR "Could not find libpcap. Please install with: brew install libpcap")
endif()

set(PCAP_INCLUDE_DIRS ${PCAP_INCLUDE_DIR})
set(PCAP_LIBRARIES ${PCAP_LIBRARY})
set(PCAP_LIBRARY_DIRS "")
set(PCAP_CFLAGS_OTHER "")

# Find OpenSSL (for SHA256 fingerprinting and X509 parsing)
find_package(OpenSSL REQUIRED)

# Find nDPI - try pkg-config first, then manual search
find_package(PkgConfig)
if(PKG_CONFIG_FOUND)
  pkg_check_modules(NDPI QUIET ndpi)
  if(NOT NDPI_FOUND)
    pkg_check_modules(NDPI QUIET libndpi)
  endif()
endif()

if(NOT NDPI_FOUND)
  # Manual fallback for nDPI
  find_path(NDPI_INCLUDE_DIR
    NAMES ndpi_api.h
    PATHS /opt/homebrew/include /usr/local/include /usr/include
    PATH_SUFFIXES ndpi
  )
  
  find_library(NDPI_LIBRARY
    NAMES ndpi
    PATHS /opt/homebrew/lib /usr/local/lib /usr/lib
  )
  
  if(NDPI_INCLUDE_DIR AND NDPI_LIBRARY)
    set(NDPI_FOUND TRUE)
    set(NDPI_INCLUDE_DIRS ${NDPI_INCLUDE_DIR})
    set(NDPI_LIBRARIES ${NDPI_LIBRARY})
    set(NDPI_LIBRARY_DIRS "")
    set(NDPI_CFLAGS_OTHER "")
    message(STATUS "Found nDPI manually: ${NDPI_LIBRARY}")
  else()
    message(FATAL_ERROR "Could not find nDPI. Please install or build nDPI from source.")
  endif()
endif()

include_directories(
  ${NDPI_INCLUDE_DIRS}
  ${PCAP_INCLUDE_DIRS}
  ${CMAKE_CURRENT_SOURCE_DIR}/include
)

link_directories(
  ${NDPI_LIBRARY_DIRS}
  ${PCAP_LIBRARY_DIRS}
)

add_compile_options(${NDPI_CFLAGS_OTHER} ${PCAP_CFLAGS_OTHER})
add_executable(pqc-flow
  src/main.c
  src/flow.c
  src/pqc_detect.c
  src/ndpi_glue.c
  src/run_afpacket.c
  src/pcap_offline.c
  src/ssh_kex_sniffer.c
  src/tls_pqc_sniffer.c
)

target_link_libraries(pqc-flow
  ${NDPI_LIBRARIES}
  ${PCAP_LIBRARIES}
  OpenSSL::SSL
  OpenSSL::Crypto
)

# Tests (simple C unit tests without external frameworks)
if(ENABLE_TESTS)
  add_executable(pqc-tests
    tests/test_pqc.c
    src/pqc_detect.c
    src/flow.c
  )
  target_include_directories(pqc-tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
  target_link_libraries(pqc-tests ${NDPI_LIBRARIES})
endif()