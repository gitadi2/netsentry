cmake_minimum_required(VERSION 3.16)
project(netsentry CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Release build by default
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_CXX_FLAGS_RELEASE "-O3 -march=native -DNDEBUG")

add_executable(netsentry src/main.cpp)
target_include_directories(netsentry PRIVATE src)

# ── Optional: libpcap for live capture ────────────────────────────────────
# cmake -DWITH_PCAP=ON ..
option(WITH_PCAP "Build with libpcap live capture support" OFF)
if(WITH_PCAP)
  find_library(PCAP_LIB pcap REQUIRED)
  target_link_libraries(netsentry ${PCAP_LIB})
  target_compile_definitions(netsentry PRIVATE HAVE_PCAP)
  message(STATUS "libpcap: ENABLED")
else()
  message(STATUS "libpcap: DISABLED (simulation mode only)")
endif()

# ── Threads ────────────────────────────────────────────────────────────────
find_package(Threads REQUIRED)
target_link_libraries(netsentry Threads::Threads)

# ── Math (needed for log2f) ────────────────────────────────────────────────
target_link_libraries(netsentry m)

install(TARGETS netsentry RUNTIME DESTINATION bin)
