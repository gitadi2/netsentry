cmake_minimum_required(VERSION 3.16)
project(netsentry CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Release build by default
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

# -march=native breaks on CI runners with different CPUs. Make it opt-in so the
# default build is portable; turn on with -DNATIVE_ARCH=ON for local max perf.
option(NATIVE_ARCH "Optimize for the local CPU (-march=native)" OFF)
if(NATIVE_ARCH)
  set(CMAKE_CXX_FLAGS_RELEASE "-O3 -march=native -DNDEBUG")
else()
  set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")
endif()

# -- Main engine binary -------------------------------------------------------
add_executable(netsentry src/main.cpp)
target_include_directories(netsentry PRIVATE src)

# -- Optional: libpcap for live capture --------------------------------------
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

# -- Threads + math -----------------------------------------------------------
find_package(Threads REQUIRED)
target_link_libraries(netsentry Threads::Threads m)

install(TARGETS netsentry RUNTIME DESTINATION bin)

# -----------------------------------------------------------------------------
#  Unit tests (GoogleTest)
#  Enable with:  cmake -B build -DBUILD_TESTS=ON
#  Run with:     ctest --test-dir build --output-on-failure
#                 (or ./build/netsentry_tests directly)
# -----------------------------------------------------------------------------
option(BUILD_TESTS "Build the GoogleTest unit tests" OFF)
option(COVERAGE    "Build tests with gcov coverage instrumentation" OFF)

if(BUILD_TESTS)
  enable_testing()

  # Fetch GoogleTest at configure time -- no system install needed.
  include(FetchContent)
  FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG        v1.14.0
  )
  # Prevent gtest from overriding our compiler/linker options on Windows.
  set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
  FetchContent_MakeAvailable(googletest)

  add_executable(netsentry_tests tests/test_netsentry.cpp)
  target_include_directories(netsentry_tests PRIVATE src)
  target_link_libraries(netsentry_tests
    GTest::gtest_main
    Threads::Threads
    m
  )

  # Optional coverage instrumentation (GCC/Clang).
  if(COVERAGE)
    target_compile_options(netsentry_tests PRIVATE -O0 -g --coverage)
    target_link_options(netsentry_tests PRIVATE --coverage)
    message(STATUS "Coverage: ENABLED (use gcov/lcov on netsentry_tests)")
  endif()

  include(GoogleTest)
  gtest_discover_tests(netsentry_tests)
  message(STATUS "Unit tests: ENABLED")
endif()