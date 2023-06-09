cmake_minimum_required(VERSION 3.0)
project(socks5-asio)

if (${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
    message("building with Linux!")
else()
    message(FATAL_ERROR "Only support Linux!")
endif()

# CXX 11
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# debug build
set(CMAKE_BUILD_TYPE debug)

# CXX flags
set(CMAKE_CXX_FLAGS
    "-std=c++11 -g -O0 -Wno-unused-parameter -Werror -Wno-unused-variable")

# multi thread support
find_package(Threads REQUIRED)
find_package(Boost 1.65 COMPONENTS system REQUIRED)

# 'gcc -I' include directories
include_directories(${PROJECT_SOURCE_DIR})

# binary output path
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/build/bin)

# compile && link
aux_source_directory(. SOURCES)
add_executable(socks5-asio ${SOURCES})
target_link_libraries(socks5-asio Boost::system Threads::Threads)