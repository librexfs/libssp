cmake_minimum_required(VERSION 3.5)
project(itl_ssp)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")
set(CMAKE_CXX_LINKER_PREFERENCE lld)

# Default to Release mode
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

add_subdirectory(source)

option(BUILD_SHARED "Build SHARED library" ON)

message("BUILD_SHARED=" ${BUILD_SHARED})

install(TARGETS ssp LIBRARY DESTINATION lib)