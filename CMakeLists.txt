cmake_minimum_required(VERSION 3.22.1)
project("srxmanager")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -fvisibility=hidden -fstack-protector-strong -fPIE -ffunction-sections -fdata-sections")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,--strip-all -Wl,--gc-sections -fPIE -pie")

add_library(
    srxmanager
    SHARED
    ${CMAKE_SOURCE_DIR}/native-lib.cpp
)

find_library(log-lib log)

target_link_libraries(
    srxmanager
    ${log-lib}
)
