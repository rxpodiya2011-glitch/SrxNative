cmake_minimum_required(VERSION 3.10.2)
project("srxmanager")

# Security & Optimization Flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} \
    -O3 \
    -fvisibility=hidden \
    -fstack-protector-strong \
    -fPIE \
    -ffunction-sections \
    -fdata-sections")

set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} \
    -Wl,--strip-all \
    -Wl,--gc-sections \
    -fPIE -pie")

add_library(
    srxmanager
    SHARED
    native-lib.cpp
)
