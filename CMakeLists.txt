cmake_minimum_required(VERSION 3.3)
project(SeedCSISMP)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -lpcap")

set(SOURCE_FILES main.cpp SeedPacket.cpp SeedPacket.h)
add_executable(SeedCup ${SOURCE_FILES})