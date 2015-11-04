cmake_minimum_required(VERSION 3.3)
project(SeedCSISMP)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -lpcap")

set(SOURCE_FILES main.cpp SeedPacket.cpp SeedPacket.h SeedCommandCenter.cpp SeedCommandCenter.h SeedConfig.cpp SeedConfig.h SeedSession.cpp SeedSession.h)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/bin")

add_executable(SeedCup ${SOURCE_FILES})
