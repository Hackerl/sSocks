cmake_minimum_required(VERSION 3.17)
project(sSocks)

set(CMAKE_CXX_STANDARD 20)

set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

find_package(asyncio CONFIG REQUIRED)

add_executable(client src/client.cpp src/common.cpp)
target_link_libraries(client PRIVATE asyncio::asyncio)

add_executable(server src/server.cpp src/common.cpp)
target_link_libraries(server PRIVATE asyncio::asyncio)