cmake_minimum_required(VERSION 3.17)
project(sSocks)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)

find_package(asyncio CONFIG REQUIRED)

add_executable(client src/client.cpp)
target_link_libraries(client PRIVATE asyncio::asyncio-main)

add_executable(server src/server.cpp)
target_link_libraries(server PRIVATE asyncio::asyncio-main)
