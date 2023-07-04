cmake_minimum_required(VERSION 3.17)
project(sSocks)

set(CMAKE_CXX_STANDARD 17)

set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

find_package(aio CONFIG REQUIRED)

add_executable(client client.cpp common.cpp)
target_link_libraries(client PRIVATE aio::aio)

add_executable(server server.cpp common.cpp)
target_link_libraries(server PRIVATE aio::aio)