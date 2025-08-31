cmake_minimum_required(VERSION 3.25)
project(sSocks)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)

include(GNUInstallDirs)

find_package(asyncio CONFIG REQUIRED)

add_executable(client MACOSX_BUNDLE src/client.cpp)

if (UNIX AND NOT APPLE)
    set_target_properties(client PROPERTIES INSTALL_RPATH "\$ORIGIN/../${CMAKE_INSTALL_LIBDIR}")
endif ()

target_link_libraries(client PRIVATE asyncio::asyncio-main)

add_executable(server MACOSX_BUNDLE src/server.cpp)

if (UNIX AND NOT APPLE)
    set_target_properties(server PROPERTIES INSTALL_RPATH "\$ORIGIN/../${CMAKE_INSTALL_LIBDIR}")
endif ()

target_link_libraries(server PRIVATE asyncio::asyncio-main)

if (APPLE)
    install(TARGETS client server BUNDLE DESTINATION .)
    install(CODE [[
        include(BundleUtilities)
        fixup_bundle("${CMAKE_INSTALL_PREFIX}/$<TARGET_BUNDLE_DIR_NAME:client>" "" "")
        fixup_bundle("${CMAKE_INSTALL_PREFIX}/$<TARGET_BUNDLE_DIR_NAME:server>" "" "")
    ]])
elseif (WIN32)
    install(
            TARGETS client server
            RUNTIME_DEPENDENCIES
            PRE_EXCLUDE_REGEXES "api-ms-" "ext-ms-"
            POST_EXCLUDE_REGEXES ".*system32/.*\\.dll"
            DESTINATION ${CMAKE_INSTALL_BINDIR}
            RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
else ()
    install(
            TARGETS client server
            RUNTIME_DEPENDENCIES
            PRE_EXCLUDE_REGEXES "ld-"
            DESTINATION ${CMAKE_INSTALL_LIBDIR}
            RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
endif ()
