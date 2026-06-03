cmake_minimum_required(VERSION 3.20)
project(wraith LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

add_executable(wraith
    src/main.cpp
    src/protobuf.cpp
    src/pipe_server.cpp
    src/gateway.cpp
    src/session.cpp
    src/fingerprint.cpp
    src/attestation.cpp
    src/stealth.cpp
    src/launcher.cpp
    src/puuid.cpp
    src/log.cpp
)

target_include_directories(wraith PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(wraith PRIVATE
    winhttp
    ws2_32
    bcrypt
    crypt32
    advapi32
    wtsapi32
    ntdll
    shlwapi
    userenv
    version
)

target_compile_options(wraith PRIVATE /EHsc)

target_compile_definitions(wraith PRIVATE
    _CRT_SECURE_NO_WARNINGS
    UNICODE
    _UNICODE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)

# Static link everything for single-binary deployment
set_target_properties(wraith PROPERTIES
    LINK_FLAGS "/SUBSYSTEM:CONSOLE"
)
