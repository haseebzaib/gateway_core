cmake_minimum_required(VERSION 3.20)

project(
    metacrust_gateway_engine
    VERSION 0.1.0
    DESCRIPTION "MetaCrust Gateway C++ engine"
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_library(gateway_engine
    src/core/application.cpp
    src/config/config_store.cpp
    src/api/local_api.cpp
    src/storage/storage.cpp
)

target_include_directories(gateway_engine
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

add_executable(gatewayd
    apps/gatewayd/main.cpp
)

target_link_libraries(gatewayd
    PRIVATE gateway_engine
)

