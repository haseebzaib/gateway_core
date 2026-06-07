cmake_minimum_required(VERSION 3.20)

project(
    gateway_core
    VERSION 0.1.0
    DESCRIPTION "gateway core software"
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)



add_subdirectory(src/core)
add_subdirectory(apps)
add_subdirectory(third_party/spdlog)