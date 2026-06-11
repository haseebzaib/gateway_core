

add_library(module_dustrak
drx_85xx.cpp
)


target_include_directories(module_dustrak
    PUBLIC
        ${CMAKE_SOURCE_DIR}/include
)



target_link_libraries(module_dustrak
    PUBLIC
        spdlog::spdlog_header_only
        module_serial
)