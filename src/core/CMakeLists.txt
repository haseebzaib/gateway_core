

add_library(core

application.cpp

)


target_include_directories(core
    PUBLIC
        ${CMAKE_SOURCE_DIR}/include
)



target_link_libraries(core
    PUBLIC
        spdlog::spdlog_header_only
)