

add_library(module_ipc
tcp_socket.cpp
)


target_include_directories(module_ipc
    PUBLIC
        ${CMAKE_SOURCE_DIR}/include
)



target_link_libraries(module_ipc
    PUBLIC
        spdlog::spdlog_header_only
)