

add_library(module_message_protocol
message_protocol.cpp
)


target_include_directories(module_message_protocol
    PUBLIC
        ${CMAKE_SOURCE_DIR}/include
)



target_link_libraries(module_message_protocol
    PUBLIC
        spdlog::spdlog_header_only
) 