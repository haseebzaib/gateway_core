

add_library(module_serial
serial_port.cpp
SerialPort.cpp
)


target_include_directories(module_serial
    PUBLIC
        ${CMAKE_SOURCE_DIR}/include
)



target_link_libraries(module_serial
    PUBLIC
        spdlog::spdlog_header_only
)