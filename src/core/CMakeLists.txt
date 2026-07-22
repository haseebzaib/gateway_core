

add_library(core

application.cpp
interprocess.cpp
sensorprocess.cpp
sensor_config.cpp
sensor_anomaly_config.cpp
rs232_runtime.cpp
modbus_runtime.cpp
deviceprocess.cpp

)


target_include_directories(core
    PUBLIC
        ${CMAKE_SOURCE_DIR}/include
)



target_link_libraries(core
    PUBLIC
        spdlog::spdlog_header_only
        module_ipc
        module_serial
        module_message_protocol
        module_modbus
        module_dustrak
        module_anomaly_detection
)
