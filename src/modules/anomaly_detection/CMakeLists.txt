

add_library(module_anomaly_detection
threshold_detector.cpp
)


target_include_directories(module_anomaly_detection
    PUBLIC
        ${CMAKE_SOURCE_DIR}/include
)



target_link_libraries(module_anomaly_detection
    PUBLIC
        spdlog::spdlog_header_only
) 