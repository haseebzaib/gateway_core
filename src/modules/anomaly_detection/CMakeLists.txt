

add_library(module_anomaly_detection
threshold_detector.cpp
range_check_detector.cpp
timeout_detector.cpp
delta_detector.cpp
slope_detector.cpp
multi_condition_detector.cpp
z_score_detector.cpp
)


target_include_directories(module_anomaly_detection
    PUBLIC
        ${CMAKE_SOURCE_DIR}/include
)



target_link_libraries(module_anomaly_detection
    PUBLIC
        spdlog::spdlog_header_only
) 