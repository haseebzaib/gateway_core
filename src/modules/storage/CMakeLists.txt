

add_library(module_storage
sq_lite.cpp

)


target_include_directories(module_storage
    PUBLIC
        ${CMAKE_SOURCE_DIR}/include
)



target_link_libraries(module_storage
    PUBLIC
        spdlog::spdlog_header_only
) 