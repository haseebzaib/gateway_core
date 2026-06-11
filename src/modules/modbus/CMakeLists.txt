

add_library(module_modbus
modbus_client.cpp
)

find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(LIBMODBUS QUIET IMPORTED_TARGET libmodbus)
endif()

if(NOT TARGET PkgConfig::LIBMODBUS)
    find_path(LIBMODBUS_INCLUDE_DIR
        NAMES modbus/modbus.h modbus.h
    )
    find_library(LIBMODBUS_LIBRARY
        NAMES modbus
    )

    if(NOT LIBMODBUS_INCLUDE_DIR OR NOT LIBMODBUS_LIBRARY)
        message(FATAL_ERROR "libmodbus was not found. Install libmodbus-dev or provide LIBMODBUS_INCLUDE_DIR and LIBMODBUS_LIBRARY.")
    endif()
endif()


target_include_directories(module_modbus
    PUBLIC
        ${CMAKE_SOURCE_DIR}/include
)

if(NOT TARGET PkgConfig::LIBMODBUS)
    target_include_directories(module_modbus
        PUBLIC
            ${LIBMODBUS_INCLUDE_DIR}
    )
endif()




target_link_libraries(module_modbus
    PUBLIC
        spdlog::spdlog_header_only
)


if(TARGET PkgConfig::LIBMODBUS)
    target_link_libraries(module_modbus
        PUBLIC
            PkgConfig::LIBMODBUS
    )
else()
    target_link_libraries(module_modbus
        PUBLIC
            ${LIBMODBUS_LIBRARY}
    )
endif()
