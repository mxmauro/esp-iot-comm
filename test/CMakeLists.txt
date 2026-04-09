cmake_minimum_required(VERSION 3.16)

set(idf_version_header "$ENV{IDF_PATH}/components/esp_common/include/esp_idf_version.h")
set(idf_version_major "")

if(EXISTS "${idf_version_header}")
    file(STRINGS "${idf_version_header}" idf_version_major_line REGEX "^#define[ \t]+ESP_IDF_VERSION_MAJOR[ \t]+[0-9]+$")
    if(idf_version_major_line)
        string(REGEX REPLACE "^#define[ \t]+ESP_IDF_VERSION_MAJOR[ \t]+([0-9]+)$" "\\1" idf_version_major "${idf_version_major_line}")
    endif()
endif()

set(SDKCONFIG_DEFAULTS "sdkconfig.defaults")
if(idf_version_major STREQUAL "" OR idf_version_major VERSION_LESS "6")
    list(APPEND SDKCONFIG_DEFAULTS "sdkconfig.defaults.v5")
endif()

include($ENV{IDF_PATH}/tools/cmake/project.cmake)

set(COMPONENTS main unity)

project(esp_iot_comm_test)
