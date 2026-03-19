idf_build_get_property(target IDF_TARGET)

if(${target} STREQUAL "linux")
    return() # This component is not supported by the POSIX/Linux simulator
endif()

set(srcs "src/challenge.cpp"
         "src/iot_comm.cpp"
         "src/rate_limit.cpp"
         "src/user.cpp"
         "src/captive_portal/captive_portal.cpp"
         "src/crypto/aes.cpp"
         "src/crypto/hkdf.cpp"
         "src/crypto/p256.cpp"
         "src/crypto/utils.cpp"
         "src/http/http_helpers.cpp"
         "src/provisioning/wifi.cpp"
         "src/utils/binary.cpp"
         "src/utils/network.cpp"
)

idf_component_register(SRCS "${srcs}"
                       INCLUDE_DIRS "include"
                       PRIV_INCLUDE_DIRS "private_include"
                       REQUIRES mbedtls esp_http_server
                       PRIV_REQUIRES esp_netif esp_event esp_wifi nvs_flash
                       EMBED_FILES "src/captive_portal/web/dist/index.html"
                                   "src/captive_portal/web/dist/assets/app.js"
                                   "src/captive_portal/web/dist/assets/app.css")
