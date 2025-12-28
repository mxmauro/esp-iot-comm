idf_build_get_property(target IDF_TARGET)

if(${target} STREQUAL "linux")
    return() # This component is not supported by the POSIX/Linux simulator
endif()

set(srcs "src/binary_reader.cpp"
         "src/challenge.cpp"
         "src/iot_comm.cpp"
         "src/ip_address.cpp"
         "src/rate_limit.cpp"
         "src/user.cpp"
         "src/mDNS/mDNS.cpp"
         "src/provisioning/wifi.cpp"
         "src/crypto/aes.cpp"
         "src/crypto/hash.cpp"
         "src/crypto/p256.cpp"
)

idf_component_register(SRCS "${srcs}"
                       INCLUDE_DIRS "include"
                       PRIV_INCLUDE_DIRS "private_include"
                       REQUIRES mbedtls
                       PRIV_REQUIRES network_provisioning esp_netif bt esp_event esp_http_server)
