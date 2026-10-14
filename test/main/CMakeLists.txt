
file(GLOB TEST_SRCS
     "test_*.c"
     "test_*.cpp"
)

set(srcs "main.cpp"
         ${TEST_SRCS})

idf_component_register(SRCS ${srcs}
                       INCLUDE_DIRS "."
                       REQUIRES unity esp_event esp_netif
                       WHOLE_ARCHIVE)
