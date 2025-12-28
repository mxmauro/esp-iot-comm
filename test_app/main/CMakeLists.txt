
set(srcs "main.cpp"
         "test_iot_comm.cpp")

idf_component_register(SRCS ${srcs}
                       INCLUDE_DIRS ".")
