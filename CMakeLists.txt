cmake_minimum_required(VERSION 3.0.0)
project(embedCSample VERSION 0.1.0)

include(CTest)
enable_testing()

add_executable(embedCSample devicesample.c heap.c vector_heap.c bearssltagenerator.c azheap.c llcomms.c base64util.c)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D MQTT_USE_BEARSSL")
#add_compile_definitions(embedCSample PRIVATE MQTT_USE_BEARSSL)
target_link_libraries(embedCSample az_iot_hub az_core az_iot_common az_nohttp az_posix  bearssl mqttc m)

#add_executable(jsontest jsontest.c)
#target_link_libraries(jsontest az_iot_hub az_core az_iot_common az_nohttp az_posix)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
