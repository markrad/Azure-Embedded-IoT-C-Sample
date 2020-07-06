cmake_minimum_required(VERSION 3.0.0)
project(embedCSample VERSION 0.1.0)

include(CTest)
enable_testing()

#libaz_core.a
#libaz_iot_common.a
#libaz_iot_hub.a
#libaz_iot_provisioning.a
#libaz_keyvault.a
#libaz_nohttp.a
#libaz_noplatform.a
#libaz_storage_blobs.a
#libbearssl.a
#mqtt.c.o
#mqtt_pal.c.o

add_executable(embedCSample sassample.c heap.c bearssltagenerator.c azheap.c llcomms.c base64util.c)
add_compile_definitions(embedCSample PRIVATE MQTT_USE_BEARSSL)
target_link_libraries(embedCSample az_iot_hub az_core az_iot_common az_nohttp az_posix  bearssl mqttc m)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
