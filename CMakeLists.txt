cmake_minimum_required(VERSION 3.0.0)
project(embedCSample VERSION 0.1.0)

include(CTest)
enable_testing()

set (SOURCE src/devicesample.c src/heap.c src/vector_heap.c src/bearssltagenerator.c src/azheap.c src/llcomms.c src/base64util.c)

add_executable(embedCSample "${SOURCE}")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D MQTT_USE_BEARSSL")
#add_compile_definitions(embedCSample PRIVATE MQTT_USE_BEARSSL) - not supported latest cmake available in WSL
target_include_directories(embedCSample PRIVATE "./include")
target_link_libraries(embedCSample 
    az_iot_hub 
    az_core 
    az_iot_common 
    az_nohttp 
    az_posix  
    bearssl 
    mqttc 
    m
)

#add_executable(jsontest jsontest.c)
#target_link_libraries(jsontest az_iot_hub az_core az_iot_common az_nohttp az_posix)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
