get_property(open62541_BUILD_INCLUDE_DIRS TARGET open62541 PROPERTY INTERFACE_INCLUDE_DIRECTORIES)
include_directories(${open62541_BUILD_INCLUDE_DIRS})
# ua_server_internal.h
include_directories("${PROJECT_SOURCE_DIR}/src")
include_directories("${PROJECT_SOURCE_DIR}/src/server")
# testing_clock.h
include_directories("${PROJECT_SOURCE_DIR}/tests/testing-plugins")

add_definitions(-DUA_sleep_ms=UA_comboSleep)

if(NOT MSVC)
    add_definitions(-Wno-deprecated-declarations)
endif()

remove_definitions(-std=c99 -Wmissing-prototypes -Wstrict-prototypes)
set (CMAKE_CXX_STANDARD 20)

if(NOT "x${CMAKE_C_COMPILER_ID}" STREQUAL "xClang")
    MESSAGE(FATAL_ERROR "To build fuzzing, you need to use Clang as the compiler")
endif()

# oss-fuzz builds already include these flags
if (CMAKE_CXX_COMPILER_VERSION VERSION_LESS 10.0)
    message(FATAL_ERROR "To use stateful fuzzing, you need at least clang version 10")
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=fuzzer -fno-omit-frame-pointer -gline-tables-only -fsanitize=address -fsanitize-address-use-after-scope")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-deprecated-volatile -fsanitize=fuzzer -fno-omit-frame-pointer -gline-tables-only -fsanitize=address -fsanitize-address-use-after-scope")

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
list(APPEND LIBS "${open62541_LIBRARIES}")

# Use different plugins for testing
set(fuzzing_plugin_sources ${PROJECT_SOURCE_DIR}/arch/network_tcp.c
    ${PROJECT_SOURCE_DIR}/tests/testing-plugins/testing_clock.c
    ${PROJECT_SOURCE_DIR}/tests/testing-plugins/testing_networklayers.c
    ${PROJECT_SOURCE_DIR}/plugins/ua_log_stdout.c
    ${PROJECT_SOURCE_DIR}/plugins/ua_config_default.c
    ${PROJECT_SOURCE_DIR}/plugins/ua_nodestore_ziptree.c
    ${PROJECT_SOURCE_DIR}/plugins/ua_nodestore_hashmap.c
    ${PROJECT_SOURCE_DIR}/plugins/ua_accesscontrol_default.c
    ${PROJECT_SOURCE_DIR}/plugins/crypto/ua_pki_none.c
    ${PROJECT_SOURCE_DIR}/plugins/crypto/ua_securitypolicy_none.c
)

if(UA_ENABLE_ENCRYPTION)
  list(APPEND fuzzing_plugin_sources
       ${PROJECT_SOURCE_DIR}/plugins/crypto/mbedtls/securitypolicy_mbedtls_common.c
       ${PROJECT_SOURCE_DIR}/plugins/crypto/mbedtls/ua_securitypolicy_basic128rsa15.c
       ${PROJECT_SOURCE_DIR}/plugins/crypto/mbedtls/ua_securitypolicy_basic256.c
       ${PROJECT_SOURCE_DIR}/plugins/crypto/mbedtls/ua_securitypolicy_basic256sha256.c
       ${PROJECT_SOURCE_DIR}/plugins/crypto/mbedtls/ua_securitypolicy_aes128sha256rsaoaep.c
       ${PROJECT_SOURCE_DIR}/plugins/crypto/mbedtls/ua_pki_mbedtls.c)
endif()

#add_library(open62541-fuzzplugins OBJECT
#            ${fuzzing_plugin_sources}
#            ${PROJECT_SOURCE_DIR}/arch/${UA_ARCHITECTURE}/ua_architecture_functions.c)
add_dependencies(open62541-fuzzplugins open62541)

# the fuzzer test are built directly on the open62541 object files. so they can
# access symbols that are hidden/not exported to the shared library

set(FUZZER_TARGETS)

macro(add_fuzzer FUZZER_NAME FUZZER_SOURCE)
    add_executable(${FUZZER_NAME} $<TARGET_OBJECTS:open62541-object> $<TARGET_OBJECTS:open62541-fuzzplugins> ${FUZZER_SOURCE} ${ARGN})
    target_link_libraries(${FUZZER_NAME} ${LIBS} AbstractFuzzTest)
    target_include_directories(${FUZZER_NAME} PRIVATE ${PROJECT_SOURCE_DIR}/src/server)
    target_include_directories(${FUZZER_NAME} PRIVATE ${PROJECT_SOURCE_DIR}/deps/mdnsd)
    target_include_directories(${FUZZER_NAME} PRIVATE ${PROJECT_SOURCE_DIR}/deps/abstractfuzztest/include)
    assign_source_group(${FUZZER_SOURCE})
    list(APPEND FUZZER_TARGETS ${FUZZER_NAME})
endmacro()

# Add new fuzzers here
add_fuzzer(fuzz_stateful fuzz_stateful.cc)
#
## Run fuzzer on existing corpus to avoid regression
#file(GLOB CORPUS_FILES ${PROJECT_SOURCE_DIR}/tests/fuzz/fuzz_binary_message_corpus/generated/*)
#SET(CORPUS_CMDS "")
#FOREACH(f ${CORPUS_FILES})
#    LIST(APPEND CORPUS_CMDS COMMAND ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/fuzz_binary_message "${f}")
#ENDFOREACH(f)
#
#add_custom_target(run_fuzzer ${CORPUS_CMDS}
#                  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
#                  DEPENDS ${FUZZER_TARGETS}
#                  ${MAYBE_USES_TERMINAL})

