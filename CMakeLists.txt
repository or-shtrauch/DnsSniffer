cmake_minimum_required(VERSION 3.10)
project(DnsSniffer C)

include(ExternalProject)

set(SUBMOD_DIR submodules)
set(EXTERNAL_INSTALL_DIR ${CMAKE_BINARY_DIR}/external)

# External project for libmnl
ExternalProject_Add(libmnl
    PREFIX ${CMAKE_BINARY_DIR}/libmnl
    SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/${SUBMOD_DIR}/libmnl
    CONFIGURE_COMMAND
      ${CMAKE_CURRENT_SOURCE_DIR}/${SUBMOD_DIR}/libmnl/autogen.sh &&
      ${CMAKE_CURRENT_SOURCE_DIR}/${SUBMOD_DIR}/libmnl/configure --prefix=${EXTERNAL_INSTALL_DIR} --enable-static
    BUILD_COMMAND make
    INSTALL_COMMAND make install
    BUILD_IN_SOURCE 1
)

# External project for libnfnetlink
ExternalProject_Add(libnfnetlink
    PREFIX ${CMAKE_BINARY_DIR}/libnfnetlink
    SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/${SUBMOD_DIR}/libnfnetlink
    CONFIGURE_COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/${SUBMOD_DIR}/libnfnetlink/autogen.sh &&
                      ${CMAKE_CURRENT_SOURCE_DIR}/${SUBMOD_DIR}/libnfnetlink/configure --prefix=${EXTERNAL_INSTALL_DIR} --enable-static
    BUILD_COMMAND make
    INSTALL_COMMAND make install
    BUILD_IN_SOURCE 1
)

# External project for libnetfilter_log
ExternalProject_Add(libnetfilter_log
    PREFIX ${CMAKE_BINARY_DIR}/libnetfilter_log
    SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/${SUBMOD_DIR}/libnetfilter_log
    CONFIGURE_COMMAND
      PKG_CONFIG_PATH=${EXTERNAL_INSTALL_DIR}/lib/pkgconfig
      ${CMAKE_CURRENT_SOURCE_DIR}/${SUBMOD_DIR}/libnetfilter_log/autogen.sh &&
      PKG_CONFIG_PATH=${EXTERNAL_INSTALL_DIR}/lib/pkgconfig
      ${CMAKE_CURRENT_SOURCE_DIR}/${SUBMOD_DIR}/libnetfilter_log/configure --prefix=${EXTERNAL_INSTALL_DIR} --enable-static
    BUILD_COMMAND make
    INSTALL_COMMAND make install
    BUILD_IN_SOURCE 1
    DEPENDS libnfnetlink libmnl
)

file(GLOB
    SRCS
    "src/*.c")

# Add the executable
add_executable(dns_sniffer ${SRCS} main.c)

target_include_directories(dns_sniffer PRIVATE ${EXTERNAL_INSTALL_DIR}/include)
target_include_directories(dns_sniffer PRIVATE include)

# Link shared libraries (.so) and enforce static linking at runtime
target_link_directories(dns_sniffer PRIVATE ${EXTERNAL_INSTALL_DIR}/lib)
target_link_libraries(dns_sniffer PRIVATE
    ${EXTERNAL_INSTALL_DIR}/lib/libmnl.so
    ${EXTERNAL_INSTALL_DIR}/lib/libnfnetlink.so
    ${EXTERNAL_INSTALL_DIR}/lib/libnetfilter_log.so
)

# Ensure the external projects are built before linking
add_dependencies(dns_sniffer libmnl libnfnetlink libnetfilter_log)

# Enforce static linking of .so files (if you prefer static behavior)
if(UNIX)
set_target_properties(dns_sniffer PROPERTIES LINK_FLAGS "-static-libgcc -static-libstdc++")
endif()

################ Unit Tests ######################
enable_testing()

message(" [*] Compiling DNS Sniffer Unit Tests")

add_subdirectory(${SUBMOD_DIR}/cmocka)

file(GLOB TEST_FIREWALL_SRC "tests/src/test_firewall.c")
add_executable(test_firewall ${TEST_FIREWALL_SRC})
target_include_directories(test_firewall PRIVATE src)
target_link_libraries(test_firewall cmocka)
# target_link_options(${CHIP8_HANDLERS_TESTS} PRIVATE
#     -Wl,-wrap=srand
#     -Wl,-wrap=time
# )
add_test(NAME test_firewall COMMAND test_firewall)

###############################################################

file(GLOB TEST_DNS_SNIFFER "tests/src/test_dns_sniffer.c")
add_executable(test_dns_sniffer ${TEST_DNS_SNIFFER})
target_include_directories(test_dns_sniffer PRIVATE src)
target_link_libraries(test_dns_sniffer cmocka)
# target_link_options(${CHIP8_HANDLERS_TESTS} PRIVATE
#     -Wl,-wrap=srand
#     -Wl,-wrap=time
# )
add_test(NAME test_dns_sniffer COMMAND test_dns_sniffer)

###############################################################

file(GLOB TEST_NAIN "tests/src//test_main.c")
add_executable(test_main ${TEST_NAIN})
target_include_directories(test_main PRIVATE src)
target_link_libraries(test_main cmocka)
# target_link_options(${CHIP8_HANDLERS_TESTS} PRIVATE
#     -Wl,-wrap=srand
#     -Wl,-wrap=time
# )
add_test(NAME test_main COMMAND test_main)
# ###############################################################

message(" [*] Finished Compiling DNS Sniffer Unit Tests")
