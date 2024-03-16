project(sslget)

set(SSLGET_PRIVATE_INCLUDE_DIRS
  ${CMAKE_BINARY_DIR}
  ${NSPR_INCLUDE_DIRS}
  ${NSS_INCLUDE_DIRS}
)

set(sslget_SRCS
    sslget.c
    getopt.c
)

include_directories(${SSLGET_PRIVATE_INCLUDE_DIRS})

add_executable(sslget ${sslget_SRCS})
add_dependencies(native sslget)
target_link_libraries(sslget plc4 nspr4 ssl3 nss3)

install(
    TARGETS sslget
    RUNTIME DESTINATION ${BIN_INSTALL_DIR}
    LIBRARY DESTINATION ${LIB_INSTALL_DIR}
    ARCHIVE DESTINATION ${LIB_INSTALL_DIR}
)
