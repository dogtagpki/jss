project(p12tool)

set(P12TOOL_PRIVATE_INCLUDE_DIRS
  ${CMAKE_BINARY_DIR}
  ${NSPR_INCLUDE_DIRS}
  ${NSS_INCLUDE_DIRS}
)

set(p12tool_SRCS
    basicutil.c
    pppolicy.c
    secutil.c
    secpwd.c
    moreoids.c
    p12tool.c
)

include_directories(${P12TOOL_PRIVATE_INCLUDE_DIRS})

add_executable(p12tool ${p12tool_SRCS})
add_dependencies(native p12tool)
target_link_libraries(p12tool smime3 ssl3 nss3 nssutil3 plc4 plds4 nspr4)

install(
    TARGETS p12tool
    RUNTIME DESTINATION ${BIN_INSTALL_DIR}
    LIBRARY DESTINATION ${LIB_INSTALL_DIR}
    ARCHIVE DESTINATION ${LIB_INSTALL_DIR}
)
