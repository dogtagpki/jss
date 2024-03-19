project(p7tool)

set(P7TOOL_PRIVATE_INCLUDE_DIRS
  ${CMAKE_BINARY_DIR}
  ${NSPR_INCLUDE_DIRS}
  ${NSS_INCLUDE_DIRS}
)

set(p7tool_SRCS
    secerror.c
    secpwd.c
    secutil.c
    pppolicy.c
    p7tool.c
)

include_directories(${P7TOOL_PRIVATE_INCLUDE_DIRS})

add_executable(p7tool ${p7tool_SRCS})
add_dependencies(native p7tool)
target_link_libraries(p7tool smime3 nss3 plc4 nspr4)

install(
    TARGETS p7tool
    RUNTIME DESTINATION ${BIN_INSTALL_DIR}
    LIBRARY DESTINATION ${LIB_INSTALL_DIR}
    ARCHIVE DESTINATION ${LIB_INSTALL_DIR}
)
