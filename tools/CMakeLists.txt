project(tools)

if(WITH_NATIVE)
    add_subdirectory(src/main/native/p12tool)
    add_subdirectory(src/main/native/p7tool)
    add_subdirectory(src/main/native/sslget)
endif(WITH_NATIVE)
