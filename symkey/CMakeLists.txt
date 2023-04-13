project(symkey)

set(SYMKEY_PUBLIC_INCLUDE_DIRS
    ${CMAKE_CURRENT_BINARY_DIR}/src/main/native/org/mozilla/jss/symkey
    ${CMAKE_CURRENT_SOURCE_DIR}/src/main/native/org/mozilla/jss/symkey
    CACHE INTERNAL "symkey public include directories"
)

set(SYMKEY_PRIVATE_INCLUDE_DIRS
    ${CMAKE_CURRENT_BINARY_DIR}/include
    ${JNI_INCLUDE_DIRS}
    ${NSPR_INCLUDE_DIRS}
    ${NSS_INCLUDE_DIRS}
)

set(SYMKEY_SHARED_LIBRARY symkey_library CACHE INTERNAL "symkey shared library")

set(symkey_library_SRCS
    src/main/native/org/mozilla/jss/symkey/Buffer.cpp
    src/main/native/org/mozilla/jss/symkey/EncryptData.cpp
    src/main/native/org/mozilla/jss/symkey/SessionKey.cpp
    src/main/native/org/mozilla/jss/symkey/SymKey.cpp
    src/main/native/org/mozilla/jss/symkey/NistSP800_108KDF.cpp
)

include_directories(${SYMKEY_PRIVATE_INCLUDE_DIRS})

add_library(${SYMKEY_SHARED_LIBRARY} SHARED
    ${symkey_library_SRCS})

add_dependencies(${SYMKEY_SHARED_LIBRARY} generate_so)

set_target_properties(${SYMKEY_SHARED_LIBRARY}
    PROPERTIES
        OUTPUT_NAME
            jss-symkey
)

target_link_libraries(${SYMKEY_SHARED_LIBRARY}
    smime3 ssl3 nss3 nssutil3 plc4 plds4 nspr4 pthread dl)

install(
    FILES
        ${CMAKE_CURRENT_BINARY_DIR}/libjss-symkey.so
    DESTINATION
        ${LIB_DIR}/jss
    PERMISSIONS
        OWNER_READ OWNER_WRITE OWNER_EXECUTE
        GROUP_READ GROUP_EXECUTE
        WORLD_READ WORLD_EXECUTE
)
