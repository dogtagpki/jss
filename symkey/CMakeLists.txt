project(symkey)

javac(symkey-classes
    SOURCES
        src/main/java/*.java
    CLASSPATH
        ${JAVAC_CLASSPATH}
        ${CLASSES_OUTPUT_DIR}
    OUTPUT_DIR
        ${CMAKE_CURRENT_BINARY_DIR}/classes
    HEADER_DIR
        ${CMAKE_CURRENT_BINARY_DIR}/include
    DEPENDS
        generate_java
)

# TODO: merge into jss.jar
jar(symkey-jar
    CREATE
        ${CMAKE_CURRENT_BINARY_DIR}/jss-symkey.jar
    INPUT_DIR
        ${CMAKE_CURRENT_BINARY_DIR}/classes
    DEPENDS
        symkey-classes
)

install(
    FILES
        ${CMAKE_CURRENT_BINARY_DIR}/jss-symkey.jar
    DESTINATION
        ${JNI_DIR}
)

set(SYMKEY_JAR ${CMAKE_BINARY_DIR}/jss-symkey.jar CACHE INTERNAL "symkey jar file")

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

add_dependencies(${SYMKEY_SHARED_LIBRARY} symkey-jar)

set_target_properties(${SYMKEY_SHARED_LIBRARY}
    PROPERTIES
        OUTPUT_NAME
            jss-symkey
)

target_link_libraries(${SYMKEY_SHARED_LIBRARY}
    smime3 ssl3 nss3 nssutil3 plc4 plds4 nspr4 pthread dl)

install(
    TARGETS
        ${SYMKEY_SHARED_LIBRARY}
    LIBRARY DESTINATION
        ${LIB_DIR}/jss
)

install(
    CODE "execute_process(
        COMMAND ln -sf ../../../${JNI_DIR}/jss-symkey.jar \$ENV{DESTDIR}${LIB_DIR}/jss/jss-symkey.jar
    )"
)
