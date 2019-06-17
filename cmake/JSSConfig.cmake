macro(jss_config)
    # Set the current JSS release number. Arguments are:
    #   MAJOR MINOR PATCH BETA
    # When BETA is zero, it isn't a beta release.
    jss_config_version(4 6 0 0)

    # Configure output directories
    jss_config_outputs()

    # Configure flags for compiling and linking
    jss_config_cflags()
    jss_config_ldflags()

    # Configure java-related flags
    jss_config_java()
endmacro()

macro(jss_config_version MAJOR MINOR PATCH BETA)
    # This sets the JSS Version for use in CMake and propagates it to the
    # necessary source locations. These are:
    #
    #   org/mozilla/jss/util/jssver.h{.in,}
    #   lib/MANIFEST.MF.in -> build/MANIFEST.MF
    #
    # On a build, these automatically get generated with the correct versions
    # included. Note that all "sets" are of global scope, so these variables
    # can be used anywhere that is necessary. Some uses are for setting the
    # version number in the library and jar file, etc.

    # Define variables from passed arguments
    set(JSS_VERSION_MAJOR "${MAJOR}")
    set(JSS_VERSION_MINOR "${MINOR}")
    set(JSS_VERSION_PATCH "${PATCH}")
    set(JSS_VERSION_BETA "${BETA}")

    set(JSS_VERSION "${JSS_VERSION_MAJOR}.${JSS_VERSION_MINOR}.${JSS_VERSION_PATCH}")
    set(JSS_VERSION_MANIFEST "${JSS_VERSION_MAJOR}.${JSS_VERSION_MINOR}")
    set(JSS_VERSION_STR "JSS_${JSS_VERSION_MAJOR}_${JSS_VERSION_MINOR}")

    if(${PATCH} GREATER 0)
        set(JSS_VERSION_MANIFEST "${JSS_VERSION_MANIFEST}.${JSS_VERSION_PATCH}")
        set(JSS_VERSION_STR "${JSS_VERSION_STR}_${JSS_VERSION_PATCH}")
    endif()
    if(${BETA} GREATER 0)
        set(JSS_VERSION "${JSS_VERSION} beta ${JSS_VERSION_BETA}")
        set(JSS_VERSION_STR "${JSS_VERSION_STR}_b${JSS_VERSION_BETA}")
    endif()

    # Template files
    configure_file(
        "${PROJECT_SOURCE_DIR}/org/mozilla/jss/util/jssver.h.in"
        "${PROJECT_SOURCE_DIR}/org/mozilla/jss/util/jssver.h"
    )
    configure_file(
        "${PROJECT_SOURCE_DIR}/lib/MANIFEST.MF.in"
        "${CMAKE_BINARY_DIR}/MANIFEST.MF"
    )
endmacro()

macro(jss_config_outputs)
    # Global variables representing various output files; note that these are
    # created at the end of this macro.
    set(CLASSES_OUTPUT_DIR "${CMAKE_BINARY_DIR}/classes/jss")
    set(DOCS_OUTPUT_DIR "${CMAKE_BINARY_DIR}/docs")
    set(LIB_OUTPUT_DIR "${CMAKE_BINARY_DIR}/lib")
    set(BIN_OUTPUT_DIR "${CMAKE_BINARY_DIR}/bin")
    set(INCLUDE_OUTPUT_DIR "${CMAKE_BINARY_DIR}/include/jss")
    set(JNI_OUTPUT_DIR "${CMAKE_BINARY_DIR}/include/jss/_jni")

    # This folder is for pseudo-locations for CMake targets
    set(TARGETS_OUTPUT_DIR "${CMAKE_BINARY_DIR}/.targets")

    # These folders are for the NSS DBs created during testing
    set(RESULTS_DATA_OUTPUT_DIR "${CMAKE_BINARY_DIR}/results/data")
    set(RESULTS_NSSDB_OUTPUT_DIR "${CMAKE_BINARY_DIR}/results/nssdb")
    set(RESULTS_NSSDB_FIPS_OUTPUT_DIR "${CMAKE_BINARY_DIR}/results/fips")

    # This is a temporary location for building the reproducible jar
    set(REPRODUCIBLE_TEMP_DIR "${CMAKE_BINARY_DIR}/reproducible")

    set(JSS_BUILD_JAR "staging.jar")
    set(JSS_JAR "jss${JSS_VERSION_MAJOR}.jar")
    set(JSS_SO "libjss${JSS_VERSION_MAJOR}.so")
    set(JSS_BUILD_JAR_PATH "${CMAKE_BINARY_DIR}/${JSS_BUILD_JAR}")
    set(JSS_JAR_PATH "${CMAKE_BINARY_DIR}/${JSS_JAR}")
    set(JSS_SO_PATH "${CMAKE_BINARY_DIR}/${JSS_SO}")

    # These options are for the test suite and mirror their non-tests
    # counterparts. Note that JSS_TESTS_SO is the same as JSS_SO, but
    # JSS_TESTS_SO_PATH differs -- one is "unversioned" and lacks a
    # version script so we can test internal methods.
    set(TESTS_CLASSES_OUTPUT_DIR "${CMAKE_BINARY_DIR}/classes/tests")
    set(TESTS_INCLUDE_OUTPUT_DIR "${CMAKE_BINARY_DIR}/include/tests")
    set(TESTS_JNI_OUTPUT_DIR "${CMAKE_BINARY_DIR}/include/jss/_jni")
    set(JSS_TESTS_JAR "tests-jss${JSS_VERSION_MAJOR}.jar")
    set(JSS_TESTS_SO "${JSS_SO}")
    set(JSS_TESTS_JAR_PATH "${CMAKE_BINARY_DIR}/${JSS_TESTS_JAR}")
    set(JSS_TESTS_SO_PATH "${LIB_OUTPUT_DIR}/${JSS_TESTS_SO}")

    # Create the *_OUTPUT_DIR locations.
    file(MAKE_DIRECTORY "${CLASSES_OUTPUT_DIR}")
    file(MAKE_DIRECTORY "${DOCS_OUTPUT_DIR}")
    file(MAKE_DIRECTORY "${LIB_OUTPUT_DIR}")
    file(MAKE_DIRECTORY "${BIN_OUTPUT_DIR}")
    file(MAKE_DIRECTORY "${INCLUDE_OUTPUT_DIR}")
    file(MAKE_DIRECTORY "${JNI_OUTPUT_DIR}")

    file(MAKE_DIRECTORY "${TARGETS_OUTPUT_DIR}")

    file(MAKE_DIRECTORY "${TESTS_CLASSES_OUTPUT_DIR}")
    file(MAKE_DIRECTORY "${TESTS_INCLUDE_OUTPUT_DIR}")
    file(MAKE_DIRECTORY "${TESTS_JNI_OUTPUT_DIR}")
endmacro()

macro(jss_config_cflags)
    # We check that the C compiler can handle each of the C flags below
    include(CheckCCompilerFlag)

    # This list of C flags was taken from the original build scripts for
    # debug and release builds.
    if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
        list(APPEND JSS_RAW_C_FLAGS "-Og")
        list(APPEND JSS_RAW_C_FLAGS "-ggdb")
        list(APPEND JSS_RAW_C_FLAGS "-DDEBUG")
        list(APPEND JSS_RAW_C_FLAGS "-DFORCE_PR_ASSERT")
    else()
        list(APPEND JSS_RAW_C_FLAGS "-O2")
    endif()

    list(APPEND JSS_RAW_C_FLAGS "-Wall")
    list(APPEND JSS_RAW_C_FLAGS "-std=gnu99")
    list(APPEND JSS_RAW_C_FLAGS "-Wno-cast-function-type")
    list(APPEND JSS_RAW_C_FLAGS "-Wno-unused-parameter")
    list(APPEND JSS_RAW_C_FLAGS "-Wno-unknown-warning-option")
    list(APPEND JSS_RAW_C_FLAGS "-Werror-implicit-function-declaration")
    list(APPEND JSS_RAW_C_FLAGS "-Wno-switch")
    list(APPEND JSS_RAW_C_FLAGS "-I${NSPR_INCLUDE_DIR}")
    list(APPEND JSS_RAW_C_FLAGS "-I${NSS_INCLUDE_DIR}")
    list(APPEND JSS_RAW_C_FLAGS "-I${INCLUDE_OUTPUT_DIR}")
    foreach(JNI_INCLUDE_DIR ${JNI_INCLUDE_DIRS})
        list(APPEND JSS_RAW_C_FLAGS "-I${JNI_INCLUDE_DIR}")
    endforeach()

    foreach(JSS_RAW_C_FLAG ${JSS_RAW_C_FLAGS})
        # Validate that each of our desired CFLAGS is supported by the
        # compiler, or well, at least the compiler doesn't immediately
        # error on it. :)
        check_c_compiler_flag(${JSS_RAW_C_FLAG} HAVE_C_FLAG)
        if(${HAVE_C_FLAG})
            list(APPEND JSS_C_FLAGS "${JSS_RAW_C_FLAG}")
        endif()
    endforeach()

    # Handle passed-in C flags as well; assume they are valid.
    separate_arguments(PASSED_C_FLAGS UNIX_COMMAND "${CMAKE_C_FLAGS}")
    foreach(PASSED_C_FLAG ${PASSED_C_FLAGS})
        list(INSERT JSS_C_FLAGS 0 "${PASSED_C_FLAG}")
    endforeach()

    message(STATUS "JSS C FLAGS: ${JSS_C_FLAGS}")
endmacro()

macro(jss_config_ldflags)
    # This list of C linker flags was taken from the original build scripts
    # for debug and release builds. We lack a "check_c_linker_flag" macro,
    # so no effort is made to validate these flags.
    list(APPEND JSS_LD_FLAGS "-lsmime3")
    list(APPEND JSS_LD_FLAGS "-lssl3")
    list(APPEND JSS_LD_FLAGS "-lnss3")
    list(APPEND JSS_LD_FLAGS "-lnssutil3")
    list(APPEND JSS_LD_FLAGS "-lplc4")
    list(APPEND JSS_LD_FLAGS "-lplds4")
    list(APPEND JSS_LD_FLAGS "-lnspr4")
    list(APPEND JSS_LD_FLAGS "-lpthread")
    list(APPEND JSS_LD_FLAGS "-ldl")

    separate_arguments(PASSED_LD_FLAGS UNIX_COMMAND "${CMAKE_SHARED_LINKER_FLAGS}")
    foreach(PASSED_LD_FLAG ${PASSED_LD_FLAGS})
        list(INSERT JSS_LD_FLAGS 0 "${PASSED_LD_FLAG}")
    endforeach()

    # This set of flags is specific to building the libjss library.
    list(APPEND JSS_LIBRARY_FLAGS "-shared")
    list(APPEND JSS_LIBRARY_FLAGS "-Wl,-z,defs")
    list(APPEND JSS_LIBRARY_FLAGS "-Wl,-soname")
    list(APPEND JSS_LIBRARY_FLAGS "-Wl,${JSS_SO}")

    set(JSS_VERSION_SCRIPT "-Wl,--version-script,${PROJECT_SOURCE_DIR}/lib/jss.map")

    message(STATUS "JSS LD FLAGS: ${JSS_LD_FLAGS}")
    message(STATUS "JSS LIBRARY FLAGS: ${JSS_LIBRARY_FLAGS}")
endmacro()

macro(jss_config_java)
    # Find various JARs required by JSS build and test suite
    find_jar(
        SLF4J_API_JAR
        NAMES api slf4j/api slf4j-api
    )
    find_jar(
        CODEC_JAR
        NAMES apache-commons-codec commons-codec
    )
    find_jar(
        LANG_JAR
        NAMES apache-commons-lang commons-lang
    )
    find_jar(
        JAXB_JAR
        NAMES jaxb-api
    )
    find_jar(
        SLF4J_JDK14_JAR
        NAMES jdk14 slf4j/jdk14 slf4j-jdk14
    )
    find_jar(
        JUNIT4_JAR
        NAMES junit4 junit
    )
    find_jar(
        HAMCREST_JAR
        NAMES hamcrest/core hamcrest-core
    )

    # Validate that we've found the required JARs
    if(SLF4J_API_JAR STREQUAL "SLF4J_API_JAR-NOTFOUND")
        message(FATAL_ERROR "Required dependency sfl4j-api.jar not found by find_jar!")
    endif()

    if(CODEC_JAR STREQUAL "CODEC_JAR-NOTFOUND")
        message(FATAL_ERROR "Required dependency apache-commons-codec.jar not found by find_jar!")
    endif()

    if(LANG_JAR STREQUAL "LANG_JAR-NOTFOUND")
        message(FATAL_ERROR "Required dependency apache-commons-lang.jar not found by find_jar!")
    endif()

    if(JAXB_JAR STREQUAL "JAXB_JAR-NOTFOUND")
        message(FATAL_ERROR "Required dependency javaee-jaxb-api.jar not found by find_jar!")
    endif()

    if(SLF4J_JDK14_JAR STREQUAL "SLF4J_JDK14_JAR-NOTFOUND")
        message(WARNING "Test dependency sfl4j-jdk14.jar not found by find_jar! Tests might not run properly.")
    endif()

    if(JUINT4_JAR STREQUAL "JUNIT4_JAR-NOTFOUND")
        message(FATAL_ERROR "Test dependency junit4.jar not found by find_jar! Tests will not compile.")
    endif()

    if(HAMCREST_JAR STREQUAL "HAMCREST_JAR-NOTFOUND")
        message(WARNING "Test dependency hamcrest/core.jar not found by find_jar! Tests might not run properly.")
    endif()

    # Set class paths
    set(JAVAC_CLASSPATH "${SLF4J_API_JAR}:${CODEC_JAR}:${LANG_JAR}:${JAXB_JAR}")
    set(TEST_CLASSPATH "${JSS_JAR_PATH}:${JSS_TESTS_JAR_PATH}:${JAVAC_CLASSPATH}:${SLF4J_JDK14_JAR}:${JUNIT4_JAR}:${HAMCREST_JAR}")

    message(STATUS "javac classpath: ${JAVAC_CLASSPATH}")
    message(STATUS "tests classpath: ${TEST_CLASSPATH}")

    # Set compile flags for JSS
    list(APPEND JSS_JAVAC_FLAGS "-classpath")
    list(APPEND JSS_JAVAC_FLAGS "${JAVAC_CLASSPATH}")
    list(APPEND JSS_JAVAC_FLAGS "-sourcepath")
    list(APPEND JSS_JAVAC_FLAGS "${PROJECT_SOURCE_DIR}")

    # Ensure we're compatible with JDK 8
    list(APPEND JSS_JAVAC_FLAGS "-target")
    list(APPEND JSS_JAVAC_FLAGS "1.8")
    list(APPEND JSS_JAVAC_FLAGS "-source")
    list(APPEND JSS_JAVAC_FLAGS "1.8")

    # Handle passed-in javac flags as well; assume they are valid.
    separate_arguments(PASSED_JAVAC_FLAGS UNIX_COMMAND "$ENV{JAVACFLAGS}")
    foreach(PASSED_JAVAC_FLAG ${PASSED_JAVAC_FLAGS})
        list(APPEND JSS_JAVAC_FLAGS "${PASSED_JAVAC_FLAG}")
    endforeach()

    if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
        list(APPEND JSS_JAVAC_FLAGS "-g")
    else()
        list(APPEND JSS_JAVAC_FLAGS "-O")
    endif()

    # Set compile flags for JSS test suite
    list(APPEND JSS_TEST_JAVAC_FLAGS "-classpath")
    list(APPEND JSS_TEST_JAVAC_FLAGS "${JAVAC_CLASSPATH}:${JUNIT4_JAR}")
    list(APPEND JSS_TEST_JAVAC_FLAGS "-sourcepath")
    list(APPEND JSS_TEST_JAVAC_FLAGS "${PROJECT_SOURCE_DIR}")

    # Ensure we're compatible with JDK 8
    list(APPEND JSS_TEST_JAVAC_FLAGS "-target")
    list(APPEND JSS_TEST_JAVAC_FLAGS "1.8")
    list(APPEND JSS_TEST_JAVAC_FLAGS "-source")
    list(APPEND JSS_TEST_JAVAC_FLAGS "1.8")

    # Handle passed-in javac flags as well; assume they are valid.
    separate_arguments(PASSED_JAVAC_FLAGS UNIX_COMMAND "$ENV{JAVACFLAGS}")
    foreach(PASSED_JAVAC_FLAG ${PASSED_JAVAC_FLAGS})
        list(APPEND JSS_TEST_JAVAC_FLAGS "${PASSED_JAVAC_FLAG}")
    endforeach()

    if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
        list(APPEND JSS_TEST_JAVAC_FLAGS "-g")
    else()
        list(APPEND JSS_TEST_JAVAC_FLAGS "-O")
    endif()

    # Variables for javadoc building. Note that JSS_PACKAGES needs to be
    # updated whenever a new package is created.
    set(JSS_WINDOW_TITLE "JSS: Java Security Services")
    set(JSS_PACKAGES "org.mozilla.jss;org.mozilla.jss.asn1;org.mozilla.jss.crypto;org.mozilla.jss.pkcs7;org.mozilla.jss.pkcs10;org.mozilla.jss.pkcs11;org.mozilla.jss.pkcs12;org.mozilla.jss.pkix.primitive;org.mozilla.jss.pkix.cert;org.mozilla.jss.pkix.cmc;org.mozilla.jss.pkix.cmmf;org.mozilla.jss.pkix.cms;org.mozilla.jss.pkix.crmf;org.mozilla.jss.provider.java.security;org.mozilla.jss.provider.javax.crypto;org.mozilla.jss.SecretDecoderRing;org.mozilla.jss.ssl;org.mozilla.jss.util;org.mozilla.jss.netscape.security.util;org.mozilla.jss.netscape.security.extensions;org.mozilla.jss.netscape.security.acl;org.mozilla.jss.netscape.security.pkcs;org.mozilla.jss.netscape.security.x509;org.mozilla.jss.netscape.security.provider;org.mozilla.jss.nss;org.mozilla.jss.ssl.javax")

    set(JSS_BASE_PORT 2876)
    math(EXPR JSS_TEST_PORT_CLIENTAUTH ${JSS_BASE_PORT}+0)
    math(EXPR JSS_TEST_PORT_CLIENTAUTH_FIPS ${JSS_BASE_PORT}+1)
endmacro()
