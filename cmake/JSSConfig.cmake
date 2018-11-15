macro(jss_config)
    # Set the current JSS release number. Arguments are MAJOR MINOR PATCH.
    jss_config_version(4 5 0 0)

    jss_config_outputs()

    jss_config_cflags()
    jss_config_ldflags()

    jss_config_java()
endmacro()

macro(jss_config_version MAJOR MINOR PATCH BETA)
    # This sets the JSS Version for use in CMake and propagates it to the
    # necessary source locations. These are:
    #
    #   org/mozilla/jss/CryptoManager.java{.in,}
    #   org/mozilla/jss/JSSProvider.java{.in,}
    #   org/mozilla/jss/util/jssver.h{.in,}
    #   lib/MANIFEST.MF.in -> build/MANIFEST.MF
    #
    # On a build, these automatically get generated with the correct versions
    # included. Note that all "sets" are of global scope, so these variables
    # can be used anywhere that is necessary, hence why

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
    # created here.
    set(CLASSES_OUTPUT_DIR "${CMAKE_BINARY_DIR}/classes")
    set(DOCS_OUTPUT_DIR "${CMAKE_BINARY_DIR}/docs")
    set(JNI_OUTPUT_DIR "${CMAKE_BINARY_DIR}/jss/_jni")
    set(LIB_OUTPUT_DIR "${CMAKE_BINARY_DIR}/lib")
    set(INCLUDE_OUTPUT_DIR "${CMAKE_BINARY_DIR}/include")

    # These two are pseudo-locations for CMake targets and the test suite
    set(TARGETS_OUTPUT_DIR "${CMAKE_BINARY_DIR}/.targets")
    set(RESULTS_OUTPUT_DIR "${CMAKE_BINARY_DIR}/results/tests")
    set(RESULTS_FIPS_OUTPUT_DIR "${CMAKE_BINARY_DIR}/results/fips")

    set(JSS_JAR "jss${JSS_VERSION_MAJOR}.jar")
    set(JSS_SO "libjss${JSS_VERSION_MAJOR}.so")
    set(JSS_JAR_PATH "${CMAKE_BINARY_DIR}/${JSS_JAR}")
    set(JSS_SO_PATH "${CMAKE_BINARY_DIR}/${JSS_SO}")

    # Create the *_OUTPUT_DIR locations.
    file(MAKE_DIRECTORY "${JNI_OUTPUT_DIR}")
    file(MAKE_DIRECTORY "${CLASSES_OUTPUT_DIR}")
    file(MAKE_DIRECTORY "${DOCS_OUTPUT_DIR}")
    file(MAKE_DIRECTORY "${LIB_OUTPUT_DIR}")
    file(MAKE_DIRECTORY "${INCLUDE_OUTPUT_DIR}")
    file(MAKE_DIRECTORY "${TARGETS_OUTPUT_DIR}")
    file(MAKE_DIRECTORY "${RESULTS_OUTPUT_DIR}")
    file(MAKE_DIRECTORY "${RESULTS_FIPS_OUTPUT_DIR}")
endmacro()

macro(jss_config_cflags)
    include(CheckCCompilerFlag)

    list(APPEND JSS_RAW_C_FLAGS "-c")
    list(APPEND JSS_RAW_C_FLAGS "-g")
    list(APPEND JSS_RAW_C_FLAGS "-fPIC")
    list(APPEND JSS_RAW_C_FLAGS "-Wall")
    list(APPEND JSS_RAW_C_FLAGS "-Werror-implicit-function-declaration")
    list(APPEND JSS_RAW_C_FLAGS "-Wno-switch")
    list(APPEND JSS_RAW_C_FLAGS "-pipe")
    list(APPEND JSS_RAW_C_FLAGS "-I${NSPR_INCLUDE_DIR}")
    list(APPEND JSS_RAW_C_FLAGS "-I${NSS_INCLUDE_DIR}")
    list(APPEND JSS_RAW_C_FLAGS "-I${INCLUDE_OUTPUT_DIR}")
    foreach(JNI_INCLUDE_DIR ${JNI_INCLUDE_DIRS})
        list(APPEND JSS_RAW_C_FLAGS "-I${JNI_INCLUDE_DIR}")
    endforeach()
    list(APPEND JSS_RAW_C_FLAGS "-I${CMAKE_BINARY_DIR}/jss")

    foreach(JSS_RAW_C_FLAG ${JSS_RAW_C_FLAGS})
        # Validate that each of our desired CFLAGS is supported by the
        # compiler, or well, at least the compiler doesn't immediately
        # error on it. :)
        check_c_compiler_flag(${JSS_RAW_C_FLAG} HAVE_C_FLAG)
        if(${HAVE_C_FLAG})
            list(APPEND JSS_C_FLAGS "${JSS_RAW_C_FLAG}")
        endif()
    endforeach()

    separate_arguments(PASSED_C_FLAGS UNIX_COMMAND "${CMAKE_C_FLAGS}")
    foreach(PASSED_C_FLAG ${PASSED_C_FLAGS})
        list(APPEND JSS_C_FLAGS "${PASSED_C_FLAG}")
    endforeach()

    message(STATUS "JSS C FLAGS: ${JSS_C_FLAGS}")
endmacro()

macro(jss_config_ldflags)
    list(APPEND JSS_LD_FLAGS "-shared")
    list(APPEND JSS_LD_FLAGS "-Wl,-z,defs")
    list(APPEND JSS_LD_FLAGS "-Wl,-soname")
    list(APPEND JSS_LD_FLAGS "-Wl,${JSS_SO}")
    list(APPEND JSS_LD_FLAGS "-Wl,--version-script,${PROJECT_SOURCE_DIR}/lib/jss.map")
    list(APPEND JSS_LD_FLAGS "-lsmime3")
    list(APPEND JSS_LD_FLAGS "-lssl3")
    list(APPEND JSS_LD_FLAGS "-lnss3")
    list(APPEND JSS_LD_FLAGS "-lnssutil3")
    list(APPEND JSS_LD_FLAGS "-lplc4")
    list(APPEND JSS_LD_FLAGS "-lplds4")
    list(APPEND JSS_LD_FLAGS "-lnspr4")
    list(APPEND JSS_LD_FLAGS "-lpthread")
    list(APPEND JSS_LD_FLAGS "-ldl")
endmacro()

macro(jss_config_java)
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

    set(JAVAC_CLASSPATH "${SLF4J_API_JAR}:${CODEC_JAR}:${LANG_JAR}:${JAXB_JAR}")
    set(TEST_CLASSPATH "${JSS_JAR_PATH}:${JAVAC_CLASSPATH}:${SLF4J_JDK14_JAR}")

    set(JSS_WINDOW_TITLE "JSS: Java Security Services")
    set(JSS_PACKAGES "org.mozilla.jss;org.mozilla.jss.asn1;org.mozilla.jss.crypto;org.mozilla.jss.pkcs7;org.mozilla.jss.pkcs10;org.mozilla.jss.pkcs11;org.mozilla.jss.pkcs12;org.mozilla.jss.pkix.primitive;org.mozilla.jss.pkix.cert;org.mozilla.jss.pkix.cmc;org.mozilla.jss.pkix.cmmf;org.mozilla.jss.pkix.cms;org.mozilla.jss.pkix.crmf;org.mozilla.jss.provider.java.security;org.mozilla.jss.provider.javax.crypto;org.mozilla.jss.SecretDecoderRing;org.mozilla.jss.ssl;org.mozilla.jss.tests;org.mozilla.jss.util")
endmacro()
