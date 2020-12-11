macro(jss_config)
    # Set the current JSS release number. Arguments are:
    #   MAJOR MINOR PATCH BETA
    # When BETA is zero, it isn't a beta release.
    jss_config_version(4 8 1 0)

    # Configure output directories
    jss_config_outputs()

    # Configure flags for compiling and linking
    jss_config_cflags()
    jss_config_ldflags()

    # Configure java-related flags
    jss_config_java()

    # Configure test variables
    jss_config_tests()

    # Check symbols to see what tests we run
    jss_config_symbols()

    # Template auto-generated files
    jss_config_template()
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
endmacro()

macro(jss_config_outputs)
    # Global variables representing various output files; note that these
    # directories are created at the end of this macro.
    set(CLASSES_OUTPUT_DIR "${CMAKE_BINARY_DIR}/classes/jss")
    set(CONFIG_OUTPUT_DIR "${CMAKE_BINARY_DIR}/config")
    set(DOCS_OUTPUT_DIR "${CMAKE_BINARY_DIR}/docs")
    set(LIB_OUTPUT_DIR "${CMAKE_BINARY_DIR}/lib")
    set(BIN_OUTPUT_DIR "${CMAKE_BINARY_DIR}/bin")
    set(INCLUDE_OUTPUT_DIR "${CMAKE_BINARY_DIR}/include/jss")
    set(JNI_OUTPUT_DIR "${CMAKE_BINARY_DIR}/include/jss/_jni")

    # This folder is for pseudo-locations for CMake targets
    set(TARGETS_OUTPUT_DIR "${CMAKE_BINARY_DIR}/.targets")
    set(JAVA_SOURCES_FILE "${TARGETS_OUTPUT_DIR}/java.sources")
    set(JAVA_TEST_SOURCES_FILE "${TARGETS_OUTPUT_DIR}/java-test.sources")

    # These folders are for the NSS DBs created during testing
    set(RESULTS_DATA_OUTPUT_DIR "${CMAKE_BINARY_DIR}/results/data")
    set(RESULTS_NSSDB_OUTPUT_DIR "${CMAKE_BINARY_DIR}/results/nssdb")
    set(RESULTS_NSSDB_FIPS_OUTPUT_DIR "${CMAKE_BINARY_DIR}/results/fips")
    set(RESULTS_NSSDB_INTERNET_OUTPUT_DIR "${CMAKE_BINARY_DIR}/results/internet")

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
    file(MAKE_DIRECTORY "${CONFIG_OUTPUT_DIR}")
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
    list(APPEND JSS_RAW_C_FLAGS "-Wno-unused-but-set-variable")
    list(APPEND JSS_RAW_C_FLAGS "-Werror-implicit-function-declaration")
    list(APPEND JSS_RAW_C_FLAGS "-Wno-switch")
    list(APPEND JSS_RAW_C_FLAGS "-I${INCLUDE_OUTPUT_DIR}")
    foreach(JNI_INCLUDE_DIR ${JNI_INCLUDE_DIRS})
        list(APPEND JSS_RAW_C_FLAGS "-I${JNI_INCLUDE_DIR}")
    endforeach()
    foreach(NSPR_INCLUDE_DIR ${NSPR_INCLUDE_DIRS})
        list(APPEND JSS_RAW_C_FLAGS "-I${NSPR_INCLUDE_DIR}")
    endforeach()
    foreach(NSS_INCLUDE_DIR ${NSS_INCLUDE_DIRS})
        list(APPEND JSS_RAW_C_FLAGS "-I${NSS_INCLUDE_DIR}")
    endforeach()
    foreach(NSPR_LIBRARY ${NSPR_LIBRARIES})
        list(APPEND JSS_RAW_C_FLAGS "-L${NSPR_LIBRARY}")
    endforeach()
    foreach(NSS_LIBRARY ${NSS_LIBRARIES})
        list(APPEND JSS_RAW_C_FLAGS "-L${NSS_LIBRARY}")
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
        LANG_JAR
        NAMES apache-commons-lang3 commons-lang3
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

    if(LANG_JAR STREQUAL "LANG_JAR-NOTFOUND")
        message(FATAL_ERROR "Required dependency apache-commons-lang.jar not found by find_jar!")
    endif()

    if(JAXB_JAR STREQUAL "JAXB_JAR-NOTFOUND")
        message(FATAL_ERROR "Required dependency javaee-jaxb-api.jar not found by find_jar!")
    endif()

    if(SLF4J_JDK14_JAR STREQUAL "SLF4J_JDK14_JAR-NOTFOUND")
        message(WARNING "Test dependency sfl4j-jdk14.jar not found by find_jar! Tests might not run properly.")
    endif()

    if(JUNIT4_JAR STREQUAL "JUNIT4_JAR-NOTFOUND")
        message(FATAL_ERROR "Test dependency junit4.jar not found by find_jar! Tests will not compile.")
    endif()

    if(HAMCREST_JAR STREQUAL "HAMCREST_JAR-NOTFOUND")
        message(WARNING "Test dependency hamcrest/core.jar not found by find_jar! Tests might not run properly.")
    endif()

    # Set class paths
    set(JAVAC_CLASSPATH "${SLF4J_API_JAR}:${LANG_JAR}:${JAXB_JAR}")
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
        list(APPEND JSS_JAVAC_FLAGS "-Xlint:unchecked")
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

    message(STATUS "JSS JAVAC FLAGS: ${JSS_JAVAC_FLAGS}")
    message(STATUS "JSS TEST JAVAC FLAGS: ${JSS_TEST_JAVAC_FLAGS}")

    # Variables for javadoc building.
    set(JSS_WINDOW_TITLE "JSS: Java Security Services")

    set(JSS_BASE_PORT 2876)
    math(EXPR JSS_TEST_PORT_CLIENTAUTH ${JSS_BASE_PORT}+0)
    math(EXPR JSS_TEST_PORT_CLIENTAUTH_FIPS ${JSS_BASE_PORT}+1)

    # Create META-INF directory for provider
    file(MAKE_DIRECTORY "${CLASSES_OUTPUT_DIR}/META-INF/services")
endmacro()

macro(jss_config_template)
    # Template files
    configure_file(
        "${PROJECT_SOURCE_DIR}/org/mozilla/jss/jssconfig.h.in"
        "${PROJECT_SOURCE_DIR}/org/mozilla/jss/jssconfig.h"
    )
    configure_file(
        "${PROJECT_SOURCE_DIR}/org/mozilla/jss/util/jssver.h.in"
        "${PROJECT_SOURCE_DIR}/org/mozilla/jss/util/jssver.h"
    )
    configure_file(
        "${PROJECT_SOURCE_DIR}/lib/MANIFEST.MF.in"
        "${CMAKE_BINARY_DIR}/MANIFEST.MF"
    )
    configure_file(
        "${PROJECT_SOURCE_DIR}/lib/java.security.Provider.in"
        "${CLASSES_OUTPUT_DIR}/META-INF/services/java.security.Provider"
    )
    configure_file(
        "${PROJECT_SOURCE_DIR}/tools/run_test.sh.in"
        "${CMAKE_BINARY_DIR}/run_test.sh"
    )
    set(JSS_CFG_PATH "${CONFIG_OUTPUT_DIR}/jss.cfg")
    configure_file(
        "${PROJECT_SOURCE_DIR}/tools/java.security.in"
        "${CONFIG_OUTPUT_DIR}/java.security"
        @ONLY
    )
    set(NSS_DB_PATH "${RESULTS_NSSDB_OUTPUT_DIR}")
    configure_file(
        "${PROJECT_SOURCE_DIR}/tools/jss.cfg.in"
        "${JSS_CFG_PATH}"
    )
    set(JSS_CFG_PATH "${CONFIG_OUTPUT_DIR}/jss-fips.cfg")
    configure_file(
        "${PROJECT_SOURCE_DIR}/tools/java.security.in"
        "${CONFIG_OUTPUT_DIR}/fips.security"
        @ONLY
    )
    set(NSS_DB_PATH "${RESULTS_NSSDB_FIPS_OUTPUT_DIR}")
    configure_file(
        "${PROJECT_SOURCE_DIR}/tools/jss.cfg.in"
        "${JSS_CFG_PATH}"
    )
    set(JSS_CFG_PATH "${CONFIG_OUTPUT_DIR}/jss-internet.cfg")
    configure_file(
        "${PROJECT_SOURCE_DIR}/tools/java.security.in"
        "${CONFIG_OUTPUT_DIR}/internet.security"
        @ONLY
    )
    set(NSS_DB_PATH "${RESULTS_NSSDB_INTERNET_OUTPUT_DIR}")
    configure_file(
        "${PROJECT_SOURCE_DIR}/tools/jss.cfg.in"
        "${JSS_CFG_PATH}"
    )
    unset(JSS_CFG_PATH)
    unset(NSS_DB_PATH)
endmacro()

macro(jss_config_symbols)
    list(APPEND CMAKE_REQUIRED_INCLUDES ${NSPR_INCLUDE_DIRS})
    list(APPEND CMAKE_REQUIRED_INCLUDES ${NSS_INCLUDE_DIRS})
    jss_list_join(JSS_C_FLAGS " " CMAKE_REQUIRED_FLAGS)

    check_symbol_exists("CKM_AES_CMAC" "nspr.h;nss.h;pkcs11t.h" HAVE_NSS_CMAC)
    if(NOT HAVE_NSS_CMAC)
        message(WARNING "Your NSS version doesn't support CMAC; some features of JSS won't work.")
    endif()

    check_symbol_exists("CKM_SP800_108_COUNTER_KDF" "nspr.h;nss.h;pkcs11t.h" HAVE_NSS_KBKDF)
    if(NOT HAVE_NSS_KBKDF)
        message(WARNING "Your NSS version doesn't support NIST SP800-108 KBKDF; some features of JSS won't work.")
    endif()

    try_compile(CK_HAVE_COMPILING_OAEP
                ${CMAKE_BINARY_DIR}/results
                ${CMAKE_SOURCE_DIR}/tools/tests/oaep.c
                CMAKE_FLAGS
                    "-DINCLUDE_DIRECTORIES=${CMAKE_REQUIRED_INCLUDES}"
                    "-DREQUIRED_FLAGS=${CMAKE_REQUIRED_FLAGS}"
                LINK_OPTIONS ${JSS_LD_FLAGS}
                OUTPUT_VARIABLE COMP_OUT)
    if (CK_HAVE_COMPILING_OAEP)
        set(HAVE_NSS_OAEP TRUE)
    else()
        message(WARNING "Your NSS version doesn't support RSA-OAEP key wra/unwrap; some features of JSS won't work.")
        message(WARNING "Compile output: ${COMP_OUT}")
    endif()


    if(HAVE_NSS_CMAC)
        try_run(CK_HAVE_WORKING_CMAC
                CK_HAVE_COMPILING_CMAC
                ${CMAKE_BINARY_DIR}/results
                ${CMAKE_SOURCE_DIR}/tools/tests/cmac.c
                CMAKE_FLAGS
                        "-DINCLUDE_DIRECTORIES=${CMAKE_REQUIRED_INCLUDES}"
                        "-DREQUIRED_FLAGS=${CMAKE_REQUIRED_FLAGS}"
                COMPILE_OUTPUT_VARIABLE COMP_OUT
                RUN_OUTPUT_VARIABLE RUN_OUT)

        if (NOT CK_HAVE_WORKING_CMAC STREQUAL "0" OR NOT CK_HAVE_COMPILING_CMAC)
            set(HAVE_NSS_CMAC FALSE)
            set(HAVE_NSS_KBKDF FALSE)
            message(WARNING "Your NSS version is broken: between NSS v3.47 and v3.50, the values of CKM_AES_CMAC and CKM_AES_CMAC_GENERAL were swapped. Disabling CMAC and KBKDF support.")
            message(WARNING "Compile output: ${COMP_OUT}")
            message(WARNING "Run output: ${RUN_OUT}")
        endif()
    endif()

    # Added in NSS v3.43
    check_struct_has_member(
        SSLCipherSuiteInfo
        kdfHash
        ssl.h
        HAVE_NSS_CIPHER_SUITE_INFO_KDFHASH
    )

    # Added in NSS v3.34
    check_struct_has_member(
        SSLChannelInfo
        originalKeaGroup
        ssl.h
        HAVE_NSS_CHANNEL_INFO_ORIGINAL_KEA_GROUP
    )

    # Added in NSS v3.45
    check_struct_has_member(
        SSLChannelInfo
        peerDelegCred
        ssl.h
        HAVE_NSS_CHANNEL_INFO_PEER_DELEG_CRED
    )

    # Added in NSS v3.43
    check_struct_has_member(
        SSLPreliminaryChannelInfo
        zeroRttCipherSuite
        ssl.h
        HAVE_NSS_PRELIMINARY_CHANNEL_INFO_ZERO_RTT_CIPHER_SUITE
    )

    # Added in NSS v3.48
    check_struct_has_member(
        SSLPreliminaryChannelInfo
        peerDelegCred
        ssl.h
        HAVE_NSS_PRELIMINARY_CHANNEL_INFO_PEER_DELEG_CRED
    )
endmacro()

macro(jss_config_tests)
    # Common variables used as arguments to several tests
    set(JSS_TEST_DIR "${PROJECT_SOURCE_DIR}/org/mozilla/jss/tests")
    set(PASSWORD_FILE "${JSS_TEST_DIR}/passwords")
    set(DB_PWD "m1oZilla")
endmacro()
