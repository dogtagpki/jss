macro(jss_tests)
    enable_testing()

    jss_tests_compile()

    # Create directories for test cases:
    #  - results/data
    #  - results/nssdb
    #  - results/fips
    jss_test_exec(
        NAME "Clean_Data_Dir"
        COMMAND "cmake" "-E" "remove_directory" "${RESULTS_DATA_OUTPUT_DIR}"
    )
    jss_test_exec(
        NAME "Create_Data_Dir"
        COMMAND "cmake" "-E" "make_directory" "${RESULTS_DATA_OUTPUT_DIR}"
        DEPENDS "Clean_Data_Dir"
    )

    # Rather than creating our results directories earlier in JSSConfig,
    # create them here so that the test suite can be rerun multiple times.
    jss_test_exec(
        NAME "Clean_Setup_DBs"
        COMMAND "cmake" "-E" "remove_directory" "${RESULTS_NSSDB_OUTPUT_DIR}"
    )
    jss_test_exec(
        NAME "Create_Setup_DBs"
        COMMAND "cmake" "-E" "make_directory" "${RESULTS_NSSDB_OUTPUT_DIR}"
        DEPENDS "Clean_Setup_DBs"
    )
    jss_test_java(
        NAME "Setup_DBs"
        COMMAND "org.mozilla.jss.tests.SetupDBs" "${RESULTS_NSSDB_OUTPUT_DIR}" "${PASSWORD_FILE}"
        DEPENDS "Create_Setup_DBs"
        MODE "NONE"
    )

    # Various FIPS related tests depend on FIPS being enabled; since this
    # affects the entire NSS DB, create a separate database for them.
    jss_test_exec(
        NAME "Clean_FIPS_Setup_DBs"
        COMMAND "cmake" "-E" "remove_directory" "${RESULTS_NSSDB_FIPS_OUTPUT_DIR}"
    )
    jss_test_exec(
        NAME "Create_FIPS_Setup_DBs"
        COMMAND "cmake" "-E" "make_directory" "${RESULTS_NSSDB_FIPS_OUTPUT_DIR}"
        DEPENDS "Clean_FIPS_Setup_DBs"
    )
    jss_test_java(
        NAME "Setup_FIPS_DBs"
        COMMAND "org.mozilla.jss.tests.SetupDBs" "${RESULTS_NSSDB_FIPS_OUTPUT_DIR}" "${PASSWORD_FILE}"
        DEPENDS "Create_FIPS_Setup_DBs"
        MODE "NONE"
    )

    # NSS DB for internet connected tests; imports global root CA certs.
    if(TEST_WITH_INTERNET)
        jss_test_exec(
            NAME "Clean_Internet_Setup_DBs"
            COMMAND "cmake" "-E" "remove_directory" "${RESULTS_NSSDB_INTERNET_OUTPUT_DIR}"
        )
        jss_test_exec(
            NAME "Import_Internet_Certs"
            COMMAND "${CMAKE_SOURCE_DIR}/tools/common_roots.sh" "${RESULTS_NSSDB_INTERNET_OUTPUT_DIR}"
            DEPENDS "Clean_Internet_Setup_DBs"
        )
    endif()

    jss_test_exec(
        NAME "TestBufferPRFD"
        COMMAND "${BIN_OUTPUT_DIR}/TestBufferPRFD"
    )
    jss_test_java(
        NAME "Test_UTF-8_Converter"
        COMMAND "org.mozilla.jss.tests.UTF8ConverterTest"
    )
    jss_test_java(
        NAME "Test_Base64_Parsing"
        COMMAND "org.mozilla.jss.tests.Base64Parsing"
    )
    jss_test_java(
        NAME "JSS_DER_Encoding_of_Enumeration_regression_test"
        COMMAND "org.mozilla.jss.tests.EnumerationZeroTest"
    )
    jss_test_java(
        NAME "JSS_Test_DER_Encoding_Functionality"
        COMMAND "org.mozilla.jss.tests.DEROutputStreamTests"
    )
    jss_test_java(
        NAME "JSS_Test_Empty_DER_Value"
        COMMAND "org.mozilla.jss.tests.EmptyDerValue"
    )
    jss_test_java(
        NAME "BigObjectIdentifier"
        COMMAND "org.mozilla.jss.tests.BigObjectIdentifier"
    )
    jss_test_java(
        NAME "JSS_Test_PR_FileDesc"
        COMMAND "org.mozilla.jss.tests.TestPRFD"
    )
    jss_test_java(
        NAME "JSS_Test_Raw_SSL"
        COMMAND "org.mozilla.jss.tests.TestRawSSL" "${RESULTS_NSSDB_OUTPUT_DIR}"
        DEPENDS "Setup_DBs"
    )
    jss_test_java(
        NAME "JSS_Test_Buffer"
        COMMAND "org.mozilla.jss.tests.TestBuffer"
    )
    jss_test_java(
        NAME "JSS_Test_GlobalRefProxy"
        COMMAND "org.mozilla.jss.tests.TestGlobalReference"
        MODE "NONE"
    )
    if ((${Java_VERSION_MAJOR} EQUAL 1) AND (${Java_VERSION_MINOR} LESS 9) AND (${JSS_VERSION_BETA} EQUAL 1))
        jss_test_java(
            NAME "Test_PKCS11Constants.java_for_Sun_compatibility"
            COMMAND "org.mozilla.jss.tests.TestPKCS11Constants"
        )
    endif()
    jss_test_java(
        NAME "JUnit_BMPStringTest"
        COMMAND "org.junit.runner.JUnitCore" "org.mozilla.jss.tests.BMPStringTest"
    )
    jss_test_java(
        NAME "JUnit_IA5StringTest"
        COMMAND "org.junit.runner.JUnitCore" "org.mozilla.jss.tests.IA5StringTest"
    )
    jss_test_java(
        NAME "JUnit_PrintableStringTest"
        COMMAND "org.junit.runner.JUnitCore" "org.mozilla.jss.tests.PrintableStringTest"
    )
    jss_test_java(
        NAME "JUnit_TeletexStringTest"
        COMMAND "org.junit.runner.JUnitCore" "org.mozilla.jss.tests.TeletexStringTest"
    )
    jss_test_java(
        NAME "JUnit_UniversalStringTest"
        COMMAND "org.junit.runner.JUnitCore" "org.mozilla.jss.tests.UniversalStringTest"
    )
    jss_test_java(
        NAME "JUnit_UTF8StringTest"
        COMMAND "org.junit.runner.JUnitCore" "org.mozilla.jss.tests.UTF8StringTest"
    )
    jss_test_exec(
        NAME "buffer_size_1"
        COMMAND "${BIN_OUTPUT_DIR}/buffer_size_1"
        DEPENDS "generate_c_buffer_size_1"
    )
    jss_test_exec(
        NAME "buffer_size_4"
        COMMAND "${BIN_OUTPUT_DIR}/buffer_size_4"
        DEPENDS "generate_c_buffer_size_4"
    )
    jss_test_java(
        NAME "JUnit_CertificateChainTest"
        COMMAND "org.junit.runner.JUnitCore" "org.mozilla.jss.tests.CertificateChainTest"
    )
    jss_test_java(
        NAME "JUnit_ChainSortingTest"
        COMMAND "org.junit.runner.JUnitCore" "org.mozilla.jss.tests.ChainSortingTest"
    )
    jss_test_java(
        NAME "Generate_known_RSA_cert_pair"
        COMMAND "org.mozilla.jss.tests.GenerateTestCert" "${RESULTS_NSSDB_OUTPUT_DIR}" "${PASSWORD_FILE}" "20" "localhost" "SHA-256/RSA" "CA_RSA" "Server_RSA" "Client_RSA"
        DEPENDS "Setup_DBs"
    )
    jss_test_java(
        NAME "Generate_known_ECDSA_cert_pair"
        COMMAND "org.mozilla.jss.tests.GenerateTestCert" "${RESULTS_NSSDB_OUTPUT_DIR}" "${PASSWORD_FILE}" "30" "localhost" "SHA-256/EC" "CA_ECDSA" "Server_ECDSA" "Client_ECDSA"
        DEPENDS "Generate_known_RSA_cert_pair"
    )
    jss_test_exec(
        NAME "Create_PKCS11_cert_to_PKCS12_rsa.pfx"
        COMMAND "pk12util" "-o" "${RESULTS_NSSDB_OUTPUT_DIR}/rsa.pfx" "-n" "CA_RSA" "-d" "${RESULTS_NSSDB_OUTPUT_DIR}" "-K" "${DB_PWD}" "-W" "${DB_PWD}"
        DEPENDS "Generate_known_RSA_cert_pair"
    )
    jss_test_exec(
        NAME "Create_PKCS11_cert_to_PKCS12_ecdsa.pfx"
        COMMAND "pk12util" "-o" "${RESULTS_NSSDB_OUTPUT_DIR}/ecdsa.pfx" "-n" "CA_ECDSA" "-d" "${RESULTS_NSSDB_OUTPUT_DIR}" "-K" "${DB_PWD}" "-W" "${DB_PWD}"
        DEPENDS "Generate_known_ECDSA_cert_pair"
    )
    jss_test_java(
        NAME "List_CA_certs"
        COMMAND "org.mozilla.jss.tests.ListCACerts" "${RESULTS_NSSDB_OUTPUT_DIR}" "Verbose"
        DEPENDS "Generate_known_ECDSA_cert_pair"
    )
    jss_test_java(
        NAME "SSLClientAuth"
        COMMAND "org.mozilla.jss.tests.SSLClientAuth" "${RESULTS_NSSDB_OUTPUT_DIR}" "${PASSWORD_FILE}" "${JSS_TEST_PORT_CLIENTAUTH}" "50"
        DEPENDS "List_CA_certs"
    )
    jss_test_java(
        NAME "Key_Generation"
        COMMAND "org.mozilla.jss.tests.TestKeyGen" "${RESULTS_NSSDB_OUTPUT_DIR}" "${PASSWORD_FILE}"
        DEPENDS "Setup_DBs"
    )
    jss_test_java(
        NAME "Digest"
        COMMAND "org.mozilla.jss.tests.DigestTest" "${RESULTS_NSSDB_OUTPUT_DIR}" "${PASSWORD_FILE}"
        DEPENDS "Setup_DBs"
    )
    jss_test_java(
        NAME "HMAC"
        COMMAND "org.mozilla.jss.tests.CrossHMACTest" "${RESULTS_NSSDB_OUTPUT_DIR}" "${PASSWORD_FILE}"
        DEPENDS "Setup_DBs"
    )
    jss_test_java(
        NAME "KeyWrapping"
        COMMAND "org.mozilla.jss.tests.JCAKeyWrap" "${RESULTS_NSSDB_OUTPUT_DIR}" "${PASSWORD_FILE}"
        DEPENDS "Setup_DBs"
    )
    if(HAVE_NSS_OAEP)
        jss_test_java(
            NAME "JSS-KeyWrapping"
            COMMAND "org.mozilla.jss.tests.KeyWrapping" "${RESULTS_NSSDB_OUTPUT_DIR}" "${PASSWORD_FILE}"
            DEPENDS "Setup_DBs"
        )
    endif()
    jss_test_java(
        NAME "Mozilla_JSS_JCA_Signature"
        COMMAND "org.mozilla.jss.tests.JCASigTest" "${RESULTS_NSSDB_OUTPUT_DIR}" "${PASSWORD_FILE}"
        DEPENDS "Setup_DBs"
    )
    jss_test_java(
        NAME "Mozilla_JSS_NSS_Signature"
        COMMAND "org.mozilla.jss.tests.SigTest" "${RESULTS_NSSDB_OUTPUT_DIR}" "${PASSWORD_FILE}"
        DEPENDS "Setup_DBs"
    )
    jss_test_java(
        NAME "JSS_Signature_test"
        COMMAND "org.mozilla.jss.tests.SigTest" "${RESULTS_NSSDB_OUTPUT_DIR}" "${PASSWORD_FILE}"
        DEPENDS "Setup_DBs"
    )
    jss_test_java(
        NAME "Secret_Decoder_Ring"
        COMMAND "org.mozilla.jss.tests.TestSDR" "${RESULTS_NSSDB_OUTPUT_DIR}" "${PASSWORD_FILE}"
        DEPENDS "Setup_DBs"
    )
    jss_test_java(
        NAME "List_cert_by_certnick"
        COMMAND "org.mozilla.jss.tests.ListCerts" "${RESULTS_NSSDB_OUTPUT_DIR}" "Server_RSA"
        DEPENDS "Setup_DBs"
    )
    jss_test_java(
        NAME "Verify_cert_by_certnick"
        COMMAND "org.mozilla.jss.tests.VerifyCert" "${RESULTS_NSSDB_OUTPUT_DIR}" "${PASSWORD_FILE}" "Server_RSA"
        DEPENDS "Setup_DBs"
    )
    jss_test_java(
        NAME "Secret_Key_Generation"
        COMMAND "org.mozilla.jss.tests.SymKeyGen" "${RESULTS_NSSDB_OUTPUT_DIR}"
        DEPENDS "Setup_DBs"
    )
    jss_test_java(
        NAME "Symmetric_Key_Deriving"
        COMMAND "org.mozilla.jss.tests.SymKeyDeriving" "${RESULTS_NSSDB_OUTPUT_DIR}" "${PASSWORD_FILE}"
        DEPENDS "Setup_DBs"
    )
    jss_test_java(
        NAME "X509CertTest"
        COMMAND "org.mozilla.jss.tests.X509CertTest" "${RESULTS_NSSDB_OUTPUT_DIR}" "${PASSWORD_FILE}"
        DEPENDS "List_CA_certs"
    )
    jss_test_java(
        NAME "KeyStoreTest"
        COMMAND "org.mozilla.jss.tests.KeyStoreTest" "${RESULTS_NSSDB_OUTPUT_DIR}" "${PASSWORD_FILE}" getAliases
        DEPENDS "List_CA_certs" "X509CertTest" "Secret_Key_Generation" "Symmetric_Key_Deriving" "SSLClientAuth"
    )
    jss_test_java(
        NAME "JSSProvider"
        COMMAND "org.mozilla.jss.tests.JSSProvider" "${RESULTS_NSSDB_OUTPUT_DIR}" "${PASSWORD_FILE}"
        DEPENDS "List_CA_certs" "X509CertTest" "Secret_Key_Generation" "Symmetric_Key_Deriving" "SSLClientAuth"
    )
    jss_test_java(
        NAME "SSLEngine_RSA"
        COMMAND "org.mozilla.jss.tests.TestSSLEngine" "${RESULTS_NSSDB_OUTPUT_DIR}" "${PASSWORD_FILE}" "Client_RSA" "Server_RSA"
        DEPENDS "List_CA_certs"
    )
    jss_test_java(
        NAME "SSLEngine_ECDSA"
        COMMAND "org.mozilla.jss.tests.TestSSLEngine" "${RESULTS_NSSDB_OUTPUT_DIR}" "${PASSWORD_FILE}" "Client_ECDSA" "Server_ECDSA"
        DEPENDS "SSLEngine_RSA"
    )

    if(NOT FIPS_ENABLED)
        jss_test_java(
            NAME "Key_Factory"
            COMMAND "org.mozilla.jss.tests.KeyFactoryTest" "${RESULTS_NSSDB_OUTPUT_DIR}" "${PASSWORD_FILE}"
            DEPENDS "Setup_DBs"
        )
        jss_test_java(
            NAME "HMAC_Unwrap"
            COMMAND "org.mozilla.jss.tests.HmacTest" "${RESULTS_NSSDB_OUTPUT_DIR}" "${PASSWORD_FILE}"
            DEPENDS "Setup_DBs"
        )
        if(HAVE_NSS_CMAC)
            jss_test_java(
                NAME "CMAC_Test"
                COMMAND "org.mozilla.jss.tests.TestCmac" "${RESULTS_NSSDB_OUTPUT_DIR}" "${PASSWORD_FILE}"
                DEPENDS "Setup_DBs"
            )
        endif()
        if(HAVE_NSS_KBKDF)
            jss_test_java(
                NAME "KBKDF_Test"
                COMMAND "org.mozilla.jss.tests.TestKBKDF" "${RESULTS_NSSDB_OUTPUT_DIR}" "${PASSWORD_FILE}"
                DEPENDS "Setup_DBs"
            )
        endif()
        jss_test_java(
            NAME "Mozilla_JSS_Secret_Key_Generation"
            COMMAND "org.mozilla.jss.tests.JCASymKeyGen" "${RESULTS_NSSDB_OUTPUT_DIR}"
            DEPENDS "Setup_DBs"
        )

        # SSL Engine related tests
        jss_test_exec(
            NAME "TestBufferPRFDSSL_RSA"
            COMMAND "${BIN_OUTPUT_DIR}/TestBufferPRFDSSL" "${RESULTS_NSSDB_OUTPUT_DIR}" "${DB_PWD}" "Server_RSA"
            DEPENDS "List_CA_certs" "generate_c_TestBufferPRFDSSL"
        )
        jss_test_exec(
            NAME "TestBufferPRFDSSL_ECDSA"
            COMMAND "${BIN_OUTPUT_DIR}/TestBufferPRFDSSL" "${RESULTS_NSSDB_OUTPUT_DIR}" "${DB_PWD}" "Server_ECDSA"
            DEPENDS "List_CA_certs" "generate_c_TestBufferPRFDSSL"
        )
        jss_test_java(
            NAME "JSS_Test_BufferPRFD"
            COMMAND "org.mozilla.jss.tests.TestBufferPRFD" "${RESULTS_NSSDB_OUTPUT_DIR}" "${DB_PWD}"
            DEPENDS "List_CA_certs"
        )

        # FIPS-related tests
        jss_test_java(
            NAME "Generate_FIPS_known_RSA_cert_pair"
            COMMAND "org.mozilla.jss.tests.GenerateTestCert" "${RESULTS_NSSDB_FIPS_OUTPUT_DIR}" "${PASSWORD_FILE}" "70" "localhost" "SHA-256/RSA" "CA_RSA" "Server_RSA" "Client_RSA"
            DEPENDS "Setup_FIPS_DBs"
            MODE "FIPS"
        )
        jss_test_java(
            NAME "Generate_FIPS_known_ECDSA_cert_pair"
            COMMAND "org.mozilla.jss.tests.GenerateTestCert" "${RESULTS_NSSDB_FIPS_OUTPUT_DIR}" "${PASSWORD_FILE}" "80" "localhost" "SHA-256/EC" "CA_ECDSA" "Server_ECDSA" "Client_ECDSA"
            DEPENDS "Generate_FIPS_known_RSA_cert_pair"
            MODE "FIPS"
        )
        jss_test_java(
            NAME "Enable_FipsMODE"
            COMMAND "org.mozilla.jss.tests.FipsTest" "${RESULTS_NSSDB_FIPS_OUTPUT_DIR}" "enable"
            DEPENDS "Generate_FIPS_known_ECDSA_cert_pair"
            MODE "NONE"
        )
        jss_test_java(
            NAME "check_FipsMODE"
            COMMAND "org.mozilla.jss.tests.FipsTest" "${RESULTS_NSSDB_FIPS_OUTPUT_DIR}" "chkfips"
            DEPENDS "Enable_FipsMODE"
            MODE "NONE"
        )

        # The current version of NSS features partial support for TLS 1.3 in
        # FIPS mode.
        if (NOT SANDBOX)
            jss_test_java(
                NAME "SSLClientAuth_FIPSMODE"
                COMMAND "org.mozilla.jss.tests.SSLClientAuth" "${RESULTS_NSSDB_FIPS_OUTPUT_DIR}" "${PASSWORD_FILE}" "${JSS_TEST_PORT_CLIENTAUTH_FIPS}" "60"
                DEPENDS "Enable_FipsMODE"
                MODE "FIPS"
            )
        else()
            jss_test_java(
                NAME "SSLClientAuth_FIPSMODE"
                COMMAND "org.mozilla.jss.tests.JSSProvider"
                DEPENDS "Enable_FipsMODE"
                MODE "FIPS"
            )
        endif()

        jss_test_java(
            NAME "HMAC_FIPSMODE"
            COMMAND "org.mozilla.jss.tests.CrossHMACTest" "${RESULTS_NSSDB_FIPS_OUTPUT_DIR}" "${PASSWORD_FILE}"
            DEPENDS "Enable_FipsMODE"
            MODE "FIPS"
        )
        jss_test_java(
            NAME "KeyWrapping_FIPSMODE"
            COMMAND "org.mozilla.jss.tests.JCAKeyWrap" "${RESULTS_NSSDB_FIPS_OUTPUT_DIR}" "${PASSWORD_FILE}"
            DEPENDS "Enable_FipsMODE"
            MODE "FIPS"
        )
        jss_test_java(
            NAME "Mozilla_JSS_JCA_Signature_FIPSMODE"
            COMMAND "org.mozilla.jss.tests.JCASigTest" "${RESULTS_NSSDB_FIPS_OUTPUT_DIR}" "${PASSWORD_FILE}"
            DEPENDS "Enable_FipsMODE"
            MODE "FIPS"
        )
        jss_test_java(
            NAME "JSS_Signature_test_FipsMODE"
            COMMAND "org.mozilla.jss.tests.SigTest" "${RESULTS_NSSDB_FIPS_OUTPUT_DIR}" "${PASSWORD_FILE}"
            DEPENDS "Enable_FipsMODE"
            MODE "FIPS"
        )
        jss_test_java(
            NAME "SSLEngine_RSA_FIPSMODE"
            COMMAND "org.mozilla.jss.tests.TestSSLEngine" "${RESULTS_NSSDB_FIPS_OUTPUT_DIR}" "${PASSWORD_FILE}" "Client_RSA" "Server_RSA"
            DEPENDS "Enable_FipsMODE" "SSLEngine_ECDSA"
            MODE "FIPS"
        )
        jss_test_java(
            NAME "SSLEngine_ECDSA_FIPSMODE"
            COMMAND "org.mozilla.jss.tests.TestSSLEngine" "${RESULTS_NSSDB_FIPS_OUTPUT_DIR}" "${PASSWORD_FILE}" "Client_ECDSA" "Server_ECDSA"
            DEPENDS "SSLEngine_RSA_FIPSMODE" "SSLEngine_ECDSA"
            MODE "FIPS"
        )

        # Since we need to disable FIPS mode _after_ all FIPS-mode tests have
        # run, we have to add a strict dependency from Disable_FipsMODE onto all
        # FIPS-related checks.
        jss_test_java(
            NAME "Disable_FipsMODE"
            COMMAND "org.mozilla.jss.tests.FipsTest" "${RESULTS_NSSDB_FIPS_OUTPUT_DIR}" "disable"
            DEPENDS "check_FipsMODE" "SSLClientAuth_FIPSMODE" "HMAC_FIPSMODE" "KeyWrapping_FIPSMODE" "Mozilla_JSS_JCA_Signature_FIPSMODE" "JSS_Signature_test_FipsMODE" "SSLEngine_RSA_FIPSMODE" "SSLEngine_ECDSA_FIPSMODE"
            MODE "NONE"
        )
    endif()

    jss_test_java(
        NAME "JUnit_GenericValueConverterTest"
        COMMAND "org.junit.runner.JUnitCore" "org.mozilla.jss.tests.GenericValueConverterTest"
    )
    jss_test_java(
        NAME "JUnit_IA5StringConverterTest"
        COMMAND "org.junit.runner.JUnitCore" "org.mozilla.jss.tests.IA5StringConverterTest"
    )
    jss_test_java(
        NAME "JUnit_PrintableConverterTest"
        COMMAND "org.junit.runner.JUnitCore" "org.mozilla.jss.tests.PrintableConverterTest"
    )

    if(TEST_WITH_INTERNET)
        jss_test_java(
            NAME "BadSSL"
            COMMAND "org.mozilla.jss.tests.BadSSL" "${RESULTS_NSSDB_INTERNET_OUTPUT_DIR}"
            DEPENDS "Import_Internet_Certs"
            MODE "INTERNET"
        )
        jss_test_java(
            NAME "BadSSL_Leaf_And_Chain"
            COMMAND "org.mozilla.jss.tests.BadSSL" "${RESULTS_NSSDB_INTERNET_OUTPUT_DIR}" "LEAF_AND_CHAIN"
            DEPENDS "Import_Internet_Certs"
            MODE "INTERNET"
        )
    endif()

    # For compliance with several existing clients
    add_custom_target(
        check
        DEPENDS test
    )
endmacro()

macro(jss_tests_compile)
    jss_tests_compile_c("${PROJECT_SOURCE_DIR}/org/mozilla/jss/tests/buffer_size_1.c" "${BIN_OUTPUT_DIR}/buffer_size_1" "buffer_size_1")
    jss_tests_compile_c("${PROJECT_SOURCE_DIR}/org/mozilla/jss/tests/buffer_size_4.c" "${BIN_OUTPUT_DIR}/buffer_size_4" "buffer_size_4")
    jss_tests_compile_c("${PROJECT_SOURCE_DIR}/org/mozilla/jss/tests/TestBufferPRFD.c" "${BIN_OUTPUT_DIR}/TestBufferPRFD" "TestBufferPRFD")
    jss_tests_compile_c("${PROJECT_SOURCE_DIR}/org/mozilla/jss/tests/TestBufferPRFDSSL.c" "${BIN_OUTPUT_DIR}/TestBufferPRFDSSL" "TestBufferPRFDSSL")
endmacro()

macro(jss_tests_compile_c C_FILE C_OUTPUT C_TARGET)
    # Generate the target executable from C_FILE

    add_custom_command(
        OUTPUT "${C_OUTPUT}"
        COMMAND ${CMAKE_C_COMPILER} ${JSS_C_FLAGS} -o ${C_OUTPUT} ${C_FILE} -L${LIB_OUTPUT_DIR} -ljss4 ${JSS_LD_FLAGS}
        WORKING_DIRECTORY ${C_DIR}
        DEPENDS "${C_FILE}"
        DEPENDS "${JSS_TESTS_SO_PATH}"
        DEPENDS generate_java
        DEPENDS generate_includes
    )

    add_custom_target(
        "generate_c_${C_TARGET}"
        DEPENDS "${C_OUTPUT}"
    )

    add_dependencies("generate_so" "generate_c_${C_TARGET}")
endmacro()

function(jss_test_java)
    set(TEST_FLAGS "NAME")
    set(TEST_ARGS  "COMMAND" "DEPENDS" "MODE")
    cmake_parse_arguments(TEST_JAVA "" "${TEST_FLAGS}" "${TEST_ARGS}" ${ARGN})

    list(APPEND EXEC_COMMAND "${Java_JAVA_EXECUTABLE}")
    list(APPEND EXEC_COMMAND "-classpath")
    list(APPEND EXEC_COMMAND "${TEST_CLASSPATH}")
    list(APPEND EXEC_COMMAND "-ea")
    list(APPEND EXEC_COMMAND "-Djava.library.path=${CMAKE_BINARY_DIR}")
    if(TEST_JAVA_MODE STREQUAL "FIPS")
        list(APPEND EXEC_COMMAND "-Djava.security.properties=${CONFIG_OUTPUT_DIR}/fips.security")
    elseif(TEST_JAVA_MODE STREQUAL "INTERNET")
        list(APPEND EXEC_COMMAND "-Djava.security.properties=${CONFIG_OUTPUT_DIR}/internet.security")
    elseif(NOT TEST_JAVA_MODE STREQUAL "NONE")
        list(APPEND EXEC_COMMAND "-Djava.security.properties=${CONFIG_OUTPUT_DIR}/java.security")
    endif()
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        list(APPEND EXEC_COMMAND "-Djava.util.logging.config.file=${PROJECT_SOURCE_DIR}/tools/logging.properties")
    endif()
    set(EXEC_COMMAND "${EXEC_COMMAND};${TEST_JAVA_COMMAND}")

    if(TEST_JAVA_DEPENDS)
        jss_test_exec(
            NAME "${TEST_JAVA_NAME}"
            COMMAND "${EXEC_COMMAND}"
            DEPENDS ${TEST_JAVA_DEPENDS}
            LIBRARY "java"
        )
    else()
        jss_test_exec(
            NAME "${TEST_JAVA_NAME}"
            COMMAND "${EXEC_COMMAND}"
            LIBRARY "java"
        )
    endif()
endfunction()

macro(jss_test_exec)
    # Usage:
    #
    #   jss_test_exec(
    #     NAME TEST_NAME
    #     COMMAND TEST_COMMAND
    #     [DEPENDS [TEST_DEPENDS TEST_DEPENDS...]]
    #
    # Note that TEST_COMMAND can be a list by quoting the list:
    #
    #   jss_test_exec("NAME" "ARG1" "ARG2" "...")

    set(TEST_FLAGS "NAME" "LIBRARY")
    set(TEST_ARGS  "COMMAND" "DEPENDS")
    cmake_parse_arguments(TEST_EXEC "" "${TEST_FLAGS}" "${TEST_ARGS}" ${ARGN})

    if(TEST_VALGRIND)
        list(INSERT TEST_EXEC_COMMAND 0 "valgrind" "--track-origins=yes" "--leak-check=full")
    endif()

    add_test(
        NAME "${TEST_EXEC_NAME}"
        COMMAND ${TEST_EXEC_COMMAND}
    )

    list(APPEND LD_LIBRARY ${NSS_LIBRARIES})
    list(APPEND LD_LIBRARY ${NSPR_LIBRARIES})

    # If we are calling a java program, use the versioned library to ensure
    # that any new JNI calls are made visible.
    if(TEST_EXEC_LIBRARY AND (TEST_EXEC_LIBRARY STREQUAL "java"))
        list(APPEND LD_LIBRARY "${CMAKE_BINARY_DIR}")
        list(REMOVE_DUPLICATES LD_LIBRARY)
        jss_list_join(LD_LIBRARY ":" LD_LIBRARY_PATH)

        set_tests_properties(
            "${TEST_EXEC_NAME}"
            PROPERTIES ENVIRONMENT
            "LD_LIBRARY_PATH=${LD_LIBRARY_PATH}"
        )
    else()
        list(APPEND LD_LIBRARY "${LIB_OUTPUT_DIR}")
        list(REMOVE_DUPLICATES LD_LIBRARY)
        jss_list_join(LD_LIBRARY ":" LD_LIBRARY_PATH)

        set_tests_properties(
            "${TEST_EXEC_NAME}"
            PROPERTIES ENVIRONMENT
            "LD_LIBRARY_PATH=${LD_LIBRARY_PATH}"
        )
    endif()
    if(TEST_EXEC_DEPENDS)
        set_tests_properties(
            "${TEST_EXEC_NAME}"
            PROPERTIES DEPENDS
            "${TEST_EXEC_DEPENDS}"
        )
    endif()
endmacro()
