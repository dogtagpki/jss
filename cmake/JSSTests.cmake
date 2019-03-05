macro(jss_tests)
    enable_testing()

    # Common variables used as arguments to several tests
    set(JSS_TEST_DIR "${PROJECT_SOURCE_DIR}/org/mozilla/jss/tests")
    set(PASSWORD_FILE "${JSS_TEST_DIR}/passwords")
    set(DB_PWD "m1oZilla")


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
    )


    jss_test_java(
        NAME "Test_UTF-8_Converter"
        COMMAND "org.mozilla.jss.tests.UTF8ConverterTest"
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
    if ((${Java_VERSION_MAJOR} EQUAL 1) AND (${Java_VERSION_MINOR} LESS 9))
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
    jss_test_java(
        NAME "Generate_known_DSS_cert_pair"
        COMMAND "org.mozilla.jss.tests.GenerateTestCert" "${RESULTS_NSSDB_OUTPUT_DIR}" "${PASSWORD_FILE}" "40" "localhost" "SHA-1/DSA" "CA_DSS" "Server_DSS" "Client_DSS"
        DEPENDS "Generate_known_ECDSA_cert_pair"
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
    jss_test_exec(
        NAME "Create_PKCS11_cert_to_PKCS12_dss.pfx"
        COMMAND "pk12util" "-o" "${RESULTS_NSSDB_OUTPUT_DIR}/dss.pfx" "-n" "CA_DSS" "-d" "${RESULTS_NSSDB_OUTPUT_DIR}" "-K" "${DB_PWD}" "-W" "${DB_PWD}"
        DEPENDS "Generate_known_DSS_cert_pair"
    )
    jss_test_java(
        NAME "List_CA_certs"
        COMMAND "org.mozilla.jss.tests.ListCACerts" "${RESULTS_NSSDB_OUTPUT_DIR}"
        DEPENDS "Generate_known_DSS_cert_pair"
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
        NAME "Key_Factory"
        COMMAND "org.mozilla.jss.tests.KeyFactoryTest" "${RESULTS_NSSDB_OUTPUT_DIR}" "${PASSWORD_FILE}"
        DEPENDS "Setup_DBs"
    )
    jss_test_java(
        NAME "Digest"
        COMMAND "org.mozilla.jss.tests.DigestTest" "${RESULTS_NSSDB_OUTPUT_DIR}" "${PASSWORD_FILE}"
        DEPENDS "Setup_DBs"
    )
    jss_test_java(
        NAME "HMAC"
        COMMAND "org.mozilla.jss.tests.HMACTest" "${RESULTS_NSSDB_OUTPUT_DIR}" "${PASSWORD_FILE}"
        DEPENDS "Setup_DBs"
    )
    jss_test_java(
        NAME "HMAC_Unwrap"
        COMMAND "org.mozilla.jss.tests.HmacTest" "${RESULTS_NSSDB_OUTPUT_DIR}" "${PASSWORD_FILE}"
        DEPENDS "Setup_DBs"
    )
    jss_test_java(
        NAME "KeyWrapping"
        COMMAND "org.mozilla.jss.tests.JCAKeyWrap" "${RESULTS_NSSDB_OUTPUT_DIR}" "${PASSWORD_FILE}"
        DEPENDS "Setup_DBs"
    )
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
        NAME "Mozilla_JSS_Secret_Key_Generation"
        COMMAND "org.mozilla.jss.tests.JCASymKeyGen" "${RESULTS_NSSDB_OUTPUT_DIR}"
        DEPENDS "Setup_DBs"
    )

    # FIPS-related tests
    jss_test_java(
        NAME "Enable_FipsMODE"
        COMMAND "org.mozilla.jss.tests.FipsTest" "${RESULTS_NSSDB_FIPS_OUTPUT_DIR}" "enable"
        DEPENDS "Setup_FIPS_DBs"
    )
    jss_test_java(
        NAME "check_FipsMODE"
        COMMAND "org.mozilla.jss.tests.FipsTest" "${RESULTS_NSSDB_FIPS_OUTPUT_DIR}" "chkfips"
        DEPENDS "Enable_FipsMODE"
    )
    jss_test_java(
        NAME "SSLClientAuth_FIPSMODE"
        COMMAND "org.mozilla.jss.tests.SSLClientAuth" "${RESULTS_NSSDB_FIPS_OUTPUT_DIR}" "${PASSWORD_FILE}" "${JSS_TEST_PORT_CLIENTAUTH_FIPS}" "60"
        DEPENDS "Enable_FipsMODE"
    )
    jss_test_java(
        NAME "HMAC_FIPSMODE"
        COMMAND "org.mozilla.jss.tests.HMACTest" "${RESULTS_NSSDB_FIPS_OUTPUT_DIR}" "${PASSWORD_FILE}"
        DEPENDS "Enable_FipsMODE"
    )
    jss_test_java(
        NAME "KeyWrapping_FIPSMODE"
        COMMAND "org.mozilla.jss.tests.JCAKeyWrap" "${RESULTS_NSSDB_FIPS_OUTPUT_DIR}" "${PASSWORD_FILE}"
        DEPENDS "Enable_FipsMODE"
    )
    jss_test_java(
        NAME "Mozilla_JSS_JCA_Signature_FIPSMODE"
        COMMAND "org.mozilla.jss.tests.JCASigTest" "${RESULTS_NSSDB_FIPS_OUTPUT_DIR}" "${PASSWORD_FILE}"
        DEPENDS "Enable_FipsMODE"
    )
    jss_test_java(
        NAME "JSS_Signature_test_FipsMODE"
        COMMAND "org.mozilla.jss.tests.SigTest" "${RESULTS_NSSDB_FIPS_OUTPUT_DIR}" "${PASSWORD_FILE}"
        DEPENDS "Enable_FipsMODE"
    )

    # Since we need to disable FIPS mode _after_ all FIPS-mode tests have
    # run, we have to add a strict dependency from Disable_FipsMODE onto all
    # FIPS-related checks.
    jss_test_java(
        NAME "Disable_FipsMODE"
        COMMAND "org.mozilla.jss.tests.FipsTest" "${RESULTS_NSSDB_FIPS_OUTPUT_DIR}" "disable"
        DEPENDS "check_FipsMODE" "SSLClientAuth_FIPSMODE" "HMAC_FIPSMODE" "KeyWrapping_FIPSMODE" "Mozilla_JSS_JCA_Signature_FIPSMODE" "JSS_Signature_test_FipsMODE"
    )

    jss_test_java(
        NAME "JUnit_GenericValueConverterTest"
        COMMAND "org.junit.runner.JUnitCore" "org.mozilla.jss.tests.GenericValueConverterTest"
        DEPENDS "Disable_FipsMODE"
    )
    jss_test_java(
        NAME "JUnit_IA5StringConverterTest"
        COMMAND "org.junit.runner.JUnitCore" "org.mozilla.jss.tests.IA5StringConverterTest"
        DEPENDS "Disable_FipsMODE"
    )
    jss_test_java(
        NAME "JUnit_PrintableConverterTest"
        COMMAND "org.junit.runner.JUnitCore" "org.mozilla.jss.tests.PrintableConverterTest"
        DEPENDS "Disable_FipsMODE"
    )


    # For compliance with several
    add_custom_target(
      check
      DEPENDS test
    )
endmacro()

function(jss_test_java)
    set(TEST_FLAGS "NAME")
    set(TEST_ARGS  "COMMAND" "DEPENDS")
    cmake_parse_arguments(TEST_JAVA "" "${TEST_FLAGS}" "${TEST_ARGS}" ${ARGN})

    list(APPEND EXEC_COMMAND "${Java_JAVA_EXECUTABLE}")
    list(APPEND EXEC_COMMAND "-classpath")
    list(APPEND EXEC_COMMAND "${TEST_CLASSPATH}")
    list(APPEND EXEC_COMMAND "-ea")
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

    add_test(
        NAME "${TEST_EXEC_NAME}"
        COMMAND ${TEST_EXEC_COMMAND}
    )

    # If we are calling a java program, use the versioned library to ensure
    # that any new JNI calls are made visible.
    if(TEST_EXEC_LIBRARY AND (TEST_EXEC_LIBRARY STREQUAL "java"))
        set_tests_properties(
            "${TEST_EXEC_NAME}"
            PROPERTIES ENVIRONMENT
            "LD_LIBRARY_PATH=${CMAKE_BINARY_DIR}"
        )
    else()
        set_tests_properties(
            "${TEST_EXEC_NAME}"
            PROPERTIES ENVIRONMENT
            "LD_LIBRARY_PATH=${LIB_OUTPUT_DIR}"
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
