macro(jss_tests)
    enable_testing()

    set(JSS_TEST_DIR "${PROJECT_SOURCE_DIR}/org/mozilla/jss/tests")
    set(PASSWORD_FILE "${JSS_TEST_DIR}/passwords")
    set(DB_PWD "m1oZilla")

    jss_test_java(
        NAME "Test_UTF-8_Converter"
        COMMAND "org.mozilla.jss.tests.UTF8ConverterTest"
    )
    jss_test_java(
        NAME "Setup_DBs"
        COMMAND "org.mozilla.jss.tests.SetupDBs" "${RESULTS_OUTPUT_DIR}" "${PASSWORD_FILE}"
    )
    jss_test_java(
        NAME "Setup_FIPS_DBs"
        COMMAND "org.mozilla.jss.tests.SetupDBs" "${RESULTS_FIPS_OUTPUT_DIR}" "${PASSWORD_FILE}"
    )
    jss_test_java(
        NAME "Generate_known_RSA_cert_pair"
        COMMAND "org.mozilla.jss.tests.GenerateTestCert" "${RESULTS_OUTPUT_DIR}" "${PASSWORD_FILE}" "20" "localhost" "SHA-256/RSA" "CA_RSA" "Server_RSA" "Client_RSA"
        DEPENDS "Setup_DBs"
    )
    jss_test_java(
        NAME "Generate_known_ECDSA_cert_pair"
        COMMAND "org.mozilla.jss.tests.GenerateTestCert" "${RESULTS_OUTPUT_DIR}" "${PASSWORD_FILE}" "30" "localhost" "SHA-256/EC" "CA_ECDSA" "Server_ECDSA" "Client_ECDSA"
        DEPENDS "Generate_known_RSA_cert_pair"
    )
    jss_test_java(
        NAME "Generate_known_DSS_cert_pair"
        COMMAND "org.mozilla.jss.tests.GenerateTestCert" "${RESULTS_OUTPUT_DIR}" "${PASSWORD_FILE}" "40" "localhost" "SHA-1/DSA" "CA_DSS" "Server_DSS" "Client_DSS"
        DEPENDS "Generate_known_ECDSA_cert_pair"
    )
    jss_test_exec(
        NAME "Create_PKCS11_cert_to_PKCS12_rsa.pfx"
        COMMAND "pk12util" "-o" "${RESULTS_OUTPUT_DIR}/rsa.pfx" "-n" "CA_RSA" "-d" "${RESULTS_OUTPUT_DIR}" "-K" "${DB_PWD}" "-W" "${DB_PWD}"
        DEPENDS "Generate_known_RSA_cert_pair"
    )
    jss_test_exec(
        NAME "Create_PKCS11_cert_to_PKCS12_ecdsa.pfx"
        COMMAND "pk12util" "-o" "${RESULTS_OUTPUT_DIR}/ecdsa.pfx" "-n" "CA_ECDSA" "-d" "${RESULTS_OUTPUT_DIR}" "-K" "${DB_PWD}" "-W" "${DB_PWD}"
        DEPENDS "Generate_known_ECDSA_cert_pair"
    )
    jss_test_exec(
        NAME "Create_PKCS11_cert_to_PKCS12_dss.pfx"
        COMMAND "pk12util" "-o" "${RESULTS_OUTPUT_DIR}/dss.pfx" "-n" "CA_DSS" "-d" "${RESULTS_OUTPUT_DIR}" "-K" "${DB_PWD}" "-W" "${DB_PWD}"
        DEPENDS "Generate_known_DSS_cert_pair"
    )
    jss_test_java(
        NAME "List_CA_certs"
        COMMAND "org.mozilla.jss.tests.ListCACerts" "${RESULTS_OUTPUT_DIR}"
        DEPENDS "Generate_known_DSS_cert_pair"
    )
    jss_test_java(
        NAME "Key_Generation"
        COMMAND "org.mozilla.jss.tests.TestKeyGen" "${RESULTS_OUTPUT_DIR}" "${PASSWORD_FILE}"
        DEPENDS "Setup_DBs"
    )
    jss_test_java(
        NAME "Key_Factory"
        COMMAND "org.mozilla.jss.tests.KeyFactoryTest" "${RESULTS_OUTPUT_DIR}" "${PASSWORD_FILE}"
        DEPENDS "Setup_DBs"
    )
    jss_test_java(
        NAME "Digest"
        COMMAND "org.mozilla.jss.tests.DigestTest" "${RESULTS_OUTPUT_DIR}" "${PASSWORD_FILE}"
        DEPENDS "Setup_DBs"
    )
    jss_test_java(
        NAME "HMAC"
        COMMAND "org.mozilla.jss.tests.HMACTest" "${RESULTS_OUTPUT_DIR}" "${PASSWORD_FILE}"
        DEPENDS "Setup_DBs"
    )
    jss_test_java(
        NAME "HMAC_Unwrap"
        COMMAND "org.mozilla.jss.tests.HmacTest" "${RESULTS_OUTPUT_DIR}" "${PASSWORD_FILE}"
        DEPENDS "Setup_DBs"
    )
    jss_test_java(
        NAME "KeyWrapping"
        COMMAND "org.mozilla.jss.tests.JCAKeyWrap" "${RESULTS_OUTPUT_DIR}" "${PASSWORD_FILE}"
        DEPENDS "Setup_DBs"
    )
    jss_test_java(
        NAME "Mozilla_JSS_JCA_Signature"
        COMMAND "org.mozilla.jss.tests.JCASigTest" "${RESULTS_OUTPUT_DIR}" "${PASSWORD_FILE}"
        DEPENDS "Setup_DBs"
    )
    jss_test_java(
        NAME "Mozilla_JSS_NSS_Signature"
        COMMAND "org.mozilla.jss.tests.SigTest" "${RESULTS_OUTPUT_DIR}" "${PASSWORD_FILE}"
        DEPENDS "Setup_DBs"
    )
    jss_test_java(
        NAME "JSS_Signature_test"
        COMMAND "org.mozilla.jss.tests.SigTest" "${RESULTS_OUTPUT_DIR}" "${PASSWORD_FILE}"
        DEPENDS "Setup_DBs"
    )
    jss_test_java(
        NAME "Secret_Decoder_Ring"
        COMMAND "org.mozilla.jss.tests.TestSDR" "${RESULTS_OUTPUT_DIR}" "${PASSWORD_FILE}"
        DEPENDS "Setup_DBs"
    )
    jss_test_java(
        NAME "List_cert_by_certnick"
        COMMAND "org.mozilla.jss.tests.ListCerts" "${RESULTS_OUTPUT_DIR}" "Server_RSA"
        DEPENDS "Setup_DBs"
    )
    jss_test_java(
        NAME "Verify_cert_by_certnick"
        COMMAND "org.mozilla.jss.tests.VerifyCert" "${RESULTS_OUTPUT_DIR}" "${PASSWORD_FILE}" "Server_RSA"
        DEPENDS "Setup_DBs"
    )
    jss_test_java(
        NAME "Secret_Key_Generation"
        COMMAND "org.mozilla.jss.tests.SymKeyGen" "${RESULTS_OUTPUT_DIR}"
        DEPENDS "Setup_DBs"
    )
    jss_test_java(
        NAME "Mozilla_JSS_Secret_Key_Generation"
        COMMAND "org.mozilla.jss.tests.JCASymKeyGen" "${RESULTS_OUTPUT_DIR}"
        DEPENDS "Setup_DBs"
    )
    jss_test_java(
        NAME "Enable_FipsMODE"
        COMMAND "org.mozilla.jss.tests.FipsTest" "${RESULTS_FIPS_OUTPUT_DIR}" "enable"
        DEPENDS "Setup_FIPS_DBs"
    )
    jss_test_java(
        NAME "check_FipsMODE"
        COMMAND "org.mozilla.jss.tests.FipsTest" "${RESULTS_FIPS_OUTPUT_DIR}" "chkfips"
        DEPENDS "Enable_FipsMODE"
    )
    jss_test_java(
        NAME "HMAC_FIPSMODE"
        COMMAND "org.mozilla.jss.tests.HMACTest" "${RESULTS_FIPS_OUTPUT_DIR}" "${PASSWORD_FILE}"
        DEPENDS "check_FipsMODE"
    )
    jss_test_java(
        NAME "KeyWrapping_FIPSMODE"
        COMMAND "org.mozilla.jss.tests.JCAKeyWrap" "${RESULTS_FIPS_OUTPUT_DIR}" "${PASSWORD_FILE}"
        DEPENDS "HMAC_FIPSMODE"
    )
    jss_test_java(
        NAME "Mozilla_JSS_JCA_Signature_FIPSMODE"
        COMMAND "org.mozilla.jss.tests.JCASigTest" "${RESULTS_FIPS_OUTPUT_DIR}" "${PASSWORD_FILE}"
        DEPENDS "KeyWrapping_FIPSMODE"
    )
    jss_test_java(
        NAME "JSS_Signature_test_FipsMODE"
        COMMAND "org.mozilla.jss.tests.SigTest" "${RESULTS_FIPS_OUTPUT_DIR}" "${PASSWORD_FILE}"
        DEPENDS "Mozilla_JSS_JCA_Signature_FIPSMODE"
    )
    jss_test_java(
        NAME "Disable_FipsMODE"
        COMMAND "org.mozilla.jss.tests.FipsTest" "${RESULTS_FIPS_OUTPUT_DIR}" "disable"
        DEPENDS "JSS_Signature_test_FipsMODE"
    )
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
        )
    else()
        jss_test_exec(
            NAME "${TEST_JAVA_NAME}"
            COMMAND "${EXEC_COMMAND}"
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

    set(TEST_FLAGS "NAME")
    set(TEST_ARGS  "COMMAND" "DEPENDS")
    cmake_parse_arguments(TEST_EXEC "" "${TEST_FLAGS}" "${TEST_ARGS}" ${ARGN})

    add_test(
        NAME "${TEST_EXEC_NAME}"
        COMMAND ${TEST_EXEC_COMMAND}
    )
    set_tests_properties(
        "${TEST_EXEC_NAME}"
        PROPERTIES ENVIRONMENT
        "LD_LIBRARY_PATH=${CMAKE_BINARY_DIR}"
    )
    if(TEST_EXEC_DEPENDS)
        set_tests_properties(
            "${TEST_EXEC_NAME}"
            PROPERTIES DEPENDS
            "${TEST_EXEC_DEPENDS}"
        )
    endif()
endmacro()
