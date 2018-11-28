# Core of JSS building

# Build JSS; high level flow
macro(jss_build)
    # "set(..)" in CMake defines a globally-scoped variable (or more
    # precisely, a variable that exists in all scopes _after_ this one)
    # by default. These are three helpful globs of files for dependencies:
    # all java, headers, and c source files. Note that org/*.java differs
    # from the bash-style glob in that it matches all files which begin with
    # "org" and end with ".java". This includes, e.g.,
    # "org/mozilla/jss/CryptoManager.java". Because these globs are computed
    # at cmake time (prior to the make step) incremental builds are not
    # possible; each time the build directory should be removed and recreated
    # prior to building again.
    jss_build_globs()

    # To build JSS, we need:
    #   1. To build the Java files.
    #   2. To copy the headers for compilation.
    #   3. To build the library.
    #   4. To build the jar.
    #   5. To build the javadocs.
    jss_build_java()
    jss_build_includes()
    jss_build_c()
    jss_build_jars()
    jss_build_javadocs()
endmacro()

macro(jss_build_globs)
    file(GLOB_RECURSE _JAVA_SOURCES org/*.java)
    foreach(_JAVA_SOURCE ${_JAVA_SOURCES})
        if(${_JAVA_SOURCE} MATCHES "mozilla/jss/tests/")
            list(APPEND JAVA_TEST_SOURCES "${_JAVA_SOURCE}")
        else()
            list(APPEND JAVA_SOURCES "${_JAVA_SOURCE}")
        endif()
    endforeach()

    file(GLOB_RECURSE _C_HEADERS org/*.h)
    foreach(_C_HEADER ${_C_HEADERS})
        if(${_C_HEADER} MATCHES "mozilla/jss/tests/")
            list(APPEND C_TEST_HEADERS "${_C_HEADER}")
        else()
            list(APPEND C_HEADERS "${_C_HEADER}")
        endif()
    endforeach()

    file(GLOB_RECURSE _C_SOURCES org/*.c)
    # We exclude any C files in the tests directory because they shouldn't
    # contribute to our library. They should instead be built as part of the
    # test suite and probably be built as stand alone binaries which link
    # against libjss4.so (at most).
    foreach(_C_SOURCE ${_C_SOURCES})
        if(${_C_SOURCE} MATCHES "mozilla/jss/tests/")
            list(APPEND C_TEST_SOURCES "${_C_SOURCE}")
        else()
            list(APPEND C_SOURCES "${_C_SOURCE}")
        endif()
    endforeach()
endmacro()

# Build all Java sources into classes and generate JNI headers
macro(jss_build_java)
    # Create a fake, pseudo-target for generate_java -- we have to have some
    # status for when the build finishes for the add_custom_target to depend
    # on, but it also must be the last-thing created; thus, we touch
    # ${JNI_OUTPUTS} after the javac command finishes.
    set(JNI_OUTPUTS "${TARGETS_OUTPUT_DIR}/finished_generate_java")
    set(TESTS_JNI_OUTPUTS "${TARGETS_OUTPUT_DIR}/finished_tests_generate_java")

    # We frequently use the add_custom_command + add_custom_target wrapper due
    # to a quirk of CMake. This is documented more extensively in the
    # following links:
    #   https://samthursfield.wordpress.com/2015/11/21/cmake-dependencies-between-targets-and-files-and-custom-commands/
    #   https://gitlab.kitware.com/cmake/community/wikis/FAQ#how-can-i-add-a-dependency-to-a-source-file-which-is-generated-in-a-subdirectory
    add_custom_command(
        OUTPUT "${JNI_OUTPUTS}"
        COMMAND ${Java_JAVAC_EXECUTABLE} ${JSS_JAVAC_FLAGS} -d ${CLASSES_OUTPUT_DIR} -h ${JNI_OUTPUT_DIR} ${JAVA_SOURCES}
        COMMAND touch "${JNI_OUTPUTS}"
        DEPENDS ${JAVA_SOURCES}
    )

    add_custom_command(
        OUTPUT "${TESTS_JNI_OUTPUTS}"
        COMMAND ${Java_JAVAC_EXECUTABLE} ${JSS_JAVAC_FLAGS} -d ${TESTS_CLASSES_OUTPUT_DIR} -h ${TESTS_JNI_OUTPUT_DIR} ${JAVA_TEST_SOURCES}
        COMMAND touch "${TESTS_JNI_OUTPUTS}"
        DEPENDS ${JAVA_TEST_SOURCES}
    )

    add_custom_target(
        generate_java ALL
        DEPENDS ${JNI_OUTPUTS} ${TESTS_JNI_OUTPUTS}
    )
endmacro()

# "Build" all includes by copying them to a common directory
macro(jss_build_includes)
    # Note that file(COPY ...) operations are performed at "CMake" run time,
    # (equivalent to configure time), so CMake needs to be reconfigured every
    # time a new header file is added. This is most easily done by removing
    # the build directory and recreating it. This also applies to all other
    # build steps as the globs are computed at configure time as well.
    foreach(C_HEADER ${C_HEADERS})
        file(COPY "${C_HEADER}" DESTINATION ${INCLUDE_OUTPUT_DIR})
    endforeach()

    foreach(C_TEST_HEADER ${C_TEST_HEADERS})
        file(COPY "${C_TEST_HEADER}" DESTINATION ${TESTS_INCLUDE_OUTPUT_DIR})
    endforeach()

    add_custom_target(
        generate_includes
    )
endmacro()

# Compile a single C file
macro(jss_build_c_file C_FILE C_OUTPUT C_TARGET C_DIR)
    # C files can be built in parallel. This macro builds each file wrapped in
    # add_custom_command+add_custom_target so parallel builds work. Note that
    # each build depends on generate_java and generate_includes to have
    # finished, else many headers wouldn't exist.
    add_custom_command(
        OUTPUT "${C_OUTPUT}"
        COMMAND ${CMAKE_C_COMPILER} -fPIC ${JSS_C_FLAGS} -o ${C_OUTPUT} -c ${C_FILE}
        WORKING_DIRECTORY ${C_DIR}
        DEPENDS ${C_FILE}
        DEPENDS generate_java
        DEPENDS generate_includes
    )

    add_custom_target(
        "generate_c_${C_TARGET}"
        DEPENDS "${C_OUTPUT}" ${C_HEADERS}
    )
endmacro()

# Compile all C source files and build libjss library
macro(jss_build_c)
    foreach(C_SOURCE ${C_SOURCES})
        get_filename_component(C_TARGET ${C_SOURCE} NAME_WE)
        get_filename_component(C_DIR ${C_SOURCE} DIRECTORY)
        set(C_OUTPUT "${LIB_OUTPUT_DIR}/${C_TARGET}.o")

        jss_build_c_file("${C_SOURCE}" "${C_OUTPUT}" "${C_TARGET}" "${C_DIR}")
        list(APPEND C_OUTPUTS "${C_OUTPUT}")
    endforeach()

    # Combine all C targets here into a single pseudo-target for parallel
    # builds.
    add_custom_target(
        generate_c ALL
        DEPENDS ${C_OUTPUTS}
    )

    # We generate two libraries: build/lib/libjss.so and build/libjss.so:
    # the former is for testing and is unversioned, so all symbols are public
    # and can thus be tested; the latter is for releases and is versioned,
    # limiting which symbols are made public. We only need to make the JNI
    # symbols public as libjss.so should only be used from Java in conjunction
    # with jss.jar.
    add_custom_command(
        OUTPUT "${JSS_SO_PATH}" "${JSS_TESTS_SO_PATH}"
        COMMAND ${CMAKE_C_COMPILER} -o ${JSS_TESTS_SO_PATH} ${LIB_OUTPUT_DIR}/*.o ${JSS_LD_FLAGS} ${JSS_LIBRARY_FLAGS}
        COMMAND ${CMAKE_C_COMPILER} -o ${JSS_SO_PATH} ${LIB_OUTPUT_DIR}/*.o ${JSS_LD_FLAGS} ${JSS_VERSION_SCRIPT} ${JSS_LIBRARY_FLAGS}
        DEPENDS generate_c
    )

    # Add a target for anything depending on the library existing.
    add_custom_target(
        generate_so ALL
        DEPENDS ${JSS_SO_PATH} ${JSS_TESTS_SO_PATH}
    )
endmacro()

# Build the jar by combining the java classes from generate_java step
macro(jss_build_jars)
    # Note that build/MANIFEST.MF is generated by JSSConfig.cmake's
    # jss_config_version macro. Further, this doesn't yet build a reproducible
    # JAR.
    add_custom_command(
        OUTPUT "${JSS_BUILD_JAR_PATH}"
        COMMAND "${Java_JAR_EXECUTABLE}" cmf "${CMAKE_BINARY_DIR}/MANIFEST.MF" ${JSS_BUILD_JAR_PATH} org/*
        WORKING_DIRECTORY "${CLASSES_OUTPUT_DIR}"
        DEPENDS generate_java
    )

    add_custom_command(
        OUTPUT "${JSS_TESTS_JAR_PATH}"
        COMMAND "${Java_JAR_EXECUTABLE}" cmf "${CMAKE_BINARY_DIR}/MANIFEST.MF" ${JSS_TESTS_JAR_PATH} org/*
        WORKING_DIRECTORY "${TESTS_CLASSES_OUTPUT_DIR}"
        DEPENDS generate_java
    )

    add_custom_target(
        generate_build_jar
        DEPENDS "${JSS_BUILD_JAR_PATH}"
    )

    add_custom_command(
        OUTPUT "${JSS_JAR_PATH}"
        COMMAND "${PROJECT_SOURCE_DIR}/tools/reproducible_jar.sh" "${JSS_BUILD_JAR_PATH}" "${REPRODUCIBLE_TEMP_DIR}" "${JSS_JAR_PATH}"
        DEPENDS generate_build_jar
    )

    add_custom_target(
        generate_jar ALL
        DEPENDS "${JSS_JAR_PATH}" "${JSS_TESTS_JAR_PATH}"
    )
endmacro()

# Build javadocs from the source files
macro(jss_build_javadocs)
    # Add another pseudo-target here as well -- javadocs create a lot of
    # output, but anything which depends on the javadocs existing should
    # depend on the javadoc target.
    set(JAVADOCS_OUTPUTS "${TARGETS_OUTPUT_DIR}/finished_generate_javadocs")

    add_custom_command(
        OUTPUT ${JAVADOCS_OUTPUTS}
        COMMAND "${Java_JAVADOC_EXECUTABLE}" -overview "${PROJECT_SOURCE_DIR}/tools/javadoc/overview.html" -windowtitle "${JSS_WINDOW_TITLE}" -notimestamp -breakiterator -classpath ${JAVAC_CLASSPATH} -sourcepath ${PROJECT_SOURCE_DIR} -d ${DOCS_OUTPUT_DIR} ${JSS_PACKAGES}
        COMMAND touch "${JAVADOCS_OUTPUTS}"
        DEPENDS ${JAVA_SOURCES}
    )

    add_custom_target(
        javadoc
        DEPENDS ${JAVADOCS_OUTPUTS}
    )

    # For compliance with GNU Make standard targets
    add_custom_target(
        html
        DEPENDS javadoc
    )
endmacro()
