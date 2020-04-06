# Build System

This document describes the CMake build system and various locations used
by CMake.


## Overview

The new build system relies on CMake to build JSS. Most of the functionality
is located under the `cmake/` directory in the root of the project. JSS is
built in five stages:

1. Classes are built from Java source and JNI headers are generated. This is
   done in a single pass of the `javac` compiler. All Java source files under
   `org/` are currently compiled to the `build/classes/` folder.
2. Any C header files are moved to the `build/includes/` folder.
3. C source files are compiled to objects and linked to form `libjss4.so`,
   excluding any C source files in `org/mozilla/jss/tests`. If any exist,
   they'll be compiled at a later stage for `ctest`. This step is dependent
   on steps 1 and 2.
4. Build the JAR archive from compiled Java classes. Note that at this time,
   all classes in `build/classes/` are compiled into one JAR; in the future,
   a white list might be applied and testing classes separated out into a
   different JAR. This is dependent on step 1.
5. (Optionally) build Javadocs. This requires the user to build the `javadoc`
   target.

The test suite is also generated using CMake in `cmake/JSSTests.cmake`. This
allows JSS to run its test in parallel.


## `CMakeLists.txt`

This is a file required by CMake for all CMake projects; it defines how the
project is built. We use it as a high-level overview of CMake: options are
defined, environment variables are read, modules are imported, and JSS is
built and tested through here.

JSS uses a direct approach to building: as a single call to `javac` suffices
to build all of our classes and JNI headers, we don't need a recursive
structure to build. This lets us have only one `CMakeLists.txt` in the root
of our project.


## `cmake/`

This directory contains two sets of files: dependencies and core modules.
The non-standard CMake dependencies currently include the `FindNSPR` and
`FindNSS` modules: these allow CMake to find NSPR and NSS system libraries
and were imported from PKI. The core modules include `JSSConfig`, which
sets useful variables for use within CMake, `JSSCommon`, which controls
building JSS, and `JSSTests`, which sets up the JSS test suite within
CTest.

### Available CMake Options

Our CMake generator currently understands the following options when
configuring the build system. Each option can either be specified on the CMake
command line with `-D<VAR>=<VALUE>` syntax, or in the environment.

 - `CHECK_DEPRECATION` -- enable `-Xlint:deprecation` when compiling JSS to
    check for use of deprecated APIs.
 - `FIPS_ENABLED` -- disable certain test cases which are known to fail in
    FIPS mode for various reasons. These usually include tests which try to
    disable FIPS mode, use unsupported ciphers, or too small of key sizes.
    Note that NSS must still be built with FIPS mode support enabled.
 - `SANDBOX` -- support building sandboxed builds to test changes to NSPR or
    NSS alongside changes to JSS. This assumes you have the following
    directory structure:

    ```
    sandbox/
    sandbox/nspr
    sandbox/nss
    sandbox/dist
    sandbox/jss
    ```

    Note that `sandbox` can be replaced by any directory name. The
    `sandbox/dist` folder is automatically created by NSS upon build.
    Please first build NSS (according to current instructions) and then
    build JSS.
 - `TEST_VALGRIND` -- run the entire test suite under Valgrind. This option
    is quite slow. By default it passes two arguments: `--track-origins=yes`
    and `--leak-check=full`. Modify `cmake/JSSTests.cmake` (macro:
    `jss_test_exec`) to change these options.
 - `WITH_INTERNET` -- run tests which require an internet connection. This
    exposes your system to other hosts on the internet, including badssl.com
    and www.mozilla.org. Correct execution requires a working `common_roots.sh`
    script under `tools/`; update for your system as necessary.

### Adding a Test Case

To add a new test case, add an entry to `cmake/JSSTests.cmake`. There's two
useful helpers macros `jss_test_exec` and `jss_test_java`.

`jss_test_exec` takes a `NAME` parameter (to use to identify the test case
in output and when running particular tests), a `COMMAND` to execute, and an
optional set of dependencies (`DEPENDS ...`) on other tests. We use this
because `add_test` doesn't itself handle dependencies or set environment
variables (we need to inject `LD_LIBRARY_PATH` to handle testing our built
`libjss4.so`).

`jss_test_java` is a wrapper over `jss_test_exec` which handles setting up
the JVM and passing required arguments to it (`-classpath`, `-enableasserts`,
etc.). Pass only the class you wish to execute and any arguments to it as
the COMMAND field. (e.g., `COMMAND "org.mozilla.jss.tests.TestBuffer"`).

There are a few useful variables defined:

 - `JSS_TEST_DIR` -- directory to the souce code where the tests are
    contained.
 - `PASSWORD_FILE` -- password for the NSS DB tokens.
 - `DB_PWD` -- password for the NSS DB internal (default) token.
 - `RESULTS_DATA_OUTPUT_DIR` -- directory to write test results to.
 - `RESULTS_NSSDB_OUTPUT_DIR` -- path of the non-FIPS NSS DB.
 - `RESULTS_NSSDB_FIPS_OUTPUT_DIR` -- path of the FIPS NSS DB.

Note that, on a FIPS-enabled machine, `RESULTS_NSSDB_FIPS_OUTPUT_DIR` is
unused and `RESULTS_NSSDB_OUTPUT_DIR` is actually placed in FIPS mode.
For tests which would fail in FIPS mode, place them in the
`if(NOT FIPS_ENABLED)` block.

## `lib/`

This includes a few templated files including `jss.map`, the linker script
which contains a versioned API of JSS, and `MANIFEST.MF.in`, JSS's Jar
manifest file.
