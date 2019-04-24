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
FindNSS` modules: these allow CMake to find NSPR and NSS system libraries
and were imported from PKI. The core modules include `JSSConfig`, which
sets useful variables for use within CMake, `JSSCommon`, which controls
building JSS, and `JSSTests`, which sets up the JSS test suite within
CTest.


## `lib/`

This includes a few templated files including `jss.map`, the linker script
which contains a versioned API of JSS, and `MANIFEST.MF.in`, JSS's Jar
manifest file.
