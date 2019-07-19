# This is the CMakeLists.txt for the JSS Project.
project(jss)

# Required cmake version; set a 3.0.2 since that's the version of the
# documentation I referenced.
cmake_minimum_required(VERSION 3.0.2)

# Source our custom CMake modules; this includes NSS and NSPR modules from
# PKI and the JSSConfig and JSSCommon modules.
set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)

# Define optional variables and conditionals.
if (DEFINED ENV{CHECK_DEPRECATION})
    list(APPEND JSS_JAVAC_FLAGS "-Xlint:deprecation")
endif()

if (DEFINED ENV{FIPS_ENABLED})
    set(FIPS_ENABLED_ENV TRUE)
endif()
option(FIPS_ENABLED "When enabled, disable certain tests which don't work in FIPS mode. This should only be specified when the host system is in FIPS mode." ${FIPS_ENABLED_ENV})

# Build a debug build by default when no type is specified on the command line
if(NOT (DEFINED CMAKE_BUILD_TYPE))
    set(CMAKE_BUILD_TYPE "Debug")
endif()

# Find NSPR and NSS Libraries.
find_package(NSPR REQUIRED)
find_package(NSS REQUIRED)

# Find Java and JNI packages; this sets CMake wariables like
# Java_JAVAC_EXECUTABLE.
find_package(Java REQUIRED)
find_package(JNI REQUIRED)

# Since we found Java, include UseJava to provide the find_jar function.
include(UseJava)

# Load JSSConfig module; this defines the jss_config() macro which defines
# JSS-specific configuration values.
include(JSSConfig)

# Load JSSCommon module; this defines the jss_build() macros which defines
# the JSS build procedure.
include(JSSCommon)

# Load JSSTests module; this defines the jss_tests() macro which defines the
# JSS test procedure.
include(JSSTests)

jss_config()
jss_build()
jss_tests()
