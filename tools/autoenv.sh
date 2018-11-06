#!/bin/sh

# This script attempts to detect the correct environmental variables required
# to build JSS from source.

# Try and detect a JDK installation.
if [ "x$JAVA_HOME" = "x" ] && [ -e "/etc/alternatives/java_sdk" ]; then
    export JAVA_HOME="/etc/alternatives/java_sdk"
fi
if [ "x$JAVA_HOME" = "x" ]; then
    # Prefer JDK 8 installation, if present...
    java8_jdk="$(find /usr/lib/jvm -maxdepth 1 -mindepth 1 -type d | grep '\(\-8\-\|-1\.8\.\)' | sort | tail -n 1)"
    if [ -d "$java8_jdk" ]; then
        export JAVA_HOME="$java8_jdk"
    fi
fi
if [ "x$JAVA_HOME" = "x" ]; then
    # Attempt to automatically detect it from java program...
    system_java="$(java -XshowSettings:properties -version 2>&1 > /dev/null | grep 'java.home' | sed 's/^.* = //g')"
    dirname_system_java="$(dirname "$system_java")"

    if [ -e "$system_java/bin/javac" ]; then
        export JAVA_HOME="$system_java"
    elif [ -e "$dirname_system_java/bin/javac" ]; then
	export JAVA_HOME="$dirname_system_java"
    fi
fi

# Validate that JAVA_HOME was set; otherwise, exit.
if [ "x$JAVA_HOME" = "x" ]; then
    echo "Unable to detect JAVA_HOME installation automatically!" 1>&2
    return 1
fi

# Check if we're running in 64-bit mode.
if [ "x$(getconf LONG_BIT)" = "x64" ]; then
    export USE_64=1
fi

# Check if we're in a location with nss/nspr above us; if not, use the system
# versions.
if [ ! -d ../nspr ] || [ ! -d ../nss ]; then
    export USE_INSTALLED_NSPR=1
    export USE_INSTALLED_NSS=1
    export PKG_CONFIG_ALLOW_SYSTEM_LIBS=1
    export PKG_CONFIG_ALLOW_SYSTEM_CFLAGS=1

    NSPR_INCLUDE_DIR="$(pkg-config --cflags-only-I nspr | sed 's/-I//')"
    NSPR_LIB_DIR="$(pkg-config --libs-only-L nspr | sed 's/-L//')"
    NSS_INCLUDE_DIR="$(pkg-config --cflags-only-I nss | sed 's/-I//')"
    NSS_LIB_DIR="$(pkg-config --libs-only-L nss | sed 's/-L//')"
    export NSPR_INCLUDE_DIR
    export NSPR_LIB_DIR
    export NSS_INCLUDE_DIR
    export NSS_LIB_DIR
    export XCFLAGS="-g"
else
    export USE_INSTALLED_NSPR=""
    export USE_INSTALLED_NSS=""
fi
