# Building JSS

There are two main ways of building JSS: against the system installed NSS and
NSPR libraries, or against the source versions of those libraries. These two
methods are discussed further below.


## Dependencies

Please make sure your dependencies are up to date before continuing. For more
information on our dependencies, see the contents of
[`docs/dependencies.md`](dependencies.md).


## Quick Build

If you're looking to build JSS quickly, please make sure you have all the
required dependencies installed. Then, to build:

    source tools/autoenv.sh
    make clean all

And to run tests:

    source tools/autoenv.sh
    make check

For more information about the build system, please read refer to the build
system documentation: [`docs/build_system.md`](build_system.md).

`tools/autoenv.sh` is a script which attempts to detect the required
environment variables to build: `JAVA_HOME`, `USE_64`, and whether to use
a source version of NSS and NSPR or the system-installed version.


## Sandbox Build

If you're looking to build JSS against the latest NSS and NSPR versions, or
against the latest upstream code, we recommend doing a sandboxed build.

### 1. Preparing the Sandbox

Create a directory (perhaps called `sandbox`) and change into it:

    mkdir sandbox/
    cd sandbox

Then, fetch the latest contents from upstream:

    hg clone https://hg.mozilla.org/projects/nspr
    hg clone https://hg.mozilla.org/projects/nss
    git clone https://github.com/dogtagpki/jss

For additional builds, you can update these dependencies with the following:

    cd nspr && hg pull -u -v && cd ..
    cd nss && hg pull -u -v && cd ..
    cd jss && checkout master && git pull -v && cd ..

Note that there is no need to re-clone each time; updating will suffice.

### 2. Set Environment Variables

The following environment variables are mandatory; please ensure the
path specified by `JAVA_HOME` points to a valid JDK installation:

    export JAVA_HOME=/etc/alternatives/java_sdk_openjdk

Note that JSS only supports building against OpenJDK. Additionally,
if building in a 64-bit environment:

    export USE_64=1

For more information about the build system and the available environment
variables, please read refer to the build system documentation:
[`docs/build_system.md`](build_system.md).

### 3. Building JSS

To build JSS, execute the following; this builds JSS using the `Makefile`
wrapper around the Perl build system:

    cd jss
    make clean all

The built contents are placed in `sandbox/dist`. Note that this also builds
and installs NSS and NSPR to the same location.

### 4. Testing JSS

To test JSS, run the test suite from the `Makefile` interface:

    make check

### 5. Installing JSS

If JSS already exists on the system, run something similar to the
following command(s) to back up the old installation:

    sudo mv /usr/lib/java/jss4.jar /usr/lib/java/jss4.jar.orig

If the platform is 32-bit Linux:

    sudo mv /usr/lib/jss/libjss4.so /usr/lib/jss/libjss4.so.orig

else if the platform is 64-bit Linux:

    sudo mv /usr/lib64/jss/libjss4.so /usr/lib64/jss/libjss4.so.orig

Then install the new JSS binaries:

    sudo cp sandbox/dist/xpclass.jar /usr/lib/java/jss4.jar
    sudo chown root:root /usr/lib/java/jss4.jar
    sudo chmod 644 /usr/lib/java/jss4.jar

    sudo cp sandbox/jss/lib/Linux*.OBJ/libjss4.so /usr/lib64/jss/libjss4.so
    sudo chown root:root /usr/lib64/jss/libjss4.so
    sudo chmod 755 /usr/lib64/jss/libjss4.so

Note that the above paths are specific to Fedora; your operating system might
have different paths and preferred installation locations. Please adapt as
necessary.

### 6. Uninstalling JSS

If step (4) above was run, and the system is being used for purposes
other than test, the user may wish to restore the original system JSS
by running the following commands:

    sudo mv /usr/lib/java/jss4.jar.orig /usr/lib/java/jss4.jar

If the platform is 32-bit Linux:

    sudo mv /usr/lib/jss/libjss4.so.orig /usr/lib/jss/libjss4.so

else if the platform is 64-bit Linux:

    sudo mv /usr/lib64/jss/libjss4.so.orig /usr/lib64/jss/libjss4.so

NOTE: For this procedure, no ownership or permission changes should
be necessary.


## System Build

The steps for performing a system build are the same as the steps for
performing a sandboxed build, outside of steps one and two. In particular,
there is no need to fetch NSS and NSPR upstreams, though it is required to
build a sandbox directory. Secondly, additional environment variables need
to be set.

### 1. Preparing the Sandbox

Create a directory (perhaps called `sandbox`) and change into it:

    mkdir sandbox/
    cd sandbox

Then, fetch the latest contents from upstream:

    git clone https://github.com/dogtagpki/jss

For additional builds, you can update these dependencies with the following:

    cd jss && checkout master && git pull -v && cd ..

Note that there is no need to re-clone each time; updating will suffice.

### 2. Set Environment Variables

The following environment variables are mandatory; please ensure the
path specified by `JAVA_HOME` points to a valid JDK installation:

    export JAVA_HOME=/etc/alternatives/java_sdk_openjdk

Note that JSS only supports building against OpenJDK. Additionally,
if building in a 64-bit environment:

    export USE_64=1

Additionally, to use the system installed NSS and NSPR:

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

Note that we do not recommend and will not support mixing the system-installed
NSS with a sandboxed NSPR version and visa versa.

For more information about the build system and the available environment
variables, please read refer to the build system documentation:
[`docs/build_system.md`](build_system.md).

### 3. Proceed with step 3 above.

To complete the build, follow the same steps as step 3 through 6 above.


## RPM Build

To build a RPM release, please ensure all dependencies are installed:

    sudo dnf install rpm-build
    cd jss && sudo dnf builddep --spec jss.spec

Then, issue a build using the `build.sh` interface:

    ./build.sh

This will build RPMS and place them in `$HOME/build/jss` by default. For more
information about this build script, refer to its help text:

    ./build.sh --help
