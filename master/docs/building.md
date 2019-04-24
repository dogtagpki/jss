# Building JSS

As of version 4.5.1, JSS has moved to a CMake build system. This is a modern
alternative to our legacy build system and gives us a standard framework for
building and testing JSS. This also allows us to support parallel builds
and tests; to take advantage of this, specify the `-j` flag when using
`make` or `ctest`.

Please make sure the required dependencies are installed prior to building
(see: [`docs/dependencies`](dependencies.md)).


## In-Source Build

To build JSS from the source release, use `cmake`; JSS behaves much like
a regular CMake project.


### Building JSS

To build JSS using CMake:

    cd jss/build
    cmake ..
    make all

To later rebuild from scratch, remove the build directory and recreate it.
This ensures that any new dependencies are reflected in the build system.

    cd jss
    rm -rf build && mkdir build && cd build
    cmake ..
    make all


### Building Documentation
Optionally, build the javadocs:

    cd jss/build
    make javadoc


### Testing
To run the test suite:

    cd jss/build
    make test

Note that the test suite currently doesn't handling re-running without
clearing the results directory. To re-run the test suite:

    cd jss/build
    rm -rf results
    mkdir -p results/tests results/fips
    make test

Alternatively, use CTest to run the test suite:

    ctest --output-on-failure

Helpful flags for ctest are `--verbose` and `--output-log`; for more
information, read `man ctest`.


### Installation

To install JSS, place `jss4.jar` and `libjss4.so` in places where the system
can find them. We recommend the following locations on a 64-bit system:

    cd jss/build
    sudo cp jss4.jar /usr/lib/java/jss4.jar
    sudo chown root:root /usr/lib/java/jss4.jar
    sudo chmod 644 /usr/lib/java/jss4.jar

    sudo cp libjss4.so /usr/lib64/jss/libjss4.so
    sudo chown root:root /usr/lib64/jss/libjss4.so
    sudo chmod 755 /usr/lib64/jss/libjss4.so

To uninstall, simply remove the created files (`/usr/lib/java/jss4.jar` and
`/usr/lib64/jss/libjss4.so`).

Note that the preferred way to install JSS is from your distribution or via
an RPM built with `build.sh`.


## RPM Builds

To build a RPM release, please ensure all dependencies are installed:

    sudo dnf install rpm-build
    cd jss && sudo dnf builddep --spec jss.spec

Then, issue a build using the `build.sh` interface:

    ./build.sh

This will build RPMS and place them in `$HOME/build/jss` by default. For more
information about this build script, refer to its help text:

    ./build.sh --help
