# Build System

There are three interfaces to the build system:

 - `build_java.pl`
 - `build.sh`
 - `Makefile`

Each of these are described in further detail below.


## `build_java.pl`

This is the primary script that drive the build system. It contains all logic
for compiling the Java files and producing the output artifacts. It supports
five primary operations:

 - `clean` -- removes build artifacts from the directory, including `dist`
   directory.
 - `build` -- builds JSS by finding java files, compiling them, and creating
    JNI headers
 - `release` -- creates a release with all classes in one location.
 - `javadoc` -- build documentation from the in-source javadocs
   This creates an HTML version in `sandbox/dist/jssdoc`.
 - `test` -- runs the JSS test suite. Note that the NSS and NSPR
   test suites are run as part of their build processes.

The build is affected by several environment variables:

 - `JAVA_HOME` -- required to point to the path to the JDK installation
   that they are building against.
 - `USE_64` -- whether or not to build a 64-bit distribution. Note that
   this is required to be set to true on 64-bit systems (i.e., you cannot
   build JSS for `i386/i686` on `x86_64`.
 - `BUILD_OPT` -- whether or not to build optimized binaries (`-O` as a
   compiler flag; by default (if not present or false), binaries are
   built with debug flags (`-g`).
 - `CHECK_DEPRECATION` -- if set, checks for use of deprecated objects
   during the Java build.
 - `USE_INSTALLED_NSPR` -- if set, use the system NSPR instead of the
   version in the sandbox.
 - `USE_INSTALLED_NSS` -- if set, use the system NSS instead of the version
   in the sandbox.
 - `NSS_LIB_DIR` -- location to NSS libraries; required if `USE_INSTALLED_NSS`
   is set.
 - `HTML_HEADER` -- HTML header for use with `javadoc` target; passed by
   `-header HTML_HEADER` to `javadoc` command.


## `build.sh`

This script uses the rpmbuild to transform the in-source spec file into an
RPM which triggers the build and test processes. The result is a set of RPMs
which mirror the current state of the source tree. Using this interface adds
an additional dependency on `rpmbuild`; it is also suggested to install
all dependencies via `dnf build-dep --spec jss.spec`.


## `make`

Using `make `from the root of the source tree provides a wrapper over the
`build_java.pl` interface. This is used by the spec file to build JSS and
exposes several targets similar to `build_java.pl`:

 - `all` (default target) -- build jss and rebuild dependencies if not
   present.
 - `clean` -- remove
 - `check` or `test_jss` -- run jss test suite on built objects; note that
   jss must be built prior to running the test suite.
 - `dist` or `release_classes` -- build jss for release.
 - `javadoc` or `html` -- build java documentation.
