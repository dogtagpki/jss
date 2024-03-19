#!/bin/bash -e

# BEGIN COPYRIGHT BLOCK
# (C) 2018 Red Hat, Inc.
# All rights reserved.
# END COPYRIGHT BLOCK

SCRIPT_PATH="$(readlink -f "$0")"
SCRIPT_NAME="$(basename "$SCRIPT_PATH")"
SRC_DIR="$(dirname "$SCRIPT_PATH")"

NAME=jss
WORK_DIR=

PREFIX_DIR="/usr"
INCLUDE_DIR="/usr/include"

if [ "$HOSTTYPE" = "x86_64" ]; then
   LIB_DIR="/usr/lib64"
else
   LIB_DIR="/usr/lib"
fi

SYSCONF_DIR="/etc"
SHARE_DIR="/usr/share"

CMAKE="cmake"

JNI_DIR="/usr/lib/java"
INSTALL_DIR=

SOURCE_TAG=
SPEC_TEMPLATE="$SRC_DIR/jss.spec"
SPEC_FILE=

VERSION=
RELEASE=

WITH_TIMESTAMP=
WITH_COMMIT_ID=
DIST=

WITH_JAVA=true
WITH_NATIVE=true
WITH_JAVADOC=true
WITH_TESTS=true

VERBOSE=
DEBUG=

usage() {
    echo "Usage: $SCRIPT_NAME [OPTIONS] <target>"
    echo
    echo "Options:"
    echo "    --name=<name>          Package name (default: $NAME)."
    echo "    --work-dir=<path>      Working directory (default: ~/build/$NAME)."
    echo "    --prefix-dir=<path>    Prefix directory (default: $PREFIX_DIR)."
    echo "    --include-dir=<path>   Include directory (default: $INCLUDE_DIR)."
    echo "    --lib-dir=<path>       Library directory (default: $LIB_DIR)."
    echo "    --sysconf-dir=<path>   System configuration directory (default: $SYSCONF_DIR)."
    echo "    --share-dir=<path>     Share directory (default: $SHARE_DIR)."
    echo "    --cmake=<path>         Path to CMake executable"
    echo "    --java-home=<path>     Java home"
    echo "    --jni-dir=<path>       JNI directory (default: $JNI_DIR)."
    echo "    --install-dir=<path>   Installation directory."
    echo "    --source-tag=<tag>     Generate RPM sources from a source tag."
    echo "    --spec=<file>          Use the specified RPM spec (default: $SPEC_TEMPLATE)."
    echo "    --version=<version>    Use the specified version."
    echo "    --release=<release>    Use the specified release."
    echo "    --with-timestamp       Append timestamp to release number."
    echo "    --with-commit-id       Append commit ID to release number."
    echo "    --dist=<name>          Distribution name (e.g. fc28)."
    echo "    --without-java         Do not build Java binaries."
    echo "    --without-native       Do not build native binaries."
    echo "    --without-javadoc      Do not build Javadoc package."
    echo "    --without-tests        Do not build tests package."
    echo " -v,--verbose              Run in verbose mode."
    echo "    --debug                Run in debug mode."
    echo "    --help                 Show help message."
    echo
    echo "Target:"
    echo "    dist     Build JSS binaries (default)."
    echo "    install  Install JSS binaries."
    echo "    src      Generate RPM sources."
    echo "    spec     Generate RPM spec."
    echo "    srpm     Build SRPM package."
    echo "    rpm      Build RPM packages."
}

generate_rpm_sources() {

    PREFIX="jss-$VERSION"

    if [[ "$PHASE" != "" ]]; then
        PREFIX=$PREFIX-$PHASE
    fi

    TARBALL="$PREFIX.tar.gz"

    if [ "$SOURCE_TAG" != "" ] ; then

        if [ "$VERBOSE" = true ] ; then
            echo "Generating $TARBALL from $SOURCE_TAG tag"
        fi

        git -C "$SRC_DIR" \
            archive \
            --format=tar.gz \
            --prefix "$PREFIX/" \
            -o "$WORK_DIR/SOURCES/$TARBALL" \
            "$SOURCE_TAG"

        if [ "$SOURCE_TAG" != "HEAD" ] ; then

            TAG_ID="$(git -C "$SRC_DIR" rev-parse "$SOURCE_TAG")"
            HEAD_ID="$(git -C "$SRC_DIR" rev-parse HEAD)"

            if [ "$TAG_ID" != "$HEAD_ID" ] ; then
                generate_patch
            fi
        fi

        return
    fi

    if [ "$VERBOSE" = true ] ; then
        echo "Generating $TARBALL"
    fi

    tar czf "$WORK_DIR/SOURCES/$TARBALL" \
        --transform "s,^./,$PREFIX/," \
        --exclude .git \
        --exclude build \
        -C "$SRC_DIR" \
        .
}

generate_patch() {

    PATCH="jss-$VERSION-$RELEASE.patch"

    if [ "$VERBOSE" = true ] ; then
        echo "Generating $PATCH for all changes since $SOURCE_TAG tag"
    fi

    git -C "$SRC_DIR" \
        format-patch \
        --stdout \
        "$SOURCE_TAG" \
        > "$WORK_DIR/SOURCES/$PATCH"
}

generate_rpm_spec() {

    SPEC_FILE="$WORK_DIR/SPECS/$NAME.spec"

    if [ "$VERBOSE" = true ] ; then
        echo "Creating $SPEC_FILE"
    fi

    cp "$SPEC_TEMPLATE" "$SPEC_FILE"

    # hard-code package name
    sed -i "s/^\(Name: *\).*\$/\1${NAME}/g" "$SPEC_FILE"

    # hard-code timestamp
    if [ "$TIMESTAMP" != "" ] ; then
        sed -i "s/%undefine *timestamp/%global timestamp $TIMESTAMP/g" "$SPEC_FILE"
    fi

    # hard-code commit ID
    if [ "$COMMIT_ID" != "" ] ; then
        sed -i "s/%undefine *commit_id/%global commit_id $COMMIT_ID/g" "$SPEC_FILE"
    fi

    # hard-code patch
    if [ "$PATCH" != "" ] ; then
        sed -i "s/# Patch: jss-VERSION-RELEASE.patch/Patch: $PATCH/g" "$SPEC_FILE"
    fi

    # hard-code Javadoc option
    if [ "$WITH_JAVADOC" = false ] ; then
        # convert bcond_without into bcond_with such that Javadoc package is not built by default
        sed -i "s/%\(bcond_without *javadoc\)\$/# \1\n%bcond_with javadoc/g" "$SPEC_FILE"
    fi

    # hard-code tests option
    if [ "$WITH_TESTS" = false ] ; then
        # convert bcond_without into bcond_with such that tests package is not built by default
        sed -i "s/%\(bcond_without *tests\)\$/# \1\n%bcond_with tests/g" "$SPEC_FILE"
    fi

    # rpmlint "$SPEC_FILE"
}

while getopts v-: arg ; do
    case $arg in
    v)
        VERBOSE=true
        ;;
    -)
        LONG_OPTARG="${OPTARG#*=}"

        case $OPTARG in
        name=?*)
            NAME="$LONG_OPTARG"
            ;;
        work-dir=?*)
            WORK_DIR=$(readlink -f "$LONG_OPTARG")
            ;;
        prefix-dir=?*)
            PREFIX_DIR=$(readlink -f "$LONG_OPTARG")
            ;;
        include-dir=?*)
            INCLUDE_DIR=$(readlink -f "$LONG_OPTARG")
            ;;
        lib-dir=?*)
            LIB_DIR=$(readlink -f "$LONG_OPTARG")
            ;;
        sysconf-dir=?*)
            SYSCONF_DIR=$(readlink -f "$LONG_OPTARG")
            ;;
        share-dir=?*)
            SHARE_DIR=$(readlink -f "$LONG_OPTARG")
            ;;
        cmake=?*)
            CMAKE=$(readlink -f "$LONG_OPTARG")
            ;;
        java-home=?*)
            JAVA_HOME=$(readlink -f "$LONG_OPTARG")
            ;;
        jni-dir=?*)
            JNI_DIR=$(readlink -f "$LONG_OPTARG")
            ;;
        install-dir=?*)
            INSTALL_DIR=$(readlink -f "$LONG_OPTARG")
            ;;
        source-tag=?*)
            SOURCE_TAG="$LONG_OPTARG"
            ;;
        spec=?*)
            SPEC_TEMPLATE="$LONG_OPTARG"
            ;;
        version=?*)
            VERSION="$LONG_OPTARG"
            ;;
        release=?*)
            RELEASE="$LONG_OPTARG"
            ;;
        with-timestamp)
            WITH_TIMESTAMP=true
            ;;
        with-commit-id)
            WITH_COMMIT_ID=true
            ;;
        dist=?*)
            DIST="$LONG_OPTARG"
            ;;
        without-java)
            WITH_JAVA=false
            ;;
        without-native)
            WITH_NATIVE=false
            ;;
        without-javadoc)
            WITH_JAVADOC=false
            ;;
        without-tests)
            WITH_TESTS=false
            ;;
        verbose)
            VERBOSE=true
            ;;
        debug)
            VERBOSE=true
            DEBUG=true
            ;;
        help)
            usage
            exit
            ;;
        '')
            break # "--" terminates argument processing
            ;;
        name* | work-dir* | prefix-dir* | include-dir* | lib-dir* | sysconf-dir* | share-dir* | cmake* | \
        java-home* | jni-dir* | install-dir* | \
        source-tag* | spec* | version* | release* | dist*)
            echo "ERROR: Missing argument for --$OPTARG option" >&2
            exit 1
            ;;
        *)
            echo "ERROR: Illegal option --$OPTARG" >&2
            exit 1
            ;;
        esac
        ;;
    \?)
        exit 1 # getopts already reported the illegal option
        ;;
    esac
done

# remove parsed options and args from $@ list
shift $((OPTIND-1))

if [ "$#" -lt 1 ] ; then
    BUILD_TARGET=dist
else
    BUILD_TARGET=$1
fi

if [ "$WORK_DIR" = "" ] ; then
    WORK_DIR="$HOME/build/$NAME"
fi

if [ "$DEBUG" = true ] ; then
    echo "NAME: $NAME"
    echo "WORK_DIR: $WORK_DIR"
    echo "PREFIX_DIR: $PREFIX_DIR"
    echo "INCLUDE_DIR: $INCLUDE_DIR"
    echo "LIB_DIR: $LIB_DIR"
    echo "SYSCONF_DIR: $SYSCONF_DIR"
    echo "SHARE_DIR: $SHARE_DIR"
    echo "CMAKE: $CMAKE"
    echo "JAVA_HOME: $JAVA_HOME"
    echo "JNI_DIR: $JNI_DIR"
    echo "INSTALL_DIR: $INSTALL_DIR"
    echo "BUILD_TARGET: $BUILD_TARGET"
fi

if [ "$BUILD_TARGET" != "dist" ] &&
        [ "$BUILD_TARGET" != "install" ] &&
        [ "$BUILD_TARGET" != "src" ] &&
        [ "$BUILD_TARGET" != "spec" ] &&
        [ "$BUILD_TARGET" != "srpm" ] &&
        [ "$BUILD_TARGET" != "rpm" ] ; then
    echo "ERROR: Invalid build target: $BUILD_TARGET" >&2
    exit 1
fi

################################################################################
# Initialization
################################################################################

if [ "$VERBOSE" = true ] ; then
    echo "Initializing $WORK_DIR"
fi

mkdir -p "$WORK_DIR"
cd "$WORK_DIR"

################################################################################
# Build JSS
################################################################################

if [ "$BUILD_TARGET" = "dist" ] ; then

    if [ "$VERBOSE" = true ] ; then
        echo "Building $NAME"
    fi

    OPTIONS=()

    OPTIONS+=(-S "$SRC_DIR")
    OPTIONS+=(-B "$WORK_DIR")

    # Set environment variables for CMake
    # (see /usr/lib/rpm/macros.d/macros.cmake)

    OPTIONS+=(-DCMAKE_C_FLAGS_RELEASE:STRING=-DNDEBUG)
    OPTIONS+=(-DCMAKE_CXX_FLAGS_RELEASE:STRING=-DNDEBUG)
    OPTIONS+=(-DCMAKE_Fortran_FLAGS_RELEASE:STRING=-DNDEBUG)
    OPTIONS+=(-DCMAKE_VERBOSE_MAKEFILE:BOOL=ON)
    OPTIONS+=(-DCMAKE_INSTALL_DO_STRIP:BOOL=OFF)
    OPTIONS+=(-DCMAKE_INSTALL_PREFIX:PATH="$PREFIX_DIR")

    OPTIONS+=(-DINCLUDE_INSTALL_DIR:PATH="$INCLUDE_DIR")
    OPTIONS+=(-DLIB_INSTALL_DIR:PATH="$LIB_DIR")
    OPTIONS+=(-DSYSCONF_INSTALL_DIR:PATH="$SYSCONF_DIR")
    OPTIONS+=(-DSHARE_INSTALL_PREFIX:PATH="$SHARE_DIR")

    OPTIONS+=(-DLIB_SUFFIX=64)
    OPTIONS+=(-DBUILD_SHARED_LIBS:BOOL=ON)

    if [ "$JAVA_HOME" != "" ] ; then
        OPTIONS+=(-DJAVA_HOME="$JAVA_HOME")
    fi

    OPTIONS+=(-DLIB_DIR="$LIB_DIR")
    OPTIONS+=(-DJNI_DIR="$JNI_DIR" )

    OPTIONS+=(-DVERSION="$VERSION")

    if [ "$WITH_JAVA" = false ] ; then
        OPTIONS+=(-DWITH_JAVA=FALSE)
    fi

    if [ "$WITH_NATIVE" = false ] ; then
        OPTIONS+=(-DWITH_NATIVE=FALSE)
    fi

    if [ "$WITH_JAVADOC" = false ] ; then
        OPTIONS+=(-DWITH_JAVADOC=FALSE)
    fi

    if [ "$WITH_TESTS" = false ] ; then
        OPTIONS+=(-DWITH_TESTS=FALSE)
    fi

    $CMAKE "${OPTIONS[@]}"

    OPTIONS=()

    if [ "$VERBOSE" = true ] ; then
        OPTIONS+=(VERBOSE=1)
    fi

    OPTIONS+=(CMAKE_NO_VERBOSE=1)
    OPTIONS+=(--no-print-directory)

    if [ "$WITH_JAVA" = true ] ; then
        make "${OPTIONS[@]}" java
    fi

    if [ "$WITH_NATIVE" = true ] ; then
        make "${OPTIONS[@]}" native
    fi

    if [ "$WITH_JAVADOC" = true ] ; then
        make "${OPTIONS[@]}" javadoc
    fi

    if [ "$WITH_TESTS" = true ] ; then

        OPTIONS=()

        if [ "$VERBOSE" = true ] ; then
            OPTIONS+=(--verbose)
        fi

        OPTIONS+=(--output-on-failure)

        ctest "${OPTIONS[@]}"
    fi

    echo
    echo "Build artifacts:"

    if [ "$WITH_JAVA" = true ] ; then
        echo "- Java binaries:"
        echo "    $WORK_DIR/jss.jar"

        if [ "$WITH_TESTS" = true ] ; then
            echo "    $WORK_DIR/jss-tests.jar"
        fi
    fi

    if [ "$WITH_NATIVE" = true ] ; then
        echo "- native binaries:"
        echo "    $WORK_DIR/libjss.so"
        echo "    $WORK_DIR/symkey/libjss-symkey.so"
        echo "    $WORK_DIR/tools/src/main/native/p12tool/p12tool"
        echo "    $WORK_DIR/tools/src/main/native/p7tool/p7tool"
        echo "    $WORK_DIR/tools/src/main/native/sslget/sslget"
    fi

    if [ "$WITH_JAVADOC" = true ] ; then
        echo "- documentation:"
        echo "    $WORK_DIR/docs"
    fi

    echo
    echo "To install the build: $0 install"
    echo "To create RPM packages: $0 rpm"
    echo

    exit
fi

################################################################################
# Install JSS
################################################################################

if [ "$BUILD_TARGET" = "install" ] ; then

    if [ "$VERBOSE" = true ] ; then
        echo "Installing $NAME"
    fi

    OPTIONS=()

    if [ "$VERBOSE" = true ] ; then
        OPTIONS+=(VERBOSE=1)
    fi

    OPTIONS+=(CMAKE_NO_VERBOSE=1)
    OPTIONS+=(DESTDIR="$INSTALL_DIR")
    OPTIONS+=(INSTALL="install -p")
    OPTIONS+=(--no-print-directory)

    make "${OPTIONS[@]}" install

    exit
fi

################################################################################
# Prepare RPM build
################################################################################

if [ "$VERSION" = "" ] ; then
    # if version not specified, get from spec template
    VERSION="$(rpmspec -P "$SPEC_TEMPLATE" | grep "^Version:" | awk '{print $2;}')"
fi

if [ "$DEBUG" = true ] ; then
    echo "VERSION: $VERSION"
fi

if [ "$RELEASE" = "" ] ; then
    # if release not specified, get from spec template
    RELEASE="$(rpmspec -P "$SPEC_TEMPLATE" --undefine dist | grep "^Release:" | awk '{print $2;}')"
fi

if [ "$DEBUG" = true ] ; then
    echo "RELEASE: $RELEASE"
fi

spec=$(<"$SPEC_TEMPLATE")

regex=$'%global *phase *([^\n]+)'
if [[ $spec =~ $regex ]] ; then
    PHASE="${BASH_REMATCH[1]}"
    RELEASE=$RELEASE.$PHASE
fi

if [ "$DEBUG" = true ] ; then
    echo "PHASE: $PHASE"
fi

if [ "$WITH_TIMESTAMP" = true ] ; then
    TIMESTAMP=$(date -u +"%Y%m%d%H%M%S%Z")
    RELEASE=$RELEASE.$TIMESTAMP
fi

if [ "$DEBUG" = true ] ; then
    echo "TIMESTAMP: $TIMESTAMP"
fi

if [ "$WITH_COMMIT_ID" = true ]; then
    COMMIT_ID=$(git -C "$SRC_DIR" rev-parse --short=8 HEAD)
    RELEASE=$RELEASE.$COMMIT_ID
fi

if [ "$DEBUG" = true ] ; then
    echo "COMMIT_ID: $COMMIT_ID"
fi

echo "Building $NAME-$VERSION-$RELEASE"

rm -rf BUILD
rm -rf RPMS
rm -rf SOURCES
rm -rf SPECS
rm -rf SRPMS

mkdir BUILD
mkdir RPMS
mkdir SOURCES
mkdir SPECS
mkdir SRPMS

################################################################################
# Generate RPM sources
################################################################################

generate_rpm_sources

echo "RPM sources:"
find "$WORK_DIR/SOURCES" -type f -printf " %p\\n"

if [ "$BUILD_TARGET" = "src" ] ; then
    exit
fi

################################################################################
# Generate RPM spec
################################################################################

generate_rpm_spec

echo "RPM spec:"
find "$WORK_DIR/SPECS" -type f -printf " %p\\n"

if [ "$BUILD_TARGET" = "spec" ] ; then
    exit
fi

################################################################################
# Build source package
################################################################################

OPTIONS=()

OPTIONS+=(--quiet)
OPTIONS+=(--define "_topdir ${WORK_DIR}")

if [ "$DIST" != "" ] ; then
    OPTIONS+=(--define "dist .$DIST")
fi

if [ "$DEBUG" = true ] ; then
    echo rpmbuild -bs "${OPTIONS[@]}" "$SPEC_FILE"
fi

# build SRPM with user-provided options
rpmbuild -bs "${OPTIONS[@]}" "$SPEC_FILE"

rc=$?

if [ $rc != 0 ]; then
    echo "ERROR: Unable to build SRPM package"
    exit 1
fi

SRPM="$(find "$WORK_DIR/SRPMS" -type f)"

echo "SRPM package:"
echo " $SRPM"

if [ "$BUILD_TARGET" = "srpm" ] ; then
    exit
fi

################################################################################
# Build binary packages
################################################################################

OPTIONS=()

if [ "$VERBOSE" = true ] ; then
    OPTIONS+=(--define "_verbose 1")
fi

OPTIONS+=(--define "_topdir ${WORK_DIR}")

if [ "$DEBUG" = true ] ; then
    echo rpmbuild --rebuild "${OPTIONS[@]}" "$SRPM"
fi

# rebuild RPM with hard-coded options in SRPM
rpmbuild --rebuild "${OPTIONS[@]}" "$SRPM"

rc=$?

if [ $rc != 0 ]; then
    echo "ERROR: Unable to build RPM packages"
    exit 1
fi

# install SRPM to restore sources and spec file removed during rebuild
rpm -i --define "_topdir $WORK_DIR" "$SRPM"

# flatten folder
find "$WORK_DIR/RPMS" -mindepth 2 -type f -exec mv -i '{}' "$WORK_DIR/RPMS" ';'

# remove empty subfolders
find "$WORK_DIR/RPMS" -mindepth 1 -type d -delete

echo "RPM packages:"
find "$WORK_DIR/RPMS" -type f -printf " %p\\n"
