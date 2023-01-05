#!/bin/bash -e

# Use this script to automate updating pki version.
#
# Usage: ./update_version.sh <major> <minor> <update> <phase> # (phase is optional)
#
# Explanation:
# -    change_spec_version
# -        Updates the spec version to the new version provided
# -    commit_version_change
# -        Commits that change
# -    create_tag
# -        Creates a tag based on the new version provided
# -    create_source_tarball
# -        Creates a source tarball based on the new version provided

NEXT_MAJOR=$1
NEXT_MINOR=$2
NEXT_UPDATE=$3
NEXT_PHASE=$4

NEXT_VERSION=$NEXT_MAJOR.$NEXT_MINOR.$NEXT_UPDATE
if [ -z "$NEXT_PHASE" ] ; then
    NEXT_VERSION_PHASE=$NEXT_VERSION
else
    NEXT_VERSION_PHASE=$NEXT_VERSION-$NEXT_PHASE
fi
echo "New version is $NEXT_VERSION_PHASE"

verify_phase() {
    if [[ "$NEXT_PHASE" =~ ^(alpha|beta)[0-9]+$ ]] ; then
        echo "$NEXT_PHASE is a valid phase"
    elif [ -z "$NEXT_PHASE" ] ; then
        echo "Empty phase"
    else
        echo "$NEXT_PHASE is an invalid phase, aborting"
        exit 1
    fi
}

change_spec_version() {
    CURRENT_VERSION=$(grep "Version: " jss.spec | grep -Eo '[0-9]+(\.[0-9]+)?(\.[0-9]+)?$')
    CURRENT_PHASE=$(grep "_phase " jss.spec | grep -E 'alpha|beta' | awk '{print $(NF)}')
    CURRENT_RELEASE_NUMBER=$(grep "release_number " jss.spec | grep -Eo '[0-9]+(\.[0-9]+)?$')

    echo "Update version to $NEXT_VERSION"
    sed -i "/Version:        /cVersion:        $NEXT_VERSION" jss.spec

    if [[ "$CURRENT_PHASE" != "$NEXT_PHASE" ]] ; then
        if [ -z "$NEXT_PHASE" ] ; then
            echo "Remove phase"
            sed -i "/_phase /c\#global         _phase" jss.spec
            echo "Update release_number"
            sed -i "/release_number /c\%global         release_number 1" jss.spec
        elif [ -z "$CURRENT_PHASE" ] ; then
            echo "Add phase, set to $NEXT_PHASE"
            sed -i "/#global         _phase/c\%global         _phase -$NEXT_PHASE" jss.spec
            echo "Update release_number"
            sed -i "/release_number /c\%global         release_number 0.1" jss.spec
        else
            echo "Update phase to $NEXT_PHASE"
            sed -i "/_phase /c\%global         _phase -$NEXT_PHASE" jss.spec
            echo "Update release_number"
            IFS='.' read -ra CRL <<< "$CURRENT_RELEASE_NUMBER"
            (( CRL[1]++ ))
            sed -i "/release_number /c\%global         release_number ${CRL[0]}.${CRL[1]}" jss.spec
        fi
    fi
}

change_jss_config_version() {
    if [ "$NEXT_PHASE" ] ; then
        IS_BETA="1"
    else
        IS_BETA="0"
    fi
    JSS_CONFIG_VERSION="$NEXT_MAJOR $NEXT_MINOR $NEXT_UPDATE $IS_BETA"
    echo "Updating jss_config_version to $JSS_CONFIG_VERSION"
    sed -i "/ jss_config_version/c\    jss_config_version($JSS_CONFIG_VERSION)" cmake/JSSConfig.cmake
}

commit_version_change() {
    git add jss.spec cmake/JSSConfig.cmake
    git commit -m "Updating version to v$NEXT_VERSION_PHASE"
}

create_tag() {
    git tag v"$NEXT_VERSION_PHASE"
}

create_source_tarball() {
    ./build.sh --source-tag=v"$NEXT_VERSION_PHASE" src
}

### Perform operations

verify_phase
change_spec_version
change_jss_config_version
commit_version_change
create_tag
create_source_tarball
