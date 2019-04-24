#!/bin/bash

function _e() {
    if [ ! -z "$VERBOSE" ]; then
        echo cd "$(pwd)" '&&' "$@" 1>&2
    fi

    local command="$1"
    shift

    "$command" "$@"
}

function build_javadoc() {
    local output_dir="$1"

    if [ -e CMakeLists.txt ]; then
        # Build Javadoc only
        pushd build
            _e cmake ..
            _e make javadoc

            # Preserve javadoc
            _e cp -rv docs "$output_dir"
        popd # build
    else
        local work_dir="/tmp/jss-docs-build"

        _e rm -rf "$work_dir"
        _e mkdir -p "$work_dir"

        # Build the RPMs; easiest way to build the javadocs
        _e bash ./build.sh --work-dir="$work_dir" rpm

        # Extract the javadocs
        pushd "$work_dir/RPMS"
            _e rpm2cpio jss-javadoc*.rpm > javadoc.cpio
            _e cpio -idv < javadoc.cpio
            _e cp -rv ./usr/share/javadoc/jss* "$output_dir"
        popd # "$work_dir"

        rm -rf "$work_dir"
    fi
}

function build_doc() {
    local output_dir="$1"

    if [ -e docs/ ]; then
        _e cp -rv docs "$output_dir"
    fi
}

function clean_checkout() {
    local branch="$1"

    _e git clean -xdf
    _e git checkout "$branch"
}

function main() {(
    set -e

    local user="$1"
    local remote="https://github.com/$user/jss"
    local upstream="https://github.com/dogtagpki/jss"

    local sandbox="/tmp/jss-docs-sandbox"
    local artifacts="/tmp/jss-docs-artifacts"

    if [ -z "$user" ]; then
        echo "Usage: update-gh-pages.sh <username>"
        echo "Update the user's gh-pages branch with the latest javadocs content."
        return 1
    fi

    # Start with a fresh environment each time.
    _e rm -rf "$sandbox" "$artifacts"
    _e mkdir -p "$sandbox"
    _e mkdir -p "$artifacts"

    pushd "$sandbox"
        _e git clone "$remote" jss
        cd jss
        _e git remote add upstream "$upstream"
        _e git fetch --all

        # Build docs for master branch
        clean_checkout "upstream/master"
        build_javadoc "$artifacts/javadocs-master"
        build_doc "$artifacts/docs-master"

        # Build docs for the v4.5.x branch
        clean_checkout "upstream/v4.5.x"
        build_javadoc "$artifacts/javadocs-v4.5.x"
        build_doc "$artifacts/docs-v4.5.x"

        # Build docs for the v4.4.x branch
        clean_checkout "upstream/v4.4.x"
        build_javadoc "$artifacts/javadocs-v4.4.x"
        build_doc "$artifacts/docs-v4.4.x"

        # Get to the gh-pages branch, in a clean state
        clean_checkout "upstream/gh-pages"
        _e git branch -D "gh-pages" || true
        _e git checkout -b "gh-pages"
        _e rm -rf javadoc master/javadocs master/docs v4.5.x/javadocs v4.5.x/docs v4.4.x/javadocs v4.4.x/docs

        # Preserve new changes
        _e mkdir -p master v4.5.x v4.4.x || true
        _e cp -rv "$artifacts/javadocs-master" master/javadocs || true
        _e cp -rv "$artifacts/docs-master" master/docs || true
        _e cp -rv "$artifacts/javadocs-v4.5.x" v4.5.x/javadocs || true
        _e cp -rv "$artifacts/docs-v4.5.x" v4.5.x/docs || true
        _e cp -rv "$artifacts/javadocs-v4.4.x" v4.4.x/javadocs || true
        _e cp -rv "$artifacts/docs-v4.4.x" v4.4.x/docs || true

        # Track all of our new changes
        _e git add --all
        _e git commit -m "Update javadocs from master at $(date '+%Y-%m-%d %H:%M')"
        _e git push --set-upstream origin gh-pages --force
    popd # "$sandbox"

    _e rm -rf "$sandbox"

    echo ""
    echo ""
    echo "All done! To open a PR, click the following link:"
    echo "$upstream/compare/gh-pages...$user:gh-pages"
)}

main "$@"
