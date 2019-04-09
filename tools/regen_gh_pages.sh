#!/bin/bash

function _e() {
    if [ ! -z "$VERBOSE" ]; then
        echo cd "$(pwd)" '&&' "$@" 1>&2
    fi

    local command="$1"
    shift

    "$command" "$@"
}

function main() {(
    set -e

    local user="$1"
    local remote="https://github.com/$user/jss"
    local upstream="https://github.com/dogtagpki/jss"
    local sandbox="/tmp/jss-docs-sandbox"

    if [ -z "$user" ]; then
        echo "Usage: update-gh-pages.sh <username>"
        echo "Update the user's gh-pages branch with the latest javadocs content."
        return 1
    fi

    _e rm -rf "$sandbox"
    _e mkdir -p "$sandbox"
    pushd "$sandbox"
        _e git clone "$remote" jss
        cd jss/build
        _e git remote add upstream "$upstream"
        _e git fetch --all
        _e git checkout "upstream/master"

        # Build Javadoc only
        _e cmake ..
        _e make javadoc

        # Preserve javadoc
        _e cp -rv docs "$sandbox/docs"

        # Update javadocs
        cd ../
        _e git clean -xdf
        _e git checkout "upstream/gh-pages"
        _e git branch -D "gh-pages" || true
        _e git checkout -b "gh-pages"
        _e rm -rf javadoc
        _e cp -rv "$sandbox/docs" javadoc
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
