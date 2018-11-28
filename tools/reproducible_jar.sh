#!/bin/bash

# A shell script to create a reproducible jar distirbution for JSS.
#
# This will extract the created JSS build and normalize timestamp and file
# insertion order. This will help to ensure that anyone building in the same
# environment will receive the same jar file assuming the contents of Java
# haven't changed.
#
# Usage:
#   reproducible_jar.sh /path/to/input.jar /path/to/tmp/dir /path/to/output.jar

set -e

function extract() {
    local jar="$1"
    local path="$2"

    if [ -d "$path" ]; then
        rm -rf "$path"
    fi

    mkdir -p "$path"
    unzip -q "$jar" -d "$path"
}

function normalize_timestamps() {
    local path="$1"
    find "$path" -exec touch -t 201801010000 {} +
}

function add_manifest() {
    local path="$1"
    local output="$2"

    pushd "$path" >/dev/null
        zip -X -q "$output" "META-INF"
        zip -X -q "$output" "META-INF/MANIFEST.MF"
    popd >/dev/null
}

function add_classes() {
    local path="$1"
    local output="$2"

    pushd "$path" >/dev/null
        for file in $(find "org" | sort); do
            zip -X -q "$output" "$file"
        done
    popd >/dev/null
}

abs_jar="$(realpath "$1")"
abs_path="$(realpath "$2")"
abs_output="$(realpath "$3")"

extract "$abs_jar" "$abs_path"
normalize_timestamps "$abs_path"
add_manifest "$abs_path" "$abs_output"
add_classes "$abs_path" "$abs_output"
