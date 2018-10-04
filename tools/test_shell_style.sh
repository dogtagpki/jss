#!/bin/sh

#
# Usage:
# test_shell_style.sh [path]
#
# Tests the style of shell scripts in the build tree for compliance with strict
# guidance. Runs:
#
#     `shellcheck <file>`
#
# On all checked files. If [path] is specified, assumed to be the root of the
# jss repository. Otherwise, defaults to `pwd`.
#

root_source_dir="$1"
if [ "x$root_source_dir" = "x" ]; then
    root_source_dir="$(pwd)"
fi

shell_check() {
    target_file="$1"

    shellcheck "$root_source_dir/$target_file"
}


shell_check "build.sh"
shell_check "tools/test_perl_style.sh"
shell_check "tools/test_shell_style.sh"
