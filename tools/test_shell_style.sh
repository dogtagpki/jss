#!/bin/sh
set -e

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

    shellcheck -x "$root_source_dir/$target_file"
    if [ ! -x "$root_source_dir/$target_file" ]; then
        echo "$root_source_dir/$target_file must be executable!"
        return 1
    fi
    echo "$root_source_dir/$target_file OK"
}


shell_check "build.sh"
shell_check "tools/autoenv.sh"
shell_check "tools/reproducible_jar.sh"
shell_check "tools/run_container.sh"
shell_check "tools/test_python_style.sh"
shell_check "tools/test_shell_style.sh"
