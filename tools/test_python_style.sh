#!/bin/sh
set -e

#
# Usage:
# test_python_style.sh [path]
#
# Tests the style of Python scripts in the build tree for compliance with pylint
# guidance. Runs:
#
#     pylint <file>
#
# On all checked files. If [path] is specified, assumed to be the root of the
# jss repository. Otherwise, defaults to `pwd`.
#

root_source_dir="$1"
if [ "x$root_source_dir" = "x" ]; then
    root_source_dir="$(pwd)"
fi

python_check() {
    target_file="$1"

    pylint "$root_source_dir/$target_file"
}


python_check "tools/build_pkcs11_constants.py"
