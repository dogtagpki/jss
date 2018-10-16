#!/bin/sh
set -e

#
# Usage:
# test_perl_style.sh [path]
#
# Tests the style of Perl scripts in the build tree for compliance with strict
# guidance. Runs:
#
#     perl -Mstrict -Mdiagnostics -cw <file>
#
# On all checked files. If [path] is specified, assumed to be the root of the
# jss repository. Otherwise, defaults to `pwd`.
#

root_source_dir="$1"
if [ "x$root_source_dir" = "x" ]; then
    root_source_dir="$(pwd)"
fi

perl_check() {
    target_file="$1"

    perl -Mstrict -Mdiagnostics -cw "$root_source_dir/$target_file"
}


perl_check "build_java.pl"
perl_check "lib/Common.pm"
perl_check "org/mozilla/jss/tests/all.pl"
