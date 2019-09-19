#!/bin/bash

# This script reads the contents of the OS CA bundle store,
#   /usr/share/pki/ca-trust-source/ca-bundle.trust.p11-kit
# and places the contained CAs into the specified NSS DB.
#
# This NSS DB is used by various JSS tests that aren't enabled
# by default because they require an active internet connection.

nssdb="$1"

if [ -z "$nssdb" ] && [ -e "build" ]; then
    nssdb="build/results/cadb"
elif [ -z "$nssdb" ] && [ -e "../build" ]; then
    nssdb="../build/results/cadb"
elif [ -z "$nssdb" ] || [ "x$nssdb" == "x--help" ]; then
    echo "Usage: $0 [/path/to/nssdb]" 1>&2
    echo "" 1>&2
    echo "Must provide path to NSS DB!" 1>&2
    exit 1
fi

if [ -e "$nssdb" ]; then
    rm -rf "$nssdb"
fi

mkdir -p "$nssdb"
echo "" > "$nssdb/password.txt"
certutil -N -d "$nssdb" -f "$nssdb/password.txt"

trust extract --format=pem-bundle  --filter=ca-anchors "$nssdb/complete.pem"

# From: https://serverfault.com/questions/391396/how-to-split-a-pem-file
csplit -f "$nssdb/individual-" "$nssdb/complete.pem" '/-----BEGIN CERTIFICATE-----/' '{*}'

for cert in "$nssdb"/individual*; do
    certutil -A -a -i "$cert" -n "$cert" -t CT,C,C -d "$nssdb" -f "$nssdb/password.txt"
done
