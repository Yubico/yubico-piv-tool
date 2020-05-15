#!/bin/bash
# Script to produce the source distribution package

VERSION=$1 # Full yubico-piv-tool version, tex 2.1.0

mkdir dist_build; cd dist_build
cmake ..
make
cd ..
rm -r dist_build

set +e

tar --exclude README.adoc --exclude .git --exclude .github --exclude .gitignore --transform="s/^\./yubico-piv-tool-$VERSION/" -czf yubico-piv-tool-$VERSION.tar.gz .
exitcode=$?
if [ "$exitcode" != "1" ] && [ "$exitcode" != "0" ]; then
    exit $exitcode
fi

set -e