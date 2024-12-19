#!/bin/bash
# Script to produce the source distribution package

if [ "$#" -ne 1 ]; then
    echo "Script to produce the source distribution package. If no version is specified, a source package will be built without a version number"
    echo ""
    echo "      Usage: ./make_src_dist.sh [<Release version>]"
    echo ""
fi

VERSION=$1 # Full yubico-piv-tool version, tex 2.1.0

mkdir dist_build; cd dist_build
cmake ..
make
cd ..
rm -r dist_build

set +e
set -x

tar --exclude README.adoc --exclude .git --exclude .github --exclude --exclude .gitignore --transform="s/^\./yubico-piv-tool-$VERSION/" -czf yubico-piv-tool-$VERSION.tar.gz .
exitcode=$?
if [ "$exitcode" != "1" ] && [ "$exitcode" != "0" ]; then
    exit $exitcode
fi

set -e