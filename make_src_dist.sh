#!/bin/bash
# Script to produce an OS X installer .pkg
# This script has to be run from the source directory

VERSION=$1 # Full yubico-piv-tool version, tex 2.1.0

mkdir dist_build; cd dist_build
cmake ..
make
cd ..
rm -r dist_build
tar --exclude README.adoc --exclude .git --exclude .github --exclude .gitignore --transform="s/^\./yubico-piv-tool-$VERSION/" -czf yubico-piv-tool-$VERSION.tar.gz .
