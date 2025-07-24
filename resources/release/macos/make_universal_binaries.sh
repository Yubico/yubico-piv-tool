#!/bin/bash

# Script to produce universal binaries for OSX by combining 2 binary sets
if [ "$#" -ne 2 ]; then
    echo "This script combines x86_64 and arm64 binaries into universal binaries for MacOS"
    echo ""
    echo "      Usage: ./make_universal_binaries.sh <path/to/x86_64_binaries> <path/to/arm64_binaries>"
    echo "";
    exit 0
fi

X86_64_PATH=$1
ARM64_PATH=$2
UNIVERSAL_PATH=universal

set -x

mkdir -p universal/usr/local/bin universal/usr/local/lib

for f in $X86_64_PATH/usr/local/bin/*; do
  filename="$(basename $f)"
  lipo -create -output $UNIVERSAL_PATH/usr/local/bin/$filename  $X86_64_PATH/usr/local/bin/$filename $ARM64_PATH/usr/local/bin/$filename
done

for f in $X86_64_PATH/usr/local/lib/*.dylib; do
  filename="$(basename $f)"
  lipo -create -output $UNIVERSAL_PATH/usr/local/lib/$filename $X86_64_PATH/usr/local/lib/$filename $ARM64_PATH/usr/local/lib/$filename
done

cp -r $X86_64_PATH/usr/local/share $UNIVERSAL_PATH/usr/local/
cp -r $X86_64_PATH/usr/local/licenses $UNIVERSAL_PATH/usr/local/
cp -r $X86_64_PATH/usr/local/include $UNIVERSAL_PATH/usr/local/

set +x