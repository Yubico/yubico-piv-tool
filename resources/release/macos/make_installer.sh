#!/bin/bash
# Script to produce an OS X installer .pkg
# This script has to be run from the source directory

if [ "$#" -ne 4 ]; then
    echo "This script is a guide to build a .pkg installer. Output installer will be found in the directory this script is running from."
    echo ""
    echo "      Usage: ./make_installer.sh <amd|arm> <SO VERSION> <RELEASE_VERSION> <BINARIES DIRECTORY>"
    echo "";
    exit 0
fi

set -e -o pipefail

ARCH=$1 # amd or arm
SO_VERSION=$2
RELEASE_VERSION=$3
SRC_DIR=$4 #path to unsigned binaries structured /usr/local/...

echo "ARCH: $ARCH"
echo "Release version: $RELEASE_VERSION"
echo "Binaries: $SRC_DIR"
echo "Current directory: $PWD"
read -p "Press Enter to continue"

MAC_DIR=$PWD
PKG_DIR=$MAC_DIR/pkg_$ARCH

mkdir -p $PKG_DIR/root $PKG_DIR/comp
cp -r resources $PKG_DIR/
cp -r $SRC_DIR/ $PKG_DIR/root/

# Fix symbolic links
echo "Fixing symbolic links"
cd $PKG_DIR/root/usr/local/lib
rm libcrypto.dylib
rm libykpiv.$SO_VERSION.dylib
rm libykpiv.dylib
rm libykcs11.$SO_VERSION.dylib
rm libykcs11.dylib
ln -s libcrypto.3.dylib libcrypto.dylib
ln -s libykpiv.$RELEASE_VERSION.dylib libykpiv.$SO_VERSION.dylib
ln -s libykpiv.$SO_VERSION.dylib libykpiv.dylib
ln -s libykcs11.$RELEASE_VERSION.dylib libykcs11.$SO_VERSION.dylib
ln -s libykcs11.$SO_VERSION.dylib libykcs11.dylib

# Fix file permissions
cd ..
chmod +x bin/*
chmod +x lib/*

ls -l bin
ls -l lib
echo "\nDO NOW: Make sure that the files in bin/ and lib/ directories are correct."
echo "\nThe files in lib/ should include libcrypto*.dylib and libz*.dylib files."
read -p "Press Enter to continue"


echo "\nChecking binary files' paths using 'otool -L FILE' and 'otool -l FILE'"
otool -L lib/libcrypto.dylib
read -p "Press Enter to continue"

otool -L lib/libz.1.dylib
read -p "Press Enter to continue"

otool -L lib/libykpiv.dylib
read -p "Press Enter to continue"

otool -L lib/libykcs11.dylib
otool -l lib/libykcs11.dylib | grep LC_RPATH -A 3
read -p "Press Enter to continue"

otool -L bin/yubico-piv-tool
otool -l bin/yubico-piv-tool | grep LC_RPATH -A 3
read -p "Press Enter to continue"


# Sign binaries
read -p "DO NOW: Insert signing key then press Enter to continue"
codesign -f --timestamp --options runtime --sign 'Application' lib/libcrypto.3.dylib
codesign -f --timestamp --options runtime --sign 'Application' lib/libz.1.dylib
codesign -f --timestamp --options runtime --sign 'Application' lib/libykpiv.$RELEASE_VERSION.dylib
codesign -f --timestamp --options runtime --sign 'Application' lib/libykcs11.$RELEASE_VERSION.dylib
codesign -f --timestamp --options runtime --sign 'Application' bin/yubico-piv-tool
echo "\nDO NOW: Remove signing key"
read -p "Press Enter to continue"

# Verify signature
codesign -dv --verbose=4 lib/libcrypto.dylib
read -p "Press Enter to continue"
codesign -dv --verbose=4 lib/libz.1.dylib
read -p "Press Enter to continue"
codesign -dv --verbose=4 lib/libykpiv.dylib
read -p "Press Enter to continue"
codesign -dv --verbose=4 lib/libykcs11.dylib
read -p "Press Enter to continue"
codesign -dv --verbose=4 bin/yubico-piv-tool
read -p "Press Enter to continue"

ls licenses
echo "\nDO NOW: Make sure that the 'licenses' directory includes licenses for yubico-piv-tool, OpenSSL and libz"
read -p "Press Enter to continue"

cd $MAC_DIR
pkgbuild --root $PKG_DIR/root --identifier "com.yubico.yubico-piv-tool" --version "$RELEASE_VERSION" $PKG_DIR/comp/yubico-piv-tool.pkg
productbuild  --package-path $PKG_DIR/comp --distribution distribution.xml yubico-piv-tool-$RELEASE_VERSION-mac-$ARCH.pkg

read -p "DO NOW: Insert signing key then press Enter to continue"
productsign --sign 'Installer' yubico-piv-tool-$RELEASE_VERSION-mac-$ARCH.pkg yubico-piv-tool-$RELEASE_VERSION-mac-$ARCH-signed.pkg
echo "\nDO NOW: Remove signing key"