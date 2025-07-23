#!/bin/bash
# Script to produce an OS X installer .pkg
# This script has to be run from the source directory

if [ "$#" -ne 5 ]; then
    echo "This script unzips the bianries and packages them into a .pkg MacOS installer. This script should be run from the main project directory"
    echo ""
    echo "      Usage: ./make_installer.sh <amd|armn> <SO VERSION> <RELEASE VERSION> <UNSIGNED BINARIES> <LICENSE>"
    echo ""
    echo "The unsiged binaries are expected to be in a directory containing the structure 'usr/local/...'.\n"
    echo "The license file is expected to be a plain text file. It is the file 'COPYING' under the main project directory.\n"
    echo "IMPORTANT: distribution.xml file must be in the same location as this script"
    exit 0
fi

ARCH=$1 # amd or arm
SO_VERSION=$2
RELEASE_VERSION=$3
BIN_DIR=$4 #path to unsigned binaries containing "usr/local/..."
LICENSE_FILE=$5 #path to the license file

echo "ARCH: $ARCH"
echo "Release version : $RELEASE_VERSION"
echo "Binaries: $BIN_DIR"
echo "Working directory: $PWD"
read -p "Press Enter to continue"

set -x

MAC_DIR=$PWD
PKG_DIR=$MAC_DIR/pkg_$ARCH
mkdir -p $PKG_DIR/root $PKG_DIR/comp $PKG_DIR/resources/English.lproj
cp -r $BIN_DIR/* $PKG_DIR/root

# Fix symbolic links
echo "Fixing symbolic links"
cd $PKG_DIR/root/usr/local/lib
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
read -p "Press Enter to continue"

# Checking files's paths
echo "\nChecking binary files' paths using 'otool -L FILE' and 'otool -l FILE'\n"

otool -L lib/libcrypto.dylib
read -p "Press Enter to continue"
otool -L lib/libz.1..dylib
read -p "Press Enter to continue"
otool -L lib/libcrypto.dylib
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
codesign -f --timestamp --options runtime --sign 'Application' lib/libusb-1.0.0.dylib
codesign -f --timestamp --options runtime --sign 'Application' lib/libz-1.dylib
codesign -f --timestamp --options runtime --sign 'Application' lib/libykpiv.$RELEASE_VERSION.dylib
codesign -f --timestamp --options runtime --sign 'Application' lib/libykcs11.$RELEASE_VERSION.dylib
codesign -f --timestamp --options runtime --sign 'Application' bin/yubico-piv-tool
echo "\nDO NOW: Remove signing key"
read -p "Press Enter to continue"

# Verify signature
codesign -dv --verbose=4 lib/libcrypto.3.dylib
read -p "Press Enter to continue"
codesign -dv --verbose=4 lib/libusb-1.0.0.dylib
read -p "Press Enter to continue"
codesign -dv --verbose=4 lib/libz.1.dylib
read -p "Press Enter to continue"
codesign -dv --verbose=4 lib/libykpiv.dylib
read -p "Press Enter to continue"
codesign -dv --verbose=4 lib/libykcs11.dylib
read -p "Press Enter to continue"
codesign -dv --verbose=4 bin/yubico-piv-tool
read -p "Press Enter to continue"

# Include licenses
echo "\nDO NOW: Make sure that there exists share/licenses/yubico-piv-tool directory and it includes licenses for yubico-piv-tool, OpenSSL, zlib"
read -p "Press Enter to continue"

asciidoctor -o $PKG_DIR/resources/English.lproj/license.html $LICENSE_FILE

# Made installer
cd $MAC_DIR
pkgbuild --root=$PKG_DIR/root --identifier "com.yubico.yubico-piv-tool" $PKG_DIR/comp/yubico-piv-tool.pkg
productbuild  --package-path $PKG_DIR/comp/yubico-piv-tool.pkg --distribution distribution.xml --resources $PKG_DIR/resources yubico-piv-tool-$RELEASE_VERSION-mac-$ARCH.pkg

read -p "DO NOW: Insert signing key then press Enter to continue"
productsign --sign 'Installer' yubico-piv-tool-$RELEASE_VERSION-mac-$ARCH.pkg yubico-piv-tool-$RELEASE_VERSION-mac-$ARCH-signed.pkg
echo "\nDO NOW: Remove signing key"

set +x