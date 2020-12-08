#!/bin/bash
# Script to produce an OS X installer .pkg
# This script has to be run from the source directory

if [ "$#" -ne 2 ]; then
    echo "This script unzips the bianries and packages them into a .pkg MacOS installer. This script should be run from the main project directory"
    echo ""
    echo "      Usage: ./resources/macos/make_installer.sh <Release version> <path to the zip file containing the binaries>"
    echo ""
    exit 0
fi

RELEASE_VERSION=$1
SRC_ZIP=$2

echo "Release version : $RELEASE_VERSION"
echo "Binaries: $SRC_ZIP"
echo "Working directory: $PWD"

set -x

SOURCE_DIR=$PWD
MAC_DIR=$SOURCE_DIR/resources/macos
PKG_DIR=$MAC_DIR/pkg
PKG_ROOT=$PKG_DIR/root
PKG_COMP=$PKG_DIR/comp


INSTALL_DIR=$PKG_DIR/install
FINAL_INSTALL_DIR=$INSTALL_DIR/$CMAKE_INSTALL_PREFIX
BUILD_DIR=$PKG_DIR/build
LICENSE_DIR=$PKG_DIR/licenses

cd $MAC_DIR
mkdir -p $PKG_ROOT $PKG_COMP
unzip $SRC_ZIP -d $PKG_ROOT/

pkgbuild --root="$PKG_ROOT" --identifier "com.yubico.yubico-piv-tool" --version "$RELEASE_VERSION" "$PKG_COMP/yubico-piv-tool.pkg"

productbuild  --package-path "$PKG_COMP" --distribution "$MAC_DIR/distribution.xml" "$MAC_DIR/yubico-piv-tool-$RELEASE_VERSION.pkg"