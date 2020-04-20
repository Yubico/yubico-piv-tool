#!/bin/bash
# Script to produce an OS X installer .pkg
# This script has to be run from the source directory

PACKAGE=yubico-piv-tool
VERSION=$1
OPENSSLVERSION=1.0.2u
CFLAGS="-mmacosx-version-min=10.6"

SOURCE_DIR=$PWD
MAC_DIR=$SOURCE_DIR/macos
PKG_DIR=$MAC_DIR/pkgtmp
INSTALL_DIR=$PKG_DIR/install
BUILD_DIR=$PKG_DIR/build
LICENSE_DIR=$PKG_DIR/licenses

# Create missing directories
rm -rf $PKG_DIR
mkdir -p $PKG_DIR $INSTALL_DIR $BUILD_DIR $LICENSE_DIR

cd $PKG_DIR

# Download openssl if it's not already in this directory
if [ ! -f $MAC_DIR/openssl-$OPENSSLVERSION.tar.gz ]
then
  curl -L -O "https://www.openssl.org/source/openssl-$OPENSSLVERSION.tar.gz"
else
  echo Using already existing openssl-$OPENSSLVERSION.tar.gz
fi

# unpack and install openssl into its remporary root
tar xfz openssl-$OPENSSLVERSION.tar.gz
cd openssl-$OPENSSLVERSION
./Configure darwin64-x86_64-cc shared no-ssl2 no-ssl3 --prefix=$INSTALL_DIR $CFLAGS
make all install_sw VERSION="$OPENSSLVERSION"

# Copy the OpenSSL license to include it in the installer
cp LICENSE $LICENSE_DIR/openssl.txt

# Removed unused OpenSSL files
rm -rf $INSTALL_DIR/ssl
rm -rf $INSTALL_DIR/bin
rm -rf $INSTALL_DIR/lib/engines
rm -rf $INSTALL_DIR/lib/libssl*
rm $INSTALL_DIR/lib/pkgconfig/libssl.pc
rm $INSTALL_DIR/lib/pkgconfig/openssl.pc

# Build yubico-piv-tool and install it in $INSTALL_DIR
cd $BUILD_DIR
export PKG_CONFIG_PATH=$INSTALL_DIR/lib/pkgconfig
env CFLAGS=$CFLAGS cmake $SOURCE_DIR -DVERBOSE_CMAKE=ON -DENABLE_GCC_WARN=ON -DRELEASE_BUILD=1
make
env DESTDIR="$INSTALL_DIR" make install;

# Fix paths
chmod u+w $INSTALL_DIR/lib/libcrypto.1.0.0.dylib
install_name_tool -id @loader_path/libcrypto.1.0.0.dylib $INSTALL_DIR/lib/libcrypto.1.0.0.dylib
install_name_tool -id @loader_path/libykpiv.1.dylib $INSTALL_DIR/lib/libykpiv.1.dylib
install_name_tool -id @loader_path/libykcs11.1.dylib $INSTALL_DIR/lib/libykcs11.1.dylib
install_name_tool -change $INSTALL_DIR/lib/libcrypto.1.0.0.dylib @loader_path/libcrypto.1.0.0.dylib $INSTALL_DIR/lib/libykpiv.1.dylib
install_name_tool -change $INSTALL_DIR/lib/libcrypto.1.0.0.dylib @loader_path/libcrypto.1.0.0.dylib $INSTALL_DIR/lib/libykcs11.1.dylib
install_name_tool -change $INSTALL_DIR/lib/libcrypto.1.0.0.dylib @executable_path/../lib/libcrypto.1.0.0.dylib $INSTALL_DIR/bin/yubico-piv-tool
install_name_tool -change $INSTALL_DIR/lib/libykpiv.1.dylib @loader_path/libykpiv.1.dylib $INSTALL_DIR/lib/libykcs11.1.dylib
install_name_tool -change $INSTALL_DIR/lib/libykpiv.1.dylib @executable_path/../lib/libykpiv.1.dylib $INSTALL_DIR/bin/yubico-piv-tool;
if otool -L $INSTALL_DIR/lib/*.dylib $INSTALL_DIR/bin/* | grep '$INSTALL_DIR' | grep -q compatibility; then
	echo "something is incorrectly linked!";
	exit 1;
fi

# Removed unused files
rm $INSTALL_DIR/lib/*.la
rm -rf $INSTALL_DIR/lib/pkgconfig

# Copy yubico-piv-tool lisense
cp COPYING $LICENSE_DIR/licenses/$PACKAGE.txt

cd INSTALL_DIR
zip -r MAC_DIR/$PACKAGE-$VERSION-mac.zip *