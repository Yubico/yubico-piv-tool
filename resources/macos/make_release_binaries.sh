#!/bin/bash
# Script to produce an OS X binaries
# This script has to be run from the source directory
if [ "$#" -ne 4 ]; then
    echo "This script build the binaries to be installed on a MacOS. This script should be run from the main project directory"
    echo ""
    echo "      Usage: ./resources/macos/make_release_binaries.sh <Arch> <Release version> <SO version> <Value of CMAKE_INSTALL_PREFIX>"
    echo ""
    echo "Arch                          : 'amd' or 'arm'"
    echo "Release version               : Full yubico-piv-tool version, tex 2.1.0"
    echo "SO version                    : The version of the ykpiv library, tex 2"
    echo "Value of CMAKE_INSTALL_PREFIX : The value of the CMAKE_INSTALL_PREFIX, tex /usr/local. Can be displayed by running 'cmake -L | grep CMAKE_INSTALL_PREFIX'"
    exit 0
fi

ARCH = $1
VERSION=$2 # Full yubico-piv-tool version, tex 2.1.0
SO_VERSION=$3
CMAKE_INSTALL_PREFIX=$4 # The value of the CMAKE_INSTALL_PREFIX, tex /usr/local. Can be displayed by running "cmake -L | grep CMAKE_INSTALL_PREFIX"

echo "Release version : $VERSION"
echo "SO version: $SO_VERSION"
echo "CMAKE_INSTALL_PREFIX: $CMAKE_INSTALL_PREFIX"
echo "Working directory: $PWD"

set -x

if [ "$ARCH" == "amd" ]; then
  BREW_LIB="/usr/local/opt"
  #BREW_CELLAR="/usr/local/Cellar"
elif [ "$ARCH" == "arm" ]; then
  BREW_LIB="/opt/homebrew/opt"
  #BREW_CELLAR="/opt/homebrew/Cellar"
else
  echo "Unknown architecture"
  exit
fi

PACKAGE=yubico-piv-tool
CFLAGS="-mmacosx-version-min=10.6"

SOURCE_DIR=$PWD
MAC_DIR=$SOURCE_DIR/resources/macos
PKG_DIR=$MAC_DIR/pkgtmp
INSTALL_DIR=$PKG_DIR/install
FINAL_INSTALL_DIR=$INSTALL_DIR/$CMAKE_INSTALL_PREFIX
BUILD_DIR=$PKG_DIR/build
LICENSE_DIR=$PKG_DIR/licenses


# Create missing directories
rm -rf $PKG_DIR
mkdir -p $PKG_DIR $INSTALL_DIR $BUILD_DIR $LICENSE_DIR $FINAL_INSTALL_DIR

export LIBRARY_PATH="$LIBRARY_PATH:/opt/homebrew/Cellar/openssl@3/3.3.0/lib"
export PATH="$PATH:/opt/homebrew/Cellar/openssl@3/3.3.0/bin"


ls /opt/homebrew/Cellar


# Build yubico-piv-tool and install it in $INSTALL_DIR
cd $BUILD_DIR
CFLAGS=$CFLAGS PKG_CONFIG_PATH=$BREW_LIB/openssl/lib/pkgconfig cmake $SOURCE_DIR -DCMAKE_BUILD_TYPE=Release
make
env DESTDIR="$INSTALL_DIR" make install;

cp "/opt/homebrew/Cellar/openssl@3/3.3.0/lib/libcrypto.3.dylib" "$FINAL_INSTALL_DIR/lib"
chmod +w "$FINAL_INSTALL_DIR/lib/libcrypto.3.dylib"
cp -r /opt/homebrew/Cellar/openssl@3/3.3.0/include/openssl "$FINAL_INSTALL_DIR/include"

cp "$BREW_LIB/zlib/lib/libz.1.dylib" "$FINAL_INSTALL_DIR/lib"
chmod +w "$FINAL_INSTALL_DIR/lib/libz.1.dylib"
cp -r $BREW_LIB/zlib/include/zlib.h "$FINAL_INSTALL_DIR/include"

# Fix paths
install_name_tool -id "@loader_path/../lib/libcrypto.3.dylib" "$FINAL_INSTALL_DIR/lib/libcrypto.3.dylib"
install_name_tool -id "@loader_path/../lib/libz.1.dylib" "$FINAL_INSTALL_DIR/lib/libz.1.dylib"

install_name_tool -change $BREW_LIB/openssl@3/lib/libcrypto.3.dylib @loader_path/../lib/libcrypto.3.dylib $FINAL_INSTALL_DIR/lib/libykpiv.$VERSION.dylib
install_name_tool -change $BREW_LIB/openssl@3/lib/libcrypto.3.dylib @loader_path/../lib/libcrypto.3.dylib $FINAL_INSTALL_DIR/lib/libykcs11.$VERSION.dylib
install_name_tool -change $BREW_LIB/openssl@3/lib/libcrypto.3.dylib @loader_path/../lib/libcrypto.3.dylib $FINAL_INSTALL_DIR/bin/yubico-piv-tool

install_name_tool -change /usr/lib/libz.1.dylib @loader_path/../lib/libz.1.dylib $FINAL_INSTALL_DIR/lib/libykcs11.$VERSION.dylib
install_name_tool -change /usr/lib/libz.1.dylib @loader_path/../lib/libz.1.dylib $FINAL_INSTALL_DIR/lib/libykpiv.$VERSION.dylib
install_name_tool -change /usr/lib/libz.1.dylib @loader_path/../lib/libz.1.dylib $FINAL_INSTALL_DIR/bin/yubico-piv-tool

install_name_tool -rpath "/usr/local/lib" "@loader_path/../lib" "$FINAL_INSTALL_DIR/lib/libykcs11.$VERSION.dylib"
install_name_tool -rpath "/usr/local/lib" "@loader_path/../lib" "$FINAL_INSTALL_DIR/lib/libykpiv.$VERSION.dylib"
install_name_tool -rpath "/usr/local/lib" "@loader_path/../lib" "$FINAL_INSTALL_DIR/bin/yubico-piv-tool"

if otool -L $FINAL_INSTALL_DIR/lib/*.dylib $FINAL_INSTALL_DIR/bin/* | grep '$FINAL_INSTALL_DIR' | grep -q compatibility; then
	echo "something is incorrectly linked!";
	exit 1;
fi

# Copy yubico-piv-tool license and move the whole lisenses directory under FINALINSTALL_DIR.
cd $SOURCE_DIR
cp COPYING $LICENSE_DIR/$PACKAGE.txt
cp $BREW_LIB/zlib/LICENSE $LICENSE_DIR/zlib.txt
mv $LICENSE_DIR $FINAL_INSTALL_DIR/

cd $INSTALL_DIR
zip -r $MAC_DIR/$PACKAGE-$VERSION-mac-$ARCH.zip .

cd $MAC_DIR
rm -rf $PKG_DIR