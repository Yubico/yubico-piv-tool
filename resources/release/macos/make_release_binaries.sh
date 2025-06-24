#!/bin/bash
# Script to produce an OS X binaries
# This script has to be run from the source directory
echo $#
if [ "$#" -ne 5 ]; then
    echo "This script build the binaries to be installed on a MacOS. Output files will be found in the directory this script is running from."
    echo ""
    echo "      Usage: ./make_release_binaries.sh <arm|amd> <RELEASE VERSION> <SO VERSION> <SOURCECODE DIRECTORY>"
    echo ""
    echo "Arch                          : 'amd' or 'arm'"
    echo "RELEASE VERSION               : Full yubico-piv-tool version, tex 2.1.0"
    echo "SO VERSION                    : The version of the ykpiv library, tex 2"
    echo "SOURCECODE DIRECTORY          : Absolute path to the directory containing the source code"
    exit 0
fi

ARCH = $1
VERSION=$2 # Full yubico-piv-tool version, tex 2.1.0
SO_VERSION=$3
SOURCE_DIR=$4

echo "Release version : $VERSION"
echo "SO version: $SO_VERSION"
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

echo $BREW_LIB

#PACKAGE=yubico-piv-tool
CFLAGS="-mmacosx-version-min=10.6"

OUTPUT=$PWD/yubico-piv-tool-$VERSION-mac-$ARCH/usr/local
LICENSE_DIR=$OUTPUT/licenses

#MAC_DIR=$SOURCE_DIR/resources/macos
#PKG_DIR=$MAC_DIR/pkgtmp
#INSTALL_DIR=$PKG_DIR/install
#FINAL_INSTALL_DIR=$INSTALL_DIR/$CMAKE_INSTALL_PREFIX
#BUILD_DIR=$PKG_DIR/build
#LICENSE_DIR=$PKG_DIR/licenses


# Create missing directories
#rm -rf $PKG_DIR
#mkdir -p $PKG_DIR $INSTALL_DIR $BUILD_DIR $LICENSE_DIR $FINAL_INSTALL_DIR
mkdir -p $LICENSE_DIR



# Build yubico-piv-tool and install it in $INSTALL_DIR
cd $SOURCE_DIR
mkdir build; cd build
CFLAGS=$CFLAGS PKG_CONFIG_PATH=$BREW_LIB/openssl/lib/pkgconfig cmake $SOURCE_DIR -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$OUTPUT/"
make install
#env DESTDIR="$INSTALL_DIR" make install;

cd $OUTPUT

ls -l lib/

#rm lib/libykpiv.$SO_VERSION.dylib
#rm libykpiv.dylib
#rm lib/libykcs11.$SO_VERSION.dylib
#rm lib/libykcs11.dylib

cp -r $BREW_LIB/openssl/include/openssl include/
cp $BREW_LIB/openssl/lib/libcrypto.3.dylib lib/
chmod +w lib/libcrypto.3.dylib

cp -r $BREW_LIB/zlib/include/zlib.h include
cp $BREW_LIB/zlib/lib/libz.1.dylib lib/
chmod +w lib/libz.1.dylib

# Fix paths
install_name_tool -id @loader_path/../lib/libcrypto.3.dylib lib/libcrypto.3.dylib
otool -L lib/libcrypto.3.dylib

install_name_tool -id @loader_path/../lib/libz.1.dylib lib/libz.1.dylib
otool -L lib/libz.1.dylib

install_name_tool -change $BREW_LIB/openssl@3/lib/libcrypto.3.dylib @loader_path/../lib/libcrypto.3.dylib lib/libykpiv.$VERSION.dylib
install_name_tool -change /usr/lib/libz.1.dylib @loader_path/../lib/libz.1.dylib lib/libykpiv.$VERSION.dylib
#install_name_tool -rpath $OUTPUT/lib @loader_path/../lib lib/libykpiv.$VERSION.dylib
otool -L lib/libykpiv.$VERSION.dylib

install_name_tool -change $BREW_LIB/openssl@3/lib/libcrypto.3.dylib @loader_path/../lib/libcrypto.3.dylib lib/libykcs11.$VERSION.dylib
install_name_tool -change /usr/lib/libz.1.dylib @loader_path/../lib/libz.1.dylib lib/libykcs11.$VERSION.dylib
install_name_tool -rpath $OUTPUT/lib @loader_path/../lib lib/libykcs11.$VERSION.dylib
otool -L lib/libykcs11.$VERSION.dylib
otool -l lib/libykcs11.$VERSION.dylib | grep LC_RPATH -A 3

install_name_tool -change $BREW_LIB/openssl@3/lib/libcrypto.3.dylib @loader_path/../lib/libcrypto.3.dylib bin/yubico-piv-tool
install_name_tool -change /usr/lib/libz.1.dylib @loader_path/../lib/libz.1.dylib bin/yubico-piv-tool
install_name_tool -rpath $OUTPUT/lib @loader_path/../lib bin/yubico-piv-tool
otool -L bin/yubico-piv-tool
otool -l bin/yubico-piv-tool | grep LC_RPATH -A 3


if otool -L $OUTPUT/lib/*.dylib $OUTPUT/bin/* | grep '$OUTPUT' | grep -q compatibility; then
	echo "something is incorrectly linked!";
	exit 1;
fi

# Copy licenses
cd $SOURCE_DIR
cp COPYING $LICENSE_DIR/yubico-piv-tool.txt
cp $BREW_LIB/zlib/LICENSE $LICENSE_DIR/zlib.txt
cp $BREW_LIB/openssl/LICENSE.txt $LICENSE_DIR/openssl.txt
