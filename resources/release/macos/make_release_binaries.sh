#!/bin/bash
# Script to produce an OS X binaries
# This script has to be run from the source directory
if [ "$#" -ne 4 ]; then
    echo "This script build the binaries to be installed on a MacOS. This script should be run from the main project directory"
    echo ""
    echo "      Usage: ./resources/macos/make_release_binaries.sh <amd|arm> <RELEASE_VERSION> <SO_VERSION> <SOURCE_DIRECTORY>"
    echo ""
    exit 0
fi

ARCH = $1
VERSION=$2 # Full yubico-piv-tool version, tex 2.1.0
SO_VERSION=$3
SOURCE_DIR=$4 # Source code directory, aka, path to yubico-piv-tool source code

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

echo "Release version : $VERSION"
echo "SO version: $SO_VERSION"
echo "Source directory: $SOURCE_DIR"
echo "BREW_LIB: $BREW_LIB"

set -x

#PACKAGE=yubico-piv-tool
#CFLAGS="-mmacosx-version-min=10.6"
OUTPUT=$PWD/yubico-piv-tool-$VERSION-mac-$ARCH/usr/local

# Build yubico-piv-tool and install it in $OUTPUT
export PKG_CONFIG_PATH=$BREW_LIB/openssl/lib/pkgconfig
cd $SOURCE_DIR
mkdir build; cd build
cmake $SOURCE_DIR -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$OUTPUT/"
make install;

rm $OUTPUT/lib/libykpiv.$SO_VERSION.dylib
rm $OUTPUT/lib/libykpiv.dylib
rm $OUTPUT/lib/libykcs11.$SO_VERSION.dylib
rm $OUTPUT/lib/libykcs11.dylib

cp "$BREW_LIB/openssl/lib/libcrypto.3.dylib" "$OUTPUT/lib"
chmod +w "$OUTPUT/lib/libcrypto.3.dylib"
cp -r $BREW_LIB/openssl/include/openssl "$OUTPUT/include/"

cp "$BREW_LIB/zlib/lib/libz.1.dylib" "$OUTPUT/lib/"
chmod +w "$OUTPUT/lib/libz.1.dylib"
cp -r $BREW_LIB/zlib/include/zlib.h "$OUTPUT/include/"

# Fix paths
install_name_tool -id @loader_path/../lib/libcrypto.3.dylib $OUTPUT/lib/libcrypto.3.dylib
otool -L $OUTPUT/lib/libcrypto.3.dylib

install_name_tool -id @loader_path/../lib/libz.1.dylib $OUTPUT/lib/libz.1.dylib
otool -L $OUTPUT/lib/libz.1.dylib

install_name_tool -change $BREW_LIB/openssl@3/lib/libcrypto.3.dylib @loader_path/../lib/libcrypto.3.dylib $OUTPUT/lib/libykpiv.$VERSION.dylib
install_name_tool -change /usr/lib/libz.1.dylib @loader_path/../lib/libz.1.dylib $OUTPUT/lib/libykpiv.$VERSION.dylib
otool -L $OUTPUT/lib/libykpiv.$VERSION.dylib

install_name_tool -change $BREW_LIB/openssl@3/lib/libcrypto.3.dylib @loader_path/../lib/libcrypto.3.dylib $OUTPUT/lib/libykcs11.$VERSION.dylib
install_name_tool -change /usr/lib/libz.1.dylib @loader_path/../lib/libz.1.dylib $OUTPUT/lib/libykcs11.$VERSION.dylib
install_name_tool -rpath $OUTPUT/lib @loader_path/../lib $OUTPUT/lib/libykcs11.$VERSION.dylib
otool -L $OUTPUT/lib/libykcs11.$VERSION.dylib
otool -l $OUTPUT/lib/libykcs11.$VERSION.dylib | grep LC_RPATH -A 3

install_name_tool -change $BREW_LIB/openssl@3/lib/libcrypto.3.dylib @loader_path/../lib/libcrypto.3.dylib $OUTPUT/bin/yubico-piv-tool
install_name_tool -change /usr/lib/libz.1.dylib @loader_path/../lib/libz.1.dylib $OUTPUT/bin/yubico-piv-tool
install_name_tool -rpath $OUTPUT/lib @loader_path/../lib $OUTPUT/bin/yubico-piv-tool
otool -L $OUTPUT/bin/yubico-piv-tool
otool -l $OUTPUT/bin/yubico-piv-tool | grep LC_RPATH -A 3

# Copy yubico-piv-tool license and move the whole lisenses directory under FINALINSTALL_DIR.
mkdir -p $OUTPUT/licenses
cp $SOURCE_DIR/COPYING $OUTPUT/licenses/yubico-piv-tool.txt
cp $BREW_LIB/zlib/LICENSE $OUTPUT/licenses/zlib.txt
cp $BREW_LIB/openssl/LICENSE.txt $OUTPUT/licenses/openssl.txt
