Set-PSDebug -Trace 1

$RELEASE_VERSION=$args[0]
$CMAKE_ARCH=$args[1]
$VCPKG_PATH=$args[2]
if($args.length -eq 4) {
    if($args[3] -eq "zip") {
        $ZIP = "TRUE"
    }
}

if($CMAKE_ARCH -eq "Win32") {
    $ARCH="x86"
} else {
    $ARCH="x64"
}

$SOURCE_DIR="$PSScriptRoot/../.."
$BUILD_DIR="$SOURCE_DIR/win32_release"
$RELEASE_DIR="$SOURCE_DIR/yubico-piv-tool-$RELEASE_VERSION-$ARCH"
$RELEASE_ARCHIVE="$SOURCE_DIR/yubico-piv-tool-$RELEASE_VERSION-$ARCH.zip"
$LICENSES_DIR="$RELEASE_DIR/licenses"

# Install prerequisites
cd $VCPKG_PATH
.\vcpkg.exe install openssl:$ARCH-windows
.\vcpkg.exe install getopt:$ARCH-windows
.\vcpkg.exe install zlib:$ARCH-windows

$env:OPENSSL_ROOT_DIR ="$VCPKG_PATH/packages/openssl_$ARCH-windows"

ls $VCPKG_PATH/packages

$env:Path ="$VCPKG_PATH\packages\zlib_$ARCH-windows;$env:Path"
$env:include ="$VCPKG_PATH\packages\zlib_$ARCH-windows/include;$env:include"

# Build for x86 architecture
cd $SOURCE_DIR
mkdir $BUILD_DIR; cd $BUILD_DIR
cmake -A "$CMAKE_ARCH" -DVERBOSE_CMAKE=1 -DGETOPT_LIB_DIR="$VCPKG_PATH/packages/getopt-win32_$ARCH-windows/lib" -DGETOPT_INCLUDE_DIR="$VCPKG_PATH/packages/getopt-win32_$ARCH-windows/include" -DZLIB_LIB_DIR="$VCPKG_PATH/packages/zlib_$ARCH-windows/lib" -DZLIB_INCL_DIR="$VCPKG_PATH/packages/zlib_$ARCH-windows/include" -DCMAKE_INSTALL_PREFIX="$RELEASE_DIR" ..
cmake --build . -v --config Release
cmake --install .
cd $RELEASE_DIR/bin
if($ARCH -eq "x86")
{
    cp $VCPKG_PATH/packages/openssl_x86-windows/bin/libcrypto-3.dll .
    cp $VCPKG_PATH/packages/getopt-win32_x86-windows/bin/getopt.dll .
}
else
{
    cp $VCPKG_PATH/packages/openssl_x64-windows/bin/libcrypto-3-x64.dll .
    cp $VCPKG_PATH/packages/getopt-win32_x64-windows/bin/getopt.dll .
}

# Create missing directories
mkdir -p $LICENSES_DIR

# Copy licenses
$license=(Get-ChildItem -Path $SOURCE_DIR -Filter COPYING -Recurse -ErrorAction SilentlyContinue -Force | %{$_.FullName})
cp $license $LICENSES_DIR\yubico-piv-tool.txt

$license=(Get-ChildItem -Path $VCPKG_PATH\buildtrees\openssl\src\ -Filter LICENSE -Recurse -ErrorAction SilentlyContinue -Force | %{$_.FullName})
cp $license $LICENSES_DIR\openssl.txt

$license=(Get-ChildItem -Path $VCPKG_PATH\buildtrees\getopt-win32\src\ -Filter LICENSE -Recurse -ErrorAction SilentlyContinue -Force | %{$_.FullName})
cp $license $LICENSES_DIR\getopt.txt

# Copy OpenSSL header files
cp -r $VCPKG_PATH\packages\openssl_$ARCH-windows\include\openssl $RELEASE_DIR/include/

if($ZIP)
{
    # Create a zip with the binaries
    Add-Type -Assembly System.IO.Compression.FileSystem
    $compressionLevel = [System.IO.Compression.CompressionLevel]::Optimal
    [System.IO.Compression.ZipFile]::CreateFromDirectory($RELEASE_DIR, $RELEASE_ARCHIVE, $compressionLevel, $true)
    cd $SOURCE_DIR
    rm -r $RELEASE_DIR
}

# Clean directory
cd $SOURCE_DIR
rm -r $BUILD_DIR
