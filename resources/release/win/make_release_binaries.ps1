if($args.length -lt 3)
{
    echo "Usage: ./make_release_binaries.ps1 <Win32|x64> <VCPKG_PATH> <SOURCE_DIR>"
    echo ""
    echo "This is a script to build an MSI installer for yubihsm"
    echo ""
    echo "   Win32                  builds using X86 architecture by adding '-A Win32' argument to the cmake command"
    echo "   x64                    builds using X64 architecture by adding '-A x64' argument to the cmake command"
    echo ""
    echo "   VCPKG_PATH             Absolute path to the directory where vcpkg.exe is located"
    echo "   SOURCE_DIR             Absolute path to the directory where the yubihsm-shell source code is located"
    exit
}

$CMAKE_ARCH=$args[0]
$VCPKG_PATH=$args[1]
$SOURCE_DIR=$args[2]

if($CMAKE_ARCH -eq "Win32") {
    $ARCH="x86"
} else {
    $ARCH="x64"
}

$WIN_DIR = "$PSScriptRoot"
$BUILD_DIR="$WIN_DIR/build_release"
$RELEASE_DIR="$WIN_DIR/yubico-piv-tool-$ARCH"
$LICENSES_DIR="$RELEASE_DIR/licenses"

# $SOURCE_DIR="$PSScriptRoot/../.."
# $BUILD_DIR="$SOURCE_DIR/win32_release"
# $RELEASE_DIR="$SOURCE_DIR/yubico-piv-tool-$RELEASE_VERSION-$ARCH"
# $RELEASE_ARCHIVE="$SOURCE_DIR/yubico-piv-tool-$RELEASE_VERSION-$ARCH.zip"
# $LICENSES_DIR="$RELEASE_DIR/licenses"

Set-PSDebug -Trace 1


# Install prerequisites
cd $VCPKG_PATH
.\vcpkg.exe update
.\vcpkg.exe install openssl:$ARCH-windows
.\vcpkg.exe install getopt:$ARCH-windows
.\vcpkg.exe install zlib:$ARCH-windows

$env:OPENSSL_ROOT_DIR ="$VCPKG_PATH/packages/openssl_$ARCH-windows"
$env:Path ="$VCPKG_PATH\packages\zlib_$ARCH-windows\bin;$env:Path"

# Build for x86 architecture
# cd $SOURCE_DIR
mkdir $BUILD_DIR; cd $BUILD_DIR
cmake -S $SOURCE_DIR -A "$CMAKE_ARCH" -DVERBOSE_CMAKE=1 -DCMAKE_INSTALL_PREFIX="$RELEASE_DIR" `
        -DGETOPT_LIB_DIR="$VCPKG_PATH/packages/getopt-win32_$ARCH-windows/lib" `
        -DGETOPT_INCLUDE_DIR="$VCPKG_PATH/packages/getopt-win32_$ARCH-windows/include" `
        -DZLIB_LIB_DIR="$VCPKG_PATH/packages/zlib_$ARCH-windows/lib" `
        -DZLIB_INCL_DIR="$VCPKG_PATH/packages/zlib_$ARCH-windows/include" `
        -DZLIB_ROOT="$VCPKG_PATH/packages/zlib_$ARCH-windows"
        
cmake --build . -v --config Release --target install
# cmake --install .

# Copy openssl and getopt libraries
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
cp $VCPKG_PATH/packages/zlib_$ARCH-windows/bin/zlib1.dll .

# Create missing directories
Remove-Item -Path $LICENSES_DIR -Force -Recurse -ErrorAction SilentlyContinue
mkdir -p $LICENSES_DIR

# Copy licenses
$license=(Get-ChildItem -Path $SOURCE_DIR -Filter COPYING -Recurse -ErrorAction SilentlyContinue -Force | %{$_.FullName})
cp $license $LICENSES_DIR\yubico-piv-tool.txt

$license=(Get-ChildItem -Path $VCPKG_PATH\buildtrees\openssl\src\ -Filter LICENSE -Recurse -ErrorAction SilentlyContinue -Force | %{$_.FullName})
cp $license $LICENSES_DIR\openssl.txt

$license=(Get-ChildItem -Path $VCPKG_PATH\buildtrees\getopt-win32\src\ -Filter LICENSE -Recurse -ErrorAction SilentlyContinue -Force | %{$_.FullName})
cp $license $LICENSES_DIR\getopt.txt

$license=(Get-ChildItem -Path $VCPKG_PATH\buildtrees\zlib\src\ -Filter LICENSE -Recurse -ErrorAction SilentlyContinue -Force | %{$_.FullName})
cp $license $LICENSES_DIR\zlib.txt

# Copy OpenSSL header files
cp -r $VCPKG_PATH\packages\openssl_$ARCH-windows\include\openssl $RELEASE_DIR/include/
cp -r $VCPKG_PATH\packages\zlib_$ARCH-windows\include\zlib.h $RELEASE_DIR/include/

# if($ZIP)
# {
#     # Create a zip with the binaries
#     Add-Type -Assembly System.IO.Compression.FileSystem
#     $compressionLevel = [System.IO.Compression.CompressionLevel]::Optimal
#     [System.IO.Compression.ZipFile]::CreateFromDirectory($RELEASE_DIR, $RELEASE_ARCHIVE, $compressionLevel, $true)
#     cd $SOURCE_DIR
#     rm -r $RELEASE_DIR
# }

# Clean directory
# cd $SOURCE_DIR
rm -r $BUILD_DIR

Set-PSDebug -Trace 0