$RELEASE_VERSION=$args[0] # yubico-piv-tool version
$ARCH=$args[1] # x86 or x64
$WIX_PATH=$args[2] # Absolute path to the WixTools binaries
$SOURCE_DIR=$args[3] # Directory containing signed binaries
$MERGE_MODULE=$args[4] # Absolute path containing Microsoft_VC142_CRT_x86.msm or Microsoft_VC142_CRT_x64.msm


$WD="$PSScriptRoot/msi"
$env:PATH += ";$WIX_PATH"
$env:SRCDIR = $SOURCE_DIR
$env:MERGEDPATH = $MERGE_MODULE

mkdir msi
cd msi
cp "../yubico-piv-tool_$ARCH.wxs" .
heat.exe dir $SOURCE_DIR -out fragment.wxs -gg -scom -srd -sfrag -sreg -dr INSTALLDIR -cg ApplicationFiles -var env.SRCDIR
candle.exe fragment.wxs "yubico-piv-tool_$ARCH.wxs" -arch $ARCH
light.exe fragment.wixobj "yubico-piv-tool_$ARCH.wixobj" -o "yubico-piv-tool-$RELEASE_VERSION-$ARCH.msi"
mv "yubico-piv-tool-$RELEASE_VERSION-$ARCH.msi" ../
cd ..
rm -r msi