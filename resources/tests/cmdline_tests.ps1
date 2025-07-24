# This is a test script that uses the yubico-piv-tool command line tool to reset the conncted YubiKey and then
# generates keys on 4 different slots using 4 different key algorithms and then performs a signature with each
# of these keys.
#
# This script runs on Powershell. If running scripts on the current Powershell terminal is not permitted, run the
# following command to allow it only on the current terminal:
#       >> Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process


$ARCH=$args[0]
if($ARCH -eq "x86")
{
    if ((Get-Command "yubico-piv-tool.exe" -ErrorAction SilentlyContinue) -eq $null)
    {
        $env:Path += ";C:/Program Files (x86)/Yubico/Yubico PIV Tool/bin"
    }
}
elseif ($ARCH -eq "x64")
{
    if ((Get-Command "yubico-piv-tool.exe" -ErrorAction SilentlyContinue) -eq $null)
    {
        $env:Path += ";C:/Program Files/Yubico/Yubico PIV Tool/bin"
    }
}
else {
    echo "Usage: ./cmdline_test.ps1 <x86|x64>"
    echo ""
    echo "This is a test script that uses the yubico-piv-tool command line tool to reset the conncted YubiKey and then
           generates keys on 4 different slots using 4 different key algorithms and then performs a signature with each
           of these keys."
    echo ""
    echo "   x86        expects that yubico-piv-tool is installed in 'C:/Program Files (x86)/Yubico/Yubico PIV Tool/bin'"
    echo "   x64        expects that yubico-piv-tool is installed in 'C:/Program Files/Yubico/Yubico PIV Tool/bin'"
    exit
}

echo "Running commands on $ARCH architecture"

mkdir yubico-piv-tool_test_dir; cd yubico-piv-tool_test_dir
echo "test signing data" > data.txt

$BIN="yubico-piv-tool.exe"

yubico-piv-tool.exe --help

echo "********************** Reset YubiKey ********************* "

# Reset
yubico-piv-tool.exe -averify-pin -P000000
yubico-piv-tool.exe -averify-pin -P000000
yubico-piv-tool.exe -averify-pin -P000000
yubico-piv-tool.exe -averify-pin -P000000
yubico-piv-tool.exe -averify-pin -P000000
yubico-piv-tool.exe -achange-puk -P000000 -N00000000
yubico-piv-tool.exe -achange-puk -P000000 -N00000000
yubico-piv-tool.exe -achange-puk -P000000 -N00000000
yubico-piv-tool.exe -achange-puk -P000000 -N00000000
yubico-piv-tool.exe -achange-puk -P000000 -N00000000
yubico-piv-tool.exe -areset

echo "********************** Generate ECCP256 in 9a ********************* "

# Generate key on-board, issue certificate, and verify it
yubico-piv-tool.exe -agenerate -s9a -AECCP256 -o key_9a.pub
yubico-piv-tool.exe -averify -P123456 -s9a -S'/CN=YubicoTestECCP256Win/OU=YubicoGenerated/O=yubico.com/' -aselfsign -i key_9a.pub -o cert_9a.pem
yubico-piv-tool.exe -averify -P123456 -s9a -atest-signature -i cert_9a.pem
yubico-piv-tool.exe -aimport-certificate -P123456 -s9a -i cert_9a.pem

# Read status and validate fields
yubico-piv-tool.exe -astatus
yubico-piv-tool.exe -a verify-pin -P123456 --sign -s 9a -A ECCP256 -i data.txt -o data.sig

echo "********************** Generate ECCP384 in 9c ********************* "

# Generate key on-board, issue certificate, and verify it
yubico-piv-tool.exe -agenerate -s9c -AECCP384 -o key_9c.pub
yubico-piv-tool.exe -averify -P123456 -s9c -S'/CN=YubicoTestECCP384Win/OU=YubicoGenerated/O=yubico.com/' -aselfsign -i key_9c.pub -o cert_9c.pem
yubico-piv-tool.exe -averify -P123456 -s9c -atest-signature -i cert_9c.pem
yubico-piv-tool.exe -aimport-certificate -P123456 -s9c -i cert_9c.pem

# Read status and validate fields
yubico-piv-tool.exe -astatus
yubico-piv-tool.exe -a verify-pin -P123456 --sign -s 9c -A ECCP384 -i data.txt -o data.sig

echo "********************** Generate RSA1024 in 9d ********************* "

# Generate key on-board, issue certificate, and verify it
yubico-piv-tool.exe -agenerate -s9d -ARSA1024 -o key_9d.pub
yubico-piv-tool.exe -averify -P123456 -s9d -S'/CN=YubicoTestRSA1024Win/OU=YubicoGenerated/O=yubico.com/' -aselfsign -i key_9d.pub -o cert_9d.pem
yubico-piv-tool.exe -averify -P123456 -s9d -atest-signature -i cert_9d.pem
yubico-piv-tool.exe -aimport-certificate -P123456 -s9d -i cert_9d.pem

# Read status and validate fields
yubico-piv-tool.exe -astatus
yubico-piv-tool.exe -a verify-pin -P123456 --sign -s 9d -A RSA1024 -i data.txt -o data.sig

echo "********************** Generate RSA2048 in 9e ********************* "

# Generate key on-board, issue certificate, and verify it
yubico-piv-tool.exe -agenerate -s9e -ARSA2048 -o key_9e.pub
yubico-piv-tool.exe -averify -P123456 -s9e -S'/CN=YubicoTestRSA2048Win/OU=YubicoGenerated/O=yubico.com/' -aselfsign -i key_9e.pub -o cert_9e.pem
yubico-piv-tool.exe -averify -P123456 -s9e -atest-signature -i cert_9e.pem
yubico-piv-tool.exe -aimport-certificate -P123456 -s9e -i cert_9e.pem

# Read status and validate fields
yubico-piv-tool.exe -astatus
yubico-piv-tool.exe -a verify-pin -P123456 --sign -s 9e -A RSA2048 -i data.txt -o data.sig

cd ..
rm -r yubico-piv-tool_test_dir
