# This script runs on Powershell. If running scripts on the current Powershell terminal is not permitted, run the
# following command to allow it only on the current terminal:
#       >> Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process

if($args.length -eq 0) {
    echo "Usage: ./opensc_tests.ps1 <path to PKCS11 module>"
    echo ""
    echo "This script expects that libykpiv.dll and the libcrypto.dll are on PATH"
    exit
}

if ((Get-Command "pkcs11-tool.exe" -ErrorAction SilentlyContinue) -eq $null)
{
    $env:Path +=";C:\Program Files\OpenSC Project\OpenSC\tools"
}

$MODULE=$args[0]

echo "******************* Generation Tests ********************* "
pkcs11-tool.exe --module $MODULE --login --login-type so --so-pin 010203040506070801020304050607080102030405060708 --keypairgen --id 1 --key-type EC:secp384r1
pkcs11-tool.exe --module $MODULE --login --login-type so --so-pin 010203040506070801020304050607080102030405060708 --keypairgen --id 2 --key-type EC:prime256v1
pkcs11-tool.exe --module $MODULE --login --login-type so --so-pin 010203040506070801020304050607080102030405060708 --keypairgen --id 3 --key-type rsa:1024
pkcs11-tool.exe --module $MODULE --login --login-type so --so-pin 010203040506070801020304050607080102030405060708 --keypairgen --id 4 --key-type rsa:2048

echo "******************* Signing Tests ********************* "
echo "this is test data" > Z:/data.txt
pkcs11-tool.exe --module $MODULE --sign --pin 123456 --id 1 -m ECDSA-SHA1 --signature-format openssl -i Z:/data.txt -o Z:/data.sig
pkcs11-tool.exe --module $MODULE --sign --pin 123456 --id 2 -m ECDSA-SHA1 --signature-format openssl -i Z:/data.txt -o Z:/data.sig
pkcs11-tool.exe --module $MODULE --sign --pin 123456 --id 3 -i Z:/data.txt -o Z:/data.sig
pkcs11-tool.exe --module $MODULE --sign --pin 123456 --id 4 -i Z:/data.txt -o Z:/data.sig
rm Z:/data.txt
rm Z:/data.sig

echo "******************* Testing RSA Tests ********************* "
pkcs11-tool.exe --module $MODULE --login --pin 123456 --test

echo "******************* Testing EC Tests ********************* "
pkcs11-tool.exe --module $MODULE --login --login-type so --so-pin 010203040506070801020304050607080102030405060708 --test-ec --id 2 --key-type EC:secp256r1
