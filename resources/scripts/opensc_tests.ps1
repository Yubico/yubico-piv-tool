# This script runs on Powershell. If running scripts on the current Powershell terminal is not permitted, run the
# following command to allow it only on the current terminal:
#       >> Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process

if($args.length -eq 0) {
    echo "Usage: ./opensc_tests.ps1 <path to PKCS11 module>"
    echo ""
    echo "This script must be run from the directory where pkcs11-tool.exe is locates. The libykpiv.dll and the libcrypto.dll need to have been copied into the same directory too"
    exit
}

$MODULE=$args[0]

echo "******************* Generation Tests ********************* "
./pkcs11-tool.exe --module $MODULE --login --login-type so --keypairgen --id 1 --key-type EC:secp384r1
./pkcs11-tool.exe --module $MODULE --login --login-type so --keypairgen --id 2 --key-type EC:prime256v1
./pkcs11-tool.exe --module $MODULE --login --login-type so --keypairgen --id 3 --key-type rsa:1024
./pkcs11-tool.exe --module $MODULE --login --login-type so --keypairgen --id 4 --key-type rsa:2048

echo "******************* Signing Tests ********************* "
echo "this is test data" > data.txt
./pkcs11-tool.exe --module $MODULE --sign --id 1 -m ECDSA-SHA1 --signature-format openssl -i E:/data.txt -o E:/data.sig
./pkcs11-tool.exe --module $MODULE --sign --id 2 -m ECDSA-SHA1 --signature-format openssl -i E:/data.txt -o E:/data.sig
./pkcs11-tool.exe --module $MODULE --sign --id 3 -i E:/data.txt -o E:/data.sig
./pkcs11-tool.exe --module $MODULE --sign --id 4 -i E:/data.txt -o E:/data.sig
rm data.txt
rm data.sig

echo "******************* Testing RSA Tests ********************* "
./pkcs11-tool.exe --module $MODULE --login  --test

echo "******************* Testing EC Tests ********************* "
./pkcs11-tool.exe --module $MODULE --login --login-type so --test-ec --id 2 --key-type EC:secp256r1
