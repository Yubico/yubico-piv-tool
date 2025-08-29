if ($args.Count -lt 2) {
    echo "This script uses pkcs11-tool to test YKCS11 and requires a YubiKey to be plugged in."
    echo ""
    echo "      Usage: ./ykcs11_tests_o.ps1 <path to PKCS11 module> <ac|acde|all>"
    echo ""
    echo "ac|acde|all         Which slots to run tests on: 'ac' runs tests on slots 9a and 9c, 'acde' runs tests on slots 9a, 9c, 9d and 9e, 'all' runs tests on all slots"
    echo ""
    exit
}
$MODULE = $args[0]
$CMD_SLOTS = $args[1].ToString().ToLower()
$MODULE = '"' + $MODULE + '"' #Was necessary in order for the pkcs-tool to read the module path correctly if it contains spaces
echo ""
echo "WARNING! This test script can overwrite any existing YubiKey content"
echo ""
if (Test-Path -Path .\yubico-piv-tool_test_dir) {
    echo "Found existing test directory, clearing contents"
    Remove-Item -Path .\yubico-piv-tool_test_dir\* -Recurse -Force
    cd yubico-piv-tool_test_dir
}
else {
    echo "Creating test directory"
    mkdir yubico-piv-tool_test_dir; cd yubico-piv-tool_test_dir
}
echo "testing data" > data.txt
function test {
    param
    (
        [string]$Command,
        [string]$Description
    )
    Invoke-Expression "$Command" *> output.txt
    $ret = $LASTEXITCODE
    if ($ret -ne 0) {
        Write-Host $Command
        Get-Content output.txt
        Remove-Item output.txt
        exit 1
    }
    else {
        Write-Host "   $Description ... OK!"
        Remove-Item output.txt
    }
}
$SLOTS = 2
if ($CMD_SLOTS -eq "acde") {
    $SLOTS = 4
}
elseif ($CMD_SLOTS -eq "all") {
    $SLOTS = 24
}
pkcs11-tool.exe --module $MODULE --login --login-type so --so-pin 010203040506070801020304050607080102030405060708 --keypairgen --id 1 --key-type EC:edwards25519  $null 2>&1
$newkey = $?
$EC_CURVES = @("prime256v1", "secp384r1")
$RSA_KEYSIZES = @("1024", "2048")
$HASH_SIZES = @("1", "256", "384", "512")
if ($newkey -eq 0) {
    $RSA_KEYSIZE += "3072", "4096"
}
foreach ($c in $EC_CURVES) {
    echo "**********************************"
    echo "            $c"
    echo "**********************************"
    foreach ($s in 1..$SLOTS) {
        $slot = "{0:x2}" -f $s
        echo "===== Generate key in slot $s"
        test "pkcs11-tool --module $MODULE --login --login-type so --so-pin 010203040506070801020304050607080102030405060708 --keypairgen --id $slot --key-type EC:$c" "Generate keypair"
        echo "=== Get public key"
        test "pkcs11-tool --module $MODULE --read-object --type cert --id $slot -o cert.der" "Read certificate for slot $s"
        test "openssl x509 -inform DER -outform PEM -in cert.der -out cert.pem" "Convert certificate to PEM format"
        test "openssl x509 -in cert.pem -pubkey -noout -out pubkey.pem" "Extract public key from certificate"
        echo "=== Test signing"
        foreach ($h in $HASH_SIZES) {
            test "pkcs11-tool --module $MODULE --sign --pin 123456 --id $slot -m ECDSA-SHA$h --signature-format openssl -i data.txt -o data.sig" "Sign data with ECDSA-SHA$h"
            test "openssl dgst -sha$h -verify pubkey.pem -signature data.sig data.txt" "Verify signature"
        }
        echo "===== Import key into slot $s"
        openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:$c -x509 -nodes -days 365 -subj "/CN=OpenSSLGeneratedECKey/" -out cert.pem -keyout key.pem
        test "pkcs11-tool --module $MODULE --login --login-type so --so-pin 010203040506070801020304050607080102030405060708 --write-object key.pem --id $slot --type privkey" "Import private key"
        test "pkcs11-tool --module $MODULE --login --login-type so --so-pin 010203040506070801020304050607080102030405060708 --write-object cert.pem --id $slot --type cert" "Import certificate"
        echo "=== Get public key"
        test "pkcs11-tool --module $MODULE --read-object --type pubkey --id $slot -o pubkey.der" "Read certificate for slot $s"
        test "openssl pkey -pubin -inform der -in pubkey.der -out pubkey.pem" "Read out public key"
        test "openssl x509 -in cert.pem -pubkey -noout -out pubkey_from_cert.pem" "Extract public key from certificate"
        test "cmp pubkey.pem pubkey_from_cert.pem" "Compare public key read from card with public key extracted from certificate"
        # Test signing
        echo "=== Test signing"
        foreach ($h in $HASH_SIZES) {
            test "pkcs11-tool --module $MODULE --sign --pin 123456 --id $slot -m ECDSA-SHA$h --signature-format openssl -i data.txt -o data.sig" "Sign data with ECDSA-SHA$h"
            test "openssl dgst -sha$h -verify pubkey.pem -signature data.sig data.txt" "Verify signature"
        }
    }
}
if ($newkey -eq 0) {
    echo "**********************************"
    echo "            ED25519"
    echo "**********************************"
    foreach ($s in 1..$SLOTS) {
        $slot = "{0:x2}" -f $s
        echo "===== Generate key in slot $s"
        test "pkcs11-tool --module $MODULE --login --login-type so --so-pin 010203040506070801020304050607080102030405060708 --keypairgen --id $slot --key-type EC:edwards25519" "Generate keypair"
        echo "=== Get public key"
        test "pkcs11-tool --module $MODULE --read-object --type cert --id $slot -o cert.der" "Read certificate for slot $s"
        test "openssl x509 -inform DER -outform PEM -in cert.der -out cert.pem" "Convert certificate to PEM format"
        test "openssl x509 -in cert.pem -pubkey -noout -out pubkey.pem" "Extract public key from certificate"
        echo "=== Test signing"
        test "pkcs11-tool --module $MODULE --sign --pin 123456 --id $slot -m EDDSA --signature-format openssl -i data.txt -o data.sig" "Sign data with EDDSA"
        test "openssl pkeyutl -verify -pubin -inkey pubkey.pem -rawin -in data.txt -sigfile data.sig" "Verify signature with OpenSSL"
    }
}
foreach ($k in $RSA_KEYSIZES) {
    echo "**********************************"
    echo "            RSA$k"
    echo "**********************************"
    foreach ($s in 1..$SLOTS) {
        $slot = "{0:x2}" -f $s
        
        echo "===== Generate key in slot $s"
        test "pkcs11-tool --module $MODULE --login --login-type so --so-pin 010203040506070801020304050607080102030405060708 --keypairgen --id $slot --key-type rsa:$k" "Generate keypair"
        echo "=== Get public key"
        test "pkcs11-tool --module $MODULE --read-object --type cert --id $slot -o cert.der" "Read certificate for slot $s"
        test "openssl x509 -inform DER -outform PEM -in cert.der -out cert.pem" "Convert certificate to PEM format"
        test "openssl x509 -in cert.pem -pubkey -noout -out pubkey.pem" "Extract public key from certificate"
        echo "=== Test signing"
        foreach ($h in $HASH_SIZES) {
            test "pkcs11-tool --module $MODULE --sign --pin 123456 --id $slot -m SHA$h-RSA-PKCS --signature-format openssl -i data.txt -o data.sig" "Sign data with SHA$h-RSA-PKCS"
            test "openssl dgst -sha$h -verify pubkey.pem -signature data.sig data.txt" "Verify signature"
        }
        echo "=== Test decryption"
        foreach ($md in $HASH_SIZES) {
            foreach ($mgf in $HASH_SIZES) {
                # Skip 1024-bit RSA keys with SHA-512 and MGF1-SHA512 because the key size is too small
                if ($md -eq "512" -or $mgf -eq "512") {
                    if ($k -eq "1024") {
                        continue
                    }
                }
                test "openssl pkeyutl -encrypt -pubin -inkey pubkey.pem -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha$md -pkeyopt rsa_mgf1_md:sha$mgf -in data.txt -out data.oaep" "Encrypt data with OpenSSL using OAEP padding: SHA$md and MGF1-SHA$mgf"
                if ($md -eq 1) {
                    test "pkcs11-tool --module $MODULE --decrypt --pin 123456 --id $slot --hash-algorithm SHA-1 --mgf MGF1-SHA$mgf -m RSA-PKCS-OAEP -i data.oaep -o data.dec" "Decrypt data using YKCS11"
                }
                else {
                    test "pkcs11-tool --module $MODULE --decrypt --pin 123456 --id $slot --hash-algorithm SHA$md --mgf MGF1-SHA$mgf -m RSA-PKCS-OAEP -i data.oaep -o data.dec" "Decrypt data using YKCS11"
                }
                test "cmp data.dec data.txt" "Compare decrypted data with plain text data"
            }
        }
    }
}
echo "******************* Testing RSA Tests ********************* "
pkcs11-tool.exe --module $MODULE --login --pin 123456  --test
#echo "******************* Testing EC Tests ********************* "
#pkcs11-tool --module $MODULE --login --pin 123456 --login-type so --so-pin 010203040506070801020304050607080102030405060708 --test-ec --id 2 --key-type EC:secp256r1
echo "All tests passed!"
cd ..
Remove-Item -Path "yubico-piv-tool_test_dir" -Recurse -Force