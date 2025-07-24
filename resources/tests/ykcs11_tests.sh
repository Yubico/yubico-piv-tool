#!/bin/bash -e

if [ "$#" -lt 2 ]; then
  echo "This script uses pkcs11-tool to test YKCS11 and requires a YubiKey to be plugged in."
  echo ""
  echo "      Usage: ./opensc_tests.sh <path to PKCS11 module> <ac|acde|all>"
  echo ""
  echo "ac|acde|all         Which slots to run tests on: 'ac' runs tests on slots 9a and 9c, 'acde' runs tests on slots 9a, 9c, 9d and 9e, 'all' runs tests on all slots"
  echo ""
  exit
fi

set -e

MODULE=$1
CMD_SLOTS=$2 # ac|acde|all

echo ""
echo "WARNING! This test script can overwrite any existing YubiKey content"
echo ""
read -p "Press Enter to continue or Ctrl-C to abort"


if [ -e test_dir ]; then
    rm -rf test_dir
fi
mkdir test_dir; cd test_dir
echo this is testing data > data.txt

test () {
  set +e
  $1 > output.txt 2>&1
  ret=$?
  if [ $ret -ne 0 ]; then
    echo $1
    cat output.txt
    rm output.txt
    exit 1
  else
    echo "   $2 ... OK!"
    rm output.txt
  fi
  set -e
}

SLOTS=2
if [ "x$CMD_SLOTS" == "xacde" ]; then
  SLOTS=4
elif [ "x$CMD_SLOTS" == "xall" ]; then
  SLOTS=24
fi

set +e
pkcs11-tool --module $MODULE --login --login-type so --so-pin 010203040506070801020304050607080102030405060708 --keypairgen --id 1 --key-type EC:edwards25519  2>&1 > /dev/null
newkey=$?
set -e

EC_CURVES=("prime256v1" "secp384r1")
RSA_KEYSIZES=("1024" "2048")
HASH_SIZES=("1" "256" "384" "512")

if [ $newkey -eq 0 ]; then
  RSA_KEYSIZES=(${RSA_KEYSIZES[@]} "3072" "4096")
fi

for c in ${EC_CURVES[@]}; do

  echo "**********************************"
  echo "            $c"
  echo "**********************************"

  for ((s=1;s<=$SLOTS;s++)); do

    echo "===== Generate key in slot $s"
    test "pkcs11-tool --module $MODULE --login --login-type so --so-pin 010203040506070801020304050607080102030405060708 --keypairgen --id $s --key-type EC:$c" "Generate keypair"

    echo "=== Get public key"
    test "pkcs11-tool --module $MODULE --read-object --type cert --id $s -o cert.der" "Read certificate for slot $s"
    test "openssl x509 -inform DER -outform PEM -in cert.der -out cert.pem" "Convert certificate to PEM format"
    test "openssl x509 -in cert.pem -pubkey -noout -out pubkey.pem" "Extract public key from certificate"

    echo "=== Test signing"
    for h in ${HASH_SIZES[@]}; do
      test "pkcs11-tool --module $MODULE --sign --pin 123456 --id $s -m ECDSA-SHA$h --signature-format openssl -i data.txt -o data.sig" "Sign data with ECDSA-SHA$h"
      test "openssl dgst -sha$h -verify pubkey.pem -signature data.sig data.txt" "Verify signature"
    done

    echo "===== Import key into slot $s"
    openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:$c -x509 -nodes -days 365 -subj "/CN=OpenSSLGeneratedECKey/" -out cert.pem -keyout key.pem
    test "pkcs11-tool --module $MODULE --login --login-type so --so-pin 010203040506070801020304050607080102030405060708 --write-object key.pem --id $s --type privkey" "Import private key"
    test "pkcs11-tool --module $MODULE --login --login-type so --so-pin 010203040506070801020304050607080102030405060708 --write-object cert.pem --id $s --type cert" "Import certificate"

    echo "=== Get public key"
    test "pkcs11-tool --module $MODULE --read-object --type pubkey --id $s -o pubkey.der" "Read certificate for slot $s"
    test "openssl pkey -pubin -inform der -in pubkey.der -out pubkey.pem" "Read out public key"
    test "openssl x509 -in cert.pem -pubkey -noout -out pubkey_from_cert.pem" "Extract public key from certificate"
    test "cmp pubkey.pem pubkey_from_cert.pem" "Compare public key read from card with public key extracted from certificate"

    # Test signing
    echo "=== Test signing"
    for h in ${HASH_SIZES[@]}; do
      test "pkcs11-tool --module $MODULE --sign --pin 123456 --id $s -m ECDSA-SHA$h --signature-format openssl -i data.txt -o data.sig" "Sign data with ECDSA-SHA$h"
      test "openssl dgst -sha$h -verify pubkey.pem -signature data.sig data.txt" "Verify signature"
    done

  done

done

if [ $newkey -eq 0 ]; then
  echo "**********************************"
  echo "            ED25519"
  echo "**********************************"

  for ((s=1;s<=$SLOTS;s++)); do
    echo "===== Generate key in slot $s"
    test "pkcs11-tool --module $MODULE --login --login-type so --so-pin 010203040506070801020304050607080102030405060708 --keypairgen --id $s --key-type EC:edwards25519" "Generate keypair"

    echo "=== Get public key"
    test "pkcs11-tool --module $MODULE --read-object --type cert --id $s -o cert.der" "Read certificate for slot $s"
    test "openssl x509 -inform DER -outform PEM -in cert.der -out cert.pem" "Convert certificate to PEM format"
    test "openssl x509 -in cert.pem -pubkey -noout -out pubkey.pem" "Extract public key from certificate"

    echo "=== Test signing"
    test "pkcs11-tool --module $MODULE --sign --pin 123456 --id $s -m EDDSA --signature-format openssl -i data.txt -o data.sig" "Sign data with EDDSA"
    test "openssl pkeyutl -verify -pubin -inkey pubkey.pem -rawin -in data.txt -sigfile data.sig" "Verify signature with OpenSSL"
  done
fi

for k in ${RSA_KEYSIZES[@]}; do

  echo "**********************************"
  echo "            RSA$k"
  echo "**********************************"

  for ((s=1;s<=$SLOTS;s++)); do
    echo "===== Generate key in slot $s"
    test "pkcs11-tool --module $MODULE --login --login-type so --so-pin 010203040506070801020304050607080102030405060708 --keypairgen --id $s --key-type rsa:$k" "Generate keypair"

    echo "=== Get public key"
    test "pkcs11-tool --module $MODULE --read-object --type cert --id $s -o cert.der" "Read certificate for slot $s"
    test "openssl x509 -inform DER -outform PEM -in cert.der -out cert.pem" "Convert certificate to PEM format"
    test "openssl x509 -in cert.pem -pubkey -noout -out pubkey.pem" "Extract public key from certificate"

    echo "=== Test signing"
    for h in ${HASH_SIZES[@]}; do
      test "pkcs11-tool --module $MODULE --sign --pin 123456 --id $s -m SHA$h-RSA-PKCS --signature-format openssl -i data.txt -o data.sig" "Sign data with SHA$h-RSA-PKCS"
      test "openssl dgst -sha$h -verify pubkey.pem -signature data.sig data.txt" "Verify signature"
    done

    echo "=== Test decryption"
    for md in ${HASH_SIZES[@]}; do
      for mgf in ${HASH_SIZES[@]}; do

        # Skip 1024-bit RSA keys with SHA-512 and MGF1-SHA512 because the key size is too small
        if [ "x$md" == "x512" ] || [ "x$mgf" == "x512" ] ; then
          if [ "x$k" == "x1024" ] ; then
            continue
          fi
        fi

        test "openssl pkeyutl -encrypt -pubin -inkey pubkey.pem -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha$md -pkeyopt rsa_mgf1_md:sha$mgf -in data.txt -out data.oaep" "Encrypt data with OpenSSL using OAEP padding: SHA$md and MGF1-SHA$mgf"
        if [ "x$md" == "x1" ]; then
          test "pkcs11-tool --module $MODULE --decrypt --pin 123456 --id $s --hash-algorithm SHA-1 --mgf MGF1-SHA$mgf -m RSA-PKCS-OAEP -i data.oaep -o data.dec" "Decrypt data using YKCS11"
        else
          test "pkcs11-tool --module $MODULE --decrypt --pin 123456 --id $s --hash-algorithm SHA$md --mgf MGF1-SHA$mgf -m RSA-PKCS-OAEP -i data.oaep -o data.dec" "Decrypt data using YKCS11"
        fi
        test "cmp data.dec data.txt" "Compare decrypted data with plain text data"
      done
    done

 #Currently cannot import keys with pkcs11-tool because of missing support for CKA_MODULUS and CKA_PRIVATE_EXPONENT attributes for the private key
#    echo "===== Import key into slot $s"
##      test "openssl genrsa -out key.pem $k" "   Generate key with OpenSSL"
##      openssl req -key key.pem -new -subj "/CN=OpenSSLGeneratedRSACert/" -out csr.pem
##      test "openssl x509 -signkey key.pem -in csr.pem -req -days 365 -out cert.pem" "Create selfsigned certificate with OpenSSL"
#    openssl req -newkey rsa:$k -keyout key.pem -nodes -x509 -days 365 -subj "/CN=OpenSSLGeneratedRSAKey/" -out cert.pem
#    test "pkcs11-tool --module $MODULE --login --login-type so --so-pin 010203040506070801020304050607080102030405060708 --write-object key.pem --id $s --type privkey" "Import private key"
#    test "pkcs11-tool --module $MODULE --login --login-type so --so-pin 010203040506070801020304050607080102030405060708 --write-object cert.pem --id $s --type cert" "Import certificate"
#
#    echo "=== Get public key"
#    test "pkcs11-tool --module $MODULE --read-object --type pubkey --id $s -o pubkey.der" "Read certificate for slot $s"
#    test "openssl pkey -pubin -inform der -in pubkey.der -out pubkey.pem" "Read out public key"
#    test "openssl x509 -in cert.pem -pubkey -noout -out pubkey_from_cert.pem" "Extract public key from certificate"
#    test "cmp pubkey.pem pubkey_from_cert.pem" "Compare public key read from card with public key extracted from certificate"
#
#    echo "=== Test signing"
#    for h in ${HASH_SIZES[@]}; do
#      test "pkcs11-tool --module $MODULE --sign --pin 123456 --id $s -m SHA$h-RSA-PKCS -i data.txt -o data.sig" "Sign data with SHA$h-RSA-PKCS"
#      test "openssl dgst -sha$h -verify pubkey.pem -signature data.sig data.txt" "Verify signature"
#    done
#
#    echo "=== Test decryption"
#    for md in ${HASH_SIZES[@]}; do
#      for mgf in ${HASH_SIZES[@]}; do
#
#        # Skip 1024-bit RSA keys with SHA-512 and MGF1-SHA512 because the key size is too small
#        if [ "x$md" == "x512" ] || [ "x$mgf" == "x512" ] ; then
#          if [ "x$k" == "x1024" ] ; then
#            continue
#          fi
#        fi
#
#        test "openssl pkeyutl -encrypt -pubin -inkey pubkey.pem -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha$md -pkeyopt rsa_mgf1_md:sha$mgf -in data.txt -out data.oaep" "Encrypt data with OpenSSL using OAEP padding: SHA$md and MGF1-SHA$mgf"
#        if [ "x$md" == "x1" ]; then
#          test "pkcs11-tool --module $MODULE --decrypt --pin 123456 --id $s --hash-algorithm SHA-1 --mgf MGF1-SHA$mgf -m RSA-PKCS-OAEP -i data.oaep -o data.dec" "Decrypt data using YKCS11"
#        else
#          test "pkcs11-tool --module $MODULE --decrypt --pin 123456 --id $s --hash-algorithm SHA$md --mgf MGF1-SHA$mgf -m RSA-PKCS-OAEP -i data.oaep -o data.dec" "Decrypt data using YKCS11"
#        fi
#        test "cmp data.dec data.txt" "Compare decrypted data with plain text data"
#      done
#    done

  done
done

echo "******************* Testing RSA Tests ********************* "
pkcs11-tool --module $MODULE --login --pin 123456  --test

#echo "******************* Testing EC Tests ********************* "
#pkcs11-tool --module $MODULE --login --pin 123456 --login-type so --so-pin 010203040506070801020304050607080102030405060708 --test-ec --id 2 --key-type EC:secp256r1

echo "All tests passed!"

cd ..
rm -rf test_dir

set +e