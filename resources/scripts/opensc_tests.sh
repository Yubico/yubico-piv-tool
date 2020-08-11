#!/bin/bash

# This is a test script that uses pkcs11-tool command with the specified PKCS#11 module to generate keys on 4 different
# slots using 4 different key algorithms on the YubiKey and then performs a signature with each of these keys.

if [ -z "$1" ]
  then
    echo "Usage: ./opensc_tests.sh <path to PKCS11 module>"
    exit
fi

MODULE=$1

echo "******************* Generation Tests ********************* "
pkcs11-tool --module $MODULE --login --login-type so --keypairgen --id 1 --key-type EC:secp384r1
pkcs11-tool --module $MODULE --login --login-type so --keypairgen --id 2 --key-type EC:prime256v1
pkcs11-tool --module $MODULE --login --login-type so --keypairgen --id 3 --key-type rsa:1024
pkcs11-tool --module $MODULE --login --login-type so --keypairgen --id 4 --key-type rsa:2048

echo "******************* Signing Tests ********************* "
echo "this is test data" > data.txt
pkcs11-tool --module $MODULE --sign --id 1 -m ECDSA-SHA1 --signature-format openssl -i data.txt -o data.sig
pkcs11-tool --module $MODULE --sign --id 2 -m ECDSA-SHA1 --signature-format openssl -i data.txt -o data.sig
pkcs11-tool --module $MODULE --sign --id 3 -i data.txt -o data.sig
pkcs11-tool --module $MODULE --sign --id 4 -i data.txt -o data.sig
rm data.txt
rm data.sig

echo "******************* Testing RSA Tests ********************* "
pkcs11-tool --module $MODULE --login  --test

echo "******************* Testing EC Tests ********************* "
pkcs11-tool --module $MODULE --login --login-type so --test-ec --id 2 --key-type EC:secp256r1