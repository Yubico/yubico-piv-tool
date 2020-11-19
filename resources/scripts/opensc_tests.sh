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
pkcs11-tool --module $MODULE --login --login-type so --so-pin 010203040506070801020304050607080102030405060708 --keypairgen --id 1 --key-type EC:secp384r1
pkcs11-tool --module $MODULE --login --login-type so --so-pin 010203040506070801020304050607080102030405060708 --keypairgen --id 2 --key-type EC:prime256v1
pkcs11-tool --module $MODULE --login --login-type so --so-pin 010203040506070801020304050607080102030405060708 --keypairgen --id 3 --key-type rsa:1024
pkcs11-tool --module $MODULE --login --login-type so --so-pin 010203040506070801020304050607080102030405060708 --keypairgen --id 4 --key-type rsa:2048

echo "******************* Signing Tests ********************* "
echo "this is test data" > data.txt
pkcs11-tool --module $MODULE --sign --pin 123456 --id 1 -m ECDSA-SHA1 --signature-format openssl -i data.txt -o data.sig
pkcs11-tool --module $MODULE --sign --pin 123456 --id 2 -m ECDSA-SHA1 --signature-format openssl -i data.txt -o data.sig
pkcs11-tool --module $MODULE --sign --pin 123456 --id 3 -i data.txt -o data.sig
pkcs11-tool --module $MODULE --sign --pin 123456 --id 4 -i data.txt -o data.sig
rm data.txt
rm data.sig

echo "******************* Decryption Tests ********************* "
echo "this is test data" > data.txt

pkcs11-tool --module $MODULE --read-object --type cert --id 3 -o 9d_cert.crt
openssl x509 -inform DER -outform PEM -in 9d_cert.crt -out 9d_cert.pem
openssl x509 -in 9d_cert.pem -pubkey -noout > 9d_pubkey.pem

pkcs11-tool --module $MODULE --read-object --type cert --id 4 -o 9e_cert.crt
openssl x509 -inform DER -outform PEM -in 9e_cert.crt -out 9e_cert.pem
openssl x509 -in 9e_cert.pem -pubkey -noout > 9e_pubkey.pem

openssl rsautl -encrypt -oaep -inkey 9d_pubkey.pem -pubin -in data.txt -out data.oaep
pkcs11-tool --module $MODULE --decrypt --pin 123456 --id 3 -m RSA-PKCS-OAEP -i data.oaep
rm data.oaep

openssl rsautl -encrypt -oaep -inkey 9e_pubkey.pem -pubin -in data.txt -out data.oaep
pkcs11-tool --module $MODULE --decrypt --pin 123456 --id 4 -m RSA-PKCS-OAEP -i data.oaep
rm data.oaep

rm 9d_cert.crt 9d_cert.pem 9d_pubkey.pem
rm 9e_cert.crt 9e_cert.pem 9e_pubkey.pem

rm data.txt
echo "******************* Testing RSA Tests ********************* "
pkcs11-tool --module $MODULE --login --pin 123456  --test

echo "******************* Testing EC Tests ********************* "
pkcs11-tool --module $MODULE --login --login-type so --so-pin 010203040506070801020304050607080102030405060708 --test-ec --id 2 --key-type EC:secp256r1