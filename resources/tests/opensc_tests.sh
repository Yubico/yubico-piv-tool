#!/bin/bash -e
# This is a test script that uses pkcs11-tool command with the specified PKCS#11 module to generate keys on 4 different
# slots using 4 different key algorithms on the YubiKey and then performs a signature with each of these keys.

if [ "$#" -ne 1 ]; then
  echo "This is a test script that uses pkcs11-tool command with the specified PKCS#11 module to generate keys on 4 different
  slots using 4 different key algorithms on the YubiKey and then performs a signature with each of these keys."
  echo ""
  echo "      Usage: ./opensc_tests.sh <path to PKCS11 module>"
  exit
fi

set -e
set -x

MODULE=$1

echo "******************* Generation Tests ********************* "
pkcs11-tool --module $MODULE --login --login-type so --so-pin 010203040506070801020304050607080102030405060708 --keypairgen --id 1 --key-type EC:secp384r1
pkcs11-tool --module $MODULE --login --login-type so --so-pin 010203040506070801020304050607080102030405060708 --keypairgen --id 2 --key-type EC:prime256v1
pkcs11-tool --module $MODULE --login --login-type so --so-pin 010203040506070801020304050607080102030405060708 --keypairgen --id 3 --key-type rsa:1024
pkcs11-tool --module $MODULE --login --login-type so --so-pin 010203040506070801020304050607080102030405060708 --keypairgen --id 4 --key-type rsa:2048
pkcs11-tool --module $MODULE --login --login-type so --so-pin 010203040506070801020304050607080102030405060708 --keypairgen --id 5 --key-type rsa:3072
pkcs11-tool --module $MODULE --login --login-type so --so-pin 010203040506070801020304050607080102030405060708 --keypairgen --id 6 --key-type rsa:4096

pkcs11-tool --module $MODULE --read-object --type cert --id 1 -o 1_cert.der
openssl x509 -inform DER -outform PEM -in 1_cert.der -out 1_cert.pem
openssl x509 -in 1_cert.pem -pubkey -noout > 1_pubkey.pem

pkcs11-tool --module $MODULE --read-object --type cert --id 2 -o 2_cert.der
openssl x509 -inform DER -outform PEM -in 2_cert.der -out 2_cert.pem
openssl x509 -in 2_cert.pem -pubkey -noout > 2_pubkey.pem

pkcs11-tool --module $MODULE --read-object --type cert --id 3 -o 3_cert.der
openssl x509 -inform DER -outform PEM -in 3_cert.der -out 3_cert.pem
openssl x509 -in 3_cert.pem -pubkey -noout > 3_pubkey.pem

pkcs11-tool --module $MODULE --read-object --type cert --id 4 -o 4_cert.der
openssl x509 -inform DER -outform PEM -in 4_cert.der -out 4_cert.pem
openssl x509 -in 4_cert.pem -pubkey -noout > 4_pubkey.pem

pkcs11-tool --module $MODULE --read-object --type cert --id 5 -o 5_cert.der
openssl x509 -inform DER -outform PEM -in 5_cert.der -out 5_cert.pem
openssl x509 -in 5_cert.pem -pubkey -noout > 5_pubkey.pem

pkcs11-tool --module $MODULE --read-object --type cert --id 6 -o 6_cert.der
openssl x509 -inform DER -outform PEM -in 6_cert.der -out 6_cert.pem
openssl x509 -in 6_cert.pem -pubkey -noout > 6_pubkey.pem

echo "******************* Signing Tests ********************* "
echo "this is test data" > data.txt

pkcs11-tool --module $MODULE --sign --pin 123456 --id 1 -m ECDSA-SHA1 --signature-format openssl -i data.txt -o data.sig
openssl dgst -sha1 -verify 1_pubkey.pem -signature data.sig data.txt
pkcs11-tool --module $MODULE --sign --pin 123456 --id 2 -m ECDSA-SHA1 --signature-format openssl -i data.txt -o data.sig
openssl dgst -sha1 -verify 2_pubkey.pem -signature data.sig data.txt

pkcs11-tool --module $MODULE --sign -m SHA1-RSA-PKCS --pin 123456 --id 3 -i data.txt -o data.sig
openssl dgst -sha1 -verify 3_pubkey.pem -signature data.sig data.txt
pkcs11-tool --module $MODULE --sign -m SHA1-RSA-PKCS --pin 123456 --id 4 -i data.txt -o data.sig
openssl dgst -sha1 -verify 4_pubkey.pem -signature data.sig data.txt
pkcs11-tool --module $MODULE --sign -m SHA1-RSA-PKCS --pin 123456 --id 5 -i data.txt -o data.sig
openssl dgst -sha1 -verify 5_pubkey.pem -signature data.sig data.txt
pkcs11-tool --module $MODULE --sign -m SHA1-RSA-PKCS --pin 123456 --id 6 -i data.txt -o data.sig
openssl dgst -sha1 -verify 6_pubkey.pem -signature data.sig data.txt
rm data.sig

echo "******************* Decryption Tests ********************* "

openssl pkeyutl -encrypt -pubin -inkey 3_pubkey.pem -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256 -in data.txt -out data.oaep
pkcs11-tool --module $MODULE --decrypt --pin 123456 --id 3 -m RSA-PKCS-OAEP -i data.oaep
rm data.oaep

openssl pkeyutl -encrypt -pubin -inkey 4_pubkey.pem -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256 -in data.txt -out data.oaep
pkcs11-tool --module $MODULE --decrypt --pin 123456 --id 4 -m RSA-PKCS-OAEP -i data.oaep
rm data.oaep

openssl pkeyutl -encrypt -pubin -inkey 5_pubkey.pem -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256 -in data.txt -out data.oaep
pkcs11-tool --module $MODULE --decrypt --pin 123456 --id 5 -m RSA-PKCS-OAEP -i data.oaep
rm data.oaep

openssl pkeyutl -encrypt -pubin -inkey 6_pubkey.pem -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256 -in data.txt -out data.oaep
pkcs11-tool --module $MODULE --decrypt --pin 123456 --id 6 -m RSA-PKCS-OAEP -i data.oaep
rm data.oaep

rm 1_cert.der 1_cert.pem 1_pubkey.pem
rm 2_cert.der 2_cert.pem 2_pubkey.pem
rm 3_cert.der 3_cert.pem 3_pubkey.pem
rm 4_cert.der 4_cert.pem 4_pubkey.pem
rm 5_cert.der 5_cert.pem 5_pubkey.pem
rm 6_cert.der 6_cert.pem 6_pubkey.pem

rm data.txt
echo "******************* Testing RSA Tests ********************* "
pkcs11-tool --module $MODULE --login --pin 123456  --test

#echo "******************* Testing EC Tests ********************* "
#pkcs11-tool --module $MODULE --login --pin 123456 --login-type so --so-pin 010203040506070801020304050607080102030405060708 --test-ec --id 2 --key-type EC:secp256r1

set +x
set +e