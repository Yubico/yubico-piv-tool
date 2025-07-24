#!/bin/bash
set -u

if [ "$#" -lt 2 ]; then
    echo "This script runs yubico-piv-tool command line tests and requires a YubiKey to be plugged in"
    echo ""
    echo "      Usage: ./cmdline_test.sh <yubico-piv-tool> <ac|acde|all> [ <enc> ]"
    echo ""
    echo "ac|acde|all         Which slots to run tests on: 'ac' runs tests on slots 9a and 9c, 'acde' runs tests on slots 9a, 9c, 9d and 9e, 'all' runs tests on all slots"
    echo "yubico-piv-tool     Path to yubico-piv-tool commandline tool. If it is on PATH, then 'yubico-piv-tool' would be sufficient"
    echo "enc                 Optional! Run the tests over en encrypted channel"
    exit 0
fi

BIN=$1 # path to the yubico-piv-tool command line tool
CMD_SLOTS=$2 # ac|acde|all

echo ""
echo "WARNING! This test script will reset the YubiKey and delete all keys and certificates on it"
echo ""

if [ -e test_dir ]; then
    rm -rf test_dir
fi
mkdir test_dir; cd test_dir
echo test signing data > data.txt

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

echo "**********************************"
echo "            Reset YubiKey"
echo "**********************************"
set +e
$BIN -areset --global 2>&1 > /dev/null # Try to do global reset
global=$?
set -e

if [ $global -ne 0 ]; then
  # Reset
  $BIN -averify-pin -P000000 || true
  $BIN -averify-pin -P000000 || true
  $BIN -averify-pin -P000000 || true
  $BIN -averify-pin -P000000 || true
  $BIN -averify-pin -P000000 || true
  $BIN -achange-puk -P000000 -N00000000 || true
  $BIN -achange-puk -P000000 -N00000000 || true
  $BIN -achange-puk -P000000 -N00000000 || true
  $BIN -achange-puk -P000000 -N00000000 || true
  $BIN -achange-puk -P000000 -N00000000 || true
  $BIN -areset
fi

if [ "$#" -eq 3 ]; then
  BIN="$BIN --scp11" # Enable encrypted channel
fi

SLOTS=('9a' '9c')
if [ "x$CMD_SLOTS" == "xacde" ]; then
  SLOTS=('9a' '9c' '9d' '9e')
elif [ "x$CMD_SLOTS" == "xall" ]; then
  SLOTS=('9a' '9c' '9d' '9e' '82' '83' '84' '85' '86' '87' '88' '89' '8a' '8b' '8c' '8d' '8e' '8f' '90' '91' '92' '93' '94' '95')
fi

set +e
$BIN -agenerate -s9a -A ED25519 2>&1 > /dev/null # Try to generate ED25519 key to see if the YubiKey support 'new' algorithms
newkey=$?
set -e

RSA_KEYSIZE=("1024" "2048")
EC_ALGOS=("ECCP256" "ECCP384")
EC_CURVES=("prime256v1" "secp384r1")
HASH_SIZES=("1" "256" "384" "512")

if [ $newkey -eq 0 ]; then
  RSA_KEYSIZE=(${RSA_KEYSIZE[@]} "3072" "4096")
fi

for i in "${!EC_ALGOS[@]}"; do

  k=${EC_ALGOS[i]}
  c=${EC_CURVES[i]}

  echo "**********************************"
  echo "            $k"
  echo "**********************************"

  for slot in ${SLOTS[@]}; do
    echo "=== Generate key in slot $slot"
    test "$BIN -agenerate -s$slot -A$k -o pubkey.pem" "Generate key"
    $BIN -averify-pin -P123456 -s$slot -S'/CN=YubicoTest/OU=YubicoGeneratedECKey/O=yubico.com/' -aselfsign -i pubkey.pem -o cert.pem
    test "$BIN -aimport-certificate -P123456 -s$slot -i cert.pem" "Import certificate"
    test "$BIN -aread-public-key -s$slot -o pubkey_gen.pub" "Get public key"
    test "cmp pubkey.pem pubkey_gen.pub" "Compare generated and retrieved public key"
    test "$BIN -averify-pin -P123456 -s$slot -atest-signature -i cert.pem" "Test signature"
    test "$BIN -averify-pin -P123456 -s$slot -a test-decipher -i cert.pem" "Test decryption"
    test "$BIN -aattest -s$slot" "Attest private key"

    # Read status and validate fields
    STATUS=$($BIN -astatus)
    echo "$STATUS"
    ALGO=$(echo "$STATUS" |grep "Slot $slot" -A 6 |grep "Public Key Algorithm" |tr -d "[:blank:]")
    if [ "x$ALGO" != "xPublicKeyAlgorithm:$k" ]; then
      echo "$ALGO"
      echo "Generated algorithm incorrect." >/dev/stderr
      exit 1
    fi

    SUBJECT=$(echo "$STATUS" |grep "Slot $slot" -A 6 |grep "Subject DN" |tr -d "[:blank:]")
    if [ "x$SUBJECT" != "xSubjectDN:CN=YubicoTest,OU=YubicoGeneratedECKey,O=yubico.com" ]; then
      echo "$SUBJECT"
      echo "Certificate subject incorrect." >/dev/stderr
      exit 1
    fi

    echo "=== Signing with generated key:"
    for h in ${HASH_SIZES[@]}; do
      test "$BIN -a verify-pin -P123456 --sign -s $slot -A $k -H SHA$h -i data.txt -o data.sig" "Sign with ECDSA-SHA$h"
      test "openssl dgst -sha$h -verify pubkey.pem -signature data.sig data.txt" "Verify signature"
    done

    echo "=== Import key into slot $slot"
    openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:$c -x509 -nodes -days 365 -subj "/CN=OpenSSLGeneratedECKey/" -out cert.pem -keyout key.pem
    test "$BIN -aimport-key -s$slot -i key.pem" "Import private key"
    test "$BIN -aimport-certificate -s$slot -i cert.pem" "Import certificate"
    test "$BIN -aread-public-key -s$slot -o pubkey.pem" "Get public key"
    test "$BIN -averify-pin -P123456 -s$slot -a test-signature -i cert.pem" "Test signature"
    test "$BIN -averify-pin -P123456 -s$slot -a test-decipher -i cert.pem" "Test decryption"

    # Read status and validate fields
    STATUS=$($BIN -astatus)
    echo "$STATUS"
    ALGO=$(echo "$STATUS" |grep "Slot $slot" -A 6 |grep "Public Key Algorithm" |tr -d "[:blank:]")
    if [ "x$ALGO" != "xPublicKeyAlgorithm:$k" ]; then
      echo "$ALGO"
      echo "Generated algorithm incorrect." >/dev/stderr
      exit 1
    fi

    SUBJECT=$(echo "$STATUS" |grep "Slot $slot" -A 6 |grep "Subject DN" |tr -d "[:blank:]")
    if [ "x$SUBJECT" != "xSubjectDN:CN=OpenSSLGeneratedECKey" ]; then
      echo "$SUBJECT"
      echo "Certificate subject incorrect." >/dev/stderr
      exit 1
    fi

    echo "=== Signing with imported key:"
    for h in ${HASH_SIZES[@]}; do
      test "$BIN -a verify-pin -P123456 --sign -s $slot -A $k -H SHA$h -i data.txt -o data.sig" "Sign with ECDSA-SHA$h"
      test "openssl dgst -sha$h -verify pubkey.pem -signature data.sig data.txt" "Verify signature"
    done

    if [ $newkey -eq 0 ]; then
      echo "=== Clean up:"
      test "$BIN -a delete-key -s $slot" "Delete private key"
    fi
  done
done

if [ $newkey -eq 0 ]; then

  echo "**********************************"
  echo "            ED25519"
  echo "**********************************"

  for slot in ${SLOTS[@]}; do

    echo "=== Generate key in slot $slot"
    test "$BIN -agenerate -s$slot -A ED25519 -o pubkey.pem" "Generate key"
    $BIN -averify-pin -P123456 -s$slot -S'/CN=YubicoTest/OU=YubicoGeneratedEDKey/O=yubico.com/' -aselfsign -i pubkey.pem -o cert.pem
    test "$BIN -aimport-certificate -P123456 -s$slot -i cert.pem" "Import certificate"
    test "$BIN -aread-public-key -s$slot -o pubkey_gen.pub" "Get public key"
    test "cmp pubkey.pem pubkey_gen.pub" "Compare generated and retrieved public key"
    test "$BIN -averify-pin -P123456 -s$slot -atest-signature -i cert.pem" "Test signature"
    test "$BIN -aattest -s$slot -i $slot.pem" "Attest private key"

    # Read status and validate fields
    STATUS=$($BIN -astatus)
    echo "$STATUS"
    ALGO=$(echo "$STATUS" |grep "Slot $slot" -A 6 |grep "Public Key Algorithm" |tr -d "[:blank:]")
    if [ "x$ALGO" != "xPublicKeyAlgorithm:ED25519" ]; then
      echo "$ALGO"
      echo "Generated algorithm incorrect." >/dev/stderr
      exit 1
    fi

    SUBJECT=$(echo "$STATUS" |grep "Slot $slot" -A 6 |grep "Subject DN" |tr -d "[:blank:]")
    if [ "x$SUBJECT" != "xSubjectDN:CN=YubicoTest,OU=YubicoGeneratedEDKey,O=yubico.com" ]; then
      echo "$SUBJECT"
      echo "Certificate subject incorrect." >/dev/stderr
      exit 1
    fi

    echo "=== Signing with generated key:"
    test "$BIN -a verify-pin -P123456 --sign -s $slot -A ED25519 -i data.txt -o data.sig" "Sign with ED25519 key"
    test "openssl pkeyutl -verify -pubin -inkey pubkey.pem -rawin -in data.txt -sigfile data.sig" "Verify signature with OpenSSL"
    rm *.sig

    echo "=== Import key into slot $slot"
    test "openssl genpkey -algorithm ED25519 -out key.pem" "Generate ED25519 private key with OpenSSL"
    openssl req -new -out csr.pem -key key.pem  -subj "/CN=OpenSSLGeneratedEDKey/"
    test "openssl x509 -req -days 365 -in csr.pem -signkey key.pem -out cert.pem" "Sign certificate with OpenSSL"
    test "$BIN -aimport-key -s$slot -i key.pem" "Import private key"
    test "$BIN -aimport-certificate -s$slot -i cert.pem" "Import certificate"
    test "$BIN -aread-public-key -s$slot -o pubkey.pem" "Get public key"
    test "$BIN -averify-pin -P123456 -s$slot -a test-signature -i cert.pem" "Test signature"

    # Read status and validate fields
    STATUS=$($BIN -astatus)
    echo "$STATUS"
    ALGO=$(echo "$STATUS" |grep "Slot $slot" -A 6 |grep "Public Key Algorithm" |tr -d "[:blank:]")
    if [ "x$ALGO" != "xPublicKeyAlgorithm:ED25519" ]; then
      echo "$ALGO"
      echo "Generated algorithm incorrect." >/dev/stderr
      exit 1
    fi

    SUBJECT=$(echo "$STATUS" |grep "Slot $slot" -A 6 |grep "Subject DN" |tr -d "[:blank:]")
    if [ "x$SUBJECT" != "xSubjectDN:CN=OpenSSLGeneratedEDKey" ]; then
      echo "$SUBJECT"
      echo "Certificate subject incorrect." >/dev/stderr
      exit 1
    fi

    echo "=== Signing with imported key:"
    test "$BIN -a verify-pin -P123456 --sign -s $slot -A ED25519 -i data.txt -o data.sig" "Sign with ED25519 key"
    test "openssl pkeyutl -verify -pubin -inkey pubkey.pem -rawin -in data.txt -sigfile data.sig" "Verify signature with OpenSSL"

    if [ $newkey -eq 0 ]; then
      echo "=== Clean up:"
      test "$BIN -a delete-key -s $slot" "Delete private key"
    fi

  done
fi

for k in ${RSA_KEYSIZE[@]}; do

  echo "**********************************"
  echo "            RSA$k"
  echo "**********************************"

  for slot in ${SLOTS[@]}; do

    echo "=== Generate key in slot $slot"
    test "$BIN -agenerate -s$slot -ARSA$k -o pubkey.pem" "Generate key"
    $BIN -averify-pin -P123456 -s$slot -S'/CN=YubicoTest/OU=YubicoGeneratedRSAKey/O=yubico.com/' -aselfsign -i pubkey.pem -o cert.pem
    test "$BIN -aimport-certificate -P123456 -s$slot -i cert.pem" "Import certificate"
    test "$BIN -aread-public-key -s$slot -o pubkey_gen.pem" "Get public key"
    test "cmp pubkey.pem pubkey_gen.pem" "Compare generated and retrieved public key"
    test "$BIN -averify-pin -P123456 -s$slot -a test-signature -i cert.pem" "Test signature"
    test "$BIN -averify-pin -P123456 -s$slot -a test-decipher -i cert.pem" "Test decryption"
    test "$BIN -a attest -s$slot -i $slot.pem" "Attest private key"

    # Read status and validate fields
    STATUS=$($BIN -astatus)
    echo "$STATUS"
    ALGO=$(echo "$STATUS" |grep "Slot $slot" -A 6 |grep "Public Key Algorithm" |tr -d "[:blank:]")
    if [ "x$ALGO" != "xPublicKeyAlgorithm:RSA$k" ]; then
      echo "$ALGO"
      echo "Generated algorithm incorrect." >/dev/stderr
      exit 1
    fi

    SUBJECT=$(echo "$STATUS" |grep "Slot $slot" -A 6 |grep "Subject DN" |tr -d "[:blank:]")
    if [ "x$SUBJECT" != "xSubjectDN:CN=YubicoTest,OU=YubicoGeneratedRSAKey,O=yubico.com" ]; then
      echo "$SUBJECT"
      echo "Certificate subject incorrect." >/dev/stderr
      exit 1
    fi

    echo "=== Signing with generated key:"
    for h in ${HASH_SIZES[@]}; do
      test "$BIN -a verify-pin -P123456 --sign -s $slot -A RSA$k -H SHA$h -i data.txt -o data.sig" "Sign with SHA$h-RSA-PKCS"
      test "openssl dgst -sha$h -verify pubkey.pem -signature data.sig data.txt" "Verify signature"
    done

    echo "=== Import key into slot $slot"
    openssl req -newkey rsa:$k -keyout key.pem -nodes -x509 -days 365 -subj "/CN=OpenSSLGeneratedRSAKey/" -out cert.pem
    test "$BIN -aimport-key -s$slot -i key.pem" "Import private key"
    test "$BIN -aimport-certificate -s$slot -i cert.pem" "Import certificate"
    test "$BIN -aread-public-key -s$slot -o pubkey.pem" "Get public key"
    test "$BIN -averify-pin -P123456 -s$slot -a test-signature -i cert.pem" "Test signature"
    test "$BIN -averify-pin -P123456 -s$slot -a test-decipher -i cert.pem" "Test decryption"

    # Read status and validate fields
    STATUS=$($BIN -astatus)
    echo "$STATUS"
    ALGO=$(echo "$STATUS" |grep "Slot $slot" -A 6 |grep "Public Key Algorithm" |tr -d "[:blank:]")
    if [ "x$ALGO" != "xPublicKeyAlgorithm:RSA$k" ]; then
      echo "$ALGO"
      echo "Generated algorithm incorrect." >/dev/stderr
      exit 1
    fi

    SUBJECT=$(echo "$STATUS" |grep "Slot $slot" -A 6 |grep "Subject DN" |tr -d "[:blank:]")
    if [ "x$SUBJECT" != "xSubjectDN:CN=OpenSSLGeneratedRSAKey" ]; then
      echo "$SUBJECT"
      echo "Certificate subject incorrect." >/dev/stderr
      exit 1
    fi

    echo "=== Signing with imported key:"
    for h in ${HASH_SIZES[@]}; do
    test "$BIN -a verify-pin -P123456 --sign -s $slot -A RSA$k -H SHA$h -i data.txt -o data.sig" "Sign with SHA$h-RSA-PKCS"
    test "openssl dgst -sha$h -verify pubkey.pem -signature data.sig data.txt" "Verify signature"
    done

    if [ $newkey -eq 0 ]; then
      echo "=== Clean up:"
      test "$BIN -a delete-key -s $slot" "Delete private key"
    fi

  done
done

echo "****************************************************"
echo "         Compress X509 Certificate"
echo "****************************************************"

openssl req -x509 -newkey rsa:4096 -out too_large_cert.pem -sha256 -days 3650 -nodes -subj '/C=01/ST=01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567/L=01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567/O=0123456789012345678901234567890123456789012345678901234567890123/OU=0123456789012345678901234567890123456789012345678901234567890123/CN=0123456789012345678901234567890123456789012345678901234567890123/CN=0123456789012345678901234567890123456789012345678901234567890123' > /dev/null 2>&1
test "$BIN -aimport-certificate -s9a --compress -i too_large_cert.pem" "Import compressed certificate"
test "$BIN -aread-certificate -s9a -o too_large_cert_out.pem" "Read compressed certificate"
test "cmp too_large_cert.pem too_large_cert_out.pem" "Compare read certificate with the one imported"

echo "All tests passed!"

cd ..
rm -rf test_dir

set +e