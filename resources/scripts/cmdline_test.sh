#!/bin/bash

# This is a test script that uses the yubico-piv-tool command line tool to reset the conncted YubiKey and then
# generates keys on 4 different slots using 4 different key algorithms and then performs a signature with each
# of these keys.

set +e

mkdir yubico-piv-tool_test_dir; cd yubico-piv-tool_test_dir
echo test signing data > data.txt

BIN="yubico-piv-tool"

$BIN --help

echo "********************** Reset YubiKey ********************* "

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

echo "********************** Generate ECCP256 in 9a ********************* "

# Generate key on-board, issue certificate, and verify it
$BIN -agenerate -s9a -AECCP256 -o key_9a.pub
$BIN -averify -P123456 -s9a -S'/CN=YubicoTestECCP256/OU=YubicoGenerated/O=yubico.com/' -aselfsign -i key_9a.pub -o cert_9a.pem
$BIN -averify -P123456 -s9a -atest-signature -i cert_9a.pem
$BIN -aimport-certificate -P123456 -s9a -i cert_9a.pem

# Read status and validate fields
STATUS=$($BIN -astatus)
echo "$STATUS"
ALGO_9A=$(echo "$STATUS" |grep "Slot 9a" -A 6 |grep "Algorithm" |tr -d "[:blank:]")
if [ "x$ALGO_9A" != "xAlgorithm:ECCP256" ]; then
    echo "$ALGO_9A"
    echo "Generated algorithm incorrect." >/dev/stderr
    exit 1
fi

SUBJECT_9A=$(echo "$STATUS" |grep "Slot 9a" -A 6 |grep "Subject DN" |tr -d "[:blank:]")
if [ "x$SUBJECT_9A" != "xSubjectDN:CN=YubicoTestECCP256,OU=YubicoGenerated,O=yubico.com" ]; then
    echo "$SUBJECT_9A"
    echo "Certificate subject incorrect." >/dev/stderr
    exit 1
fi

$BIN -a verify-pin -P123456 --sign -s 9a -A ECCP256 -i data.txt -o data.sig
exitcode=$?
if [ "$exitcode" != "0" ]; then
    exit $exitcode
fi

echo "********************** Generate ECCP384 in 9c ********************* "

# Generate key on-board, issue certificate, and verify it
$BIN -agenerate -s9c -AECCP384 -o key_9c.pub
$BIN -averify -P123456 -s9c -S'/CN=YubicoTestECCP384/OU=YubicoGenerated/O=yubico.com/' -aselfsign -i key_9c.pub -o cert_9c.pem
$BIN -averify -P123456 -s9c -atest-signature -i cert_9c.pem
$BIN -aimport-certificate -P123456 -s9c -i cert_9c.pem

# Read status and validate fields
STATUS=$($BIN -astatus)
echo "$STATUS"
ALGO_9C=$(echo "$STATUS" |grep "Slot 9c" -A 6 |grep "Algorithm" |tr -d "[:blank:]")
if [ "x$ALGO_9C" != "xAlgorithm:ECCP384" ]; then
    echo "$ALGO_9C"
    echo "Generated algorithm incorrect." >/dev/stderr
    exit 1
fi

SUBJECT_9C=$(echo "$STATUS" |grep "Slot 9c" -A 6 |grep "Subject DN" |tr -d "[:blank:]")
if [ "x$SUBJECT_9C" != "xSubjectDN:CN=YubicoTestECCP384,OU=YubicoGenerated,O=yubico.com" ]; then
    echo "$SUBJECT_9C"
    echo "Certificate subject incorrect." >/dev/stderr
    exit 1
fi

$BIN -a verify-pin -P123456 --sign -s 9c -A ECCP384 -i data.txt -o data.sig
exitcode=$?
if [ "$exitcode" != "0" ]; then
    exit $exitcode
fi

echo "********************** Generate RSA1024 in 9d ********************* "

# Generate key on-board, issue certificate, and verify it
$BIN -agenerate -s9d -ARSA1024 -o key_9d.pub
$BIN -averify -P123456 -s9d -S'/CN=YubicoTestRSA1024/OU=YubicoGenerated/O=yubico.com/' -aselfsign -i key_9d.pub -o cert_9d.pem
$BIN -averify -P123456 -s9d -atest-signature -i cert_9d.pem
$BIN -aimport-certificate -P123456 -s9d -i cert_9d.pem

# Read status and validate fields
STATUS=$($BIN -astatus)
echo "$STATUS"
ALGO_9D=$(echo "$STATUS" |grep "Slot 9d" -A 6 |grep "Algorithm" |tr -d "[:blank:]")
if [ "x$ALGO_9D" != "xAlgorithm:RSA1024" ]; then
    echo "$ALGO_9D"
    echo "Generated algorithm incorrect." >/dev/stderr
    exit 1
fi

SUBJECT_9D=$(echo "$STATUS" |grep "Slot 9d" -A 6 |grep "Subject DN" |tr -d "[:blank:]")
if [ "x$SUBJECT_9D" != "xSubjectDN:CN=YubicoTestRSA1024,OU=YubicoGenerated,O=yubico.com" ]; then
    echo "$SUBJECT_9D"
    echo "Certificate subject incorrect." >/dev/stderr
    exit 1
fi

$BIN -a verify-pin -P123456 --sign -s 9d -A RSA1024 -i data.txt -o data.sig
exitcode=$?
if [ "$exitcode" != "0" ]; then
    exit $exitcode
fi

echo "********************** Generate RSA2048 in 9e ********************* "

# Generate key on-board, issue certificate, and verify it
$BIN -agenerate -s9e -ARSA2048 -o key_9e.pub
$BIN -averify -P123456 -s9e -S'/CN=YubicoTestRSA2048/OU=YubicoGenerated/O=yubico.com/' -aselfsign -i key_9e.pub -o cert_9e.pem
$BIN -averify -P123456 -s9e -atest-signature -i cert_9e.pem
$BIN -aimport-certificate -P123456 -s9e -i cert_9e.pem

# Read status and validate fields
STATUS=$($BIN -astatus)
echo "$STATUS"
ALGO_9E=$(echo "$STATUS" |grep "Slot 9e" -A 6 |grep "Algorithm" |tr -d "[:blank:]")
if [ "x$ALGO_9E" != "xAlgorithm:RSA2048" ]; then
    echo "$ALGO_9E"
    echo "Generated algorithm incorrect." >/dev/stderr
    exit 1
fi

SUBJECT_9E=$(echo "$STATUS" |grep "Slot 9e" -A 6 |grep "Subject DN" |tr -d "[:blank:]")
if [ "x$SUBJECT_9E" != "xSubjectDN:CN=YubicoTestRSA2048,OU=YubicoGenerated,O=yubico.com" ]; then
    echo "$SUBJECT_9E"
    echo "Certificate subject incorrect." >/dev/stderr
    exit 1
fi

$BIN -a verify-pin -P123456 --sign -s 9e -A RSA2048 -i data.txt -o data.sig
exitcode=$?
if [ "$exitcode" != "0" ]; then
    exit $exitcode
fi

cd ..
rm -r yubico-piv-tool_test_dir

set -e