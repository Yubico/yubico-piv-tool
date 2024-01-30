#!/bin/bash

# This is a test script that uses the yubico-piv-tool command line tool to reset the conncted YubiKey and then
# generates keys on 4 different slots using 4 different key algorithms and then performs a signature with each
# of these keys.

if [ "$#" -ne 1 ]; then
  BIN="yubico-piv-tool"
else
  BIN=$1 # path to the yubico-piv-tool command line tool
fi


SLOTS=('9a' '9c' '9d' '9e' '82' '83' '84' '85' '86' '87' '88' '89' '8a' '8b' '8c' '8d' '8e' '8f' '90' '91' '92' '93' '94' '95')

set -e
#set -x

if [ -e yubico-piv-tool_test_dir ];
then
    rm -rf yubico-piv-tool_test_dir
fi

mkdir yubico-piv-tool_test_dir; cd yubico-piv-tool_test_dir
echo test signing data > data.txt

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

echo "********************** Generate ECCP256 in all slots ********************* "

for slot in "${SLOTS[@]}"
do
  echo "Generating ECCP256 on slot $slot"
  $BIN -agenerate -s $slot -AECCP256 -o key.pub
  $BIN -averify -P123456 -s$slot -S'/CN=YubicoTestECCP256/OU=YubicoGenerated/O=yubico.com/' --valid-days '5' -aselfsign -i key.pub -o cert.pem
  $BIN -averify -P123456 -s$slot -atest-signature -i cert.pem
  $BIN -aimport-certificate -P123456 -s$slot -i cert.pem

  # Read status and validate fields
  STATUS=$($BIN -astatus)
  echo "$STATUS"
  ALGO=$(echo "$STATUS" |grep "Slot $slot" -A 6 |grep "Algorithm" |tr -d "[:blank:]")
  if [ "x$ALGO" != "xAlgorithm:ECCP256" ]; then
    echo "$ALGO"
    echo "Generated algorithm incorrect." >/dev/stderr
    exit 1
  fi

  SUBJECT=$(echo "$STATUS" |grep "Slot $slot" -A 6 |grep "Subject DN" |tr -d "[:blank:]")
  if [ "x$SUBJECT" != "xSubjectDN:CN=YubicoTestECCP256,OU=YubicoGenerated,O=yubico.com" ]; then
    echo "$SUBJECT"
    echo "Certificate subject incorrect." >/dev/stderr
    exit 1
  fi

  $BIN -a verify-pin -P123456 --sign -s $slot -A ECCP256 -i data.txt -o data.sig
done


echo "********************** Generate ECCP384 in all ********************* "

for slot in "${SLOTS[@]}"
do
  # Generate key on-board, issue certificate, and verify it
  $BIN -agenerate -s$slot -AECCP384 -o key.pub
  $BIN -averify -P123456 -s$slot -S'/CN=YubicoTestECCP384/OU=YubicoGenerated/O=yubico.com/' -aselfsign -i key.pub -o cert.pem
  $BIN -averify -P123456 -s$slot -atest-signature -i cert.pem
  $BIN -aimport-certificate -P123456 -s$slot -i cert.pem

  # Read status and validate fields
  STATUS=$($BIN -astatus)
  echo "$STATUS"
  ALGO=$(echo "$STATUS" |grep "Slot $slot" -A 6 |grep "Algorithm" |tr -d "[:blank:]")
  if [ "x$ALGO" != "xAlgorithm:ECCP384" ]; then
    echo "$ALGO"
    echo "Generated algorithm incorrect." >/dev/stderr
    exit 1
  fi

  SUBJECT=$(echo "$STATUS" |grep "Slot $slot" -A 6 |grep "Subject DN" |tr -d "[:blank:]")
  if [ "x$SUBJECT" != "xSubjectDN:CN=YubicoTestECCP384,OU=YubicoGenerated,O=yubico.com" ]; then
    echo "$SUBJECT"
    echo "Certificate subject incorrect." >/dev/stderr
    exit 1
  fi

  $BIN -a verify-pin -P123456 --sign -s $slot -A ECCP384 -i data.txt -o data.sig
done

echo "********************** Generate RSA1024 in all slots ********************* "

for slot in "${SLOTS[@]}"
do
  # Generate key on-board, issue certificate, and verify it
  $BIN -agenerate -s$slot -ARSA1024 -o key.pub
  $BIN -averify -P123456 -s$slot -S'/CN=YubicoTestRSA1024/OU=YubicoGenerated/O=yubico.com/' -aselfsign -i key.pub -o cert.pem
  $BIN -averify -P123456 -s$slot -atest-signature -i cert.pem
  $BIN -aimport-certificate -P123456 -s$slot -i cert.pem

  # Read status and validate fields
  STATUS=$($BIN -astatus)
  echo "$STATUS"
  ALGO=$(echo "$STATUS" |grep "Slot $slot" -A 6 |grep "Algorithm" |tr -d "[:blank:]")
  if [ "x$ALGO" != "xAlgorithm:RSA1024" ]; then
    echo "$ALGO"
    echo "Generated algorithm incorrect." >/dev/stderr
    exit 1
  fi

  SUBJECT=$(echo "$STATUS" |grep "Slot $slot" -A 6 |grep "Subject DN" |tr -d "[:blank:]")
  if [ "x$SUBJECT" != "xSubjectDN:CN=YubicoTestRSA1024,OU=YubicoGenerated,O=yubico.com" ]; then
    echo "$SUBJECT"
    echo "Certificate subject incorrect." >/dev/stderr
    exit 1
  fi

  $BIN -a verify-pin -P123456 --sign -s $slot -A RSA1024 -i data.txt -o data.sig
  openssl dgst -sha256 -verify key.pub -signature data.sig data.txt
done

echo "********************** Generate RSA2048 in all slots ********************* "

for slot in "${SLOTS[@]}"
do
  # Generate key on-board, issue certificate, and verify it
  $BIN -agenerate -s$slot -ARSA2048 -o key.pub
  $BIN -averify -P123456 -s$slot -S'/CN=YubicoTestRSA2048/OU=YubicoGenerated/O=yubico.com/' -aselfsign -i key.pub -o cert.pem
  $BIN -averify -P123456 -s$slot -atest-signature -i cert.pem
  $BIN -aimport-certificate -P123456 -s$slot -i cert.pem

  # Read status and validate fields
  STATUS=$($BIN -astatus)
  echo "$STATUS"
  ALGO=$(echo "$STATUS" |grep "Slot $slot" -A 6 |grep "Algorithm" |tr -d "[:blank:]")
  if [ "x$ALGO" != "xAlgorithm:RSA2048" ]; then
    echo "$ALGO"
    echo "Generated algorithm incorrect." >/dev/stderr
    exit 1
  fi

  SUBJECT=$(echo "$STATUS" |grep "Slot $slot" -A 6 |grep "Subject DN" |tr -d "[:blank:]")
  if [ "x$SUBJECT" != "xSubjectDN:CN=YubicoTestRSA2048,OU=YubicoGenerated,O=yubico.com" ]; then
    echo "$SUBJECT"
    echo "Certificate subject incorrect." >/dev/stderr
    exit 1
  fi

  $BIN -a verify-pin -P123456 --sign -s $slot -A RSA2048 -i data.txt -o data.sig
  openssl dgst -sha256 -verify key.pub -signature data.sig data.txt
done

echo "********************** Generate RSA3072 in all slots ********************* "

for slot in "${SLOTS[@]}"
do
  # Generate key on-board, issue certificate, and verify it
  $BIN -agenerate -s$slot -ARSA3072 -o key.pub
  $BIN -averify -P123456 -s$slot -S'/CN=YubicoTestRSA3072/OU=YubicoGenerated/O=yubico.com/' -aselfsign -i key.pub -o cert.pem
  $BIN -averify -P123456 -s$slot -atest-signature -i cert.pem
  $BIN -aimport-certificate -P123456 -s$slot -i cert.pem

  # Read status and validate fields
  STATUS=$($BIN -astatus)
  echo "$STATUS"
  ALGO=$(echo "$STATUS" |grep "Slot $slot" -A 6 |grep "Algorithm" |tr -d "[:blank:]")
  if [ "x$ALGO" != "xAlgorithm:RSA3072" ]; then
    echo "$ALGO"
    echo "Generated algorithm incorrect." >/dev/stderr
    exit 1
  fi

  SUBJECT=$(echo "$STATUS" |grep "Slot $slot" -A 6 |grep "Subject DN" |tr -d "[:blank:]")
  if [ "x$SUBJECT" != "xSubjectDN:CN=YubicoTestRSA3072,OU=YubicoGenerated,O=yubico.com" ]; then
    echo "$SUBJECT"
    echo "Certificate subject incorrect." >/dev/stderr
    exit 1
  fi

  $BIN -a verify-pin -P123456 --sign -s $slot -A RSA3072 -i data.txt -o data.sig
  openssl dgst -sha256 -verify key.pub -signature data.sig data.txt
done

echo "********************** Generate RSA4096 in all slots ********************* "

for slot in "${SLOTS[@]}"
do
  # Generate key on-board, issue certificate, and verify it
  $BIN -agenerate -s$slot -ARSA4096 -o key.pub
  $BIN -averify -P123456 -s$slot -S'/CN=YubicoTestRSA4096/OU=YubicoGenerated/O=yubico.com/' -aselfsign -i key.pub -o cert.pem
  $BIN -averify -P123456 -s$slot -atest-signature -i cert.pem
  $BIN -aimport-certificate -P123456 -s$slot -i cert.pem

  # Read status and validate fields
  STATUS=$($BIN -astatus)
  echo "$STATUS"
  ALGO=$(echo "$STATUS" |grep "Slot $slot" -A 6 |grep "Algorithm" |tr -d "[:blank:]")
  if [ "x$ALGO" != "xAlgorithm:RSA4096" ]; then
    echo "$ALGO"
    echo "Generated algorithm incorrect." >/dev/stderr
    exit 1
  fi

  SUBJECT=$(echo "$STATUS" |grep "Slot $slot" -A 6 |grep "Subject DN" |tr -d "[:blank:]")
  if [ "x$SUBJECT" != "xSubjectDN:CN=YubicoTestRSA4096,OU=YubicoGenerated,O=yubico.com" ]; then
    echo "$SUBJECT"
    echo "Certificate subject incorrect." >/dev/stderr
    exit 1
  fi

  $BIN -a verify-pin -P123456 --sign -s $slot -A RSA4096 -i data.txt -o data.sig
  openssl dgst -sha256 -verify key.pub -signature data.sig data.txt
done

echo "********************** Generate ED25519 in all slots ********************* "

for slot in "${SLOTS[@]}"
do
  # Generate key on-board, issue certificate, and verify it
  $BIN -agenerate -s$slot -AED25519 -o key.pub
  $BIN -averify -P123456 -s$slot -S'/CN=YubicoTestED25519/OU=YubicoGenerated/O=yubico.com/' -aselfsign -i key.pub -o cert.pem
  $BIN -aimport-certificate -P123456 -s$slot -i cert.pem

  # Read status and validate fields
  STATUS=$($BIN -astatus)
  echo "$STATUS"
  ALGO=$(echo "$STATUS" |grep "Slot $slot" -A 6 |grep "Algorithm" |tr -d "[:blank:]")
  if [ "x$ALGO" != "xAlgorithm:ED25519" ]; then
    echo "$ALGO"
    echo "Generated algorithm incorrect." >/dev/stderr
    exit 1
  fi

  SUBJECT=$(echo "$STATUS" |grep "Slot $slot" -A 6 |grep "Subject DN" |tr -d "[:blank:]")
  if [ "x$SUBJECT" != "xSubjectDN:CN=YubicoTestED25519,OU=YubicoGenerated,O=yubico.com" ]; then
    echo "$SUBJECT"
    echo "Certificate subject incorrect." >/dev/stderr
    exit 1
  fi

  $BIN -a verify-pin -P123456 --sign -s $slot -A ED25519 -i data.txt -o data.sig
  openssl pkeyutl -verify -pubin -inkey key.pub -rawin -in data.txt -sigfile data.sig
done



cd ..
rm -r yubico-piv-tool_test_dir

#set +x
set +e