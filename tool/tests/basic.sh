#!/bin/bash

# Copyright (c) 2014-2016 Yubico AB
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#
#   * Redistributions in binary form must reproduce the above
#     copyright notice, this list of conditions and the following
#     disclaimer in the documentation and/or other materials provided
#     with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# This is a _very_ simple test shell script, really only verifying
#  that we managed to build a binary and it can execute.

set -e

BIN="../yubico-piv-tool${EXEEXT}"
ROOT_MAKEFILE="../../Makefile"

HELP_OUTPUT=$($BIN --help)

expected="yubico-piv-tool $VERSION"
VERSION_OUTPUT=$($BIN --version | sed 's/\r//')
if [ "x$VERSION_OUTPUT" != "x$expected" ]; then
  echo "Version ($VERSION_OUTPUT) not matching expected output $expected."
  exit 1
fi


################################################################################
################################################################################
#                            HARDWARE TESTS
################################################################################
################################################################################
#
# Tests below here require a Yubikey to be connected.
# These tests are destructive.
#
################################################################################
################################################################################

# Verify that --enable-hardware-tests was a build flag.
! $(set -e && cat "$ROOT_MAKEFILE" |grep "^DEFS =" | grep -- "-DHW_TESTS" >/dev/null)
HW_TESTS=$?
if [[ $HW_TESTS -eq 0 ]]; then
    exit 0
fi

# Verify that user has confirmed destructive hw-tests
if [ "x$YKPIV_ENV_HWTESTS_CONFIRMED" != "x1" ]; then
    printf "\n***\n*** Hardware tests skipped.  Run \"make hwcheck\".\n***\n\n" >&0
    exit 77 # exit code 77 == skipped tests
fi

#
# Run basic import/validation tests on included keys/certs.  Test keys generated
# with the following commands:
#
# $ openssl genrsa -out private.pem 2048
# $ openssl rsa -in private.pem -outform PEM -pubout -out public.pem
# $ openssl req -x509 -key private.pem -out cert.pem -subj "/CN=YubicoTest/OU=YubicoTestUnit/O=yubico.com/" -new
#

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

# Generate key on-board, issue certificate, and verify it
$BIN -agenerate -s9a -AECCP256 -o key_9a.pub
$BIN -averify -P123456 -s9a -S'/CN=YubicoTest/OU=YubicoGenerated/O=yubico.com/' -aselfsign -i key_9a.pub -o cert_9a.pem
$BIN -averify -P123456 -s9a -atest-signature -i cert_9a.pem
$BIN -aimport-certificate -P123456 -s9a -i cert_9a.pem

# Import key, generate self-signed certificate, and verify it
$BIN -aimport-key -P123456 -s9e -iprivate.pem
$BIN -arequest-certificate -s9e -S"/CN=bar/OU=test/O=example.com/" -i public.pem -o req_9e.pem
$BIN -averify -P123456 -s9e -S'/CN=bar/OU=test/O=example.com/' -aselfsign -i public.pem -o cert_9e.pem
$BIN -atest-decipher -s9e -i cert_9e.pem
$BIN -aimport-certificate -P123456 -s9e -i cert.pem


# Read status and validate fields
STATUS=$($BIN -astatus)
echo "$STATUS"
ALGO_9A=$(echo "$STATUS" |grep "Slot 9a" -A 6 |grep "Algorithm" |tr -d "[:blank:]")
if [[ "x$ALGO_9A" != "xAlgorithm:ECCP256" ]]; then
    echo "$ALGO_9A"
    echo "Generated algorithm incorrect." >/dev/stderr
    exit 1
fi

ALGO_9E=$(echo "$STATUS" |grep "Slot 9e" -A 6 |grep "Algorithm" |tr -d "[:blank:]")
if [[ "x$ALGO_9E" != "xAlgorithm:RSA2048" ]]; then
    echo "$ALGO_9E"
    echo "Generated algorithm incorrect." >/dev/stderr
    exit 1
fi

SUBJECT_9A=$(echo "$STATUS" |grep "Slot 9a" -A 6 |grep "Subject DN" |tr -d "[:blank:]")
if [[ "x$SUBJECT_9A" != "xSubjectDN:CN=YubicoTest,OU=YubicoGenerated,O=yubico.com" ]]; then
    echo "$SUBJECT_9A"
    echo "Certificate subject incorrect." >/dev/stderr
    exit 1
fi

SUBJECT_9E=$(echo "$STATUS" |grep "Slot 9e" -A 6 |grep "Subject DN" |tr -d "[:blank:]")
if [[ "x$SUBJECT_9E" != "xSubjectDN:CN=YubicoTest,OU=YubicoTestUnit,O=yubico.com" ]]; then
    echo "$SUBJECT_9E"
    echo "Certificate subject incorrect." >/dev/stderr
    exit 1
fi
