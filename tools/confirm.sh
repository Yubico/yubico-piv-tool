#!/bin/bash

# Output redirected to fd 0 so it can be run from 'make check' scripts.

echo >&0
echo "Hardware tests enabled!" >&0
echo >&0
echo "******* ******* ******* ******* ******* ******* ******* ******* ******* ******* ******* ******* ******* ******* *******" >&0
echo "WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING" >&0
echo "WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING" >&0
echo >&0
echo "******* ******* ******* ******* ******* ******* ******* ******* ******* ******* ******* ******* ******* ******* *******" >&0
echo >&0
echo "                            ALL DATA WILL BE ERASED ON CONNECTED YUBIKEYS                                              " >&0
echo >&0
echo "******* ******* ******* ******* ******* ******* ******* ******* ******* ******* ******* ******* ******* ******* *******" >&0
echo >&0
echo "WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING" >&0
echo "WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING" >&0
echo "******* ******* ******* ******* ******* ******* ******* ******* ******* ******* ******* ******* ******* ******* *******" >&0
echo >&0
echo -n "Are you SURE you wish to proceed?  If so, type 'CONFIRM': " >&0

read CONFIRM
if [[ "x$CONFIRM" != "xCONFIRM" ]]; then
    echo "1"
    exit 1
fi
echo "0"
