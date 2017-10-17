#! /usr/bin/env bash

# Install development dependencies
sudo apt-get update -qq
sudo apt-get install -qq software-properties-common
sudo add-apt-repository -y ppa:yubico/stable
sudo apt-get update -qq && apt-get -qq upgrade
sudo apt-get install -qq \
    autoconf \
    automake \
    gengetopt \
    help2man \
    libpcsclite-dev \
    libssl-dev \
    libtool \
    libykpiv1 \
    pkg-config \
    virtualbox-guest-dkms
