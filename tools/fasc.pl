#!/usr/bin/perl

# Copyright (c) 2014 Yubico AB
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

# This little perl program takes an input like:
#  S9999F9999F999999F0F1F0000000000300001E
# and outputs that in hex, encoded in the 5-bit form described in
# "Technical Implementation Guidance: Smart Card Enabled Physical Access
#  Control Systems"

use strict;
use Bit::Vector;

my %encoding = (
  0 => "00001",
  1 => "10000",
  2 => "00100",
  3 => "00111",
  4 => "01000",
  5 => "01011",
  6 => "01101",
  7 => "01110",
  8 => "10000",
  9 => "10011",
  S => "11010", # the examples and definitions of S and F differ
  F => "10110", # but we'll go with the examples here..
  E => "11111",
);

my $in = shift;

my @ones = (0, 0, 0, 0);

my $bits;
foreach my $char (split(//, $in)) {
  my $enc = $encoding{$char};
  for(my $i = 0; $i < 4; $i++) {
    my $char = substr($enc, $i, 1);
    if($char eq '1') {
      $ones[$i]++;
    }
  }
  $bits .= $enc;
}
my $lrc = "";
my $lrc_one = 0;
foreach my $one (@ones) {
  if($one % 2 == 0) {
    $lrc .= '0';
  } else {
    $lrc .= '1';
    $lrc_one++;
  }
}
if($lrc_one % 2 == 0) {
  $lrc .= '1';
} else {
  $lrc .= '0';
}
$bits .= $lrc;

my $vector = Bit::Vector->new(200);
$vector->from_Bin($bits);
my $hex = $vector->to_Hex();
for(my $i = 0; $i < length($hex); $i += 2) {
  print "0x" . substr($hex, $i , 2) . ", ";
}

print "\n";
