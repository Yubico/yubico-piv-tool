#!/usr/bin/perl

# Copyright (c) 2014 Yubico AB
# All rights reserved.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#
# Additional permission under GNU GPL version 3 section 7
#
# If you modify this program, or any covered work, by linking or
# combining it with the OpenSSL project's OpenSSL library (or a
# modified version of that library), containing parts covered by the
# terms of the OpenSSL or SSLeay licenses, We grant you additional 
# permission to convey the resulting work. Corresponding Source for a
# non-source form of such a combination shall include the source code
# for the parts of OpenSSL used as well as that of the covered work.

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
  S => "10110",
  F => "11010",
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
__END__

for(my $i = 0; $i < length($in); $i += 8) {
  my $part = substr($in, $i, $i + 8);
  my $bits = "0b";
  foreach my $char (split(//, $part)) {
    $bits .= $encoding{$char};
  }

  my $num = eval($bits);
  warn $num;
}
