#!/usr/bin/env perl

use Net::SSLeay;

print "Perl version: ", $^V, "\n";
print "Net::SSLeay version: ", $Net::SSLeay::VERSION, "\n";
print "underlying openssl version: ", Net::SSLeay::SSLeay_version(), "\n";
