#!/usr/bin/env perl

# the goal is to have this be as close as possible to how swaks verifies certs internally so that we can evaluate that without
# needing an entire swaks run

use strict;
use Net::SSLeay;

my $certName = shift;
my $caFile   = shift;

my $certbio = Net::SSLeay::BIO_new_file($certName, 'r');
my $cert = Net::SSLeay::PEM_read_bio_X509($certbio);
Net::SSLeay::BIO_free($certbio);
if (!$cert) {
	die "unable to read $caFile\n";
}

$certbio = Net::SSLeay::BIO_new_file($caFile, 'r');
my $ca = Net::SSLeay::PEM_read_bio_X509($certbio);
Net::SSLeay::BIO_free($certbio);
if (!$ca) {
	die "unable to read $caFile\n";
}

my $store = Net::SSLeay::X509_STORE_new();
if (!$store) {
	die "Error creating X509_STORE object\n";
}
if ($caFile) {
	if (!Net::SSLeay::X509_STORE_add_cert($store, $ca)) {
		die "Error loading CA cert or chain file\n";
	}
}

my $vrfy_ctx = Net::SSLeay::X509_STORE_CTX_new();


Net::SSLeay::X509_STORE_CTX_init($vrfy_ctx, $store, $cert);

my $ret = Net::SSLeay::X509_verify_cert($vrfy_ctx);
if ($ret == 0) {
	die "$certName: verification failed: " . Net::SSLeay::X509_verify_cert_error_string(Net::SSLeay::X509_STORE_CTX_get_error($vrfy_ctx)) . "\n";
}
else {
	print "$certName: verification succeeded\n";
}
