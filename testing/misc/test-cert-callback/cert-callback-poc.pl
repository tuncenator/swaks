#!/usr/bin/env perl

use strict;
use IO::Socket::INET;
use Net::SSLeay;

if (scalar(@ARGV) != 2) {
	printf("usage: %s <hostname> <portnum>\n", $0);
	exit 1;
}

my $hostname = shift;
my $portnum = shift;

my $ctx = InitCTX();

printf("using library %s, Net::SSLeay version %s\n", Net::SSLeay::SSLeay_version(), $Net::SSLeay::VERSION);

my $server = OpenConnection($hostname, $portnum);

my $ssl = Net::SSLeay::new($ctx);
if (!$ssl) {
	die "Error in new(): " . Net::SSLeay::ERR_error_string(Net::SSLeay::ERR_get_error());
}
Net::SSLeay::set_fd($ssl, fileno($server)); # error check?
if (!Net::SSLeay::connect($ssl)) {
	die "Error in connect(): " . Net::SSLeay::ERR_error_string(Net::SSLeay::ERR_get_error());
}
else {
	printf("\nConnected with %s encryption\n", Net::SSLeay::get_cipher($ssl));
}

Net::SSLeay::free($ssl);
$server = undef;
Net::SSLeay::CTX_free($ctx);

exit;

sub tls_verify_callback {
	my $preverify_ok = shift;
	my $x509_ctx     = shift;

	my $x509 = Net::SSLeay::X509_STORE_CTX_get_current_cert($x509_ctx);
	my $dn   = Net::SSLeay::X509_NAME_oneline(Net::SSLeay::X509_get_subject_name($x509));
	printf("in verify callback with dn = %s\n", $dn);

	return 1;
}

sub InitCTX {
	Net::SSLeay::SSLeay_add_ssl_algorithms();
	Net::SSLeay::load_error_strings();

	my $ctx = Net::SSLeay::CTX_new();
	if (!$ctx) {
		die "Error in CTX_new: " . Net::SSLeay::ERR_error_string(Net::SSLeay::ERR_get_error());
	}

	Net::SSLeay::CTX_set_verify($ctx, &Net::SSLeay::VERIFY_NONE, \&tls_verify_callback);

	return $ctx;
}

sub OpenConnection {
	my $host = shift;
	my $port = shift;

	my $socket = IO::Socket::INET->new(
		PeerAddr  => $host,
		PeerPort  => $port,
		Proto     => 'tcp',
		Timeout   => 30,
	);
	if ($@) {
		die "Unable to connect to $host:$port:\n\t$@\n";
	}

	return $socket;
}
