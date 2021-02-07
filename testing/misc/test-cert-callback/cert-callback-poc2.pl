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

#my $ctx = InitCTX();

printf("using library %s, Net::SSLeay version %s\n", Net::SSLeay::SSLeay_version(), $Net::SSLeay::VERSION);

my $server = OpenConnection($hostname, $portnum);
$G::link{sock} = $server;
start_tls();

# my $ssl = Net::SSLeay::new($ctx);
# if (!$ssl) {
# 	die "Error in new(): " . Net::SSLeay::ERR_error_string(Net::SSLeay::ERR_get_error());
# }
# Net::SSLeay::set_fd($ssl, fileno($server)); # error check?
# if (!Net::SSLeay::connect($ssl)) {
# 	die "Error in connect(): " . Net::SSLeay::ERR_error_string(Net::SSLeay::ERR_get_error());
# }
# else {
# 	printf("\nConnected with %s encryption\n", Net::SSLeay::get_cipher($ssl));
# }

# Net::SSLeay::free($ssl);
# $server = undef;
# Net::SSLeay::CTX_free($ctx);

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

	# extra:
	#Net::SSLeay::CTX_set_default_verify_paths($ctx);

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

sub start_tls {
	my %t         = (); # This is a convenience var to access $G::link{tls}{...}
	$G::link{tls} = \%t;

	Net::SSLeay::load_error_strings();
	Net::SSLeay::SSLeay_add_ssl_algorithms();
	Net::SSLeay::randomize();
	if (!($t{con} = Net::SSLeay::CTX_new())) {
		$t{res} = "CTX_new(): " . Net::SSLeay::ERR_error_string(Net::SSLeay::ERR_get_error());
		return(0);
	}

	# we explicitly turn off time checking.  This allows us to conditionally check for it later.
	# my $vpm = Net::SSLeay::CTX_get0_param($t{con});
	# Net::SSLeay::X509_VERIFY_PARAM_set_flags($vpm, &Net::SSLeay::X509_V_FLAG_NO_CHECK_TIME);
	# Net::SSLeay::CTX_set1_param($t{con}, $vpm);

	my $ctx_options = &Net::SSLeay::OP_ALL;
	if (scalar(@G::tls_protocols)) {
		if ($G::tls_protocols[0] =~ /^no_/i) {
			foreach my $p (@G::tls_supported_protocols) {
				if (grep /^no_$p$/i, @G::tls_protocols) {
					no strict "refs";
					$ctx_options |= &{"Net::SSLeay::OP_NO_$p"}();
				}
			}
		} else {
			foreach my $p (@G::tls_supported_protocols) {
				if (!grep /^$p$/i, @G::tls_protocols) {
					no strict "refs";
					$ctx_options |= &{"Net::SSLeay::OP_NO_$p"}();
				}
			}
		}
	}
	Net::SSLeay::CTX_set_options($t{con}, $ctx_options);

	# $t{verify_failure_message}          = '';
	# $t{server_cert_verified_ca}         = 0;
	# $t{server_cert_verified_host}       = 0;
	# $t{server_cert_verified_time}       = 0;
	# $t{server_cert_verified_time_nb}    = '';
	# $t{server_cert_verified_time_na}    = '';
	$t{server_cert_host_target}         = '';
	# $t{server_cert_verification_status} = undef;


	$t{server_cert_stack}               = [];
	#Net::SSLeay::CTX_set_verify($t{con}, &Net::SSLeay::VERIFY_PEER, \&tls_verify_callback);
	Net::SSLeay::CTX_set_verify($t{con}, &Net::SSLeay::VERIFY_NONE, \&tls_verify_callback);

	# This callback is called at various stages of the TLS negotiation.  Currently used to determine whether the server requested
	# a certificate. CTX_set_client_cert_cb (cf https://www.openssl.org/docs/man1.1.1/man3/SSL_CTX_set_client_cert_cb.html)
	# would be much better for this, but doesn't seem to be implemented in Net::SSLeay yet
	$t{server_requested_cert} = 0;
	$t{client_sent_cert}      = 0;
	Net::SSLeay::CTX_set_info_callback($t{con}, sub {
		# print STDERR "in SSL info callback: $_[1], $_[2], ", Net::SSLeay::state_string($_[0]), ", ", Net::SSLeay::state_string_long($_[0]), "\n";
		if (Net::SSLeay::state_string($_[0]) eq 'TRCR') {
			# TRCR, SSLv3/TLS read server certificate request
			$t{server_requested_cert} = 1;
		}
		elsif (Net::SSLeay::state_string($_[0]) eq 'TWCV') {
			# TWCV, SSLv3/TLS write certificate verify
			$t{client_sent_cert} = 1;
		}
	});

# 	if ($G::tls_ca_path) {
# 		my @args = ('', $G::tls_ca_path);
# 		@args    = ($G::tls_ca_path, '') if (-f $G::tls_ca_path);
# print STDERR "calling custom path (@args)\n";
# 		if (!Net::SSLeay::CTX_load_verify_locations($t{con}, @args)) {
# 			$t{res} = "Unable to set set CA path to (" . join(',', @args) . "): "
# 			        . Net::SSLeay::ERR_error_string(Net::SSLeay::ERR_get_error());
# 			return(0);
# 		}
# 	} else {
# print STDERR "calling default path\n";
		Net::SSLeay::CTX_set_default_verify_paths($t{con});
	# }

	if ($G::tls_cipher) {
		if (!Net::SSLeay::CTX_set_cipher_list($t{con}, $G::tls_cipher)) {
			$t{res} = "Unable to set cipher list to $G::tls_cipher: "
			        . Net::SSLeay::ERR_error_string(Net::SSLeay::ERR_get_error());
			return(0);
		}
	}
	if ($G::tls_cert && $G::tls_key) {
		if (!Net::SSLeay::CTX_use_certificate_file($t{con}, $G::tls_cert, &Net::SSLeay::FILETYPE_PEM)) {
			$t{res} = "Unable to add cert file $G::tls_cert to SSL CTX: "
			        . Net::SSLeay::ERR_error_string(Net::SSLeay::ERR_get_error());
			return(0);
		}
		if (!Net::SSLeay::CTX_use_PrivateKey_file($t{con}, $G::tls_key, &Net::SSLeay::FILETYPE_PEM)) {
			$t{res} = "Unable to add key file $G::tls_key to SSL CTX: "
			        . Net::SSLeay::ERR_error_string(Net::SSLeay::ERR_get_error());
			return(0);
		}
	}

	if (!($t{ssl} = Net::SSLeay::new($t{con}))) {
		$t{res} = "new(): " . Net::SSLeay::ERR_error_string(Net::SSLeay::ERR_get_error());
		return(0);
	}

	if ($G::tls_sni_hostname) {
		if (!Net::SSLeay::set_tlsext_host_name($t{ssl}, $G::tls_sni_hostname)) {
			$t{res} = "Unable to set SNI hostname to $G::tls_sni_hostname: "
			        . Net::SSLeay::ERR_error_string(Net::SSLeay::ERR_get_error());
			return(0);
		}
	}

	if ($G::link{type} eq 'pipe') {
		Net::SSLeay::set_wfd($t{ssl}, fileno($G::link{sock}{wr})); # error check?
		Net::SSLeay::set_rfd($t{ssl}, fileno($G::link{sock}{re})); # error check?
	} else {
		Net::SSLeay::set_fd($t{ssl}, fileno($G::link{sock})); # error check?
	}

	$t{active} = Net::SSLeay::connect($t{ssl}) == 1 ? 1 : 0;
	if (!$t{active}) {
		$t{res} = "connect(): " . Net::SSLeay::ERR_error_string(Net::SSLeay::ERR_get_error());
		# if ($t{verify_failure_message}) {
		# 	$t{res} .= ' (' . $t{verify_failure_message} . ')';
		# }
		return(0);
	}

	# egrep 'define.*VERSION\b' *.h
	# when adding new types here, see also the code that pushes supported values onto tls_supported_protocols
	$t{version} = Net::SSLeay::version($t{ssl});
	if ($t{version} == 0x0002) {
		$t{version} = "SSLv2";    # openssl/ssl2.h
	} elsif ($t{version} == 0x0300) {
		$t{version} = "SSLv3";    # openssl/ssl3.h
	} elsif ($t{version} == 0x0301) {
		$t{version} = "TLSv1";    # openssl/tls1.h
	} elsif ($t{version} == 0x0302) {
		$t{version} = "TLSv1.1";  # openssl/tls1.h
	} elsif ($t{version} == 0x0303) {
		$t{version} = "TLSv1.2";  # openssl/tls1.h
	} elsif ($t{version} == 0x0304) {
		$t{version} = "TLSv1.3";  # openssl/tls1.h
	} elsif ($t{version} == 0xFEFF) {
		$t{version} = "DTLSv1";   # openssl/dtls1.h
	} elsif ($t{version} == 0xFEFD) {
		$t{version} = "DTLSv1.2"; # openssl/dtls1.h
	} else {
		$t{version} = sprintf("UNKNOWN(0x%04X)", $t{version});
	}
	$t{cipher}          = Net::SSLeay::get_cipher($t{ssl});
	if (!$t{cipher}) {
		$t{res} = "empty response from get_cipher()";
		return(0);
	}
	$t{cipher_bits}     = Net::SSLeay::get_cipher_bits($t{ssl}, undef);
	if (!$t{cipher_bits}) {
		$t{res} = "empty response from get_cipher_bits()";
		return(0);
	}
	$t{cipher_string}   = sprintf("%s:%s:%s", $t{version}, $t{cipher}, $t{cipher_bits});
	$t{cert}            = Net::SSLeay::get_peer_certificate($t{ssl});
	if (!$t{cert}) {
		$t{res} = "error response from get_peer_certificate()";
		return(0);
	}
	chomp($t{cert_x509} = Net::SSLeay::PEM_get_string_X509($t{cert}));
	$t{cert_subject}    = Net::SSLeay::X509_NAME_oneline(Net::SSLeay::X509_get_subject_name($t{cert}));

	if ($G::tls_cert && $G::tls_key) {
		$t{local_cert}            = Net::SSLeay::get_certificate($t{ssl});
		chomp($t{local_cert_x509} = Net::SSLeay::PEM_get_string_X509($t{local_cert}));
		$t{local_cert_subject}    = Net::SSLeay::X509_NAME_oneline(Net::SSLeay::X509_get_subject_name($t{local_cert}));
	}

	return($t{active});
}
