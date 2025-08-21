#!/usr/bin/perl

# Copyright (c) F5, Inc.
#
# This source code is licensed under the Apache License, Version 2.0 license
# found in the LICENSE file in the root directory of this source tree.

# Tests for ACME client: TLS-ALPN-01 challenge.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Nginx::ACME;
use Test::Nginx::DNS;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http http_ssl sni socket_ssl/)
	->has_daemon('openssl');

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    resolver 127.0.0.1:%%PORT_8980_UDP%%;

    acme_issuer default {
        uri https://acme.test:%%PORT_9000%%/dir;
        challenge tls-alpn-01;
        ssl_trusted_certificate acme.test.crt;
        state_path %%TESTDIR%%;
        accept_terms_of_service;
    }

    server {
        listen       127.0.0.1:8443 ssl;
        server_name  .example.test;

        acme_certificate default;

        ssl_certificate $acme_certificate;
        ssl_certificate_key $acme_certificate_key;
    }
}

EOF

$t->write_file('openssl.conf', <<EOF);
[ req ]
default_bits = 2048
encrypt_key = no
distinguished_name = req_distinguished_name
[ req_distinguished_name ]
EOF

my $d = $t->testdir();

foreach my $name ('acme.test') {
	system('openssl req -x509 -new '
		. "-config $d/openssl.conf -subj /CN=$name/ "
		. "-out $d/$name.crt -keyout $d/$name.key "
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't create certificate for $name: $!\n";
}

my $dp = port(8980, udp=>1);
my @dc = (
	{ name => 'acme.test', A => '127.0.0.1' },
	{ match => qr/^(\w+\.)?example.test$/, A => '127.0.0.1' }
);

my $acme = Test::Nginx::ACME->new($t, port(9000), port(9001),
	$t->testdir . '/acme.test.crt',
	$t->testdir . '/acme.test.key',
	tls_port => port(8443),
	dns_port => $dp,
	nosleep => 1,
);

$t->run_daemon(\&Test::Nginx::DNS::dns_test_daemon, $t, $dp, \@dc);
$t->waitforfile($t->testdir . '/' . $dp);

$t->run_daemon(\&Test::Nginx::ACME::acme_test_daemon, $t, $acme);
$t->waitforsocket('127.0.0.1:' . $acme->port());
$t->write_file('acme-root.crt', $acme->trusted_ca());

$t->write_file('index.html', 'SUCCESS');
$t->plan(1)->run();

###############################################################################

$acme->wait_certificate('example.test') or die "no certificate";

like(get(8443, 'example.test', 'acme-root'), qr/SUCCESS/, 'tls request');

###############################################################################

sub get {
	my ($port, $host, $ca) = @_;

	$ca = undef if $IO::Socket::SSL::VERSION < 2.062
		|| !eval { Net::SSLeay::X509_V_FLAG_PARTIAL_CHAIN() };

	http_get('/',
		PeerAddr => '127.0.0.1:' . port($port),
		SSL => 1,
		$ca ? (
		SSL_ca_file => "$d/$ca.crt",
		SSL_verifycn_name => $host,
		SSL_verify_mode => IO::Socket::SSL::SSL_VERIFY_PEER(),
		) : ()
	);
}

###############################################################################
