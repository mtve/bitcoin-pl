package web;

use warnings;
use strict;
use IO::Socket::INET;

use event;
use main;
use data;
use logger;

our $VERSION = '110317';

sub page_about {
	return <<HTML;
<p>Version $VERSION</p>
<p>Project home is
<a href="http://frox25.no-ip.org/~mtve/wiki/BitcoinPl.html">here</a></p>
<p>Address for donations is <b>1ADcnp7G3y7VQE1CkfveKMP6sGxGzFjwU2</b></p>
</p>
HTML
}

sub page_rotate {
	logger::rotate ();
	return '<p>Done.</p>';
}

sub page_stop {
	event::quit ();
}

sub page {
	my ($method, $uri) = @_;

	my $blocks = $main::nBestHeight;
	my $orphan = data::orphan_cnt ();
	my $txs = data::tx_cnt ();
	my $keys = data::key_cnt ();

	my $page = '';
	if ($uri =~ /(\w+)(\?|\z)(.*)/) {
		my $mvc = "page_$1";
		no strict 'refs';
		$page = $mvc->($2) if exists &$mvc;
	}

	return <<HTML;
<html><head>
<title>Bitcoin perl client</title>
</head><body>
<h3><a href="http://www.bitcoin.org">Bitcoin</a> perl client</h3>
<p>Blocks: <b>$blocks</b> (orphaned <b>$orphan</b>),
Transactions: <b>$txs</b>,
Your addresses: <b>$keys</b></p>
<p>
<a href="/">Main</a> |
<a href="/rotate">Rotate log</a> |
<a href="/stop">Stop</a> |
<a href="/about">About</a>
</p>
$page
<p>Page generated at ${\scalar localtime}.</p>
</body></html>
HTML
}

sub favicon {
	my $ico_gz = unpack 'u', <<'UUE';
M'XL(`)>2<TT``V-@8`1"`0$&,,A@96`0`](:0`P24@!B1@8.B"0C`P(@L?,6
M_P>J^`]D`7'+?X91,`I&P4@!3$#$Q`"&3#`^`X0/D6>"(A@?RL8ECP;`Y0P+
M$,+8C`S,S"Q`B"B"F,'RS'`MR'Q&H"*8>C"'@'H,\S'L1^(#P<U@!H;;X0P,
J)\T9&"Y#Z?_`(G!O-0/#!2#[:SP$&U@BV"!QD/S?>@8&`"F7`*=^!0``
UUE
	return <<HTTP;
HTTP/1.1 200 OK
Content-Type: image/x-icon
Content-Encoding: gzip
Content-Length: ${\length $ico_gz }

$ico_gz
HTTP
}

sub request {
	my ($method, $uri) = @_;

	return favicon () if $uri =~ /favicon.ico\z/;

	my $html = page ($method, $uri);

	return <<HTTP;
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: ${\length $html }

$html
HTTP
}

sub http_incoming {
	my ($file) = @_;

	my $peerhost = $file->{fh}->peerhost;
	if ($peerhost ne $file->{fh}->sockhost) {
		warn "connection from $peerhost denied";
		event::file_close ($file);
		return;
	}

	$file->{datain} =~ s/^(\C*?\015?\012)\015?\012//
		or return;
	my ($head) = $1;

	$head =~ s!^([a-z]+)\s+(\S+)\s+HTTP/1\.[01]\015?\012!!i
		or die "bad request $head";
	my ($method, $url) = ($1, $2);
	warn "httpd $peerhost:@{[ $file->{fh}->peerport ]} $method $url";

	event::file_write ($file, request ($method, $url));
	event::file_close ($file);
}

sub server {
	my ($port) = @_;

	my $sock = new IO::Socket::INET (
		Listen		=> 1,
		LocalPort	=> $port,
		ReuseAddr	=> 1,
	) or die 'listen';

	warn "started on port :$port\n";
	print "web server started at http://@{[ $sock->sockhost ]}:$port\n";
	event::server_new (
		fh	=> $sock,
		client	=> { std_read_cb => \&http_incoming },
	);
}

1;
