package web;

use warnings;
use strict;
use IO::Socket::INET;
use Encode;

use event;
use main;
use data;
use logger;
use base58;
use ecdsa;
use util;

our $VERSION = '110406';

our $SQL_PAGE = 20;

our $sid = base58::EncodeBase58 (
    substr (base58::sha256 ("$$ @{[ (stat $0)[1,4,5,7,9] ]}"), 0, 8));

sub http_params {
	my ($params) = @_;

	my %par;
	for (split /&/, $params) {
		my ($a, $b) = /^([^=]*)=?(.*)\z/ or next;
		y/+/ /, s/%([0-9a-f]{2})/pack 'C', hex $1/ieg
			for $a, $b;
		$par{$a} = decode ('utf8', $b);
	}
	return \%par;
}

sub page_sql {
	my ($file) = @_;

	my $html = '';
	my $sql = $file->{http_param}{sql} || '';
	if ($sql) {
		my $res = eval { data::sql ($sql, $SQL_PAGE) };
		if ($@) {
			$html = <<HTML;
<p><font color="#FF0000">Error: $util::hesc{$@}</font></p>
HTML
		} elsif (!@$res) {
			$html = <<HTML;
<p>No results.</p>
HTML
		} else {
			my @col = sort keys %{ $res->[0] };
			$html = <<HTML;
<table border="1">
<tr>@{[ map "<td><b>$util::hesc{$_}</b></td>", @col ]}</tr>
HTML
			$html .= <<HTML for @$res;
<tr>@{[ map "<td>$util::hesc{ /[^ -~]/ ? $util::b2h{$_} : $_ }</td>",
	@$_{@col} ]}</tr>
HTML
			$html .= <<HTML;
</table>
HTML
		}
	}

	return <<HTML;
<form action="/sql" method="get">
<p>Free form SQL query (dangerous!) :
<input type="text" name="sql" value="$util::hesc{$sql}">
<input type="hidden" name="sid" value="$sid">
<input type="submit" value="Execute">
</p>
</form>
$html
HTML
}

sub page_about {
	my $home = 'https://github.com/mtve/bitcoin-pl';
	return <<HTML;
<p>Version <b>$main::VERSION</b> running on perl $^V $^O,
with ${\data::version }, and ${\ecdsa::version }</p>
<p>Project home is at <a href="$home">$home</a></p>
<p>Address for donations is <b>1ADcnp7G3y7VQE1CkfveKMP6sGxGzFjwU2</b></p>
</p>
HTML
}

sub key_gen {
	my $key = main::NewKey ();

	return <<HTML;
<p>Generated new key with address <b>$key->{addr}</b></p>
HTML
}

sub page_key {
	my ($file) = @_;

	my $f = "key_" . ($file->{http_param}{func} || '');
	my $func = do { no strict 'refs'; exists &$f ? &$f ($file) : '' };

	my $keys = '';
	$keys .= <<HTML for data::key_all ();
<tr><td>$_->{addr}</td><td align="right">$_->{ammo}</td></tr>
HTML
	$keys = <<HTML if !$keys;
<tr><td colspan="2"><i>no keys</i></td></tr>
HTML
	return <<HTML;
<p><a href="/key?sid=$sid">List</a> |
<a href="/key?sid=$sid&func=gen">New</a> |
<a href="/key?sid=$sid&func=exp">Export</a> |
<a href="/key?sid=$sid&func=imp">Import</a></p>
$func
<table border="1"><tr>
<td><b>Address</b></td>
<td><b>Amount</b></td></tr>
$keys
</table>
HTML
}

sub page_rotate {
	logger::rotate ();
	return '<p>Done.</p>';
}

sub page_stop {
	event::quit ();
}

sub check_sid {			# prevent xss
	my ($file) = @_;

	return $sid eq ($file->{http_param}{sid} || '');
}

sub page {
	my ($file) = @_;

	my $page = '';
	if ($file->{http_url} =~ /(\w+)(\?|\z)(.*)/) {
		my $mvc = "page_$1";
		no strict 'refs';
		$file->{http_param} = http_params ($3);
		$page = $mvc->($file) if exists &$mvc && check_sid ($file);
	}

	return <<HTML;
<html><head>
<title>Bitcoin in perl</title>
</head><body>
<h3><a href="http://www.bitcoin.org">Bitcoin</a> in perl</h3>
<p>Blocks: <b>$main::blk_best->{nHeight}</b>,
Your addresses: <b>${\data::key_cnt () }</b></p>
<p>
<a href="/">Main</a> |
<a href="/key?sid=$sid">Wallet</a> |
<a href="/rotate?sid=$sid">Rotate log</a> |
<a href="/stop?sid=$sid">Stop</a> |
<a href="/sql?sid=$sid">SQL query</a> |
<a href="/about?sid=$sid">About</a>
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
	my ($file) = @_;

	return favicon () if $file->{http_url} =~ /favicon.ico\z/;

	my $html = page ($file);

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
	@$file{qw( http_method http_url )} = ($1, $2);
	warn "httpd $peerhost:@{[ $file->{fh}->peerport ]} $1 $2";

	event::file_write ($file, request ($file));
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
