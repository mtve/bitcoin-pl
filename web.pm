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

our $VERSION = '110325';
our $SQL_PAGE = 20;

our $sid = base58::EncodeBase58 (
    substr (base58::sha256 ("$$ @{[ (stat $0)[1,4,5,7,9] ]}"), 0, 8));

sub html_esc'TIEHASH { bless {}, $_[0] }

sub html_esc'FETCH {
	my (undef, $str) = @_;

	s/&/&amp;/g, s/</&lt;/g, s/>/&gt;/g, s/"/&quot;/g for $str;
	return $str;
}

tie my %H, 'html_esc';

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
<p><font color="#FF0000">Error: $H{$@}</font></p>
HTML
		} elsif (!@$res) {
			$html = <<HTML;
<p>No results.</p>
HTML
		} else {
			my @col = sort keys %{ $res->[0] };
			$html = <<HTML;
<table border="1">
<tr>@{[ map "<td><b>$H{$_}</b></td>", @col ]}</tr>
HTML
			$html .= <<HTML for @$res;
<tr>@{[ map "<td>$H{$_ =~ /[^ -~]/ ? unpack 'H*', reverse : $_ }</td>",
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
<input type="text" name="sql" value="$H{$sql}">
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
<p>Version <b>$VERSION</b> running on perl $^V $^O, with ${\data::version },
and ${\ecdsa::version }</p>
<p>Project home is at <a href="$home">$home</a></p>
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

sub check_sid {			# prevent xss
	my ($file) = @_;

	return $sid eq ($file->{http_param}{sid} || '');
}

sub page {
	my ($file) = @_;

	my $blocks = $main::nBestHeight;
	my $txs = data::tx_cnt ();
	my $keys = data::key_cnt ();

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
<p>Blocks: <b>$blocks</b>,
Transactions: <b>$txs</b>,
Your addresses: <b>$keys</b></p>
<p>
<a href="/">Main</a> |
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
