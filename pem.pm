package pem;

use warnings;
use strict;

sub D() { 0 }

#
# asn.1
#

sub asn_decode_pdu {
	my ($dataref, $tab) = @_;

	(my ($type), $$dataref) = unpack 'Ca*', $$dataref;

	my $txt = qw/ universal application context private /[$type >> 6];

	my $tag = $type & 0x1f;
	($tag, $$dataref) = unpack 'wa*', $$dataref
		if $tag == 0x1f;

	(my ($len), $$dataref) = unpack 'Ca*', $$dataref;
	if ($len & 0x80) {
		$len &= 0x7f;
		die "len is more then 4 bytes"
			if $len > 4;
		($len, $$dataref) = unpack "a$len a*", $$dataref;
		$len = unpack 'N', "\0" x (4 - length $len) . $len;
	}
	die "message too short"
		if length $$dataref < $len;

	(my ($val), $$dataref) = unpack "a$len a*", $$dataref;
	
	if ($type & 0x20) {
		my $t = '';
		my $ta = "$tab   ";
		$t .= $ta . asn_decode_pdu (\$val, $ta) . "\n"
			while length $val;
		$val = "<\n$t$tab>";
	} else {
		$val = '= "' . unpack ('H*', $val) . '"';
	}

	return "${txt}_$tag $val";
}

sub asn_decode {
	my ($data) = @_;

	my $ret = asn_decode_pdu (\$data, '');
	warn "garbage at the end"
		if length $data;
	return $ret;
}

sub asn_encode_pdu {
	my ($txt) = @_;

	$$txt =~ s/^\s*([uacp])[a-z]*_(\d+)\s*//i
		or die "bad syntax at:\n$$txt";
	my ($type, $tag) = ($1, $2);

	$type = { u => 0, a => 0x40, c => 0x80, p => 0xc0 }->{lc $type};
	$type |= $tag < 0x1f ? $tag : 0x1f;
	$type = pack 'C', $type;
	$type .= pack 'w', $tag
		if $tag >= 0x1f;

	my $val = '';

	if ($$txt =~ s/^=//) {
		$$txt =~ s/^\s*"\s*([0-9a-f]*)\s*"\s*//i
			or die "bad syntax of = at:\n$$txt";
		$val = pack 'H*', $1;
	} elsif ($$txt =~ s/^<//) {
		$type |= pack 'C', 0x20;
		$val .= asn_encode_pdu ($txt)
			while $$txt =~ /^\s*[a-z]/i;
		$$txt =~ s/^\s*>\s*//
			or die "no closing > at:\n$$txt";
	} else {
		die "bad syntax at:\n$$txt";
	}

	my $len = length $val;
	if ($len < 0x80) {
		$len = pack 'C', $len;
	} else {
		$len = pack 'N', $len;
		$len =~ s/^\0*//;
		$len = pack 'Ca*', 0x80 | length $len, $len;
	}

	return "$type$len$val";
}

sub asn_encode {
	my ($txt) = @_;

	my $pdu = asn_encode_pdu (\$txt);
	$txt =~ /^\s*\z/
		or die "garbade at the end:\n$txt";
	return $pdu;
}

my $d_re = qr/[0-9a-f]*/;
my $asn_re;
{
	use re 'eval';
	$asn_re = qr/ \w+\d+ = "$d_re" | \w+\d+ < (?:(??{ $asn_re }))* > /x;
}

#
# base64
#

sub base64_decode {
	my ($str) = @_;

	for ($str) {
		y!A-Za-z0-9+/=\0-\377!\0-\100!d;
		$_ = unpack 'B*', $_;
		/((01.{6})*)\z/;
		my $pad = length $1;
		s/..(.{6})/$1/g;
		s/.{$pad}\z//;
		$_ = pack 'B*', $_;
	}
	return $str;
}

sub base64_encode {
	my ($str) = @_;

	for ($str) {
		$_ = unpack 'B*', $_;
		s/(.{2,6})/00$1/g;
		$_ = pack 'B*', $_;
		y!\0-\77!A-Za-z0-9+/!;
		$_ .= '=' x (- length () % 4);
		s/(.{1,64})/$1\n/g;
	}
	return $str;
}

#
# pem
#

our $priv_hdr	= "-----BEGIN EC PRIVATE KEY-----\n";
our $priv_ftr	= "-----END EC PRIVATE KEY-----\n";
our $pub_hdr	= "-----BEGIN PUBLIC KEY-----\n";
our $pub_ftr	= "-----END PUBLIC KEY-----\n";

sub pem_make_priv {
	my ($key) = @_;

	my $priv = unpack 'H*', $key->{priv}	|| die "no priv key";
	my $pub  = unpack 'H*', $key->{pub}	|| die "no pub key";	

	my $body = base64_encode (asn_encode (qq!
universal_16 <
   universal_2 = "01"
   universal_4 = "$priv"
   context_0 <
      universal_6 = "2b8104000a"
   >
   context_1 <
      universal_3 = "00$pub"
   >
>
	!));

	return $priv_hdr . $body . $priv_ftr;
}

sub pem_make_pub {
	my ($key) = @_;

	my $pub  = unpack 'H*', $key->{pub}	|| die "no pub key";	

	my $body = base64_encode (asn_encode (qq!
universal_16 <
   universal_16 <
      universal_6 = "2a8648ce3d0201"
      universal_6 = "2b8104000a"
   >
   universal_3 = "00$pub"
>
	!));

	return $pub_hdr . $body . $pub_ftr;
}

sub pem_parse_priv {
	my ($pem) = @_;

	my $body = $pem;
	$body =~ s/^\Q$priv_hdr\E// && 
	$body =~ s/^\Q$priv_ftr\E//m
		or die "problem with PEM";

	my $asn = asn_decode (base64_decode ($body));
	$asn =~ s/\s+//g;
	D && warn $asn;

	my ($priv, $pub) = $asn =~ qr!^
universal_16 <
   universal_2 = "01"
   universal_4 = "($d_re)"
   context_0 <
      universal_6 = "2b8104000a"
   >
   context_1 <
      universal_3 = "($d_re)"
   >
>
	\z!x
		or die "bad key format";

	$pub =~ s/^00// or die "pub key should start with zero";

	return {
		priv	=> pack ('H*', $priv),
		pub	=> pack ('H*', $pub),
	};
}

1;
