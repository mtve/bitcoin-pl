package ecdsa;

# naive ecdsa(p) in perl
# with Pari it's around 100 times slower then openssl

use warnings;
use strict;
use Math::BigInt;

sub D() { 1 }

sub i($) { Math::BigInt->new ($_[0]) }

# secp256k1

my $EC_SIZE = 256;
my $EC_P =
	i '0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F';
my $EC_A = i 0;
my $EC_B = i 7;
my $EC_G = [
	i '0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798',
	i '0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8',
];
my $EC_N =
	i '0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141';

# element is bigint modulo ec_p

sub e_add { my ($a, $b) = @_; ($a + $b) % $EC_P }
sub e_sub { my ($a, $b) = @_; ($a - $b) % $EC_P }
sub e_inv { my ($a) = @_; $a->bmodinv ($EC_P) }
sub e_mul { my ($a, $b) = @_; $a * $b % $EC_P }
sub e_div { my ($a, $b) = @_; $a * e_inv ($b) % $EC_P }
sub e_neg { my ($a) = @_; -$a % $EC_P }
sub e_pow2  { my ($a) = @_; e_mul ($a, $a) }
sub e_pow { my ($a, $b) = @_; $a->bmodpow ($b, $EC_P) }

sub e_x_ab {
	my ($x) = @_;

	e_add (e_mul (e_add (e_pow2 ($x), $EC_A), $x), $EC_B);
}

# because $EC_P % 4 == 3
sub e_sqrt { my ($a) = @_; e_pow ($a, ($EC_P + 1) / 4) }
sub e_solve { my ($x) = @_; e_sqrt (e_x_ab ($x)) }

# point is two elements

my $p_inf = undef;
sub p_isinf { my ($a) = @_; !defined $a }

sub p_add {
	my ($a, $b) = @_;

	return $b if p_isinf ($a);
	return $a if p_isinf ($b);

	my ($ax, $ay) = @$a;
	my ($bx, $by) = @$b;

	return $ay == $by ? p_mul2 ($a) : $p_inf if $ax == $bx;

	my $g = e_div (e_sub ($by, $ay), e_sub ($bx, $ax));
	my $x3 = e_sub (e_sub (e_pow2 ($g), $ax), $bx);
	my $y3 = e_sub (e_mul ($g, e_sub ($ax, $x3)), $ay);
	return [ $x3, $y3 ];
}

sub p_neg { my ($p) = @_; [ $p->[0], -$p->[1] ] }

sub p_sub { my ($a, $b) = @_; p_isinf ($b) ? $a : p_add ($a, p_neg ($b)) }

sub p_mul {
	my ($t, $e) = @_;

	return $p_inf if p_isinf ($t) || $e == 0;

	my $h = $e * 3;
	my $neg = p_neg ($t);
	my $r = $t;

	my $hs = $h->as_bin;
	my $es = $e->as_bin;
	s/^0b// or die for $hs, $es;
	my $s = length ($hs) - length ($es);
	substr ($es, 0, $s < 0 ? -$s : 0) = '0' x $s;
	die "wtf" if length ($hs) != length ($es);

	for (1 .. length ($hs) - 2) {
		$r = p_mul2 ($r);
		my $hb = substr $hs, $_, 1;
		my $eb = substr $es, $_, 1;
		$r = p_add ($r, $hb ? $t : $neg) if $hb != $eb;
	}
        return $r;
}

sub p_mul2 {
	my ($t) = @_;

	return $p_inf if p_isinf ($t) || $t->[1] == 0;

	my ($x, $y) = @$t;

	my $g = e_div (e_add (e_mul (e_pow2 ($x), 3), $EC_A), e_mul ($y, 2));
	my $x3 = e_sub (e_pow2 ($g), e_mul ($x, 2));
	my $y3 = e_sub (e_mul ($g, e_sub ($x, $x3)), $y);
	return [ $x3, $y3 ];
}

sub p_oncurve {
	my ($p) = @_;

	my ($x, $y) = @$p;

	return e_sub (e_x_ab ($x), e_pow2 ($y)) == 0;
}

sub p_mul_sum {					# p * k + q * l
	my ($p, $k, $q, $l) = @_;

	my $z = p_add ($p, $q);
	my $r = $p_inf;

	my $ks = $k->as_bin;
	my $ls = $l->as_bin;
	s/^0b// or die $_ for $ks, $ls;
	my $s = length ($ks) - length ($ls);
	$ls = '0' x  $s . $ls if $s > 0;
	$ks = '0' x -$s . $ks if $s < 0;

	die "wtf" if length ($ks) != length ($ls);

	for (0 .. length ($ks) - 1) {
		$r = p_mul2 ($r);
		my $kb = substr $ks, $_, 1;
		my $lb = substr $ls, $_, 1;
		$r = p_add ($r, $kb ? $lb ? $z : $p : $q) if $kb || $lb;
	}
	return $r;
}

# ecdsa - priv_key is element, pub_key is point, sig is [r,s]

sub i_rand {
	return i '0x' . join '',
		map { sprintf '%02x', int rand 256 } 1 .. $EC_SIZE / 8;
}

sub ec_sign {
	my ($priv, $e) = @_;

	my ($k, $p, $r, $s);

AGAIN:	$k = i_rand ();
	goto AGAIN if !$k;

	$p = p_mul ($EC_G, $k);
	$r = $p->[0] % $EC_N;
	goto AGAIN if !$r;

	$s = $k->bmodinv ($EC_N) * ($e + $priv * $r) % $EC_N;
	goto AGAIN if !$s;

	return [ $r, $s ];
}

sub ec_verify {
	my ($pub, $e, $sig) = @_;

	my ($r, $s) = @$sig;
	return if $r <= 0 || $r >= $EC_N || $s <= 0 || $s >= $EC_N;

	my $c = $s->bmodinv ($EC_N);
	my $u1 = $e * $c % $EC_N;
	my $u2 = $r * $c % $EC_N;

	my $p = p_mul_sum ($EC_G, $u1, $pub, $u2);
	my $v = $p->[0] % $EC_N;

	return $v == $r;
}

# in/out stuff

sub i_decode { my ($bin) = @_; i '0x' . unpack 'H*', $bin };

sub i_encode {
	my ($i) = @_;

	my $bin = $i->as_hex;
	$bin =~ s/^0x// or die $i;
	$bin = "0" x ($EC_SIZE / 4 - length $bin) . $bin;
	return pack 'H*', $bin;
}

sub priv_new { i_rand () % $EC_N }

sub pub_from_priv { my ($priv) = @_; p_mul ($EC_G, $priv) }

sub pub_encode {
	my ($pub) = @_;

	return "\4" . i_encode ($pub->[0]) . i_encode ($pub->[1]);
}

sub pub_decode {
	my ($bin) = @_;

	my ($x, $y);
	my $t = ord $bin;
	my $l = length $bin;
	if ($t == 4) {
		$l == $EC_SIZE / 8 * 2 + 1	or die "bad pub size $l";
		$x = i_decode (substr $bin, 1, $EC_SIZE / 8);
		$y = i_decode (substr $bin, $EC_SIZE / 8 + 1);
	} elsif ($t == 2 || $t == 3) {
		$l == $EC_SIZE / 8 + 1		or die "bad pub size $l";
		$x = i_decode (substr $bin, 1, $EC_SIZE / 8);
		$y = e_solve ($x);
		$y = e_neg ($y) if $t % 2 != $y % 2;
	} else {
		die "bad pub start $t";
	}
	p_oncurve ([$x, $y]) or die 'not on curve';

	return [ $x, $y ];
}

sub hash_decode {
	my ($hash) = @_;

	my $s = length ($hash) * 8 - $EC_SIZE;
	my $e = i_decode ($hash);
	$e = $e->brsft ($s) if $s > 0;
	return $e;
}

sub sig_encode {
	my ($sig) = @_;

	my ($r, $s) = @$sig;
	return pack 'C w/a', 0x30,
		pack ('C w/a', 0x02, i_encode ($r)) .
		pack ('C w/a', 0x02, i_encode ($s));
}

sub sig_decode {
	my ($bin) = @_;

	my ($h, $b, $t) = unpack 'C w/a a*', $bin
		or die "bad sig";
	$h == 0x30			or die "bad sig head $h";
	length ($t) == 0		or warn "garbage after sig";
	my ($h1, $br, $h2, $bs, $t2) = unpack 'C w/a C w/a a*', $b
		or die "bad sig";
	$h1 == 0x02 && $h2 == 0x02	or die "bad sig heads $h1 or $h2";
	length ($t2) == 0		or die "garbage inside sig";
	return [ i_decode ($br), i_decode ($bs) ];
}

sub GenKey {
	my $priv = priv_new ();
	my $pub = pub_from_priv ($priv);
	return {
		priv	=> i_encode ($priv),
		pub	=> pub_encode ($pub),
	};
}

sub Sign {
	my ($key, $hash) = @_;

	ref $key eq 'HASH' && exists $key->{priv}	or die "not a key";
	my $p = i_decode ($key->{priv});
	my $e = hash_decode ($hash);
	my $s = ec_sign ($p, $e);
	return sig_encode ($s);
}

sub Verify {
	my ($key, $hash, $sig) = @_;

	ref $key eq 'HASH' && exists $key->{pub}	or die "not a key";
	my $p = pub_decode ($key->{pub});
	my $e = hash_decode ($hash);
	my $s = sig_decode ($sig);

	my $res = ec_verify ($p, $e, $s);
	D && warn $res + 0;
	return $res;
}

sub version {
	my $c = Math::BigInt->config ();
	return "Math::BigInt @$c{qw( version lib lib_version )}";
}

1;
