package serialize;

use warnings;
use strict;

sub D() { 0 }

my %struct = (
	CAddress	=> [
		nServices		=> 'Int64',
		pchReserved		=> 12,
		ip			=> 'IP',
		port			=> 'Net16',
	],
	CInv		=> [
		type			=> 'Int32',
		hash			=> 'Bin256',
	],
	COutPoint	=> [
		hash			=> 'Bin256',
		n			=> 'Int32',
	],
	CTxIn		=> [
		prevout			=> 'COutPoint',
		scriptSig		=> 'Str',
		nSequence		=> 'Int32',
	],
	CTxOut		=> [
		nValue			=> 'Int64',
		scriptPubKey		=> 'Str',
	],
	CTransaction	=> [
		nVersion		=> 'Int32',
		vin			=> \'CTxIn',
		vout			=> \'CTxOut',
		nLockTime		=> 'Int32',
	],
	CBlock		=> [
		nVersion		=> 'Int32',
		hashPrevBlock		=> 'Bin256',
		hashMerkleRoot		=> 'Bin256',
		nTime			=> 'Int32',
		nBits			=> 'Int32',
		nNonce			=> 'Int32',
		vtx			=> \'CTransaction',
	],
	CBlockOnly	=> [
		nVersion		=> 'Int32',
		hashPrevBlock		=> 'Bin256',
		hashMerkleRoot		=> 'Bin256',
		nTime			=> 'Int32',
		nBits			=> 'Int32',
		nNonce			=> 'Int32',
	],

	version		=> [
		nVersion		=> 'Int32',
		nLocalServices		=> 'Int64',
		nTime			=> 'Int64',
		addrYou			=> 'CAddress',
		addrMe			=> 'CAddress',
		nLocalHostNonce		=> 8,
		strSubVer		=> 'Str',
		nStartingHeight		=> 'Int32',
	],
	addr		=> \'CAddress',
	getaddr		=> '',
	ping		=> '',
	verack		=> '',
	getblocks	=> [
		nVersion		=> 'Int32',
		locator			=> \'Bin256',
		hashStop		=> 'Bin256',
	],
	inv		=> \'CInv',
	getdata		=> \'CInv',
	block		=> 'CBlock',
	tx		=> 'CTransaction',
);

sub SerializeInt32 { my ($i) = @_; pack 'V', $i }

sub SerializeNet16 { my ($i) = @_; pack 'n', $i }

sub SerializeInt64 {
	my ($i) = @_;

	$i < 1e15
		or die "potential problem with 32-bit perl";
	pack 'VV', $i % 2**32, $i / 2**32
}

sub SerializeIP { my ($i) = @_; pack 'C4', $i =~ /\d+/g }

sub SerializeCompactSize {
	my ($i) = @_;

	$i < 253 ?	pack 'C', $i :
	$i < 2**16 ?	pack 'Cv', 253, $i :
	$i < 2**32 ?	pack 'CV', 254, $i : die "$i is too much"
		# pack 'CVV', 255, $i % 2**32, $i / 2**32;
}

sub SerializeStr { my ($s) = @_; SerializeCompactSize (length $s) . $s }

sub Uns {
	my (undef, $fmt) = @_;	# $_[0] gets modified

	length $_[0] >= length pack $fmt, 0
		or die "no data to unserialize $fmt";

	(my $res, $_[0]) = unpack "$fmt a*", $_[0];

	D && warn "fmt=$fmt res=$res";

	return $res;
}

sub UnserializeInt32 { Uns ($_[0], 'V') }

sub UnserializeNet16 { Uns ($_[0], 'n') }

sub UnserializeBin { Uns ($_[0], "a$_[1]") }

sub UnserializeIP { join '.', unpack 'C4', Uns ($_[0], "a4") }

sub UnserializeInt64 {
	my $a = Uns ($_[0], 'V');
	my $b = Uns ($_[0], 'V');
	$b <= 232830
		or die "potential problem with 32-bit perl";
	return $b * 2**32 + $a . '';
}

sub UnserializeCompactSize {
	my $len = Uns ($_[0], 'C');
	$len < 253 ? return $len :
	$len == 253 ? return Uns ($_[0], 'v') :
	$len == 254 ? return &UnserializeInt32 : die "too long";
}

sub UnserializeStr {
	my $len = &UnserializeCompactSize;
	Uns ($_[0], "a$len");
}

sub Dump {
	my ($type, $value) = @_;

	my $res;
	if (!ref $type) {
		$res =	$type eq 'Int32' ||
			$type eq 'Int64' ||
			$type eq 'Net16' ||
			$type eq 'IP' ||
				0 ? $value :
			$type eq 'Bin256' ||
				0 ? unpack 'H*', reverse $value :
			$type eq 'Str' ||
			$type =~ /^\d+\z/ ||
				0 ? unpack 'H*', $value :
			$type eq '' ? '' :
			exists $struct{$type} ?
				Dump ($struct{$type}, $value) :
				die  "unknown type $type";
	} elsif (ref $type eq 'SCALAR') {
		$res =	'[ ' .
			join (', ', map Dump ($$type, $_), @$value) .
			' ]';
	} elsif (ref $type eq 'ARRAY') {
		$res = '{';
		for (0 .. $#$type / 2) {
			my $field = $type->[$_ * 2];
			my $type2  = $type->[$_ * 2 + 1];
			exists $value->{$field}
				or die "no field $field";
			my $value2 = $value->{$field};
			$res .= " $field=" . Dump ($type2, $value2);
		}
		$res .= ' }';
	} else {
		die "bad type $type";
	}
	return $res;
}

sub Serialize {
	my ($type, $value, $middle) = @_;

	if (!$middle) {
		D && warn "$type " . Dump ($type, $value);
	}

	my $res;
	if (!ref $type) {
		$res =	$type eq 'Int32' ? SerializeInt32 ($value) :
			$type eq 'Int64' ? SerializeInt64 ($value) :
			$type eq 'Net16' ? SerializeNet16 ($value) :
			$type eq 'Str' ? SerializeStr ($value) :
			$type eq 'IP' ? SerializeIP ($value) :
			$type eq 'Bin256' ||
			$type =~ /^\d+\z/ ? $value :
			$type eq '' ? '' :
			exists $struct{$type} ?
				Serialize ($struct{$type}, $value, 1) :
				die  "unknown type $type";
	} elsif (ref $type eq 'SCALAR') {
		$res = SerializeCompactSize (scalar @$value);
		$res .= Serialize ($$type, $_, 1) for @$value;
	} elsif (ref $type eq 'ARRAY') {
		for (0 .. $#$type / 2) {
			my $field = $type->[$_ * 2];
			my $type2  = $type->[$_ * 2 + 1];
			exists $value->{$field}
				or die "no field $field";
			my $value2 = $value->{$field};
			$res .= Serialize ($type2, $value2);
		}
	} else {
		die "bad type $type";
	}
	return $res;
}

sub Unserialize {
	my ($type, undef, $middle) = @_;	# $_[1] gets modified

	my $res;
	if (!ref $type) {
		$res =	$type eq 'Int32' ? UnserializeInt32 ($_[1]) :
			$type eq 'Int64' ? UnserializeInt64 ($_[1]) :
			$type eq 'Net16' ? UnserializeNet16 ($_[1]) :
			$type eq 'Str' ? UnserializeStr ($_[1]) :
			$type eq 'IP' ? UnserializeIP ($_[1]) :
			$type eq 'Bin256' ? UnserializeBin ($_[1], 256 / 8) :
			$type =~ /^\d+\z/ ? UnserializeBin ($_[1], $type) :
			$type eq '' ? '' :
			exists $struct{$type} ?
				Unserialize ($struct{$type}, $_[1], 1) :
				die  "unknown type $type";
	} elsif (ref $type eq 'SCALAR') {
		my $len = UnserializeCompactSize ($_[1]);
		$res->[$_] = Unserialize ($$type, $_[1], 1) for 0..$len - 1;
	} elsif (ref $type eq 'ARRAY') {
		for (0 .. $#$type / 2) {
			my $field = $type->[$_ * 2];
			my $type2  = $type->[$_ * 2 + 1];
			$res->{$field} = Unserialize ($type2, $_[1], 1);
		}
	} else {
		die "bad type $type";
	}
	if (!$middle) {
		D && warn "$type " . Dump ($type, $res);
		die "garbage " . length ($_[1]) . " bytes at $type"
			if length $_[1];
	}
	return $res;
}

1;
