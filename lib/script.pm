package script;

use warnings;
use strict;

use util;
use base58;
use ecdsa;

our %SIGHASH = (
	ALL			=> 1,
	NONE			=> 2,
	SINGLE			=> 3,
	ANYONECANPAY		=> 0x80,
);

our %OP = (
	# push value
	OP_0			=> 0x00, OP_FALSE	=> 0x00,
	OP_PUSHDATA1		=> 0x4c,
	OP_PUSHDATA2		=> 0x4d,
	OP_PUSHDATA4		=> 0x4e,
	OP_1NEGATE		=> 0x4f,
	OP_RESERVED		=> 0x50,
	OP_1			=> 0x51, OP_TRUE	=> 0x51,
	OP_2			=> 0x52,
	OP_3			=> 0x53,
	OP_4			=> 0x54,
	OP_5			=> 0x55,
	OP_6			=> 0x56,
	OP_7			=> 0x57,
	OP_8			=> 0x58,
	OP_9			=> 0x59,
	OP_10			=> 0x5a,
	OP_11			=> 0x5b,
	OP_12			=> 0x5c,
	OP_13			=> 0x5d,
	OP_14			=> 0x5e,
	OP_15			=> 0x5f,
	OP_16			=> 0x60,

	# control
	OP_NOP			=> 0x61,
	OP_VER			=> 0x62,
	OP_IF			=> 0x63,
	OP_NOTIF		=> 0x64,
	OP_VERIF		=> 0x65,
	OP_VERNOTIF		=> 0x66,
	OP_ELSE			=> 0x67,
	OP_ENDIF		=> 0x68,
	OP_VERIFY		=> 0x69,
	OP_RETURN		=> 0x6a,

	# stackops
	OP_TOALTSTACK		=> 0x6b,
	OP_FROMALTSTACK		=> 0x6c,
	OP_2DROP		=> 0x6d,
	OP_2DUP			=> 0x6e,
	OP_3DUP			=> 0x6f,
	OP_2OVER		=> 0x70,
	OP_2ROT			=> 0x71,
	OP_2SWAP		=> 0x72,
	OP_IFDUP		=> 0x73,
	OP_DEPTH		=> 0x74,
	OP_DROP			=> 0x75,
	OP_DUP			=> 0x76,
	OP_NIP			=> 0x77,
	OP_OVER			=> 0x78,
	OP_PICK			=> 0x79,
	OP_ROLL			=> 0x7a,
	OP_ROT			=> 0x7b,
	OP_SWAP			=> 0x7c,
	OP_TUCK			=> 0x7d,

	# spliceops
	OP_CAT			=> 0x7e,
	OP_SUBSTR		=> 0x7f,
	OP_LEFT			=> 0x80,
	OP_RIGHT		=> 0x81,
	OP_SIZE			=> 0x82,

	# bitlogic
	OP_INVERT		=> 0x83,
	OP_AND			=> 0x84,
	OP_OR			=> 0x85,
	OP_XOR			=> 0x86,
	OP_EQUAL		=> 0x87,
	OP_EQUALVERIFY		=> 0x88,
	OP_RESERVED1		=> 0x89,
	OP_RESERVED2		=> 0x8a,

	# numeric
	OP_1ADD			=> 0x8b,
	OP_1SUB			=> 0x8c,
	OP_2MUL			=> 0x8d,
	OP_2DIV			=> 0x8e,
	OP_NEGATE		=> 0x8f,
	OP_ABS			=> 0x90,
	OP_NOT			=> 0x91,
	OP_0NOTEQUAL		=> 0x92,

	OP_ADD			=> 0x93,
	OP_SUB			=> 0x94,
	OP_MUL			=> 0x95,
	OP_DIV			=> 0x96,
	OP_MOD			=> 0x97,
	OP_LSHIFT		=> 0x98,
	OP_RSHIFT		=> 0x99,

	OP_BOOLAND		=> 0x9a,
	OP_BOOLOR		=> 0x9b,
	OP_NUMEQUAL		=> 0x9c,
	OP_NUMEQUALVERIFY	=> 0x9d,
	OP_NUMNOTEQUAL		=> 0x9e,
	OP_LESSTHAN		=> 0x9f,
	OP_GREATERTHAN		=> 0xa0,
	OP_LESSTHANOREQUAL	=> 0xa1,
	OP_GREATERTHANOREQUAL	=> 0xa2,
	OP_MIN			=> 0xa3,
	OP_MAX			=> 0xa4,

	OP_WITHIN		=> 0xa5,

	# crypto
	OP_RIPEMD160		=> 0xa6,
	OP_SHA1			=> 0xa7,
	OP_SHA256		=> 0xa8,
	OP_HASH160		=> 0xa9,
	OP_HASH256		=> 0xaa,
	OP_CODESEPARATOR	=> 0xab,
	OP_CHECKSIG		=> 0xac,
	OP_CHECKSIGVERIFY	=> 0xad,
	OP_CHECKMULTISIG	=> 0xae,
	OP_CHECKMULTISIGVERIFY	=> 0xaf,

	# expansion
	OP_NOP1			=> 0xb0,
	OP_NOP2			=> 0xb1,
	OP_NOP3			=> 0xb2,
	OP_NOP4			=> 0xb3,
	OP_NOP5			=> 0xb4,
	OP_NOP6			=> 0xb5,
	OP_NOP7			=> 0xb6,
	OP_NOP8			=> 0xb7,
	OP_NOP9			=> 0xb8,
	OP_NOP10		=> 0xb9,

	# templatematchingparams
	OP_SMALLDATA		=> 0xf9,
	OP_SMALLINTEGER		=> 0xfa,
	OP_PUBKEYS		=> 0xfb,
	OP_PUBKEYHASH		=> 0xfd,
	OP_PUBKEY		=> 0xfe,

	OP_INVALIDOPCODE	=> 0xff,
);

our %ROP = reverse %OP;

sub Int {
	my ($i) = @_;

	return	$i == -1 ?
			chr $OP{OP_1NEGATE} :
		$i <= 0 ?
			die "$i" :
		$i >= 1 && $i <= 16 ?
			chr $OP{"OP_$i"} :
		Bin (pack
			$i < 2**8 ? 'C' :
			$i < 2**16 ? 'v' :
			$i < 2**24 ? 'VX' : 'V', $i); 
}

sub Bin {
	my ($str) = @_;

	my $len = length $str;
	my $res =
		$len < $OP{OP_PUSHDATA1} ?
			chr $len :
		$len < 0xff ?
			pack 'CC', $OP{OP_PUSHDATA1}, $len :
			pack 'Cv', $OP{OP_PUSHDATA2}, $len;
	return $res . $str;
}

sub Op {
	my ($op) = @_;

	exists $OP{$op} ? chr $OP{$op} : die "unknown op $op";
}

sub GetOp {
	# $_[0] gets modified

	die "empty script" if $_[0] eq '';

	(my $op, $_[0]) = unpack 'C a*', $_[0];
	($op, my $par, $_[0]) =
		$op > 0 && $op < $OP{OP_PUSHDATA1} ?
			('OP_PUSHDATA', unpack "a$op a*", $_[0]) :
		$op == $OP{OP_PUSHDATA1} ? ($ROP{$op}, unpack 'C/a a*', $_[0]) :
		$op == $OP{OP_PUSHDATA2} ? ($ROP{$op}, unpack 'v/a a*', $_[0]) :
		$op == $OP{OP_PUSHDATA4} ? ($ROP{$op}, unpack 'V/a a*', $_[0]) :
		exists $ROP{$op} ? ($ROP{$op}, '', $_[0]) :
		die "unknown tag $op";
	return wantarray ? ($op, $par) : $op;
}

sub bool { $_[0] ? chr 1 : chr 0 }
sub true { $_[0] eq chr 1 }

our (@stack, $checksig_cb); # will be localized

sub Pop() { @stack ? pop @stack : die "empty stack" }
sub Push(@) { push @stack, @_ }
sub Verify() { true (Pop) || die "fail" }

our %Exe; %Exe = (
	OP_1NEGATE		=> sub { Push "\x81" },
	OP_DUP			=> sub { my $el = Pop; Push $el, $el },
	OP_SHA256		=> sub { Push base58::sha256 (Pop) },
	OP_HASH160		=> sub { Push base58::Hash160 (Pop) },
	OP_EQUAL		=> sub { Push bool (Pop eq Pop) },
	OP_VERIFY		=> \&Verify,
	OP_EQUALVERIFY		=> sub { $Exe{OP_EQUAL} (); Verify; },
	OP_CHECKSIGVERIFY	=> sub { $Exe{OP_CHECKSIG} (); Verify; },
	OP_CHECKSIG		=> sub {
		my $pub = Pop;
		my $sig = Pop;
		Push bool ($checksig_cb->($sig, $pub));
	},
	# OP_IF OP_NOTIF OP_ELSE OP_ENDIF
	# stack ops
	# OP_SIZE
	# arithmetic
	# OP_RIPEMD160 OP_SHA1 OP_HASH256
	# OP_CODESEPARATOR?
	# OP_CHECKMULTISIG OP_CHECKMULTISIGVERIFY
);

sub Exe {
	my ($script, $cb) = @_;

	local @stack;
	local $checksig_cb = $cb;
	while (length $script) {
		my ($op, $par) = GetOp ($script);
		warn "debug $op $Xr{$par} stack @Xr{@stack}\n";
		if ($op =~ /^OP_PUSHDATA/) {
			Push $par;
		} elsif ($op =~ /^OP_NOP\d+\z/) {
			# nothing
		} elsif ($op =~ /^OP_(\d+)\z/) {
			Push ($1 ? chr $1 : '');
		} elsif (exists $Exe{$op}) {
			$Exe{$op} ();
		} else {
			die "$op is not implemented";
		}
	}
	return true (Pop);
}

sub Parse {
	my ($script) = @_;

	my $len = length $script;
	while ($script ne '') {
		my $pc = $len - length $script;
		my ($op, $par) = GetOp ($script);
		print "$pc: $op $Xr{$par}\n";
	}
}

sub SetBitcoinAddress {
	my ($hash160) = @_;

	Op ('OP_DUP') .
	Op ('OP_HASH160') .
	Bin ($hash160) .
	Op ('OP_EQUALVERIFY') .
	Op ('OP_CHECKSIG');
}

# fix for blocks 71036 and 127630
my $nop = Op ('OP_NOP');
my $cs = Op ('OP_CHECKSIG');
my $fix1 = qr/^($nop|$cs)+\z/o;

sub GetBitcoinAddressHash160 {
	my ($script) = @_;

	GetOp ($script) eq 'OP_DUP'				or return;
	GetOp ($script) eq 'OP_HASH160'				or return;
	my ($op, $hash) = GetOp ($script);
	$op eq 'OP_PUSHDATA' && length ($hash) == 160 / 8	or return;
	GetOp ($script) eq 'OP_EQUALVERIFY'			or return;
	GetOp ($script) eq 'OP_CHECKSIG'			or return;
	$script =~ s/$fix1//;
	$script eq ''						or return;
	return $hash;
}

sub GetPubKey {
	my ($script) = @_;

	my ($op, $pub) = GetOp ($script);
	$op =~ /^OP_PUSHDATA/					or return;
	GetOp ($script) eq 'OP_CHECKSIG'			or return;
	$script eq ''						or return;
	return $pub;
}

1;
