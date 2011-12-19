package script;

use warnings;
use strict;

our %SIGHASH = (
	ALL			=> 1,
	NONE			=> 2,
	SINGLE			=> 3,
	ANYONECANPAY		=> 0x80,
);

my $n;	# nasty effect is supposed

our %OP = (
	# push value
	OP_0			=> 0,
	OP_FALSE		=> 0,
	OP_PUSHDATA1		=> ($n = 76) + 0,
	OP_PUSHDATA2		=> ++$n + 0,
	OP_PUSHDATA4		=> ++$n + 0,
	OP_1NEGATE		=> ++$n + 0,
	OP_RESERVED		=> ++$n + 0,
	OP_1			=> ++$n + 0,
	OP_TRUE			=> $n + 0,
	OP_2			=> ++$n + 0,
	OP_3			=> ++$n + 0,
	OP_4			=> ++$n + 0,
	OP_5			=> ++$n + 0,
	OP_6			=> ++$n + 0,
	OP_7			=> ++$n + 0,
	OP_8			=> ++$n + 0,
	OP_9			=> ++$n + 0,
	OP_10			=> ++$n + 0,
	OP_11			=> ++$n + 0,
	OP_12			=> ++$n + 0,
	OP_13			=> ++$n + 0,
	OP_14			=> ++$n + 0,
	OP_15			=> ++$n + 0,
	OP_16			=> ++$n + 0,

	# control
	OP_NOP			=> ++$n + 0,
	OP_VER			=> ++$n + 0,
	OP_IF			=> ++$n + 0,
	OP_NOTIF		=> ++$n + 0,
	OP_VERIF		=> ++$n + 0,
	OP_VERNOTIF		=> ++$n + 0,
	OP_ELSE			=> ++$n + 0,
	OP_ENDIF		=> ++$n + 0,
	OP_VERIFY		=> ++$n + 0,
	OP_RETURN		=> ++$n + 0,

	# stack ops
	OP_TOALTSTACK		=> ++$n + 0,
	OP_FROMALTSTACK		=> ++$n + 0,
	OP_2DROP		=> ++$n + 0,
	OP_2DUP			=> ++$n + 0,
	OP_3DUP			=> ++$n + 0,
	OP_2OVER		=> ++$n + 0,
	OP_2ROT			=> ++$n + 0,
	OP_2SWAP		=> ++$n + 0,
	OP_IFDUP		=> ++$n + 0,
	OP_DEPTH		=> ++$n + 0,
	OP_DROP			=> ++$n + 0,
	OP_DUP			=> ++$n + 0,
	OP_NIP			=> ++$n + 0,
	OP_OVER			=> ++$n + 0,
	OP_PICK			=> ++$n + 0,
	OP_ROLL			=> ++$n + 0,
	OP_ROT			=> ++$n + 0,
	OP_SWAP			=> ++$n + 0,
	OP_TUCK			=> ++$n + 0,

	# splice ops
	OP_CAT			=> ++$n + 0,
	OP_SUBSTR		=> ++$n + 0,
	OP_LEFT			=> ++$n + 0,
	OP_RIGHT		=> ++$n + 0,
	OP_SIZE			=> ++$n + 0,

	# bit logic
	OP_INVERT		=> ++$n + 0,
	OP_AND			=> ++$n + 0,
	OP_OR			=> ++$n + 0,
	OP_XOR			=> ++$n + 0,
	OP_EQUAL		=> ++$n + 0,
	OP_EQUALVERIFY		=> ++$n + 0,
	OP_RESERVED1		=> ++$n + 0,
	OP_RESERVED2		=> ++$n + 0,

	# numeric
	OP_1ADD			=> ++$n + 0,
	OP_1SUB			=> ++$n + 0,
	OP_2MUL			=> ++$n + 0,
	OP_2DIV			=> ++$n + 0,
	OP_NEGATE		=> ++$n + 0,
	OP_ABS			=> ++$n + 0,
	OP_NOT			=> ++$n + 0,
	OP_0NOTEQUAL		=> ++$n + 0,

	OP_ADD			=> ++$n + 0,
	OP_SUB			=> ++$n + 0,
	OP_MUL			=> ++$n + 0,
	OP_DIV			=> ++$n + 0,
	OP_MOD			=> ++$n + 0,
	OP_LSHIFT		=> ++$n + 0,
	OP_RSHIFT		=> ++$n + 0,

	OP_BOOLAND		=> ++$n + 0,
	OP_BOOLOR		=> ++$n + 0,
	OP_NUMEQUAL		=> ++$n + 0,
	OP_NUMEQUALVERIFY	=> ++$n + 0,
	OP_NUMNOTEQUAL		=> ++$n + 0,
	OP_LESSTHAN		=> ++$n + 0,
	OP_GREATERTHAN		=> ++$n + 0,
	OP_LESSTHANOREQUAL	=> ++$n + 0,
	OP_GREATERTHANOREQUAL	=> ++$n + 0,
	OP_MIN			=> ++$n + 0,
	OP_MAX			=> ++$n + 0,

	OP_WITHIN		=> ++$n + 0,

	# crypto
	OP_RIPEMD160		=> ++$n + 0,
	OP_SHA1			=> ++$n + 0,
	OP_SHA256		=> ++$n + 0,
	OP_HASH160		=> ++$n + 0,
	OP_HASH256		=> ++$n + 0,
	OP_CODESEPARATOR	=> ++$n + 0,
	OP_CHECKSIG		=> ++$n + 0,
	OP_CHECKSIGVERIFY	=> ++$n + 0,
	OP_CHECKMULTISIG	=> ++$n + 0,
	OP_CHECKMULTISIGVERIFY	=> ++$n + 0,

	# multi-byte opcodes
	#OP_SINGLEBYTE_END	=> 0xF0,
	#OP_DOUBLEBYTE_BEGIN	=> ($n = 0xF000) + 0,

	# template matching params
	#OP_PUBKEY		=> ++$n + 0,
	#OP_PUBKEYHASH		=> ++$n + 0,

	#OP_INVALIDOPCODE	=> 0xFFFF,
);

our %ROP = reverse %OP;

our $EXE;

# $EXE[ $OP{OP_...} ] = sub { ... }

sub Int {
	my ($i) = @_;

	return	$i == -1 ?
			chr $OP{OP_1NEGATE} :
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
		exists $ROP{$op} ? ($ROP{$op}, undef, $_[0]) :
		die "unknown tag $op";
	return wantarray ? ($op, $par) : $op;
}

sub Parse {
	my ($script) = @_;

	my $len = length $script;
	while ($script ne '') {
		my $pc = $len - length $script;
		my ($op, $par) = GetOp ($script);
		print "$pc: $op",
			defined $par ? ' 0x' . unpack 'H*', $par : '',
			"\n";
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

sub GetBitcoinAddressHash160 {
	my ($script) = @_;

	GetOp ($script) eq 'OP_DUP'				or return;
	GetOp ($script) eq 'OP_HASH160'				or return;
	my ($op, $hash) = GetOp ($script);
	$op eq 'OP_PUSHDATA' && length ($hash) == 160 / 8	or return;
	GetOp ($script) eq 'OP_EQUALVERIFY'			or return;
	GetOp ($script) eq 'OP_CHECKSIG'			or return;
	$script =~ s/^\xac+\z//;		# yo block 71036
	$script =~ s/^\x61+\z//;		# yo block 127630
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
