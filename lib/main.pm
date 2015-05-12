package main;

use warnings;
use strict;

use serialize;
use script;
use ecdsa;
use data;
use base58;
use util;
use chain;

sub D() { 1 }
sub DD() { 0 }

our $CONFIRMATIONS = 10;

our $COINBASE_MATURITY = 100;
our $nTransactionFee = 0;
our $bnProofOfWorkLimit_bits = 32;
our $bnProofOfWorkLimit = ~pack 'B256', '0' x $bnProofOfWorkLimit_bits;

our $blk_best;

sub AmmoFormat {
	my ($ammo) = @_;

	$ammo / $chain::COIN;
}

sub ConfirmHeight {
	$main::blk_best->{nHeight} - $CONFIRMATIONS;
}

sub SetCompact256 {
	my ($nCompact) = @_;

	my $nSize = $nCompact >> 24;
	die "too big $nCompact"
		if $nSize > 256 / 8;
	my $res = $chain::NULL256;
	vec ($res, 32 - $nSize, 8) = $nCompact >> 16	if $nSize >= 1;
	vec ($res, 33 - $nSize, 8) = $nCompact >> 8	if $nSize >= 2;
	vec ($res, 34 - $nSize, 8) = $nCompact		if $nSize >= 3;
	return $res;
}

#
# transaction
#

sub IsCoinBase {
	my ($tx) = @_;

	@{ $tx->{vin} } == 1 && $tx->{vin}[0]{prevout}{hash} eq $chain::NULL256;
}

sub TransactionIncome {
	my ($tx, $last_tx, $spent) = @_;

	my $sum = 0;
	my $last = ''; # "last_tx: @X{ sort keys %$last_tx }";

	for (0 .. $#{ $tx->{vin} }) {
		my $prev = $tx->{vin}[$_]{prevout} or die;
		my $txFrom_h = $prev->{hash};
		die "prevout is null" if $txFrom_h eq $chain::NULL256;
		my $nOut = $prev->{n};

		my $txFrom = data::tx_load ($txFrom_h) ||
		    $last_tx->{$txFrom_h} || die "no tx $X{$txFrom_h}";
		$nOut < @{ $txFrom->{vout} }
			or die "bad n $nOut";

		$txFrom->{vout}[$nOut]{spentHeight} == -1
			or die "double spend";
		$spent->{$txFrom_h}{$nOut}++ == 0
			or die "double spend in the same block";
		
		my $nValue = $txFrom->{vout}[$nOut]{nValue};
		my $scriptPubKey = $txFrom->{vout}[$nOut]{scriptPubKey};
		my $scriptSig = $tx->{vin}[$_]{scriptSig};

		D && warn "$X{$tx->{hash}}:$_ <- $X{$txFrom_h}:$nOut " .
		    "=$nValue $Xr{$scriptSig} <= $Xr{$scriptPubKey} $last";

		next if !$nValue; # blk 168910 tx 3a5e0977cc64 ?

		EvalScriptCheck ($scriptSig, $scriptPubKey, $tx, $_)
			or die "tx check failed";

		$sum += $nValue;
	}
	return $sum;
}

sub TransactionOutcome {
	my ($tx) = @_;

	my $sum = 0;
	for (0 .. $#{ $tx->{vout} }) {
		my $v = $tx->{vout}[$_]{nValue};
		die "txout.nValue negative" if $v >= 2**62;
		D && warn "$X{$tx->{hash}} $_ -> +$v";
		$sum += $v;
	}
	return $sum;
}

sub CheckTransaction {
	my ($tx, $last_tx, $spent) = @_;

	die "vin or vout empty"
		if !@{ $tx->{vin} } || !@{ $tx->{vout} };

	D && warn "$X{$tx->{hash}}";

	my ($out, $in, $fee);
	if (IsCoinBase ($tx)) {
		my $len = length $tx->{vin}[0]{scriptSig};
		die "coinbase script size"
			if $len < 2 || $len > 100;

		$in = 0;
		$out = TransactionOutcome ($tx);
		$fee = GetBlockValue (0);
		D && warn "$X{$tx->{hash}} coin out=$out fee=$fee";
	} else {
		$in = TransactionIncome ($tx, $last_tx, $spent);
		$out = TransactionOutcome ($tx);
		$fee = GetMinFee ($tx);
		D && warn "$X{$tx->{hash}} in=$in fee=$fee out=$out";
		warn "XXX fix getminfree $X{$tx->{hash}} $out > $in - $fee"
			if $out > $in - $fee;
	}
	$last_tx->{$tx->{hash}} = $tx;
	return $out - $in - $fee;
}

sub TransactionFixOutAddr {
	my ($tx) = @_;

	for (0 .. $#{ $tx->{vout} }) {
		my $pub = $tx->{vout}[$_]{scriptPubKey};
		# block 157606 first tx
		my $pub_h = eval { GetKeyHash ($pub) } || 0;
		my $addr = base58::Hash160ToAddress ($pub_h);
		$tx->{vout}[$_]{addr} = $addr;
		$tx->{vout}[$_]{spentHeight} = -1;
	}
}

sub AddTransaction {
	my ($tx) = @_;

	D && warn "add tx $X{$tx->{hash}}";
	if (!data::tx_exists ($tx->{hash})) {
		TransactionFixOutAddr ($tx);
		data::tx_save ($tx->{hash}, $tx);
	}
}

sub ProcessTransaction {
	my ($tx) = @_;

	die "coinbase as individual tx"
		if IsCoinBase ($tx);

	$tx->{hash} = chain::TransactionHash ($tx);

	if (data::tx_exists ($tx->{hash})) {
		warn "tx $X{$tx->{hash}} already processed";
		return;
	}

	AddTransaction ($tx);
	data::blk_tx_add ($chain::NULL256, -1, $tx->{hash});
	warn "new tx $X{$tx->{hash}}";
}

sub GetMinFee {
	my ($tx, $nBlockSize) = @_;

	$nBlockSize ||= 1;

	# Base fee is 1 cent per kilobyte
	my $nBytes = length serialize::Serialize ('CTransaction', $tx);
	my $nMinFee = int (1 + $nBytes / 1000) * $chain::CENT;

	# Transactions under 60K are free as long as block size is under 80K
	# (about 27,000bc if made of 50bc inputs)
	$nMinFee = 0
		if $nBytes < 60000 && $nBlockSize < 80000;

	# Transactions under 3K are free as long as block size is under 200K
	$nMinFee = 0
		if $nBytes < 3000 && $nBlockSize < 200000;

	# To limit dust spam, require 0.01 fee if any output is less than 0.01
	if ($nMinFee < $chain::CENT) {
		$nMinFee = $chain::CENT
			if grep $_->{nValue} < $chain::CENT, @{ $tx->{vout} };
	}

	D && warn "nBlockSize=$nBlockSize nBytes=$nBytes nMinFee=$nMinFee";
	return $nMinFee;
}

sub IsFinal {
	my ($tx, $nBlockTime) = @_;

	return 1 if !$tx->{nLockTime};
	$nBlockTime ||= time;
	return 1 if $tx->{nLockTime} <
		($tx->{nLockTime} < 500000000 ? $blk_best->{nHeight} : $nBlockTime);
	return 0 if grep $_->{nSequence} != $chain::ONES32, @{ $tx->{vin} };
	return 1;
}

sub GetKeyHash {
	my ($scriptPubKey) = @_;

	my $key = script::GetPubKey ($scriptPubKey);
	return $key ? base58::Hash160 ($key) :
		script::GetBitcoinAddressHash160 ($scriptPubKey);
}

#
# block
#

sub GetBlockValue {
	my ($nFees) = @_;

	my $nSubsidy = 50 * $chain::COIN;

	# Subsidy is cut in half every 4 years
	$nSubsidy /= 2 ** int ($blk_best->{nHeight} / 210000);

	D && warn "$nSubsidy + $nFees";
	return $nSubsidy + $nFees;
}

sub BuildMerkleTree {
	my (@h) = @_;

	@h = map base58::Hash ($h[$_] . $h[$_ + ($_ < $#h)]),
		map $_ * 2, 0 .. $#h / 2
			while @h > 1;
	DD && warn "$X{$h[0]}";
	return $h[0];
}

sub CheckBlock {
	my ($blk) = @_;

	D && warn "$X{$blk->{hash}}";

	my $vtx = $blk->{vtx};

	die "size limits failed"
		if !@$vtx;
	die "block timestamp too far in the future"
		if $blk->{nTime} > time () + 2 * 60 * 60;
	die "first tx is not coinbase"
		if !IsCoinBase ($vtx->[0]);
	die "more than one coinbase"
		if grep IsCoinBase ($vtx->[$_]), 1..$#$vtx;

	my $compact = SetCompact256 ($blk->{nBits});
	DD && warn "$X{$compact}";

	die "nBits below minimum work"
		if $compact gt $bnProofOfWorkLimit;
	die "hash doesn't match nBits"
		if reverse ($blk->{hash}) gt $compact;

	$blk->{vtx_h} = [ map $_->{hash} = chain::TransactionHash ($_), @$vtx ];

	die "hashMerkleRoot mismatch"
		if $blk->{hashMerkleRoot} ne BuildMerkleTree (@{ $blk->{vtx_h} });
}

sub SpentBlock {
	my ($blk) = @_;

	my $spent = {};
	my $last_tx = {};
	my $sum = 0;

	$sum += CheckTransaction ($_, $last_tx, $spent) for @{ $blk->{vtx} };

	D && warn "$X{$blk->{hash}} sum $sum";
	$sum <= 0 or die "$X{$blk->{hash}} sum $sum is positive";

	for my $tx_h (keys %$spent) {
	for my $n (keys %{ $spent->{$tx_h} }) {
		D && warn "spent $X{$tx_h} $n at $blk->{nHeight}";
		data::tx_out_spent ($tx_h, $n, $blk->{nHeight});
	}}
}

sub SwitchBranch {
	my ($blk) = @_;

	D && warn "$X{$blk->{hash}}";

	my @new;
	my $fork = $blk;
	while (!$fork->{mainBranch}) {
		unshift @new, $fork;
		$fork = data::blk_exists ($fork->{hashPrevBlock}) or die;
	}

	my @old;
	my $b = $blk_best;
	while ($b->{hash} ne $fork->{hash}) {
		$b->{mainBranch} or die "best not main";
		unshift @old, $b;
		$b = data::blk_exists ($b->{hashPrevBlock}) or die;
	}

	D && warn "fork $X{$fork->{hash}}" .
		" old (@X{map $_->{hash}, @old})" .
		" new (@X{map $_->{hash}, @new})";

	data::tx_trimmain ($fork->{nHeight} + 1) if @old;
	for (@old) {
		$_->{mainBranch} = 0;
		data::blk_connect ($_);
	}
	for (@new) {
		data::blk_load ($_);
		SpentBlock ($_);
		$_->{mainBranch} = 1;
		data::blk_connect ($_);
	}
}

sub ReconnectBlock {
	my ($blk) = @_;

	D && warn "$X{$blk->{hash}}";

	if ($blk->{hash} eq $chain::GenesisHash) {
		$blk->{nHeight} = 0;
		$blk->{mainBranch} = 1;
	} else {
		my $prev = data::blk_exists ($blk->{hashPrevBlock});
		$blk->{nHeight} = $prev && $prev->{nHeight} >= 0 ?
		    $prev->{nHeight} + 1 : -1;
		$blk->{mainBranch} = 0;
	}

	if ($blk_best && $blk->{nHeight} > $blk_best->{nHeight}) {
		SwitchBranch ($blk);
	} else {
		data::blk_connect ($blk);
	}

	$blk_best = $blk
		if !$blk_best || $blk->{nHeight} > $blk_best->{nHeight};

	D && warn "height $blk->{nHeight} main $blk->{mainBranch} " .
		"txs ${\scalar @{ $blk->{vtx} } } " .
		"block $X{$blk->{hash}}";

	if ($blk->{nHeight} != -1) {
		ReconnectBlock (data::blk_exists ($_))
			for data::blk_orphan ($blk->{hash});
	}
}

sub ProcessBlock {
	my ($blk) = @_;

	$blk->{hash} = chain::BlockHash ($blk);
	D && warn "$X{$blk->{hash}}";

	if (data::blk_exists ($blk->{hash})) {
		warn "block $X{$blk->{hash}} already processed";
		return 1;
	}

	CheckBlock ($blk);

	AddTransaction ($_) for @{ $blk->{vtx} };
	data::blk_tx_del ($chain::NULL256, -1, $_) for @{ $blk->{vtx_h} };

	$blk->{nHeight} = -1;
	$blk->{mainBranch} = 0;
	data::blk_save ($blk->{hash}, $blk);

	ReconnectBlock ($blk);

	return $blk->{nHeight} != -1;
}

sub init () {
	my $gen_h = data::blk_genesis ();
	if ($gen_h) {
		$gen_h eq $chain::GenesisHash or die "db of wrong chain";
	} else {
		ProcessBlock (chain::GenesisBlock ());
	}
	$blk_best = data::blk_best () or die "no best";
	warn "chain $cfg::var{CHAIN} best $blk_best->{nHeight} " .
		"$X{$blk_best->{hash}}\n";
}

#
# action
#

sub SignatureHash {
	my ($script, $txTo, $nIn, $nHashType) = @_;

	$nHashType == 1 or die "unknown hashtype=$nHashType";
	$nIn < @{ $txTo->{vin} } or die "bad nIn=$nIn";

	my $txTmp = { %$txTo, vin => [
		map +{ %$_, scriptSig => '' }, @{ $txTo->{vin} }
	] };
	$txTmp->{vin}[$nIn]{scriptSig} = $script;

	my $ss = serialize::Serialize ('CTransaction', $txTmp) . 
		serialize::SerializeInt32 ($nHashType);
	return base58::Hash ($ss);
}

sub CheckSig {
	my ($script, $txTo, $nIn, $sig, $pub) = @_;

	# last byte of sig is tx type
	$sig =~ s/(\C)\z// or die "empty sig";
	my $nHashType = ord $1;

	my $hash = SignatureHash ($script, $txTo, $nIn, $nHashType)
		or return;
	warn "hash=$X{$hash} sig=$Xr{$sig} pub=$Xr{$pub} type=$nHashType";

	my $v = eval { ecdsa::Verify ({ pub => $pub }, $hash, $sig) } || 0;
	warn "warn ecdsa::Verify failed: $@" if $@;
	return $v;
}

our $PROB_CHECKSIG = 1;

sub EvalScriptCheck {
	my ($scriptSig, $scriptPubKey, $txTo, $nIn) = @_;

	# XXX PK/PKH/SH/MS/NULL/NONSTD

	return script::VerifyTx ($scriptSig, $scriptPubKey, sub {
		my ($script, $sig, $pub) = @_;
		return 1 if rand () > $PROB_CHECKSIG;
		return CheckSig ($script, $txTo, $nIn, $sig, $pub);
	});
}

1;
