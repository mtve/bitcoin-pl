package main;

use warnings;
use strict;

use serialize;
use script;
use ecdsa;
use data;
use base58;
use util;

sub D() { 1 }
sub DD() { 0 }

our $CONFIRMATIONS = 10;

our $COIN = 100000000;
our $CENT = 1000000;
our $COINBASE_MATURITY = 100;
our $nTransactionFee = 0;
our $bnProofOfWorkLimit_bits = 32;
our $bnProofOfWorkLimit = ~pack 'B256', '0' x $bnProofOfWorkLimit_bits;

our $NULL256 = "\0" x (256 / 8);
our $ONES32 = 0xffffffff;

our $pszTimestamp =
	'The Times 03/Jan/2009 Chancellor on brink of second bailout for banks';
our $GenesisPubKey = reverse pack 'H*',
	'5F1DF16B2B704C8A578D0BBAF74D385CDE12C11EE50455F3C438EF4C3FBCF649' .
	'B6DE611FEAE06279A60939E028A8D65C10B73071A6F16719274855FEB0FD8A6704';
our $GenesisMerkleRoot = reverse pack 'H*',
	'4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b';
our $GenesisHash = reverse pack 'H*',
	'000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f';

our $blk_best;

sub AmmoFormat {
	my ($ammo) = @_;

	$ammo / $COIN;
}

sub ConfirmHeight {
	$main::blk_best->{nHeight} - $CONFIRMATIONS;
}

sub SetCompact256 {
	my ($nCompact) = @_;

	my $nSize = $nCompact >> 24;
	die "too big $nCompact"
		if $nSize > 256 / 8;
	my $res = $NULL256;
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

	@{ $tx->{vin} } == 1 && $tx->{vin}[0]{prevout}{hash} eq $NULL256;
}

sub TransactionIncome {
	my ($tx, $last_tx, $spent) = @_;

	my $sum = 0;
	my $last = "last_tx: @util::b2h{ sort keys %$last_tx }";

	for (0 .. $#{ $tx->{vin} }) {
		my $prev = $tx->{vin}[$_]{prevout};
		my $txFrom_h = $prev->{hash};
		die "prevout is null" if $txFrom_h eq $NULL256;
		my $nOut = $prev->{n};

		my $txFrom = data::tx_load ($txFrom_h) ||
		    $last_tx->{$txFrom_h} || die "no tx $util::b2h{$txFrom_h}";
		$nOut < @{ $txFrom->{vout} }
			or die "bad n $nOut";

		$txFrom->{vout}[$nOut]{spentHeight} == -1
			or die "double spend";
		$spent->{$txFrom_h}{$nOut}++ == 0
			or die "double spend in the same block";
		
		my $nValue = $txFrom->{vout}[$nOut]{nValue};
		my $scriptPubKey = $txFrom->{vout}[$nOut]{scriptPubKey};

		D && warn "$util::b2h{$tx->{hash}} $_ <- " .
		    "$util::b2h{$txFrom_h} $nOut =$nValue $last";

		EvalScriptCheck ($tx->{vin}[$_]{scriptSig}, $scriptPubKey,
			$tx, $_) or die "tx check failed";

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
		D && warn "$util::b2h{$tx->{hash}} $_ -> +$v";
		$sum += $v;
	}
	return $sum;
}

sub CheckTransaction {
	my ($tx, $last_tx, $spent) = @_;

	die "vin or vout empty"
		if !@{ $tx->{vin} } || !@{ $tx->{vout} };

	D && warn "$util::b2h{$tx->{hash}}";

	my ($out, $in, $fee);
	if (IsCoinBase ($tx)) {
		my $len = length $tx->{vin}[0]{scriptSig};
		die "coinbase script size"
			if $len < 2 || $len > 100;

		$in = 0;
		$out = TransactionOutcome ($tx);
		$fee = GetBlockValue (0);
		D && warn "$util::b2h{$tx->{hash}} coin out=$out fee=$fee";
	} else {
		$in = TransactionIncome ($tx, $last_tx, $spent);
		$out = TransactionOutcome ($tx);
		$fee = GetMinFee ($tx);
		D && warn "$util::b2h{$tx->{hash}} in=$in fee=$fee out=$out";
		warn "XXX fix getminfree $util::b2h{$tx->{hash}} $out > $in - $fee"
			if $out > $in - $fee;
	}
	$last_tx->{$tx->{hash}} = $tx;
	return $out - $in - $fee;
}

sub TransactionFixOutAddr {
	my ($tx) = @_;

	for (0 .. $#{ $tx->{vout} }) {
		my $pub = $tx->{vout}[$_]{scriptPubKey};
		my $pub_h = eval { GetKeyHash ($pub) } || 0; # fuck you, block 157606
		my $addr = base58::Hash160ToAddress ($pub_h);
		$tx->{vout}[$_]{addr} = $addr;
		$tx->{vout}[$_]{spentHeight} = -1;
	}
}

sub AddTransaction {
	my ($tx) = @_;

	D && warn "add tx $util::b2h{$tx->{hash}}";
	if (!data::tx_exists ($tx->{hash})) {
		TransactionFixOutAddr ($tx);
		data::tx_save ($tx->{hash}, $tx);
	}
}

sub TransactionHash {
	my ($tx) = @_;

	return base58::Hash (serialize::Serialize ('CTransaction', $tx));
}

sub ProcessTransaction {
	my ($tx) = @_;

	die "coinbase as individual tx"
		if IsCoinBase ($tx);

	$tx->{hash} = TransactionHash ($tx);

	if (data::tx_exists ($tx->{hash})) {
		warn "tx $util::b2h{$tx->{hash}} already processed";
		return;
	}

	AddTransaction ($tx);
	data::blk_tx_add ($NULL256, -1, $tx->{hash});
	warn "new tx $util::b2h{$tx->{hash}}";
}

sub GetMinFee {
	my ($tx, $nBlockSize) = @_;

	$nBlockSize ||= 1;

	# Base fee is 1 cent per kilobyte
	my $nBytes = length serialize::Serialize ('CTransaction', $tx);
	my $nMinFee = int (1 + $nBytes / 1000) * $CENT;

	# Transactions under 60K are free as long as block size is under 80K
	# (about 27,000bc if made of 50bc inputs)
	$nMinFee = 0
		if $nBytes < 60000 && $nBlockSize < 80000;

	# Transactions under 3K are free as long as block size is under 200K
	$nMinFee = 0
		if $nBytes < 3000 && $nBlockSize < 200000;

	# To limit dust spam, require 0.01 fee if any output is less than 0.01
	if ($nMinFee < $CENT) {
		$nMinFee = $CENT
			if grep $_->{nValue} < $CENT, @{ $tx->{vout} };
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
	return 0 if grep $_->{nSequence} != $ONES32, @{ $tx->{vin} };
	return 1;
}

sub GetKeyHash {
	my ($scriptPubKey) = @_;

	my $key = script::GetPubKey ($scriptPubKey);
	return $key ? base58::Hash160 ($key) :
		script::GetBitcoinAddressHash160 ($scriptPubKey);
}

sub IsMine {
	my ($scriptPubKey) = @_;

	my $key = script::GetPubKey ($scriptPubKey);
	my $key_h = $key ? base58::Hash160 ($key) :
		script::GetBitcoinAddressHash160 ($scriptPubKey) || return;
	my $k = data::key_load ($key_h);
	return if !$k;
	return ($key ? 'OP_PUBKEY' : 'OP_PUBKEYHASH', $k);
}

sub GetCredit_ {
	my ($tx) = @_;

	my $nCredit = 0;
	$nCredit += $_->{nValue}
		for grep IsMine ($_->{scriptPubKey}), @{ $tx->{vout} };
	return $nCredit;	
}

sub GetDepthInMainChain_ {
	my ($tx) = @_;

	my $blk_h = $tx->{blk_h} or die "no block hash";
	my $blk = data::blk_exists ($blk_h) or die "no block";
	return $blk_best->{nHeight} - $blk->{nHeight} + 1;
}

sub GetBlocksToMaturity_ {
	my ($tx) = @_;

	return 0 if !IsCoinBase ($tx);
	my $m = ($COINBASE_MATURITY + 20) - GetDepthInMainChain ($tx);
	return $m > 0 ? $m : 0;
}

#
# block
#

sub GetBlockValue {
	my ($nFees) = @_;

	my $nSubsidy = 50 * $COIN;

	# Subsidy is cut in half every 4 years
	$nSubsidy /= 2 ** int ($blk_best->{nHeight} / 210000);

	D && warn "$nSubsidy + $nFees";
	return $nSubsidy + $nFees;
}

sub GetNextWorkRequired_ {
	my ($block) = @_;

	my $nTargetTimespan = 14 * 24 * 60 * 60;	# two weeks
	my $nTargetSpacing = 10 * 60;
	my $nInterval = $nTargetTimespan / $nTargetSpacing;

	# Only change once per interval
	return $block->{nBits}
		if ($block->{nHeight} + 1) % $nInterval != 0;

	# Go back by what we want to be 14 days worth of blocks
	my $first = $block;
	for (1 .. $nInterval - 1) {
		die if !exists $first->{hashPrevBlock};
		$first = data::blk_exists ($first->{hashPrevBlock}) or die;
	}

	my $nActualTimespan = $block->{nTime} - $first->{nTime};
	D && warn "nActualTimespan = $nActualTimespan before bounds\n";
	$nActualTimespan = int $nTargetTimespan / 4
		if $nActualTimespan < $nTargetTimespan / 4;
	$nActualTimespan = $nTargetTimespan * 4
		if $nActualTimespan > $nTargetTimespan * 4;

	# Retarget
	my $bn_e = $block->{nBits} >> 24;
	my $bn_m = $block->{nBits} & 0xffffff;
	my $bn_mn = int $bn_m * $nActualTimespan / $nTargetTimespan;
	if ($bn_mn > 0x7fffff) {
		$bn_e++;
		$bn_mn >>= 8;
	} elsif ($bn_mn <= 0x007fff) {
		$bn_e--;
		$bn_mn = int 256 * $bn_m * $nActualTimespan / $nTargetTimespan;
	}
	die if $bn_mn > 0x7fffff || $bn_mn <= 0x007fff;
	my $bn_emax = 256 / 8 - $bnProofOfWorkLimit_bits / 8 + 1;
	$bn_e = $bn_emax, $bn_mn = 0x00ffff
		if $bn_e > $bn_emax ||
			($bn_e == $bn_emax && $bn_mn > 0x00ffff);
	my $bn = ($bn_e << 24) | $bn_mn;

	# debug print
	D && warn "GetNextWorkRequired RETARGET\n";
	D && warn "nTargetTimespan = $nTargetTimespan " .
		"nActualTimespan = $nActualTimespan\n";
	D && warn "Before: $block->{nBits} After: $bn\n";

	return $bn;
}

sub BuildMerkleTree {
	my (@h) = @_;

	@h = map base58::Hash ($h[$_] . $h[$_ + ($_ < $#h)]),
		map $_ * 2, 0 .. $#h / 2
			while @h > 1;
	DD && warn "$util::b2h{$h[0]}";
	return $h[0];
}

sub CheckBlock {
	my ($blk) = @_;

	D && warn "$util::b2h{$blk->{hash}}";

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
	DD && warn "$util::b2h{$compact}";

	die "nBits below minimum work"
		if $compact gt $bnProofOfWorkLimit;
	die "hash doesn't match nBits"
		if reverse ($blk->{hash}) gt $compact;

	$blk->{vtx_h} = [ map $_->{hash} = TransactionHash ($_), @$vtx ];

	die "hashMerkleRoot mismatch"
		if $blk->{hashMerkleRoot} ne BuildMerkleTree (@{ $blk->{vtx_h} });
}

sub SpentBlock {
	my ($blk) = @_;

	my $spent = {};
	my $last_tx = {};
	my $sum = 0;

	$sum += CheckTransaction ($_, $last_tx, $spent) for @{ $blk->{vtx} };

	D && warn "$util::b2h{$blk->{hash}} sum $sum";
	$sum <= 0 or die "$util::b2h{$blk->{hash}} sum $sum is positive";

	for my $tx_h (keys %$spent) {
	for my $n (keys %{ $spent->{$tx_h} }) {
		D && warn "spent $util::b2h{$tx_h} $n at $blk->{nHeight}";
		data::tx_out_spent ($tx_h, $n, $blk->{nHeight});
	}}
}

sub SwitchBranch {
	my ($blk) = @_;

	D && warn "$util::b2h{$blk->{hash}}";

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

	D && warn "fork $util::b2h{$fork->{hash}}" .
		" old (@util::b2h{map $_->{hash}, @old})" .
		" new (@util::b2h{map $_->{hash}, @new})";

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

	D && warn "$util::b2h{$blk->{hash}}";

	if ($blk->{hash} eq $GenesisHash) {
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
		"block $util::b2h{$blk->{hash}}";

	if ($blk->{nHeight} != -1) {
		ReconnectBlock (data::blk_exists ($_))
			for data::blk_orphan ($blk->{hash});
	}
}

sub BlockHash {
	my ($blk) = @_;

	return base58::Hash (serialize::Serialize ('CBlockOnly', $blk));
}

sub ProcessBlock {
	my ($blk) = @_;

	$blk->{hash} = BlockHash ($blk);
	D && warn "$util::b2h{$blk->{hash}}";

	if (data::blk_exists ($blk->{hash})) {
		warn "block $util::b2h{$blk->{hash}} already processed";
		return 1;
	}

	CheckBlock ($blk);

	AddTransaction ($_) for @{ $blk->{vtx} };
	data::blk_tx_del ($NULL256, -1, $_) for @{ $blk->{vtx_h} };

	$blk->{nHeight} = -1;
	$blk->{mainBranch} = 0;
	data::blk_save ($blk->{hash}, $blk);

	ReconnectBlock ($blk);

	return $blk->{nHeight} != -1;
}

sub GenesisBlock {
	my $tx0	= {
		nVersion	=> 1,
		vin		=> [ {
			prevout		=> {
				hash		=> $NULL256,
				n		=> $ONES32,
			},
			scriptSig	=>
				script::Int (486604799) .
				script::Bin ("\4") .
				script::Bin ($pszTimestamp),
			nSequence	=> $ONES32,
		} ],
		vout		=> [ {
			nValue		=> 50 * $COIN,
			scriptPubKey	=>
				script::Bin ($GenesisPubKey) .
				script::Op ('OP_CHECKSIG'),
		} ],
		nLockTime	=> 0,
	};
	my $blk0 = {
		nVersion	=> 1,
		hashPrevBlock	=> $NULL256,
		hashMerkleRoot	=> TransactionHash ($tx0),
		nTime		=> 1231006505,
		nBits		=> 0x1d00ffff,
		nNonce		=> 2083236893,
		vtx		=> [ $tx0 ],
	};

	$blk0->{hashMerkleRoot} eq $GenesisMerkleRoot
		or die "assert GenesisMerkleRoot";
	BlockHash ($blk0) eq $GenesisHash
		or die "assert GenesisHash";

	return $blk0;
}

sub init () {
	ProcessBlock (GenesisBlock ());
	$blk_best = data::blk_best () or die "no best";
	warn "best $blk_best->{nHeight} $util::b2h{$blk_best->{hash}}";
}

#
# action
#

sub GetBalance_ {
	my $nTotal = 0;
	for my $tx_h (keys my %XXX) {
		my $tx = data::tx_load ($tx_h);
		$nTotal += GetCredit ($tx)
			if IsFinal ($tx) && !$tx->{fSpent};
	}
	return $nTotal;
}

sub SelectCoins_ {
	my ($nTotalValue) = @_;

	my @coins;
	my $nTotal;
	for my $tx_h (sort keys my %XXX) {
		my $tx = data::tx_load ($tx_h);
		IsFinal ($tx) && !$tx->{fSpent} or next;
		my $val= GetCredit ($tx) or next;
		push @coins, $tx;
		$nTotal += $val;
		return @coins if $nTotal >= $nTotalValue;
	}
	die "This is an oversized transaction";
}

sub SignatureHash {
	my ($scriptCode, $txTo, $nIn, $nHashType) = @_;

	$nHashType == $script::SIGHASH{ALL}
		or die "nHashType $nHashType is not supported"
			if $nHashType;	# hello, block 110300 last tx

	$nIn < @{ $txTo->{vin} }
		or die "assert";

	# In case concatenating two scripts ends up with two codeseparators,
	# or an extra one at the end, this prevents all those possible incompatibilities.
	#??? script::FindAndDelete ($scriptCode, 'OP_CODESEPARATOR');

	my $txTmp = {
		nVersion	=> $txTo->{nVersion},
		nLockTime	=> $txTo->{nLockTime},
		vin		=> [ map +{ %$_ }, @{ $txTo->{vin} } ],
		vout		=> [ map +{ %$_ }, @{ $txTo->{vout} } ],
	};
	$_->{scriptSig} = '' for @{ $txTmp->{vin} };
	$txTmp->{vin}[$nIn]{scriptSig} = $scriptCode;

	my $ss = serialize::Serialize ('CTransaction', $txTmp) . 
		serialize::SerializeInt32 ($nHashType);
	return base58::Hash ($ss);
}

sub Solver {
	my ($scriptPubKey, $hash, $nHashType) = @_;

	my ($typ, $key) = IsMine ($scriptPubKey)
		or die "not mine";
	my $sig = ecdsa::Sign ($key, $hash);
	my $scriptSig = script::Bin ($sig . pack 'C', $nHashType) .
		($typ eq 'OP_PUBKEYHASH' ? script::Bin ($key->{pub}) : '');
	return $scriptSig;
}

sub EvalScriptCheck {
	my ($scriptSig, $scriptPubKey, $txTo, $nIn) = @_;

	my ($op, $sig) = script::GetOp ($scriptSig)
		or warn ("no getop"), return;
	$op =~ /^OP_PUSHDATA/
		or warn ("$op not OP_PUSHDATA*"), return;
	$sig =~ s/(\C)\z//
		or warn ("short sig"), return;
	my $nHashType = ord $1;

	my $hash = SignatureHash ($scriptPubKey, $txTo, $nIn, $nHashType);

	my $pub = script::GetPubKey ($scriptPubKey);
	if (!$pub) {
		my $pub_h = script::GetBitcoinAddressHash160 ($scriptPubKey)
			or warn ("no addr"), return;
		($op, $pub) = script::GetOp ($scriptSig)
			or warn ("no script"), return;
		$op eq 'OP_PUSHDATA'
			or warn ("second $op not OP_PUSHDATA"), return;
		base58::Hash160 ($pub) eq $pub_h
			or warn ("bad hash"), return;
	}
	$scriptSig eq ''
		or warn ("garbage"), return;
	return ecdsa::Verify ({ pub => $pub }, $hash, $sig);
}

sub SignSignature {
	my ($txFrom, $txTo, $nIn, $nHashType) = @_;
	$nHashType ||= $script::SIGHASH{ALL};

	$nIn < @{ $txTo->{vin} } or die "assert";
	my $txin = $txTo->{vin}[$nIn];
	$txin->{prevout}{n} < @{ $txFrom->{vout} } or die "assert";
	my $txout = $txFrom->{vout}[ $txin->{prevout}{n} ];

	# Leave out the signature from the hash, since a signature can't 
	# sign itself.
	# The checksig op will also drop the signatures from its hash.
	my $hash = SignatureHash ($txout->{scriptPubKey}, $txTo, $nIn,
	    $nHashType);

	$txin->{scriptSig} = Solver ($txout->{scriptPubKey}, $hash, $nHashType);

	EvalScriptCheck ($txin->{scriptSig}, $txout->{scriptPubKey}, $txTo, $nIn)
		or die "check failed";
}

sub NewKey {
	my $key = ecdsa::GenKey ();
	$key->{addr} = base58::PubKeyToAddress ($key->{pub});
	$key->{remark} = "generated at " . localtime;
	data::key_save ($key);
	data::commit ();
	return $key;
}

sub CreateTransaction_ {
	my ($scriptPubKey, $nValue) = @_;

	my $tx = {
		nVersion	=> 1,
		nLockTime	=> 0,
	};
	my $nFee = $nTransactionFee;
	my $key;

AGAIN:	$tx->{vin} = [];
        $tx->{vout} = [];
	die if $nValue < 0;
	my $nValueOut = $nValue;
	my $nTotalValue = $nValue + $nFee;

	# Choose coins to use
	my @setCoins = SelectCoins ($nTotalValue);
	my $nValueIn = 0;
	$nValueIn += GetCredit ($_) for @setCoins;

	# Fill a vout to the payee
	my $fChangeFirst = rand () < .5;
	push @{ $tx->{vout} }, {
		nValue		=> $nValueOut,
		scriptPubKey	=> $scriptPubKey,
	} if !$fChangeFirst;

	# Fill a vout back to self with any change
	if ($nValueIn > $nTotalValue) {
		# Note: We use a new key here to keep it from being obvious which side is the change.
		# The drawback is that by not reusing a previous key, the change may be lost if a
		# backup is restored, if the backup doesn't have the new private key for the change.
		# If we reused the old key, it would be possible to add code to look for and
		# rediscover unknown transactions that were written with keys of ours to recover
		# post-backup change.

		# New private key
		$key = NewKey () if !$key;

		# Fill a vout to ourself, using same address type as the payment
		my $scriptChange =
			script::GetBitcoinAddressHash160 ($scriptPubKey) ?
				script::SetBitcoinAddress
					(base58::Hash160 ($key->{pub})) :
				script::Bin ($key->{pub}) .
				script::Op ('OP_CHECKSIG');
		push @{ $tx->{vout} }, {
			nValue		=> $nValueIn - $nTotalValue,
			scriptPubKey	=> $scriptChange,
		};
	}

	# Fill a vout to the payee
	push @{ $tx->{vout} }, {
		nValue		=> $nValueOut,
		scriptPubKey	=> $scriptPubKey,
	} if $fChangeFirst;

	# Fill vin
	my @txFrom = ();
	for my $pcoin (@setCoins) {
		my $tx_h = TransactionHash ($pcoin);
		for my $nOut (0 .. $#{ $pcoin->{vout} }) {
			IsMine ($pcoin->{vout}[$nOut]{scriptPubKey}) or next;
			push @{ $tx->{vin} }, {
				prevout		=> {
					hash		=> $tx_h,
					n		=> $nOut,
				},
				scriptSig	=> '',
				nSequence	=> $ONES32,				
			};
			push @txFrom, $pcoin;
		}
	}

	# Sign
	SignSignature ($txFrom[$_], $tx, $_) for 0 .. $#{ $tx->{vin} };

	# Check that enough fee is included
	my $nFeeMin = GetMinFee ($tx);
	if ($nFee < $nFeeMin) {
		$nFee = $nFeeMin;
		goto AGAIN;
	}

	# Fill vtxPrev by copying from previous transactions vtxPrev
	#AddSupportingTransactions ($tx);	# XXX
	#tx->{fTimeReceivedIsTxTime} = 1;

	return ($tx, $key, $nFee);
}

sub CommitTransaction_ {
	my ($wtxNew, $key) = @_;

	# XXX
}

sub SendMoneyToBitcoinAddress_ {
	my ($strAddress, $nValue) = @_;

	die "Invalid amount"
		if $nValue < 0;
	die "Insufficient funds"
		if $nValue + $nTransactionFee > GetBalance ();

	my $scriptPubKey = script::SetBitcoinAddress
		(base58::AddressToHash160 ($strAddress));
	my ($wtxNew, $key, $nFeeRequired) =
		CreateTransaction ($scriptPubKey, $nValue);
	CommitTransaction ($wtxNew, $key);
}

1;
