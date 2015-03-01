package chain;

use warnings;
use strict;

use script;
use util;
use base58;
use serialize;
use cfg;

our $NULL256 = "\0" x (256 / 8);
our $ONES32 = 0xffffffff;
our $COIN = 100000000;
our $CENT = 1000000;

sub TransactionHash {
	my ($tx) = @_;

	return base58::Hash (serialize::Serialize ('CTransaction', $tx));
}

sub BlockHash {
	my ($blk) = @_;

	return base58::Hash (serialize::Serialize ('CBlockOnly', $blk));
}

{
	my $chain = $cfg::var{CHAIN};
	no strict 'refs';
	exists ${"::"}{"chain::"}{"${chain}::"}
		or die "no chain $chain";
	*$_ = \*{"chain::$cfg::var{CHAIN}::$_"}
		for qw( WIRE_MAGIC GenesisBlock GenesisHash );
}

package chain::main;

our $WIRE_MAGIC = "\xf9\xbe\xb4\xd9";

our $pszTimestamp =
	'The Times 03/Jan/2009 Chancellor on brink of second bailout for banks';
our $GenesisPubKey = $util::h2b{
	'5F1DF16B2B704C8A578D0BBAF74D385CDE12C11EE50455F3C438EF4C3FBCF649' .
	'B6DE611FEAE06279A60939E028A8D65C10B73071A6F16719274855FEB0FD8A6704'
};
our $GenesisMerkleRoot = $util::h2b{
	'4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b'
};
our $GenesisHash = $util::h2b{
	'000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f'
};

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
		hashMerkleRoot	=> chain::TransactionHash ($tx0),
		nTime		=> 1231006505,
		nBits		=> 0x1d00ffff,
		nNonce		=> 2083236893,
		vtx		=> [ $tx0 ],
	};

	$blk0->{hashMerkleRoot} eq $GenesisMerkleRoot
		or die "assert GenesisMerkleRoot";
	chain::BlockHash ($blk0) eq $GenesisHash
		or die "assert GenesisHash";

	return $blk0;
}

package chain::testnet;

our $WIRE_MAGIC = "\x0b\x11\x09\x07";

our $GenesisHash = $util::h2b{
	'000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943'
};

sub GenesisBlock {
	my $blk0 = {
		%{ chain::main::GenesisBlock () },
		nTime		=> 1296688602,
		nNonce		=> 414098458,
	};
	chain::BlockHash ($blk0) eq $GenesisHash
		or die "assert GenesisHash";

	return $blk0;
}

package chain::regtest;

our $WIRE_MAGIC = "\xfa\xbf\xb5\xda";

our $GenesisHash = $util::h2b{
	'0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206'
};

sub GenesisBlock {
	my $blk0 = {
		%{ chain::main::GenesisBlock () },
		nTime		=> 1296688602,
		nBits		=> 0x207fffff,
		nNonce		=> 2,
	};
	chain::BlockHash ($blk0) eq $GenesisHash
		or die "assert GenesisHash";

	return $blk0;
}

1;
