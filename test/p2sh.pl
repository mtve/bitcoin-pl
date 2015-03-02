#! /usr/bin/perl

# https://bitcoin.org/en/developer-examples#p2sh-multisig

use warnings;
use strict;

my %C;

sub go($@) {
	my ($arg, @var) = @_;

	s/\s//g, s/"/\\"/g, s/\$(\w+)/$C{$1}/g for @$arg;
	print "\n> @$arg\n";
	my $res = join '', `bitcoin-cli @$arg`;

	while (@var) {
		my $pat = shift @var;
		my $var = shift @var or die;
		$pat ? $res =~ /"$pat" : "(.+)"/ : $res =~ /(\C+?)\s*\z/
			or die "no match for '$pat': $res";
		$C{$var} = $1;
		print "$var = $C{$var}\n";
	}
}

go ['getnewaddress'], '' => 'NEW_ADDRESS1';
go ['getnewaddress'], '' => 'NEW_ADDRESS2';
go ['getnewaddress'], '' => 'NEW_ADDRESS3';

go ['validateaddress', '$NEW_ADDRESS3'],
	pubkey		=> 'NEW_ADDRESS3_PUBLIC_KEY';

go ['createmultisig', 2, '
	[
		"$NEW_ADDRESS1",
		"$NEW_ADDRESS2", 
		"$NEW_ADDRESS3_PUBLIC_KEY"
	]
'],	address		=> 'P2SH_ADDRESS',
	redeemScript	=> 'P2SH_REDEEM_SCRIPT',
;

go ['sendtoaddress', '$P2SH_ADDRESS', '10.00'], '' => 'UTXO_TXID';

go ['getrawtransaction', '$UTXO_TXID', 1], '' => 'UTXO';
($C{UTXO_VOUT}, $C{UTXO_OUTPUT_SCRIPT}) = $C{UTXO} =~ /
        \s+ "n" \s : \s (\d+),
        \s+ "scriptPubKey" \s : \s {
        \s+     "asm" \s : \s ".+",
        \s+     "hex" \s : \s "(.+)",
        \s+     "reqSigs" \s : \s 1,
        \s+     "type" \s : \s "scripthash",
        \s+     "addresses" \s : \s \[
        \s+        ".+"
        \s+     \]
        \s+ }/x or die;

go ['getnewaddress'], '' => 'NEW_ADDRESS4';

go ['createrawtransaction', '
	[{
		"txid": "$UTXO_TXID",
		"vout": $UTXO_VOUT
	}]
', '
	{     "$NEW_ADDRESS4": 9.998 }
'],
	''	=> 'RAW_TX';

go ['dumpprivkey', '$NEW_ADDRESS1'], '' => 'NEW_ADDRESS1_PRIVATE_KEY';
go ['dumpprivkey', '$NEW_ADDRESS3'], '' => 'NEW_ADDRESS3_PRIVATE_KEY';

go ['signrawtransaction', '$RAW_TX', '
	[{
		"txid": "$UTXO_TXID", 
		"vout": $UTXO_VOUT, 
		"scriptPubKey": "$UTXO_OUTPUT_SCRIPT", 
		"redeemScript": "$P2SH_REDEEM_SCRIPT"
	}]
', '
	[	"$NEW_ADDRESS1_PRIVATE_KEY" ]
'
],
	hex	=> 'PARTLY_SIGNED_RAW_TX';

go ['signrawtransaction', '$PARTLY_SIGNED_RAW_TX', '
	[{
		"txid": "$UTXO_TXID",
		"vout": $UTXO_VOUT,
		"scriptPubKey": "$UTXO_OUTPUT_SCRIPT", 
		"redeemScript": "$P2SH_REDEEM_SCRIPT"
	}]
', '
	[	"$NEW_ADDRESS3_PRIVATE_KEY" ]
'],
	hex	=> 'SIGNED_RAW_TX';

go ['sendrawtransaction', '$SIGNED_RAW_TX'], '' => 'TX';
