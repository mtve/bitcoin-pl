#! /usr/bin/perl -ln

use ecdsa;
use base58;

# 1) install Oracle Berkley DB
#   http://www.oracle.com/technetwork/database/berkeleydb/downloads/index.html
#
# 2) run
#     db_dump wallet.dat | this_script.pl

/^ fd..01308201..02010104(.*)/i or next;

$priv = unpack 'C/a', pack 'H*', $1;
$pub = ecdsa::pub_encode (ecdsa::pub_from_priv (ecdsa::i_decode ($priv)));
$addr = base58::PubKeyToAddress ($pub);

print unpack ('H*', $priv), ' ', $addr;
