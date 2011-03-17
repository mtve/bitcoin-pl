package data;

use warnings;
use strict;
use DBI;

my $DBI_ARG1 = "dbi:SQLite:dbname=var/db";
my $DBI_ARG2 = '';
my $DBI_ARG3 = '';

my $dbh;
my %sth;

my $SCRIPT = <<SQL;

CREATE TABLE IF NOT EXISTS key (
	pub		BLOB PRIMARY KEY,
	priv		BLOB,
	addr		STRING(50),
	remark		STRING
);

CREATE TABLE IF NOT EXISTS tx (
	hash		BLOB(32) PRIMARY KEY,
	nLockTime	INTEGER
);

CREATE TABLE IF NOT EXISTS tx_in (
	tx_hash		BLOB(32),
	tx_n		INTEGER,
	prev_hash	BLOB(32),
	prev_n		INTEGER,
	scriptSig	BLOB,
	nSequence	INTEGER
);

CREATE INDEX IF NOT EXISTS tx_in_idx
	ON tx_in (tx_hash, tx_n);

CREATE TABLE IF NOT EXISTS tx_out (
	tx_hash		BLOB(32),
	tx_n		INTEGER,
	nValue		INTEGER,
	scriptPubKey	BLOB,
	addr		STRING(50),
	spentHeight	INTEGER
);

CREATE INDEX IF NOT EXISTS tx_out_idx
	ON tx_out (tx_hash, tx_n, addr, spentHeight);

CREATE TABLE IF NOT EXISTS blk (
	hash		BLOB(32) PRIMARY KEY,
	hashPrevblk	BLOB(32),
	nTime		INTEGER,
	nBits		INTEGER,
	nNonce		INTEGER,
	nHeight		INTEGER,
	mainBranch	INTEGER
);

CREATE INDEX IF NOT EXISTS blk_idx
	ON blk (nHeight, mainBranch);

CREATE TABLE IF NOT EXISTS orphan (
	hash		BLOB(32) PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS blk_tx (
	blk_hash	BLOB(32),
	blk_n		INTEGER,
	tx_hash		BLOB(32)
);

CREATE INDEX IF NOT EXISTS blk_tx_idx ON blk_tx (blk_hash);

SQL

my %STH = (
	blk_best	=> <<SQL,

SELECT MAX(nHeight), hash FROM blk WHERE mainBranch = 1

SQL
	orphan		=> <<SQL,

SELECT hash FROM orphan

SQL
	tx_out_spent	=> <<SQL,

UPDATE tx_out SET spentHeight = ? WHERE tx_hash = ? AND tx_n = ?

SQL
);

sub init {
	$dbh = DBI->connect ($DBI_ARG1, $DBI_ARG2, $DBI_ARG3, {
		RaiseError	=> 1,
		AutoCommit	=> 0,
	});

	while ($SCRIPT =~ /([^;]+)/g) {
		my $str = $1;
		$str =~ s/--.*//g;

		$dbh->do ($str);

		my ($table) = $str =~ /^\s+create\s+table\s.*?\b(\w+)\s*\(/i
			or next;
		my (@row) = $str =~ /[(,]\s*([a-z]\w+)/ig;

		local $" = ',';

		$sth{"$table\_ins"} = $dbh->prepare (<<SQL);
INSERT INTO $table(@row) VALUES (@{[ map '?', @row ]})
SQL

		$sth{"$table\_del"} = $dbh->prepare (<<SQL);
DELETE FROM $table WHERE $row[0] = ?
SQL

		$row[1] ||= 1;

		$sth{"$table\_sel"} = $dbh->prepare (<<SQL);
SELECT @row[1 .. $#row] FROM $table WHERE $row[0] = ?
SQL

		no strict 'refs';
		*{"$table\_cnt"} = sub { $dbh->selectrow_array (<<SQL) };
SELECT COUNT(*) FROM $table
SQL
	}

	$sth{$_} = $dbh->prepare ($STH{$_}) for keys %STH;
}

sub tx_save {
	my ($tx_h, $tx) = @_;

	for (0 .. $#{ $tx->{vin} }) {
		my $i = $tx->{vin}[$_];
		$sth{tx_in_ins}->execute ($tx_h, $_, $i->{prevout}{hash},
		    $i->{prevout}{n}, $i->{scriptSig}, $i->{nSequence});
	}
	for (0 .. $#{ $tx->{vout} }) {
		my $i = $tx->{vout}[$_];
		$sth{tx_out_ins}->execute ($tx_h, $_, @$i{qw (
			nValue scriptPubKey addr spentHeight
		)});
	}
	$sth{tx_ins}->execute ($tx_h, $tx->{nLockTime});
}

sub tx_load {
	my ($tx_h) = @_;

	$sth{tx_sel}->execute ($tx_h);
	my $h = $sth{tx_sel}->fetchrow_hashref or return;
	my $tx = $h;

	$sth{tx_in_sel}->execute ($tx_h);
	while ($h = $sth{tx_in_sel}->fetchrow_hashref) {
		$tx->{vin}[ $h->{tx_n} ] = {
			prevout		=> {
				hash		=> $h->{prev_hash},
				n		=> $h->{prev_n},
			},
			scriptSig	=> $h->{scriptSig},
			nSequence	=> $h->{nSequence},
		};
	}

	$sth{tx_out_sel}->execute ($tx_h);
	while ($h = $sth{tx_out_sel}->fetchrow_hashref) {
		$tx->{vout}[ $h->{tx_n} ] = $h;
	}

	return $tx;
}

sub tx_out_spent {
	my ($tx_h, $tx_n, $height) = @_;

	$sth{tx_out_spent}->execute ($height, $tx_h, $tx_n);
}

sub blk_save {
	my ($blk_h, $blk) = @_;

	for (0 .. $#{ $blk->{vtx} }) {
		$sth{blk_tx_ins}->execute ($blk_h, $_, $blk->{vtx}[$_]);
	}
	$sth{blk_ins}->execute ($blk_h, @$blk{qw(
		hashPrevblk nTime nBits nNonce nHeight mainBranch
	)});
}

sub blk_load {
	my ($blk_h) = @_;

	$sth{blk_sel}->execute ($blk_h);
	my $h = $sth{blk_sel}->fetchrow_hashref or return;
	my $blk = $h;

	$sth{blk_tx_sel}->execute ($blk_h);
	while ($h = $sth{blk_tx_sel}->fetchrow_hashref) {
		$blk->{vtx}[ $h->{blk_n} ] = $h->{tx_hash};
	}

	return $blk;
}

sub blk_best {
	$sth{blk_best}->execute ();
	return $sth{blk_best}->fetchrow_array;
}

sub orphan {
	$sth{orphan}->execute ();
	my ($h) = $sth{orphan}->fetchrow_array or return;
	$sth{orphan}->finish ();
	return $h;
}

sub orphan_ins {
	my ($hash) = @_;

	eval { $sth{orphan_ins}->execute ($hash) };
}

sub orphan_del {
	my ($hash) = @_;

	$sth{orphan_del}->execute ($hash);
}

sub key_load {
	my ($pub) = @_;

	$sth{key_sel}->execute ($pub);
	return $sth{key_sel}->fetchrow_hashref;
}

sub key_save {
	$sth{key_ins}->execute (@_);
}

END {
	$dbh->commit if $dbh;
}

1;
