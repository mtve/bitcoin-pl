package data;

use warnings;
use strict;
use DBI;

use event;

my $DBI_DS = 'dbi:SQLite:dbname=var/db';
my $DBI_USER = '';
my $DBI_PASS = '';

my $COMMIT_PERIOD = 10 * 60;

my $SCRIPT = <<SQL;

CREATE TABLE IF NOT EXISTS key (
	pub		BLOB PRIMARY KEY,
	priv		BLOB NOT NULL,
	addr		STRING(50) NOT NULL,
	remark		STRING NOT NULL
);

CREATE TABLE IF NOT EXISTS tx (
	hash		BLOB(32) PRIMARY KEY,
	nLockTime	INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS tx_in (
	tx_hash		BLOB(32) NOT NULL,
	tx_n		INTEGER NOT NULL,
	prev_hash	BLOB(32) NOT NULL,
	prev_n		INTEGER NOT NULL,
	scriptSig	BLOB NOT NULL,
	nSequence	INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS tx_in_idx
	ON tx_in (tx_hash, tx_n);

CREATE TABLE IF NOT EXISTS tx_out (
	tx_hash		BLOB(32) NOT NULL,
	tx_n		INTEGER NOT NULL,
	nValue		INTEGER NOT NULL,
	scriptPubKey	BLOB NOT NULL,
	addr		STRING(50) NOT NULL,
	spentHeight	INTEGER NOT NULL	-- not in chain -1, not spent 0
);

CREATE INDEX IF NOT EXISTS tx_out_idx
	ON tx_out (tx_hash, tx_n);
CREATE INDEX IF NOT EXISTS tx_out_idx2
	ON tx_out (addr);
CREATE INDEX IF NOT EXISTS tx_out_idx3
	ON tx_out (spentHeight);

CREATE TABLE IF NOT EXISTS blk (
	hash		BLOB(32) PRIMARY KEY,
	hashPrevBlock	BLOB(32) NOT NULL,
	nTime		INTEGER NOT NULL,
	nBits		INTEGER NOT NULL,
	nNonce		INTEGER NOT NULL,
	nHeight		INTEGER NOT NULL,	-- orphan is -1
	mainBranch	INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS blk_idx
	ON blk (nHeight, mainBranch);

CREATE TABLE IF NOT EXISTS blk_tx (
	blk_hash	BLOB(32) NOT NULL,
	blk_n		INTEGER NOT NULL,	-- new tx is -1
	tx_hash		BLOB(32) NOT NULL
);

CREATE INDEX IF NOT EXISTS blk_tx_idx
	ON blk_tx (blk_hash, blk_n);

SQL

my %STH = (
	blk_best	=> <<SQL,

SELECT MAX(nHeight), hash FROM blk WHERE mainBranch = 1

SQL
	blk_connect	=> <<SQL,

UPDATE blk SET nHeight = ?, mainBranch = ? WHERE hash = ?

SQL
	blk_orphan	=> <<SQL,

SELECT hash FROM blk WHERE nHeight = -1 AND hashPrevBlock = ?

SQL
	blk_orphans	=> <<SQL,

SELECT hash, hashPrevBlock FROM blk WHERE nHeight = -1

SQL
	blk_tx_del	=> <<SQL,

DELETE FROM blk_tx WHERE blk_hash = ? AND blk_n = ? AND tx_hash = ?

SQL
	tx_out_spent	=> <<SQL,

UPDATE tx_out SET spentHeight = ? WHERE tx_hash = ? AND tx_n = ?

SQL
	tx_out_unspent	=> <<SQL,

UPDATE tx_out SET spentHeight = 0 WHERE spentHeight >= ?

SQL
	tx_out_inchain	=> <<SQL,

UPDATE tx_out SET spentHeight = 0 WHERE tx_hash = ? AND spentHeight = -1

SQL
	key_all		=> <<SQL,

SELECT addr, remark FROM key

SQL
	key_ammo	=> <<SQL,

SELECT SUM(nValue) AS ammo
FROM tx_out
WHERE addr = ? AND spentHeight = 0
GROUP BY addr

SQL
);

my $dbh;
my %sth;

sub commit {
	warn "commit";
	$dbh->commit if $dbh;
}

sub init {
	$dbh = DBI->connect ($DBI_DS, $DBI_USER, $DBI_PASS, {
		RaiseError	=> 1,
		AutoCommit	=> 0,
	});

	if ($dbh->{Driver}->{Name} =~ /sqlite/i) {
		$dbh->do ('PRAGMA synchronous = OFF');
		$dbh->do ('PRAGMA cache_size = 20000');
	}

	while ($SCRIPT =~ /([^;]+)/g) {
		my $str = $1;
		s/--.*//g, s/^\s+//, s/\s+\z// for $str;
		next if !$str;

		$dbh->do ($str);

		my ($table) = $str =~ /^\s*create\s+table\s.*?\b(\w+)\s*\(/i
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

		*{"$table\_exists"} = sub {
			$sth{"$table\_sel"}->execute ($_[0]);
			return $sth{"$table\_sel"}->fetchrow_hashref;
		};

		*{"$table\_cnt"} = sub { $dbh->selectrow_array (<<SQL) };
SELECT COUNT(*) FROM $table
SQL
	}

	$sth{$_} = $dbh->prepare ($STH{$_}) for keys %STH;

	event::timer_new (
		period	=> $COMMIT_PERIOD,
		cb	=> \&commit,
	);
}

sub tx_save {
	my ($tx_h, $tx) = @_;

	$sth{tx_ins}->execute ($tx_h, $tx->{nLockTime});
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

	$tx->{h} = $tx_h;

	return $tx;
}

sub tx_out_spent {
	my ($tx_h, $tx_n, $height) = @_;

	$sth{tx_out_spent}->execute ($height, $tx_h, $tx_n);
}

sub tx_out_unspent {
	my ($height) = @_;

	$sth{tx_out_unspent}->execute ($height);
}

sub tx_out_inchain {
	my ($tx_h) = @_;

	$sth{tx_out_inchain}->execute ($tx_h);
}

sub blk_save {
	my ($blk_h, $blk) = @_;

	$sth{blk_ins}->execute ($blk_h, @$blk{qw(
		hashPrevBlock nTime nBits nNonce nHeight mainBranch
	)});
	for (0 .. $#{ $blk->{vtx_h} }) {
		$sth{blk_tx_ins}->execute ($blk_h, $_, $blk->{vtx_h}[$_]);
	}
}

sub blk_load {
	my ($blk_h) = @_;

	$sth{blk_sel}->execute ($blk_h);
	my $h = $sth{blk_sel}->fetchrow_hashref or return;
	my $blk = $h;

	$sth{blk_tx_sel}->execute ($blk_h);
	while ($h = $sth{blk_tx_sel}->fetchrow_hashref) {
		$blk->{vtx_h}[ $h->{blk_n} ] = $h->{tx_hash};
	}

	$blk->{h} = $blk_h;

	return $blk;
}

sub blk_best {
	$sth{blk_best}->execute ();
	my $h = $sth{blk_best}->fetchrow_hashref;
	return $h && blk_load ($h->{hash});
}

sub blk_connect {
	my ($blk) = @_;

	$sth{blk_connect}->execute (@$blk{qw( nHeight mainBranch h )});
}

sub blk_orphan {
	my ($blk_h) = @_;

	$sth{blk_orphan}->execute ($blk_h);
	return map $_->[0], @{ $sth{blk_orphan}->fetchall_arrayref };
}

sub blk_missed {
	$sth{blk_orphans}->execute ();
        my %prev = ();
	while (my $h = $sth{blk_orphans}->fetchrow_hashref) {
		$prev{ $h->{hash} } = $h->{hashPrevBlock};
	}
	return grep !exists $prev{$_}, values %prev;
}

sub blk_tx_add {
	my ($blk_h, $blk_n, $tx_h) = @_;

	$sth{blk_tx_ins}->execute ($blk_h, $blk_n, $tx_h);
}

sub blk_tx_del {
	my ($blk_h, $blk_n, $tx_h) = @_;

	$sth{blk_tx_del}->execute ($blk_h, $blk_n, $tx_h);
}

sub key_load {
	my ($pub) = @_;

	$sth{key_sel}->execute ($pub);
	return $sth{key_sel}->fetchrow_hashref;
}

sub key_save {
	my ($key) = @_;

	$key->{remark} ||= '';
	$sth{key_ins}->execute (@$key{qw( pub priv addr remark )});
}

sub key_ammo {
	my ($addr) = @_;

	$sth{key_ammo}->execute ($addr);
	my $h = $sth{key_ammo}->fetchrow_hashref;
	return $h ? $h->{ammo} : 0;
}

sub key_all {
	$sth{key_all}->execute ();
	my @res;
	while (my $h = $sth{key_all}->fetchrow_hashref) {
		push @res, {
			addr	=> $h->{addr},
			remark	=> $h->{remark},
			ammo	=> key_ammo ($h->{addr}),
		};
	}
	return @res;
}

sub sql {
	my ($query, $max) = @_;

	my $sth = $dbh->prepare ($query);
	$sth->execute ();
	my (@res, $h);
	while (@res < $max && ($h = $sth->fetchrow_hashref)) {
		push @res, $h;
	}
	$sth->finish;
	return \@res;
}

sub version {
	return "DBI $DBI::VERSION " .
	    $dbh->get_info (17) . " " . $dbh->get_info (18);
}

1;
