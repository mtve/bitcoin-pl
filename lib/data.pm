package data;

use warnings;
use strict;
use DBI;

use event;
use cfg;
use util;

my $SCRIPT = <<SQL;

CREATE TABLE IF NOT EXISTS key (
	pub		BLOB PRIMARY KEY,
	priv		BLOB NOT NULL,
	addr		STRING(50) NOT NULL,
	remark		STRING NOT NULL
);

CREATE TABLE IF NOT EXISTS tx (
	hash		BLOB(32) PRIMARY KEY,
	nLockTime	INTEGER NOT NULL,
	mainHeight	INTEGER NOT NULL	-- not in main chain -1
);

CREATE INDEX IF NOT EXISTS tx_idx1 ON tx (mainHeight);

CREATE TABLE IF NOT EXISTS tx_in (
	tx_hash		BLOB(32) NOT NULL,
	tx_n		INTEGER NOT NULL,
	prev_hash	BLOB(32) NOT NULL,
	prev_n		INTEGER NOT NULL,
	scriptSig	BLOB NOT NULL,
	nSequence	INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS tx_in_idx1 ON tx_in (tx_hash);
CREATE INDEX IF NOT EXISTS tx_in_idx2 ON tx_in (prev_hash);

CREATE TABLE IF NOT EXISTS tx_out (
	tx_hash		BLOB(32) NOT NULL,
	tx_n		INTEGER NOT NULL,
	nValue		INTEGER NOT NULL,
	scriptPubKey	BLOB NOT NULL,
	addr		STRING(50) NOT NULL,
	spentHeight	INTEGER NOT NULL	-- not spent -1
);

CREATE INDEX IF NOT EXISTS tx_out_idx1 ON tx_out (tx_hash);
CREATE INDEX IF NOT EXISTS tx_out_idx2 ON tx_out (addr);
CREATE INDEX IF NOT EXISTS tx_out_idx3 ON tx_out (spentHeight);

CREATE TABLE IF NOT EXISTS blk (
	hash		BLOB(32) PRIMARY KEY,
	hashPrevBlock	BLOB(32) NOT NULL,
	nTime		INTEGER NOT NULL,
	nBits		INTEGER NOT NULL,
	nNonce		INTEGER NOT NULL,
	nHeight		INTEGER NOT NULL,	-- orphan -1
	mainBranch	INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS blk_idx1 ON blk (nHeight);
CREATE INDEX IF NOT EXISTS blk_idx2 ON blk (mainBranch);

CREATE TABLE IF NOT EXISTS blk_tx (
	blk_hash	BLOB(32) NOT NULL,
	blk_n		INTEGER NOT NULL,	-- new tx -1
	tx_hash		BLOB(32) NOT NULL
);

CREATE INDEX IF NOT EXISTS blk_tx_idx1 ON blk_tx (blk_hash);
CREATE INDEX IF NOT EXISTS blk_tx_idx2 ON blk_tx (blk_n);
CREATE INDEX IF NOT EXISTS blk_tx_idx3 ON blk_tx (tx_hash);

SQL

my %STH = (
	blk_genesis	=> <<SQL,

SELECT	hash
FROM	blk
WHERE	mainBranch = 1 AND nHeight = 0

SQL
	blk_best	=> <<SQL,

SELECT	hash
FROM	blk
WHERE	mainBranch = 1 AND
	nHeight = (SELECT MAX(nHeight) FROM blk WHERE mainBranch = 1)

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
	tx_unmain	=> <<SQL,

UPDATE tx SET mainHeight = -1 WHERE mainHeight >= ?

SQL
	tx_main		=> <<SQL,

UPDATE tx SET mainHeight = ? WHERE hash = ? AND mainHeight = -1

SQL
	tx_out_spent	=> <<SQL,

UPDATE tx_out SET spentHeight = ? WHERE tx_hash = ? AND tx_n = ?

SQL
	tx_out_unspent	=> <<SQL,

UPDATE tx_out SET spentHeight = -1 WHERE spentHeight >= ?

SQL
	key_all		=> <<SQL,

SELECT addr, remark FROM key

SQL
	# all txes to our addr,
	# in main branch below some height and 
	# not spent yet or spent above some height
	key_ammo	=> <<SQL,

SELECT	SUM(tx_out.nValue) AS ammo
FROM	tx_out, tx
WHERE	tx_out.addr = ? AND
	tx_out.tx_hash == tx.hash AND
	tx.mainHeight >= 0 AND tx.mainHeight <= ? AND
	(tx_out.spentHeight = -1 OR tx_out.spentHeight > ?)

SQL
	# all txes to our addr,
	# not in main branch yet
	# or above some height
	key_ammo_plus	=> <<SQL,

SELECT	SUM(tx_out.nValue) AS ammo
FROM	tx_out, tx
WHERE	tx_out.addr = ? AND
	tx_out.tx_hash == tx.hash AND
	(tx.mainHeight == -1 OR tx.mainHeight > ?)

SQL
	# all txes(out) for our addr
	# that have spent txes(in)
	# that are not in main brahch yet or above some height
	key_ammo_minus	=> <<SQL,

SELECT	SUM(tx_out.nValue) AS ammo
FROM	tx_in, tx, tx_out
WHERE	tx_out.addr = ? AND
	tx_out.tx_hash = tx_in.prev_hash AND
	tx_out.tx_n = tx_in.prev_n AND
	tx_in.tx_hash = tx.hash AND
	(tx.mainHeight == -1 OR tx.mainHeight > ?)

SQL
);

my $dbh;
my %sth;

sub commit {
	warn "commit";
	$dbh->commit if $dbh;
}

sub init {
	my ($dbi, $user, $pass) = @cfg::var{qw( DB_DS DB_USER DB_PASS )};
	$dbh = DBI->connect ($dbi, $user, $pass, {
		RaiseError	=> 1,
		AutoCommit	=> 0,
	});

	if ($dbh->{Driver}->{Name} =~ /sqlite/i) {
		warn "sqlite specials\n";
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
SELECT @row FROM $table WHERE $row[0] = ?
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
		period	=> $cfg::var{DB_COMMIT_PERIOD},
		cb	=> \&commit,
	);
	warn "using DBI $DBI::VERSION driver $dbh->{Driver}{Name} " .
		"@{[ $dbh->get_info(18) ]}\n";
}

sub tx_save {
	my ($tx_h, $tx) = @_;

warn "xxx $X{$tx_h} $#{ $tx->{vin} } $#{ $tx->{vout} }";
	$sth{tx_ins}->execute ($tx_h, $tx->{nLockTime}, -1);
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

warn "xxx $X{$tx_h}";
	$sth{tx_sel}->execute ($tx_h);
	my $tx = $sth{tx_sel}->fetchrow_hashref or return;

	$sth{tx_in_sel}->execute ($tx_h);
	while (my $h = $sth{tx_in_sel}->fetchrow_hashref) {
		$tx->{vin}[ $h->{tx_n} ] = {
			prevout		=> {
				hash		=> $h->{prev_hash},
				n		=> $h->{prev_n},
			},
			scriptSig	=> $h->{scriptSig},
			nSequence	=> $h->{nSequence},
		};
	}
	$tx->{vin}[$_] or die "no tx_in $_ for tx $X{$tx_h}"
		for 0 .. $#{ $tx->{vin} };

	$sth{tx_out_sel}->execute ($tx_h);
	while (my $h = $sth{tx_out_sel}->fetchrow_hashref) {
		$tx->{vout}[ $h->{tx_n} ] = $h;
	}
	$tx->{vout}[$_] or die "no tx_out $_ for tx $X{$tx_h}"
		for 0 .. $#{ $tx->{vout} };

	$tx->{nVersion} = 1;

	return $tx;
}

sub tx_out_spent {
	my ($tx_h, $tx_n, $height) = @_;

	$sth{tx_out_spent}->execute ($height, $tx_h, $tx_n);
}

sub tx_trimmain {
	my ($height) = @_;

	$sth{tx_out_unspent}->execute ($height);
	$sth{tx_unmain}->execute ($height);
}

sub blk_save {
	my ($blk) = @_;

	$sth{blk_ins}->execute (@$blk{qw(
		hash hashPrevBlock nTime nBits nNonce nHeight mainBranch
	)});
	for (0 .. $#{ $blk->{vtx_h} }) {
		$sth{blk_tx_ins}->execute ($blk->{hash}, $_, $blk->{vtx_h}[$_]);
	}
}

sub blk_load {
	my ($blk) = @_;

	$sth{blk_tx_sel}->execute ($blk->{hash});
	while (my $h = $sth{blk_tx_sel}->fetchrow_hashref) {
		$blk->{vtx_h}[ $h->{blk_n} ] = $h->{tx_hash};
	}
	for (0 .. $#{ $blk->{vtx_h} }) {
		my $tx_h = $blk->{vtx_h}[$_] ||
			die "no blk_tx $_ for blk $X{$blk->{hash}}";
		$blk->{vtx}[$_] = tx_load ($tx_h)
			or die "no tx $X{$tx_h} for blk $X{$blk->{hash}} at $_";
	}
}

sub blk_genesis {
	$sth{blk_genesis}->execute ();
	my $h = $sth{blk_genesis}->fetchrow_hashref;
	return $h && $h->{hash};
}

sub blk_best {
	$sth{blk_best}->execute ();
	my $h = $sth{blk_best}->fetchrow_hashref;
	return $h && blk_exists ($h->{hash});
}

sub blk_connect {
	my ($blk) = @_;

	$sth{blk_connect}->execute (@$blk{qw( nHeight mainBranch hash )});

	# XXX update
	if ($blk->{mainBranch}) {
		$sth{tx_main}->execute ($blk->{nHeight}, $_)
			for @{ $blk->{vtx_h} };
	}
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
	my ($addr, $height) = @_;

	my (%res, $h);

	$sth{key_ammo}->execute ($addr, $height, $height);
	$h = $sth{key_ammo}->fetchrow_hashref;
	$res{ammo} = $h ? $h->{ammo} || 0 : 0;

	$sth{key_ammo_plus}->execute ($addr, $height);
	$h = $sth{key_ammo_plus}->fetchrow_hashref;
	$res{ammo_plus} = $h ? $h->{ammo} || 0 : 0;

	$sth{key_ammo_minus}->execute ($addr, $height);
	$h = $sth{key_ammo_minus}->fetchrow_hashref;
	$res{ammo_minus} = $h ? $h->{ammo} || 0 : 0;

	return \%res;
}

sub key_all {
	my ($height) = @_;

	$sth{key_all}->execute ();
	my @res;
	while (my $h = $sth{key_all}->fetchrow_hashref) {
		my $res = key_ammo ($h->{addr}, $height);
		$res->{$_} = $h->{$_} for qw( addr remark );
		push @res, $res;
	}
	return @res;
}

sub sql {
	my ($query, @param) = @_;

	my $sth = $dbh->prepare ($query);
	$sth->execute (@param);
	my (@res, $h);
	while (@res < $cfg::var{WEB_PAGE_SIZE} && ($h = $sth->fetchrow_hashref)) {
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
