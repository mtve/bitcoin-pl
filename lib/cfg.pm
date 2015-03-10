package cfg;

use warnings;
use strict;

my $NAME = 'bitcoin-pl.conf';

our %C = (
	CHAIN			=> 'main',

	LOG_FILE_NAME		=> 'var/log',
	LOG_FILES		=> 9,

	DB_DS			=> 'dbi:SQLite:dbname=var/db',
	DB_USER			=> '',
	DB_PASS			=> '',
	DB_COMMIT_PERIOD	=> 10 * 60,

	WEB_PORT		=> 8899,
	WEB_PASS		=> 'changeme',
	WEB_PAGE_SIZE		=> 20,

	NET_PEERS		=> '10.86.17.41:8333,127.0.0.1:18444',
	NET_PERIODIC		=> 60,
	NET_TIMER_PING		=> 60,
	NET_TIMER_INACT		=> 150,
);

sub cfg::var::TIEHASH { bless {}, $_[0] }
sub cfg::var::FETCH { exists $C{$_[1]} ? $C{$_[1]} : die "no cfg var $_[1]" }

tie our %var, 'cfg::var';

sub load {
	if (open my $f, $NAME) {
		while (<$f>) {
			next if /^[;#\*]|^\s*$/;
			/^\s*(\S*)\s*=\s*(.*?)\s*$/
				or die "bad config line $_\n";
			$C{uc $1} = $2;
			warn "info \U$1\E = $2\n";
		}
	} else {
		warn "no file $NAME, using defaults\n";
	}
}

1;
