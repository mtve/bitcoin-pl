package logger;

use warnings;
use strict;

use cfg;

our $fh;
our $last_d;

sub rotate {
	my $file = $cfg::var{LOG_FILE_NAME};
	rename "$file.$_", "$file." . ($_ + 1)
		for reverse 1 .. $cfg::var{LOG_FILES} - 1;
	close $fh if $fh;
	rename $file, "$file.1";
	open $fh, '>', $file
		or die "open $file: $!";
	select $fh; $|++; select STDOUT;
	$last_d = (localtime)[3];
	tie *STDERR, __PACKAGE__;
	$! = 0;
	warn "log rotated at ${\scalar localtime} pid $$ perl $^V on $^O\n";
}

sub TIEHANDLE { bless {} }

sub PRINT {
	my (undef, $msg) = @_;

	$msg =~ s/\n\z//;
	$msg .= " errno=$!(" . int ($!) . ')', $! = 0 if $!;
	my ($s, $m, $h, $d) = localtime;
	rotate () if !$last_d || $last_d != $d;
	printf { $fh || *STDERR } "%02d:%02d:%02d %s %s \n",
	    $h, $m, $s, (caller 1)[3] || '?', $msg;
}

sub trace {
	my ($msg) = @_;

	my $i = 1;
	while (caller $i) {
		my @c = caller $i++;
		print STDERR "trace: $c[3] at $c[1]:$c[2]";
	}
	print STDERR $msg;
	exit 1;
}

1;
