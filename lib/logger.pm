package logger;

use warnings;
use strict;

use cfg;

our $fh;

sub rotate {
	my $file = $cfg::var{LOG_FILE_NAME};
	rename "$file.$_", "$file." . ($_ + 1)
		for reverse 1 .. $cfg::var{LOG_FILES} - 1;
	close $fh if $fh;
	rename $file, "$file.1";
	open $fh, '>', $file
		or die "open $file: $!";
	select $fh; $|++; select STDOUT;
	$! = 0;
	tie *STDERR, __PACKAGE__;
	warn "log rotated at ${\scalar localtime}\n";
}

sub TIEHANDLE { bless {} }

sub PRINT {
	my (undef, $msg) = @_;

	$msg =~ s/\n\z//;
	$msg .= " errno=$!(" . int ($!) . ')', $! = 0 if $!;
	my ($s, $m, $h) = localtime;
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
