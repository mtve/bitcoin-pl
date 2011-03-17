package logger;

use warnings;
use strict;

our $file = 'var/log';
our $MAX_FILES = 9;
our $fh;

sub rotate {
	rename "$file.$_", "$file." . ($_ + 1)
		for reverse 1..$MAX_FILES-1;
	close $fh if $fh;
	rename $file, "$file.1";
	open $fh, '>', $file
		or die "open $file: $!";
	select $fh; $|++; select STDOUT;
	$! = 0;
	tie *STDERR, __PACKAGE__;
	warn "log rotated at " . localtime () . "\n";
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

rotate ();

1;
