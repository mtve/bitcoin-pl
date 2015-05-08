package logger;

use warnings;
use strict;

use cfg;

our $fh;
our $last;

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
}

tie *STDERR, __PACKAGE__;

sub TIEHANDLE { bless {} }
sub PRINT {
	my (undef, $msg) = @_;

	$msg =~ s/\n\z//;
	$msg .= " errno=$!(" . int ($!) . ')', $! = 0 if $!;

	my @t = localtime;
	my $time = sprintf "%02d:%02d:%02d", @t[2,1,0];

	my $rotate = $t[$cfg::var{LOG_ROTATE}];
	if (!defined $last || $last != $rotate) {
		$last = $rotate;
		rotate ();
		print { $fh || *STDOUT }
		    "$time log rotated pid $$ perl $^V on $^O\n";
	}

	print { $fh || *STDOUT } "$time @{[ (caller 1)[3] || '?' ]} $msg\n";
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
