package event;

use warnings;
use strict;

sub D() { 0 }

our $timei = time;

my @files;
my $nfiles;
my %timers;

my $quit = 0;
my $ri = '';
my $wi = '';
my $ro = '';
my $wo = '';

sub file_new {
	my (%arg) = @_;

	die 'should be called with fh'
		if !$arg{fh};
	die 'should be called with (std_)read_cb'
		if !$arg{read_cb} && !$arg{std_read_cb};

	my $fileno = $arg{fh}->fileno;
	die 'bad fileno'
		if !defined $fileno;

	my $file = {
		fileno		=> $fileno,
		read_cb		=> \&file_read_cb,
		write_cb	=> \&file_write_cb,
		%arg,
	};
	$files[$fileno] = $file;
	vec ($ri, $fileno, 1) = 1;
	$nfiles++;

	return $file;
}

sub file_write {
	my ($file, $data) = @_;

	$file->{dataout} .= $data;
	$file->{writebytes} += length $data;
	vec ($wi, $file->{fileno}, 1) = 1;
}

sub file_write_cb {
	my ($file) = @_;

	my $bytes = syswrite $file->{fh}, $file->{dataout};
	die 'syswrite'
		if !defined $bytes;
	substr ($file->{dataout}, 0, $bytes) = '';
	vec ($wi, $file->{fileno}, 1) = $file->{dataout} ne '';
}

sub file_pktwrite {
	my ($file, $data) = @_;

	vec ($wi, $file->{fileno}, 1) = 1;
	push @{ $file->{datapktout} }, $data;
	$file->{writebytes} += length $data;
}

sub file_pktwrite_cb {
	my ($file) = @_;

	return if !@{ $file->{datapktout} };

	my $bytes = syswrite $file->{fh}, $file->{datapktout}[0];
	die 'syswrite'
		if !defined $bytes;
	if ($bytes == length $file->{datapktout}[0]) {
		shift @{ $file->{datapktout} };
		vec ($wi, $file->{fileno}, 1) = @{ $file->{datapktout} } > 0;
	} else {
		substr ($file->{datapktout}[0], 0, $bytes) = '';
	}
}

sub file_read_cb {
	my ($file) = @_;

	my $bytes = sysread $file->{fh}, my $data, 2**16, 0;
	if (!$bytes) {
		file_close_now ($file, "sysread $!(" . int ($!) . ')');
		return;
	}
	$file->{readbytes} += $bytes;
	$file->{datain} .= $data;
	$file->{std_read_cb} ($file);
}

sub file_read {
	my ($file, $bytes) = @_;

	return length $file->{datain} < $bytes ? undef :
		substr $file->{datain}, 0, $bytes, '';
}

sub server_new {
	my (%arg) = @_;

	die 'should be called with client'
		if !exists $arg{client};
	die 'should be called with client (std_)read_cb'
		if !exists $arg{client}{read_cb} &&
		   !exists $arg{client}{std_read_cb};

	return file_new (read_cb => \&file_accept_cb, %arg);
}

sub file_accept_cb {
	my ($file) = @_;

	my $new = $file->{fh}->accept;
	die 'accept'	if !defined $new;
	die 'blocking'	if !defined $new->blocking (0);
	die 'binmode'	if !binmode $new;
	$file = file_new (fh => $new, %{ $file->{client} });
	$file->{start_cb} ($file) if $file->{start_cb};
}

sub file_sock_send {
	my ($file, $data, $to) = @_;

	push @{ $file->{sockout} }, { data => $data, to => $to };
	vec ($wi, $file->{fileno}, 1) = 1;
}

sub file_sock_write_cb {
	my ($file) = @_;

	my $dataref = $file->{sockout};
	my $send = shift @$dataref
		or die 'no data';
	my $bytes = send $file->{fh}, $send->{data}, 0, $send->{to};
	die 'send'
		if !defined $bytes || $bytes != length $send->{data};
	vec ($wi, $file->{fileno}, 1) = @$dataref > 0;
}

sub file_close {
	my ($file, $reason) = @_;

	$file->{closereason} = $reason;
	vec ($ri, $file->{fileno}, 1) = 0;
	vec ($ro, $file->{fileno}, 1) = 0;
	$file->{close} = 1;
}

sub file_close_now {
	my ($file, $reason) = @_;

	$file->{closereason} = $reason if $reason;
	my $i = $file->{fileno};
	delete $files[$i];
	vec ($_, $i, 1) = 0 for $ri, $wi, $ro, $wo;
	$file->{fh}->close; $! = 0;
	$file->{close_cb} ($file) if $file->{close_cb};
	$nfiles--;
	# undef %$file;
}

sub timer_new {
	my (%arg) = @_;

	die 'should be called with timer or period'
		if !exists $arg{timer} && !exists $arg{period};
	die 'should be called with cb'
		if !exists $arg{cb};

	$arg{timer} ||= $timei + ($arg{now} ? 0 : $arg{period})
		if $arg{period};

	my $timer = \%arg;
	$timers{$timer} = $timer;
	D && warn "debug $timer";
	return $timer;
}

sub timer_del {
	my ($timer) = @_;

	D && warn "debug $timer" if $timer;
	delete $timers{$timer};
	# undef %$timer;
}

sub timer_reset {
	my ($timer) = @_;

	D && warn "debug $timer";
	$timer->{timer} = $timei + $timer->{period};
}

sub loop_one {
	D && warn "debug";

	my ($t, $timer);
	!$timer || $_->{timer} < $timer->{timer} and $timer = $_
		for values %timers;
	if ($timer) {
		$t = $timer->{timer} - time;
		if ($t <= 0) {
			D && "timer cb $timer";
			$timer->{cb} ($timer);
			if ($timer->{period}) {
				$timer->{timer} += $timer->{period};
			} else {
				timer_del ($timer);
			}
			return;
		}
	}
	D && warn "select $t sec";
	select ($ro = $ri, $wo = $wi, undef, $t) >= 0
		or die 'select';
	$timei = time;

	for my $i (0 .. $#files) {
		my $file = $files[$i];
		next if !$file;
		$file->{read_cb} ($file)
			if vec $ro, $i, 1;
		$file->{write_cb} ($file)
			if vec $wo, $i, 1;
		file_close_now ($file)
			if $file->{close} && !vec $wi, $i, 1;
	}
}

sub quit {
	print "quiting, please wait\n";
	$quit = 1;
}

sub loop {
	$SIG{INT} = \&quit;
	warn "started\n";
	loop_one () while !$quit;
	warn "stopped\n";
}

1;
