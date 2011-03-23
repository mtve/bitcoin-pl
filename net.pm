package net;

use warnings;
use strict;
use IO::Socket::INET;

use event;
use serialize;
use main;
use base58;

sub D() { 1 }

our $WIRE_MAGIC = "\xf9\xbe\xb4\xd9";
our $VERSION = 300;
our $pszSubVer = ".0";
our $DEFAULT_PORT = 8333;
our $PUBLISH_HOPS = 5;
our $NODE_NETWORK = 1 << 0;
our $pchIPv4 = "\0" x 10 . "\xff" x 2;
our $MSG_TX = 1;
our $MSG_BLOCK = 2;

sub PushMessage {
	my ($file, $cmd, $data) = @_;

	D && warn "debug fileno=$file->{fileno} cmd=$cmd";
	my $msg = serialize::Serialize ($cmd, $data);

	event::timer_reset ($file->{timer_ping})
		if $cmd ne 'ping';
	event::file_write ($file, pack
		'a4 Z12 V ' . ($file->{has_crc} ? 'a4' : 'a0') . ' a*',
		$WIRE_MAGIC, $cmd, length $msg, base58::Hash ($msg), $msg);
}

sub state_hdr {
	my ($file) = @_;

	D && warn "debug";

	my $hdr = event::file_read ($file, 4 + 12 + 4);
	return \&state_hdr if !defined $hdr;

	@$file{qw( net_magic net_func net_len )} = unpack 'a4 Z12 V', $hdr;
	$file->{net_magic} eq $WIRE_MAGIC
		or die "got bad magic " . unpack 'H*', $hdr;
	D && warn "debug func=$file->{net_func} len=$file->{net_len}";
	$file->{net_len} < 1_000_000
		or die "message is too big";
	$file->{has_crc} ? goto &state_crc : goto &state_msg;
}

sub state_crc {
	my ($file) = @_;

	D && warn "debug";

	my $hdr = event::file_read ($file, 4);
	return \&state_crc if !defined $hdr;

	$file->{net_crc} = unpack 'V', $hdr;
	D && warn "debug crc=$file->{net_crc}";
	goto &state_msg;
}

sub state_msg {
	my ($file) = @_;

	D && warn "debug";

	my $msg = event::file_read ($file, $file->{net_len});
	return \&state_msg if !defined $msg;

	if (exists $file->{net_crc}) {
		my $crc = unpack 'V', base58::Hash ($msg);
		$file->{net_crc} == $crc
			or die "bad crc $crc != $file->{net_crc}";
	}
	event::timer_reset ($file->{timer_inact});

	D && warn "debug msg " . unpack ('H*', $msg);
	my $str = serialize::Unserialize ($file->{net_func}, $msg);
	D && warn "debug $file->{net_func} " .
		serialize::Dump ($file->{net_func}, $str);

	no strict 'refs';
	exists &{"got_$file->{net_func}"}
		or die "bad func $file->{net_func}";

	&{"got_$file->{net_func}"} ($file, $str);
	goto &state_hdr;
}

sub read_cb {
	my ($file) = @_;

	$file->{net_state} = $file->{net_state} ($file);
}

sub CAddress {
	return {
		nServices	=> $NODE_NETWORK,
		pchReserved	=> $pchIPv4,
		ip		=> $_[0],
		port		=> $_[1],
	};
}

sub send_version {
	my ($file) = @_;

	D && warn "debug";

	$file->{nLocalHostNonce} = join '', map chr rand 256, 1..8;

	PushMessage ($file, 'version', {
		nVersion	=> $VERSION,
		nLocalServices	=> 1,
		nTime		=> time,
		addrYou		=> CAddress ('1.2.3.4', 8333),
		addrMe		=> CAddress ('1.2.3.4', 8333),
		nLocalHostNonce	=> $file->{nLocalHostNonce},
		strSubVer	=> '',
		nStartingHeight	=> -1,
	});
}

sub got_version {
	my ($file, $ver) = @_;

	D && warn "debug";
	die "version $ver->{nVersion} is too low"
		if $ver->{nVersion} < 200;
	die "equal nonce"
		if $ver->{nLocalHostNonce} eq $file->{nLocalHostNonce};

	# PushMessage ($file, 'getaddr');
}

sub got_ping {
	my ($file) = @_;

	D && warn "debug";
}

sub PushGetBlocks {
	my ($file) = @_;

	my ($n, $h) = data::blk_best () or die "no best";

	PushMessage ($file, 'getblocks', {
		nVersion	=> $VERSION,
		locator		=> [ $h ],
		hashStop	=> $main::NULL256,
	});
}

sub got_verack {
	my ($file) = @_;

	D && warn "debug";

	PushMessage ($file, 'verack');
	$file->{has_crc} = 1;

	D && warn "start downloading";
	PushGetBlocks ($file);
}

sub got_addr {
	my ($file, $addr) = @_;

	D && warn "debug";
	my $v4 = grep $_->{pchReserved} eq $pchIPv4, @$addr;
	warn "$v4 ipv4 addresses of " . @$addr . " total\n";
}

sub got_inv {
	my ($file, $inv) = @_;

	D && warn "debug";

	my $outv = [];
	for (@$inv) {
		my $h = $_->{hash};
		if ($_->{type} == $MSG_TX) {
			push @$outv, $_ if !data::tx_exists ($h);
		} elsif ($_->{type} == $MSG_BLOCK) {
			push @$outv, $_ if !data::blk_exists ($h);
		} else {
			die "inv unknown type $_->{type}";
		}
	}
	if (@$outv) {
		PushMessage ($file, 'getdata', $outv);
	} else {
		PushGetBlocks ($file);
	}
}

sub got_block {
	my ($file, $block) = @_;

	D && warn "debug";
	$block->{nVersion} == 1
		or die "bad version $block->{nVersion}";

	PushGetBlocks ($file) if !main::ProcessBlock ($block);
}

sub got_tx {
	my ($file, $tx) = @_;

	D && warn "debug";
	$tx->{nVersion} == 1
		or die "bad version $tx->{nVersion}";

	main::ProcessTransaction ($tx);
}

sub got_getblocks {
	my ($file, $gb) = @_;

	D && warn "debug";
}

sub connect {
	my ($addr, $port) = @_;

	D && warn "connecting to $addr:$port";
	my $sock = IO::Socket::INET->new (
		PeerAddr	=> $addr,
		PeerPort	=> $port,
		Blocking	=> 0,
	) or die "connect to $addr:$port failed";
	binmode $sock;
	warn "connected to $addr:$port";
	print "connected to node $addr:$port\n";

	my $file;
	$file = event::file_new (
		fh		=> $sock,
		std_read_cb	=> \&read_cb,
		net_state	=> \&state_hdr,
		close_cb	=> sub {
			event::timer_del ($file->{timer_ping});
			event::timer_del ($file->{timer_inact});
			die "closed by $file->{closereason}";
		},
	);
	$file->{timer_ping} = event::timer_new (
		period	=> 30 * 60,
		cb	=> sub { PushMessage ($file, 'ping') },
	);
	$file->{timer_inact} = event::timer_new (
		period	=> 90 * 60,
		cb	=> sub { event::file_close ($file, 'inactivity') },
	);

	send_version ($file);
}

1;
