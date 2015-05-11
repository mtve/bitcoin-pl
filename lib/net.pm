package net;

use warnings;
use strict;
use IO::Socket::INET;

use event;
use serialize;
use main;
use base58;
use util;
use cfg;
use chain;

sub D() { 1 }

our $VERSION = 70002;
our $pszSubVer = ".0";
our $PUBLISH_HOPS = 5;
our $NODE_NETWORK = 1 << 0;
our $pchIPv4 = "\0" x 10 . "\xff" x 2;
our $MSG_TX = 1;
our $MSG_BLOCK = 2;

our $peer;

sub rand8 { join '', map chr rand 256, 1..8 }

sub PushMessage {
	my ($file, $cmd, $data) = @_;

	D && warn "debug fileno=$file->{fileno} cmd=$cmd data="
		. serialize::Dump ($cmd, $data);
	my $msg = serialize::Serialize ($cmd, $data);

	event::timer_reset ($file->{timer_ping})
		if $cmd ne 'ping';
	event::file_write ($file, pack
		'a4 Z12 V ' . ($file->{has_crc} ? 'a4' : 'a0') .
		' a*',
		$chain::WIRE_MAGIC, $cmd, length $msg, base58::Hash ($msg),
		$msg);
}

sub state_hdr {
	my ($file) = @_;

	D && warn "debug";

	my $hdr = event::file_read ($file, 4 + 12 + 4);
	return \&state_hdr if !defined $hdr;

	@$file{qw( net_magic net_func net_len )} = unpack 'a4 Z12 V', $hdr;
	$file->{net_magic} eq $chain::WIRE_MAGIC
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

	0 && warn "debug msg " . unpack ('H*', $msg);
	my $str = serialize::Unserialize ($file->{net_func}, $msg);
	0 && warn "debug $file->{net_func} " .
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

	$file->{nLocalHostNonce} = rand8 ();

	PushMessage ($file, 'version', {
		nVersion	=> $VERSION,
		nLocalServices	=> 1,
		nTime		=> time,
		addrYou		=> CAddress ('1.2.3.4', 8333),
		addrMe		=> CAddress ('1.2.3.4', 8333),
		nLocalHostNonce	=> $file->{nLocalHostNonce},
		strSubVer	=> '',
		nStartingHeight	=> -1,
		relay		=> "\1",	# bip-0037, send me all
	});
}

sub got_version {
	my ($file, $ver) = @_;

	D && warn "debug";
	die "version $ver->{nVersion} is too low"
		if $ver->{nVersion} < $VERSION;
	die "equal nonce"
		if $ver->{nLocalHostNonce} eq $file->{nLocalHostNonce};
}

sub send_ping {
	my ($file) = @_;

	PushMessage ($file, 'ping', { nonce => rand8 () });
}

sub got_ping {
	my ($file, $data) = @_;

	D && warn "debug";
	PushMessage ($file, 'pong', $data);
}

sub got_pong {
	my ($file, $data) = @_;

	D && warn "debug";
}

sub PushGetData {
	my ($file) = @_;

	my @h = data::blk_missed ();
	D && warn "debug @X{@h}";

	PushMessage ($file, 'getdata', [ map +{
		type	=> $MSG_BLOCK,
		hash	=> $_,
	}, @h ]) if @h;
}

sub PushGetBlocks {
	my ($file) = @_;

	PushMessage ($file, 'getblocks', {
		nVersion	=> $VERSION,
		locator		=> [ $main::blk_best->{hash} ],
		hashStop	=> $chain::NULL256,
	});
}

sub got_verack {
	my ($file) = @_;

	D && warn "debug";

	PushMessage ($file, 'verack');

	D && warn "start downloading";
	PushGetBlocks ($file);
}

sub got_addr {
	my ($file, $addr) = @_;

	D && warn "debug";
	my $v4 = grep $_->{addr}{pchReserved} eq $pchIPv4, @$addr;
	warn "$v4 ipv4 addresses of " . @$addr . " total\n";
}

sub got_inv {
	my ($file, $inv) = @_;

	D && warn "debug";

	my $outv = [];
	my $flag = 0;
	for (@$inv) {
		my $h = $_->{hash};
		if ($_->{type} == $MSG_TX) {
			push @$outv, $_ if !data::tx_exists ($h);
		} elsif ($_->{type} == $MSG_BLOCK) {
			my $b = data::blk_exists ($h);
			push @$outv, $_ if !$b;
			$flag = 1 if $b && $b->{nHeight} == -1;
		} else {
			die "inv unknown type $_->{type}";
		}
	}
	PushMessage ($file, 'getdata', $outv) if @$outv;
	PushGetBlocks ($file) if $flag;
}

sub got_block {
	my ($file, $blk) = @_;

	D && warn "debug";
	$blk->{nVersion} >= 1 && $blk->{nVersion} <= 3
		or die "bad version $blk->{nVersion}";

	if (!main::ProcessBlock ($blk)) {
		# orphaned, get missing blocks and continue download
		PushGetData ($file);
		PushGetBlocks ($file);
	}
}

sub got_notfound {
	my ($file, $inv) = @_;

	D && warn "debug";
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

sub got_getheaders {
	my ($file, $gb) = @_;

	D && warn "debug";
}

sub got_alert {
	my ($file, $alert) = @_;

	my $a = serialize::Unserialize ('alertPayload', $alert->{payload});
	print "alert $a->{StatusBar}\n";
}

sub start {
	my ($addr, $port) = @_;

	D && warn "connecting to $addr:$port";
	my $sock = IO::Socket::INET->new (
		PeerAddr	=> $addr,
		PeerPort	=> $port,
	) or die "connect failed: $!";
	binmode $sock;
	defined $sock->blocking (0) or die 'blocking';
	warn "connected to $addr:$port";
	print "connected to node $addr:$port\n";

	my $file;
	$file = event::file_new (
		fh		=> $sock,
		std_read_cb	=> \&read_cb,
		net_state	=> \&state_hdr,
		close_cb	=> sub {
			local *__ANON__ = 'close_cb';
			event::timer_del ($file->{timer_ping});
			event::timer_del ($file->{timer_inact});
			warn "closed by $file->{closereason}";
			undef $peer;
		},
		has_crc		=> 1,		# http://bitcoin.org/feb20
	);
	$file->{timer_ping} = event::timer_new (
		period	=> $cfg::var{NET_TIMER_PING},
		cb	=> sub { send_ping ($file); },
	);
	$file->{timer_inact} = event::timer_new (
		period	=> $cfg::var{NET_TIMER_INACT},
		cb	=> sub { event::file_close ($file, 'inactivity'); },
	);

	send_version ($file);
	$peer = $file;
}

sub periodic {
	return if $peer;
	for (split ',', $cfg::var{NET_PEERS}) {
		my ($ip, $port) = /^(.*):(\d+)\z/ or die "bad peer $_";
		eval { start ($ip, $port); };
		last if !$@;
		warn "error $_ $@";
	}
}

sub init {
	event::timer_new (
		period	=> $cfg::var{NET_PERIODIC},
		now	=> 1,
		cb	=> \&periodic,
	);
}

1;
