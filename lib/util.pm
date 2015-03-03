package util;

# autoexport %X

use warnings;
use strict;

sub D() { 0 }

# bin2hex

sub util::bin2hex::TIEHASH { bless {}, $_[0] }
sub util::bin2hex::FETCH { unpack 'H*', reverse $_[1] }

tie our %b2h, 'util::bin2hex';

sub util::bin2hexr::TIEHASH { bless {}, $_[0] }
sub util::bin2hexr::FETCH { unpack 'H*', $_[1] }

tie our %b2hr, 'util::bin2hexr';

# hex2bin

sub util::hex2bin::TIEHASH { bless {}, $_[0] }
sub util::hex2bin::FETCH { reverse pack 'H*', $_[1] }

tie our %h2b, 'util::hex2bin';

# html_esc

sub util::html_esc::TIEHASH { bless {}, $_[0] }
sub util::html_esc::FETCH {
	my (undef, $str) = @_;

	s/&/&amp;/g, s/</&lt;/g, s/>/&gt;/g, s/"/&quot;/g for $str;
	return $str;
}

tie our %hesc, 'util::html_esc';

sub import {
	my $pkg = caller;
	no strict 'refs';
	*{"$pkg\::X"} = \%b2h;
	*{"$pkg\::Xr"} = \%b2hr;
}

1;
