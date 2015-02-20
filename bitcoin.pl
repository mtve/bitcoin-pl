#! /usr/bin/perl

use warnings;
use strict;
use Math::BigInt try => 'GMP,Pari';

use logger;
use data;
use main;
use web;
use net;
use event;

our $VERSION = '140219';

print "welcome to bitcoin perl v$VERSION\n";
logger::rotate ();
data::init ();
main::init ();
web::server (8899);
net::connect ('127.0.0.1', 8333);
event::loop ();
END {
	print "commiting data\n";
	data::commit ();
	print "goodbye\n";
}
