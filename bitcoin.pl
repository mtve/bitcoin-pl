#! /usr/bin/perl

use warnings;
use strict;
use Math::BigInt try => 'GMP,Pari'; # hint in advance
use lib 'lib';

use logger;
use data;
use main;
use web;
use net;
use event;
use cfg;

our $VERSION = '140219';

print "welcome to bitcoin perl v$VERSION\n";
logger::rotate ();
cfg::load ();
data::init ();
main::init ();
web::init ();
net::init ();
event::loop ();
#END {
#	print "committing data\n";
#	data::commit ();
#	print "goodbye\n";
#}
