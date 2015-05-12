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

our $VERSION = '150508';

print "welcome to bitcoin-pl v$VERSION\n";
cfg::load ($ARGV[0]);
data::init ();
main::init ();
web::init ();
net::init ();
event::loop ();
END { print "goodbye\n"; }
