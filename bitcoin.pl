#! /usr/bin/perl

use warnings;
use strict;

use logger;
use data;
use main;
use web;
use net;
use event;

$SIG{INT} = \&event::quit;

print "welcome to bitcoin perl client v$web::VERSION\n";
data::init ();
main::init ();
web::server (8899);
net::connect ('127.0.0.1', 8333);
event::loop ();
print "goodbye\n";
