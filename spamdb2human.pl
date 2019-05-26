#!/usr/bin/perl
use POSIX qw(strftime);
while (<STDIN>) {
	chomp;
	@l=split('\|');
	$l[5]=strftime('%Y-%m-%d %H:%M:%S', localtime($l[5]));
	$l[6]=strftime('%Y-%m-%d %H:%M:%S', localtime($l[6]));
	$l[7]=strftime('%Y-%m-%d %H:%M:%S', localtime($l[7]));
	print join('|', @l);
	print "\n";
}

