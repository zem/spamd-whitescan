#!/usr/bin/perl
# 
# Copyright (c) 2019 Hans Freitag <hans.freitag@conesphere.com> 
#     gpg 1553A52AE25725279D8A499175E880E6DC59190F
# 
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
# 
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
# 
# do some whitelist scanning using regex sets
# 
# TODO: aggressive tarpitting if we discover that a domain does not provide a 
# reverse lookup
#
# TODO: Log GEYLIST Entrys 
#
# TODO2: having 2 conf directorys with lists that are read when touched, 
# containing NOSPAM: and TRAPPED: lists. Those lists can be provided 
# Externally 
#
# TODO3: Export NOSPAMD and TRAPPED lists 
#
# TODO4: Handle SPF entrys if they exist properly, eg trap/tarpit all ips 
# pretending to send from a domain that are not listed in spf
#
use Fcntl;   # For O_RDWR, O_CREAT, etc.
use SDBM_File;
use Socket;
use Net::hostent;
use Getopt::Std;
use POSIX 'strftime';

$VERSION='0.9.1';

my %opts;
getopts('hvdntaD:p:T:N:', \%opts);

if ( defined $opts{h} ) { HELP_MESSAGE(); }
if ( ! defined $opts{p} ) { $opts{p}=30; }
if ( $opts{p} !~ /^\d+$/ ) { 
	print STDERR "Warning -p $opts{p} is not numeric, using default \n";
	$opts{p}=30; 
}

tie(%db, 'SDBM_File', '/var/db/whitescan', O_RDWR|O_CREAT, 0600)
  or die "Couldn't tie SDBM file '/var/db/whitescan': $!; aborting";

######################################################################################
sub HELP_MESSAGE {
	print STDERR "whitelist.pl is a whitelist scanner for spamd\n";
	print STDERR "it can be used to whitelist hardly passing smtp hosts\n";
	print STDERR "like gmail or gmx by looking at the upperlevel part of \n";
	print STDERR "their helo domains, remembering all the ips and whitelist \n";
	print STDERR "them at once if PASSTIME is reached\n";
	print STDERR "\n";
	print STDERR "\n";
	print STDERR "PARAMETERS:\n";
	print STDERR "     -h this help \n";
	print STDERR "     --help the very same help \n";
	print STDERR "     -v be verbose on stderr eg. log what you are doing\n";
	print STDERR "     -a aggressively blacklist a grey entry that can't resolve\n";
	print STDERR "     -d dump the database content for debugging \n";
	print STDERR "     -n create a formatted <nospamd> table from this database \n";
	print STDERR "     -t create a formatted <spamd> traplist table from this database \n";
	print STDERR "     -p MINUTES set passtime in minutes, default 20 \n";
	print STDERR "     -D SOME_DB_KEY  deletes a key from the database\n";
	print STDERR "     -T SOME_HELO  sets a HELO Trap\n";
	print STDERR "     -N SOME_HELO  sets a HELO as nospam\n";
	exit;
}

sub dbg {
	if ( ! defined $opts{v} ) { return; }
	print STDERR strftime('%Y-%m-%d %H:%M:%S ', localtime).join(" ", @_)."\n";
}

sub test_helo {
	my $helostr=shift;
	# TODO Insert code regex to ignore certain helos here if ever needed 
	my @helo=split('\.', $helostr);
	if ( $#helo > 1 ) { return 1; } # if helo is not foo.bar.sth it is to short for processing
	return 0;
}

sub compare_helo_addr {
	my $helo=shift;
	my $addr=shift;
	
	my $hent=gethostbyname($helo);
	if ( ! $hent ) { return 0; }
	my $aref=$hent->addr_list;
	foreach my $haddr (map { inet_ntoa($_) } @$aref) {
		if ( $addr eq $haddr ) { return 1; }
	}
	return 0;
}

sub strip_helo {
	my @helo=split('\.', shift);
	my $foo=shift(@helo);
	return join('.', @helo);
}

sub ip_hash {
	my %iph;
	foreach my $ip (split('\|', shift)) { $iph{$ip}=1; }
	return %iph;
}

sub ip_string {
	my %iph=@_;
	return join('|', keys(%iph));
}

################################################################################
# do less syscalls 
my $time=time;
my @white_helos=();
my @trapped_helos=();
my @trapped_src=();

dbg("starting up reading spamdb");
open(SPAMDB, "spamdb |") or die "could not spawn spamdb";
while(<SPAMDB>){ 
	chomp;
	(
		$type, 
		$src, 
		$helo, 
		$from, 
		$to, 
		$first, 
		$passed, 
		$expire, 
		$block, 
		$pass
	)=split('\|');
	if ( $type ne "GREY" ) { next; }

	# we store all the Data we need. 
	
	# the next tweak is a workaround that changes expire to the actual expire time 
	# due to a bug in spamdb
	$passed=$first+($opts{p}*60);
	
	# first we store GREY entrys to the hash as they are
	$grey_key="GREY|$src|$helo|$from|$to";
	$value="$first|$passed|$expire|$block|$pass";
	if ( defined $db{$grey_key} ) { 
		#dbg("grey entry already seen", $helo, $src, $from, $to);
		next; 
	} # we have already seen and processed this greylist entry
	$db{$grey_key}=$value;

	if ( test_helo($helo) == 0 ) { 
		if ( defined $opts{a} ) { push(@trapped_src, $src); }
		next; 
	} # for not being a domain
	if ( compare_helo_addr($helo, $src) == 0 ) { 
		# domain does not resolve
		if ( defined $opts{a} ) { push(@trapped_src, $src); }
		next; 
	} 

	# store resolved IP addresses for this greylist helo entry
	my %iph=ip_hash($db{"RESOLVED|$helo"});
	$iph{$src}=1;
	$db{"RESOLVED|$helo"}=ip_string(%iph);
	dbg("stored resolved ips", $helo, keys %iph);

	$helo=strip_helo($helo);
	# $helo_key="HELO|".strip_helo($helo)."|$from|$to";
	$pass_key="PASS|$helo|$from|$to";
	$expire_key="EXPIRE|$helo|$from|$to";
	if ( ! defined $db{$pass_key} ) {
		dbg($pass_key, "is not yet in db");
		# this thing is new so lets reg
		# $db{$helo_key}=1;
		$db{$pass_key}=$passed;
		$db{$expire_key}=$expire;
		if ( defined $db{"NOSPAM|$helo"} ) {
			dbg("Whitelisting", $helo);
			# we do already know this $helo whitelist immidiately
			$db{"NOSPAM|$helo"}=$helo;
			push(@white_helos, $helo);
		} elsif ( defined $db{"TRAPPED|$helo"} ) {
			dbg("Trapping", $helo);
			# This Helo is well known and needs to be trapped immidiately
			$db{"TRAPPED|$helo"}=$helo;
			push(@trapped_helos, $helo);
			delete $db{"NOSPAM|$helo"};
		}
	} else {
		# $db{$helo_key}=$db{$helo_key}+1;
		if ( $passed < $db{$pass_key} ) { $db{$pass_key}=$passed; }
		if ( $expire < $db{$expire_key} ) { $db{$expire_key}=$expire; }
		if ( $time > $db{$pass_key} ) { 
			if ( defined $db{"TRAPPED|$helo"} ) {
				dbg("PASSTIME Exceeded but HELO is trapped Trapping", $helo);
				# this part should never run but to be complete here 
				$db{"TRAPPED|$helo"}=$helo;
				push(@trapped_helos, $helo);
				delete $db{"NOSPAM|$helo"};
			} else {
				dbg("PASSTIME Exceeded and new Pkg here Whitelisting", $helo);
				$db{"NOSPAM|$helo"}=$helo;
				push(@white_helos, $helo);
			}
		}
	}
}
close SPAMDB;

# this has to be at the right spot in the code to be effective not in the end 
# as the rest of the parameter if statements are
if ( defined $opts{N} ) {
	dbg("helo $opts{N} is put in NOSPAM status as requested by the user (-N)");
	push(@white_helos, $opts{N});
	delete $db{"TRAPPED|$opts{N}"};
	$db{"NOSPAM|$opts{N}"}=$opts{N};
}

dbg("whitelist helos");
foreach my $helo (@white_helos) {
	my @resolved_keys=sort grep {/$helo$/} grep {/^RESOLVED/} keys %db;
	my @ipa;
	foreach my $k (@resolved_keys) { 
		dbg("# $k"); 
		push(@ipa, ip_hash($db{$k}));
	}
	my %iph=@ipa;
	foreach my $addr (keys %iph) {
		dbg("spamdb -a $addr"); 
		system("spamdb -a $addr");
	}
}

# this has to be at the right spot in the code to be effective not in the end 
# as the rest of the parameter if statements are
if ( defined $opts{T} ) {
	dbg("helo $opts{T} is to be trapped as the user whishes (-T)");
	push(@trapped_helos, $opts{T});
	delete $db{"NOSPAM|$opts{T}"};
	$db{"TRAPPED|$opts{T}"}=$opts{T};
}

dbg("trapping helos");
foreach my $helo (@trapped_helos) {
	my @resolved_keys=sort grep {/$helo$/} grep {/^RESOLVED/} keys %db;
	my @ipa;
	foreach my $k (@resolved_keys) { 
		dbg("# $k"); 
		push(@ipa, ip_hash($db{$k}));
	}
	my %iph=@ipa;
	foreach my $addr (keys %iph) {
		dbg("spamdb -a -t $addr"); 
		system("spamdb -a -t $addr");
	}
}

dbg("expire old grey entrys ");
foreach my $key (grep {/^GREY/} keys %db) {
	my (
		$first, 
		$passed, 
		$expire, 
		$block, 
		$pass
	)=split('\|', $db{$key});
	if ( $time > $expire ) { 
		dbg("expire gray:", $key, $time, $expire);
		delete $db{$key}; 
	}
}
dbg("expire old helo entrys ");
foreach my $key (grep {/^EXPIRE/} keys %db) {
	if ( $time > $db{$key} ) { 
		dbg("expire helo:", $key, $time, $db{$key});
		delete $db{$key}; 
		$key =~ s/^EXPIRE/PASS/;
		dbg("expire helo:", $key, $time, $db{$key});
		delete $db{$key}; 
	}
}

if ( defined $opts{D} ) {
        dbg("deleting:", $opts{D}, $db{$opts{D}});
        delete $db{$opts{D}};
}

if ( defined $opts{t} ) {
	foreach my $key (sort grep {/^TRAPPED/} keys %db) {
		# this helo is or was once whitelisted
		my $helo = $db{$key};
		print "# IP traplist for $helo\n";
		my @resolved_keys=sort grep {/$helo$/} grep {/^RESOLVED/} keys %db;
		my @ipa;
		foreach my $k (@resolved_keys) { 
			print "# $k\n"; 
			push(@ipa, ip_hash($db{$k}));
		}
		my %iph=@ipa;
		print join("\n", sort keys %iph);
		print "\n\n";
	}
}

if ( defined $opts{n} ) {
	foreach my $key (sort grep {/^NOSPAM/} keys %db) {
		# this helo is or was once whitelisted
		my $helo = $db{$key};
		print "# IP whitelist for $helo\n";
		my @resolved_keys=sort grep {/$helo$/} grep {/^RESOLVED/} keys %db;
		my @ipa;
		foreach my $k (@resolved_keys) { 
			print "# $k\n"; 
			push(@ipa, ip_hash($db{$k}));
		}
		my %iph=@ipa;
		print join("\n", sort keys %iph);
		print "\n\n";
	}
}

if ( defined $opts{d} ) {
	foreach my $k (sort keys %db) { 
		print $k.": ".$db{$k}."\n";
	}
} 

untie %db;
exit(0);