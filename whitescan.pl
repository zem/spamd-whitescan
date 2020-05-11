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
#######################################################################################
#
#Notes part:
#
# TODO do some whitelist scanning using regex sets
#
# no SPF==classic handling
# ---------------------------
# HELO|SPF|OK
#  OK | OK|OK
#  NO | OK|OK if its also reversing and domain matches
#  OK | NO|NO definately fraud, sending domain tells us
#  NO | NO|NO definately tarpit this
#
######################################################################################
# Setup part to make load librarys and initialize vars and parse argv
use Fcntl;   # For O_RDWR, O_CREAT, etc.
use SDBM_File;
use NDBM_File;
use Socket;
use Net::hostent;
use Getopt::Std;
use Mail::SPF;
use POSIX 'strftime';

$VERSION='0.9.2';

$GREYLOG='/var/log/grey.log';

my $spf_server  = Mail::SPF::Server->new();

my %opts;
getopts('hHvdntuD:p:T:N:i', \%opts);

if ( defined $opts{h} ) { HELP_MESSAGE(); }
if ( ! defined $opts{p} ) { $opts{p}=30; }
if ( $opts{p} !~ /^\d+$/ ) {
	print STDERR "Warning -p $opts{p} is not numeric, using default \n";
	$opts{p}=30;
}

if ( -e "/var/db/whitescan.dir" ) {
	tie(%db, 'SDBM_File', '/var/db/whitescan', O_RDWR|O_CREAT, 0600)
	  or die "Couldn't tie SDBM file '/var/db/whitescan': $!; aborting";
} else {
	my %db;
}

tie(%db_pass, 'NDBM_File', '/var/db/whitescan_pass', O_RDWR|O_CREAT, 0600)
  or die "Couldn't tie NDBM file '/var/db/whitescan_pass': $!; aborting";

tie(%db_grey, 'NDBM_File', '/var/db/whitescan_grey', O_RDWR|O_CREAT, 0600)
  or die "Couldn't tie NDBM file '/var/db/whitescan_grey': $!; aborting";

tie(%db_trapped, 'NDBM_File', '/var/db/whitescan_trapped', O_RDWR|O_CREAT, 0600)
  or die "Couldn't tie NDBM file '/var/db/whitescan_trapped': $!; aborting";

tie(%db_resolved, 'NDBM_File', '/var/db/whitescan_resolved', O_RDWR|O_CREAT, 0600)
  or die "Couldn't tie NDBM file '/var/db/whitescan_resolved': $!; aborting";

tie(%db_nospam, 'NDBM_File', '/var/db/whitescan_nospam', O_RDWR|O_CREAT, 0600)
  or die "Couldn't tie NDBM file '/var/db/whitescan_nospam': $!; aborting";

tie(%db_unresolved, 'NDBM_File', '/var/db/whitescan_unresolved', O_RDWR|O_CREAT, 0600)
  or die "Couldn't tie NDBM file '/var/db/whitescan_unresolved': $!; aborting";

tie(%db_expire, 'NDBM_File', '/var/db/whitescan_expire', O_RDWR|O_CREAT, 0600)
  or die "Couldn't tie NDBM file '/var/db/whitescan_expire': $!; aborting";

dbg("opening greylog");
open(GRL, ">> /var/log/grey.log") or die "could not open grey.log";


# some more or less global variables
my $time=time;
my @white_helos=();
my @trapped_helos=();
my @trapped_src=();

######################################################################################
# The library part, functs to be used in this script
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
	print STDERR "     -d dump the database content for debugging \n";
	print STDERR "     -H print all times ( -d and grey.log ) human readable\n";
	print STDERR "     -n export nospam database entrys and their resolved entrys\n";
	print STDERR "     -t export trapped entrys and their resolved entrys \n";
	print STDERR "     -u export unresolved entrys on stdout\n";
	print STDERR "     -p MINUTES set passtime in minutes, default 20 \n";
	print STDERR "     -D SOME_DB_KEY deletes a key from the database\n";
	print STDERR "     -T SOME_HELO  sets a HELO Trap\n";
	print STDERR "     -N SOME_HELO  sets a HELO as nospam\n";
	print STDERR "     -i import exported trapped entrys (used in combination with -t -n and -u)\n";
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
	if ( $#helo > 0 ) { return 1; } # if helo is not foo.bar.sth it is to short for processing, we process foo.bar too but we dont strip that later.
	return 0;
}

sub resolve_helo {
	my $helo=shift;
	my @addrs;
	
	my $hent=gethostbyname($helo);
	if ( ! $hent ) { return; }
	my $aref=$hent->addr_list;
	@addrs=map { inet_ntoa($_) } @$aref;
	return @addrs;
}

sub compare_helo_addr {
	my $addr=shift;
	my @lst=@_;

	foreach my $haddr (@lst) {
		if ( $addr eq $haddr ) { return 1; }
	}
	return 0;
}

sub strip_helo {
	my @helo=split('\.', shift);
	my $foo=shift(@helo);
	if ( $#helo == 0 ) { return join('.', $foo, @helo); }
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

# returning human readable timestamp if the user wants one
sub hrtime {
	my $t=shift;
	if ( ! defined $opts{H} ) { return $t; }
	return strftime('%Y-%m-%d %H:%M:%S', localtime($t));
}

################################################################################
# This is some compatibility code as we try to split the single DBM Database into
# multiple Databases we have to convert the old DB format into a new one.
################################################################################
foreach my $key (keys %db) {
	my ($d, @k)=split('\|', $key);
	dbg("type is $d");
	if (join('|', @k) eq "") { print STDERR "$key is invalid, skipping\n"; next; }
	if ($db{$key} eq "") { print STDERR "$key has invalid value, skipping\n"; next; }
	if ($d eq "GREY") {
		dbg("copying $key: $db{$key} from old db to grey ".join("|",@k));
		$db_grey{join('|', @k)}=$db{$key} or die "cant write key $key to new db";
	} elsif ($d eq "PASS") {
		dbg("copying $key: $db{$key} from old db to pass ".join("|",@k));
		$db_pass{join('|', @k)}=$db{$key} or die "cant write key $key to new db";
	} elsif ($d eq "EXPIRE") {
		dbg("copying $key: $db{$key} from old db to expire ".join("|",@k));
		$db_expire{join('|', @k)}=$db{$key} or die "cant write key $key to new db";
	} elsif ($d eq "NOSPAM") {
		dbg("copying $key: $db{$key} from old db to nospam ".join("|",@k));
		$db_nospam{join('|', @k)}=$db{$key} or die "cant write key $key to new db";
	} elsif ($d eq "TRAPPED") {
		dbg("copying $key: $db{$key} from old db to trapped ".join("|",@k));
		$db_trapped{join('|', @k)}=$db{$key} or die "cant write key $key to new db";
	} elsif ($d eq "RESOLVED") {
		dbg("copying $key: $db{$key} from old db to resolved ".join("|",@k));
		$db_resolved{join('|', @k)}=$db{$key} or die "cant write key $key to new db";
	} elsif ($d eq "UNRESOLVED") {
		dbg("copying $key: $db{$key} from old db to unresolved ".join("|",@k));
		$db_unresolved{join('|', @k)}=$db{$key} or die "cant write key $key to new db";
	} else {
		die "The DB key $key is of unknown type stopping here\n";
	}
	# as SDBM files might cause trouble we need a bit more code to delete values 
	dbg("deleting $key: $db{$key} from old db");
	delete $db{$key};
}

if ( -e "/var/db/whitescan.dir" ) {
	dbg("deleting old sdbm database");
	untie %db;
	unlink("/var/db/whitescan.dir");
	unlink("/var/db/whitescan.pag");
}
# Spamdb will not be called for db import or if other administrative tasks
# will be made
if (
	( ! defined $opts{i} )
		and
	( ! defined $opts{d} )
		and
	( ! defined $opts{n} )
		and
	( ! defined $opts{u} )
		and
	( ! defined $opts{T} )
		and
	( ! defined $opts{D} )
		and
	( ! defined $opts{N} )
		and
	( ! defined $opts{h} )
) {
################################################################################
# Main workflow parsing spamdb output
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
	$grey_key="$src|$helo|$from|$to";
	$value="$first|$passed|$expire|$block|$pass";
	#$hrvalue=hrtime($first)."|".hrtime($passed)."|".hrtime($expire)."|$block|$pass";
	if ( defined $db_grey{$grey_key} ) {
		if ( $db_grey{$grey_key} ne $value ){
			$db_grey{$grey_key}=$value;
			print GRL "grey $grey_key|$value\n";
		}
		#dbg("grey entry already seen", $helo, $src, $from, $to);
		next;
	} # we have already seen and processed this greylist entry
	$db_grey{$grey_key}=$value;
	print GRL "grey $grey_key|$value\n";


	if ( test_helo($helo) == 0 ) {
		dbg("helo $helo has no domain in it and is trapped therefore");
		push(@trapped_src, $src);
		next;
	} # for not being a domain
	dbg("spf resolving $helo");
	my @addrs=resolve_helo($helo);
	dbg("spf lookup from ".substr($from, 1, -1)." for IP $src");
	my $spf_identity=substr($from, 1, -1);
	my $spf_code="none";
	if ( $spf_identity eq "" ) {
		dbg("The ip $src has trying to send mail with no identity.");
	} else {
		my $spf = $spf_server->process(Mail::SPF::Request->new(
				scope           => 'mfrom',             # or 'helo', 'pra'
				identity        => $spf_identity,
				ip_address      => $src,
			)
		);
		$spf_code=$spf->code;
	}

	# check spf cone anyway if its neither none or pass, trap the host
	if ( $spf_code ne 'none' ) {
		if ( $spf_code ne 'pass' ) {
			dbg("The ip $src is not listed in the spf record of $from");
			push(@trapped_src, $src);
			next;
		}
	}

	if ( compare_helo_addr($src, @addrs) == 0 ) {
		# domain does not resolve and does not pass spf
		dbg("The helo $helo could not be compared src $src == ".join(' ', @addrs));
		if ( $spf_code ne 'pass' ) {
			if (( $spf_identity eq "" ) and ( defined $db_resolved{"$helo"} )) {
				dbg("No rcpt-from and unresolveable but known domain $helo");
				dbg("I cant do anything here but skipping to next");
				next;
			}
			dbg("spf lookup not passed from ".substr($from, 1, -1)." ".$spf_code);
			push(@trapped_src, $src);
			next;
		}
		dbg("The helo $helo is illegal but the spf lookup has passed");
		dbg("The this is most propably the case for outlook.com");
		# we will take $src as the ip one by one.
		@addrs=($src);
	}

	# store resolved IP addresses for this greylist helo entry
	my %iph=ip_hash($db_resolved{"$helo"});
	foreach my $a (@addrs) { $iph{$a}=1; }
	$db_resolved{"$helo"}=ip_string(%iph);
	dbg("stored resolved ips", $helo, keys %iph);

	$helo=strip_helo($helo);
	# $helo_key="HELO|".strip_helo($helo)."|$from|$to";
	$pass_key="$helo|$from|$to";
	$expire_key="$helo|$from|$to";
	if ( ! defined $db_pass{$pass_key} ) {
		dbg($pass_key, "is not yet in pass db");
		dbg("testing for NOSPAM|$helo");
		dbg("testing for TRAPPED|$helo");
		# Check for nospam keys
		# we do not register PASS or EXPIRE if the
		# this thing is new so lets reg
		# $db{$helo_key}=1;
		if ( defined $db_nospam{"$helo"} ) {
			dbg("Whitelisting", $helo);
			# we do already know this $helo whitelist immidiately
			$db_nospam{"$helo"}=$time;
			push(@white_helos, $helo);
		} elsif ( defined $db_trapped{"$helo"} ) {
			dbg("Trapping", $helo);
			# This Helo is well known and needs to be trapped immidiately
			$db_trapped{"$helo"}=$time;
			push(@trapped_helos, $helo);
			delete $db_nospam{"$helo"};
		} elsif ( $helo =~ /^ncki.*\....$/ ) { # I will do some regex based configuration for sure soon
			dbg("Trapping regex", $helo);
			# This Helo is well known and needs to be trapped immidiately
			$db_trapped{"$helo"}=$time;
			push(@trapped_helos, $helo);
			delete $db_nospam{"$helo"};
		} elsif ( $helo =~ /^shaxi.*\....$/ ) { # I will do some regex based configuration for sure soon
			dbg("Trapping regex", $helo);
			# This Helo is well known and needs to be trapped immidiately
			$db_trapped{"$helo"}=$time;
			push(@trapped_helos, $helo);
			delete $db_nospam{"$helo"};
		} elsif ( $helo =~ /securedns\.com$/ ) { # I will do some regex based configuration for sure soon
			dbg("Trapping regex", $helo);
			# This Helo is well known and needs to be trapped immidiately
			$db_trapped{"$helo"}=$time;
			push(@trapped_helos, $helo);
			delete $db_nospam{"$helo"};
		} else {
			dbg("registering", $pass_key, "to db");
			dbg("registering", $expire_key, "to db");
			$db_pass{$pass_key}=$passed;
			$db_expire{$expire_key}=$expire;
		}
	} else {
		# $db{$helo_key}=$db{$helo_key}+1;
		if ( $passed < $db_pass{$pass_key} ) { $db_pass{$pass_key}=$passed; }
		if ( $expire < $db_expire{$expire_key} ) { $db_expire{$expire_key}=$expire; }
		if ( $time > $db_pass{$pass_key} ) {
			if ( defined $db_trapped{"$helo"} ) {
				dbg("PASSTIME Exceeded but HELO is trapped Trapping", $helo);
				# this part should never run but to be complete here
				$db_trapped{"$helo"}=$time;
				push(@trapped_helos, $helo);
				delete $db_nospam{"$helo"};
			} elsif ( $helo =~ /^ncki.*\....$/ ) { # I will do some regex based configuration for sure soon
				dbg("Trapping regex", $helo);
				# This Helo is well known and needs to be trapped immidiately
				$db_trapped{"$helo"}=$time;
				push(@trapped_helos, $helo);
				delete $db_nospam{"$helo"};
			} elsif ( $helo =~ /^shaxi.*\....$/ ) { # I will do some regex based configuration for sure soon
				dbg("Trapping regex", $helo);
				# This Helo is well known and needs to be trapped immidiately
				$db_trapped{"$helo"}=$time;
				push(@trapped_helos, $helo);
				delete $db_nospam{"$helo"};
			} elsif ( $helo =~ /securedns\.com$/ ) { # I will do some regex based configuration for sure soon
				dbg("Trapping regex", $helo);
				# This Helo is well known and needs to be trapped immidiately
				$db_trapped{"$helo"}=$time;
				push(@trapped_helos, $helo);
				delete $db_nospam{"$helo"};
			} else {
				dbg("PASSTIME Exceeded and new Pkg here Whitelisting", $helo);
				$db_nospam{"$helo"}=$time;
				push(@white_helos, $helo);
			}
		}
	}
}
close SPAMDB;

# this bracked closes the if in front of the spamdb open() call
}

################################################################################
# Main workflow part 2 pusching the results of main 1 back to database, stdout
# or spamdb 
#
# this has to be at the right spot in the code to be effective not in the end
# as the rest of the parameter if statements are

# importing of database files takes place before -N and -T options are processed and
# more important before the @trapped_helos and @white_helos is being processed
# when the database is getting imported data is read from STDIN and the flags t n u
# define the scope of the content to be imported, for RESOLVED and NOSPAM or RESOLVED
# and TRAPPED entrys. 
#
if ( defined $opts{i} ) {
	while(<STDIN>) {
		chomp;
		my ($T, $P, @l) = split('\|');
		my $F=join('|', @l);
		my $key="$P";

		if ( $key eq "" ) { print STDERR "Read zero length key of type $T, will not import that\n"; next; }

		my %perm;
		if ( $opts{t} ) {
			$perm{RESOLVED}=1;
			$perm{TRAPPED}=1;
		}
		if ( $opts{n} ) {
			$perm{RESOLVED}=1;
			$perm{NOSPAM}=1;
		}
		if ( $opts{u} ) { $perm{UNRESOLVED}=1; }

		if ( $T eq "RESOLVED" ) {
			if ( ! defined $perm{RESOLVED} ) {
				dbg("the keytype $T ($key) read from stdin is allowed to be imported from this source! skipping.");
				next;
			}
			if ( ! defined $db_resolved{$key} ) {
				dbg("inserting new resolved $key");
				$db_resolved{$key}=$F;
			}
		} elsif ( $T eq "UNRESOLVED" ) {
			if ( ! defined $perm{UNRESOLVED} ) {
				dbg("the keytype $T ($key) read from stdin is allowed to be imported from this source! skipping.");
				next;
			}
			if ( ( ! defined $db_unresolved{$key} ) and ( $F > $time ) ) {
				dbg("inserting new unresolved $key");
				$db_unresolved{"$key"}=$F;
				dbg("spamdb -a -t $key");
				# trap for some time
				system("spamdb -a -t $key");
			}
			elsif ( ! defined $db_unresolved{$key} ) {
				dbg("timestamp $F on $key is smaller than current time $time. skipping!");
				next;
			}
			elsif ( $db_unresolved{$key} < $F ) {
				dbg("saving new timestamp for $key");
				$db_unresolved{"$key"}=$F;
				dbg("spamdb -a -t $key");
				# trap for some time
				system("spamdb -a -t $key");
			}
		} elsif ( $T eq "NOSPAM" ) {
			if ( ! defined $perm{NOSPAM} ) {
				dbg("the keytype $T ($key) read from stdin is allowed to be imported from this source! skipping.");
				next;
			}
			if ( ( $P ne $F ) and ( $F !~ /^\d+$/ ) ) { 
				dbg("the data of $key is invalid ($F). skipping!");
				next;
			}
			if ( ! defined $db_nospam{$key} ) {
				dbg("inserting $key to database");
				my $trapped_key="$P";
				push(@white_helos, $P);
				delete $db_trapped{$trapped_key};
				$db_nospam{$key}=$F;
			}
		} elsif ( $T eq "TRAPPED" ) {
			if ( ! defined $perm{TRAPPED} ) {
				dbg("the keytype $T ($key) read from stdin is allowed to be imported from this source! skipping.");
				next;
			}
			if ( ( $P ne $F ) and ( $F !~ /^\d+$/ ) ) { 
				dbg("the data of $key is invalid ($F). skipping!");
				next:
			}
			if ( ! defined $db_trapped{$key} ) {
				dbg("inserting $key to database");
				my $nospam_key="$P";
				push(@trapped_helos, $P);
				delete $db_nospam{$nospam_key};
				$db_trapped{$key}=$F;
			}
		}
	}
}

if ( defined $opts{N} ) {
	dbg("helo $opts{N} is put in NOSPAM status as requested by the user (-N)");
	push(@white_helos, $opts{N});
	delete $db_trapped{"$opts{N}"};
	$db_nospam{"$opts{N}"}=$time;
}

dbg("whitelist helos");
foreach my $helo (@white_helos) {
	my @resolved_keys=sort grep {/$helo$/} keys %db_resolved;
	my @ipa;
	foreach my $k (@resolved_keys) {
		dbg("# $k");
		push(@ipa, ip_hash($db_resolved{$k}));
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
	delete $db_nospam{"$opts{T}"};
	$db_trapped{"$opts{T}"}=$time;
}

dbg("trapping helos");
foreach my $helo (@trapped_helos) {
	my @resolved_keys=sort grep {/$helo$/} keys %db_resolved;
	my @ipa;
	foreach my $k (@resolved_keys) {
		dbg("# $k");
		push(@ipa, ip_hash($db_resolved{$k}));
	}
	my %iph=@ipa;
	foreach my $addr (keys %iph) {
		dbg("spamdb -a -t $addr");
		system("spamdb -a -t $addr");
	}
}

dbg("trapping src");
my $traptime=$time+(60*60*24); # trap for 24 hours
foreach my $src (@trapped_src) {
	dbg("spamdb -a -t $src");
	system("spamdb -a -t $src");
	# trap for some time
	$db_unresolved{"$src"}=$traptime;
}
dbg("untrapping src to give them a try");
foreach my $key (keys %db_unresolved) {
	if ( $db_unresolved{$key} < $time ) {
		my $addr=substr($key,11);
		dbg("spamdb -d $addr");
		system("spamdb -d $addr 2> /dev/null");
		delete $db_unresolved{$key};
	}
}

dbg("expire old grey entrys ");
foreach my $key (keys %db_grey) {
	my (
		$first,
		$passed,
		$expire,
		$block,
		$pass
	)=split('\|', $db_grey{$key});
	if ( $time > $expire ) {
		dbg("expire grey:", $key, $time, $expire);
		delete $db_grey{$key};
	}
}
dbg("expire old helo entrys ");
foreach my $key (keys %db_expire) {
	if ( $time > $db_expire{$key} ) {
		dbg("expire helo expire:", $key, $time, $db_expire{$key});
		delete $db_expire{$key};
		dbg("expire helo pass:", $key, $time, $db_pass{$key});
		delete $db_pass{$key};
	}
}

if ( defined $opts{D} ) {
	my ($d, $P) = split('\|', $opts{D});
	$d=uc($d);
        dbg("deleting:", $T, $P);
	if ($d eq "GREY") {
		dbg("deleted:", $db_grey{$P});
		delete $db_grey{$P};
	} elsif ($d eq "PASS") {
		dbg("deleted:", $db_pass{$P});
		delete $db_pass{$P};
	} elsif ($d eq "EXPIRE") {
		dbg("deleted:", $db_expire{$P});
		delete $db_expire{$P};
	} elsif ($d eq "NOSPAM") {
		dbg("deleted:", $db_nospam{$P});
		delete $db_nospam{$P};
	} elsif ($d eq "TRAPPED") {
		dbg("deleted:", $db_trapped{$P});
		delete $db_trapped{$P};
	} elsif ($d eq "RESOLVED") {
		dbg("deleted:", $db_resolved{$P});
		delete $db_resolved{$P};
	} elsif ($d eq "UNRESOLVED") {
		dbg("deleted:", $db_unresolved{$P});
		delete $db_unresolved{$P};
	} else {
		die "The DB key $d is of unknown type stopping here\n";
	}
}

# do not dump out stuff if we import things
if ( ! defined $opts{i} ) {
	if ( defined $opts{t} ) {
		foreach my $key (sort keys %db_trapped) {
			# this helo is or was once whitelisted
			my $helo = $key;
			my @resolved_keys=sort grep {/$helo$/} keys %db_resolved;
			foreach my $k (@resolved_keys) {
				print "RESOLVED|$k|$db_resolved{$k}\n";
			}
			print "TRAPPED|$key|$db_trapped{$key}\n";
		}
	}

	if ( defined $opts{n} ) {
		foreach my $key (sort keys %db_nospam) {
			# this helo is or was once whitelisted
			my $helo = $key;
			my @resolved_keys=sort grep {/$helo$/} keys %db_resolved;
			foreach my $k (@resolved_keys) {
				print "RESOLVED|$k|$db_resolved{$k}\n";
			}
			print "NOSPAM|$key|$db_nospam{$key}\n";
		}
	}

	# print unresolved to stdout
	if ( defined $opts{u} ) {
		foreach my $key (sort keys %db_unresolved) {
			print "UNRESOLVED|$key|$db_unresolved{$key}\n";
		}
	}
}

if ( defined $opts{d} ) {
	foreach my $k (sort keys %db_grey) {
		my @l=split('\|', $db_grey{$k});
		$l[0]=hrtime($l[0]);
		$l[1]=hrtime($l[1]);
		$l[2]=hrtime($l[2]);
		print "GREY|".$k.": ".join('|', @l)."\n";
	}
	foreach my $k (sort keys %db_pass) {
		print "PASS|".$k.": ".hrtime($db_pass{$k})."\n";
	}
	foreach my $k (sort keys %db_expire) {
		print "EXPIRE|".$k.": ".hrtime($db_expire{$k})."\n";
	}
	foreach my $k (sort keys %db_nospam) {
		print "NOSPAM|".$k.": ".$db_nospam{$k}."\n";
	}
	foreach my $k (sort keys %db_trapped) {
		print "TRAPPED|".$k.": ".$db_trapped{$k}."\n";
	}
	foreach my $k (sort keys %db_resolved) {
		print "RESOLVED|".$k.": ".$db_resolved{$k}."\n";
	}
	foreach my $k (sort keys %db_unresolved) {
		print "UNRESOLVED|".$k.": ".hrtime($db_unresolved{$k})."\n";
	}
}

################################################################################
# close open files before exit
untie %db;
untie %db_grey;
untie %db_pass;
untie %db_expire;
untie %db_nospam;
untie %db_trapped;
untie %db_resolved;
untie %db_unresolved;
close GRL;
exit(0);
