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

tie(%db, 'SDBM_File', '/var/db/whitescan', O_RDWR|O_CREAT, 0600)
  or die "Couldn't tie SDBM file '/var/db/whitescan': $!; aborting";

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
	$grey_key="GREY|$src|$helo|$from|$to";
	$value="$first|$passed|$expire|$block|$pass";
	#$hrvalue=hrtime($first)."|".hrtime($passed)."|".hrtime($expire)."|$block|$pass";
	if ( defined $db{$grey_key} ) { 
		if ( $db{$grey_key} ne $value ){
			$db{$grey_key}=$value;
			print GRL "$grey_key|$value\n";
		}
		#dbg("grey entry already seen", $helo, $src, $from, $to);
		next; 
	} # we have already seen and processed this greylist entry
	$db{$grey_key}=$value;
	print GRL "$grey_key|$value\n";


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
			if (( $spf_identity eq "" ) and ( defined $db{"RESOLVED|$helo"} )) {
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
	my %iph=ip_hash($db{"RESOLVED|$helo"});
	foreach my $a (@addrs) { $iph{$a}=1; }
	$db{"RESOLVED|$helo"}=ip_string(%iph);
	dbg("stored resolved ips", $helo, keys %iph);

	$helo=strip_helo($helo);
	# $helo_key="HELO|".strip_helo($helo)."|$from|$to";
	$pass_key="PASS|$helo|$from|$to";
	$expire_key="EXPIRE|$helo|$from|$to";
	if ( ! defined $db{$pass_key} ) {
		dbg($pass_key, "is not yet in db");
		dbg("testing for NOSPAM|$helo");
		dbg("testing for TRAPPED|$helo");
		# Check for nospam keys
		# we do not register PASS or EXPIRE if the 
		# this thing is new so lets reg
		# $db{$helo_key}=1;
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
		} else {
			dbg("registering", $pass_key, "to db");
			dbg("registering", $expire_key, "to db");
			$db{$pass_key}=$passed;
			$db{$expire_key}=$expire;
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
if ( defined $opts{i} ) {
	while(<STDIN>) {
		chomp;
		my ($T, $P, @l) = split(/\|/);
		my $F=join('|', @l);
		my $key="$T|$P";

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
			if ( ! defined $db{$key} ) { 
				dbg("inserting new $key");
				$db{$key}=$F; 
			}
		} elsif ( $T eq "UNRESOLVED" ) {
			if ( ! defined $perm{UNRESOLVED} ) {
				dbg("the keytype $T ($key) read from stdin is allowed to be imported from this source! skipping.");
				next;
			}
			if ( ! defined $db{$key} ) { 
				dbg("inserting new $key");
				push(@trapped_src, $P);
			}
			elsif ( $F < $time ) { 
				dbg("timestamp $F on $key is smaller than current time $time. skipping!");
				next;
			}
			elsif ( $db{$key} < $F ) { 
				dbg("saving new timestamp for $key");
				push(@trapped_src, $P);
			}
		} elsif ( $T eq "NOSPAM" ) {
			if ( ! defined $perm{NOSPAM} ) {
				dbg("the keytype $T ($key) read from stdin is allowed to be imported from this source! skipping.");
				next;
			}
			if ( $P ne $F ) {  
				dbg("the data of $key is invalid ($F). skipping!");
				next;
			}
			if ( ! defined $db{$key} ) { 
				dbg("inserting $key to database");
				my $trapped_key="TRAPPED|$P";
				push(@white_helos, $F);
				delete $db{$trapped_key};
				$db{$key}=$F; 
			}
		} elsif ( $T eq "TRAPPED" ) {
			if ( ! defined $perm{TRAPPED} ) {
				dbg("the keytype $T ($key) read from stdin is allowed to be imported from this source! skipping.");
				next;
			}
			if ( $P ne $F ) {  
				dbg("the data of $key is invalid ($F). skipping!");
				next:
			}
			if ( ! defined $db{$key} ) { 
				dbg("inserting $key to database");
				my $nospam_key="NOSPAM|$P";
				push(@trapped_helos, $F);
				delete $db{$nospam_key};
				$db{$key}=$F; 
			}
		}
	}
}

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

dbg("trapping src");
my $traptime=$time+(60*60*24); # trap for 24 hours
foreach my $src (@trapped_src) {
	dbg("spamdb -a -t $src"); 
	system("spamdb -a -t $src");
	# trap for some time
	$db{"UNRESOLVED|$src"}=$traptime;
}
dbg("untrapping src to give them a try");
foreach my $key (grep {/^UNRESOLVED/} keys %db) {
	if ( $db{$key} < $time ) {
		my $addr=substr($key,11);
		dbg("spamdb -d $addr"); 
		system("spamdb -d $addr 2> /dev/null"); 
		delete $db{$key};
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

# do not dump out stuff if we import things 
if ( ! defined $opts{i} ) {
	if ( defined $opts{t} ) {
		foreach my $key (sort grep {/^TRAPPED/} keys %db) {
			# this helo is or was once whitelisted
			my $helo = $db{$key};
			my @resolved_keys=sort grep {/$helo$/} grep {/^RESOLVED/} keys %db;
			foreach my $k (@resolved_keys) { 
				print "$k|$db{$k}\n";
			}
			print "$key|$db{$key}\n";
		}
	}

	if ( defined $opts{n} ) {
		foreach my $key (sort grep {/^NOSPAM/} keys %db) {
			# this helo is or was once whitelisted
			my $helo = $db{$key};
			my @resolved_keys=sort grep {/$helo$/} grep {/^RESOLVED/} keys %db;
			foreach my $k (@resolved_keys) { 
				print "$k|$db{$k}\n";
			}
			print "$key|$db{$key}\n";
		}
	}

	# print unresolved to stdout 
	if ( defined $opts{u} ) {
		foreach my $key (sort grep {/^UNRESOLVED/} keys %db) {
			print "$key|$db{$key}\n";
		}
	}
}

if ( defined $opts{d} ) {
	foreach my $k (sort keys %db) { 
		if ( $k =~ /^UNRESOLVED/ ) {
			print $k.": ".hrtime($db{$k})."\n";
		} elsif ( $k =~ /^PASS/ ) {
			print $k.": ".hrtime($db{$k})."\n";
		} elsif ( $k =~ /^EXPIRE/ ) {
			print $k.": ".hrtime($db{$k})."\n";
		} elsif ( $k =~ /^GREY/ ) {
			my @l=split('\|', $db{$k});
			$l[0]=hrtime($l[0]);
			$l[1]=hrtime($l[1]);
			$l[2]=hrtime($l[2]);
			print $k.": ".join('|', @l)."\n";
		} else {
			print $k.": ".$db{$k}."\n";
		}
	}
} 

################################################################################
# close open files before exit 
untie %db;
close GRL;
exit(0);
