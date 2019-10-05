# spamd-whitescan
a whitelist scanner for openbsd's spamd

## openbsd's spamd and its missing features

Although openbsd's spamd is an outstanding mailfilter 
and spammers nightmare, it still lacks some feature. 
Most importantly:  

   'it can't detect smtp sender clouds!'

If an E-Mail is delivered from a cloud provider like google it is 
delivered in from different source e-mail addresses, so that one IP address
cant be detected from spamd. The typical workaround to circumvent that is
to write all IP addresses from that Provider to the nospamd table and 
circumvent spamd permanently for that ip range. Every provider missing in 
that List, can't deliver mail. 

whitescan.pl scans for those providers by using the helo which always 
points to a domain that points back to the sending IP address or the 
sender is lying about its identity and can be treated as a spammer. 

This documentation and the development of whitescan is in progress. 

## how it works

The first idea of whitescan is to check that a sending smtp client is actually not 
lying about its identity. It does that by checking if a clients HELO name resolves 
to the IP address it is coming from. 

It then checks if the sending domain has an SPF entry and if that entry allowes the 
client to send email for that sender domain. 

Any host that fails these first two checks is tarpitted for 24 hours (UNRESOLVED), it 
will fail the same test after 24 hours again unless the sender hat made a
config error, so no worries about that timing. 

Whitescan will then shorten the helo a bit. For example: out-7.smtp.github.com will 
be identified as smtp.github.com from now on.

whitescan then does the same logic as spamd does for single hosts. it tracks all encounters 
for that shortened hello.  When PASSTIME is reached, the first resend attemt makes 
spamd learn all ip addresses of all HELOS seen so far that end with the shortened helo 
(*.smtp.github.com in our example) as whitelisted addresses at once. 

Any new ip for that shortened HELO, is immidiately added to spamd's whitelist to keep 
waiting times short.

For HELOS that use big sender systems it is also possible to TRAP the domain manually and very permanently 
with -T or via a trapped export/import list that can be used to track HELOs sending out spam 
(very much like the nixspam or dns blocklists.)


## how it works, from a users perspective 

whitescan.pl is started every few minutes from crontab (i am using 2 min atm)
it calls spamdb and reads its output, compares it with the information stored it its 
sdbm database in /var/db/whitescan and feeds back the white and trapped ip hosts to 
spamdb. 

There is a logfile in /var/log/grey.log showing all undecided grey entrys. 

## whitescan.pl --help

```
whitelist.pl is a whitelist scanner for spamd
it can be used to whitelist hardly passing smtp hosts
like gmail or gmx by looking at the upperlevel part of 
their helo domains, remembering all the ips and whitelist 
them at once if PASSTIME is reached


PARAMETERS:
     -h this help 
     --help the very same help 
     -v be verbose on stderr eg. log what you are doing
     -d dump the database content for debugging 
     -H print all times ( -d and grey.log ) human readable
     -n create a formatted <nospamd> table from this database 
     -t create a formatted <spamd> traplist table from this database 
     -p MINUTES set passtime in minutes, default 20 
     -D SOME_DB_KEY  deletes a key from the database
     -T SOME_HELO  sets a HELO Trap
     -N SOME_HELO  sets a HELO as nospam
     -e EXPORT_DIR export trapped nospam and resolved data to this directory
     -i IMPORT_DIR import trapped nospam and resolved data from this directory
```

## IDEA
Stop processing if dns resolving does not work at all. 

