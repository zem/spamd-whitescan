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

## how it works, from a users perspective 

whitescan.pl is started every few minutes from crontab (i am using 2 min atm)
it calls spamdb and reads its output, compares it with the information stored it its 
sdbm database in /var/db/whitescan and feeds back the white and trapped ip hosts to 
spamdb. 

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
     -n create a formatted <nospamd> table from this database 
     -t create a formatted <spamd> traplist table from this database 
     -p MINUTES set passtime in minutes, default 20 
     -D SOME_DB_KEY  deletes a key from the database
     -T SOME_HELO  sets a HELO Trap
     -N SOME_HELO  sets a HELO as nospam
```


