[![SnertSoft: We Serve Your Server](Img/logo-300x74.png)](http://software.snert.com/)

milter-gris  
===========

Copyright 2004, 2024 by Anthony Howe.  All rights reserved.

« We are Grey.  We stand between the darkness and the light. »  
   -- Delenn, All Alone in the Night, Babylon 5

WARNING
-------

THIS IS MAIL FILTERING SOFTWARE AND WILL BLOCK MAIL THAT FAILS TO PASS A GIVEN SET OF TESTS.  SNERTSOFT AND THE AUTHOR DO NOT ACCEPT ANY RESPONSIBLITY FOR MAIL REJECTED OR POSSIBLE LOSS OF BUSINESSS THROUGH THE USE OF THIS SOFTWARE.  BY INSTALLING THIS SOFTWARE THE CLIENT UNDERSTANDS AND ACCEPTS THE RISKS INVOLVED.


Description
-----------

« Gris » is French for grey and this is a variation of the grey-listing concept as originally outlined in [The Next Step in the Spam Control War: Greylisting](http://projects.puremagic.com/greylisting/).

Basically, grey listing keeps track of tuples consisting of the connecting IP, sender's envelope, and recipient's envelope.  If a tuple, does not exist in the cache, then a new entry is added and kept until it expires and the message is temporarily rejected.

A legitimate server, when temporarily rejected, is expected to queue the message and retry sending it sometime in the near future.  The temporary reject policy remains in force until the temporary block period has elapsed, at which point the message will be allowed to be delivered until the cache entry expires.

There is also support for auto white listing of expected replies.  If a connection, sender, or recipient is white listed in the Sendmail access.db, then any mail sent generates an auto white list entry for each recipient that might reply and also each recipient's domain for DSN messages.  Normally a site will white list their local network and/or local users to send without grey-listing and with auto white listing, replies or DSN responses to those messages will by-pass grey-listing too.

milter-gris allows for fine grained control over how SMTP authenticated messages are treated.  They can be globally and/or selectively white, black, or grey listed.  See the milter-gris-auth: tag below.

Additional information can be found in [RFC 6647](https://datatracker.ietf.org/doc/html/rfc6647). 


Usage
-----

        milter-gris [options ...] [arguments ...]

Options can be expressed in four different ways.  Boolean options are expressed as `+option` or `-option` to turn the option on or off respectively.  Options that required a value are expressed as `option=value` or `option+=value` for appending to a value list.  Note that the `+option` and `-option` syntax are equivalent to `option=1` and `option=0` respectively.  Option names are case insensitive.

Some options, like `+help` or `-help`, are treated as immediate actions or commands.  Unknown options are ignored.  The first command-line argument is that which does not adhere to the above option syntax.  The special command-line argument `--` can be used to explicitly signal an end to the list of options.

The default options, as shown below, can be altered by specifying them on the command-line or within an option file, which simply contains command-line options one or more per line and/or on multiple lines.  Comments are allowed and are denoted by a line starting with a hash (#) character.  If the `file=` option is defined and not empty, then it is parsed first followed by the command-line options.

Note that there may be additional options that are listed in the option summary given by `+help` or `-help` that are not described here.

- - -
### +accept-null-sender

Do not grey-list the null address used for DSN and MDN messages.  Normally bounce messages are grey listed like any other mail. 

- - -
### access-db=/etc/mail/access.db

The type and location of the read-only access key-value map.  It provides a centralised means to black and white list hosts, domains, mail addresses, etc.  The following methods are supported:

        text!/path/map.txt                      R/O text file, memory hash
        /path/map.db                            Berkeley DB hash format
        db!/path/map.db                         Berkeley DB hash format
        db!btree!/path/map.db                   Berkeley DB btree format
        sql!/path/database                      An SQLite3 database
        socketmap!host:port                     Sendmail style socket-map
        socketmap!/path/local/socket            Sendmail style socket-map
        socketmap!123.45.67.89:port             Sendmail style socket-map
        socketmap![2001:0DB8::1234]:port        Sendmail style socket-map

If `:port` is omitted, the default is `7953`.

The `access-db` contains key-value pairs.  Lookups are performed from most to least specific, stopping on the first entry found.  Keys are case-insensitive.

An IPv4 lookup is repeated several times reducing the IP address by one octet from right to left until a match is found.

        tag:192.0.2.9
        tag:192.0.2
        tag:192.0
        tag:192

An IPv6 lookup is repeated several times reducing the IP address by one 16-bit word from right to left until a match is found.

        tag:2001:0DB8:0:0:0:0:1234:5678
        tag:2001:0DB8:0:0:0:0:1234
        tag:2001:0DB8:0:0:0:0
        tag:2001:0DB8:0:0:0
        tag:2001:0DB8:0:0
        tag:2001:0DB8:0:0
        tag:2001:0DB8:0
        tag:2001:0DB8
        tag:2001

A domain lookup is repeated several times reducing the domain by one label from left to right until a match is found.

        tag:[ipv6:2001:0DB8::1234:5678]
        tag:[192.0.2.9]
        tag:sub.domain.tld
        tag:domain.tld
        tag:tld
        tag:

An email lookup is similar to a domain lookup, the exact address is first tried, then the address's domain, and finally the local part of the address.

        tag:account@sub.domain.tld
        tag:sub.domain.tld
        tag:domain.tld
        tag:tld
        tag:account@
        tag:

If a key is found and is a milter specific tag (ie. `milter-gris-Connect`, `milter-gris-To`), then the value is processed as a pattern list and the result returned.  The Sendmail variants cannot have a pattern list.  A pattern list is a whitespace separated list of _pattern-action_ pairs followed by an optional default _action_.  The supported patterns are:

        [network/cidr]action            Classless Inter-Domain Routing
        !pattern!action                 Simple fast text matching.
        /regex/action                   POSIX Extended Regular Expressions

The CIDR will only ever match for IP address related lookups.

A `!pattern!` uses an astrisk (\*) for a wildcard, scanning over zero or more characters; a question-mark (?) matches any single character; a backslash followed by any character treats it as a literal (it loses any special meaning).

        !abc!           exact match for 'abc'
        !abc*!          match 'abc' at start of string
        !*abc!          match 'abc' at the end of string
        !abc*def!       match 'abc' at the start and match 'def' at the end, maybe with stuff in between.
        !*abc*def*!     find 'abc', then find 'def'

For black-white lookups, the following actions are recognised: `OK` or `RELAY` (allow), `REJECT` or `ERROR` (deny), `DISCARD` (accept & discard), `SKIP` or `DUNNO` (stop lookup, no result), and `NEXT` (opposite of `SKIP`, resume lookup).  Its possible to specify an empty action after a pattern, which is treated like `SKIP` returning an undefined result.  Other options may specify other actions.

Below is a list of supported tags.  Other options may specify additional tags.

        milter-gris-Connect:client-ip           value           § Can be a pattern list.
        milter-gris-Connect:[client-ip]         value           § Can be a pattern list.
        milter-gris-Connect:client-domain       value           § Can be a pattern list.
        milter-gris-Connect:                    value           § Can be a pattern list.
        Connect:client-ip                       value
        Connect:[client-ip]                     value
        Connect:client-domain                   value

All mail sent by a connecting _client-ip_, unresolved _client-ip_ address or IP addresses that resolve to a _client-domain_ are black or white-listed.  These allows you to white-list your network for mail sent internally and off-site, or connections from outside networks.  *Note that Sendmail also has special semantics for `Connect:` and untagged forms.*

        milter-gris-Auth:auth_authen            value           § Can be a pattern list.
        milter-gris-Auth:                       value           § Can be a pattern list.

All mail from the authenticated sender, as given by sendmail's `{auth_authen}` macro, is black or white-listed.  The string searched by the pattern list will be the sender-address.  The empty form of `milter-gris-Auth:` allows for a milter specific default only when `{auth_authen}` is defined.

        milter-gris-From:sender-address         value           § Can be a pattern list.
        milter-gris-From:sender-domain          value           § Can be a pattern list.
        milter-gris-From:sender@                value           § Can be a pattern list.
        milter-gris-From:                       value           § Can be a pattern list.
        From:sender-address                     value
        From:sender-domain                      value
        From:sender@                            value

All mail from the _sender-address_, _sender-domain_, or that begins with _sender_ is black or white-listed.  In the case of a _+detailed_ email address, the left hand side of the _+detail_ is used for the _sender@_ lookup.  *Note that Sendmail also has special semantics for From: and untagged forms.*

        milter-gris-To:recipient-address        value           § Can be a pattern list.
        milter-gris-To:recipient-domain         value           § Can be a pattern list.
        milter-gris-To:recipient@               value           § Can be a pattern list.
        milter-gris-To:                         value           § Can be a pattern list.
        Spam:recipient-address                  value           (FRIEND or HATER are recognised)
        Spam:recipient-domain                   value           (FRIEND or HATER are recognised)
        Spam:recipient@                         value           (FRIEND or HATER are recognised)
        To:recipient-address                    value
        To:recipient-domain                     value
        To:recipient@                           value

All mail to the _recipient-address_, _recipient-domain_, or that begins with _recipient_ is black or white-listed.  In the case of a _+detailed_ email address, the left hand side of the _+detail_ is used for the _recipient@_ lookup.  *Note that Sendmail also has special semantics for `Spam:`, `To:`, and untagged forms.*

The `milter-gris-Connect:` and `milter-gris-To:` tags provide a milter specific means to override the Sendmail variants.  For example, you normally white list your local network through any and all milters, but on the odd occasion you might want to actually scan mail from inside going out, without removing the `Connect:` tag that allows Sendmail to relay for your network or white listing for other milters.  So for example if you have Sendmail tags like:

        To:mx.example.com                       RELAY

You might have to add milter specific overrides in order to make sure the mail still gets filtered:

        To:mx.example.com                       RELAY
        milter-gris-To:mx.example.com           SKIP

Some additional examples:

        milter-gris-Connect:80.94              [80.94.96.0/20]OK REJECT

Accept connections from the netblock 80.94.96.0/20 (80.94.96.0 through to 80.94.111.255) and rejecting anything else in 80.94.0.0/16.

        milter-gris-Connect:192.0.2            /^192\.0\.2\.8[0-9]/OK REJECT

Accept connections from 192.0.2.80 through to 192.0.2.89, reject everything else in 192.0.2.0/24.

        milter-gris-To:example.com             /^john@.+/OK /^fred\+.*@.*/OK REJECT

Accept mail to <john@example.com> and <fred@example.com> when fred's address contains a plus-detail in the address.  Reject everything else to example.com.

        milter-gris-To:example.net             !*+*@*!REJECT !*.smith@*!REJECT /^[0-9\].*/REJECT

Reject mail to example.net using a plus-detail address or to any user who's last name is "smith" or addresses starting with a digit.  No default given, so B/W processing would continue.

Normally when the _access.db_ lookup matches a milter tag, then the _value_ pattern list is processed and there are no further _access.db_ lookups.  The `NEXT` action allows the _access.db_ lookups to resume and is effectively the opposite of `SKIP`.  Consider the following examples:

        milter-gris-To:com                     /@com/REJECT  NEXT
        To:com                                 OK

Reject mail to places like _compaq.com_ or _com.com_ if the pattern matches, but resume the _access.db_ lookups otherwise.

        milter-gris-To:aol.com                 /^[a-zA-Z0-9!#$&'*+=?^_`{|}~.-]{3,16}@aol.com$/NEXT REJECT
        To:fred@aol.com                        OK

AOL local parts are between 3 and 16 characters long and can contain dots and RFC 2822 atext characters except `%` and `/`.  The `NEXT` used above allows one simple regex to validate the format of the address and resume lookups of white listed and/or black listed addresses.


- - -
### best-guess-txt=

If the initial SPF test does not yield a Pass for any reason, then we check this "best guess" TXT record (eg. `v=spf1 a/24 mx/24 ptr`) to see if it yields a Pass result.  If the best guess passes, then the message is accepted, else the original SPF result is used.  This option is disabled by default.


- - -
### block-time=600

The amount of time in seconds that a message corresponding to the connecting IP, sender, and recipient tuple will be temporarily blocked. This value must be less than the cache-accept-ttl option.  A value between 10 to 30 minutes is suggested as reasonable. 


- - -
### block-time-static=-1

If the client connection resolves (ie. has a reverse DNS PTR record) and appears to be from a static IP address, then this value in seconds is used instead of the block-time value.  The value can be 0 to pass through immediately without grey listing.  The value must be less than equal to the block-time.  This option is disabled with -1. 


- - -
### grey-list-key=ip,mail,rcpt 

A comma separated list of what items are used for the grey-list key.  While many combinations are possible, only some will be of particular interest, like `mail,rcpt` in case you sit behind a mail filtering service like Postini.  However, some system administrators might like to experiment with other variations and its recommended that you use at least two items.

        all     All possible bits.
        ip      The connection client IP address.
        helo    The HELO/EHLO argument.
        mail    The MAIL argument.
        rcpt    The current RCPT argument.
        

- - -
### cache-accept-ttl=ttl

This is the time-to-live in seconds for accepted and auto white list entries stored in the cache. 


- - -
### cache-file=/var/db/milter-limit.db

The file path used for BDB or flatfile cache types. 


- - -
### cache-gc-frequency=250

This option specifies the cache garbage collection frequency, which is based on the number of SMTP connections (not messages) handled by the milter.  Every N connections, the cache is traversed to remove expired entries. 


- - -
### cache-temp-fail-ttl=90000

This is the time-to-live in seconds for temporary fail entries stored in the cache. 


- - -
### cache-type=bdb

The cache type can be one of: `bdb`, `flatfile`, `hash`. 


- - -
### +daemon

Start as a background daemon or foreground application.


- - -
### file=/etc/mail/milter-gris.cf

Read the option file before command line options.  This option is set by default.  To disable the use of an option file, simply say `file=''`.


- - -
### -help or +help

Write the option summary to standard output and exit.  The output is suitable for use as an option file.


- - -
### milter-socket=unix:/var/run/milter/milter-gris.socket

A socket specifier used to communicate between Sendmail and `milter-gris`.  Typically a unix named socket or a host:port.  This value must match the value specified for the `INPUT_MAIL_FILTER()` macro in the sendmail.mc file.  The accepted syntax is:

        {unix|local}:/path/to/file              A named pipe. (default)
        inet:port@{hostname|ip-address}         An IPV4 socket.
        inet6:port@{hostname|ip-address}        An IPV6 socket.


- - -
### milter-timeout=7210

The sendmail/milter I/O timeout in seconds.


- - -
### pid-file=/var/run/milter/milter-gris.pid

The file path of where to save the process-id.


- - -
### -quit or +quit

Quit an already running instance of the milter and exit.  This is equivalent to:

        kill -QUIT `cat /var/run/milter/milter-gris.pid`.

- - -
### -restart or +restart

Terminate an already running instance of the milter before starting.


- - -
### run-group=milter

The process runtime group name to be used when started by root.

- - -
### run-user=milter

The process runtime user name to be used when started by root.


- - -
### verbose=info

A comma separated list of how much detail to write to the mail log.  Those mark with `§` have meaning for this milter.

        §  all          All messages
        §  0            Log nothing.
        §  info         General info messages. (default)
        §  trace        Trace progress through the milter.
        §  parse        Details from parsing addresses or special strings.
           debug        Lots of debug messages.
           dialog       I/O from Communications dialog
           state        State transitions of message body scanner.
           dns          Trace & debug of DNS operations
        §  cache        Cache get/put/gc operations.
        §  database     Sendmail database lookups.
           socket-fd    socket open & close calls
           socket-all   All socket operations & I/O
        §  libmilter    libmilter engine diagnostics


- - -
### work-dir=/var/tmp

The working directory of the process.  Normally serves no purpose unless the kernel option that permits daemon process core dumps is set.


SMTP Responses
--------------

This is the list of possible SMTP responses.

* 553 5.1.0 imbalanced angle brackets in path  
  The path given for a `MAIL` or `RCPT` command is missing a closing angle bracket

* 553 5.1.0 address does not conform to RFC 2821 syntax  
  The address is missing the angle brackets, `<` and `>`, as required by the RFC grammar.

* 553 5.1.0 local-part too long  
  The stuff before the `@` is too long.

* 553 5.1.[37] invalid local part  
  The stuff before the `@` sign contains unacceptable characters.

* 553 5.1.0 domain name too long  
  The stuff after the `@` is too long.

* 553 5.1.7 address incomplete  
  Expecting a domain.tld after the `@` sign and found none.

* 553 5.1.[37] invalid domain name  
  The domain after the `@` sign contains unacceptable characters.

* 450 4.7.1 try again later  
  The response issued during the initial temporary block period.


Build & Install
---------------

* Install `SQLite` from a package if desired.  Prior to [LibSnert's](https://github.com/SirWumpus/libsnert) availability on GitHub, the old `libsnert` tarballs included SQLite, but the GitHub [libsnert](https://github.com/SirWumpus/libsnert) repository does not, so it needs to be installed separately.   `milter-gris` does not require it, but other milters that need a cache will.

* If you have never built a milter for Sendmail, then please make sure that you build and install `libmilter` (or install a pre-built package), which is _not_ built by default when you build Sendmail.  Please read the `libmilter` documentation.  Briefly, it should be something like this:

        cd (path to)/sendmail-8.13.6/libmilter
        sh Build -c install

* [Build LibSnert](https://github.com/SirWumpus/libsnert#configuration--build) first, do *not* disable `sqlite3` support; it should find the pre-installed version of SQLite if any.

* Building `milter-gris` should be:

        cd com/snert/src
        git clone https://github.com/SirWumpus/milter-gris.git
        cd milter-gris
        ./configure --help
        ./configure
        make
        sudo make install

* An example `/usr/local/share/examples/milter-gris/milter-gris.mc` is supplied.  This file should be reviewed and the necessary elements inserted into your Sendmail `.mc` file and `sendmail.cf` rebuilt.  Please note the comments on the general milter flags.

* Once installed and configured, start `milter-gris` and then restart Sendmail.  An example startup script is provided in `/usr/local/share/examples/milter-gris/milter-gris.sh`.


Notes
-----

* The minimum desired file ownership and permissions are as follows for a typical Linux system.  For FreeBSD, NetBSD, and OpenBSD the binary and cache locations may differ, but have the same permissions.  Process user `milter` is primary member of group `milter` and secondary member of group `smmsp`.  Note that the milter should be started as `root`, so that it can create a _.pid file_ and _.socket file_ in `/var/run`; after which it will switch process ownership to `milter:milter` before starting the accept socket thread.

        /etc/mail/                              root:smmsp      0750 drwxr-x---
        /etc/mail/access.db                     root:smmsp      0640 -rw-r-----
        /etc/mail/sendmail.cf                   root:smmsp      0640 -rw-r-----
        /etc/mail/milter-gris.cf                root:root       0644 -rw-r--r--
        /var/run/milter/milter-gris.pid         milter:milter   0644 -rw-r--r--
        /var/run/milter/milter-gris.socket      milter:milter   0644 srw-r--r--
        /var/db/milter-gris                     milter:milter   0644 -rw-r--r-- (*BSD)
        /var/cache/milter-gris                  milter:milter   0644 -rw-r--r-- (linux)
        /usr/local/libexec/milter-gris          root:milter     0550 -r-xr-x---
