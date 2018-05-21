
# Metasploitable/SSH/Keys
##Obtaining Remote Access Using SSH Keys

The basic idea behind this type of exploit is to copy your SSH keys into the remote machine's list of authorized keys.
- It requires write access to the remote filesystem.

- On the attacker machine, the public key is located in
```
~/.ssh/id_rsa.pub.
```

- Using a remote shell on metasploitable, or by taking advantage of backdoors, or by mounting the remote filesystem using an exploit, gain write access to the victim's machine.
- Then copy the public key into

```
/root/.ssh/authorized_keys
```
, and you'll have passwordless root access.

If you have write access to a filesystem, this technique can turn that write access into remote shell access without cracking the root password.

Then you'll be able to log in like this:
```
 ssh root@10.0.0.27

Last login: Tue Mar 22 20:26:16 EDT 2016 from :0.0 on pts/0
Linux metasploitable 2.6.24-16-server #1 SMP Thu Apr 10 13:58:00 UTC 2008 i686
root@metasploitable:~#
```
