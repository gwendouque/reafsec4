#Exploits




```
cd /usr/share/exploitdb/
searchsploit <term1> <term2> <term3>
searchsploit sshd remote 1.2

Choose your exploit and copy it to a working location.
cp platforms/windows/remote/5751.pl /root/exploit.pl

```


### Headers



```
Some exploits may be written for compilation under Windows, while others for Linux.
You can identify the environment by inspecting the headers.

Linux - arpa/inet.h, fcntl.h, netdb.h, netinet/in.h, sys/sockt.h, sys/types.h, unistd.h

Windows - process.h, string.h, winbase.h, windows.h, winsock2.h
```



### Grep out Windows headers, to leave only Linux based exploits.



```
cat sploitlist.txt | grep -i 'exploit' | cut -d ' ' -f1 | xargs grep 'sys' | cut -d ':' -f1 | sort -u

```

