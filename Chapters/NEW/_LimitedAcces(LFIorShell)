# Gather information from files
## In case of LFI or unprivileged shell, gathering information could be very useful.
        - ** Mostly taken from `g0tmi1k Linux Privilege Escalation Blog <https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/>`_
## Operating System

- Code:

```
cat /etc/issue
cat /etc/*-release
cat /etc/lsb-release         # Debian based
cat /etc/redhat-release    # Redhat based
```

## /Proc Variables

- Code:
```
/proc/sched_debug      This is usually enabled on newer systems, such as RHEL 6.  It provides information as to what process is running on which cpu.  This can be handy to get a list of processes and their PID number.
/proc/mounts           Provides a list of mounted file systems.  Can be used to determine where other interesting files might be located
/proc/net/arp          Shows the ARP table.  This is one way to find out IP addresses for other internal servers.
/proc/net/route        Shows the routing table information.
/proc/net/tcp
/proc/net/udp          Provides a list of active connections.  Can be used to determine what ports are listening on the server
/proc/net/fib_trie     This is used for route caching.  This can also be used to determine local IPs, as well as gain a better understanding of the target's networking structure
/proc/version          Shows the kernel version.  This can be used to help determine the OS running and the last time it's been fully updated.
```

- Each process also has its own set of attributes. If we have the PID number and access to that process, then we can obtain some useful information about it, such as its environmental variables and any command line options that were run. Sometimes these include passwords. Linux also has a special proc directory called self which can be used to query information about the current process without having to know it’s PID.

```
            - /proc/[PID]/cmdline    Lists everything that was used to invoke the process. This sometimes contains useful paths to configuration files as well as usernames and passwords.
            - /proc/[PID]/environ    Lists all the environment variables that were set when the process was invoked.  This also sometimes contains useful paths to configuration files as well as usernames and passwords.
            - /proc/[PID]/cwd        Points to the current working directory of the process.  This may be useful if you don't know the absolute path to a configuration file.
            - /proc/[PID]/fd/[#]     Provides access to the file descriptors being used.  In some cases this can be used to read files that are opened by a process.

```
- The information about Proc variables has been taken from “Directory Traversal, File Inclusion, and The Proc File
```
            - https://blog.netspi.com/directory-traversal-file-inclusion-proc-file-system/
```


## Environment Variables
```
cat /etc/profile
cat /etc/bashrc
cat ~/.bash_profile
cat ~/.bashrc
cat ~/.bash_logout
```

## Configuration Files
```
- Apache Web Server : Helps in figuring out the DocumentRoot where does your webserver files are?
- /etc/apache2/apache2.conf
- /etc/apache2/sites-enabled/000-default
```
## User History

```
- ~/.bash_history
- ~/.nano_history
- ~/.atftp_history
- ~/.mysql_history
- ~/.php_history
- ~/.viminfo

```

## Private SSH Keys / SSH Configuration

```
- ~/.ssh/authorized_keys : specifies the SSH keys that can be used for logging into the user account
- ~/.ssh/identity.pub
- ~/.ssh/identity
- ~/.ssh/id_rsa.pub
- ~/.ssh/id_rsa
- ~/.ssh/id_dsa.pub
- ~/.ssh/id_dsa
- /etc/ssh/ssh_config  : OpenSSH SSH client configuration files
- /etc/ssh/sshd_config : OpenSSH SSH daemon configuration file

```
