# PORT SCANNING
  # NMAP
       (Voor NSE zie Vuln. Scanning hoofdstuk)
##  Nmap Cheat Sheet

- Port Selection

```
- Scan Types
- Service and Operating System Detection
- Output formats
- NSE Scripting
- Find DDOS reflectors
- HTTP info gathering
- Heartbleed Detection
- IP Information Gathering
- Remote Scanning
- Additional Resources
```

###  Nmap Target Selection
```
                - Scan a single IP 	nmap 192.168.1.1
                - Scan a host 	nmap www.testhostname.com
                - Scan a range of IPs 	nmap 192.168.1.1-20
                - Scan a subnet 	nmap 192.168.1.0/24
                - Scan targets from a text file 	nmap -iL list-of-ips.txt
                - These are all default scans, which will scan 1000 TCP ports. Host discovery will take place.

```

###  Nmap Port Selection

```
                - Scan a single Port 	nmap -p 22 192.168.1.1
                - Scan a range of ports 	nmap -p 1-100 192.168.1.1
                - Scan 100 most common ports (Fast) 	nmap -F 192.168.1.1
                - Scan all 65535 ports 	nmap -p- 192.168.1.1
     ```
###    Nmap Port Scan types
```
                - Scan using TCP connect 	nmap -sT 192.168.1.1
                - Scan using TCP SYN scan (default) 	nmap -sS 192.168.1.1
                - Scan UDP ports 	nmap -sU -p 123,161,162 192.168.1.1
                - Scan selected ports - ignore discovery 	nmap -Pn -F 192.168.1.1
                - Privileged access is required to perform the default SYN scans. If privileges are insufficient a TCP connect scan will be used. A TCP connect requires a full TCP connection to be established and therefore is a slower scan. Ignoring discovery is often required as many firewalls or hosts will not respond to PING, so could be missed unless you select the -Pn parameter. Of course this can make scan times much longer as you could end up sending scan probes to hosts that are not there.
     ```
###    Service and OS Detection
```
                - Detect OS and Services 	nmap -A 192.168.1.1
                - Standard service detection 	nmap -sV 192.168.1.1
                - More aggressive Service Detection 	nmap -sV --version-intensity 5 192.168.1.1
                - Lighter banner grabbing detection 	nmap -sV --version-intensity 0 192.168.1.1
                - Service and OS detection rely on different methods to determine the operating system or service running on a particular port. The more aggressive service detection is often helpful if there are services running on unusual ports. On the other hand the lighter version of the service will be much faster as it does not really attempt to detect the service simply grabbing the banner of the open service.
                ```
###    Nmap Output Formats
```
                - Save default output to file 	nmap -oN outputfile.txt 192.168.1.1
                - Save results as XML 	nmap -oX outputfile.xml 192.168.1.1
                - Save results in a format for grep 	nmap -oG outputfile.txt 192.168.1.1
                - Save in all formats 	nmap -oA outputfile 192.168.1.1
                - The default format could also be saved to a file using a simple file redirect command > file. Using the -oN option allows the results to be saved but also can be monitored in the terminal as the scan is under way.
```
- NSE Scripts
               Zie vuln.scanning


###  IP Address information

```
                - Find Information about IP address 	nmap --script=asn-query,whois,ip-geolocation-maxmind 192.168.1.0/24
                - Gather information related to the IP address and netblock owner of the IP address. Uses ASN, whois and geoip location lookups. See the IP Tools for more information and similar IP address and DNS lookups.

                ```
###    Remote Scanning
```
                - Testing your network perimeter from an external perspective is key when you wish to get the most accurate results. By assessing your exposure from the attackers perspective you can validate firewall rule audits and understand exactly what is allowed into your network. This is the reason we offer a hosted or online version of the Nmap port scanner. To enable remote scanning easily and effectively because anyone who has played with shodan.io knows very well how badly people test their perimeter networks.
     ```
###  Nmap Ports Scan
```
            - 1)decoy- masqurade nmap -D RND:10 [target] (Generates a random number of decoys) 1)decoy- masqurade nmap -D RND:10 [target] (Generates a random number of decoys) 2)fargement
            - 3)data packed – like orginal one not scan packet
            - 4)use auxiliary/scanner/ip/ipidseq for find zombie ip in network to use them to scan — nmap -sI ip target 5)nmap –source-port 53 target


            - nmap -sS -sV -D IP1,IP2,IP3,IP4,IP5 -f –mtu=24 –data-length=1337 -T2 target ( Randomize scan form diff IP) nmap -Pn -T2 -sV –randomize-hosts IP1,IP2
            - nmap –script smb-check-vulns.nse -p445 target (using NSE scripts) nmap -sU -P0 -T Aggressive -p123 target (Aggresive Scan T1-T5) nmap -sA -PN -sN target
            - nmap -sS -sV -T5 -F -A -O target (version detection)
            - nmap -sU -v target (Udp)
            - nmap -sU -P0 (Udp)
            - nmap -sC 192.168.31.10-12 (all scan default)
 ```
## NC Scanning
```
        - nc -v -w 1 target -z 1-1000
        - for i in {101..102}; do nc -vv -n -w 1 192.168.56.$i 21-25 -z; done
```
##  Unicornscan
```
        - us -H -msf -Iv 192.168.56.101 -p 1-65535 us -H -mU -Iv 192.168.56.101 -p 1-65535
        - -H resolve hostnames during the reporting phase -m scan mode (sf - tcp, U - udp)
        - -Iv - verbose
        - Xprobe2 OS fingerprinting
        - xprobe2 -v -p tcp:80:open IP
```
    - —————————————————————————————————


# _Quick Reference on Port Scanning
###  Intro
            - This article is about basic types of port scanning.
###  Port States (taking from Nmap man page)
```
            - open
            - An application is actively accepting TCP connections, UDP datagrams or SCTP associations on this port.
            - closed
            - A closed port is accessible (it receives and responds to Nmap probe packets), but there is no application listening on it. They can be helpful in showing that a host is up on an IP address (host discovery, or ping scanning), and as part of OS detection. Because closed ports are reachable, it may be worth scanning later in case some open up. Administrators may want to consider blocking such ports with a firewall. Then they would appear in the filtered state, discussed next.
            - filtered
            - Nmap cannot determine whether the port is open because packet filtering prevents its probes from reaching the port. The filtering could be from a dedicated firewall device, router rules, or host-based firewall software. Sometimes they respond with ICMP error messages such as type 3 code 13 (destination unreachable: communication administratively prohibited), but filters that simply drop probes without responding are far more common.
            - unfiltered
            - The unfiltered state means that a port is accessible, but Nmap is unable to determine whether it is open or closed. Only the ACK scan, which is used to map firewall rulesets, classifies ports into this state. Scanning unfiltered ports with other scan types such as Window scan, SYN scan, or FIN scan, may help resolve whether the port is open.
            - open|filtered
            - Nmap places ports in this state when it is unable to determine whether a port is open or filtered. This occurs for scan types in which open ports give no response. The lack of response could also mean that a packet filter dropped the probe or any response it elicited. So Nmap does not know for sure whether the port is open or being filtered. The UDP, IP protocol, FIN, NULL, and Xmas scans classify ports this way.
            - closed|filtered
            - This state is used when Nmap is unable to determine whether a port is closed or filtered. It is only used for the IP ID idle scan.
 ```
###  TCP SYN scan (with Hping2)
```
            - Scanner --- SYN (Sequence Number Set to 1) ---> Target
            - Scanner <- SYN/ACK (Sequence Number Set 0 and Acknowledgment Set 0) - Target
            - Scanner --- RST (Sequence Number Set Again to 1) ---> Target (Only if host listens)
            - Note: Scanner Viciously Dropped The Connection.

            - Or

            - Scanner --- RST/ACK ---> Target (Not used by Hping2 connection termination pattern)
            - Note: Graciously Terminated connection? (both parties have ti exchange an ACK flag), see below.
            - Scanner --- FIN ---> Target
            - Scanner <--- FIN/ACK --- Target
            - Scanner --- ACK ---> Target 
            - Only a SYN packet is sent to the target port.If a SYN/ACK is received from the target port, we can deduce that it is in the LISTENING state. If a RST/ACK is received, it usually indicates that the port is not listening, but we can deduce that the host is up. A RST/ACK or RST can be sent by the system performing the port scan so that a full connection is never established (also known as half open connections).
            ```
###  Half Open Connections in SYN scans
```
            - A connection can be "half-open", in which case one side has terminated its end, but the other has not. The side that has terminated can no longer send any data into the connection, but the other side can. The terminating side should continue reading the data until the other side terminates as well (always based in RFC's).
            - Connection termination in port scanning?
            - The connection termination phase uses, at most, a four-way handshake, with each side of the connection terminating independently. When an endpoint wishes to stop its half of the connection, it transmits a FIN packet, which the other end acknowledges with an ACK. Therefore, a typical tear-down requires a pair of FIN and ACK segments from each TCP endpoint. After both FIN/ACK exchanges are concluded, the terminating side waits for a timeout before finally closing the connection, during which time the local port is unavailable for new connections; this prevents confusion due to delayed packets being delivered during subsequent connections.It is also possible to terminate the connection by a 3-way handshake, when host A sends a FIN and host B replies with a FIN & ACK (merely combines 2 steps into one) and host A replies with an ACK. This is perhaps the most common method.
```

###  TCP ACK scan (with Hping2)

```
            - Scanner - ACK (Sequence Number Set 0 and Acknowledgment Set 0)-> Target
            - Scanner <--- RST (Sequence Number Set Again to 1) ---> Target
            - Or
            - Scanner <--- Connection Timeout or Sent ICMP Error --- Target 
            - The ACK scan probe packet has only the ACK flag set (unless you use --scanflags with Nmap). When scanning unfiltered systems, open and closed ports will both return a RST packet. Nmap then labels them as unfiltered, meaning that they are reachable by the ACK packet, but whether they are open or closed is undetermined. Ports that don't respond, or send certain ICMP error messages back (type 3, code 1, 2, 3, 9, 10, or 13), are ussually labeled filtered by Nmap.
            ```
###  TCP Full Handshake or Connect scan (with Hping2)
```
            - Scanner --- SYN (Sequence Number Set to 0) ---> Target
            - Scanner <--- SYN/ACK (Sequence Number Set 0 and Acknowledgment Set 1) --- Target
            - Scanner --- ACK (Sequence Number Set 1 and Acknowledgment Set 1) ---> Target
            - Scanner --- FIN/ACK ---> Target
            - Scanner <--- ACK --- Target
            - Or
            - Scanner --- RST ---> Target (Nmap terminates the connection this way!)
            - Note: This type of scans might be logged from firewalls based always type and configuration of firewalls.
 ```
###  UDP scan (with Hping2)
```
            - Scanner --- UDP ---> Target
            - Scanner <--- ICMP error (for closed ports) --- Target
            - Scanner <--- Connection Timeout (for open or filtered ports) --- Target
            - When a UDP packet is sent to a port that is not open, the system will respond with an ICMP port unreachable message. Most UDP port scanners use this scanning method, and use the absence of a response to infer that a port is open. However, if a port is blocked by a firewall, this method will falsely report that the port is open.
            ```
###  TCP NULL scan (with Hping2)
```
            - Scanner --- NULL ---> Target (All flags is set to 0)
            - Scanner <--- RST --- Target
            - Or
            - Scanner <--- Timeout Connection --- Target (Target host is filtered from firewall that silently drops the
            - connection) 
            - TCP Null scan This technique turns off all fl ags. Based on RFC 793, the target system should send back an RST for all closed ports.
 ```
###  TCP FIN scan (with Hping2)
```
            - Scanner --- FIN ---> Target
            - Scanner <--- RST --- Target
            - Or
            - Scanner <--- Timeout Connection --- Target (Target host is filtered from firewall that silently drops the
            - connection)
            - TCP FIN scan This technique sends a FIN packet to the target port. Based on RFC 793 (http://ww.ietf.org/rfc/rfc0793.txt), the target system should send back an RST for all closed ports. This technique usually only works or used to worj on UNIXbased TCP/IP stacks.
            ```
###    TCP Xmas scan (with Hping2) 
            - Scanner --- FIN,URG,PUSH ---> Target
            - Scanner <--- RST --- Target (For all closed ports, drop connection; works in UNIXboxs)
            - Or
            - Scanner <--- Timeout Connection --- Target (Target host is filtered and silently drops the connection)
            - TCP Xmas Tree scan This technique sends a FIN, URG, and PUSH packet to the target port. Based on RFC 793, the target system should send back an RST for all closed ports.

            ```
###  TCP Window scan (with Hping2)
```
            - Scanner - ACK (Sequence Number Set 0 and Acknowledgment Set 0)-> Target 
            - Scanner <--- RST (Sequence Number Set Again to 1) ---> Target
            - Or
            - Scanner <--- Connection Timeout or Sent ICMP Error --- Target 
            - Window scan is exactly the same as ACK scan except that it exploits an implementation detail of certain systems to differentiate open ports from closed ones, rather than always printing unfiltered when a RST is returned. It does this by examining the TCP Window field of the RST packets returned. On some systems, open ports use a positive window size (even for RST packets) while closed ones have a zero window. So instead of always listing a port as unfiltered when it receives a RST back, Window scan lists the port as open or closed if the TCP Window value in that reset is positive or zero, respectively.
 ```
###  TCP Mainmon scan (with Hping2 used for BSD hosts)
```
            - Scanner --- FIN/ACK ---> Target
            - Scanner <--- RST (Possibly) --- Target
            - Or
            - Scanner <--- Timeout Connection --- Target (Target host is filtered and silently drops the connection)
            - The Maimon scan is named after its discoverer, Uriel Maimon. He described the technique in Phrack Magazine issue #49 (November 1996). Nmap, which included this technique, was released two issues later. This technique is exactly the same as NULL, FIN, and Xmas scans, except that the probe is FIN/ACK. According to RFC 793 (TCP), a RST packet should be generated in response to such a probe whether the port is open or closed. However, Uriel noticed that many BSD-derived systems simply drop the packet if the port is open.
 ```
###  TCP Idle Scan (using Nmap
```
            - Scanner --- SYN/ACK ---> Zombie
            - Scanner <--- RST with IP ID = 1 --- Zombie
            - Scanner --- Forged from zombie SYN ---> Target
            - Then when open port:
            - Target --- SYN/ACK ---> Zombie
            - Target <--- RST IP ID = 2 --- Zombie
            - Scanner --- SYN/ACK ---> Zombie
            - Scanner <--- RST IP ID = 3 --- Zombie 
            - Or when closed or filtered port:
            - Target --- Timeout  or RST ---> Zombie (With timeout or RST no ID is increased)
            - Scanner --- SYN/ACK ---> Zombie
            - Scanner <--- RST IP ID = 2 --- Zombie
            - Fundamentally, an idle scan consists of three steps that are repeated for each port:
            - 	1.	Probe the zombie's IP ID and record it. 
            - 	2.	Forge a SYN packet from the zombie and send it to the desired port on the target. Depending on the port state, the target's reaction may or may not cause the zombie's IP ID to be incremented. 
            - 	3.	Probe the zombie's IP ID again. The target port state is then determined by comparing this new IP ID with the one recorded in step 1. 
 ```
###  References:
```
            - http://www.pcvr.nl/tcpip/udp_user.htm
            - http://www.techrepublic.com/article/exploring-the-anatomy-of-a-data-packet/1041907
            - http://www.freesoft.org/CIE/Course/Section3/7.htm
 ```
