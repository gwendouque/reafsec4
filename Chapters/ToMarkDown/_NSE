# NMAP NSE
##    -   Vulnerability Scanning with Nmap
        - -   Nmap Exploit Scripts
        - [*https://nmap.org/nsedoc/categories/exploit.html*](https://nmap.org/nsedoc/categories/exploit.html)
        - -   Nmap search through vulnerability scripts
        - `cd /usr/share/nmap/scripts/
        - ls -l \*vuln\*`
        - -   Nmap search through Nmap Scripts for a specific keyword
        - `ls /usr/share/nmap/scripts/\* | grep ftp`
        - -   Scan for vulnerable exploits with nmap
        - `nmap --script exploit -Pn $ip`
        - -   NMap Auth Scripts
        - [*https://nmap.org/nsedoc/categories/auth.html*](https://nmap.org/nsedoc/categories/auth.html)
        - -   Nmap Vuln Scanning
        - [*https://nmap.org/nsedoc/categories/vuln.html*](https://nmap.org/nsedoc/categories/vuln.html)
        - -   NMap DOS Scanning
        - `nmap --script dos -Pn $ip
        - NMap Execute DOS Attack
        - nmap --max-parallelism 750 -Pn --script http-slowloris --script-args
        - http-slowloris.runforever=true`
        - -   Scan for coldfusion web vulnerabilities
        - `nmap -v -p 80 --script=http-vuln-cve2010-2861 $ip`
        - -   Anonymous FTP dump with Nmap
        - `nmap -v -p 21 --script=ftp-anon.nse $ip-254`
        - -   SMB Security mode scan with Nmap
        - `nmap -v -p 21 --script=ftp-anon.nse $ip-254`

##    -   NMap Enumeration Script List:

###   -   NMap Discovery

            - [*https://nmap.org/nsedoc/categories/discovery.html*](https://nmap.org/nsedoc/categories/discovery.html)

###   -   Nmap port version detection MAXIMUM power

            - `nmap -vvv -A --reason --script="+(safe or default) and not broadcast" -p <port> <host>`
##  NSE Scripts

    - Scan using default safe scripts 	nmap -sV -sC 192.168.1.1
    - Get help for a script 	nmap --script-help=ssl-heartbleed
    - Scan using a specific NSE script 	nmap -sV -p 443 –script=ssl-heartbleed.nse 192.168.1.1
    - Scan with a set of scripts 	nmap -sV --script=smb* 192.168.1.1
    - According to my Nmap install there are currently 471 NSE scripts. The scripts are able to perform a wide range of security related testing and discovery functions. If you are serious about your network scanning you really should take the time to get familiar with some of them.
    - The option --script-help=$scriptname will display help for the individual scripts. To get an easy list of the installed scripts try locate nse | grep script.
    - You will notice I have used the -sV service detection parameter. Generally most NSE scripts will be more effective and you will get better coverage by including service detection.
##    A scan to search for DDOS reflection UDP services
        - Scan for UDP DDOS reflectors 	nmap –sU –A –PN –n –pU:19,53,123,161 –script=ntp-monlist,dns-recursion,snmp-sysdescr 192.168.1.0/24
        - UDP based DDOS reflection attacks are a common problem that network defenders come up against. This is a handy Nmap command that will scan a target list for systems with open UDP services that allow these attacks to take place. Full details of the command and the background can be found on the Sans Institute Blog where it was first posted.
##    HTTP Service Information
        - Gather page titles from HTTP services 	nmap --script=http-title 192.168.1.0/24
        - Get HTTP headers of web services 	nmap --script=http-headers 192.168.1.0/24
        - Find web apps from known paths 	nmap --script=http-enum 192.168.1.0/24
        - There are many HTTP information gathering scripts, here are a few that are simple but helpful when examining larger networks. Helps in quickly identifying what the HTTP service is that is running on the open port. Note the http-enum script is particularly noisy. It is similar to Nikto in that it will attempt to enumerate known paths of web applications and scripts. This will inevitably generated hundreds of 404 HTTP responses in the web server error and access logs.
##    Detect Heartbleed SSL Vulnerability
        - Heartbleed Testing 	nmap -sV -p 443 --script=ssl-heartbleed 192.168.1.0/24
        - Heartbleed detection is one of the available SSL scripts. It will detect the presence of the well known Heartbleed vulnerability in SSL services. Specify alternative ports to test SSL on mail and other protocols (Requires Nmap 6.46).
