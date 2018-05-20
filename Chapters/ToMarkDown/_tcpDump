# USING TCPDUMP
   http://www.dankalia.com/tutor/01005/0100501019.htm
    - The tcpdump program is an extremely useful although little known tool that comes with most Linux distributions. Used to diagnose problems on the network, tcpdump is a console tool that monitors network packets and displays them to the screen. It is used to see packets coming in and out of any given network interface. In addition, it can be restricted to only view certain types of packets.
    - For example, tcpdump could be helpful if you are experiencing a Denial of Service (DoS) attack. You can tell tcpdump to view the Internet Control Message Protocol (ICMP) packets, which would, in turn, tell you if someone was giving you the "ping of death."
## You must be root to use tcpdump, so, as root, execute the following:
        - # tcpdump icmp -n -i eth0
## Now try pinging yourself from another machine, and you should see something like this:
        - 23:12:38.239111 10.0.5.15 > 10.0.5.10: icmp: echo request (DF)
        - 23:12:38.239177 10.0.5.10 > 10.0.5.15: icmp: echo reply
    - In the above example, tcpdump tells you the time the packet was received, the direction it was going, and what type of packet it is. The first line shows the echo request (ping) being sent from 10.0.5.15 to 10.0.5.10 (the local machine).
    - The second line is the reply from 10.0.5.10 to 10.0.5.15 (the remote machine).
