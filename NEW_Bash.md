# *******BASH*******
##   Shell Commands and Tricks
    - nb more:https://github.com/bt3gl/My-Gray-Hacker-Resources/tree/master/Linux_Hacking
###  Reading Files
####  cat
Prints the content of a file in the terminal:
                       - cat <FILENAME>
####  tac
Prints the inverse of the content of a file in the terminal (starting from the bottom):
                       - tac <FILENAME>
####  less and more
Both print the content of a file, but adding page control:
                       - less <FILENAME>
                       - more <FILENAME>
####  head and tail
To read 20 lines from the begin:
                       - head -20 <FILENAME>
To read 20 lines from the bottom:
                       - tail -10 <FILENAME>
####  nl
To print (cat) a file with line numbers:
                       - nl <FILENAME>
####  tee
To save the output of a program and see it as well:
                       - <PROGRAM> | tee -a <FILENAME>
####  wc
To print the length and number of lines of a file:
                       - wc <FILENAME>
----------------------------------------------------------

###  Modifying Files
####  true
To make a file empty:
                       - true > <FILENAME>
####  tr
tr takes a pair of strings as arguments and replaces, in its input, every letter that occurs in the first string by the corresponding characters in the second string. For example, to make everything lowercase:
                       - tr A-Z a-z
To put every word in a line by replacing spaces with newlines:
                       - tr -s ' ' '\n'
To combine multiple lines into a single line:
                       - tr -d '\n'
tr doesn't accept the names of files to act upon, so we can pipe it with cat to take input file arguments (same effect as $ <PROGRAM> < <FILENAME>):
                       - cat "$@" | tr
####  sort
Sort the contents of text files. The flag -r sort backwards, and the flag -n selects numeric sort order (for example, without it, 2 comes after 1000):
                       - sort -rn <FILENAME>
To output a frequency count (histogram):
                       - sort <FILENAME> | uniq -c | sort -rn
To chose random lines from a file:
                       - sort -R  <FILENAME> | head -10
To combine multiple files into one sorted file:
                       - sort -m <FILENAME>
####  uniq

uniq remove adjacent duplicate lines. The flag -c can include a count:
```
                   - uniq -c <FILENAME>
```
To output only duplicate lines:
```

        - $ uniq -d <FILENAME>
        ```
####  cut
cut selects particular fields (columns) from a structured text files (or particular characters from each line of any text file). The flag -d specifies what delimiter should be used to divide columns (default is tab), the flag -f specifies which field or fields to print and in what order:

```
                       - cut -d ' ' -f 2 <FILENAME>
```

The flag -c specifies a range of characters to output, so -c1-2 means to output only the first two characters of each line:
                       - cut -c1-2 <FILENAME>
####  join
join combines multiple file by common delimited fields:
```
                       - join <FILENAME1> <FILENAME2>
```
----------------------------------------------------------

###  Listing or Searching for Files. #NB
####  ls
  ls lists directory and files. Useful flags are -l to list the permissions of each file in the directory and -a to include the dot-files:
         - ls -la
  To list files sorted by size:
         - ls -lrS
  To list the names of the 10 most recently modified files ending with .txt:
  ```
         - ls -rt *.txt | tail -10
```
####  tree
  The tree command lists contents of directories in a tree-like format.
        - find
           To find files in a directory:
####  which
           To find binaries in PATH variables:

         - which ls
####  whereis
To find any file in any directory:
         - whereis <FILENAME>
####  locate
To find files by name (using database):
         - locate <FILENAME>
####  test
           To test if a a file exist:
         - test -f <FILENAME>
###  Searching inside Files
####  diff and diff3
  diff can be used to compare files and directories. Useful flags include: -c to list differences, -r to recursively compare subdirectories, -i to ignore case, and -w to ignore spaces and tabs.
  You can compare three files at once using diff3, which uses one file as the reference basis for the other two.
####  file
           The command file shows the real nature of a file:
$ file requirements.txt
                requirements.txt: ASCII text
####  grep
           grep finds matches for a particular search pattern. The flag -l lists the files that contain matches, the flag -i makes the search case insensitive, and the flag -r searches all the files in a directory and subdirectory:
         - grep -lir <PATTERN> <FILENAME>
For example, to remove lines that are not equal to a word:
                       - grep -xv <WORD> <FILENAME>
###  Creating Files and Directories
####  mkdir
  mkdir creates a directory. An useful flag is -p which creates the entire path of directories (in case they don't exist):
         - mkdir -p <DIRNAME>
####  cp
  Copying directory trees is done with cp. The flag -a is used to preserve all metadata:
         - cp -a <ORIGIN> <DEST>
  Interestingly, commands enclosed in $() can be run and then the output of the commands is substituted for the clause and can be used as a part of another command line:
  ```
         - cp $(ls -rt *.txt | tail -10) <DEST>
```         
####  pushd and popd
  The pushd command saves the current working directory in memory so it can be returned to at any time, optionally changing to a new directory:
         - pushd ~/Desktop/
  The popd command returns to the path at the top of the directory stack.
####  ln
  Files can be linked with different names with the ln. To create a symbolic (soft) link you can use the flag -s:
         - ln -s <TARGET> <LINKNAME>
####  dd
           dd is used for disk-to-disk copies, being useful for making copies of raw disk space.
For example, to back up your Master Boot Record (MBR):
                       - dd if=/dev/sda of=sda.mbr bs=512 count=1
To use dd to make a copy of one disk onto another:
                       - dd if=/dev/sda of=/dev/sdb
###  Network and Admin
####  du
  du shows how much disk space is used for each file:
         - du -sha
  To see this information sorted and only the 10 largest files:
         - du -a | sort -rn | head -10
  To determine which subdirectories are taking a lot of disk space:
         - du --max-depth=1  | sort -k1 -rn
####  df
  df shows how much disk space is used on each mounted filesystem. It displays five columns for each filesystem: the name, the size, how much is used, how much is available, percentage of use, and where it is mounted. Note the values won't add up because Unix filesystems have reserved storage blogs which only the root user can write to.
         - df -h
####  ifconfig
  You can check and configure your network interface with:
         - ifconfig
  In general, you will see the following devices when you issue ifconfig:
  eth0: shows the Ethernet card with information such as: hardware (MAC) address, IP address, and the network mask.
  lo: loopback address or localhost.
  ifconfig is supposed to be deprecated. See my short guide on ip-netns.
####  dhclient
  Linux has a DHCP server that runs a daemon called dhcpd, assigning IP address to all the systems on the subnet (it also keeps logs files):
         - dhclient
####  dig
  dig is a DNS lookup utility (similar to dnslookup in Windows).
####  netstat
  netstat prints the network connections, routing tables, interface statistics, among others. Useful flags are -t for TCP, -u for UDP, -l for listening, -p for program, -n for numeric. For example:
         - netstat -tulpn
####  netcat, telnet and ssh
To connect to a host server, you can use netcat (nc) and telnet. To connect under an encrypted session, ssh is used. For example, to send a string to a host at port 3000:
         - echo 4wcYUJFw0k0XLShlDzztnTBHiqxU3b3e | nc localhost 3000
  To telnet to localhost at port 3000:
         - telnet localhost 3000
####  lsof
lsof lists open files (remember that everything is considered a file in Linux):
         - lsof <STRING>
To see open TCP ports:
                       - lsof | grep TCP
To see IPv4 port(s):
                       - lsof -Pnl +M -i4
To see IPv6 listing port(s):
                       - lsof -Pnl +M -i6
###  Environment Variables
       Environment variables are several dynamic named values in the operating system that can be used in running processes.
####  set and env
You can see the environment variables and configuration in your system with:
                       - set
or
                       - env
####  export and echo
The value of an environment variable can be changed with:
                       - export VAR=<value>
The value can be checked with:
                       - echo $VAR
The PATH (search path) is the list of directories that the shell look in to try to find a particular command. For example, when you type ls it will look at /bin/ls. The path is stored in the variable PATH, which is a list of directory names separated by colons and it's coded inside ./bashrc. To export a new path you can do:
                       - export PATH=$PATH:/<DIRECTORY>
####  Variable in Scripts
  Inside a running shell script, there are pseudo-environment variables that are called with $1, $2, etc., for individual arguments that were passed to the script when it was run. In addition, $0 is the name of the script and $@ is for the list of all the command-line arguments.
###  Short Summary
       Useful Command Line
####  Searching
```
  grep word f1
  sort | uniq -c
  diff f1 f2
  find -size f1
  ```
####  Compressed Files
```
  zcat f1 > f2
  gzip -d file
  bzip2 -d f1
  tar -xvf file
  ```
####  Connecting to a Server/Port
```
  nc localhost 30000
  echo 4wcYUJFw0k0XLShlDzztnTBHiqxU3b3e | nc localhost 30000
  openssl s_client -connect localhost:30001 -quiet
  nmap -p 31000-32000 localhost
  telnet localhost 3000
  ```
