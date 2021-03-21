# Linux Commands Cheatsheet

This is a cheatsheet for common linux commands. 

[Linux Local Enum is over here.](../linux_local_enumeration.md)

## Essential Navigation

```bash
# show directory content 
ls

# list all files with permissions and ownership
ls -al

# recursive file listing
tree
ls -lR

# change directory
cd somedir
cd ..       # parent dir
cd /        # root dir
cd ~        # home dir

# move file or directory
mv source dest
mv /path/to/source /path/to/dest

# copy file
cp /etc/shadow /tmp/shadow

# create directory
mkdir whatever

# create (empty) file
touch somefile

# print file content
cat /etc/passwd
less /etc/passwd

# edit file
nano ./somefile
vi ./somefile
vim ./somefile
emacs ./somefile

# figure out file type (based on content)
file ./somefile
```

## Pipes

```bash
# pipe output into another command
sort record.txt | uniq

# copy/overwrite file content without overwriting the target file metadata
cat sourcefile > targetfile

# merge several files
cat file0 file1 file2 > merged_file

# append to file
echo "some text" >> targetfile
cat sourcefile >> targetfile

# discard all output
command > /dev/null

# discard only errors
command 2> /dev/null
```

## User Management

```bash
# Switch users
su someuser
sudo -u <user> <command>
sudo su someuser

# Switch to root
su -
sudo su -
```

## Local Enum

```bash
# whoami?
whoami
id

# Figure out Kernel version, OS, Processor Architecture
uname -a
lsb_release -a
cat /proc/version
cat /etc/*-release
cat /etc/lsb-release
cat /etc/redhat-release
getconf LONG_BIT

# hostname
hostname
dnsdomainname

# IP address(es) and interfaces
ip addr
ifconfig

# Networks
cat /etc/networks
cat /etc/sysconfig/network

# Hosts file
cat /etc/hosts
cat /etc/resolv.conf

# ARP table (neighboring hosts)
cat /proc/net/arp
arp -a

# firewall (might need root)
iptables -L

# Printers
lpstat -a
cat /etc/printcap
```

Open ports

```
# show open ports and associated application
netstat -tulpn
ss -lntu
lsof -i

# local nmap
sudo nmap -n -PN -sT -sU -p- localhost
nmap -n -PN -sT -sU -p- localhost


# BSD
sockstat -4 -l
sockstat -6 -l
```

## Jobs

```bash
# run as background job
somecommand &

# see jobs and their status
jobs

# put currently running process into background and suspend it
CTRL+Z

# unsuspend the backgrounded job (the one we moved to background with CTRL+Z)
bg
bg <id>

# Move backgrounded job back to foreground
fg <id>
```

## Binary Analysis

Shallow look:
```bash
# Figure out binary type:
file ./somebinary

# Hex Dump
xxd ./somebinary

# print human readable strings contained in binary file
strings ./somebinary

# print library calls made by binary during execution (program flow dependent)
ltrace ./somebinary

# print system calls made by binary during execution (program flow dependent)
strace ./somebinary
```

Elf files:
```bash
# show elf file layout and info
readelf -a ./binary

# prints assembly of section ".text"
objdump -D -M intel -j .text ./start
```

GDP Peda:
```bash
# install
apt install gdp
git clone https://github.com/longld/peda.git ~/peda
echo "source ~/peda/peda.py" >> ~/.gdbinit

# run
gdp ./binary

# show function labels
gdb-peda$ info functions

# add breakpoint
gdb-peda$ break _label

Use n to step and ni to step each instruction.

# clear breakpoint
gdb-peda$ info break
gdb-peda$ del <num>

# execute
gdb-peda$ run (?params)

# print registers
gdb-peda$ info registers

# print value at address
x 0x<addr>

# use file content when asked for input
run < filename
```


## Shell Tricks

* Upgrading shells -  https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/

Upgrade semi-interactive shell to interactive shell:

```bash
python -c 'import pty; pty.spawn("/bin/bash")'
```

Automatically answer input query (asking for password, etc.):

```bash
(sleep 1; echo secretpassword) | some_command_requiring_input
```

Get from euid to actual uid:

```bash
python -c 'import os,pty;os.setuid(0);os.setgid(0);pty.spawn("/bin/bash")';
```

## Compile Exploits

Cross-compile Windows exploits on Linux:

```bash
# Requirements:
# sudo apt-get install mingw-w64
 
# C
i686-w64-mingw32-gcc hello.c -o hello32.exe      # 32-bit
x86_64-w64-mingw32-gcc hello.c -o hello64.exe    # 64-bit
 
# C++
i686-w64-mingw32-g++ hello.cc -o hello32.exe     # 32-bit
x86_64-w64-mingw32-g++ hello.cc -o hello64.exe   # 64-bit

# add this to link the winsock library (often required):
-lws2_32
i686-w64-mingw32-gcc hello.c -o hello32.exe -lws2_32
```
