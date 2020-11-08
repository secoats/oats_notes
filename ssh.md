# SSH

## Basic usage

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
```

Start local SSH server:
```bash
sudo systemctl start ssh.socket
```

Stop local SSH server:
```bash
sudo systemctl stop ssh.socket
```

## Deal with errors

Use nmap to figure out what key exchange methods and ciphers are supported. But the error usually tells you what is supported by the server too.

Error: "no matching key exchange method..."
```bash
ssh user@host -oKexAlgorithms=+<key-exchange>
ssh user@host -oKexAlgorithms=+diffie-hellman-group1-sha1
```

Error: "no matching cipher..."
```bash
ssh user@host -c <cipher>
ssh user@host -c aes128-cbc
```

Error: "key too open"
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

## Permanent Access

Append your public key to ~/.ssh/authorized_keys

```bash
echo "<your_pub_key>" >> /home/admin/.ssh/authorized_keys
```

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

## Port Forwarding
### Local Forward

Example (you are Kali):

```bash
⎡   Kali    ⎤         ⎡     TARGET     ⎤
⎜ 10.1.1.42 ⎟ ======= ⎜    10.1.1.99   ⎟
⎜           ⎟         ⎜ Open:       22 ⎟
⎜           ⎟         ⎜ Filtered: 3306 ⎟
⎣           ⎦         ⎣ Filtered: 8080 ⎦
```

You have SSH access to the TARGET host. 

The target machine has a firewall that blocks remote access to the 3306 port (the MySQL database running on TARGET).

You want to forward that filtered MySQL port on TARGET to your own machine so you can interact with it more easily.

```bash
# Local port forward. Access is limited to localhost
ssh -L <local-ip>:<local-port>:<target-host>:<target-port> <user@target>
ssh -L 127.0.0.1:1337:10.1.1.99:3306 user@10.1.1.99

# short-hand version
ssh -L <local-port>:<target-host>:<target-port> <user@target>
ssh -L 1337:10.1.1.99:3306 user@10.1.1.99
```

This will open the port 1337 on Kali's localhost (127.0.0.1). When you interact with socket `localhost:1337`, then the connection will be automatically forwarded to `10.1.1.99:3306`.

Effectively it will look to you as if the MySQL database was running on your own machine on port 1337.

Now you can interact with the MySQL server via `mysql --port 1337` in a local terminal on Kali.

### Access control on forwarded port

If you write 127.0.0.1 as local IP address then you will only be able to access it from localhost. If you wish to open the local port 1337 globally (to the entire network), then use the wildcard 0.0.0.0:

```bash
# Local port forward. Allow access to all IP addresses (wildcard)
ssh -L 0.0.0.0:<local-port>:<target-host>:<target-port> <user@target>
ssh -L 0.0.0.0:1337:10.1.1.99:3306 user@10.1.1.99

# short-hand version
ssh -L :<local-port>:<target-host>:<target-port> <user@target>
ssh -L :1337:10.1.1.99:3306 user@10.1.1.99
```

### Remote Forward

The process can also be done in reverse, opening a port on the TARGET which forwards to one of your local ports.

Initially the setup looks like this:

```bash
⎡    Kali   ⎤         ⎡   TARGET  ⎤
⎜ 10.1.1.42 ⎟ ======= ⎜ 10.1.1.99 ⎟
⎣ Open:  80 ⎦         ⎣ Open:  22 ⎦                            
```

There is an HTTP server running on your own machine (Kali) on port 80. You wish to open a port on TARGET which forwards to your HTTP server.

On Kali you would run:
```bash
# Remote forward. Open port on TARGET loopback interface.
ssh -R <target-port>:<forward-to-host>:<forward-to-port> user@target
ssh -R 10080:127.0.0.1:80 user@target

# Make port on target globally accessible (GatewayPorts yes)
ssh -R 0.0.0.0:10080:127.0.0.1:80 user@target
```

The result would look like this:

```bash
⎡    Kali   ⎤         ⎡    TARGET   ⎤
⎜ 10.1.1.42 ⎟ ======= ⎜  10.1.1.99  ⎟
⎜ Open:  80 ⎟         ⎜ Open:    22 ⎟
⎣           ⎦         ⎣ Open: 10080 ⎦                        
```

Wherein `10.1.1.99:10080` forwards to `10.1.1.42:80`.

Now users on the TARGET can visit `http://localhost:10080` and they will see the web server running on `http://10.1.1.42:80`.

Please note that the remote forward permissions are determined by the SSH config for the TARGET SSH server. 
In the `/etc/ssh/sshd_config` of the TARGET you need to set `GatewayPorts yes` in order to bind a port globally (wildcard 0.0.0.0). Changing that config usually requires root access on TARGET.

When bound to 0.0.0.0, then anybody in the nework can visit `http://10.1.1.99:10080` in order to access the web server running on `http://10.1.1.42:80`.


## Pivoting

Use a bridge host to reach a remote network. 

This can be rather confusing, so here is a practical example:

- **10.1.1.42 - Kali (you)**
- **10.8.8.77 - TARGET**

In this scenario you cannot reach the **TARGET** host because the router firewall will block it or there is no route to the 10.8.8.0/24 network.

```bash
⎡   Kali    ⎤                          ⎡   TARGET  ⎤
⎜ 10.1.1.42 ⎟ ========== X|X --------- ⎜ 10.8.8.77 ⎟
⎣           ⎦                          ⎣           ⎦
```

Now assume you compromised a host that is able to reach the target:

* **10.1.1.33 - BRIDGE**

You have ssh access on the **BRIDGE** host with username pippin, i.e. you could do `ssh pippin@10.1.1.33` from **Kali** to get a shell on BRIDGE.

Now you can use **BRIDGE** to access **TARGET** via port forwarding:

```bash
⎡    Kali   ⎤       ⎡   BRIDGE  ⎤       ⎡   TARGET  ⎤
⎜ 10.1.1.42 ⎟ ===== ⎜ 10.1.1.33 ⎟ ===== ⎜ 10.8.8.77 ⎟
⎣           ⎦       ⎣ Port:  22 ⎦       ⎣           ⎦
```

You can either set up a forward to a single port on 10.8.8.77 or you can set up a dynamic Proxy in order to access all of 10.8.8.0/24.

### Pivoting: Single Port Forward

```bash
⎡    Kali   ⎤       ⎡   BRIDGE  ⎤       ⎡   TARGET  ⎤
⎜ 10.1.1.42 ⎟ ===== ⎜ 10.1.1.33 ⎟ ===== ⎜ 10.8.8.77 ⎟
⎣ Port:8888 ⎦       ⎣ Port:  22 ⎦       ⎣ Port:  80 ⎦
```
```bash
ssh -L <localport>:<target>:<targethost> <user@bridge>
ssh -L 8888:10.8.8.77:80 pippin@10.1.1.33
```

Just to be clear, you execute that ssh command on Kali.

Now you can visit `http://localhost:8888` in your browser on Kali which will be forwarded to the HTTP server on 10.8.8.77


### Pivoting: Dynamic SOCKS Proxy

You can also set up a proxy with SSH in order to reach every host/port in the target network 10.8.8.0/24 via SOCKS proxy:

```bash
⎡    Kali   ⎤       ⎡   BRIDGE  ⎤       ⎡   network   ⎤
⎜ 10.1.1.42 ⎟ ===== ⎜ 10.1.1.33 ⎟ ====< ⎜ 10.8.8.0/24 ⎟
⎣ Port:1337 ⎦       ⎣ Port:  22 ⎦       ⎣             ⎦
```
```bash
ssh -N -D <localport> -q -C -f <user@bridge>
ssh -N -D 1337 -q -C -f pippin@10.1.1.33
```

Now you can use foxyproxy in your browser to create a SOCKS 5 profile pointing to `localhost:1337`. With that proxy active you can reach any host in the 10.8.8.0/24 network. e.g. http://10.8.8.222

Similarly you can use any command line program that supports SOCKS proxies. For programs that do not, take a look at "proxychains".

If you need to use a program that does not support proxies or if using proxies is not feasible, then just create a single port forward (see above) to access a single remote service. Especially when scanning a service that method is preferred.

By default SSH will use SOCKS 5 which supports TCP and UDP tunneling, but you can also specify a version with `-X 4` which will use SOCKS 4 (only supports TCP).


### Pivoting: Useful Params

```bash
# -L  -- local forward
# -R  -- remote forward
# -N  -- don't open shell
# -C  -- compress connection (save bandwidth)
# -q  -- quiet mode (don't print anything locally)
# -f  -- fork to background command (like & basically)
# -X  -- set SOCKS version 4 / 5 (default)
```

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

## References

* SSH Port Forwarding - https://zaiste.net/posts/ssh-port-forwarding/
