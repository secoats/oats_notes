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