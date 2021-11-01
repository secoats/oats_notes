# Email Servers

Most Important Protocols:

* **SMTP** - Simple Mail Transfer Protocol
* **POP** - Post Office Protocol
* **IMAP** - Internet Message Access Protocol

## SMTP - Simple Mail Transfer Protocol

SMTP is a simple plaintext over TCP socket protocol (optionally encryped with SSL/TLS). 

SMTP allows email servers to exchange emails with one another. But there is nothing preventing us from pretending to be an email server.

Well-known ports:

* TCP -- 25 (plain)
* TCP -- 587 (SSL/TLS)

If the `VRFY` command is allowed then you can enumerate usernames:

```bash
# VRFY user enum with custom list
smtp-user-enum -M VRFY -U /tmp/users.txt -t 10.0.0.42 -p 25

# VRFY example with seclists small username list
smtp-user-enum -M VRFY -U "/usr/share/seclists/Usernames/top-usernames-shortlist.txt" -t 10.0.0.42 -p 25
```

You might also be able to enumerate users via `RCPT TO` or `EXPN`.

```bash
# RCPT - check if email recipient exists
smtp-user-enum -M RCPT -U /tmp/users.txt -t 10.0.0.42 -p 25

# EXPN - query users in given "email list"
smtp-user-enum -M EXPN -U /tmp/maillists.txt -t 10.0.0.42 -p 25
```

Login bruteforce:
```bash
hydra -l <username> -P /tmp/passwords.txt <IP> smtp -V
hydra -l <username> -P /tmp/passwords.txt -s 587 <IP> -S -v -V #Port 587 for SMTP with SSL

hydra -L /tmp/users.txt -P /tmp/passwords.txt <IP> smtp -V
hydra -L /tmp/users.txt -P /tmp/passwords.txt -s 587 <IP> -S -v -V #Port 587 for SMTP with SSL
```

You can communicate with an SMTP server using **netcat** or **telnet**:

```bash
$ nc 10.0.0.42 25
220 localhost ESMTP server ready.
HELO x
250 localhost Hello, x.
HELP
214-Recognized SMTP commands are:
214-   HELO   EHLO   MAIL   RCPT   DATA   RSET
214-   AUTH   NOOP   QUIT   HELP   VRFY   SOML
214 Mail server account is 'Maiser'.
```

It is worth enumerating the **Server Domain Name** that the server might give you in the server banner. You can assume that local email accounts will use that domain: `admin@localhost` (example above, CTFy) / `admin@example.com` (more normal), which can be useful to know for POP/IMAP or sending emails to that account.

There are two ways to initiate communication with an SMTP server:

```bash
# Basic SMTP greeting. <x> stands for your own domain. Often it doesn't matter what you enter as your own domain.
HELO x

# Extended SMTP (ESMTP) greeting. An ESMTP session might offer more server commands than a regular SMTP conversation. So using this is usually preferable.
EHLO x
```

The `HELP` command should print the available server commands.

### AUTH

Usually you can authenticate to the server using the `AUTH` command.

The three common AUTH methods are:

* **AUTH PLAIN**
* **AUTH LOGIN**
* **AUTH CRAM-MD5**

**PLAIN:** Send `base64(username + password)`

```bash
C: AUTH PLAIN
S: 334
C: dXNlcm5hbWVQNDU1VzBSRA==
S: 235 2.7.0 Authentication successful
```

It might be confusing, but the credentials are sent as base64 and not sent as plaintext despite the name.

**LOGIN:** Send `base64(username)` and `base64(password)` as separate messages

```bash
C: AUTH LOGIN
S: 334 dXNlcm5hbWU=
C: adlxdkej
S: 334 UDQ1NVcwUkQ=
C: lkujsefxlj
S: 235 2.7.0 Authentication successful
```

**CRAM-MD5:**

> After [...] the AUTH CRAM-MD5 command has been sent to the server, the servers sends back an one-time BASE64 encoded "challenge" to the client. The client responds by sending a BASE64 encoded string to the server that contains a username and a 16-byte digest in hexadecimal notation.
 
> The digest in the reply string is the output of an HMAC (Hash-based Message Authentication Code) calculation with the password as the secret key and the SMTP server's original challenge as the message. The SMTP server also calculates its own digest with its notion of the user's password, and if the client's digest and the server's digest match then authentication was successful and a 235 reply code is sent to the client.

-- [samlogic](https://www.samlogic.net/articles/smtp-commands-reference-auth.htm)


## POP - Post Office Protocol

POP (POP3 is still in common use) allows email clients to retrieve email messages from a mail server. It lacks some features compared to the newer IMAP.

Well-known ports (POP3):

* TCP -- 110 (plain)
* TCP -- 995 (SSL/TLS)

Like with SMTP you can connect via a TCP socket:

```bash
nc -nv 10.0.0.42 110
openssl s_client -connect 10.0.0.42:995 -crlf -quiet
```

```bash
POP commands:
  USER uid           Log in as "uid"
  PASS password      Substitue "password" for your actual password
  STAT               List number of messages, total mailbox size
  LIST               List messages and sizes
  RETR n             Show message n
  DELE n             Mark message n for deletion
  RSET               Undo any changes
  QUIT               Logout (expunges messages if no RSET)
  TOP msg n          Show first n lines of message number msg
  CAPA               Get capabilities
```

`CAPA` prints the capabilities of the server. You can also use nmap in order to enumerate this:

```bash
nmap --script "pop3-capabilities or pop3-ntlm-info" -sV -p 110 10.0.0.42
nmap --script "pop3-capabilities or pop3-ntlm-info" -sV -p <PORT> <IP>
```

Login bruteforce:

```bash
hydra -l USERNAME -P /path/to/passwords.txt -f <IP> pop3 -V
hydra -S -v -l USERNAME -P /path/to/passwords.txt -s 995 -f <IP> pop3 -V
```

Please note that the username probably must be in `username@domain.tld` format. Not just `username` like with SMTP. Use small spray lists, you will probably get blacklisted.





## IMAP - Internet Message Access Protocol

IMAP allows email clients to retrieve email messages from a mail server, similar to POP. It comes with more features than the earlier POP3 protocol, but the purpose is the same.

Well-known ports:

* TCP -- 143 (plain)
* TCP -- 993 (SSL/TLS)






## References

* https://book.hacktricks.xyz/pentesting/pentesting-smtp
* https://www.samlogic.net/articles/smtp-commands-reference.htm
* https://www.samlogic.net/articles/smtp-commands-reference-auth.htm
* https://book.hacktricks.xyz/pentesting/pentesting-pop