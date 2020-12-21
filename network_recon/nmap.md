# Nmap Cheatsheet
```default
                    ___.-------.___
                _.-' ___.--;--.___ `-._
             .-' _.-'  /  .+.  \  `-._ `-.
           .' .-'      |-|-o-|-|      `-. `.
          (_ <O__      \  `+'  /      __O> _)
            `--._``-..__`._|_.'__..-''_.--'
                  ``--._________.--''
   ____  _____  ____    ____       _       _______
  |_   \|_   _||_   \  /   _|     / \     |_   __ \
    |   \ | |    |   \/   |      / _ \      | |__) |
    | |\ \| |    | |\  /| |     / ___ \     |  ___/
   _| |_\   |_  _| |_\/_| |_  _/ /   \ \_  _| |_
  |_____|\____||_____||_____||____| |____||_____|
```

**Important:** Always use sudo/root or you will not be able to use all features of Nmap. Especially SYN scanning requires root access.

## Full TCP all ports
```bash
sudo nmap -p 1-65535 -T4 -A -v $ip
sudo nmap -vv --reason -Pn -A --osscan-guess --version-all -p- $ip
```

## Ipp setting
```bash
sudo nmap -sC -sV -oA nmap_output.txt $ip
```

## Full scan with UDP
```bash
sudo nmap -sS -sU -T4 -A -v $ip
```

## UDP top 20
```bash
sudo nmap -vv --reason -Pn -sU -A --top-ports=20 --version-all
```

## Ping scan (No port scan) 
```bash
sudo nmap -sn $ip
```

## Quick Scan
```bash
sudo nmap -T4 -F $ip
```

## Quick Scan Plus
```bash
sudo nmap -sV -T4 -O -F --version-light $ip
```

## SMB scan
```bash
sudo nmap -sV -p139,445 --script=smb-vuln* $ip
sudo nmap -sV -p139,445 --script=smb-protocols,smb-vuln* $ip
```

## HTTP scan
```bash
sudo nmap -vv --reason -Pn -sV -p 80,443 "--script=banner,(http* or ssl*) and not (brute or broadcast or dos or external or http-slowloris* or fuzzer)" $ip
```

## SSH scan
```bash
sudo nmap -vv --reason -Pn -sV -p 22 --script=banner,ssh2-enum-algos,ssh-hostkey,ssh-auth-methods $ip
```

## FTP scan

```bash
sudo nmap -vv --reason -Pn -sV -p 21 "--script=banner,(ftp* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" $ip
```

## SNMP scan
Simple Network Management Protocol (SNMP). Usually runs on UDP port 161.

Enum:
```bash
sudo nmap -vv --reason -Pn -sU -sV -p 161 "--script=banner,(snmp* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" $ip
```


## SMTP scan

```bash
sudo nmap -vv --reason -Pn -sV -p 25 "--script=banner,(smtp* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" $ip
```


## Scripts
```bash
ls -al /usr/share/nmap/scripts/

# https://www.tecmint.com/use-nmap-script-engine-nse-scripts-in-linux/
# DEFAULT: -sC or --script=default
```

## Useful parameters
```bash
# SYN scan
-sS

# TCP connect scan
-sT

# IPv6 scan enable
-6

# Skip host is up check
-PN

# OS DETECTION:
-O # Enable OS detection
--osscan-limit # Limit OS detection to promising targets
--osscan-guess # Guess OS more aggressively

# SERVICE/VERSION DETECTION:
-sV # Probe open ports to determine service/version info
--version-intensity <level> # Set from 0 (light) to 9 (try all probes)
--version-light # Limit to most likely probes (intensity 2)
--version-all # Try every single probe (intensity 9)
--version-trace # Show detailed version scan activity (for debugging)

# Greppable output
-oG output.txt

```

## Nmap Exploits

* https://gtfobins.github.io/gtfobins/nmap/
* https://archive.today/CkonW

