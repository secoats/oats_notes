# Hashes and Codes

## Hash Databases

Before you start cracking hashes you should check whether they are already in one of the common databases:

* https://crackstation.net/
* https://hashes.com/en/decrypt/hash
* hashes.org

## Hash Identification

* [hash-identifier](https://tools.kali.org/password-attacks/hash-identifier)
* [hashid](https://github.com/psypanda/hashID)

## User Hash Generation

### md5Crypt ($1$ hash)
```bash
openssl passwd -1 -salt hack cowabunga77
$1$hack$Ms0RDU0fPwY2uBBL9/Cnb/
```

### sha512crypt ($6$ hash)
```bash
mkpasswd -m sha-512 cowabunga77
$6$k1T3o1vgxLGYOT6V$IE9LrzWNqPbaZwLMaG7i93l2arSrttHLfi.NLUtk2t.qj8hufYC5T2FsP96vhllYZUUFRY4.I6jSbr37RddsE1
```

### NTLM
```bash
echo -n 'cowabunga77' | python3 -c "import sys,hashlib;print(hashlib.new('md4',sys.stdin.read().strip().encode('utf-16le')).hexdigest())"
248c89eb5d2da0b43384b536343f4e1d
```

LM:NTLM (blank LM) notation for Pass-the-Hash:
```bash
aad3b435b51404eeaad3b435b51404ee:248c89eb5d2da0b43384b536343f4e1d
```


## Hashcat

Hashcat should always be run on bare metal and not in a virtual environment. But if you need to run it in a VM, then use the `--force` command line parameter.

### Hash Mode

See: https://hashcat.net/wiki/doku.php?id=example_hashes

---

You can also get a list with `hashcat --help`.

For example if you have a hash: `$6$wyfLrB...` then we can probably find the correct hash mode using grep:

```bash
# Find hashcat mode:
hashcat --help | grep -i '$6'

## 1800 | sha512crypt $6$, SHA512 (Unix)                   | Operating System
```

So in order to crack our `$6$wyf...` hash we will have to use `-m 1800`.


### Hash cracking using a wordlist (attack mode 0):

Insert your hash(es) into a text file named `hashes.txt`

```bash
hashcat -m 500 -a 0 ./hashes.txt /usr/share/wordlists/rockyou.txt
```

The password wordlist `rockyou.txt` is included in Kali Linux and also in [SecLists](https://github.com/danielmiessler/SecLists/tree/d5271820d00935387bdff87d0a79ae5513b47ce3/Passwords/Leaked-Databases), among others.


### Hash cracking using bruteforcing / mask rules (attack mode 3):

The following example will try all possible character permutations, starting with a single character up to seven characters (X - XXXXXXX).

```bash
hashcat -m 500 -a 3 ./hashes.txt -1?a ?1?1?1?1?1?1?1 --increment
```

The paramter `-1?a` defines a custom-charset named `1` which includes all common characters `?a` (lowercase, uppercase, numbers, special characters):

```default
  ? | Charset
 ===+=========
  l | abcdefghijklmnopqrstuvwxyz
  u | ABCDEFGHIJKLMNOPQRSTUVWXYZ
  d | 0123456789
  h | 0123456789abcdef
  H | 0123456789ABCDEF
  s |  !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
  a | ?l?u?d?s
  b | 0x00 - 0xff
```

The mask `?1?1?1?1?1?1?1` then stands for 7 characters according to the previously defined custom-charset `1`.

The `--increment` parameter tells hashcat that it should start trying with a single character `?1` and then, once all permutations are depleted, it will move on to two `?1?1` characters and so forth, all the way up to the full 7 characters `?1?1?1?1?1?1?1`. If you know the exact length of the password then omit the `--increment` parameter.

#### Partially Known Passphrases

You can also hardcode parts of the test phrase if parts of the correct pass are known:

```bash
hashcat -m 500 -a 3 ./hashes.txt -1?a password?1?1?1?1 --increment
```

This would detect possible passphrases such as: `password!!`, `password123`, `password3210` or `password#$$#`.

