---
title: "HackTheBox Writeup: Grandpa"
date: 2019-08-25T03:21:29+02:00
tags:
  - hackthebox
  - ctf
  - writeup
showdate: true
toc: true
page: false
---
{{%summary%}}
![img](/images/grandpa-writeup/1.png)
{{%/summary%}}

Grandpa and its sister box [Granny](/post/htb-writeup-granny/) are unique in the way that they use very old versions of Windows but the approach to follow is still the same for any Windows challenge, and both boxes rely a lot on publicly know vulnerabilities making them easy to own. As I mentioned in Granny's writeup one could own either one of these two boxes and then pivot on to the other one, but this is no longer possible with the current lab system so I won't be talking about that approach, as I never had the chance to try it myself.

---

## Enumeration

Let's start from a usual nmap scan to run safe scripts (-sC) and enumerate services (-sV):

![img](/images/grandpa-writeup/2.png)

Only port 80 is open and the web server appears to be empty too, nothing interesting but a default installation of IIS 6.0 (which tells us the OS is Windows Server 2003, just like Granny) with WebDAV enabled. Since WebDAV is enabled we can try using davtest to see if it is possible to upload any files on the server:

```shell-session
$ davtest -url http://10.10.10.14
```

![img](/images/grandpa-writeup/3.png)

Unfortunately we cannot upload any files or create directories, but since IIS 6.0 is so old it's possible to find plenty vulnerabilities so we consult exploit-db and soon enough find this [buffer overflow exploit](https://www.exploit-db.com/exploits/41738). The CVE for the vulnerability is CVE-2017-7269 so to make our lives easier we can try taking a look at Metasploit's modules, maybe there's one that can give us a meterpreter shell directly:

![img](/images/grandpa-writeup/4.png)

---

## Exploitation: CVE-2017-7269 w/ Metasploit

All we need to launch this module is set up the RHOSTS option to Grandpa's IP address and a meterpreter session will be granted to us as NT AUTHORITY\NETWORK SERVICE:

![img](/images/grandpa-writeup/5.png)

For reasons that are unknown to me at times this exploit will spawn a session under a process that doesn't have enough privileges to run getuid, despite it running under the same network authority account:

```shell-session
meterpreter > getuid
[-] stdapi_sys_config_getuid: Operation failed: Access is denied.
```

When this happens list the running processes with *ps* and select one owned by the network authority account (the *whoami* command still works after spawning a shell with *shell*) and migrate to it, this will fix the issue. If this action isn't performed virtually every privilege escalation exploit will fail:

```shell-session
meterpreter > getuid
[-] stdapi_sys_config_getuid: Operation failed: Access is denied.
meterpreter > migrate 3372
[*] Migrating from 2680 to 3372...
[*] Migration completed successfully.
meterpreter > getuid
Server username: NT AUTHORITY\NETWORK SERVICE
```

We can see from here that there are two accounts, Administrator and Harry, however we cannot open either of the two folders:

![img](/images/grandpa-writeup/6.png)

The local exploit suggester provided by Metasploit can help us find privilege escalation vulnerabilities we can use to take control of an account with higher privileges:

```shell-session
msf5 > use multi/recon/local_exploit_suggester
msf5 > set session 1
msf5 > run
```

Or:

```shell-session
meterpreter > run post/multi/recon/local_exploit_suggester
```

![img](/images/grandpa-writeup/7.png)

---

## Privilege escalation: ppr_flatten_rec

A few exploits were found, I'll try using exploit/windows/local/ppr_flatten_rec although the other ones may work as well, in fact I think the same exploit can be used to root both Granny and Grandpa:

```shell-session
msf5> use exploit/windows/local/ppr_flatten_rec
msf5> set session 1
msf5> run
```

It might take a try or two but with this we will spawn a new session as NT AUTHORITY\SYSTEM giving us complete control over the box:

![img](/images/grandpa-writeup/8.png)

Now we can grab both flags and call it a day:

![img](/images/grandpa-writeup/9.png)


