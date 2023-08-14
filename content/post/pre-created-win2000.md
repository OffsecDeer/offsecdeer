---
title: "Pre-Windows 2000 Settings, Pre-created And Reset Computer Accounts"
date: 2023-08-14T01:00:01+02:00
tags:
  - active-directory
  - windows
  - pentesting
toc: true
showdate: true
---


## Theory

Machine (or "computer") accounts have their own strong and randomly generated password which by default is changed every 30 days, and this is why cracking a machine account's NT hash is pretty much a waste of time, especially since you can just authenticate with the hash alone.

There are however two ways a machine account will be given a predictable password we as attackers can leverage:
- a computer is pre-created with pre-Windows 2000 compatibility
- an existing computer is reset

The first scenario isn't that common anymore, unless we are in a domain that has existed long enough for pre-Windows 2000 compatibility to have made sense at some point, while the second scenario can take place in any network as resetting computer accounts is normal practice, and system administrators aren't aware of the potential consequences because Microsoft doesn't explicitely tell you the new password is guessable.

Pre-creating a computer means adding a computer object to AD without using it to join a host to the domain yet, once created the computer account can be used to join a host at a later time. Pre-Windows 2000 compatibility is an option that can be chosen when creating a computer from ADUC, still present in Windows Server 2022 for backwards compatibility:

![f60e13fb0ea62f863411269fcf7c5255.png](/_resources/f60e13fb0ea62f863411269fcf7c5255.png)

Resetting a computer on the other hand breaks its connection to the domain: the computer account will still exist but it won't be tied to the host that used it anymore, so that host can't log into the domain anymore until it joins it again. A computer reset can be done either from ADUC or PowerShell.

![5df84374967823a54ed9efab65fb036b.png](/_resources/5df84374967823a54ed9efab65fb036b.png)

In both cases the machine account's password is set to the lowercase name of the computer itself, minus the $ character. In the image above I created a TEST2 computer with pre-Windows 2000 compatibility, which means its password will be "test2". I have also created a TEST1 computer but without pre-Windows 2000 compatibility, then I used CME to try logging in to both using their lowercase name as password:

![d951ad37897a4bd6f1ab571125d299eb.png](/_resources/d951ad37897a4bd6f1ab571125d299eb.png)

We didn't get an SMB session working but the error message changed, confirming the password is correct even if we can't use it for SMB, but we can still use it for fun things as we'll see.

To prove that computer passwords are changed upon reset I took an account associated to an actual host (no pre-Windows 2000 compatibility), tried logging in, then reset it and logged in again:

![476d0acc8e92d2b54c582ea294a975ab.png](/_resources/476d0acc8e92d2b54c582ea294a975ab.png)

So resetting AD-DEBIAN set its password to "ad-debian" even if pre-Windows 2000 compatibility was never set. 

---

## Exploitation

What can we do with these credentials though? We have a couple options: we either use them to request a TGT via Kerberos, or we authenticate over RPC to change our own password using the SAMR protocol. After changing the password we will be able to use the computer account over SMB too.

Impacket's *changepasswd* script can be used to change a user's password with a few protocols, including LDAP, kpasswd, SMB, and RPC. Both SMB and RPC will utilize the SAMR protocol, but SMB requires us to connect to the IPC$ share, which we can't access with the default password as seen above. Therefore, we pick rpc-samr:

![30717c3bf3345e263cd1518186c62fb5.png](/_resources/30717c3bf3345e263cd1518186c62fb5.png)

After the password change we were able to connect to the DC with SMB, meaning we can now do anything the machine account had permissions for.

On top of that, DACL are preserved after a computer is reset, which means that if this computer account used to have privileged access to resources we can still exploit its permissions. For example AD-DEBIAN had replication permissions on the domain, so we can just DCSync our way to domain admin (not exactly realistic but it's to prove a point):

![3f3cddbe8cae1dbb3a2a914db35480a6.png](/_resources/3f3cddbe8cae1dbb3a2a914db35480a6.png)

We don't necessarily need to change the account's password though, we can authenticate with Kerberos and obtain a TGT to use with other tools:

![8c844ade97ebb6d4ebf9289921e6b98d.png](/_resources/8c844ade97ebb6d4ebf9289921e6b98d.png)

Any tool that supports Kerberos authentication should now work, for example impacket's GetNPUsers:

![e8ec49ffcf03793b6e1b78e8165fdf56.png](/_resources/e8ec49ffcf03793b6e1b78e8165fdf56.png)

---

## Automation

**Linux**

[pre2k](https://github.com/garrettfoster13/pre2k) is my personal favorite option because it's Python, so we can run it from a Linux box, and can be used with or without credentials.
If we already have domain credentials pre2k will retrieve the list of computers from LDAP and will check which of these has default credentials:

![7be422a7754097037749f2a263812a17.png](/_resources/7be422a7754097037749f2a263812a17.png)

Or, even better, without needing any credentials we can just pass a list of computer account names to the program and obtain the same result, but without needing a foothold in the domain:

![3d2b2817bff1bd6c078e2a443ce63a05.png](/_resources/3d2b2817bff1bd6c078e2a443ce63a05.png)

This is good and all, but the previous example assumes we already have a file containing all computer names, so I took automation one step further and wrote a little script which takes a range of IP addresses, grabs the NetBIOS name of each Windows computer it finds, and then feeds the list of computer names to pre2k:
```bash
#!/bin/bash
nbtscan -s : -q $1 | cut -d ':' -f 2 | tr -d ' ' | sed -e 's/$/$/' > ad_computers.txt
pre2k unauth -inputfile ad_computers.txt -d $2 -dc-ip $3
```

![3070f0d89d7ca598f40e4e2555d9db2b.png](/_resources/3070f0d89d7ca598f40e4e2555d9db2b.png)

The obvious limitation of this script is that it can only find the credentials of reset computer accounts that belonged to still running machines, because it is not possible for unauthenticated users to obtain a list of all computer accounts unless NULL sessions or LDAP binds are [enabled](https://www.pwndefend.com/2021/02/25/how-to-enable-null-bind-on-ldap-with-windows-server-2019/), in which case you can just use *pre2k auth* with an empty username and password (this however hasn't been enabled by default for a long time, and for good reasons).

**Windows**

If we are attacking from a Windows box or have already gained access to a domain joined machine we can resort to [prenum](https://github.com/4ndr34z/prenum):

![eda782628bd2dc07208f676735bb7fa2.png](/_resources/eda782628bd2dc07208f676735bb7fa2.png)

The good thing about prenum is that it can reflectively load Rubeus and Certify and use the vulnerable accounts for automatic exploitation. For example to requests TGTs for the compromised computers we can use the *AskTgt* option:

![2011a798ebc7d98f51b2100411a747d3.png](/_resources/2011a798ebc7d98f51b2100411a747d3.png)

Alternatively, [Invoke-Pre2kSpray](https://github.com/eversinc33/Invoke-Pre2kSpray) can also be used, a nice feature is the *Filter* option which only tries to spray computers that have had their passwords changed more than 30 days ago.


---

## Mitigation

Mitigating this issue is rather simple: make sure you never pre-create a computer account with pre-Windows 2000 compayibility and be mindful that when you reset a computer that account's password will become predictable, so use the account to join another computer to the domain or delete it altogether, as the more unused and reset computer accounts you leave in your domain, the more entry points you're leaving for attackers.

Note that computer account passwords are updated when used in a domain join regardless of the pre-Windows 2000 option, so if you happen to have used it a long time ago but the computer accounts are associated with a machine then there are no risks.

---


## Pre-Windows 2000 Compatible Access Group

Despite the name, this feature is not directly related to the "pre-Windows 2000" option we are talking about, but is still worth mentioning because it can impact security.

Pre-Windows 2000 Compatible Access is a built-in security group that's been part of AD domains since Windows 2000, and still comes packaged within Windows Server 2022. Its purpose is to provide users backwards compatibility with much older OS versions like Windows NT 4, back when access was given to objects either completely or not at all.

Then, Windows 2000 made it possible to assign users access based on attributes with the introduction of Active Directory, so this group was introduced to allow older users to be compatible with AD.

Back in Windows 2000 and Windows Server 2003, the group was automatically populated with three other groups: Anonymous, Everyone, and Authenticated Users. Starting with Server 2008 the group only contains Authenticated Users, however if the domain was originally created under Windows 2000 or Server 2003 and then updated to a later version, the group membership would have persisted.

On every Windows installation this group is given full read permissions over the domain root, applied to every descending InetOrg, User and Group object:

![0b03ec8fda725fa5c4d8e744d80e49f6.png](/_resources/0b03ec8fda725fa5c4d8e744d80e49f6.png)

The consequences of such a setup are that anonymous users would be able to enumerate all users and groups within the domain, and unauthenticated user enumeration is never a good thing.

Below is a screenshot of two CME commands run without credentials, the first was launched only with Authenticated Users under the Pre-Windows 2000 Compatible Access group, while for the second one the Everyone and Anonymous groups were added as members too:

![37ee934407b4e883b2a32255371653c3.png](/_resources/37ee934407b4e883b2a32255371653c3.png)

The obvious solution is to empty out this old group, by now you shouldn't be using systems as old as Windows NT 4 to begin with, and chances are that even if this group might have been useful to your domain some time ago, now its presence is only a security concern.

---


**References**
- https://www.trustedsec.com/blog/diving-into-pre-created-computer-accounts/
- https://www.optiv.com/insights/source-zero/blog/diving-deeper-pre-created-computer-accounts
- https://github.com/garrettfoster13/pre2k
- https://github.com/eversinc33/Invoke-Pre2kSpray
- https://github.com/4ndr34z/prenum
- https://www.semperis.com/blog/security-risks-pre-windows-2000-compatibility-windows-2022/