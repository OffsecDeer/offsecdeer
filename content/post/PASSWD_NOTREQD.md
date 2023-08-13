---
title: "PASSWD_NOTREQD: Potentially Passwordless"
date: 2023-08-13T15:50:01+02:00
tags:
  - active-directory
  - windows
  - pentesting
toc: true
showdate: true
---

By default every Active Directory user must have a password that follows the domain password policy, otherwise Windows complains:

![b2bdbead2d90de0d9f01692e551a9346.png](/images/PASSWD/PASSWD1.png)

There is however a bit flag in the [userAccountControl](https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties) attirbute called PASSWD_NOTREQD (bit n. 32), when set it allows users to set a blank password, thus completely bypassing the password policy.

This is not uncommon especially in large environments, where some accounts are made passwordless for convenience. While it may be convenient for administrators this is also extremely convenient for attackers, who can take control of such accounts with no effort.

## User Accounts

This is how we would give a user a blank password in PowerShell, notice the lack of asterisks when the password gets prompted:

![ffaaef909d70b31fcc239901ee4a96ab.png](/images/PASSWD/PASSWD2.png)

Now the user mmario can authenticate to the domain without specifying a password:

![5be4e34f47bc4f965d1c2eb24904d300.png](/images/PASSWD/PASSWD3.png)

Sometimes users are automatically given the PASSWD_NOTREQD flag when tools other than ADUC are used, for example adding a new user from ADSI Edit will create a passwordless disabled user:

![7ae08ef37732c323da546c1279e1c713.png](/images/PASSWD/PASSWD4.png)

Plus, as mentioned by [Tim Wanierke](https://activedirectoryfaq.com/2013/12/empty-password-in-active-directory-despite-activated-password-policy/), the bit flag will get set if user accounts are created programmatically using these methods:
-  IADsContainer.Create
-  IADs.Put
-  IADs.SetInfo 

Migrating a domain from Windows NT4 will also set the bit on some users. For this reason a domain might contain users with PASSWD_NOTREQD set even though the admins never enabled it themselves, so double check even if you never used this feature.

Now, a user with PASSWD_NOTREQD set doesn't necessarily have a blank password, it only means they CAN have it if they want to. Regardless, looking for this property when doing domain enumeration can result in acquiring a new account so it's always a good idea to check. The following are a few ways to identify accounts with PASSWD_NOTREQD.

AD PowerShell module:
```powershell
Get-ADUser -Filter {PasswordNotRequired -eq $true -and Enabled -eq $true} | Select SamAccountName
```

![29fe31e642d34794f8ce45bdd42e0e25.png](/images/PASSWD/PASSWD5.png)

PowerView:
```powershell
Get-DomainUser -UACFilter PASSWD_NOTREQD | Select-Object samaccountname
```

LDAP query:
```text
(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))
```

ldapsearch:
```text
ldapsearch -LLL -x -H ldap://192.168.0.100 -D '<user@domain>' -w '<password>' \
'(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))' \
-b "<domainDN>" sAMAccountName | grep sAMAccountName
```

![9890e7cfa94225daffcd5a4f627cba96.png](/images/PASSWD/PASSWD6.png)

Query to include computers too:
```text
(userAccountControl:1.2.840.113556.1.4.803:=32)
```

![cdce013ac616d0d965c212787107efda.png](/images/PASSWD/PASSWD7.png)

BloodHound Cypher query:
```cypher
MATCH (u:User) WHERE u.passwordnotreqd = true RETURN u.samaccountname
```


![375046ae2a8fd0709381324a2186dc05.png](/images/PASSWD/PASSWD8.png)

---

## Computer Accounts

PASSWD_NOTREQD will be set in computer accounts too under some circumstances:

![0aa6e427d2f8ea9ebb4c0f0d39d1bc01.png](/images/PASSWD/PASSWD9.png)

These are the possibilitiea I am aware of:
- if a computer is created by a domain join or with New-ADComputer, PASSWD_NOTREQD is NOT set and a randomly generated password is assigned to it (New-ADComputer can set it if desired, but read below)
- if a computer is created from ADUC, PASSWD_NOTREQD is set but the account is given a randomly generated password
- if created using ADSI Edit, PASSWD_NOTREQD is set and the account is given an empty password, however the account can't be used without changing the password first and the account is disabled
- if dsadd.exe is used PASSWD_NOTREQD is set, plus the computer is given a blank password and is enabled!

dsadd.exe comes builtin with Windows so it's a common tool used by administrators, computer accounts are added to the domain with *dsadd computer* and specifying the new account's distinguished name:

![c2128bff20ae325d3f046d89ded5b2a8.png](/images/PASSWD/PASSWD10.png)

The account is enabled and PASSWD_NOTREQD is set, and on top of that we can verify its password is blank:

![72c0a087c66246f99638945a283ee489.png](/images/PASSWD/PASSWD11.png)

ADSI Edit creates passwordless computer accounts too, also it does not automatically append the dollar sign to its name. The account is disabled upon creation, but even when enabled manually it cannot be used without changing the password first:

![97fbcafe13b70143efc716d8e0f7c3da.png](/images/PASSWD/PASSWD12.png)

The same error message is given when trying to login through RPC, which makes it impossible to change the computer's password remotely. As far as I know there are no ways to bypass this limitation.

Basically, if you ever use automated tools to create computer objects it's possible that your domain contains password-protected computers with PASSWD_NOTREQD at best, and enabled passwordless computers at worst. Make sure to remove the flag from every one:
```powershell
Get-ADCompuer -Filter {PasswordNotRequired -eq $true} | Set-ADCompuer -PasswordNotRequired $false
```

**References**
- https://northwave-cybersecurity.com/threat-intel-research/abusing-empty-passwords-during-your-next-red-teaming-engagement
- https://www.trustedsec.com/blog/diving-into-pre-created-computer-accounts/
- https://learn.microsoft.com/en-us/powershell/module/activedirectory/new-adcomputer?view=windowsserver2022-ps
- https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties