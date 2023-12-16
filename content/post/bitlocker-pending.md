---
title: "Decrypting Pending BitLocker Partitions"
date: 2023-12-16T01:00:01+02:00
tags:
  - active-directory
  - windows
showdate: true
---

Twice in a row now I encountered BitLocker installations noted as "pending", requiring to be activated despite the disk already being encrypted. This is what they would look like from the control panel:

![44ac01d42ae1138845a344d47f86b9c7.png](/_resources/44ac01d42ae1138845a344d47f86b9c7.png)

The C disk didn't even appear encrypted at all from Explorer:

![79e0419916d8e517e896602056734e5a.png](/_resources/79e0419916d8e517e896602056734e5a.png)

This happened to me while doing a client computer assessment, where we were tasked with taking a sample laptop that an employee would use and see if it was possible to circumvent AV/EDR software, escalate privileges, read data on the disk, and later use the computer as an entry point in the corporate network.

The plan was to launch a live Linux distro or a Windows restore ISO and rename the EDR installation folders: that way Windows wouldn't have found the service executables anymore, leaving the system unprotected.

Obviously we needed BitLocker out of the way for this to work, so we had to check its status and if found enabled we would try to disable it and decrypt the disk. Indeed, the disk was encrypted but it appeared as shown above, so we did some Googling and found some pretty interesting info.

In order to encrypt and decrypt data in a drive BitLocker generates a Full Volume Encryption Key (**FVEK**), this is in turn protected by a different key, the Volume Master Key (**VMK**), which encrypts the FVEK and stores it in the volume metadata.

The VMK on the other hand can be protected in many ways: either by storing it on a TPM, protecting it with a PIN or password, copying it on a USB drive, uploading it to Azure, etc... Either way, the result of any one of these methods is a protected VMK, all these methods are called Key Protectors (**KP**).

![e960a899a305b8ff0cc6743b5920f988.png](/_resources/e960a899a305b8ff0cc6743b5920f988.png)

Ever since version 8.1 Windows has been shipping with BitLocker enabled by default on computers supporting [Modern Standby](https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/modern-standby) or that are [HSTI compliant](https://learn.microsoft.com/en-us/windows-hardware/test/hlk/testref/hardware-security-testability-specification). Now, despite BitLocker being enabled right after installation, it doesn't necessarily know which key protectors you may want to use. This means that by default BitLocker will be encrypting the volume like normal, but it won't be using any key protectors out of the box so that users can configure their preferred method. This is what the aforementioned "activation" is.

There's only one problem: this leaves the VMK completely exposed! Without a default KP the VMK is just sitting there waiting to be snatched, which of course would result in the decryption of the entire disk as it would allow for the decryption of the FVEK. This leaves a lot of default BitLocker installations to be essentially useless against any attacker with knowledge of this quirk.

All we need to do to decrypt the disk is use the standard BitLocker CLI utility, `manage-bde`, to find the VMK for us and use it to do its magic. Normally the utility can only be used by an administrator but this is easily bypassed with a Windows restore ISO, open a CMD window by holding Shift+F10 and we are all set.

![3736c6c997f97d9cb63095f3319d1766.png](/_resources/3736c6c997f97d9cb63095f3319d1766.png)

Start by issuing `manage-bde -status`

![6c0648d51f4a2051709b3fb7b2b7976f.png](/_resources/6c0648d51f4a2051709b3fb7b2b7976f.png)

The output clearly tells us we have an encrypted but unprotected drive due to a lack of KPs. This conferms we can simply decrypt the drive and get rid of BitLocker altogether: `manage-bde -off c:`

![85d3b68b2fd1eb48d057a7b75c3e457b.png](/_resources/85d3b68b2fd1eb48d057a7b75c3e457b.png)

After issuing this command the decryption process will begin and we can monitor it with `manage-bde -status`. After a few (or a lot, depending on disk size) minutes the status command will show us this message:

![fb4d5b1afea8a0fa2b4183858217792a.png](/_resources/fb4d5b1afea8a0fa2b4183858217792a.png)

We now have full read and write permissions on the drive. We used this to rename the installation folders of security products and then created a copy of cmd.exe in `C:\Windows\System32\Utilman.exe`.

![45933ff74b784fbee4d0467abf72d1cf.png](/_resources/45933ff74b784fbee4d0467abf72d1cf.png)

![1e7585bd11b842b6221cec6990de13ba.png](/_resources/1e7585bd11b842b6221cec6990de13ba.png)

This little trick allows us to open a cmd window as SYSTEM without having any credentials, just by clicking on the accessibility icon on the login screen.

![238dfe2af5ca82faf5298b5a248d1de6.png](/_resources/238dfe2af5ca82faf5298b5a248d1de6.png)

From here we created a local admin user and used it to login, obtaining complete access on the machine.

```text
net user EvilAdmin EvilPass!1 /add
net localgroup Administrators EvilAdmin /add
```

What we can learn from this is that default BitLocker installations should always be double checked to make sure there are key protectors configured to encrypt the VMK, otherwise anyone with physical access to the machine can bypass the encryption with a simple USB stick and no credentials. One could also consider adding a strong BIOS password and disabling boot from anywhere but the internal drive, but that won't stop anyone from just unplugging the hard drive.

**References**
- https://superuser.com/questions/1299600/is-a-volume-with-bitlocker-waiting-for-activation-encrypted-or-not
- https://community.spiceworks.com/how_to/150987-access-windows-partition-in-linux-bitlocker-suspended
- https://security.stackexchange.com/questions/213184/how-does-windows-use-the-tpm-for-bitlocker-encryption-without-an-attacker-being