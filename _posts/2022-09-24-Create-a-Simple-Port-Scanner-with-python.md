---
layout: post
title: How to Create a Simple Port Scanner With Python
date: 2022-09-24 07:00:00 -500
categories: [Ethical Hacking,python]
tags: [python]
image:
  path: /assets/img/headers/Port_scanner.webp
---

***
<center><strong><font color="DarkGray">Port scanning is a scanning method for determining which ports on a network device are open, whether it's a server, a router, or a regular machine. A port scanner is just a script or a program that is designed to probe a host for open ports.</font></strong></center>

<center><strong><font color="DarkGray">In this tutorial, you will be able to make your own port scanner in Python using the socket library. The basic idea behind this simple port scanner is to try to connect to a specific host (website, server, or any device connected to the Internet/network) through a list of ports. If a successful connection has been established, that means the port is open.</font></strong></center>

<center><strong><font color="DarkGray">For instance, when you loaded this web page, you made a connection to this website on port 80. Similarly, this script will try to connect to a host but on multiple ports. These kinds of tools are useful for hackers and penetration testers, so don't use this tool on a host that you don't have permission to test!</font></strong></center>


***
## **<strong><font color="Brown">EnumerSimple Port Scanneration</font></strong>**
***

### **<strong><font color="DarkCyan">Requirements</font></strong>**
To get started, let's install the required libraries:
* Optionally, you need to install colorama module for printing in colors

```bash
pip3 install colorama
```

### **<strong><font color="DarkCyan">Librairies</font></strong>**
First, let's start by making a simple port scanner. Let's import the socket module:

```python
import socket # for connecting
from colorama import init, Fore

# some colors
init()
GREEN = Fore.GREEN
RESET = Fore.RESET
GRAY = Fore.LIGHTBLACK_EXa
```
* Note:```socket```module is already installed on your machine, it is a built-in module in the Python standard library, so you don't have to install anything.


The socket module provides us with socket operations, functions for network-related tasks, etc. They are widely used on the Internet, as they are behind any connection to any network. Any network communication goes through a socket. More details are in the official Python documentation.


We will use ```colorama``` here just for printing in green colors whenever a port is open, and gray when it is closed.



### **<strong><font color="DarkCyan">Start Coding</font></strong>**
Let's define the function that is responsible for determining whether a port is open:


```python
def is_port_open(host, port):
    """
    determine whether `host` has the `port` open
    """
    # creates a new socket
    s = socket.socket()
    try:
        # tries to connect to host using that port
        s.connect((host, port))
        # make timeout if you want it a little faster ( less accuracy )
        # s.settimeout(0.2)
    except:
        # cannot connect, port is closed
        # return false
        return False
    else:
        # the connection was established, port is open!
        return True
```

* ```s.connect((host, port))``` function tries to connect the socket to a remote address using the (host, port) tuple, it will raise an exception when it fails to connect to that host, that is why we have wrapped that line of code into a try-except block, so whenever an exception is raised, that's an indication for us that the port is actually closed, otherwise it is open.

Now let's use the above function and iterate over a range of ports:


```python
# get the host from the user
host = input("Enter the host:")
# iterate over ports, from 1 to 1024
for port in range(1, 1025):
    if is_port_open(host, port):
        print(f"{GREEN}[+] {host}:{port} is open      {RESET}")
    else:
        print(f"{GRAY}[!] {host}:{port} is closed    {RESET}", end="\r")
```

The above code will scan ports ranging from 1 all the way to 1024, you can change the range to 65535 if you want, but that will take longer to finish.

When you try to run it, you'll immediately notice that the script is quite slow. Well, we can get away with that if we set a timeout of 200 milliseconds or so (using ```settimeout(0.2)``` method). However, this actually can reduce the accuracy of the reconnaissance, especially when your latency is quite high. As a result, we need a better way to accelerate this.

### **<strong><font color="DarkCyan">Conclusion</font></strong>**

Port scanning proves to be useful in many cases. An authorized penetration tester can use this tool to see which ports are open and reveal the presence of potential security devices such as firewalls, as well as test the network security and the strength of a device.

<center><strong><font color="DarkGray">Happy Scanning :) </font></strong></center>

