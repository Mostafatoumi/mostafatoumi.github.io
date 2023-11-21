---
layout: post
title: Active Directory Mastery - A Guide to Windows Server Setup for Penetration Testing
date: 2022-11-20 07:00:00 -500
categories: [Ethical Hacking,AD DC]
tags: [Active Directory]
image: lab_01.png
img_path: /assets/img/favicons/HackTheBox/ADDC-LAB/
---

**Setting Up a Windows Server for Penetration Testing with Active Directory**

## **<strong><font color="Brown">1. Introduction</font></strong>**
### **<strong><font color="DarkCyan">Overview of the blog's purpose</font></strong>**

Welcome to the Active Directory Pentesting Blog, your ultimate guide for constructing a robust and secure Windows Server environment crafted specifically for penetration testing. Whether you're a beginner or an experienced professional, this blog aims to offer a comprehensive guide to help you build your own penetration testing lab

### **<strong><font color="DarkCyan">Importance of a controlled environment for penetration testing</font></strong>**
In the realm of cybersecurity, the significance of a controlled environment for penetration testing cannot be overstated. A controlled environment provides a safe and isolated space where ethical hackers, security professionals, and enthusiasts can simulate real-world cyber threats without compromising the integrity of live systems. Here's why it matters:

* `Risk Mitigation` :

Enables safe exploration without the risk of damaging live systems.
* Realistic Scenarios:

Mimics real-world conditions, providing a close-to-reality testing environment.
* `Skill Development` :

Offers a hands-on learning ground for system administration, network security, and ethical hacking.
* `Confidentiality and Compliance` :

Protects sensitive data, ensuring compliance with regulatory requirements.
* `Iterative Testing` :

Facilitates continuous improvement by refining strategies based on test outcomes.
* `Ethical Practices` :

Promotes ethical and responsible hacking, emphasizing constructive use of hacking skills.

## **<strong><font color="Brown">2. Lab Setup</font></strong>**
### **<strong><font color="DarkCyan">Hardware and software requirements.</font></strong>**

To establish a robust penetration testing lab with Windows Server 2012 as the Active Directory Domain Controller (AD DC) server, Windows 10 as the client machine, and Kali Linux for attacking, ensure your hardware and software meet the following requirements:

### **<strong><font color="DarkCyan">Hardware Requirements:</font></strong>**

* Server Machine (Windows Server 2012 r2):

| Component  | Specification  |
| ----------- | ----------- |
|`Processor`| Dual-core processor or higher.|
|`RAM`| 2 GB or more.|
|`Storage`| 50 GB or more for the operating system and additional space for virtual machines.|

* Client Machine (Windows 10):

| Component  | Specification  |
| ----------- | ----------- |
|`Processor`| Dual-core processor or higher.|
|`RAM`| 2 GB or more.|
|`Storage`| 30 GB or more for the operating system and applications.|

* Attacking Machine (Kali Linux):

| Component  | Specification  |
| ----------- | ----------- |
|`Processor`| Dual-core processor or higher.|
| `RAM` | 2 GB or more.|
|`Storage`| 30 GB or more for the operating system and tools.|


### **<strong><font color="DarkCyan">Software Requirements:</font></strong>**

* Windows Server 2012 R2 : 

You can Download ISO of Windows SERVER 2012 r1 from  [here](https://info.microsoft.com/ww-landing-windows-server-2012-R2.html?lcid=fr) 

* Windows 10:

You can Download Windows 10 from [here](https://www.microsoft.com/fr-fr/software-download/windows10) 

* Kali Linux:

Choose any OS for penetration testing; I recommend using [Kali linux](https://www.kali.org/get-kali/#kali-installer-images)  for optimal results.


### **<strong><font color="DarkCyan">Virtualization Platform:</font></strong>**

Choose a virtualization platform like [VMware Workstation Pro](https://www.vmware.com/fr/products/workstation-pro/workstation-pro-evaluation.html) or [VirtualBox](https://www.virtualbox.org/wiki/Downloads) for creating and managing virtual machines.


## **<strong><font color="Brown">3. Basic Configuration</font></strong>**

### **<strong><font color="DarkCyan">Configuration script</font></strong>**

Windows Server 2012 r2 :

| Component  | Specification  |
| ----------- | ----------- |
| `MACHINE NAME` | SRV-1 |
| `IPv4 Address` | 10.10.10.10/8 |
|`Mask`|255.0.0.0|
|`DNS`|127.0.0.1 (We will make changes to this in part 2 as we need to create a DNS server)|
|`ANTIVIRUS`|<span style="color:green">ENABLE </span>|
|`FIREWALL`|<span style="color:red">DISABLE</span>|


Why disable the firewall? Because the firewall might block ICMP connections between the host server and the client, as well as the client to the server. Alternatively, you would have to allow these ports through the firewall settings

Windows 10 (clients) and kali linux :

For simplicity, we will assign the following IP addresses: Client 1 - 10.10.10.20, Client 2 - 10.10.10.30, and Kali Linux - 10.10.10.40

*<span style="color:red"> Note </span>: The DNS and default gateway will be set to the server's address, which is 10.10.10.10.*

I think that is clear. Now, let's configure this setup



### **<strong><font color="DarkCyan">Adding Second Interface in VMware</font></strong>**
After installing Windows Server 2012, Windows 10, and Kali Linux, the next step is to configure the network. Create a second bridged virtual network adapter directed to the second card and add it to the Virtual Machine. Why? This is done to isolate this LAN segment, enabling seamless communication among these machines. The first interface ensures internet connectivity for downloading or upgrading system components.

To add a new network adapter, navigate to `Settings of SRV Machine  > click add` (make sure the first interface is `NAT` for Internet connection) 

![vm interface](interface_config_01.png)

Select `Network Adapter` and click `Finish` 

![vm interface](interface_config_02.png)
Create a LAN Segment called 'LAB.LOCAL'
![vm interface](interface_config_03.png)
Link This LAN segment with the second interface 
![vm interface](interface_config_04.png)

*<span style="color:red"> Note </span>: You can follow the same previous steps for all machines.*

### Configuring networking (static IP, DNS settings).</font></strong>**

Windows Server 2012 r2 :

By default Ethenet0 is the first interface and the second interface that we added is Ethernet1 . 
To set a static IP for Ethernet1 in Windows using CMD, you can use the following commands (`win + R` & `cmd` ):

![WIN + R](WIN-R.png)

```powershell
#IP Address
netsh interface ipv4 set address name="Ethernet1" static 10.10.10.10 255.0.0.0 10.10.10.1
#DNS
netsh interface ipv4 set dns name="Ethernet1" static 127.0.0.1

#Changeing Name of Machine
netdom renamecomputer %COMPUTERNAME% /newname:SRV-1 /reboot:0
```
![interface Eth1 SRV-1](Interface-SRV-1.png)

```powershell
#To disable Firewall
netsh advfirewall set allprofiles state off
#If you want to enable it later
netsh advfirewall set allprofiles state on

```
![firewall](firewall-SRV-1.png)

Windows 10 (Clinet-1 & Clinet-2):

- Client-1 :

```powershell
#IP Address
netsh interface ipv4 set address name="Ethernet1" static 10.10.10.20 255.0.0.0 10.10.10.10

#DNS (address of AD server)
netsh interface ipv4 set dns name="Ethernet1" static 10.10.10.10

# Changing Name of Machine
netdom renamecomputer %COMPUTERNAME% /newname:user-2 /reboot:0

#To disable Firewall
netsh advfirewall set allprofiles state off
#If you want to enable it later
netsh advfirewall set allprofiles state on
```
- Client-2 :

```powershell
#IP Address
netsh interface ipv4 set address name="Ethernet1" static 10.10.10.30 255.0.0.0 10.10.10.10

#DNS (address of AD server)
netsh interface ipv4 set dns name="Ethernet1" static 10.10.10.10

# Changing Name of Machine
netdom renamecomputer %COMPUTERNAME% /newname:user-1 /reboot:0

#To disable Firewall
netsh advfirewall set allprofiles state off
#If you want to enable it later
netsh advfirewall set allprofiles state on
```

* Kali Linux : 

```bash
# IP Address
sudo ifconfig eth1 10.10.10.40 netmask 255.0.0.0
# DNS
sudo ip route add default via 10.10.10.10 dev eth1
# Activate The Interface 
sudo ip link set eth1 up
```

### **<strong><font color="DarkCyan">Testing The connectivity</font></strong>**

We have completed the basic configuration of the machines and the necessary settings. Now, it's time to test the connectivity, ensuring it works both from the server to the client and from the client to the server.

* From Kali linux to SRV1 :

The connection is successful between Kali Linux (attacker) and SRVE-1 (Windows Server 2012)

![PING TEST ](kali-To-SRV-1.png)

* From SRV1 To Kali:

It's fine too

![PING TEST ](SRV-1-To-Kali.png)

*<span style="color:red"> Note </span>: If the connectivity fails, check the firewall settings as mentioned earlier.*

You can follow the same steps to check the connectivity between the clients and SRVE-1, as well as with Kali Linux.

### **<strong><font color="DarkCyan">Finall Diagram :</font></strong>**

![Lab](diagram_02.png)

## **<strong><font color="Brown">5. Active Directory Domain Controller Setup</font></strong>**

   - Installing the Active Directory Domain Services role.
   - Promoting the server to a domain controller.
   - Creating the domain and forest.

## **<strong><font color="Brown">6. User and Group Management</font></strong>**

   - Adding users and groups to the domain.
   - Assigning appropriate permissions.

## **<strong><font color="Brown">7. Group Policy Configuration</font></strong>**

   - Creating and applying Group Policies for security.
   - Implementing password policies.

## **<strong><font color="Brown">8. Adding Machines to the Domain</font></strong>**

   - Configuring client machines to join the domain.
   - Troubleshooting common issues.

## 9. Networking Considerations
   - Configuring firewalls and network policies.
   - Port configurations for domain communication.

## 10. Security Best Practices
    - Guidelines for securing your Windows Server environment.
    - Regular updates and patch management.

## 11. Pentesting Tools Installation
    - Installing common penetration testing tools (Metasploit, Wireshark, etc.).
    - Configuring firewall rules for testing.

## 12. Logging and Monitoring
    - Setting up logs for security events.
    - Monitoring tools for tracking activities.

## 13. Conclusion
    - Recap of the key steps and considerations.
    - Encouragement for responsible and ethical use of the lab.
