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

## **<strong><font color="Brown">1. Introduction </font></strong>**
### **<strong><font color="DarkCyan">Overview of the blog's purpose :</font></strong>**

Welcome to the Active Directory Pentesting Blog, your ultimate guide for constructing a robust and secure Windows Server environment crafted specifically for penetration testing. Whether you're a beginner or an experienced professional, this blog aims to offer a comprehensive guide to help you build your own penetration testing lab

### **<strong><font color="DarkCyan">Importance of a controlled environment for penetration testing :</font></strong>**
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
### **<strong><font color="DarkCyan">Hardware and software requirements :</font></strong>**

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


### **<strong><font color="DarkCyan">Software Requirements :</font></strong>**

* Windows Server 2012 R2 : 

You can Download ISO of Windows SERVER 2012 r1 from  [here](https://info.microsoft.com/ww-landing-windows-server-2012-R2.html?lcid=fr) 

* Windows 10 :

You can Download Windows 10 from [here](https://www.microsoft.com/fr-fr/software-download/windows10) 

* Kali Linux :

Choose any OS for penetration testing; I recommend using [Kali linux](https://www.kali.org/get-kali/#kali-installer-images)  for optimal results.


### **<strong><font color="DarkCyan">Virtualization Platform :</font></strong>**

Choose a virtualization platform like [VMware Workstation Pro](https://www.vmware.com/fr/products/workstation-pro/workstation-pro-evaluation.html) or [VirtualBox](https://www.virtualbox.org/wiki/Downloads) for creating and managing virtual machines.


## **<strong><font color="Brown">3. Basic Configuration </font></strong>**

### **<strong><font color="DarkCyan">Configuration script :</font></strong>**

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



### **<strong><font color="DarkCyan">Adding Second Interface in VMware :</font></strong>**
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

### **<strong><font color="DarkCyan">Configuring networking (static IP, DNS settings).</font></strong>**

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
netdom renamecomputer %COMPUTERNAME% /newname:user-1 /reboot:0

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
netdom renamecomputer %COMPUTERNAME% /newname:user-2 /reboot:0

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

### **<strong><font color="DarkCyan">Testing The connectivity :</font></strong>**

We have completed the basic configuration of the machines and the necessary settings. Now, it's time to test the connectivity, ensuring it works both from the server to the client and from the client to the server.

* From Kali linux to SRV1 :

The connection is successful between Kali Linux (attacker) and SRVE-1 (Windows Server 2012)

![PING TEST ](kali-To-SRV-1.png)

* From SRV1 To Kali:

It's fine too

![PING TEST ](SRV-1-To-Kali.png)

*<span style="color:red"> Note </span>: If the connectivity fails, check the firewall settings as mentioned earlier.*

You can follow the same steps to check the connectivity between the clients and SRVE-1, as well as with Kali Linux.

### **<strong><font color="DarkCyan">Diagram :</font></strong>**

![Lab](diagram_02.png)

## **<strong><font color="Brown">5. Active Directory Domain Controller Setup</font></strong>**

### **<strong><font color="DarkCyan">Installing the Active Directory Domain Services role :</font></strong>**

While Windows Server 2012 provides a graphical user interface (GUI) method for adding features such as the Active Directory module, we'll take a detour and explore the command-line prowess of PowerShell. Why? Because embracing PowerShell not only enhances your scripting skills but also offers a more efficient and scalable way to manage and automate tasks. So, let's skip the GUI this time and dive into the powerful world of PowerShell for our Active Directory module installation.

| Component  | Specification  |
| ----------- | ----------- |
|`Domain Name`|DC.LAB.LOCAL|
|`Password` |Pen_lab@2023!|

- **Open PowerShell as Administrator**

Right-click on the PowerShell icon and choose `Run as Administrator` to ensure elevated privileges.

- **Install the Active Directory Module**

```powershell
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
```
![install AD ](AD_installation.png)

- **Creating the domain and forest.**

So, the domain name will be `dc.lab.local`, and the password is `Pen_lab@2023!`. The domain installation process may take from 2 to 5 minutes. During the installation, PowerShell will prompt you to restart the machine. Choose `Y` or `Yes` and wait until the installation completes and the machine reboots

```powershell
Install-ADDSForest -DomainName dc.lab.local -InstallDNS
```

![creating domain](creating_domain.png)

After the machine reboots, the name of our domain will appear in `Server Manager` under `Local Server` :

![info domain](info_domain.png)

checking by `Get-ADdoamin` command, This will show you information about your new `Domain` :

![Get-addoamin](get-addomain.png)

Now, everything looks great. We have successfully created our domain `dc.lab.local`. Let's move on to the user and group management section.

## **<strong><font color="Brown">6. User and Group Management</font></strong>**

### **<strong><font color="DarkCyan">Adding users and groups to the domain :</font></strong>**

Now that our `Active Directory` is up and running, let's dive into user and group management—a crucial aspect of network security. In this scenario, imagine we're setting up a lab for a fictional organization called `"TechSecure Corp."`

### **<strong><font color="DarkCyan">User Creation :</font></strong>**

   - **`User 1` : Alice Green**
      - *`Username` :* alice.green
      - *`Role` :* Junior Administrator
   - **`User 2` : Bob Smith**
      - *`Username` :* bob.smith
      - *`Role` :* Developer
   - **`User 3`: Emma White**
      - *`Username` :* emma.white
      - *`Role` :* QA Tester

```powershell
# Create Users
New-ADUser -Name "Alice Green" -SamAccountName "alice.green" -UserPrincipalName "alice.green@techsecure.local" -Title "Junior Administrator" -Enabled $true -AccountPassword (ConvertTo-SecureString -AsPlainText "Alice@2023!" -Force)
New-ADUser -Name "Bob Smith" -SamAccountName "bob.smith" -UserPrincipalName "bob.smith@techsecure.local" -Title "Developer" -Enabled $true -AccountPassword (ConvertTo-SecureString -AsPlainText "Bob@2023!" -Force)
New-ADUser -Name "Emma White" -SamAccountName "emma.white" -UserPrincipalName "emma.white@techsecure.local" -Title "QA Tester" -Enabled $true -AccountPassword (ConvertTo-SecureString -AsPlainText "Emma@2023!" -Force)

```

### **<strong><font color="DarkCyan">Organizing Users into Groups :</font></strong>**

   - **Group 1 : Admins**
      - *`Members` :* Alice Green
      - *`Permissions` :* Full administrative access to servers and Active Directory.
   - **Group 2 : Developers**
      - *`Members` :* Bob Smith
      - *`Permissions` :* Access to development resources and shared project folders.
   - **Group 3 : Testers**
      - *`Members` :* Emma White
      - *`Permissions` :* Limited access to testing environments and relevant resources.

```powershell
# Create Groups
New-ADGroup -Name "Admins" -GroupScope Global -GroupCategory Security
New-ADGroup -Name "Developers" -GroupScope Global -GroupCategory Security
New-ADGroup -Name "Testers" -GroupScope Global -GroupCategory Security
```

```powershell
# Add Users to Groups
Add-ADGroupMember -Identity "Admins" -Members "alice.green"
Add-ADGroupMember -Identity "Developers" -Members "bob.smith"
Add-ADGroupMember -Identity "Testers" -Members "emma.white"
```

![users](AD_users.png)
### **<strong><font color="DarkCyan">Assigning Appropriate Permissions :</font></strong>**

##### **File Server Permissions :**
   - **Shared Project Folder :**
      - *`Group Access` :* Developers have read/write access; Testers have read-only access.
   - **Admin Access :**
      - *`Administrators` :* Full control over shared resources.

##### **Active Directory Permissions :**
   - **Admin Group:**
      - *`Admins Group` :* Full control over Active Directory settings.
   - **User Management :**
      - *`Developers Group`:* Limited user management capabilities for their team members.
      - *`Testers Group`:* Basic user information access for their team members.



```powershell

# Note  : This is a simplified example. In a real-world scenario, you would replace placeholders with actual file paths and server details.*

#Assume shared project folder is located at `"C:\SharedProjects"`

$projectFolderPath = "C:\SharedProjects"
$adminsGroup = Get-ADGroup -Filter {Name -eq "Admins"}
$developersGroup = Get-ADGroup -Filter {Name -eq "Developers"}
$testersGroup = Get-ADGroup -Filter {Name -eq "Testers"}

# Grant permissions on the shared project folder
# Administrators have full control
icacls $projectFolderPath /grant "$($adminsGroup.Name):(F)"
# Developers have read/write access
icacls $projectFolderPath /grant "$($developersGroup.Name):(R,W)"
# Testers have read-only access
icacls $projectFolderPath /grant "$($testersGroup.Name):(R)"

# Assign Active Directory Permissions
# Assume AD paths for user management and admin group
$userManagementPath = "OU=Users,DC=dc,DC=lab,DC=local"
$adminGroupPath = "CN=Admins,OU=Groups,DC=dc,DC=lab,DC=local"
```

### **<strong><font color="DarkCyan">Real-world Application :</font></strong>**

**Scenario:* Alice, a Junior Administrator, needs to create user accounts for new developers joining the team. She adds them to the Developers group, granting them the necessary permissions on the file server. Meanwhile, Bob, a Developer, requires access to project-related resources, which is facilitated through his group membership.*

This scenario provides a glimpse into how user and group management in Active Directory plays out in a practical setting. Stay tuned as we explore the dynamic realm of `Group Policy Configuration` in the upcoming blog post! 

### **<strong><font color="DarkCyan">Diagram :</font></strong>**

![Diagram 2](diagram_03.png)



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
