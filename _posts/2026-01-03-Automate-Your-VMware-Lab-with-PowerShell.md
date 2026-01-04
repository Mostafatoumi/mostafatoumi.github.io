---
layout: post
title: "Automate Your VMware Lab with PowerShell"
date: 2026-01-03 22:36:00 -500
categories: [Automation Scripts]
tags: [Automation Scripts]
image:
  path: /assets/img/headers/vmware-lab-automation.webp
---

### Managing VMware Workstation with PowerShell and vmrun

In many home labs, security labs, and development environments, **VMware Workstation** is the backbone of daily work. Most users rely on the GUI, but once your number of virtual machines grows, clicking through menus quickly becomes inefficient. This is where **PowerShell automation with `vmrun`** shines.

This article walks through practical, real-world techniques for managing VMware Workstation entirely from PowerShell. Everything here is based on hands-on usage: starting and stopping VMs, interacting with the guest OS, collecting output, and building small automation utilities that scale well for labs and testing environments.

---

### Why Manage VMware from PowerShell?

Using PowerShell instead of the GUI gives you repeatability and control. Once a task is scripted, it becomes deterministic and fast. This is especially useful for:

- Rapidly spinning up or shutting down multiple lab machines
- Headless VM operation for performance and automation
- Running commands inside guest systems without manual login
- Collecting artifacts such as IP addresses, logs, or screenshots
- Building repeatable red-team / blue-team lab workflows

PowerShell turns VMware Workstation from a click-driven tool into a fully controllable hypervisor platform.

---

### Preparing the Environment

VMware Workstation includes a CLI tool called `vmrun.exe`. To make it available in PowerShell, add it to your system PATH:

```powershell
setx PATH "$env:PATH;C:\Program Files (x86)\VMware\VMware Workstation"
```

After reopening your terminal, verify access:

```powershell
PS C:\Users\emsec-pc> vmrun

vmrun version 1.17.0.24995812

Usage: vmrun [AUTHENTICATION-FLAGS] COMMAND [PARAMETERS]



AUTHENTICATION-FLAGS
--------------------
These must appear before the command and any command parameters.

   -T <hostType> (ws|fusion||player)
   -vp <password for encrypted virtual machine>
   -gu <userName in guest OS>
   -gp <password in guest OS>
```

If the help menu appears, your environment is ready. You can see available authentication flags, commands, and options for interacting with your VMs.

---

### Listing and Controlling Virtual Machines :

You can list all currently running virtual machines with a single command:

```powershell
PS C:\Users\emsec-pc> vmrun list
Total running VMs: 0
PS C:\Users\emsec-pc>
```

To start a VM:

```powershell
vmrun start "C:\VM\Win10\Windows 10 x64.vmx"
```
![alt text](/assets/img/posts/vmware-lab-automation/image.png)

We can run the VM in the background without a GUI, which is ideal for automation and saves system resources, simply by adding the nogui option:

```powershell
vmrun start "C:\VM\Win10\Windows 10 x64.vmx" nogui
```

In the same way, we can stop a VM gracefully (soft shutdown):

```powershell
vmrun stop "C:\VM\Win10\Windows 10 x64.vmx" soft
```

![alt text](/assets/img/posts/vmware-lab-automation/image-1.png)


Suspending and resuming is often much faster than full shutdowns:

```powershell
vmrun suspend "C:\VM\Win10\Windows 10 x64.vmx"
```

You can also reset a VM when needed:

```powershell
vmrun -T ws reset "C:\VM\Win10\Windows 10 x64.vmx"
```

---

### Checking VM Status Before Actions :

Before starting or interacting with a VM, it is good practice to verify whether it is already running.

```powershell
PS C:\Users\emsec-pc> vmrun list | findstr /i "Windows 10 x64.vmx"
C:\VM\Win10\Windows 10 x64.vmx
PS C:\Users\emsec-pc>
```

This allows you to build condition-based scripts instead of blindly starting machines.

---

### Interacting with the Guest Operating System

One of the most powerful features of `vmrun` is **guest OS interaction**. As long as VMware Tools is installed, you can execute commands inside the virtual machine. This is extremely useful when you have multiple VMs running at once and need to interact with a specific VM without opening its console or manually logging in.

With `vmrun`, you can authenticate using the guest operating system’s local username and password to run commands or manage processes

Listing processes inside the guest:

```powershell
vmrun -T ws -gu pc01 -gp "Password@123!" listProcessesInGuest "C:\VM\Win10\Windows 10 x64.vmx"
```

```powershell
PS C:\Users\emsec-pc> vmrun -T ws -gu pc01 -gp "Password@123!" listProcessesInGuest "C:\VM\Win10\Windows 10 x64.vmx"
Process list: 86
pid=0, owner=, cmd=[System Process]
pid=4, owner=NT AUTHORITY\SYSTEM, cmd=System
pid=108, owner=NT AUTHORITY\SYSTEM, cmd=Registry
pid=328, owner=NT AUTHORITY\SYSTEM, cmd=smss.exe
pid=452, owner=NT AUTHORITY\SYSTEM, cmd=csrss.exe
pid=532, owner=NT AUTHORITY\SYSTEM, cmd=wininit.exe
pid=540, owner=NT AUTHORITY\SYSTEM, cmd=csrss.exe
pid=612, owner=NT AUTHORITY\SYSTEM, cmd=services.exe
pid=640, owner=NT AUTHORITY\SYSTEM, cmd=winlogon.exe
pid=672, owner=NT AUTHORITY\SYSTEM, cmd=lsass.exe
pid=820, owner=NT AUTHORITY\SYSTEM, cmd=svchost.exe
pid=848, owner=Font Driver Host\UMFD-1, cmd=fontdrvhost.exe
pid=856, owner=Font Driver Host\UMFD-0, cmd=fontdrvhost.exe
pid=944, owner=NT AUTHORITY\NETWORK SERVICE, cmd=svchost.exe
pid=988, owner=NT AUTHORITY\SYSTEM, cmd=svchost.exe
pid=384, owner=NT AUTHORITY\SYSTEM, cmd=LogonUI.exe
pid=752, owner=Window Manager\DWM-1, cmd=dwm.exe
pid=960, owner=NT AUTHORITY\SYSTEM, cmd=svchost.exe
pid=376, owner=NT AUTHORITY\SYSTEM, cmd=svchost.exe
pid=1036, owner=NT AUTHORITY\SYSTEM, cmd=svchost.exe
pid=1188, owner=NT AUTHORITY\LOCAL SERVICE, cmd=svchost.exe
pid=1196, owner=NT AUTHORITY\LOCAL SERVICE, cmd=svchost.exe
pid=1204, owner=NT AUTHORITY\LOCAL SERVICE, cmd=svchost.exe
pid=1216, owner=NT AUTHORITY\LOCAL SERVICE, cmd=svchost.exe
pid=1288, owner=NT AUTHORITY\SYSTEM, cmd=svchost.exe
pid=1304, owner=NT AUTHORITY\LOCAL SERVICE, cmd=svchost.exe
pid=1336, owner=NT AUTHORITY\SYSTEM, cmd=svchost.exe
pid=1344, owner=NT AUTHORITY\LOCAL SERVICE, cmd=svchost.exe
pid=1376, owner=NT AUTHORITY\LOCAL SERVICE, cmd=svchost.exe
pid=1436, owner=NT AUTHORITY\NETWORK SERVICE, cmd=svchost.exe
pid=1504, owner=NT AUTHORITY\SYSTEM, cmd=svchost.exe
pid=1644, owner=NT AUTHORITY\NETWORK SERVICE, cmd=svchost.exe
pid=1688, owner=NT AUTHORITY\LOCAL SERVICE, cmd=svchost.exe
pid=1708, owner=NT AUTHORITY\SYSTEM, cmd=svchost.exe
pid=1716, owner=NT AUTHORITY\LOCAL SERVICE, cmd=svchost.exe
pid=1904, owner=NT AUTHORITY\LOCAL SERVICE, cmd=svchost.exe
pid=2000, owner=NT AUTHORITY\LOCAL SERVICE, cmd=svchost.exe
pid=2008, owner=NT AUTHORITY\SYSTEM, cmd=svchost.exe
pid=2016, owner=NT AUTHORITY\SYSTEM, cmd=svchost.exe
pid=1888, owner=NT AUTHORITY\SYSTEM, cmd=Memory Compression
pid=1952, owner=NT AUTHORITY\SYSTEM, cmd=svchost.exe
pid=2112, owner=NT AUTHORITY\SYSTEM, cmd=svchost.exe
pid=2124, owner=NT AUTHORITY\LOCAL SERVICE, cmd=svchost.exe
pid=2212, owner=NT AUTHORITY\LOCAL SERVICE, cmd=svchost.exe
pid=2328, owner=NT AUTHORITY\LOCAL SERVICE, cmd=svchost.exe
pid=2404, owner=NT AUTHORITY\NETWORK SERVICE, cmd=svchost.exe
pid=2412, owner=NT AUTHORITY\SYSTEM, cmd=svchost.exe
pid=2432, owner=NT AUTHORITY\SYSTEM, cmd=svchost.exe
pid=2492, owner=NT AUTHORITY\LOCAL SERVICE, cmd=svchost.exe
pid=2516, owner=NT AUTHORITY\LOCAL SERVICE, cmd=svchost.exe
pid=2580, owner=NT AUTHORITY\SYSTEM, cmd=svchost.exe
pid=2624, owner=NT AUTHORITY\SYSTEM, cmd=svchost.exe
pid=2632, owner=NT AUTHORITY\SYSTEM, cmd=svchost.exe
pid=2776, owner=NT AUTHORITY\SYSTEM, cmd=spoolsv.exe
pid=2896, owner=NT AUTHORITY\NETWORK SERVICE, cmd=svchost.exe
pid=3016, owner=NT AUTHORITY\NETWORK SERVICE, cmd=svchost.exe
pid=3024, owner=NT AUTHORITY\SYSTEM, cmd=svchost.exe
pid=3032, owner=NT AUTHORITY\LOCAL SERVICE, cmd=svchost.exe
pid=2656, owner=NT AUTHORITY\SYSTEM, cmd=svchost.exe
pid=2724, owner=NT AUTHORITY\SYSTEM, cmd=VGAuthService.exe
pid=2980, owner=NT AUTHORITY\SYSTEM, cmd=MsMpEng.exe
pid=2712, owner=NT AUTHORITY\SYSTEM, cmd=vmtoolsd.exe
pid=3088, owner=NT AUTHORITY\SYSTEM, cmd=svchost.exe
pid=3096, owner=NT AUTHORITY\SYSTEM, cmd=vm3dservice.exe
pid=3112, owner=NT AUTHORITY\SYSTEM, cmd=svchost.exe
pid=3256, owner=NT AUTHORITY\SYSTEM, cmd=vm3dservice.exe
pid=3328, owner=NT AUTHORITY\LOCAL SERVICE, cmd=svchost.exe
pid=3412, owner=NT AUTHORITY\LOCAL SERVICE, cmd=svchost.exe
pid=3828, owner=NT AUTHORITY\SYSTEM, cmd=dllhost.exe
pid=3972, owner=NT AUTHORITY\NETWORK SERVICE, cmd=WmiPrvSE.exe
pid=3340, owner=NT AUTHORITY\SYSTEM, cmd=SearchIndexer.exe
pid=3368, owner=NT AUTHORITY\SYSTEM, cmd=svchost.exe
pid=1128, owner=NT AUTHORITY\NETWORK SERVICE, cmd=msdtc.exe
pid=4480, owner=NT AUTHORITY\LOCAL SERVICE, cmd=NisSrv.exe
pid=4508, owner=NT AUTHORITY\SYSTEM, cmd=svchost.exe
pid=4892, owner=NT AUTHORITY\SYSTEM, cmd=svchost.exe
pid=4980, owner=NT AUTHORITY\SYSTEM, cmd=WmiPrvSE.exe
pid=5024, owner=NT AUTHORITY\SYSTEM, cmd=svchost.exe
pid=5064, owner=NT AUTHORITY\LOCAL SERVICE, cmd=svchost.exe
pid=5108, owner=NT AUTHORITY\LOCAL SERVICE, cmd=svchost.exe
pid=1244, owner=NT AUTHORITY\NETWORK SERVICE, cmd=svchost.exe
pid=3296, owner=NT AUTHORITY\SYSTEM, cmd=MicrosoftEdgeUpdate.exe
pid=4360, owner=NT AUTHORITY\SYSTEM, cmd=SgrmBroker.exe
pid=1252, owner=NT AUTHORITY\SYSTEM, cmd=svchost.exe
pid=2532, owner=NT AUTHORITY\SYSTEM, cmd=svchost.exe
pid=2996, owner=NT AUTHORITY\LOCAL SERVICE, cmd=svchost.exe
PS C:\Users\emsec-pc>
```

Running a command inside the guest and saving output:

```powershell
vmrun -T ws -gu pc01 -gp "Password@123!" runProgramInGuest "C:\VM\Win10\Windows 10 x64.vmx" -interactive "C:\Windows\System32\cmd.exe" "/c ipconfig > C:\Users\pc01\Desktop\ip.txt"
```

![alt text](/assets/img/posts/vmware-lab-automation/image-2.png)


Copying files from the guest back to the host is also useful when you need to transfer files from the VM:

```powershell
vmrun -T ws -gu pc01 -gp "Password@123!" CopyFileFromGuestToHost `
"C:\VM\Win10\Windows 10 x64.vmx" `
"C:\Users\pc01\Desktop\ip.txt" `
"C:\Temp\ip_from_vm.txt"
```

![alt text](/assets/img/posts/vmware-lab-automation/image-3.png)

Capturing a screenshot of the guest VM:

```powershell
vmrun -T ws -gu pc01 -gp "Password@123!" captureScreen `
"C:\VM\Win10\Windows 10 x64.vmx" `
"C:\Users\emsec-pc\Desktop\a.png"
```

![alt text](/assets/img/posts/vmware-lab-automation/image-4.png)

Retrieving the VM IP address:

```powershell
PS C:\Users\emsec-pc\Desktop> vmrun -T ws -gu pc01 -gp "Password@123!" getGuestIPAddress "C:\VM\Win10\Windows 10 x64.vmx"
10.10.10.20
PS C:\Users\emsec-pc\Desktop>
```

Terminating a specific process inside the VM :

For example, if we want to terminate the Calculator process from the host, we can first find its process ID (PID) and then terminate it using the `killProcessInGuest` option.

![alt text](/assets/img/posts/vmware-lab-automation/image-5.png)

The PID of the Calculator program is 6760:

```powershell
vmrun -T ws -gu pc01 -gp "Password@123!" killProcessInGuest "C:\VM\Win10\Windows 10 x64.vmx" 6760
```

![alt text]/assets/img/posts/vmware-lab-automation/(image-6.png)


---

### Editing VM Configuration (.vmx Files)

VM properties like memory and CPU can be adjusted directly in the .vmx file. Always power off the VM first.

```powershell
PS C:\Users\emsec-pc\Desktop> cat "C:\VM\Win10\Windows 10 x64.vmx"
.encoding = "windows-1252"
displayName = "Win10"
config.version = "8"
virtualHW.version = "21"
mks.enable3d = "TRUE"
pciBridge0.present = "TRUE"
pciBridge4.present = "TRUE"
pciBridge4.virtualDev = "pcieRootPort"
pciBridge4.functions = "8"
pciBridge5.present = "TRUE"
pciBridge5.virtualDev = "pcieRootPort"
pciBridge5.functions = "8"
pciBridge6.present = "TRUE"
pciBridge6.virtualDev = "pcieRootPort"
pciBridge6.functions = "8"
pciBridge7.present = "TRUE"
pciBridge7.virtualDev = "pcieRootPort"
pciBridge7.functions = "8"
vmci0.present = "TRUE"
hpet0.present = "TRUE"
nvram = "Windows 10 x64.nvram"
virtualHW.productCompatibility = "hosted"
powerType.powerOff = "soft"
powerType.powerOn = "soft"
powerType.suspend = "soft"
powerType.reset = "soft"
firmware = "efi"
sensor.location = "pass-through"
guestOS = "windows9-64"
tools.syncTime = "FALSE"
sound.autoDetect = "TRUE"
sound.virtualDev = "hdaudio"
sound.fileName = "-1"
sound.present = "TRUE"
numvcpus = "4"
cpuid.coresPerSocket = "2"
memsize = "4388"
mem.hotadd = "TRUE"
sata0.present = "TRUE"
nvme0.present = "TRUE"
nvme0:0.fileName = "Windows 10 x64-000001.vmdk"
nvme0:0.present = "TRUE"
sata0:1.deviceType = "cdrom-image"
sata0:1.fileName = "C:\Users\dell\Desktop\ISO\Windows_10.iso"
sata0:1.present = "TRUE"
usb.present = "TRUE"
ehci.present = "TRUE"
usb_xhci.present = "TRUE"
svga.graphicsMemoryKB = "8388608"
ethernet0.connectionType = "pvn"
ethernet0.addressType = "generated"
ethernet0.virtualDev = "e1000e"
ethernet0.present = "TRUE"
extendedConfigFile = "Windows 10 x64.vmxf"
floppy0.present = "FALSE"
gui.lastPoweredViewMode = "fullscreen"
vmxstats.filename = "Windows 10 x64.scoreboard"
numa.autosize.cookie = "40022"
numa.autosize.vcpu.maxPerVirtualNode = "4"
uuid.bios = "56 4d 97 43 fa f2 27 61-f5 da 79 65 e2 91 a3 08"
uuid.location = "56 4d 4a 1a d3 98 f8 0f-55 14 08 80 ca ad 08 54"
pciBridge0.pciSlotNumber = "17"
pciBridge4.pciSlotNumber = "21"
pciBridge5.pciSlotNumber = "22"
pciBridge6.pciSlotNumber = "23"
pciBridge7.pciSlotNumber = "24"
usb.pciSlotNumber = "32"
ethernet0.pciSlotNumber = "160"
sound.pciSlotNumber = "33"
ehci.pciSlotNumber = "34"
usb_xhci.pciSlotNumber = "192"
sata0.pciSlotNumber = "35"
nvme0.pciSlotNumber = "224"
nvme0:0.redo = ""
svga.vramSize = "268435456"
vmotion.checkpointFBSize = "4194304"
vmotion.checkpointSVGAPrimarySize = "268435456"
vmotion.svga.mobMaxSize = "1073741824"
vmotion.svga.graphicsMemoryKB = "8388608"
vmotion.svga.supports3D = "1"
vmotion.svga.baseCapsLevel = "9"
vmotion.svga.maxPointSize = "189"
vmotion.svga.maxTextureSize = "16384"
vmotion.svga.maxVolumeExtent = "2048"
vmotion.svga.maxTextureAnisotropy = "16"
vmotion.svga.lineStipple = "1"
vmotion.svga.dxMaxConstantBuffers = "15"
vmotion.svga.dxProvokingVertex = "1"
vmotion.svga.sm41 = "1"
vmotion.svga.multisample2x = "1"
vmotion.svga.multisample4x = "1"
vmotion.svga.msFullQuality = "1"
vmotion.svga.logicOps = "1"
vmotion.svga.bc67 = "9"
vmotion.svga.sm5 = "1"
vmotion.svga.multisample8x = "1"
vmotion.svga.logicBlendOps = "1"
vmotion.svga.maxForcedSampleCount = "8"
vmotion.svga.gl43 = "1"
ethernet0.generatedAddress = "00:0C:29:91:A3:08"
ethernet0.generatedAddressOffset = "0"
vmci0.id = "-1801159540"
monitor.phys_bits_used = "45"
softPowerOff = "FALSE"
sata0:1.startConnected = "TRUE"
toolsInstallManager.lastInstallError = "0"
tools.upgrade.policy = "upgradeAtPowerCycle"
ethernet0.pvnID = "52 36 78 b4 6e e7 bd 14-b4 21 73 1b 4c 9d b8 ac"
svga.guestBackedPrimaryAware = "TRUE"
tools.capability.verifiedSamlToken = "TRUE"
tools.remindInstall = "FALSE"
toolsInstallManager.updateCounter = "3"
guestInfo.detailed.data = "architecture='X86' bitness='64' buildNumber='19045' distroName='Windows' distroVersion='10.0' familyName='Windows' kernelVersion='19045.3803' prettyName='Windows 10 Pro, 64-bit (Build 19045.3803)'"
checkpoint.vmState.readOnly = "FALSE"
vm.genid = "-1956126922046584683"
vm.genidX = "9146803400505436936"
cleanShutdown = "FALSE"
applianceView.coverPage.author = "emsec"
applianceView.coverPage.version = "1"
isolation.tools.hgfs.disable = "TRUE"
sharedFolder0.present = "FALSE"
sharedFolder0.enabled = "TRUE"
sharedFolder0.readAccess = "TRUE"
sharedFolder0.writeAccess = "TRUE"
sharedFolder0.guestName = "hostshare"
sharedFolder0.expiration = "never"
sharedFolder.maxNum = "0"
usb_xhci:4.present = "TRUE"
usb_xhci:4.deviceType = "hid"
usb_xhci:4.port = "4"
usb_xhci:4.parent = "-1"
PS C:\Users\emsec-pc\Desktop>
```

for example letsincrease memory from 4388 MB to 8192 MB (Before editing the .vmx file, it is important to ensure that the VM is powered off):

```powershell
$vmx = "C:\VM\Win10\Windows 10 x64.vmx"

vmrun stop $vmx soft

(Get-Content $vmx) `
  -replace 'memsize\s*=\s*"\d+"', 'memsize = "8192"' |
Set-Content $vmx
```

This replaces memsize = "4388" with a higher value, for example 8192 MB.

Check changes:

```powershell
PS C:\Users\emsec-pc\Desktop> Select-String -Path $vmx -Pattern 'memsize'

C:\VM\Win10\Windows 10 x64.vmx:37:memsize = "8192"

PS C:\Users\emsec-pc\Desktop>
```

This approach is particularly useful when cloning labs or preparing standardized VM templates.

---

### Full Automation Example: 

Here's a PowerShell script for managing multiple VMware VMs interactively:

```powershell
# VMware VM Manager (PowerShell)
# Author: EmSec
# Purpose: Easy management of VMware Workstation VMs via vmrun.exe

$VmRoot = "C:\VM"
$VmwarePath = "C:\Program Files (x86)\VMware\VMware Workstation"

# Ensure vmrun is available
if (-not (Get-Command vmrun -ErrorAction SilentlyContinue)) {
    if (Test-Path "$VmwarePath\vmrun.exe") { $env:Path += ";$VmwarePath" }
    else { Write-Error "vmrun.exe not found. Install VMware Workstation."; exit 1 }
}

# Get all VMX files
$Vms = Get-ChildItem $VmRoot -Recurse | Where-Object { $_.Extension -eq ".vmx" }

if ($Vms.Count -eq 0) { Write-Error "No .vmx files found."; exit 1 }

# Menu
Clear-Host
Write-Host "==== VMware Virtual Machines ====`n"
for ($i = 0; $i -lt $Vms.Count; $i++) { Write-Host "[$($i + 1)] $($Vms[$i].BaseName)" }
Write-Host "[S] Show running VMs`n[Q] Quit`n"

$Choice = Read-Host "Select VM number or option"

if ($Choice -match '^[Qq]$') { exit }
if ($Choice -match '^[Ss]$') { vmrun list; exit }
if ($Choice -notmatch '^\d+$' -or $Choice -lt 1 -or $Choice -gt $Vms.Count) { Write-Error "Invalid selection."; exit 1 }

$Vm = $Vms[$Choice - 1]
$VmPath = $Vm.FullName

# Action menu
Write-Host "`nSelected VM: $($Vm.BaseName)`n"
Write-Host "[1] Start (nogui)`n[2] Stop (soft)`n[3] Suspend`n[4] Resume`n[5] Reset`n[6] Check if running`n"

$Action = Read-Host "Choose action"

switch ($Action) {
    "1" { if (vmrun list | Select-String -Quiet $VmPath) { Write-Host "VM is already running." } else { vmrun start "$VmPath" nogui; Write-Host "VM started." } }
    "2" { vmrun stop "$VmPath" soft; Write-Host "VM stopped." }
    "3" { vmrun suspend "$VmPath"; Write-Host "VM suspended." }
    "4" { vmrun start "$VmPath" nogui; Write-Host "VM resumed." }
    "5" { vmrun -T ws reset "$VmPath"; Write-Host "VM reset." }
    "6" { if (vmrun list | Select-String -Quiet $VmPath) { Write-Host "VM is running." } else { Write-Host "VM is not running." } }
    default { Write-Error "Invalid action." }
}
```


---

### Conclusion

Managing VMware Workstation from PowerShell transforms it from a desktop virtualization tool into a fully scriptable lab platform. With `vmrun`, you gain precise control over VM lifecycles, guest interaction, and automation workflows.

Once you adopt this approach, going back to manual GUI operations feels slow and limiting. Whether you are building security labs, testing software, or managing multiple operating systems locally, PowerShell-driven VMware automation is a skill worth mastering.

