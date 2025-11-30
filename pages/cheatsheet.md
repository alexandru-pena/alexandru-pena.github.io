---
layout: default
---


## Cheatsheet
 

**Description**

Just a page with some usual commands I use for quick access. This page is not indexed so well, nice one.


**GDB (GEF)**

- x/20xg *addr
- print *addr
- p system
- heap chunk addr
- search-pattern pattern
- find &system,+9999999,"/bin/sh"
- i b
- del 1 # delete breakpoint
- set follow-fork-mode child|parent # tell's GDB which process to track when a fork happens
- set $eax = 0 # change register
- info function .*@plt
- info frame
- info args
- info locals
- bt -> backtrace
- info files
- disas 0x4008b0, +40
- p *0x00602060@7 -> print array "p *array@len"
- stepi -> step into
- info variables
- set disable-randomization off
- info symbol ADDR
- search-pattern 0x57ef0a little 0x00007ac97a994000-0x00007ac97a99b000
- scan libc 0x000057ef0a400000-0x000057ef0a603000 -> scan for addresses in libc that point to addresses in 2nd argument


**Shell**

- LD_PRELOAD=./libc.so.6 ./ld.so ./prog
- patchelf --set-interpreter ./ld.so ./prog (patch binary with correct linker)
- readelf -s ./libc.so.6 | grep system          # find system offset
- objdump --dynamic-reloc ./bin | grep strtok   # find offset of GOT table
- ROPgadget --binary ./bin > gadgets.txt
- pwn cyclic 65
- pwn cyclic -l pattern
- pwn template bin
- echo 0 | sudo tee /proc/sys/kernel/randomize_va_space # disable aslr
- echo 2 | sudo tee /proc/sys/kernel/randomize_va_space # enable aslr

- sudo docker build -t name .
- sudo docker run -p 8080:8080 54320a9eecce

**python**

- Convert to decimal hex value.
```python
int(canary_byte_value.decode(), base=16)
```

- Get bytes from hex
```python
bytes.fromhex('4a4b4c').decode('utf-8')
```

- Set libc in pwn template.
```python
if args.LOCAL_LIBC:
    libc = exe.libc
else:
    library_path = '/home/alex/Downloads/ctfs/curr_ctf/' #libcdb.download_libraries('libc.so.6')
    if library_path:
        exe = context.binary = ELF.patch_custom_libraries(exe.path, library_path)
        libc = exe.libc
    else:
        libc = ELF('libc.so.6')
```


## Generic Notes

- "disas addr" will fail if binary has no debug symbols. In this case should use something like "disas 0x4008b0, +40"



[back](/index)