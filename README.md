# snowflake
Rust based application which scans for patterns in the memory of a running process.

```bash
scanmem 0.1
scan memory of running process

USAGE:
    snowflake [OPTIONS] --pid <PID> <--bytes <value>|--word <value>|--dword <value>|--qword <value>|--string <string>|--maps>

FLAGS:
    -h, --help       Prints help information
    -m, --maps       Print out the memory maping
    -V, --version    Prints version information

OPTIONS:
    -b, --bytes <value>       Search for 1-byte value
    -d, --dword <value>       Search for 4-byte value
    -i, --in <pattern>        Search inside specified region, 
                              unnamed regions are marked as [unassigned]
        --perm <perm>         Permission of memory to search for  : <rwx>
    -p, --pid <PID>           Set the target process id
    -q, --qword <value>       Search for 8-byte value
    -r, --range <range>...    Address range to search for
    -s, --string <string>     Search for string
    -w, --word <value>        Search for 2-byte value
```
```bash
$ snowflake -p $(pgrep firefox) -s "/bin/s." --in libc-2.28
Scanning memory 0x7fc25e4f8000-0x7fc25e51a000	 /usr/lib/x86_64-linux-gnu/libc-2.28.so
Scanning memory 0x7fc25e51a000-0x7fc25e662000	 /usr/lib/x86_64-linux-gnu/libc-2.28.so
Scanning memory 0x7fc25e662000-0x7fc25e6ae000	 /usr/lib/x86_64-linux-gnu/libc-2.28.so
Found /bin/sh              @ 0x7fc25e679519
Scanning memory 0x7fc25e6ae000-0x7fc25e6af000	 /usr/lib/x86_64-linux-gnu/libc-2.28.so
Scanning memory 0x7fc25e6af000-0x7fc25e6b3000	 /usr/lib/x86_64-linux-gnu/libc-2.28.so
Scanning memory 0x7fc25e6b3000-0x7fc25e6b5000	 /usr/lib/x86_64-linux-gnu/libc-2.28.so
```
