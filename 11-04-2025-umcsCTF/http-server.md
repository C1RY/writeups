## **http-server (RE)**

![image](https://github.com/user-attachments/assets/d49c9b97-3daa-4e18-a6ef-8af4953c7a88)



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
