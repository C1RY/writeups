## Coding Mountains

```
Author: @Soups71I
like mountains and I like coding, so I made this game. I hope you also 
like both of those things, or else you probably won't have a ton of 
fun...  **Press the Start button in the top-right to begin this challenge.**
```

Kali Linux:

![image](https://github.com/user-attachments/assets/f319665d-2ab2-4168-96cd-f3c0f42e3025)


- The server then asks a series of mountain-related questions.
- Each question follows this pattern:
    
    ```
    What is the height and first ascent year of <Mountain Name>:
    ```
    
- The player must respond with the correct height and first ascent year in a comma-separated format, like this:
    
    ```
    height,year
    ```
    

Python script used to automate the challenge:

```python
import json
import socket
import re
import time

# Load mountain data from JSON file
with open("mountains.json", "r") as file:
    mountains = json.load(file)

# Convert mountains data into a dictionary for quick lookup
mountain_dict = {m["name"].lower(): (m["height"].replace(",", ""), m["first"]) for m in mountains}

# Connect to the challenge server
HOST = "challenge.ctf.games"
PORT = 30173

# Establish a socket connection
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    time.sleep(1)  # Give time for server to respond

    # Read the welcome message
    data = s.recv(4096).decode()
    print(data)

    # Send "y" to start the quiz
    s.sendall(b"y\n")
    time.sleep(1)  # Wait for the server to process

    while True:
        # Receive the question
        data = s.recv(4096).decode()
        print(data)

        # Extract mountain name using regex
        match = re.search(r"What is the height and first ascent year of (.*?):", data)
        if not match:
            break  # If no more questions, exit loop

        mountain_name = match.group(1).strip().lower()

        # Look up the mountain data
        if mountain_name in mountain_dict:
            height, first_ascent = mountain_dict[mountain_name]
            answer = f"{height},{first_ascent}"
        else:
            print(f"Mountain '{mountain_name}' not found!")
            answer = "none,none"

        # Send the answer
        s.sendall(answer.encode() + b"\n")
        time.sleep(1)  # Wait for server response

    # Final response from the server
    final_response = s.recv(4096).decode()
    print(final_response)
```

After 50 questions, you will get the flag:

![image 1](https://github.com/user-attachments/assets/3aa52f63-452f-4f73-a9cd-dedd33390a55)
