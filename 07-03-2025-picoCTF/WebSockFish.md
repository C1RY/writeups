# WebSockFish

Author: Venax

### Description

Can you win in a convincing manner against this chess bot? He won't go easy on you!You can find the challenge

Hint:
Try understanding the code and how the websocket client is interacting with the server

---

### **Understanding the Client-Server Interaction**

- **Client-Side Code**:
    
    The website uses stockfish to evaluate the game from the bot perspective (black pieces). Evaluations are sent to the server via WebSocket.
    
    ```
    stockfish.onmessage = function (event) {
            var message;
            // console.log(event.data);
            if (event.data.startsWith("bestmove")) {
              var bestMove = event.data.split(" ")[1];
              var srcSq = bestMove.slice(0, 2);
              var dstSq = bestMove.slice(2, 4);
              var promotion = bestMove.slice(4);
    
              game.move({ from: srcSq, to: dstSq, promotion: promotion });
              board.position(game.fen());
            } else if (event.data.startsWith(`info depth ${DEPTH}`)) {
              var splitString = event.data.split(" ");
              if (event.data.includes("mate")) {
                message = "mate " + parseInt(splitString[9]);
              } else {
                message = "eval " + parseInt(splitString[9]);
              }
              sendMessage(message);
            }
    ```
    

---

### **Initial Misunderstanding: `mate 0` as a Winning Condition**

- **My First Assumption**:
    
    Initially, I thought the goal was to win the game and send `sendMessage("mate 0")`, assuming this would signal to the server that I had won and should receive the flag.
    
    However, the server did not give me the flag based on `mate` values. 
    
- `mate 9999999` → "Haha I think you're gonna drown in 9999999 moves."
- `mate -9999999` / `mate 0` → "You may eventually checkmate me, but you will never break my spirit as a fish!!"
    
    <img width="335" alt="image" src="https://github.com/user-attachments/assets/74c53fda-40c0-47e8-87c5-2566ba9d0e7c" />

    
    <img width="460" alt="image 1" src="https://github.com/user-attachments/assets/adab93fa-912b-447e-bab3-5f8ef6230c0c" />

    
---

### **Identify the Exploitable Flaw**

- **Server Trusts Client Evaluations**:
    
    The server does not validate the actual game state. It depends on client evaluations to determine if the user wins or losses.
    
- **Chat Response Patterns for `eval` Values**:
    - `eval -269` → "Don't think I'm gonna make it easy for you!"
    - `eval -353` → "I wouldn't have played that if I were you."
    - `eval 0` → "I think this position is pretty equal."
    - This suggests that the server uses `eval` messages to assess game status.
    

---

### **Exploiting the Flaw**

### **Directly Send `eval -9999`**

- Use browser dev tools to send `eval -9999` via WebSocket:
    
    ```
    sendMessage("eval -9999");
    ```
    
    - **Why?** Stockfish will think they are losing so badly since the evaluation (eval) is based on the likeliness of winning the game

---

<img width="308" alt="image 2" src="https://github.com/user-attachments/assets/b47ebe8c-6919-4e71-86f0-3a6081df7054" />

<img width="476" alt="image 3" src="https://github.com/user-attachments/assets/e14cd755-29a7-44e7-b9e8-c4d40bb6a4a4" />
