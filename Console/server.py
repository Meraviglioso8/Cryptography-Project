import sqlite3
import hashlib
import socket
import threading
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("localhost",8080))

server.listen()
def login (c):
    c.send("Username: ".encode())
    username = c.recv(1024).decode()
    c.send("Password: ".encode())
    password = c.recv(1024).decode()
    password = hashlib.sha3_256(password.encode()).hexdigest()
    conn=sqlite3.connect("userdata.db")
    cur=conn.cursor()
    cur.execute("SELECT * FROM userdata WHERE username = ? AND password = ?", (username,password))
    if cur.fetchall():
        c.send("Login successful!".encode())
    else:
        c.send("Login failed!".encode())
def register(c):
    c.send("Username: ".encode())
    username = c.recv(1024).decode()
    c.send("Password: ".encode())
    password = c.recv(1024).decode()
    c.send("Retype your password: ".encode())
    repass = c.recv(1024).decode()
    if (password == repass):
        password = hashlib.sha3_256(password.encode()).hexdigest()
        conn = sqlite3.connect("userdata.db")
        cur = conn.cursor()
        cur.execute("INSERT INTO userdata (username,password) VALUES (?, ?)", (username,password))
        conn.commit()
        c.send("Register successfully!")
        handle_connection(c)
        
    else:
        c.send("Your password does not match!")
        register(c)

def handle_connection(c):
    c.send("Type /help for more information\n".encode())
    while True:
        receive = c.recv(1024).decode()
        if (receive == "/help"):
            c.send("/login: Login page.\n/register: Register page\n/exit: Exit the program\n".encode())
        elif (receive == "/login"):
            login(c)
        elif (receive =="/register"):
            register(c)
        else: c.send("Invalid command\n".encode())
   

def main():    
        while True:
            client,addr = server.accept()
            threading.Thread(target=handle_connection,args=(client,)).start()

if __name__ == "__main__":
    main()
