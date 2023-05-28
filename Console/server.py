import sqlite3
import socket
import threading
from argon2 import PasswordHasher
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("localhost",8888))
server.listen()



def login (c):
    c.send("Username: ".encode())
    username = c.recv(1024).decode()
    c.send("Password: ".encode())
    password = c.recv(1024).decode()
    ph = PasswordHasher()
    conn=sqlite3.connect("userdata.db")
    cur=conn.cursor()
    conn.text_factory = str
    data = cur.execute("SELECT password FROM userdata WHERE username = ?", [username]).fetchall()[0][0]
    print(data)
    try:
        verifyValid = ph.verify(data ,password)
        c.send("Login complete!\n".encode())
    except:
         c.send("Login failed!\n".encode())

        
def register(c):
    c.send("Username: ".encode())
    username = c.recv(1024).decode()
    c.send("Password: ".encode())
    password = c.recv(1024).decode()
    ph = PasswordHasher()
    hashpass = ph.hash(password)
    conn = sqlite3.connect("userdata.db")
    cur = conn.cursor()
    cur.execute("INSERT INTO userdata (username,password) VALUES (?, ?)", (username,hashpass))
    conn.commit()
    c.send("Register successfully!\n".encode())
    handle_connection(c)

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
        else: 
            c.send("Invalid command\n".encode())
   

def main():    
        while True:
            client,addr = server.accept()
            threading.Thread(target=handle_connection,args=(client,)).start()
            

if __name__ == "__main__":
    main()
