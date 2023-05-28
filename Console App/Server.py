import sqlite3
import socket
import threading
from argon2 import PasswordHasher

# server
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("localhost",9999))
server.listen()

def createUser(client_socket):
    if check_permission(client_socket, "createUser"):
        client_socket.send("Username: ".encode())
        username = client_socket.recv(1024).decode()
        client_socket.send("Password: ".encode())
        password = client_socket.recv(1024).decode()
        client_socket.send("Role: ".encode())
        role = client_socket.recv(1024).decode()
        ph = PasswordHasher
        hashpass = ph.hash(password)

        sqlConnect = sqlite3.connect("userdata.db")
        cursor = sqlConnect.cursor()
        cursor.execute("INSERT INTO userdata (username,password,role) VALUES (?, ?, ?)", (username, hashpass, role))
        sqlConnect.commit()

        client_socket.send("New user created successfully!".encode)
    else: client_socket.send("Current user don't have permission to createUser")

        
def login(client_socket):
    client_socket.send("Username: ".encode())
    username = client_socket.recv(1024).decode()
    client_socket.send("Password: ".encode())
    password = client_socket.recv(1024).decode()

    ph = PasswordHasher()
    sqlConnection=sqlite3.connect("userdata.db")
    cursor=sqlConnection.cursor()
    data = cursor.execute("SELECT password FROM userdata WHERE username = ?", (username,)).fetchall()[0][0]
    try:
        verifyValid = ph.verify(data ,password)
        client_socket.username = username
        client_socket.send("Login complete!\n".encode())
        Menu(client_socket)
    except:
        client_socket.send("Login failed!\n".encode())
        Menu(client_socket)


def check_permission(client_socket, permission):
    username = client_socket.username
    sqlConnection = sqlite3.connect("userdata.db")
    cursor = sqlConnection.cursor()
    cursor.execute("""
        SELECT role FROM userdata
        WHERE username = ?
    """, (username,))
    result = cursor.fetchone()
    if result is None:
        return False # user not found
    role = result[0]

    cursor.execute("""
        SELECT ? FROM role_permissions
        WHERE role = ?
    """, (permission, role))
    result = cursor.fetchone()
    if result[0] == 1:
        return True # permission granted
    else:
        return False # permission denied
    
def deleteUser():
    pass
def searchData():
    pass
def insertData():
    pass
def updateData():
    pass
def deleteData():
    pass

def Menu(client_socket):
    while True:
        client_socket.send("Type /help for more information\n".encode())
        command = client_socket.recv(1024).decode().strip()
        switch = {
            "/login": login,
            "/createuser": createUser,
            "/deleteuser": deleteUser,
            "/search": searchData,
            "/insert": insertData,
            "/update": updateData,
            "/delete": deleteData,
            "/help": showHelp,
            "/exit": exitProgram
        }
        handler = switch.get(command, invalidCommand)
        handler(client_socket)

def showHelp(client_socket):
    client_socket.send("/login: login\n/createuser: create new user\n/deleteuser: delete existing user\n/search: search for data\n/insert: insert data\n/update: update data\n/delete: delete data\n/exit: disconnect\n".encode())

def exitProgram(client_socket):
    client_socket.send("User disconnected!\n".encode())
    client_socket.close()

def invalidCommand(client_socket):
    client_socket.send("Invalid command\n".encode())
   
def main():    
        while True:
            client_socket, address = server.accept()
            thread = threading.Thread(target=Menu,args=(client_socket,))
            thread.start()

if __name__ == "__main__":
    main()