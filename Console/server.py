import os
import urllib.parse as up
import psycopg2
import socket
import threading
from argon2 import PasswordHasher
import ssl

# Setup connection
context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain(certfile="server.crt", keyfile="server.key")

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("0.0.0.0", 9999))
server.listen()
server = context.wrap_socket(server, server_side=True)
print("Server starting...")

#set up database
up.uses_netloc.append("rbzkziqg")
url = up.urlparse("postgres://rbzkziqg:rGJI2QMcTMo7C6GGrC1f1X82FqysVz2H@satao.db.elephantsql.com/rbzkziqg")
conn = None
cur = None
ph = PasswordHasher()

def check_permission(client_socket, permission):
    username = client_socket.username
    #sqlConnection = sqlite3.connect("userdata.db")
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
    
def login(client_socket):
    client_socket.send("Username: ".encode())
    username = client_socket.recv(1024).decode()
    client_socket.send("Password: ".encode())
    password = client_socket.recv(1024).decode()

    try:
        conn = psycopg2.connect(database=url.path[1:],
        user=url.username,
        password=url.password,
        host=url.hostname,
        port=url.port
        )
    except Exception as error:
        print(error)
    cur = conn.cursor()
    cur.execute("SELECT password FROM userInfo WHERE username = %s", [username])
    data = cur.fetchall()[0][0]
    print(str(data))
    try:
        verifyValid = ph.verify(str(data),password)
        print(verifyValid)
        client_socket.send("Login complete!".encode())
    except:
        client_socket.send("Login failed!".encode())
    finally:
        Menu(client_socket)



def register(c):
    c.send("Username: ".encode())
    username = c.recv(1024).decode()
    c.send("Password: ".encode())
    password = c.recv(1024).decode()
    hashpass = ph.hash(password)
    try:
        conn = psycopg2.connect(database=url.path[1:],
        user=url.username,
        password=url.password,
        host=url.hostname,
        port=url.port
        )
    except Exception as error:
        print(error)
    cur = conn.cursor()
    cur.execute("INSERT INTO userInfo (username,password,role) VALUES (%s, %s, %s)", (username,hashpass,"normal"))
    conn.commit()
    c.send("Register successfully!\n".encode())
    Menu(c)


def Menu(client_socket):
    while True:
        command = client_socket.recv(1024).decode().strip()
        switch = {
            "/login": login,
            "/register": register,
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
            client_socket, addr = server.accept()
            print(f'{addr} Connected')
            thread = threading.Thread(target=Menu,args=(client_socket,))
            thread.start()

if __name__ == "__main__":
    main()