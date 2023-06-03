import os
import urllib.parse as up
import psycopg2
import socket
import threading
from argon2 import PasswordHasher
import ssl
from random import getrandbits
from Crypto.Cipher import AES
import binascii

# Setup connection
dir_path = os.path.dirname(os.path.abspath(__file__))

# Construct the paths to the certificate and key files
certfile = os.path.join(dir_path, "server.crt")
keyfile = os.path.join(dir_path, "server.key")

# Create an SSL context and load the certificate and key files
context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain(certfile=certfile, keyfile=keyfile)

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
    cur.execute("""
        SELECT role FROM userdata
        WHERE username = ?
    """, (username,))
    result = cur.fetchone()
    if result is None:
        return False # user not found
    role = result[0]

    cur.execute("""
        SELECT ? FROM role_permissions
        WHERE role = ?
    """, (permission, role))
    result = cur.fetchone()
    if result[0] == 1:
        return True # permission granted
    else:
        return False # permission denied
    
def getRoles(username):
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
    cur.execute("""
        SELECT role FROM userInfo WHERE username = ?
    """, (username,))
    result = cur.fetchone()
    if result is None:
        return False # user not found
    return result[0]

def generateFactor(username):
    role = getRoles(username)
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
    cur.execute("""
        SELECT delete_user, search_data, insert_data, update_data, delete_data
        FROM role_permissions
        WHERE role = ?
    """, (role,))
    result = cur.fetchone()

    if result:
        key = binascii.unhexlify("9A1C95B959B9B67EEF032BA0FD0ABC22")
        permissions = {
                    'delete_user': result[0],
                    'search_data': result[1],
                    'insert_data': result[2],
                    'update_data': result[3],
                    'delete_data': result[4]
                }
        permissions_bin = ''.join([bin(value)[2:].zfill(1) for value in permissions.values()])
        random1 = bin(getrandbits(8))[2:]  
        random2 = bin(getrandbits(8))[2:]  
        factor = permissions_bin + random1 + random2
        enc = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = enc.encrypt_and_digest(factor.encode())
        encryptedFactor = ciphertext.hex()

        factor32char = encryptedFactor[:16] + encryptedFactor[-16:]
         # insert the factor into the database table
        cur.execute("UPDATE userInfo SET factor = ? WHERE username = ? VALUES (?, ?)", (factor32char, username))
        conn.commit() # commit the transaction to save the changes to the database
        print(f"Factor saved to database for user {username}: {factor32char}")
        return factor32char
    else:
        print(f"No permissions found for role: {role}")


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


def register(client_socket):
    client_socket.send("Username: ".encode())
    username = client_socket.recv(1024).decode()
    client_socket.send("Password: ".encode())
    password = client_socket.recv(1024).decode()
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
    client_socket.send("Register successfully!\n".encode())

    factor = generateFactor(username)
    client_socket.send("FACTOR:" + factor.encode())

    Menu(client_socket)


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