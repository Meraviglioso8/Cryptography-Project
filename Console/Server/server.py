import os
import urllib.parse as up
import psycopg2
import socket
import threading
import binascii
import hmac
import hashlib
import struct
import time
import ssl
from random import getrandbits
from Crypto.Cipher import AES
from argon2 import PasswordHasher
import subprocess
import smtplib

# Setup connection
dir_path = os.path.dirname(os.path.abspath(__file__))

# Construct the paths to the certificate and key files
certfile = os.path.join(dir_path, "C:/Users/gohan/OneDrive/Documents/GitHub/Cryptography-Project/Console/server.crt")
keyfile = os.path.join(dir_path, "C:/Users/gohan/OneDrive/Documents/GitHub/Cryptography-Project/Console/server.key")

# Create an SSL context and load the certificate and key files
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.minimum_version = ssl.TLSVersion.TLSv1_3
context.load_cert_chain(certfile=certfile, keyfile=keyfile)

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("0.0.0.0", 9999))
server.listen()
server = context.wrap_socket(server, server_side=True)
print("Server starting...")

#set up database
up.uses_netloc.append("rslgnkrk")
url = up.urlparse("postgres://rslgnkrk:KlTouCgQoGMPRngRKf8ddlBAI0FaL9_j@satao.db.elephantsql.com/rslgnkrk")
conn = None
cur = None
ph = PasswordHasher() 
tempOTP =''

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
        SELECT ? FROM rolePermissions
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
    cur.execute("SELECT role FROM userInfo WHERE username = %s", [username])
    result = cur.fetchall()[0][0]
    if result is None:
        return False # user not found
    return result

def generate_totp(secret_key, state=0):
    current_time = int(time.time())
    time_interval = 30
    time_steps = (current_time // time_interval) + state
    time_steps_bytes = struct.pack(">Q", time_steps)
    secret_key_bytes = secret_key.encode("ascii")
    # Generate an HMAC-SHA1 hash of the time steps using the secret key
    hmac_hash = hmac.new(secret_key_bytes, time_steps_bytes, hashlib.sha3_256).digest()

    # Calculate the offset and take last 4-byte for the TOTP code
    offset = hmac_hash[-1] & 0x0F
    code_bytes = hmac_hash[offset:offset+4]
    code = struct.unpack(">I", code_bytes)[0]
    totp_code= '{0:06d}'.format((code & 0x7FFFFFFF) % 1000000)

    return totp_code

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
    cur.execute("SELECT delete_user, search_data, insert_data, update_data, delete_data FROM rolePermissions WHERE role = %s", [role])
    result = cur.fetchall()

    if result:
        key = binascii.unhexlify("9A1C95B959B9B67EEF032BA0FD0ABC22")
        permissions = {
                    'delete_user': result[0][0],
                    'search_data': result[0][1],
                    'insert_data': result[0][2],
                    'update_data': result[0][3],
                    'delete_data': result[0][4]
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
        cur.execute("UPDATE userInfo SET factor = %s WHERE username = %s", [factor32char, username])
        conn.commit() # commit the transaction to save the changes to the database
        print(f"Factor saved to database for user {username}: {factor32char}")
        return factor32char
    else:
        print(f"No permissions found for role: {role}")

def reqOtp(username):
    try:
        conn = psycopg2.connect(database=url.path[1:],
                               user=url.username,
                               password=url.password,
                               host=url.hostname,
                               port=url.port
                               )

        cur = conn.cursor()
        cur.execute("SELECT factor FROM userInfo WHERE username = %s", [username])
        result = cur.fetchall()
        #user name exists or not
        if len(result) > 0: 
            factor = result[0][0]
            otp = generate_totp(factor)
            return True, otp
        else:
            return False, None
    except Exception as error:
        print(error)
        return False, None


def login(client_socket):
    client_socket.send("Username: ".encode())
    username = client_socket.recv(1024).decode()
    exists, genOTP = reqOtp(username)

    password = client_socket.recv(1024).decode()
    client_socket.send("Your OTP code:".encode())
    client_socket.send(genOTP.encode())
    
    if not exists:  # doesn't exist
        client_socket.send("Invalid username. Please try again.".encode())
        login(client_socket)  # client to log in again
        return
    
    print(genOTP)
    otp_code = client_socket.recv(1024).decode()
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
        if(otp_code == genOTP):
            client_socket.send("Login complete!".encode())
        else:
            cur.execute("INSERT INTO suspiciousTable (usernameSUSSY) VALUES (%s)", [username])
            conn.commit()
            cur.execute("SELECT COUNT(*) FROM suspiciousTable WHERE usernameSUSSY = %s", [username])
            count = cur.fetchone()[0]
            cur.execute("SELECT email FROM userInfo WHERE username = %s", [username])
            gmailofSussy = cur.fetchone()[0]
            client_socket.send("Invalid OTP code, you are added into suspicious table".encode())
            client_socket.send(("User added to suspiciousTable count: " + str(count)).encode())
            sendEmail(count,gmailofSussy)
    except:
        cur.execute("INSERT INTO suspiciousTable (usernameSUSSY) VALUES (%s)", [username])
        conn.commit()
        cur.execute("SELECT COUNT(*) FROM suspiciousTable WHERE usernameSUSSY = %s", [username])
        count = cur.fetchone()[0]
        cur.execute("SELECT email FROM userInfo WHERE username = %s", [username])
        gmailofSussy = cur.fetchone()[0]
        client_socket.send("Invalid Password, you are added into suspicious table".encode())
        client_socket.send(("User added to suspiciousTable count: " + str(count)).encode())
        sendEmail(count)
    finally:
        Menu(client_socket)

#send email if count > 5
def sendEmail(count, gmailofSussy):
    if count >= 5:
        sendtogmail(gmailofSussy)

def sendtogmail(gmailofSussy):
    gmail_user = ''
    gmail_app_password = ''

    sent_from = gmail_user
    sent_to = [gmailofSussy]
    sent_subject = "Hey Friends!"
    sent_body = ("Hello\n\n"
                "I have to inform that you are now in SUSPECTED table by our application!\n"
                "\n"
                "Seeya,\n"
                "Group6\n")

    email_text = """\
    From: %s
    To: %s
    Subject: %s

    %s
    """ % (sent_from, ", ".join(sent_to), sent_subject, sent_body)

    #try until success
    try:
        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.ehlo()
        server.login(gmail_user, gmail_app_password)
        server.sendmail(sent_from, sent_to, email_text)
        server.close()

        print('Email sent!')
    except Exception as exception:
        print("Error: %s!\n\n" % exception)
        
# def login(client_socket):
#     client_socket.send("Username: ".encode())
#     username = client_socket.recv(1024).decode()
#     exists, genOTP = reqOtp(username)

#     password = client_socket.recv(1024).decode()
    
#     try:
#         conn = psycopg2.connect(database=url.path[1:],
#                                 user=url.username,
#                                 password=url.password,
#                                 host=url.hostname,
#                                 port=url.port
#                                )
#     except Exception as error:
#         print(error)

#     cur = conn.cursor()
#     cur.execute("SELECT password FROM userInfo WHERE username = %s", [username])
#     data = cur.fetchall()
    
#     if not data:  # user doesn't exist
#         client_socket.send("Invalid username. Please try again.".encode())
#         login(client_socket)  # client to log in again
#         return
    
#     stored_password = data[0][0]
    
#     try:
#         verifyValid = ph.verify(stored_password, password)
#         client_socket.recv(1024)
#         client_socket.send(verifyValid.encode())
        
#         if verifyValid:
#             client_socket.send("Password correct. Please enter OTP code:".encode())
#             client_socket.send(genOTP.encode())
#             otp_code = client_socket.recv(1024).decode()
            
#             if otp_code == genOTP:
#                 client_socket.send("Login complete!".encode())
#             else:
#                 client_socket.send("Invalid OTP code".encode())
#                 cur.execute("INSERT INTO suspiciousTable (usernameSUSSY) VALUES (%s)", [username])
#                 conn.commit()
#                 cur.execute("SELECT COUNT(*) FROM suspiciousTable WHERE usernameSUSSY = %s", [username])
#                 count = cur.fetchone()[0]
#                 client_socket.send(f"User added to suspiciousTable {count} time(s)".encode())
#         else:
#             client_socket.send("Invalid password".encode())
#             cur.execute("INSERT INTO suspiciousTable (usernameSUSSY) VALUES (%s)", [username])
#             conn.commit()
#             cur.execute("SELECT COUNT(*) FROM suspiciousTable WHERE usernameSUSSY = %s", [username])
#             count = cur.fetchone()[0]
#             client_socket.send(f"User added to suspiciousTable {count} time(s)".encode())
#     except:
#         client_socket.send("Login failed!".encode())
    
#     Menu(client_socket)


def register(client_socket):
    client_socket.send("Username: ".encode())
    username = client_socket.recv(1024).decode()
    password = client_socket.recv(1024).decode()
    email = client_socket.recv(1024).decode()
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
    cur.execute("INSERT INTO userInfo (username,password,email,role) VALUES (%s, %s, %s, %s)", [username,hashpass,email,"normal"])
    conn.commit()

    factor = generateFactor(username)
    cur.execute("UPDATE userInfo SET factor = %s WHERE username = %s", [factor,username])
    conn.commit()
    cur.close()
    conn.close()
    client_socket.send(("FACTOR:" + username+ "/"+ factor).encode())
    client_socket.send("Register successfully!\n".encode())

    Menu(client_socket)


def Menu(client_socket):
    while True:
        command = client_socket.recv(1024).decode().strip()
        switch = {
            "/login": login,
            "/register": register,
            "/exit": exitProgram,
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