import os
import urllib.parse as up
import psycopg2
import socket
import threading
from binascii import unhexlify
import hmac
import hashlib
import struct
import time
import ssl
from random import getrandbits
from Crypto.Cipher import AES
from argon2 import PasswordHasher
import smtplib
import random
import re
import ast
from cfg import AES_KEY,DB_PASS,DB_URL,GMAIL_USER,GMAIL_PASS
#Global Value
otp =""
stop_threads = False
regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b'
# Setup connection
dir_path = os.path.dirname(os.path.abspath(__file__))

# Construct the paths to the certificate, ca and key files
ca_bundle_file = os.path.join(dir_path, "ca_bundle.crt")
cert_file = os.path.join(dir_path, "certificate.crt")
key_file = os.path.join(dir_path, "server.key")

# create an SSL context 
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.minimum_version = ssl.TLSVersion.TLSv1_3
context.load_cert_chain(certfile=cert_file, keyfile=key_file, password=None)
context.load_verify_locations(cafile=ca_bundle_file)

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("0.0.0.0", 9999))
server.listen()
server = context.wrap_socket(server, server_side=True)
print("Server starting...")

#set up database
up.uses_netloc.append(DB_PASS)
url = up.urlparse(DB_URL)
conn = None
cur = None
tempOTP =''

#connect database
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

    
def getRoles(username):
    try:
       
        cur = conn.cursor()
        cur.execute("SELECT role FROM userInfo WHERE username = %s", [username])
        result = cur.fetchall()[0][0]
    except Exception as e:
        print(e)
    
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
        
        cur = conn.cursor()
        cur.execute("SELECT delete_user, search_data, insert_data, update_data, delete_data FROM rolePermissions WHERE role = %s", [role])
        result = cur.fetchall()
    except Exception as e:
        print(e)

    if result:
        key = unhexlify(AES_KEY)
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
        cur.close()
        print(f"Factor saved to database for user {username}: {factor32char}")
        return factor32char
    else:
        print(f"No permissions found for role: {role}")

#get recoverycode
def getRecoveryCode(factor32char):
    recoveryCode = ''.join(random.sample(factor32char, 6))
    return recoveryCode

#encrypt function
def encrypt(in_str):
    enc = AES.new(unhexlify(AES_KEY), AES.MODE_GCM)
    ciphertext, tag = enc.encrypt_and_digest(in_str.encode())
    nonce = enc.nonce
    return ciphertext.hex(), tag.hex(),nonce.hex()

#decrypt function
def decrypt (in_str,tag,nonce):
    in_str = unhexlify(in_str)
    decrypt_cipher = AES.new(unhexlify(AES_KEY), AES.MODE_GCM,nonce=unhexlify(nonce))
    plain_text = decrypt_cipher.decrypt_and_verify(in_str, unhexlify(tag))
    return plain_text.decode()

#decrypt data get from DB
def getDecryptData(get_data):
    get_data = decrypt(get_data[0],get_data[1],get_data[2])
    return get_data

def reqOtp(username,log_time):
    try:
        cur = conn.cursor()
        cur.execute("SELECT factor FROM userInfo WHERE username = %s", [username])
        data = ast.literal_eval(cur.fetchone()[0])
        factor = getDecryptData(data)
        cur.close()
        #user name exists or not
        if len(factor) > 0: 
            #generate first time
            global otp
            otp = generate_totp(factor)
            print(otp)

            while True:
                global stop_threads
                #generate again after 60 secs
                if (int(time.time())- log_time == 60):
                    log_time = int(time.time())
                    otp = generate_totp(factor)
                    print(otp)
                #stop thread when have input OTP
                if stop_threads == True:
                    print("Stop generating OTP")
                    stop_threads = False
                    break
                    
               
    except Exception as error:
        print(error)

def checkUsername(username):
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM userInfo WHERE username = %s", [username])
        result = cur.fetchall()
        cur.close()
        if (len(result)> 0):
            return True
        else:
            return False
    except Exception as e:
        print(e)
        return False
    
def login(client_socket):
    ph = PasswordHasher()
    client_socket.send("Username: ".encode())
    username = client_socket.recv(1024).decode()
    
    client_socket.send("Password: ".encode())
    password = client_socket.recv(1024).decode()
    #check Invalid Username
    if (checkUsername(username) == False):  # doesn't exist
        client_socket.send("Invalid username. Please try again.".encode())
        return login(client_socket)
    
    #Check incorrect Password

    cur = conn.cursor()
    cur.execute("SELECT status FROM userInfo WHERE username = %s", [username])
    data = cur.fetchall()[0][0]
    if (int(data) == 1):
        client_socket.send("Your account has been locked. Please contact adminstrators for more information.".encode())
        cur.close()
        return Menu(client_socket)
    
    cur.execute("SELECT password FROM userInfo WHERE username = %s", [username])
    data = cur.fetchall()[0][0]
    try:
        verifyValid = ph.verify(str(data),password)
    except:
        cur.execute("INSERT INTO suspiciousTable (usernameSUSSY) VALUES (%s)", [username])
        conn.commit()
        cur.execute("SELECT COUNT(*) FROM suspiciousTable WHERE usernameSUSSY = %s", [username])
        count = cur.fetchone()[0]
        cur.execute("SELECT email FROM userInfo WHERE username = %s", [username])
        data = ast.literal_eval(cur.fetchone()[0])
        gmailofSussy = getDecryptData(data)
        client_socket.send("Invalid Password, you are added into suspicious table".encode())
        client_socket.send(("User added to suspiciousTable count: " + str(count)).encode())
        sendEmail(count,gmailofSussy)
        if (count >= 5):
            client_socket.send("Your account has been locked. Please contact adminstrators for more information.".encode())
            cur.close()
            return Menu(client_socket)
        cur.close()
        return login(client_socket)
    
    #check valid ip, if new have to auth
    client_ip = client_socket.getpeername()[0]
    cur.execute("SELECT ipaddress FROM userInfo WHERE username = %s", [username])
    ipofusername =cur.fetchone()[0]

    if ipofusername and ipofusername != client_ip:
        client_socket.send("Login IP does not match the stored IP address. Please enter recoverycode to continue.".encode())
        recoveryCode = client_socket.recv(1024).decode()
        try: 
            verifyValid = ph.verify(str(storedRecoveryCode),recoveryCode)
        
        except:
            client_socket.send("Invalid recovery code. Please try login again.".encode())
            cur.close()
            return Menu(client_socket)
            # Retrieve the updated user information

        storedRecoveryCode = getRecoveryCode(factor)
        encRecvCode = ph.hash(storedRecoveryCode)
        factor = generateFactor(username)
        encFactor = str(encrypt(factor))

        cur.execute("UPDATE userInfo SET recoverycode = %s, factor = %s,ipaddress = %s, WHERE username = %s", [encRecvCode,encFactor,client_ip,username])
        conn.commit()
        client_socket.send("Change login location".encode())
        client_socket.send(("FACTOR:" + username+ "/"+ factor).encode())
        cur.execute("SELECT email FROM userInfo WHERE username = %s", [username])
        data = ast.literal_eval(cur.fetchone()[0])
        email = getDecryptData(data)
        sendRecoveryCode(email, storedRecoveryCode)
        cur.close()
    #start generating OTP as username + password are valid

    if (verifyValid == True):
        client_socket.send(("Start"+username).encode())
        log_time = int(time.time())
        client_socket.send("Input your OTP: ".encode())
        thread = threading.Thread(target=reqOtp,args=(username,log_time))
        thread.start()

        otp_code = client_socket.recv(1024).decode()
        global stop_threads
        stop_threads = True
        thread.join()
         
        if(otp_code == otp):
            client_socket.send("Login complete!".encode())
        else:
            cur.execute("INSERT INTO suspiciousTable (usernameSUSSY) VALUES (%s)", [username])
            conn.commit()
            cur.execute("SELECT COUNT(*) FROM suspiciousTable WHERE usernameSUSSY = %s", [username])
            count = cur.fetchone()[0]
            cur.execute("SELECT email FROM userInfo WHERE username = %s", [username])
            data = ast.literal_eval(cur.fetchone()[0])
            gmailofSussy = getDecryptData(data)
            client_socket.send("Invalid OTP code, you are added into suspicious table".encode())
            client_socket.send(("User added to suspiciousTable count: " + str(count)).encode())
            sendEmail(count,gmailofSussy)
            if (count >= 5):
                client_socket.send("Your account has been locked. Please contact adminstrators for more information.".encode())
                return Menu(client_socket)
            cur.close()
            return login(client_socket)

    cur.close()
    Menu(client_socket)

#send email if count > 5
def sendEmail(count, gmailofSussy):
    if count >= 5:
        #send annoucement your account has been locked
        sendtogmail(gmailofSussy)
        # change status as to protect sussy login
        try:
            
            cur = conn.cursor()
            cur.execute("""UPDATE userInfo
                SET status = 1
                WHERE email = %s""", [gmailofSussy])
            conn.commit()
            cur.close()
        except Exception as e:
            print(e)

def sendtogmail(gmailofSussy):
    gmail_user = GMAIL_USER
    gmail_app_password = GMAIL_PASS

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
        
def sendRecoveryCode(gmailofUser, recoveryCode):
    gmail_user = GMAIL_USER
    gmail_app_password = GMAIL_PASS

    sent_from = gmail_user
    sent_to = [gmailofUser]
    sent_subject = "Hey Friends! Check this recovery code"
    sent_body = ("Hello\n\n"
                f"Please note this recovery code: {recoveryCode}\n"
                "It will use every time you need to recovery password and login at new location\n"
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
        

def register(client_socket):
    ph = PasswordHasher()
    client_socket.send("Username: ".encode())
    username = client_socket.recv(1024).decode()
    
    client_socket.send("Password: ".encode())
    password = client_socket.recv(1024).decode()
    client_socket.send("Email: ".encode())
    email = client_socket.recv(1024).decode()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM userInfo WHERE username = %s", [username])
        data = cur.fetchall()[0]
        cur.close()
        if(len(data) > 0):
            client_socket.send("Username already existed! Try again.".encode())
            register(client_socket)
    except:
        pass

    
    if(re.fullmatch(regex, email)):
        #check existed email:
        cur = conn.cursor()
        cur.execute("SELECT email FROM userInfo")
        data = cur.fetchall()
        for mail in data:
            tup = mail[0]
            if(getDecryptData(ast.literal_eval(tup)) == email):
                client_socket.send("Your email already been used. Try again".encode())
                register(client_socket)
            
        hashpass = ph.hash(password)
        cur.execute("INSERT INTO userInfo (username,password,email,role) VALUES (%s, %s, %s, %s)", [username,hashpass,str(encrypt(email)),"normal"])

    #factor, recoverycode, ip of client
        
        factor = generateFactor(username)
        encfactor = str(encrypt(factor))
        recoveryCode = getRecoveryCode(factor)
        hashRecoveryCode = ph.hash(recoveryCode)
        client_ip = client_socket.getpeername()[0]
    
        cur.execute("UPDATE userInfo SET factor = %s , recoverycode = %s, ipaddress = %s WHERE username = %s",[encfactor, hashRecoveryCode, client_ip, username])
        conn.commit()
        cur.close()
        client_socket.send(("FACTOR:" + username+ "/"+ factor).encode())
        client_socket.send(f"Register successfully! Please remember this recovery code: {recoveryCode}\n".encode())
        sendRecoveryCode(email, recoveryCode)
    else:
        client_socket.send("Your email is not valid. Try again".encode())

    Menu(client_socket)

def forget(client_socket):
    ph = PasswordHasher()
    client_socket.send("Enter your username to recover: ".encode())
    username = client_socket.recv(1024).decode()
    
    client_socket.send("Enter your recovery code: ".encode())
    recoverycode = client_socket.recv(1024).decode()

    cur = conn.cursor()
    cur.execute("SELECT recoverycode, factor, email FROM userInfo WHERE username = %s", [username])
    result = cur.fetchone()
    storedRecoveryCode = result[0]
    factor = getDecryptData(ast.literal_eval(result[1]))
    email = getDecryptData(ast.literal_eval(result[2])).strip()

    try: 
        verifyValid = ph.verify(str(storedRecoveryCode),recoverycode)
        client_socket.send("Enter your new password: ".encode())
        newpassword1 = client_socket.recv(1024).decode()
        client_socket.send("Please confirm your password: ".encode())
        newpassword2 = client_socket.recv(1024).decode()
        if newpassword1 != newpassword2:
            client_socket.send("Your password did not match. Please try again".encode())
            cur.close()
            return Menu(client_socket)
        else:
            newRecoveryCode = getRecoveryCode(factor)
            cur.execute("UPDATE userInfo SET password = %s, recoverycode = %s WHERE username = %s", [ph.hash(newpassword1), str(encrypt(newRecoveryCode)), username])
            conn.commit()
            sendRecoveryCode(email, newRecoveryCode)
            client_socket.send("Password changed successfully".encode()) 
            cur.close()
            return Menu(client_socket)
    except:
        client_socket.send("Wrong recovery code! Please try again".encode())
        cur.close()
        return Menu(client_socket)
    
def Menu(client_socket):
    while True:
        command = client_socket.recv(1024).decode().strip()
        switch = {
            "/login": login,
            "/register": register,
            "/exit": exitProgram,
            "/forget": forget,
            
        }
        handler = switch.get(command, invalidCommand)
        handler(client_socket)

def showHelp(client_socket):
    client_socket.send("/login: login\n/createuser: create new user\n/forget: forget password\n/deleteuser: delete existing user\n/search: search for data\n/insert: insert data\n/update: update data\n/delete: delete data\n/exit: disconnect\n".encode())

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