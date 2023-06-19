import os
import urllib.parse as up
import psycopg2
import socket
import threading
from datetime import datetime
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
from contextlib import redirect_stdout
import io
from subprocess import *
#Global Value
regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b'
# Setup connection
dir_path = os.path.dirname(os.path.abspath(__file__))

# Construct the paths to the certificate, ca and key files
ca_bundle_file = os.path.join(dir_path, "/etc/ssl/certs/ca_bundle.crt")
cert_file = os.path.join(dir_path, "/etc/ssl/certs/certificate.crt")
key_file = os.path.join(dir_path, "/etc/ssl/private/server.key")

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
up.uses_netloc.append(os.getenv('DB_PASS'))
url = up.urlparse(os.getenv('DB_URL'))
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

def getAES_KEY():
    command = f"sudo tpm2_unseal -c seal.ctx -p pcr:sha256:0,1,2,3"
    command_1 =  f"sudo tpm2_flushcontext -t"
    passw = check_output(command, shell = True)
    check_output(command_1,shell=True)
    return passw.decode()[0:32]

def generateFactor(username):
    role = getRoles(username)
    try:

        cur = conn.cursor()
        cur.execute("SELECT delete_user, search_data, insert_data, update_data, delete_data FROM rolePermissions WHERE role = %s", [role])
        result = cur.fetchall()
    except Exception as e:
        print(e)

    if result:
        permissions = {
                    'delete_user': result[0][0],
                    'search_data': result[0][1],
                    'insert_data': result[0][2],
                    'update_data': result[0][3],
                    'delete_data': result[0][4]
                }
        permissions_bin = ''.join([bin(value)[2:].zfill(1) for value in permissions.values()])
        factor = permissions_bin + bin(getrandbits(8))[2:] + bin(getrandbits(8))[2:]
        enc = AES.new(unhexlify(getAES_KEY()), AES.MODE_CTR)
        ciphertext = enc.encrypt(factor.encode())
        nonce = enc.nonce
        return ciphertext.hex(), nonce.hex()
    else:
        print(f"No permissions found for role: {role}")
        return

#get recoverycode
def getRecoveryCode(factor32char):
    recoveryCode = ''.join(random.sample(factor32char, 6))
    return recoveryCode

#encrypt function
def encrypt(in_str):
    enc = AES.new(unhexlify(getAES_KEY()), AES.MODE_GCM)
    ciphertext, tag = enc.encrypt_and_digest(in_str.encode())
    nonce = enc.nonce
    return ciphertext.hex(), tag.hex(),nonce.hex()

#decrypt function
def decrypt (in_str,tag,nonce):
    in_str = unhexlify(in_str)
    decrypt_cipher = AES.new(unhexlify(getAES_KEY()), AES.MODE_GCM,nonce=unhexlify(nonce))
    plain_text = decrypt_cipher.decrypt_and_verify(in_str, unhexlify(tag))
    return plain_text.decode()

#decrypt data get from DB
def getDecryptData(get_data):
    get_data = decrypt(get_data[0],get_data[1],get_data[2])
    return get_data
#decrypt Factor for permission checking
def decryptFactor(in_str,nonce):
     in_str = unhexlify(in_str)
     nonce = unhexlify(nonce)
     decrypt_cipher = AES.new(unhexlify(getAES_KEY()), AES.MODE_CTR,nonce=nonce)
     return decrypt_cipher.decrypt(in_str).decode()

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
def getPermission(role):
    try:
        cur = conn.cursor()
        cur.execute("SELECT delete_user, search_data, insert_data, update_data, delete_data FROM rolePermissions WHERE role = %s", [role])
        result = cur.fetchall()
        permissions = {
                    'delete_user': result[0][0],
                    'search_data': result[0][1],
                    'insert_data': result[0][2],
                    'update_data': result[0][3],
                    'delete_data': result[0][4]
                }
    except:
        permissions = None
        print("No valid permission found")
        return
    return''.join([bin(value)[2:].zfill(1) for value in permissions.values()])

#LOGIN function
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
        return

    cur.execute("SELECT password FROM userInfo WHERE username = %s", [username])
    data = cur.fetchall()[0][0]
    try:
        verifyValid = ph.verify(str(data),password)
    except:
        cur.execute("INSERT INTO suspiciousTable (usernameSUSSY,ipaddress,logtime) VALUES (%s,%s,%s)", [username,client_socket.getpeername()[0],datetime.now()])
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
            try:
                cur = conn.cursor()
                cur.execute("""UPDATE userInfo
                SET status = 1
                WHERE username = %s""", [username])
                conn.commit()
                cur.close()
                return
            except:
                return
        else:
            return

    #check valid ip, if new have to auth
    client_ip = client_socket.getpeername()[0]
    cur.execute("SELECT ipaddress, recoverycode FROM userInfo WHERE username = %s", [username])
    ans=cur.fetchone()

    ipofusername =ans[0]
    storedRecoveryCode = ans[1]

    if ipofusername and ipofusername != client_ip:
        client_socket.send("Login IP does not match the stored IP address. Please enter recoverycode to continue.".encode())
        recoveryCode = client_socket.recv(1024).decode()
        try:
            verifyValid = ph.verify(str(storedRecoveryCode),recoveryCode)

        except:
            client_socket.send("Invalid recovery code. Please try login again.".encode())
            cur.execute("INSERT INTO suspiciousTable (usernameSUSSY,ipaddress,logtime) VALUES (%s,%s,%s)", [username,client_ip,datetime.now()])
            conn.commit()
            cur.execute("SELECT COUNT(*) FROM suspiciousTable WHERE usernameSUSSY = %s", [username])
            count = cur.fetchone()[0]
            cur.execute("SELECT email FROM userInfo WHERE username = %s", [username])
            data = ast.literal_eval(cur.fetchone()[0])
            gmailofSussy = getDecryptData(data)
            client_socket.send(("User added to suspiciousTable count: " + str(count)).encode())
            sendEmail(count,gmailofSussy)
            cur.close()
            return
        
        # Retrieve the updated user information

        factor = generateFactor(username)
        storedRecoveryCode = getRecoveryCode(factor[0])
        encRecvCode = ph.hash(storedRecoveryCode)
        encFactor = str(encrypt(str(factor)))

        cur.execute("UPDATE userInfo SET recoverycode = %s, factor = %s,ipaddress = %s WHERE username = %s", [encRecvCode,encFactor,client_ip,username])
        conn.commit()
        client_socket.send("Change login location".encode())
        client_socket.send(("FACTOR:" + username + '/'+'('+ str(factor[0])+')').encode())
        cur.execute("SELECT email FROM userInfo WHERE username = %s", [username])
        data = ast.literal_eval(cur.fetchone()[0])
        email = getDecryptData(data)
        sendRecoveryCode(email, storedRecoveryCode)
    #start generating OTP as username + password are valid

    if (verifyValid == True):
        client_socket.send(("Start"+username).encode())
        client_socket.send("Input your OTP: ".encode())
        otp_code = client_socket.recv(1024).decode()
        factor = None
        try:
            cur = conn.cursor()
            cur.execute("SELECT factor FROM userInfo WHERE username = %s", [username])
            data = ast.literal_eval(cur.fetchone()[0])
            factor = ast.literal_eval(getDecryptData(data))
            print("CURRENT USER FACTOR: ",factor[0])

        except Exception as e:
            print(e)
            return
        #user name exists or not
        if(otp_code == generate_totp(factor[0]) or otp_code ==generate_totp(factor[0],-1)):
            client_socket.send("Login complete!".encode())

            #get "database role"
            cur.execute("SELECT role FROM userInfo Where username = %s", [username])
            role = cur.fetchone()[0]
            permission = getPermission(role)

            #check role using factor
            print(factor[1])
            if ((decryptFactor(factor[0],factor[1])[0:5]) == permission and role =="admin"):
                factor = generateFactor(username)
                client_socket.send(("FACTOR:" + username + '/'+'('+ str(factor[0])+')').encode())
                encfactor = str(encrypt(str(factor)))
                #UPDATE NEW FACTOR INTO DB
                cur.execute("UPDATE userInfo SET factor = %s WHERE username = %s", [encfactor,username])
                conn.commit()
                client_socket.send("You are recognized as admin privilege".encode())

                return adminConsole(client_socket)
            
            elif (decryptFactor(factor[0],factor[1])[0:5] == permission):
                factor = generateFactor(username)
                client_socket.send(("FACTOR:" + username + '/'+'('+ str(factor[0])+')').encode())
                encfactor = str(encrypt(str(factor)))
                #UPDATE NEW FACTOR INTO DB
                cur = conn.cursor()
                cur.execute("UPDATE userInfo SET factor = %s WHERE username = %s", [encfactor,username])
                conn.commit()
                client_socket.send("You are recognized as user privilege".encode())
                return
            else:
                client_socket.send("Your role was changed by the third party. Please contact admin of the service.")
                return

        else:
            cur.execute("INSERT INTO suspiciousTable (usernameSUSSY,ipaddress,logtime) VALUES (%s,%s,%s)", [username,client_ip,datetime.now()])
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
                try:
                    cur = conn.cursor()
                    cur.execute("""UPDATE userInfo
                    SET status = 1
                    WHERE username = %s""", [username])
                    conn.commit()
                    cur.close()
                    return
                except:
                    return
            else:
                return
    return

#send email if count > 5
def sendEmail(count, gmailofSussy):
    if count >= 5:
        #send annoucement your account has been locked
        sendtogmail(gmailofSussy)
        # change status as to protect sussy login


def sendtogmail(gmailofSussy):
    gmail_user = os.getenv('GMAIL_USER')
    gmail_app_password = os.getenv('GMAIL_PASS')

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
    gmail_user = os.getenv('GMAIL_USER')
    gmail_app_password = os.getenv('GMAIL_PASS')

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
        if(len(data) > 0):
            client_socket.send("Username already existed! Try again.".encode())
            register(client_socket)
    except:
        pass

    #check valid email format
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
        cur.execute("INSERT INTO userInfo (username,password,email,role) VALUES (%s, %s, %s, %s)", [username,hashpass,str(encrypt(email)),"admin"])
        conn.commit()

    #factor, recoverycode, ip of client

        factor = generateFactor(username)
        encfactor = str(encrypt(str(factor)))
        recoveryCode = getRecoveryCode(factor[0])
        print(recoveryCode)
        hashRecoveryCode = ph.hash(recoveryCode)
        client_ip = client_socket.getpeername()[0]
        print("CURRENT USER FACTOR: ",factor[0])

        cur.execute("UPDATE userInfo SET factor = %s , recoverycode = %s, ipaddress = %s WHERE username = %s",[encfactor, hashRecoveryCode, client_ip, username])
        conn.commit()
        cur.close()
        client_socket.send(("FACTOR:" + username + '/'+'('+ str(factor[0])+')').encode())
        client_socket.send(("Register successfully! Please remember this recovery code:"+ recoveryCode).encode())
        sendRecoveryCode(email, recoveryCode)
    else:
        client_socket.send("Your email is not valid. Try again".encode())
    return

def forget(client_socket):
    ph = PasswordHasher()
    client_socket.send("Enter your username to recover: ".encode())
    username = client_socket.recv(1024).decode()

    client_socket.send("Enter your recovery code: ".encode())
    recoverycode = client_socket.recv(1024).decode()

    #get neccessary data
    cur = conn.cursor()
    cur.execute("SELECT recoverycode, factor, email FROM userInfo WHERE username = %s", [username])
    result = cur.fetchone()
    storedRecoveryCode = result[0]
    print(storedRecoveryCode)

    #verify RecoveryCode
    try:
        verifyValid = ph.verify(storedRecoveryCode, recoverycode)
        cur = conn.cursor()
        cur.execute("SELECT role FROM userInfo Where username = %s", [username])
        #check role from factor

        role = cur.fetchone()[0]
        permission = getPermission(role)
        data = ast.literal_eval(result[1])
        factor = ast.literal_eval(getDecryptData(data))
        print(factor)

        if ((decryptFactor(factor[0],factor[1])[0:5]) == permission):
            client_socket.send("Enter your new password: ".encode())
            newpassword1 = client_socket.recv(1024).decode()
            client_socket.send("Please confirm your password: ".encode())
            newpassword2 = client_socket.recv(1024).decode()
        else:
            client_socket.send("Your role was changed by the third party. Please contact admin of the service.")
            return
        
        if newpassword1 != newpassword2:
            client_socket.send("Your password did not match. Please try again".encode())
            return
        else:
            #extract factor and email when have verify success only
            email = getDecryptData(ast.literal_eval(result[2])).strip()
            
            #REGEN recv code + factor 
            newfactor = generateFactor(username)
            client_socket.send(("FACTOR:" + username + '/'+'('+ str(newfactor[0])+')').encode())
            encfactor = str(encrypt(str(newfactor)))
            newRecoveryCode = getRecoveryCode(newfactor[0])
            cur = conn.cursor()
            cur.execute("UPDATE userInfo SET password = %s, recoverycode = %s,factor = %s WHERE username = %s", [ph.hash(newpassword1), ph.hash(newRecoveryCode),encfactor, username])
            conn.commit()
            sendRecoveryCode(email, newRecoveryCode)
            client_socket.send("Password changed successfully".encode())
            cur.close()
            return
        
    #Verify Fail
    except Exception as e:
        print(e)
        client_ip = client_socket.getpeername()[0]
        client_socket.send("Wrong recovery code! Please try again".encode())
        cur.execute("INSERT INTO suspiciousTable (usernameSUSSY,ipaddress,logtime) VALUES (%s,%s,%s)", [username,client_ip,datetime.now()])
        conn.commit()
        cur.execute("SELECT COUNT(*) FROM suspiciousTable WHERE usernameSUSSY = %s", [username])
        count = cur.fetchone()[0]
        cur.execute("SELECT email FROM userInfo WHERE username = %s", [username])
        data = ast.literal_eval(cur.fetchone()[0])
        gmailofSussy = getDecryptData(data)
        client_socket.send(("User added to suspiciousTable count: " + str(count)).encode())
        sendEmail(count,gmailofSussy)
        cur.close()
        return


def ChangeUserPrivilege(client_socket):
    try:
        client_socket.send("Enter username you want to change privilege: ".encode())
        usertochange = client_socket.recv(1024).decode().strip()
        client_socket.send("admin or normal? ".encode())
        userrole = client_socket.recv(1024).decode().strip()
        cur = conn.cursor()
        cur.execute(" UPDATE userInfo SET role = %s WHERE username = %s", [userrole, usertochange])
        conn.commit()
        cur.close()
        client_socket.send(f"Changed role to {userrole}".encode())
    except Exception as e:
        print(e)
        client_socket.send("No user found".encode())
    return adminConsole(client_socket)

def DeleteUser(client_socket):
    try:
        client_socket.send("Enter username you want to delete: ".encode())
        usertochange = client_socket.recv(1024).decode().strip()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM userInfo WHERE username = %s", [usertochange])
        row_count = cur.fetchone()[0]
        if row_count > 0:
            cur.execute("DELETE FROM userInfo WHERE username = %s", [usertochange])
            conn.commit()
            client_socket.send(f"User {usertochange} deleted".encode())
        else:
            client_socket.send(f"User {usertochange} doesn't exist".encode())

        cur.execute("SELECT COUNT(*) FROM suspiciousTable WHERE usernameSUSSY = %s", [usertochange])
        row_count = cur.fetchone()[0]
        if row_count > 0:
            cur.execute("DELETE FROM suspiciousTable WHERE usernameSUSSY = %s", [usertochange])
        conn.commit()
        cur.close()
    except Exception as e:
        print(e)
    return adminConsole(client_socket)
def UnlockUser(client_socket):
    try:
        client_socket.send("Enter username you want to unlock: ".encode())
        usertochange = client_socket.recv(1024).decode().strip()
        cur = conn.cursor()
        cur.execute("UPDATE userInfo SET status = 0 WHERE username = %s", [usertochange])
        conn.commit()
        cur.execute("SELECT COUNT(*) FROM suspiciousTable WHERE usernameSUSSY = %s", [usertochange])
        row_count = cur.fetchone()[0]
        if row_count > 0:
            cur.execute("DELETE FROM suspiciousTable WHERE usernameSUSSY = %s", [usertochange])
            client_socket.send(f"User {usertochange} unlocked".encode())
        else:
            client_socket.send(f"User {usertochange} is not in Suspected Table".encode())
        conn.commit()
        cur.close()
    except Exception as e:
        print(e)
    return adminConsole(client_socket)
def adminConsole(client_socket):
    command = client_socket.recv(1024).decode().strip()
    switch = {
            "/login": login,
            "/register": register,
            "/exit": exitProgram,
            "/forget": forget,
            "/change": ChangeUserPrivilege,
            "/delete": DeleteUser,
            "/unlock": UnlockUser,
            "/showhelp": showHelp,
            "/admincommandhelp": adminconsole
        }
    handler = switch.get(command, invalidCommand)
    handler(client_socket)
def Menu(client_socket):
    while True:
        command = client_socket.recv(1024).decode().strip()
        switch = {
            "/login": login,
            "/register": register,
            "/exit": exitProgram,
            "/forget": forget,
            "/showhelp": showHelp,
        }
        handler = switch.get(command, invalidCommand)
        handler(client_socket)

def showHelp(client_socket):
    client_socket.send('''
/login: login
/register: register
/forget: forget password
'''.encode())

def adminconsole(client_socket):
    client_socket.send('''
/change: ChangeUserPrivilege,
/delete: Delete specific user,
/unlock: unlock banned users
'''.encode())

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