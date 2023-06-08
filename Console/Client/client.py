import socket
import ssl
import threading
import requests
import hmac
import hashlib
import struct
import time
from binascii import hexlify
from getpass import getpass
#global value
otp =''
stop_threads = False
# SSL context
context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.minimum_version = ssl.TLSVersion.TLSv1_3
context.load_verify_locations(cafile="server.crt")
context.verify_mode = ssl.CERT_REQUIRED

# Connect to the server
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client = context.wrap_socket(client, server_hostname="Group6")
client.connect(("localhost", 9999))

print("Client connected successfully")
def receive():
    while True:
        try:
            message = client.recv(1024)
            if message.startswith(b"FACTOR:"):
            # Received the encrypted factor, save it to file
                factor = message[-32:]
                username = message.decode().split(':')[1].split('/')[0]
                filename = hashlib.sha256(username.encode()).hexdigest()
                with open(str(filename[:10]), "wb") as f:
                    f.write(bytes.fromhex(factor.decode()))
                print("factor saved to file. input OK for confirmation")
            #start generating OTP ass username + password is valid
            elif message.startswith(b"Start"):
                username = message.decode()[5:]
                log_time = int(time.time())
                thread = threading.Thread(target=reqOTP,args=(username,log_time))
                thread.start()
                
                
                print("Please open OTP file. Note that OTP only valid in a small amount of time.")
            #stop generate OTP as login successfully
            elif message.startswith(b"Login complete"):
                global stop_threads
                stop_threads = True
            else:
                # Received a regular message, print it to the console
                print(message.decode())
        except Exception as e:
            print(e)
            client.close()
            break
def reqOTP(username,log_time):
    filename = hashlib.sha256(username.encode()).hexdigest()
    f= open(str(filename[:10]), "rb")
    factor = hexlify(f.read())
    #generate first time
    global otp
    otp = generate_totp(factor.decode())
    filename = hashlib.sha256(username.encode()).hexdigest()
    with open(str(filename[:10]) + "_OTP", "w") as f:
        f.write(otp)

    while True:
        global stop_threads
        #generate again after 60 secs
        if (int(time.time())- log_time == 60):
            log_time = int(time.time())
            otp = generate_totp(factor.decode())
            with open(str(filename[:10]) + "_OTP", "w") as f:
                f.write(otp)
        #stop thread when have input OTP
        if stop_threads == True:
            stop_threads = False
            
def send():
    while True:
        try:
            message = input()
            client.send(message.encode())
        except Exception as e:
            print(e)
            client.close()
            break
def generate_totp(secret_key, state=0):
    current_time = int(time.time())
    time_interval = 30
    time_steps = (current_time // time_interval) + state
    time_steps_bytes = struct.pack(">Q", time_steps)
    secret_key_bytes = secret_key.encode("ascii")
    # Generate an HMAC-SHA256 hash of the time steps using the secret key
    hmac_hash = hmac.new(secret_key_bytes, time_steps_bytes, hashlib.sha3_256).digest()

    # Calculate the offset and take last 4-byte for the TOTP code
    offset = hmac_hash[-1] & 0x0F
    code_bytes = hmac_hash[offset:offset+4]
    code = struct.unpack(">I", code_bytes)[0]
    totp_code= '{0:06d}'.format((code & 0x7FFFFFFF) % 1000000)

    return totp_code

def main():
    # Verify cert
    cert = client.getpeercert()
    if cert:
        issuer = dict(x[0] for x in cert['issuer'])
        subject = dict(x[0] for x in cert['subject'])
        if issuer['commonName'] == "Group6" and subject['commonName'] == "Group6":
            print("Server certificate verified")
        else:
            print("Server certificate verification failed")
    else:
        print("Server certificate verification failed")

    receive_thread = threading.Thread(target=receive)
    receive_thread.start()
    send_thread = threading.Thread(target=send)
    send_thread.start()



if __name__ == "__main__":
    main()
