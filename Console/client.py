import socket
import ssl
import threading
import requests
import hmac
import hashlib
import struct
import time

# SSL context
context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
context.load_verify_locations(cafile="server.crt")

# Connect to the server
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client = context.wrap_socket(client, server_hostname="Group6")
client.connect(("localhost", 9999))
print("Client connected successfully")

def receive():
    while True:
        try:
            message = client.recv(1024).decode()
            if message.startswith("FACTOR:"):
                # Received the encrypted factor, save it to file
                factor = message[7:]
                with open("factor", "wb") as f:
                    f.write(factor)
                print("factor saved to file")
            else:
                # Received a regular message, print it to the console
                print(message)
        except:
            print('Error! Cannot receive from server!')
            client.close()
            break

def send():
    while True:
        try:
            message = input()
            client.send(message.encode())
        except:
            print('Error! Cannot send message to server!')
            client.close()
            break

def generate_totp(secret_key):
    current_time = int(time.time())
    time_interval = 30
    time_steps = current_time // time_interval
    time_steps_bytes = struct.pack(">Q", time_steps)
    secret_key_bytes = secret_key.encode("ascii")
    
    # Generate an HMAC-SHA1 hash of the time steps using the secret key
    hmac_hash = hmac.new(secret_key_bytes, time_steps_bytes, hashlib.sha1).digest()

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
