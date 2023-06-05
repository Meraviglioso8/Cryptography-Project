import socket
import ssl
import threading
import requests
from OpenSSL import crypto
# SSL context
context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
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
            rev = client.recv(1024).decode()
            print(rev)
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
