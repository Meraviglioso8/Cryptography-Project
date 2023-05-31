import socket
import ssl
import threading

#SSL context
context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
context.load_verify_locations(cafile="server.crt")

# Connect to the server
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client = context.wrap_socket(client, server_hostname="Group6")
client.connect(("localhost", 9999))
print("Client connecting...")
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
    receive_thread = threading.Thread(target=receive)
    receive_thread.start()
    send_thread = threading.Thread(target=send)
    send_thread.start()

if __name__ == "__main__":
    main()
