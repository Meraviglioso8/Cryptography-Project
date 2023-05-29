import socket
import threading

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR, 1)
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
