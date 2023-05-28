import socket

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(("localhost",8888))

while True:
    message = client.recv(1024).decode()
    client.send(input(message).encode())
    
    
    