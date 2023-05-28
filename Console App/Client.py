import socket

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(("localhost", 9999))

while True:
    command = input()
    client.send(command.encode())

    response = client.recv(1024).decode()
    print(response)

    if command == "/exit":
        client.close()
        break

