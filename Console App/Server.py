import sqlite3
import socket
import threading
import binascii
from random import randint
from Crypto.Cipher import AES
from argon2 import PasswordHasher

# server
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("localhost",9999))
server.listen()
key = binascii.unhexlify("9A1C95B959B9B67EEF032BA0FD0ABC22")
IV = binascii.unhexlify("26D56A8A379834C3784E8FBFB0142464")

def getRoles(username):
    sqlConnection = sqlite3.connect("userdata.db")
    cursor = sqlConnection.cursor()
    cursor.execute("""
        SELECT role FROM userdata
        WHERE username = ?
    """, (username,))
    result = cursor.fetchone()
    if result is None:
        return False # user not found
    return result[0]

def generateFactor(client_socket):
    role = getRoles(client_socket.username)
    sqlConnection = sqlite3.connect("userdata.db")
    cursor = sqlConnection.cursor()
    cursor.execute("""
        SELECT create_user, delete_user, search_data, insert_data, update_data, delete_data
        FROM role_permissions
        WHERE role = ?
    """, (role,))

    result = cursor.fetchone()

    if result:
        permissions = {
            'create_user': result[0],
            'delete_user': result[1],
            'search_data': result[2],
            'insert_data': result[3],
            'update_data': result[4],
            'delete_data': result[5]
        }

        random1 = bin(randint)
        random2 = bin(randint)
        factor = permissions + random1 + random2
        encryptor = AES.new(key, AES.MODE_, IV=IV)
        encryptedFactor = encryptor.encrypt(factor)
        encryptedFactor_hex = encryptedFactor.hex()

        client_socket.factor = encryptedFactor_hex[:5] + encryptedFactor_hex[-5:]
         # insert the factor into the database table
        cursor.execute("UPDATE userdata SET factor = ? WHERE username = ? VALUES (?, ?)", (client_socket.factor, client_socket.username))
        sqlConnection.commit() # commit the transaction to save the changes to the database
        print(f"Factor saved to database for user {client_socket.username}: {client_socket.factor}")

    else:
        print(f"No permissions found for role: {role}")

        

def check_permission(client_socket, permission):
    username = client_socket.username
    sqlConnection = sqlite3.connect("userdata.db")
    cursor = sqlConnection.cursor()
    cursor.execute("""
        SELECT role FROM userdata
        WHERE username = ?
    """, (username,))
    result = cursor.fetchone()
    if result is None:
        return False # user not found
    role = result[0]

    cursor.execute("""
        SELECT ? FROM role_permissions
        WHERE role = ?
    """, (permission, role))
    result = cursor.fetchone()
    if result[0] == 1:
        return True # permission granted
    else:
        return False # permission denied
    
def login(client_socket):
    client_socket.send("Username: ".encode())
    username = client_socket.recv(1024).decode()
    client_socket.send("Password: ".encode())
    password = client_socket.recv(1024).decode()

    ph = PasswordHasher()
    sqlConnection=sqlite3.connect("userdata.db")
    cursor=sqlConnection.cursor()
    data = cursor.execute("SELECT password FROM userdata WHERE username = ?", (username,)).fetchall()[0][0]
    try:
        verifyValid = ph.verify(data ,password)
        client_socket.username = username
        client_socket.send("Login complete!\n".encode())
        Menu(client_socket)
    except:
        client_socket.send("Login failed!\n".encode())
        Menu(client_socket)



def register(c):
    c.send("Username: ".encode())
    username = c.recv(1024).decode()
    c.send("Password: ".encode())
    password = c.recv(1024).decode()
    ph = PasswordHasher()
    hashpass = ph.hash(password)
    conn = sqlite3.connect("userdata.db")
    cur = conn.cursor()
    cur.execute("INSERT INTO userdata (username,password) VALUES (?, ?)", (username,hashpass))
    conn.commit()
    c.send("Register successfully!\n".encode())
    Menu(c)

<<<<<<< Updated upstream
def deleteUser(client_socket):
    if check_permission(client_socket, "delete_user"):
        client_socket.send("Username to delete: ".encode())
        username = client_socket.recv(1024).decode().strip()
        sqlConnection = sqlite3.connect("userdata.db")
        cursor = sqlConnection.cursor()
        cursor.execute("""
            DELETE FROM userdata
            WHERE username = ?
        """, (username,))
        if cursor.rowcount == 1:
            client_socket.send(f"User {username} deleted successfully!\n".encode())
            sqlConnection.commit()
        else:
            client_socket.send(f"User {username} not found!\n".encode())
        sqlConnection.close()
    else:
        client_socket.send("Current user doesn't have permission to delete users.\n".encode())

def searchData(client_socket):
    if check_permission(client_socket, "search_data"):
        client_socket.send("Enter search query: ".encode())
        query = client_socket.recv(1024).decode().strip()
        sqlConnection = sqlite3.connect("productdata.db")
        cursor = sqlConnection.cursor()
        cursor.execute("""
            SELECT *
            FROM product
            WHERE name LIKE ?
            OR description LIKE ?
        """, (f"%{query}%", f"%{query}%"))
        results = cursor.fetchall()
        if len(results) > 0:
            client_socket.send(f"Search results for '{query}':\n".encode())
            for row in results:
                client_socket.send(f"ID: {row[0]}\tName: {row[1]}\tDescription: {row[2]}\tPrice: {row[3]}\tStock: {row[4]}\n".encode())
        else:
            client_socket.send(f"No results found for '{query}'\n".encode())
        sqlConnection.close()
    else:
        client_socket.send("Current user doesn't have permission to search data.\n".encode())

def insertData(client_socket):
    if check_permission(client_socket, "insert_data"):
        client_socket.send("Enter product name: ".encode())
        name = client_socket.recv(1024).decode().strip()
        client_socket.send("Enter product description: ".encode())
        description = client_socket.recv(1024).decode().strip()
        client_socket.send("Enter product price: ".encode())
        price = float(client_socket.recv(1024).decode().strip())
        client_socket.send("Enter product stock: ".encode())
        stock = int(client_socket.recv(1024).decode().strip())

        sqlConnection = sqlite3.connect("productdata.db")
        cursor = sqlConnection.cursor()
        cursor.execute("""
            INSERT INTO product (name, description, price, stock)
            VALUES (?, ?, ?, ?)
        """, (name, description, price, stock))
        sqlConnection.commit()
        client_socket.send("Product added successfully!\n".encode())
        sqlConnection.close()
    else:
        client_socket.send("Current user doesn't have permission to insert data.\n".encode())

def updateData(client_socket):
    if check_permission(client_socket, "update_data"):
        client_socket.send("Enter product ID to update: ".encode())
        product_id = int(client_socket.recv(1024).decode().strip())

        sqlConnection = sqlite3.connect("productdata.db")
        cursor = sqlConnection.cursor()
        cursor.execute("""
            SELECT * FROM product WHERE id = ?
        """, (product_id,))
        result = cursor.fetchone()
        if result is None:
            client_socket.send(f"Product with ID {product_id} not found!\n".encode())
        else:
            # Display current product information
            client_socket.send(f"Current product information:\nID: {result[0]}\nName: {result[1]}\nDescription: {result[2]}\nPrice: {result[3]}\nStock: {result[4]}\n".encode())

            # Prompt for new product information
            client_socket.send("Enter new product name (or leave blank to keep current value): ".encode())
            name = client_socket.recv(1024).decode().strip() or result[1]
            client_socket.send("Enter new product description (or leave blank to keep current value): ".encode())
            description = client_socket.recv(1024).decode().strip() or result[2]
            client_socket.send("Enter new product price (or leave blank to keep current value): ".encode())
            price_str = client_socket.recv(1024).decode().strip()
            price = float(price_str) if price_str else result[3]
            client_socket.send("Enter new product stock (or leave blank to keep current value): ".encode())
            stock_str = client_socket.recv(1024).decode().strip()
            stock = int(stock_str) if stock_str else result[4]

            # Update the product information in the database
            cursor.execute("""
                UPDATE product
                SET name = ?, description = ?, price = ?, stock = ?
                WHERE id = ?
            """, (name, description, price, stock, product_id))
            sqlConnection.commit()
            client_socket.send(f"Product with ID {product_id} updated successfully!\n".encode())
        sqlConnection.close()
    else:
        client_socket.send("Current user doesn't have permission to update data.\n".encode())

def deleteData(client_socket):
    if check_permission(client_socket, "delete_data"):
        client_socket.send("Enter product ID to delete: ".encode())
        product_id = int(client_socket.recv(1024).decode().strip())

        sqlConnection = sqlite3.connect("productdata.db")
        cursor = sqlConnection.cursor()
        cursor.execute("""
            SELECT * FROM product WHERE id = ?
        """, (product_id,))
        result = cursor.fetchone()
        if result is None:
            client_socket.send(f"Product with ID {product_id} not found!\n".encode())
        else:
            cursor.execute("""
                DELETE FROM product
                WHERE id = ?
            """, (product_id,))
            sqlConnection.commit()
            client_socket.send(f"Product with ID {product_id} deleted successfully!\n".encode())
        sqlConnection.close()
    else:
        client_socket.send("Current user doesn't have permission to delete data.\n".encode())
=======
>>>>>>> Stashed changes

def Menu(client_socket):
    while True:
        client_socket.send("Type /help for more information\n".encode())
        command = client_socket.recv(1024).decode().strip()
        switch = {
            "/login": login,
            "/register": register,
            "/exit": exitProgram
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
            client_socket, address = server.accept()
            thread = threading.Thread(target=Menu,args=(client_socket,))
            thread.start()

if __name__ == "__main__":
    main()