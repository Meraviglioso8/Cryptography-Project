import sqlite3
import hashlib

sqlConnection = sqlite3.connect("userdata.db")
cursor = sqlConnection.cursor()
cursor.execute("""
CREATE TABLE IF NOT EXISTS userdata (
    id INTEGER PRIMARY KEY,
    username VARCHAR(255),
    password VARCHAR(255),
    role VARCHAR(255)
    FOREIGN KEY (role) REFERENCES role_permissions(role)
)
""")

username, password, role = "admin", hashlib.sha3_256("adminpassword".encode()).hexdigest(), "admin"
cursor.execute("INSERT INTO userdata (username,password,role) VALUES ('{}','{}','{}')".format(username,password,role))

sqlConnection.commit()