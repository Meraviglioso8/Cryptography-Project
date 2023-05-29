import sqlite3
from argon2 import PasswordHasher

sqlConnection = sqlite3.connect("userdata.db")
cursor = sqlConnection.cursor()
cursor.execute("""
CREATE TABLE IF NOT EXISTS userdata (
    id INTEGER PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    role VARCHAR(255) NOT NULL REFERENCES role_permissions(role)
)
""")

ph=PasswordHasher()
username, password, role = "admin", ph.hash("adm1n@pass"), "admin"
username1, password1, role1 = "mera", ph.hash("m3r@pass"), "normal"
username2, password2, role2 = "kizme", ph.hash("kizme@pass"), "normal"
username3, password3, role3 = "tlhung", ph.hash("tlhwng@pass"), "normal"

cursor.execute("INSERT INTO userdata (username,password,role) VALUES (?, ?, ?)", (username,password,role))
cursor.execute("INSERT INTO userdata (username,password,role) VALUES (?, ?, ?)", (username1,password1,role1))
cursor.execute("INSERT INTO userdata (username,password,role) VALUES (?, ?, ?)", (username2,password2,role2))
cursor.execute("INSERT INTO userdata (username,password,role) VALUES (?, ?, ?)", (username3,password3,role3))

sqlConnection.commit()