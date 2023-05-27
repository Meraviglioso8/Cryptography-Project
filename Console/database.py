import sqlite3
import hashlib

conn = sqlite3.connect("userdata.db")
cur = conn.cursor()

cur.execute("""
CREATE TABLE IF NOT EXISTS userdata (
    id INTEGER PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL
)
""")

username1, password1 = "mera", hashlib.sha3_256("m3r@pass".encode()).hexdigest()
username2, password2 = "kizme", hashlib.sha3_256("k!zm3@pass".encode()).hexdigest()
username3, password3 = "tlhung", hashlib.sha3_256("tlhwng@pass".encode()).hexdigest()
cur.execute("INSERT INTO userdata (username,password) VALUES (?, ?)", (username1,password1))
cur.execute("INSERT INTO userdata (username,password) VALUES (?, ?)", (username2,password2))
cur.execute("INSERT INTO userdata (username,password) VALUES (?, ?)", (username3,password3))

conn.commit()