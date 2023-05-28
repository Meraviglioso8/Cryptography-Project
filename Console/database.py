import sqlite3
import hashlib
import os
from argon2 import PasswordHasher
conn = sqlite3.connect("userdata.db")
cur = conn.cursor()

cur.execute("""
CREATE TABLE IF NOT EXISTS userdata (
    id INTEGER PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL
)
""")
ph=PasswordHasher()
username1, password1 = "mera", ph.hash("m3r@pass")
username2, password2 = "kizme", ph.hash("kizme@pass")
username3, password3 = "tlhung", ph.hash("tlhwng@pass")
cur.execute("INSERT INTO userdata (username,password) VALUES (?, ?)", (username1,password1))
cur.execute("INSERT INTO userdata (username,password) VALUES (?, ?)", (username2,password2))
cur.execute("INSERT INTO userdata (username,password) VALUES (?, ?)", (username3,password3))

conn.commit()