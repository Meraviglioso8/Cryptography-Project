import os
import urllib.parse as up
import psycopg2
from argon2 import PasswordHasher
up.uses_netloc.append("rbzkziqg")
url = up.urlparse("postgres://rbzkziqg:rGJI2QMcTMo7C6GGrC1f1X82FqysVz2H@satao.db.elephantsql.com/rbzkziqg")
conn = None
cur = None
ph = PasswordHasher()
try:
    
    conn = psycopg2.connect(database=url.path[1:],
    user=url.username,
    password=url.password,
    host=url.hostname,
    port=url.port
    )
    cur = conn.cursor()
    cur.execute('DROP TABLE IF EXISTS userInfo')
    create_script = ''' CREATE TABLE IF NOT EXISTS userInfo (
                            id SERIAL NOT NULL PRIMARY KEY,
                            username varchar(40) NOT NULL,
                            password varchar(100) NOT NULL,
                            role varchar(10) )'''
    cur.execute(create_script)
    insert_script = 'INSERT INTO userInfo (username, password, role) VALUES (%s ,%s ,%s)'
    insert_values = [("mera",ph.hash("mera"),"normal"), ("kizme",ph.hash("kizme"),"normal"), ("tlhung",ph.hash("tlhung"),"normal")]
    for i in insert_values:
        cur.execute(insert_script,i)
    conn.commit()
    print ("DATABASE CREATED!")
except Exception as error:
    print(error)
finally:
    if cur is not None:
        cur.close()
    if conn is not None:
        conn.close()
