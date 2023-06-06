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

    print("\n-------------------USER INFO TABLE-------------------\n")
    script = 'SELECT * FROM userInfo'
    cur.execute(script)

    rows = cur.fetchall()
    for row in rows:
        print(row)

    print("\n-------------------ROLE PERMISSIONS TABLE-------------------\n")
    script = 'SELECT * FROM rolePermissions'
    cur.execute(script)

    rows = cur.fetchall()
    for row in rows:
        print(row)
    
except Exception as error:
    print(error)
finally:
    if cur is not None:
        cur.close()
    if conn is not None:
        conn.close()
