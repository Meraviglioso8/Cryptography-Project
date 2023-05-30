import os
import urllib.parse as up
import psycopg2

up.uses_netloc.append("rbzkziqg")
url = up.urlparse("postgres://rbzkziqg:rGJI2QMcTMo7C6GGrC1f1X82FqysVz2H@satao.db.elephantsql.com/rbzkziqg")
conn = None
cur = None
try:
    
    conn = psycopg2.connect(database=url.path[1:],
    user=url.username,
    password=url.password,
    host=url.hostname,
    port=url.port
    )
    cur = conn.cursor()
    cur.execute('DROP TABLE IF EXISTS rolePer')
    create_script = '''
    CREATE TABLE IF NOT EXISTS rolePer (
        id SERIAL NOT NULL PRIMARY KEY,
        role VARCHAR(40) NOT NULL UNIQUE,
        create_user INTEGER NOT NULL DEFAULT 0,
        delete_user INTEGER NOT NULL DEFAULT 0,
        search_data INTEGER NOT NULL DEFAULT 0,
        insert_data INTEGER NOT NULL DEFAULT 0,
        update_data INTEGER NOT NULL DEFAULT 0,
        delete_data INTEGER NOT NULL DEFAULT 0
                                                )'''

    cur.execute(create_script)
    insert_script = '''INSERT INTO rolePer (role, create_user,delete_user,search_data,insert_data,update_data,delete_data) 
    VALUES (%s ,%s ,%s ,%s, %s, %s, %s)'''
    insert_values = [("admin", 1, 1, 1, 1, 1, 1),("normal",0 , 0, 1, 1, 1, 1)]
    for i in insert_values:
        cur.execute(insert_script, i)
    conn.commit()
    print ("ADD TABLE SUCCESSFULLY!")
except Exception as error:
    print(error)
finally:
    if cur is not None:
        cur.close()
    if conn is not None:
        conn.close()

