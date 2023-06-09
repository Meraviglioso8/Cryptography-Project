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

    cur.execute('DROP TABLE IF EXISTS rolePermissions CASCADE')
    create_script = ''' CREATE TABLE IF NOT EXISTS rolePermissions (
                            id SERIAL NOT NULL PRIMARY KEY,
                            role VARCHAR(10) NOT NULL UNIQUE,
                            delete_user INTEGER NOT NULL DEFAULT 0,
                            search_data INTEGER NOT NULL DEFAULT 0,
                            insert_data INTEGER NOT NULL DEFAULT 0,
                            update_data INTEGER NOT NULL DEFAULT 0,
                            delete_data INTEGER NOT NULL DEFAULT 0 )'''
    cur.execute(create_script)
    insert_script = 'INSERT INTO rolePermissions (role, delete_user, search_data, insert_data, update_data, delete_data) VALUES (%s ,%s ,%s ,%s ,%s ,%s)'
    insert_values = [("admin",1,1,1,1,1), ("normal",0,1,1,1,1)]
    for i in insert_values:
        cur.execute(insert_script,i)
    
    cur.execute('DROP TABLE IF EXISTS userInfo')
    create_script = ''' CREATE TABLE IF NOT EXISTS userInfo (
                            id SERIAL NOT NULL PRIMARY KEY,
                            username varchar(40) NOT NULL,
                            password varchar(100) NOT NULL,
                            email varchar(100) NOT NULL,
                            role varchar(10) REFERENCES rolePermissions(role),
                            factor varchar(40),
                            ipaddress varchar(30),
                            recoverycode varchar(10),
                            status INTEGER NOT NULL DEFAULT 0 )'''
    cur.execute(create_script)
    insert_script = 'INSERT INTO userInfo (username, password, email, role, factor) VALUES (%s ,%s, %s ,%s ,%s)'
    insert_values = [("mera",ph.hash("mera"),"harukasociu2308@gmail.com","normal","37fceec33bbdacf998c57171d230fa9e"), ("kizme",ph.hash("kizme"),"kietngo255@gmail.com","normal","9f8ba164ed55fe5e2b77c4d4b028e0b3"), ("tlhung",ph.hash("tlhung")," ","normal","236919a82f2eab4e4eb5fe76d8f7844f")]
    for i in insert_values:
        cur.execute(insert_script,i)

    #suspected table
    cur.execute('drop table if exists suspiciousTable')
    create_script = '''CREATE TABLE IF NOT EXISTS suspiciousTable(
                        usernameSUSSY varchar(40),
                        emailSUSSY varchar(40) )'''
    cur.execute(create_script)
    
    #trigger for sussyTable email the same with userInfo email
    trigger_script1 = '''CREATE OR REPLACE FUNCTION update_sussy_email()
    RETURNS TRIGGER AS $$
    BEGIN
        UPDATE suspiciousTable
        SET emailSUSSY = (SELECT email FROM userInfo WHERE username = NEW.usernameSUSSY)
        WHERE usernameSUSSY = NEW.usernameSUSSY;
        RETURN NEW;
    END;
    $$ LANGUAGE plpgsql;'''
    cur.execute(trigger_script1)

    trigger_script2 = '''
    CREATE TRIGGER update_sussy_email_trigger
    AFTER INSERT ON suspiciousTable
    FOR EACH ROW
    EXECUTE FUNCTION update_sussy_email();
    '''
    cur.execute(trigger_script2)
    conn.commit()
    print ("DATABASE CREATED!")
except Exception as error:
    print(error)
finally:
    if cur is not None:
        cur.close()
    if conn is not None:
        conn.close()
